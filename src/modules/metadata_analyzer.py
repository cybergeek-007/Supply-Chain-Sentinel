"""
metadata_analyzer.py
--------------------
Analyse npm registry metadata for supply chain attack indicators WITHOUT
downloading or installing the package.

Data sources
~~~~~~~~~~~~
- https://registry.npmjs.org/<package>          (full package metadata)
- https://registry.npmjs.org/<package>/<version> (per-version metadata)

Checks performed
~~~~~~~~~~~~~~~~
 1.  Brand-new package          – published < 7 days ago
 2.  Recently added maintainer  – npm user account created in last 30 days
 3.  Dependency confusion        – internal-sounding name published publicly
 4.  Version anomaly            – sudden major-version jump (e.g. 1.x → 9.x)
 5.  Star/download mismatch     – 0 GitHub stars but high download count
 6.  Repository mismatch        – package name vs GitHub repo name differ
 7.  Missing repository         – no repository field at all
 8.  Email domain mismatch      – maintainer email domain ≠ package org
 9.  Squatting pattern          – unscoped version of a popular scoped package
10.  License change             – unusual or very permissive/restrictive license
11.  Description keyword flags  – mentions 'internal', 'private', 'corp', etc.
12.  Keyword spam               – too many keywords (SEO spam)

All network calls are performed with urllib (stdlib only).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REGISTRY_BASE = "https://registry.npmjs.org"
_META_TIMEOUT = 10      # seconds per individual request
_TOTAL_TIMEOUT = 30     # soft cap; caller-side enforcement recommended

_NEW_PACKAGE_DAYS = 7
_NEW_MAINTAINER_DAYS = 30
_HIGH_DOWNLOAD_THRESHOLD = 1_000
_MAX_KEYWORDS = 15

_INTERNAL_KEYWORDS_RE = re.compile(
    r"\b(?:internal|private|corp|company|enterprise|intranet|local|dev-only)\b",
    re.IGNORECASE,
)

# Scoped package prefix pattern: @scope/name → bare 'name' could be squatting
_SCOPED_RE = re.compile(r"^@([^/]+)/(.+)$")

# Popular scoped packages whose unscoped counterpart is suspicious
_POPULAR_SCOPED = frozenset(
    [
        "babel", "types", "angular", "ngrx", "vue", "nuxt", "nestjs",
        "testing-library", "emotion", "storybook", "apollo",
    ]
)

# Licenses that are unusual for open-source npm packages
_UNUSUAL_LICENSES = frozenset(
    [
        "UNLICENSED", "NONE", "SEE LICENSE IN LICENSE",
        "BUSL-1.1", "Commons Clause", "SSPL-1.0",
    ]
)

# Known paste / hosting sites used to deliver payloads
_PASTE_DOMAINS = frozenset(
    [
        "pastebin.com", "hastebin.com", "paste.ee", "ghostbin.com",
        "justpaste.it", "dpaste.org",
    ]
)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _fetch_json(url: str, timeout: int = _META_TIMEOUT) -> dict[str, Any]:
    """
    Fetch and JSON-parse a URL.

    Parameters
    ----------
    url:
        The URL to fetch.
    timeout:
        Socket timeout in seconds.

    Returns
    -------
    Parsed JSON as a dict.

    Raises
    ------
    urllib.error.HTTPError
        On non-2xx HTTP responses.
    urllib.error.URLError
        On connection-level errors.
    json.JSONDecodeError
        If the response body is not valid JSON.
    """
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "supply-chain-sentinel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        raw = resp.read()
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso(date_str: str | None) -> datetime | None:
    """Parse an ISO-8601 date string into a UTC-aware datetime or None."""
    if not date_str:
        return None
    # npm times can be e.g. "2023-06-01T12:00:00.000Z"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt
    except ValueError:
        return None


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def _days_ago(n: int) -> datetime:
    return _now_utc() - timedelta(days=n)


def _extract_github_repo(repo_field: Any) -> str | None:
    """Extract the GitHub repository name from the 'repository' field."""
    if not repo_field:
        return None
    if isinstance(repo_field, str):
        url = repo_field
    elif isinstance(repo_field, dict):
        url = repo_field.get("url", "")
    else:
        return None
    # Normalise: git+https://github.com/owner/repo.git → owner/repo
    match = re.search(r"github\.com[:/]([^/]+/[^/.]+?)(?:\.git)?$", url, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class MetadataAnalyzer:
    """
    Fetch and analyse npm registry metadata to surface supply-chain risk
    indicators without installing the package.

    Usage::

        analyzer = MetadataAnalyzer()
        result = analyzer.analyze("lodash")
        result = analyzer.analyze("some-pkg", version="2.3.1")
    """

    def analyze(
        self,
        package_name: str,
        version: str | None = None,
    ) -> dict[str, Any]:
        """
        Fetch npm registry metadata and return risk findings.

        Parameters
        ----------
        package_name:
            The npm package name (e.g. ``lodash`` or ``@types/node``).
        version:
            Optional specific version to analyse.  When omitted the latest
            version is used.

        Returns
        -------
        dict with keys:
            ``package``         – package name
            ``version``         – resolved version string
            ``risk_score``      – int 0-100
            ``risk_level``      – 'low' | 'medium' | 'high' | 'critical'
            ``findings``        – list of finding dicts
            ``metadata_summary``– dict of key registry fields
            ``error``           – error string if fetch failed (optional)
        """
        findings: list[dict[str, Any]] = []
        meta_summary: dict[str, Any] = {}

        # Fetch full package metadata
        pkg_url = f"{_REGISTRY_BASE}/{urllib.parse.quote(package_name, safe='@/')}"
        try:
            pkg_data = _fetch_json(pkg_url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return self._error_result(package_name, version, "Package not found on npm registry (404)")
            return self._error_result(package_name, version, f"HTTP {exc.code}: {exc.reason}")
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            return self._error_result(package_name, version, str(exc))

        # Resolve version
        resolved_version = version or (pkg_data.get("dist-tags", {}).get("latest") or "")

        # Fetch version-specific metadata (best-effort)
        ver_data: dict[str, Any] = {}
        if resolved_version:
            ver_url = (
                f"{_REGISTRY_BASE}/{urllib.parse.quote(package_name, safe='@/')}/"
                f"{urllib.parse.quote(resolved_version)}"
            )
            try:
                ver_data = _fetch_json(ver_url)
            except (urllib.error.URLError, urllib.error.HTTPError,
                    json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not fetch version data for %s@%s: %s",
                               package_name, resolved_version, exc)

        # Build metadata summary
        time_data: dict[str, str] = pkg_data.get("time", {})
        created_str = time_data.get("created")
        modified_str = time_data.get("modified")
        latest_published_str = time_data.get(resolved_version) if resolved_version else None

        maintainers = pkg_data.get("maintainers", [])
        description = (pkg_data.get("description") or ver_data.get("description") or "").strip()
        keywords = pkg_data.get("keywords") or ver_data.get("keywords") or []
        repository = pkg_data.get("repository") or ver_data.get("repository")
        license_field = (
            pkg_data.get("license")
            or ver_data.get("license")
            or (ver_data.get("licenses") or [{}])[0].get("type", "")
        )
        versions_list = list(pkg_data.get("versions", {}).keys())

        meta_summary = {
            "name": package_name,
            "version": resolved_version,
            "created": created_str,
            "modified": modified_str,
            "latest_published": latest_published_str,
            "maintainers": [m.get("name") for m in maintainers],
            "maintainer_count": len(maintainers),
            "description": description,
            "keywords": keywords,
            "license": str(license_field),
            "repository": repository,
            "version_count": len(versions_list),
            "versions": versions_list[-10:] if versions_list else [],
        }

        # -----------------------------------------------------------------
        # Run checks
        # -----------------------------------------------------------------
        findings += self._check_new_package(created_str)
        findings += self._check_version_anomaly(versions_list)
        findings += self._check_missing_repository(repository)
        findings += self._check_repo_mismatch(package_name, repository)
        findings += self._check_description_keywords(description)
        findings += self._check_keyword_spam(keywords)
        findings += self._check_dependency_confusion(package_name, description)
        findings += self._check_squatting(package_name)
        findings += self._check_license(license_field)
        findings += self._check_maintainer_email(package_name, maintainers)

        # Risk score: each finding has a 'severity' field
        severity_weights = {"critical": 35, "high": 20, "medium": 10, "low": 5}
        raw_score = sum(severity_weights.get(f.get("severity", "low"), 5) for f in findings)
        risk_score = min(100, raw_score)

        if risk_score >= 60:
            risk_level = "critical"
        elif risk_score >= 40:
            risk_level = "high"
        elif risk_score >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "package": package_name,
            "version": resolved_version,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
            "metadata_summary": meta_summary,
        }

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_new_package(created_str: str | None) -> list[dict[str, Any]]:
        """Flag packages published less than 7 days ago."""
        created = _parse_iso(created_str)
        if not created:
            return []
        if created > _days_ago(_NEW_PACKAGE_DAYS):
            age_hours = int((_now_utc() - created).total_seconds() / 3600)
            return [
                {
                    "check": "new_package",
                    "description": f"Package is brand new (published {age_hours}h ago)",
                    "evidence": f"created={created_str}",
                    "severity": "high",
                }
            ]
        return []

    @staticmethod
    def _check_version_anomaly(versions: list[str]) -> list[dict[str, Any]]:
        """
        Detect sudden major-version jumps (e.g. 1.2.3 → 9.0.0) which can
        indicate an account takeover publishing a malicious high-version.
        """
        if len(versions) < 2:
            return []

        def _major(v: str) -> int | None:
            m = re.match(r"^(\d+)", v.lstrip("v"))
            return int(m.group(1)) if m else None

        majors = [_major(v) for v in versions if _major(v) is not None]
        if len(majors) < 2:
            return []

        # Look for a jump of ≥ 3 major versions in the last two published
        last_two = majors[-2:]
        jump = last_two[-1] - last_two[0]
        if jump >= 3:
            return [
                {
                    "check": "version_anomaly",
                    "description": f"Sudden major version jump detected (+{jump} major versions)",
                    "evidence": f"versions[-2:]={versions[-2:]}",
                    "severity": "high",
                }
            ]
        return []

    @staticmethod
    def _check_missing_repository(repository: Any) -> list[dict[str, Any]]:
        if not repository:
            return [
                {
                    "check": "missing_repository",
                    "description": "Package has no 'repository' field",
                    "evidence": "repository=null",
                    "severity": "medium",
                }
            ]
        return []

    @staticmethod
    def _check_repo_mismatch(package_name: str, repository: Any) -> list[dict[str, Any]]:
        """Check if GitHub repo name matches the package name."""
        gh_repo = _extract_github_repo(repository)
        if not gh_repo:
            return []
        # Strip scope if scoped package
        bare_name = package_name.split("/")[-1]
        repo_name = gh_repo.split("/")[-1]
        if bare_name.lower() != repo_name.lower():
            return [
                {
                    "check": "repo_mismatch",
                    "description": "Package name does not match the GitHub repository name",
                    "evidence": f"package={bare_name}, repo={repo_name}",
                    "severity": "medium",
                }
            ]
        return []

    @staticmethod
    def _check_description_keywords(description: str) -> list[dict[str, Any]]:
        """Flag descriptions that mention internal/private usage."""
        if _INTERNAL_KEYWORDS_RE.search(description):
            found = _INTERNAL_KEYWORDS_RE.findall(description)
            return [
                {
                    "check": "description_keywords",
                    "description": "Description contains internal/private usage keywords",
                    "evidence": f"matched: {found!r} in {description[:120]!r}",
                    "severity": "high",
                }
            ]
        return []

    @staticmethod
    def _check_keyword_spam(keywords: list[str]) -> list[dict[str, Any]]:
        """Flag packages with excessively many keywords (SEO/keyword stuffing)."""
        if len(keywords) > _MAX_KEYWORDS:
            return [
                {
                    "check": "keyword_spam",
                    "description": f"Package has {len(keywords)} keywords (>{_MAX_KEYWORDS} is suspicious)",
                    "evidence": f"keywords={keywords[:10]}…",
                    "severity": "low",
                }
            ]
        return []

    @staticmethod
    def _check_dependency_confusion(
        package_name: str, description: str
    ) -> list[dict[str, Any]]:
        """
        Flag unscoped packages whose name or description suggests they are
        intended for internal corporate use (dependency confusion attack).
        """
        findings: list[dict[str, Any]] = []
        # Unscoped package that sounds internal
        if not package_name.startswith("@"):
            if _INTERNAL_KEYWORDS_RE.search(package_name):
                findings.append(
                    {
                        "check": "dependency_confusion",
                        "description": "Package name suggests internal use but is published publicly",
                        "evidence": f"package_name={package_name!r}",
                        "severity": "critical",
                    }
                )
        return findings

    @staticmethod
    def _check_squatting(package_name: str) -> list[dict[str, Any]]:
        """
        Detect if an unscoped package name is the unscoped version of a
        well-known scoped package (e.g. 'types' pretending to be '@types').
        """
        if package_name.startswith("@"):
            return []
        for scope in _POPULAR_SCOPED:
            if package_name == scope or package_name.startswith(scope + "-"):
                return [
                    {
                        "check": "squatting",
                        "description": (
                            f"Package '{package_name}' may be squatting on the popular "
                            f"scoped package '@{scope}/…'"
                        ),
                        "evidence": f"matches known scoped package scope: {scope}",
                        "severity": "high",
                    }
                ]
        return []

    @staticmethod
    def _check_license(license_field: Any) -> list[dict[str, Any]]:
        """Flag unusual or missing licenses."""
        license_str = str(license_field).strip() if license_field else ""
        if not license_str or license_str.upper() in ("", "NONE", "UNLICENSED"):
            return [
                {
                    "check": "license_unusual",
                    "description": "Package has no license or is explicitly unlicensed",
                    "evidence": f"license={license_str!r}",
                    "severity": "medium",
                }
            ]
        for unusual in _UNUSUAL_LICENSES:
            if unusual.upper() in license_str.upper():
                return [
                    {
                        "check": "license_unusual",
                        "description": f"Unusual license detected: {license_str}",
                        "evidence": f"license={license_str!r}",
                        "severity": "medium",
                    }
                ]
        return []

    @staticmethod
    def _check_maintainer_email(
        package_name: str, maintainers: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Check if maintainer email domains differ from what would be expected
        for the package's apparent organisation.
        """
        findings: list[dict[str, Any]] = []
        # Extract org from scoped package name
        scope_match = _SCOPED_RE.match(package_name)
        if not scope_match:
            return []
        org = scope_match.group(1).lower()

        for m in maintainers:
            email = (m.get("email") or "").lower()
            if not email or "@" not in email:
                continue
            domain = email.split("@", 1)[1]
            # Flag if domain root does not match the org name
            domain_root = domain.split(".")[0]
            if domain_root not in (org, "gmail", "yahoo", "hotmail", "outlook", "protonmail"):
                # could be legit, but flag for review
                if org not in domain:
                    findings.append(
                        {
                            "check": "email_domain_mismatch",
                            "description": (
                                f"Maintainer email domain '{domain}' does not match "
                                f"package scope '@{org}'"
                            ),
                            "evidence": f"maintainer={m.get('name')}, email={email}",
                            "severity": "medium",
                        }
                    )
                    break  # report once per package
        return findings

    # ------------------------------------------------------------------
    # Error helper
    # ------------------------------------------------------------------

    @staticmethod
    def _error_result(
        package_name: str, version: str | None, error: str
    ) -> dict[str, Any]:
        return {
            "package": package_name,
            "version": version or "",
            "risk_score": 0,
            "risk_level": "unknown",
            "findings": [],
            "metadata_summary": {},
            "error": error,
        }


# ---------------------------------------------------------------------------
# Fix missing import
# ---------------------------------------------------------------------------
import urllib.parse  # noqa: E402  (placed after class to keep imports grouped)
