"""Unified threat intelligence aggregator.

Queries multiple external threat APIs and merges results into a single
report for IPs, domains, URLs, and file hashes extracted during analysis.

Supported APIs (all optional):
  - VirusTotal v3    — file hash, URL, domain reputation
  - AbuseIPDB v2     — IP abuse confidence scoring
  - ip-api.com       — Free IP geolocation + proxy detection
  - URLhaus (abuse.ch) — Known malicious URL database
  - MalwareBazaar    — Known malware hash database
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import quote

from src.core.python.logger import get_logger

_logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple per-API rate limiter (token bucket)."""

    def __init__(self, max_calls: int, period_seconds: float) -> None:
        self.max_calls = max_calls
        self.period = period_seconds
        self._calls: list[float] = []

    def acquire(self) -> bool:
        """Return True if a call is allowed, False if rate-limited."""
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < self.period]
        if len(self._calls) >= self.max_calls:
            return False
        self._calls.append(now)
        return True


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ThreatIndicator:
    """A single threat indicator from one API."""
    source: str
    indicator_type: str  # ip | domain | url | hash
    indicator_value: str
    is_malicious: bool
    confidence: float  # 0.0 – 1.0
    details: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatReport:
    """Aggregated threat report for one indicator across all APIs."""
    indicator_type: str
    indicator_value: str
    indicators: list[ThreatIndicator] = field(default_factory=list)
    overall_malicious: bool = False
    overall_confidence: float = 0.0

    def add(self, ind: ThreatIndicator) -> None:
        self.indicators.append(ind)
        if ind.is_malicious:
            self.overall_malicious = True
            self.overall_confidence = max(self.overall_confidence, ind.confidence)


# ---------------------------------------------------------------------------
# API helper
# ---------------------------------------------------------------------------

def _http_json(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
    timeout: int = 15,
) -> dict[str, Any] | None:
    """Fire an HTTP request and return parsed JSON, or None on failure."""
    hdrs = {"Accept": "application/json", **(headers or {})}
    req = Request(url, headers=hdrs, method=method, data=data)
    try:
        with urlopen(req, timeout=timeout) as resp:  # nosec B310
            return json.load(resp)  # type: ignore[no-any-return]
    except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
        _logger.debug("Threat intel request failed (%s): %s", url[:80], exc)
        return None


# ---------------------------------------------------------------------------
# Individual API clients
# ---------------------------------------------------------------------------

class _VirusTotalClient:
    """VirusTotal v3 API — file hash, URL, and domain lookups."""

    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._limiter = _RateLimiter(max_calls=4, period_seconds=60)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key}

    def check_hash(self, sha256: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            _logger.debug("VirusTotal rate-limited, skipping hash %s", sha256[:16])
            return None
        data = _http_json(f"{self.BASE}/files/{sha256}", headers=self._headers())
        if data is None:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = malicious + suspicious + int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))
        conf = (malicious + suspicious) / max(total, 1)
        return ThreatIndicator(
            source="virustotal",
            indicator_type="hash",
            indicator_value=sha256,
            is_malicious=malicious >= 3,
            confidence=round(conf, 3),
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "reputation": attrs.get("reputation", 0),
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            },
        )

    def check_domain(self, domain: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        data = _http_json(f"{self.BASE}/domains/{domain}", headers=self._headers())
        if data is None:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        return ThreatIndicator(
            source="virustotal",
            indicator_type="domain",
            indicator_value=domain,
            is_malicious=malicious >= 3,
            confidence=round(malicious / max(sum(stats.values()), 1), 3),
            details={"malicious_votes": malicious, "reputation": attrs.get("reputation", 0)},
        )

    def check_url(self, url_str: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        import base64
        url_id = base64.urlsafe_b64encode(url_str.encode()).decode().rstrip("=")
        data = _http_json(f"{self.BASE}/urls/{url_id}", headers=self._headers())
        if data is None:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        return ThreatIndicator(
            source="virustotal",
            indicator_type="url",
            indicator_value=url_str,
            is_malicious=malicious >= 3,
            confidence=round(malicious / max(sum(stats.values()), 1), 3),
            details={"malicious_votes": malicious},
        )


class _AbuseIPDBClient:
    """AbuseIPDB v2 API — IP abuse confidence scoring."""

    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._limiter = _RateLimiter(max_calls=10, period_seconds=60)

    def check_ip(self, ip: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        data = _http_json(
            f"{self.BASE}/check?ipAddress={quote(ip)}&maxAgeInDays=90",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        if data is None:
            return None
        d = data.get("data", {})
        score = int(d.get("abuseConfidenceScore", 0))
        return ThreatIndicator(
            source="abuseipdb",
            indicator_type="ip",
            indicator_value=ip,
            is_malicious=score >= 50,
            confidence=round(score / 100, 3),
            details={
                "abuse_score": score,
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "total_reports": d.get("totalReports", 0),
                "is_tor": d.get("isTor", False),
            },
        )


class _IPAPIClient:
    """ip-api.com — Free IP geolocation + proxy detection (no API key)."""

    # NOTE: ip-api.com free tier only supports HTTP. HTTPS requires a paid plan.
    # We use the free endpoint but log a warning. The data sent is just IP addresses,
    # not credentials.
    BASE = "http://ip-api.com/json"

    def __init__(self) -> None:
        self._limiter = _RateLimiter(max_calls=40, period_seconds=60)

    def check_ip(self, ip: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        data = _http_json(
            f"{self.BASE}/{quote(ip)}?fields=status,country,isp,org,proxy,hosting,as",
        )
        if data is None or data.get("status") != "success":
            return None
        is_proxy = bool(data.get("proxy", False))
        is_hosting = bool(data.get("hosting", False))
        return ThreatIndicator(
            source="ip-api",
            indicator_type="ip",
            indicator_value=ip,
            is_malicious=False,  # ip-api doesn't provide malicious scoring
            confidence=0.0,
            details={
                "country": data.get("country", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "is_proxy": is_proxy,
                "is_hosting": is_hosting,
                "as": data.get("as", ""),
            },
        )


class _URLhausClient:
    """URLhaus (abuse.ch) — Known malicious URL database."""

    BASE = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self) -> None:
        self._limiter = _RateLimiter(max_calls=10, period_seconds=60)

    def check_url(self, url_str: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        data = _http_json(
            f"{self.BASE}/url/",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
            data=f"url={quote(url_str)}".encode(),
        )
        if data is None:
            return None
        status = data.get("query_status", "")
        if status == "no_results":
            return ThreatIndicator(
                source="urlhaus",
                indicator_type="url",
                indicator_value=url_str,
                is_malicious=False,
                confidence=0.0,
                details={"status": "not_found"},
            )
        threat = data.get("threat", "")
        return ThreatIndicator(
            source="urlhaus",
            indicator_type="url",
            indicator_value=url_str,
            is_malicious=True,
            confidence=0.9,
            details={
                "threat": threat,
                "tags": data.get("tags", []),
                "date_added": data.get("date_added", ""),
                "urlhaus_reference": data.get("urlhaus_reference", ""),
            },
        )

    def check_domain(self, domain: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        data = _http_json(
            f"{self.BASE}/host/",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
            data=f"host={quote(domain)}".encode(),
        )
        if data is None:
            return None
        url_count = int(data.get("url_count", 0))
        return ThreatIndicator(
            source="urlhaus",
            indicator_type="domain",
            indicator_value=domain,
            is_malicious=url_count > 0,
            confidence=min(0.9, url_count * 0.15),
            details={"malicious_urls": url_count},
        )


class _MalwareBazaarClient:
    """MalwareBazaar (abuse.ch) — Known malware hash lookup."""

    BASE = "https://mb-api.abuse.ch/api/v1"

    def __init__(self) -> None:
        self._limiter = _RateLimiter(max_calls=10, period_seconds=60)

    def check_hash(self, sha256: str) -> ThreatIndicator | None:
        if not self._limiter.acquire():
            return None
        data = _http_json(
            f"{self.BASE}/",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
            data=f"query=get_info&hash={sha256}".encode(),
        )
        if data is None:
            return None
        status = data.get("query_status", "")
        if status in ("hash_not_found", "no_results"):
            return ThreatIndicator(
                source="malwarebazaar",
                indicator_type="hash",
                indicator_value=sha256,
                is_malicious=False,
                confidence=0.0,
                details={"status": "not_found"},
            )
        d = data.get("data", [{}])[0] if data.get("data") else {}
        return ThreatIndicator(
            source="malwarebazaar",
            indicator_type="hash",
            indicator_value=sha256,
            is_malicious=True,
            confidence=0.95,
            details={
                "signature": d.get("signature", ""),
                "file_type": d.get("file_type", ""),
                "tags": d.get("tags", []),
                "reporter": d.get("reporter", ""),
            },
        )


# ---------------------------------------------------------------------------
# Main aggregator
# ---------------------------------------------------------------------------

class ThreatIntelAggregator:
    """Query multiple threat intelligence APIs and merge results.

    All API keys are optional. When a key is missing, that API is silently
    skipped. The aggregator merges results from all available APIs into a
    single :class:`ThreatReport`.

    Parameters
    ----------
    virustotal_key:
        VirusTotal v3 API key.
    abuseipdb_key:
        AbuseIPDB v2 API key.
    """

    def __init__(
        self,
        virustotal_key: str = "",
        abuseipdb_key: str = "",
    ) -> None:
        self.logger = get_logger(__name__)
        self._vt = _VirusTotalClient(virustotal_key) if virustotal_key else None
        self._abuse = _AbuseIPDBClient(abuseipdb_key) if abuseipdb_key else None
        self._ipapi = _IPAPIClient()
        self._urlhaus = _URLhausClient()
        self._bazaar = _MalwareBazaarClient()

        # Warn about missing optional API keys
        if not virustotal_key:
            self.logger.info("VirusTotal API key not configured — hash/URL/domain lookups disabled")
        if not abuseipdb_key:
            self.logger.info("AbuseIPDB API key not configured — IP reputation lookups disabled")

    @property
    def available_apis(self) -> list[str]:
        """List of APIs that have valid credentials configured."""
        apis = ["ip-api", "urlhaus", "malwarebazaar"]  # Always available (free)
        if self._vt:
            apis.append("virustotal")
        if self._abuse:
            apis.append("abuseipdb")
        return apis

    def check_ip(self, ip: str) -> ThreatReport:
        """Check an IP address against all available APIs."""
        report = ThreatReport(indicator_type="ip", indicator_value=ip)

        # AbuseIPDB
        if self._abuse:
            try:
                result = self._abuse.check_ip(ip)
                if result:
                    report.add(result)
            except Exception as exc:
                self.logger.debug("AbuseIPDB error for %s: %s", ip, exc)

        # ip-api (geolocation + proxy detection)
        try:
            result = self._ipapi.check_ip(ip)
            if result:
                report.add(result)
        except Exception as exc:
            self.logger.debug("ip-api error for %s: %s", ip, exc)

        return report

    def check_domain(self, domain: str) -> ThreatReport:
        """Check a domain against all available APIs."""
        report = ThreatReport(indicator_type="domain", indicator_value=domain)

        if self._vt:
            try:
                result = self._vt.check_domain(domain)
                if result:
                    report.add(result)
            except Exception as exc:
                self.logger.debug("VT domain error for %s: %s", domain, exc)

        try:
            result = self._urlhaus.check_domain(domain)
            if result:
                report.add(result)
        except Exception as exc:
            self.logger.debug("URLhaus domain error for %s: %s", domain, exc)

        return report

    def check_url(self, url: str) -> ThreatReport:
        """Check a URL against all available APIs."""
        report = ThreatReport(indicator_type="url", indicator_value=url)

        if self._vt:
            try:
                result = self._vt.check_url(url)
                if result:
                    report.add(result)
            except Exception as exc:
                self.logger.debug("VT URL error for %s: %s", url[:60], exc)

        try:
            result = self._urlhaus.check_url(url)
            if result:
                report.add(result)
        except Exception as exc:
            self.logger.debug("URLhaus URL error for %s: %s", url[:60], exc)

        return report

    def check_hash(self, sha256: str) -> ThreatReport:
        """Check a file hash against all available APIs."""
        report = ThreatReport(indicator_type="hash", indicator_value=sha256)

        if self._vt:
            try:
                result = self._vt.check_hash(sha256)
                if result:
                    report.add(result)
            except Exception as exc:
                self.logger.debug("VT hash error for %s: %s", sha256[:16], exc)

        try:
            result = self._bazaar.check_hash(sha256)
            if result:
                report.add(result)
        except Exception as exc:
            self.logger.debug("MalwareBazaar hash error for %s: %s", sha256[:16], exc)

        return report

    def bulk_check_network_indicators(
        self,
        ips: list[str] | None = None,
        domains: list[str] | None = None,
        urls: list[str] | None = None,
        max_per_type: int = 10,
    ) -> dict[str, list[ThreatReport]]:
        """Check multiple network indicators in bulk.

        Parameters
        ----------
        ips:
            List of IP addresses to check.
        domains:
            List of domain names to check.
        urls:
            List of URLs to check.
        max_per_type:
            Maximum number of each indicator type to check (to control API usage).

        Returns
        -------
        dict with keys ``ips``, ``domains``, ``urls``, each a list of ThreatReports.
        """
        result: dict[str, list[ThreatReport]] = {"ips": [], "domains": [], "urls": []}

        for ip in (ips or [])[:max_per_type]:
            try:
                report = self.check_ip(ip)
                if report.indicators:
                    result["ips"].append(report)
            except Exception as exc:
                self.logger.warning("Threat intel IP check failed for %s: %s", ip, exc)

        for domain in (domains or [])[:max_per_type]:
            try:
                report = self.check_domain(domain)
                if report.indicators:
                    result["domains"].append(report)
            except Exception as exc:
                self.logger.warning("Threat intel domain check failed for %s: %s", domain, exc)

        for url in (urls or [])[:max_per_type]:
            try:
                report = self.check_url(url)
                if report.indicators:
                    result["urls"].append(report)
            except Exception as exc:
                self.logger.warning("Threat intel URL check failed for %s: %s", url[:60], exc)

        total = sum(len(v) for v in result.values())
        self.logger.info("Threat intel: checked %d indicators", total)
        return result

    def to_findings(self, reports: dict[str, list[ThreatReport]]) -> list[dict[str, Any]]:
        """Convert threat reports to pipeline-compatible finding dicts."""
        findings: list[dict[str, Any]] = []

        for report_list in reports.values():
            for report in report_list:
                if not report.overall_malicious:
                    continue
                # Build a merged detail summary
                sources = [ind.source for ind in report.indicators if ind.is_malicious]
                details = {}
                for ind in report.indicators:
                    details.update(ind.details)

                findings.append({
                    "id": f"threat-intel.{report.indicator_type}",
                    "title": f"Malicious {report.indicator_type} detected: {report.indicator_value}",
                    "severity": "critical" if report.overall_confidence >= 0.7 else "high",
                    "confidence": report.overall_confidence,
                    "category": "threat-intel",
                    "source": f"threat-intel ({', '.join(sources)})",
                    "file": "",
                    "evidence": json.dumps(details, default=str)[:300],
                    "tags": ["threat-intel", report.indicator_type],
                })

        return findings
