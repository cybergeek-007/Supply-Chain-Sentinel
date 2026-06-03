"""
network_analyzer.py
--------------------
Deep static network analysis – extract and classify ALL network indicators
from source files without executing them.

Supported file types
~~~~~~~~~~~~~~~~~~~~
.js  .mjs  .cjs  .ts  .tsx  .jsx  .json  .env  .sh  .py

Detections
~~~~~~~~~~
 1.  All URLs               – every http / https URL found
 2.  Raw IP addresses       – public non-RFC1918 IPs are suspicious
 3.  Dynamic domain construction  – baseUrl + variable + '.evil.com'
 4.  DNS-over-HTTPS         – Cloudflare / Google DoH queries
 5.  Data-URI exfiltration  – fetch('https://…?data=' + btoa(data))
 6.  WebSocket connections  – new WebSocket('ws://…')
 7.  Hard-coded C2 patterns – IP:port combos, base64-encoded URLs
 8.  Paste-site payloads    – fetching from pastebin / hastebin / etc.
 9.  URL shorteners         – bit.ly / tinyurl / etc.
10.  NPM-registry bypass    – fetching packages from non-registry sources
11.  Env-var in URL         – process.env.HOST concatenated into URL
12.  Port scan patterns     – looping through port ranges

Classification
~~~~~~~~~~~~~~
SAFE       – registry.npmjs.org, cdn.jsdelivr.net, unpkg.com, and known CDNs
SUSPICIOUS – unknown external domain
DANGEROUS  – raw public IP, known-bad domain, paste site, URL shortener
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPPORTED_EXTENSIONS = frozenset(
    [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".env", ".sh", ".py"]
)

_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Domains that are considered safe / canonical for the npm ecosystem
_SAFE_DOMAINS = frozenset(
    [
        "registry.npmjs.org",
        "npmjs.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "storage.googleapis.com",
        "raw.githubusercontent.com",
        "github.com",
        "githubusercontent.com",
        "api.github.com",
        "sentry.io",
        "bugsnag.com",
        "newrelic.com",
        "datadog.com",
        "segment.com",
        "amplitude.com",
    ]
)

# Paste / payload hosting sites (DANGEROUS)
_PASTE_DOMAINS = frozenset(
    [
        "pastebin.com",
        "pastebin.pl",
        "hastebin.com",
        "paste.ee",
        "ghostbin.com",
        "justpaste.it",
        "dpaste.org",
        "controlc.com",
        "paste2.org",
        "rentry.co",
        "0paste.com",
        "privatbin.net",
    ]
)

# URL shorteners (DANGEROUS – hide actual destination)
_SHORTENER_DOMAINS = frozenset(
    [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "short.link",
        "buff.ly",
        "is.gd",
        "rb.gy",
        "cutt.ly",
        "tiny.cc",
        "shorturl.at",
    ]
)

# DNS-over-HTTPS endpoints (suspicious in npm packages)
_DOH_DOMAINS = frozenset(
    [
        "cloudflare-dns.com",
        "1.1.1.1",
        "8.8.8.8",
        "dns.google",
        "doh.opendns.com",
    ]
)

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Generic URL extractor (http / https / ws / wss)
_RE_URL = re.compile(
    r"""(?:https?|wss?|ftp)://[^\s'"`,;\)\]>]{3,}""",
    re.IGNORECASE,
)

# Raw IPv4 addresses (possibly with port)
_RE_IPV4 = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{2,5}))?\b"
)

# IP:port combo (explicit – no surrounding context needed)
_RE_IP_PORT = re.compile(
    r"""['"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})['"]"""
)

# WebSocket instantiation
_RE_WS = re.compile(
    r"""new\s+WebSocket\s*\(\s*['"`]?(wss?://[^\s'"`,;)]{3,})""",
    re.IGNORECASE,
)

# Dynamic URL construction: variable + string fragment with a TLD-like suffix
_RE_DYN_URL = re.compile(
    r"""(?:https?['"]\s*\+\s*\w|(?:\w+)\s*\+\s*['"]\.[a-z]{2,6}['"])""",
    re.IGNORECASE,
)

# Data exfiltration via query param: fetch('…?data=' + …)
_RE_EXFIL = re.compile(
    r"""fetch\s*\(\s*['"`][^'"`;)]+\?[^='"`;)]*=\s*['"`]?\s*\+""",
    re.IGNORECASE,
)

# btoa / atob combined with fetch / XMLHttpRequest
_RE_B64_EXFIL = re.compile(
    r"""(?:fetch|XMLHttpRequest|axios)\s*[\.(].+?(?:btoa|encodeURI(?:Component)?)\s*\(""",
    re.IGNORECASE | re.DOTALL,
)

# process.env.* in string concatenation context
_RE_ENV_IN_URL = re.compile(
    r"""(?:https?['"]\s*\+|`https?://[^`]*\$\{)\s*process\.env\.""",
    re.IGNORECASE,
)

# Port scan: for loop iterating over port range
_RE_PORT_SCAN = re.compile(
    r"""for\s*\(.*?(?:port|p)\s*=\s*\d+\s*;.*?(?:port|p)\s*[<>]=?\s*\d+\s*;.*?(?:port|p)\s*\+""",
    re.IGNORECASE | re.DOTALL,
)

# NPM registry bypass: require / fetch of non-registry npm URL
_RE_NPM_BYPASS = re.compile(
    r"""(?:require|fetch|import)\s*\(['"](https?://(?!registry\.npmjs\.org)[^'"]+\.(?:tgz|tar\.gz|zip))['"]\)""",
    re.IGNORECASE,
)

# Hard-coded base64 URL (base64 string that decodes to a URL)
_RE_B64_URL_HINT = re.compile(
    r"""atob\s*\(\s*['"]([A-Za-z0-9+/]{20,}={0,2})['"]\s*\)""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class _NetworkIndicator(NamedTuple):
    indicator: str           # URL / IP / domain string
    indicator_type: str      # 'url', 'ip', 'websocket', etc.
    classification: str      # 'SAFE', 'SUSPICIOUS', 'DANGEROUS'
    reason: str              # human-readable explanation
    file: str                # source file path
    line: int                # line number (1-based)


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _classify_domain(domain: str) -> tuple[str, str]:
    """Return (classification, reason) for a domain name."""
    domain = domain.lower().rstrip(".")

    for safe in _SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return "SAFE", f"Known trusted domain: {safe}"

    for paste in _PASTE_DOMAINS:
        if domain == paste or domain.endswith("." + paste):
            return "DANGEROUS", f"Known paste/payload hosting site: {paste}"

    for shortener in _SHORTENER_DOMAINS:
        if domain == shortener or domain.endswith("." + shortener):
            return "DANGEROUS", f"URL shortener (hides destination): {shortener}"

    for doh in _DOH_DOMAINS:
        if domain == doh or domain.endswith("." + doh):
            return "DANGEROUS", f"DNS-over-HTTPS endpoint (evades DNS monitoring): {doh}"

    return "SUSPICIOUS", f"Unknown external domain: {domain}"


def _classify_ip(ip_str: str) -> tuple[str, str]:
    """Return (classification, reason) for a raw IP address string."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "SUSPICIOUS", f"Could not parse IP: {ip_str}"

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "SUSPICIOUS", f"Private/loopback IP in source: {ip_str}"
    if addr.is_reserved or addr.is_multicast:
        return "SUSPICIOUS", f"Reserved/multicast IP: {ip_str}"
    return "DANGEROUS", f"Public (non-RFC1918) IP address hard-coded in source: {ip_str}"


def _extract_domain(url: str) -> str | None:
    """Extract the hostname from a URL string."""
    m = re.match(r"https?://([^/:?\s#]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _line_number(source: str, pos: int) -> int:
    """Convert a character position to a 1-based line number."""
    return source[:pos].count("\n") + 1


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class NetworkAnalyzer:
    """
    Statically analyse source files in a directory for network indicators
    (URLs, IPs, WebSockets, exfiltration patterns, etc.) without executing
    any code.

    Usage::

        analyzer = NetworkAnalyzer()
        result = analyzer.analyze_directory("/path/to/project")
    """

    def analyze_directory(self, directory: str) -> dict[str, Any]:
        """
        Walk *directory* recursively and analyse every supported source file.

        Parameters
        ----------
        directory:
            Absolute or relative path to the root directory to analyse.

        Returns
        -------
        dict with keys:
            ``directory``            – canonical directory path
            ``files_scanned``        – number of files analysed
            ``indicators``           – list of indicator dicts
            ``summary``              – aggregated counts by classification
            ``dangerous_count``      – shortcut count
            ``suspicious_count``     – shortcut count
            ``safe_count``           – shortcut count
            ``unique_domains``       – sorted list of unique external domains
            ``unique_ips``           – sorted list of unique raw IPs found
        """
        canonical = os.path.realpath(directory)
        indicators: list[dict[str, Any]] = []
        files_scanned = 0

        for root, _dirs, files in os.walk(canonical):
            # Skip node_modules / .git
            _dirs[:] = [
                d for d in _dirs
                if d not in ("node_modules", ".git", ".svn", "__pycache__", "dist", "build")
            ]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in _SUPPORTED_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    file_indicators = self._analyze_file(fpath)
                    indicators.extend(file_indicators)
                    files_scanned += 1
                except OSError as exc:
                    logger.warning("Could not read %s: %s", fpath, exc)

        # Build summary
        cls_counts: dict[str, int] = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
        unique_domains: set[str] = set()
        unique_ips: set[str] = set()

        for ind in indicators:
            cls_counts[ind.get("classification", "SUSPICIOUS")] = (
                cls_counts.get(ind.get("classification", "SUSPICIOUS"), 0) + 1
            )
            if ind.get("indicator_type") == "ip":
                unique_ips.add(ind["indicator"])
            else:
                domain = _extract_domain(ind.get("indicator", ""))
                if domain:
                    unique_domains.add(domain)

        return {
            "directory": canonical,
            "files_scanned": files_scanned,
            "indicators": [self._indicator_to_dict(i) for i in indicators],
            "summary": cls_counts,
            "dangerous_count": cls_counts["DANGEROUS"],
            "suspicious_count": cls_counts["SUSPICIOUS"],
            "safe_count": cls_counts["SAFE"],
            "unique_domains": sorted(unique_domains),
            "unique_ips": sorted(unique_ips),
        }

    def analyze_file(self, file_path: str) -> dict[str, Any]:
        """
        Analyse a single file and return the same schema as
        :meth:`analyze_directory` but scoped to one file.
        """
        canonical = os.path.realpath(file_path)
        try:
            indicators = self._analyze_file(canonical)
        except OSError as exc:
            return {"error": str(exc), "file": canonical, "indicators": []}

        cls_counts: dict[str, int] = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
        for ind in indicators:
            cls_counts[ind.classification] = cls_counts.get(ind.classification, 0) + 1

        return {
            "file": canonical,
            "indicators": [self._indicator_to_dict(i) for i in indicators],
            "summary": cls_counts,
            "dangerous_count": cls_counts["DANGEROUS"],
            "suspicious_count": cls_counts["SUSPICIOUS"],
            "safe_count": cls_counts["SAFE"],
        }

    # ------------------------------------------------------------------
    # Private – per-file analysis
    # ------------------------------------------------------------------

    def _analyze_file(self, file_path: str) -> list[_NetworkIndicator]:
        """Run all network extraction heuristics on a single file."""
        size = os.path.getsize(file_path)
        if size > _MAX_FILE_SIZE:
            logger.warning("Skipping oversized file: %s (%d bytes)", file_path, size)
            return []

        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()

        results: list[_NetworkIndicator] = []

        results.extend(self._extract_urls(source, file_path))
        results.extend(self._extract_ips(source, file_path))
        results.extend(self._extract_websockets(source, file_path))
        results.extend(self._detect_dynamic_url(source, file_path))
        results.extend(self._detect_exfiltration(source, file_path))
        results.extend(self._detect_env_in_url(source, file_path))
        results.extend(self._detect_port_scan(source, file_path))
        results.extend(self._detect_npm_bypass(source, file_path))
        results.extend(self._detect_b64_url(source, file_path))

        return results

    # ------------------------------------------------------------------
    # Extraction methods
    # ------------------------------------------------------------------

    def _extract_urls(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Extract and classify all http/https/ws/wss URLs from source."""
        results: list[_NetworkIndicator] = []
        seen: set[str] = set()

        for m in _RE_URL.finditer(source):
            url = m.group(0).rstrip(".,;)'\"")
            if url in seen:
                continue
            seen.add(url)

            line = _line_number(source, m.start())
            domain = _extract_domain(url)
            if not domain:
                continue

            cls, reason = _classify_domain(domain)
            ind_type = "websocket" if url.lower().startswith(("ws://", "wss://")) else "url"
            results.append(
                _NetworkIndicator(url, ind_type, cls, reason, file_path, line)
            )
        return results

    def _extract_ips(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Extract and classify raw IPv4 addresses (with optional port)."""
        results: list[_NetworkIndicator] = []
        seen: set[str] = set()

        for m in _RE_IPV4.finditer(source):
            ip_str = m.group(1)
            port = m.group(2)
            key = f"{ip_str}:{port}" if port else ip_str
            if key in seen:
                continue
            seen.add(key)

            line = _line_number(source, m.start())
            cls, reason = _classify_ip(ip_str)
            indicator = key
            if port:
                reason += f" (port {port})"
                cls = "DANGEROUS"  # hard-coded IP:port is always dangerous
            results.append(
                _NetworkIndicator(indicator, "ip", cls, reason, file_path, line)
            )
        return results

    def _extract_websockets(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Extract explicit WebSocket constructor calls."""
        results: list[_NetworkIndicator] = []
        for m in _RE_WS.finditer(source):
            url = m.group(1)
            line = _line_number(source, m.start())
            domain = _extract_domain(url.replace("wss://", "https://").replace("ws://", "http://"))
            if not domain:
                cls, reason = "SUSPICIOUS", "WebSocket URL without parseable domain"
            else:
                cls, reason = _classify_domain(domain)
            reason = f"WebSocket connection: {reason}"
            results.append(
                _NetworkIndicator(url, "websocket", cls, reason, file_path, line)
            )
        return results

    def _detect_dynamic_url(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Detect dynamic URL construction via string concatenation."""
        results: list[_NetworkIndicator] = []
        for m in _RE_DYN_URL.finditer(source):
            snippet = source[max(0, m.start() - 20): m.end() + 20].replace("\n", " ")
            line = _line_number(source, m.start())
            results.append(
                _NetworkIndicator(
                    snippet.strip(),
                    "dynamic_url",
                    "SUSPICIOUS",
                    "Dynamic URL construction detected (may hide real destination)",
                    file_path,
                    line,
                )
            )
        return results

    def _detect_exfiltration(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Detect data exfiltration via URL query parameters."""
        results: list[_NetworkIndicator] = []
        for m in _RE_EXFIL.finditer(source):
            snippet = source[m.start(): m.end() + 40].replace("\n", " ")
            line = _line_number(source, m.start())
            results.append(
                _NetworkIndicator(
                    snippet[:120].strip(),
                    "exfiltration",
                    "DANGEROUS",
                    "Data exfiltration pattern: fetch with dynamic query parameter",
                    file_path,
                    line,
                )
            )

        for m in _RE_B64_EXFIL.finditer(source):
            snippet = source[m.start(): m.end()].replace("\n", " ")
            line = _line_number(source, m.start())
            results.append(
                _NetworkIndicator(
                    snippet[:120].strip(),
                    "exfiltration",
                    "DANGEROUS",
                    "Base64 encoded data sent via network (potential exfiltration)",
                    file_path,
                    line,
                )
            )
        return results

    def _detect_env_in_url(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Detect environment variable values concatenated into URLs."""
        results: list[_NetworkIndicator] = []
        for m in _RE_ENV_IN_URL.finditer(source):
            snippet = source[m.start(): m.end() + 30].replace("\n", " ")
            line = _line_number(source, m.start())
            results.append(
                _NetworkIndicator(
                    snippet[:120].strip(),
                    "env_in_url",
                    "SUSPICIOUS",
                    "process.env variable concatenated into URL (dynamic endpoint selection)",
                    file_path,
                    line,
                )
            )
        return results

    def _detect_port_scan(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Detect port-scanning loops."""
        results: list[_NetworkIndicator] = []
        for m in _RE_PORT_SCAN.finditer(source):
            snippet = source[m.start(): m.end()].replace("\n", " ")
            line = _line_number(source, m.start())
            results.append(
                _NetworkIndicator(
                    snippet[:120].strip(),
                    "port_scan",
                    "DANGEROUS",
                    "Port scanning loop detected",
                    file_path,
                    line,
                )
            )
        return results

    def _detect_npm_bypass(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Detect fetching npm packages from non-registry sources."""
        results: list[_NetworkIndicator] = []
        for m in _RE_NPM_BYPASS.finditer(source):
            url = m.group(1)
            line = _line_number(source, m.start())
            results.append(
                _NetworkIndicator(
                    url,
                    "npm_bypass",
                    "DANGEROUS",
                    "Package fetched from non-registry URL (npm registry bypass)",
                    file_path,
                    line,
                )
            )
        return results

    def _detect_b64_url(self, source: str, file_path: str) -> list[_NetworkIndicator]:
        """Detect base64-encoded URLs passed to atob()."""
        import base64  # local import – stdlib
        results: list[_NetworkIndicator] = []
        for m in _RE_B64_URL_HINT.finditer(source):
            b64 = m.group(1)
            line = _line_number(source, m.start())
            try:
                decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
                if decoded.startswith(("http://", "https://", "ws://", "wss://")):
                    domain = _extract_domain(decoded)
                    cls, reason = _classify_domain(domain) if domain else ("SUSPICIOUS", "No domain")
                    results.append(
                        _NetworkIndicator(
                            decoded[:200],
                            "b64_encoded_url",
                            "DANGEROUS",
                            f"Base64-encoded URL decoded from source: {reason}",
                            file_path,
                            line,
                        )
                    )
            except Exception:  # noqa: BLE001
                pass
        return results

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def _indicator_to_dict(ind: _NetworkIndicator) -> dict[str, Any]:
        return {
            "indicator": ind.indicator,
            "indicator_type": ind.indicator_type,
            "classification": ind.classification,
            "reason": ind.reason,
            "file": ind.file,
            "line": ind.line,
        }
