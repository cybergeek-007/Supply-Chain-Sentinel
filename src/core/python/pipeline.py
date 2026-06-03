"""Analysis pipeline orchestrator for Supply Chain Sentinel.

Coordinates all analysis phases in sequence:
  metadata → typosquat → extraction → entropy → static → obfuscation → network → [dynamic]

Aggregates findings from every phase, computes risk score, and returns
a unified result dict consumable by the CLI display layer.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any, Callable

try:
    from src.core.python.cache import ResultCache
    _HAS_CACHE = True
except Exception:
    _HAS_CACHE = False

from src.core.python.config import SentinelConfig
from src.core.python.logger import get_logger
from src.modules.entropy import ShannonEntropyCalculator
from src.modules.extractor import PackageExtractor
from src.modules.static_analyzer import StaticAnalyzer

# Optional modules — graceful import so the tool doesn't crash
# if a module has issues.
try:
    from src.modules.obfuscation_detector import ObfuscationDetector
    _HAS_OBFUSCATION = True
except Exception:
    _HAS_OBFUSCATION = False

try:
    from src.modules.metadata_analyzer import MetadataAnalyzer
    _HAS_METADATA = True
except Exception:
    _HAS_METADATA = False

try:
    from src.modules.network_analyzer import NetworkAnalyzer
    _HAS_NETWORK = True
except Exception:
    _HAS_NETWORK = False

try:
    from src.modules.typosquat_detector import TyposquatDetector
    _HAS_TYPOSQUAT = True
except Exception:
    _HAS_TYPOSQUAT = False

try:
    from src.modules.dynamic_sandbox import DynamicSandbox
    _HAS_DYNAMIC = True
except Exception:
    _HAS_DYNAMIC = False

try:
    from src.modules.behavior_monitor import BehaviorMonitor
    _HAS_BEHAVIOR = True
except Exception:
    _HAS_BEHAVIOR = False

try:
    from src.modules.virustotal import VirusTotalClient
    _HAS_VT = True
except Exception:
    _HAS_VT = False

try:
    from src.modules.evasion_detector import EvasionDetector
    _HAS_EVASION = True
except Exception:
    _HAS_EVASION = False

try:
    from src.modules.threat_intel import ThreatIntelAggregator
    _HAS_THREAT_INTEL = True
except Exception:
    _HAS_THREAT_INTEL = False

try:
    from src.modules.ai_explainer import AIAnalyzer
    _HAS_AI = True
except Exception:
    _HAS_AI = False

try:
    from src.modules.npm_registry import (
        stage_npm_package_archive,
        split_package_spec,
    )
    _HAS_NPM = True
except Exception:
    _HAS_NPM = False

try:
    import sentinel_core  # type: ignore[import-not-found]
except ModuleNotFoundError:
    sentinel_core = None


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 30.0,
    "high":     12.0,
    "medium":    3.0,
    "low":       0.5,
    "info":      0.1,
}


def _compute_risk_score(findings: list[dict[str, Any]]) -> tuple[int, str]:
    """Compute a 0-100 risk score with diminishing returns.

    Uses a logarithmic curve so that many low-severity findings
    don't spike the score to CRITICAL. A single critical finding
    still pushes the score high.
    """
    import math

    if not findings:
        return 0, "LOW"

    # Count by severity for weighted scoring
    raw_total = 0.0
    has_critical = False
    has_high = False
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        confidence = float(f.get("confidence", 0.8))
        weight = _SEVERITY_WEIGHTS.get(sev, 0.5)
        raw_total += weight * confidence
        if sev == "critical":
            has_critical = True
        elif sev == "high":
            has_high = True

    # Diminishing returns curve: score = 100 * (1 - e^(-raw/k))
    # k controls how fast the curve saturates
    k = 60.0
    score = int(round(100 * (1 - math.exp(-raw_total / k))))
    score = max(0, min(100, score))

    # Ensure critical findings always push score appropriately
    if has_critical and score < 75:
        score = max(score, 75)
    elif has_high and score < 25:
        score = max(score, 25)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def _verdict(level: str) -> tuple[str, str]:
    """Return (verdict_text, recommendation) for a risk level."""
    if level == "CRITICAL":
        return "MALICIOUS", "Do NOT install. Package exhibits strong indicators of malicious behavior."
    if level == "HIGH":
        return "SUSPICIOUS", "Manual security review required before use."
    if level == "MEDIUM":
        return "CAUTION", "Some indicators found. Review findings before proceeding."
    return "SAFE", "No significant risk indicators detected."


# ---------------------------------------------------------------------------
# Finding normalisation
# ---------------------------------------------------------------------------

# Files/directories where findings are less concerning (test code, docs, etc.)
_LOW_RISK_PATH_PATTERNS = {
    "test", "tests", "__tests__", "spec", "specs",
    "perf", "benchmark", "benchmarks", "example", "examples",
    "doc", "docs", "documentation",
}

_DOC_EXTENSIONS = {".md", ".txt", ".rst", ".html", ".htm", ".adoc", ".map"}


def _adjust_finding_severity(f: dict[str, Any]) -> dict[str, Any]:
    """Adjust severity based on context to reduce false positives.

    The static analyzer's regex rules fire on many legitimate Node.js patterns.
    This function provides contextual adjustment so that:
      - express using require('http') isn't flagged as "exfiltration"
      - chalk using process.env isn't flagged as "credential access"
      - eval() in test files isn't HIGH severity
    """
    file_path = f.get("file", "").replace("\\", "/").lower()
    title = f.get("title", "").lower()
    evidence = f.get("evidence", "").lower()

    # Check if finding is in test/doc/perf files
    parts = set(file_path.split("/"))
    in_test_dir = bool(parts & _LOW_RISK_PATH_PATTERNS)

    # Check if it's a documentation file
    is_doc_file = any(file_path.endswith(ext) for ext in _DOC_EXTENSIONS)

    # Check if it's in library source (lib/, src/, vendor/)
    in_lib_dir = bool(parts & {"lib", "src", "source", "vendor", "dist"})

    # ---- Context-aware downgrade rules ----

    # 1) "Interesting string" from docs/README → filter out
    if "interesting string" in title and (is_doc_file or "readme" in file_path):
        f["severity"] = "info"
        f["confidence"] = 0.1
        return f

    # 2) "Interesting string" from any file → low
    if "interesting string" in title:
        f["severity"] = "low"
        f["confidence"] = 0.2
        return f

    # 3) "Network or exfiltration" findings
    if "network" in title or "exfiltration" in title:
        # Type definition files -> noise
        if file_path.endswith(".d.ts"):
            f["severity"] = "info"
            f["confidence"] = 0.1
            return f
        # Documentation files -> noise
        if is_doc_file or "readme" in file_path:
            f["severity"] = "info"
            f["confidence"] = 0.1
            return f
        # In library or package root code, HTTP/network usage is usually legitimate
        # Most npm packages put their main code at root level (index.js, etc.)
        if not any(kw in evidence for kw in [
            "pastebin", "ngrok", "webhook.site", "requestbin",
            "base64", "encode", "exfiltrat",
        ]):
            # Only keep high severity if evidence contains actual suspicious targets
            if any(kw in evidence for kw in [
                "process.env", ".npmrc", ".ssh", "id_rsa", "aws_",
                "npm_token", "github_token", "password",
            ]):
                f["severity"] = "medium"
                f["confidence"] = 0.5
            else:
                f["severity"] = "low"
                f["confidence"] = 0.2
            return f

    # 4) "Dynamic code evaluation" (eval/Function) in library code
    #    Libraries like Express, dotenv legitimately use eval() and new Function()
    #    Many packages put main code at root level, not in lib/src/
    if "dynamic code eval" in title:
        if in_lib_dir:
            f["severity"] = "low"
            f["confidence"] = 0.25
            return f
        # Even outside lib directories, eval in non-test code isn't automatically
        # malicious — downgrade from high to medium
        if not in_test_dir:
            f["severity"] = "medium"
            f["confidence"] = 0.4
            return f

    # 5) "Command execution" (child_process / exec)
    #    Static analyzer fires on \bexec\s*\( which matches both
    #    child_process.exec() (dangerous) and RegExp.exec() (normal)
    if "command execution" in title:
        # Check if evidence suggests actual shell exec vs regex exec
        dangerous_patterns = [
            "child_process", "spawn", "execfile", "execsync",
            "shell", "bin/sh", "cmd.exe", "powershell",
        ]
        is_actually_dangerous = any(p in evidence for p in dangerous_patterns)

        if not is_actually_dangerous:
            # Likely RegExp.exec() or similar - not a real threat
            f["severity"] = "low"
            f["confidence"] = 0.15
            return f
        elif in_lib_dir:
            f["severity"] = "medium"
            f["confidence"] = 0.4
            return f

    # 6) "Credential access" via process.env — very common in all Node apps
    if "credential" in title or "secret" in title:
        # In library code, process.env access is virtually always for config
        if in_lib_dir:
            f["severity"] = "low"
            f["confidence"] = 0.2
            return f
        # Even outside lib, only truly suspicious if targeting known secrets
        if "process.env" in evidence or "process\\.env" in evidence:
            has_secret_target = any(kw in evidence for kw in [
                "npm_token", "aws_access", "aws_secret", "github_token",
                "_authtoken", ".npmrc", "id_rsa", ".ssh",
                "password", "passwd", "credential",
            ])
            if not has_secret_target:
                f["severity"] = "low"
                f["confidence"] = 0.25
                return f

    # 7) "Signature match: suspicious_npm_postinstall" / "preinstall" findings
    #    The real threat is postinstall scripts in package.json.
    #    When this fires in .js/.ts/.md/.map files, it's matching the word
    #    "install" or lifecycle-related strings, not actual malicious scripts.
    if "postinstall" in title or "preinstall" in title:
        file_ext = file_path.rsplit(".", 1)[-1] if "." in file_path else ""
        # Docs, markdown, changelogs, source maps → noise
        if file_ext in ("md", "txt", "rst", "html", "htm", "adoc", "map"):
            f["severity"] = "info"
            f["confidence"] = 0.05
            return f
        # JS/TS source code mentioning postinstall → low risk
        if file_ext in ("js", "jsx", "ts", "tsx", "mjs", "cjs"):
            f["severity"] = "low"
            f["confidence"] = 0.15
            return f

    # 8) "Lifecycle script: prepare" is a standard npm lifecycle script.
    #    It runs on `npm install` from git repos and typically does
    #    compilation (tsc, node-gyp). Only preinstall/postinstall are suspicious.
    if "lifecycle script" in title:
        if "prepare" in title or "prepublish" in title or "build" in title:
            f["severity"] = "low"
            f["confidence"] = 0.15
            return f

    # 8) Findings in test/benchmark/example directories — downgrade
    if in_test_dir:
        sev = f.get("severity", "low")
        if sev == "critical":
            f["severity"] = "high"
            f["confidence"] = float(f.get("confidence", 0.8)) * 0.5
        elif sev == "high":
            f["severity"] = "medium"
            f["confidence"] = float(f.get("confidence", 0.8)) * 0.4
        elif sev == "medium":
            f["severity"] = "low"
            f["confidence"] = float(f.get("confidence", 0.8)) * 0.3

    return f


def _relativize_path(file_path: str, staging_dir: str = "") -> str:
    """Strip staging dir prefix and normalise path separators."""
    if not file_path:
        return file_path

    # Normalise separators
    normalized = file_path.replace("\\", "/")

    # Strip staging dir prefix if present
    if staging_dir:
        staging_norm = staging_dir.replace("\\", "/")
        if normalized.startswith(staging_norm):
            normalized = normalized[len(staging_norm):].lstrip("/")

    # Also strip temp directory paths
    import tempfile
    tmp = tempfile.gettempdir().replace("\\", "/")
    if normalized.startswith(tmp):
        # Find the package directory name after staging
        normalized = normalized[len(tmp):].lstrip("/")
        # Strip "sentinel_staging/" prefix
        if normalized.startswith("sentinel_staging/"):
            normalized = normalized[len("sentinel_staging/"):]
        # Strip package-name directory (e.g., "left-pad/")
        parts = normalized.split("/", 1)
        if len(parts) > 1:
            normalized = parts[1]

    return normalized


def _normalize_finding(
    f: dict[str, Any],
    source: str,
    default_severity: str = "medium",
    staging_dir: str = "",
) -> dict[str, Any]:
    """Normalise a raw finding dict into a consistent schema."""
    file_path = str(f.get("file", ""))
    file_path = _relativize_path(file_path, staging_dir)

    result = {
        "id":          str(f.get("id", f.get("finding_id", "unknown"))),
        "title":       str(f.get("title", f.get("rule", "Unknown"))),
        "severity":    str(f.get("severity", default_severity)).lower(),
        "confidence":  float(f.get("confidence", 0.8)),
        "category":    str(f.get("category", source)),
        "source":      source,
        "file":        file_path,
        "evidence":    str(f.get("evidence", f.get("description", ""))),
        "tags":        list(f.get("tags", [])),
    }
    return _adjust_finding_severity(result)


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by (id, file, evidence) and sort by severity."""
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for f in findings:
        # Skip info-level findings to reduce noise
        if f.get("severity") == "info" and f.get("confidence", 1.0) < 0.3:
            continue
        key = (f["id"], f["file"], f["evidence"][:200])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    deduped.sort(
        key=lambda x: (-severity_order.get(x["severity"], 0), x["file"], x["title"])
    )

    # Anti-flooding: if a finding title appears in 10+ files, consolidate
    return _consolidate_flooding(deduped)


def _consolidate_flooding(
    findings: list[dict[str, Any]],
    threshold: int = 10,
) -> list[dict[str, Any]]:
    """Consolidate repeated finding types that appear in many files.

    When the same finding title fires in 10+ distinct files, it's a code pattern
    (e.g., lodash importing helpers in every file), not individual malicious actions.
    We keep 3 representative examples and add a summary note, downgrading severity.
    """
    from collections import Counter

    # Count occurrences per title
    title_counts: Counter[str] = Counter()
    for f in findings:
        title_counts[f["title"]] += 1

    # Find flooded titles
    flooded = {t for t, c in title_counts.items() if c >= threshold}
    if not flooded:
        return findings

    result: list[dict[str, Any]] = []
    flooded_seen: dict[str, list[dict[str, Any]]] = {}

    for f in findings:
        if f["title"] not in flooded:
            result.append(f)
        else:
            title = f["title"]
            if title not in flooded_seen:
                flooded_seen[title] = []
            flooded_seen[title].append(f)

    # For each flooded title, keep up to 3 examples (downgraded) plus a summary
    for title, items in flooded_seen.items():
        count = len(items)
        # Keep first 3 as examples, downgrade severity
        for item in items[:3]:
            if item["severity"] in ("critical", "high"):
                item["severity"] = "low"
            item["confidence"] = min(item.get("confidence", 0.5), 0.2)
            result.append(item)

        # Add summary finding
        result.append({
            "id": "pattern-flood",
            "title": f"{title} (×{count} files — code pattern)",
            "severity": "info",
            "confidence": 0.1,
            "category": "pattern",
            "source": "pipeline",
            "file": "",
            "evidence": f"This finding appeared in {count} files, suggesting a consistent code pattern rather than malicious intent.",
            "tags": ["pattern-flood"],
        })

    return result


# ---------------------------------------------------------------------------
# Pipeline class
# ---------------------------------------------------------------------------

class AnalysisPipeline:
    """High-level orchestrator for all analysis phases.

    Supports three entry modes:
      - analyze_npm()        — fetch from npm registry, then full analysis
      - analyze_file()       — analyse a local .tgz archive
      - analyze_directory()  — analyse a pre-extracted directory

    All methods are synchronous. The pipeline handles async internally.
    """

    def __init__(self, config: SentinelConfig, *, no_cache: bool = False) -> None:
        self.config = config
        self.logger = get_logger(__name__)
        self._extractor = PackageExtractor(config.staging_dir)
        self._static = StaticAnalyzer(rules_dir=config.rules_dir)
        
        # Initialize result cache
        if _HAS_CACHE and not no_cache:
            self._cache = ResultCache(enabled=True)
        else:
            self._cache = None
        
        # Initialize threat intel with config keys
        if _HAS_THREAT_INTEL:
            self._threat_intel = ThreatIntelAggregator(
                virustotal_key=getattr(config, "virustotal_api_key", ""),
                abuseipdb_key=getattr(config, "abuseipdb_api_key", ""),
            )
        else:
            self._threat_intel = None
            
        # Initialize AI analyzer
        if _HAS_AI:
            self._ai_analyzer = AIAnalyzer(
                provider=getattr(config, "ai_provider", ""),
                api_key=getattr(config, "ai_api_key", ""),
                model=getattr(config, "ai_model", ""),
                enabled=getattr(config, "ai_enabled", False),
            )
        else:
            self._ai_analyzer = None

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def analyze_npm(
        self,
        package_spec: str,
        *,
        dynamic: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Fetch an npm package and run full analysis."""
        if not _HAS_NPM:
            raise RuntimeError("npm registry module unavailable")
        if not package_spec:
            raise ValueError("package_spec must not be empty")

        # Parse package spec
        pkg_name, pkg_version = split_package_spec(package_spec)

        # Check cache first
        cache_mode = "static" if not dynamic else "full"
        if self._cache is not None:
            cache_key = self._cache.make_key(pkg_name, pkg_version or "latest", cache_mode)
            cached = self._cache.get(cache_key)
            if cached is not None:
                self.logger.info("Cache hit for %s@%s", pkg_name, pkg_version)
                return cached
        else:
            cache_key = None

        start = time.monotonic()
        all_findings: list[dict[str, Any]] = []
        phases: dict[str, Any] = {}

        # Ensure we don't double-append the version in the display name
        display_name = pkg_name

        # Phase 1: Metadata analysis (registry only)
        if _HAS_METADATA:
            try:
                meta = MetadataAnalyzer()
                meta_result = meta.analyze(pkg_name, version=pkg_version)
                phases["metadata"] = meta_result
                for f in meta_result.get("findings", []):
                    all_findings.append(_normalize_finding(f, "metadata"))
            except Exception as exc:
                phases["metadata"] = {"status": "error", "error": str(exc)}
                self.logger.warning("Metadata analysis failed: %s", exc)

        # Phase 2: Typosquatting detection
        if _HAS_TYPOSQUAT:
            try:
                typo = TyposquatDetector()
                typo_result = typo.analyze(pkg_name)
                phases["typosquat"] = typo_result
                for f in typo_result.get("findings", []):
                    all_findings.append(_normalize_finding(f, "typosquat"))
            except Exception as exc:
                phases["typosquat"] = {"status": "error", "error": str(exc)}
                self.logger.warning("Typosquat detection failed: %s", exc)

        # Phase 3: Download package
        staging_dir = Path(self.config.staging_dir)
        analysis_id = str(uuid.uuid4())
        try:
            resolved_name, archive_path = stage_npm_package_archive(
                package_spec=package_spec,
                staging_dir=staging_dir,
                analysis_id=analysis_id,
                max_size_bytes=int(self.config.max_package_size),
            )
            phases["download"] = {"status": "success", "resolved": resolved_name}
        except (ValueError, OSError) as exc:
            duration = time.monotonic() - start
            return {
                "package_name": package_spec,
                "package_version": pkg_version or "latest",
                "status": "error",
                "analysis_time": round(duration, 2),
                "phases": phases,
                "findings": _dedupe_findings(all_findings),
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "verdict": "ERROR",
                "recommendation": f"Could not download package: {exc}",
                "error": str(exc),
            }

        try:
            # Continue with file-based analysis
            # Extract version from resolved_name if it includes @version
            actual_name = resolved_name
            actual_version = pkg_version or ""
            if "@" in resolved_name:
                # resolved_name may be like "left-pad@1.3.0"
                parts = resolved_name.rsplit("@", 1)
                if len(parts) == 2 and parts[1][0:1].isdigit():
                    actual_name = parts[0]
                    actual_version = parts[1]

            result = self._analyze_archive(
                archive_path=str(archive_path),
                package_name=actual_name,
                existing_phases=phases,
                existing_findings=all_findings,
                dynamic=dynamic,
                timeout=timeout,
                start_time=start,
            )
            # Ensure version is set
            if actual_version:
                result["package_version"] = actual_version
            return result
        finally:
            archive_path.unlink(missing_ok=True)

    def analyze_file(
        self,
        path: str,
        *,
        package_name: str | None = None,
        dynamic: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Analyse a local .tgz package archive."""
        resolved = Path(path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Package path not found: {path}")

        # Extract a clean package name from the filename
        # e.g., "is-odd-3.0.1.tgz" → "is-odd", "chalk-5.3.0.tgz" → "chalk"
        name = package_name
        if not name:
            stem = resolved.stem
            # Try to strip version suffix (e.g., "-3.0.1", "-1.0.0-beta.1")
            import re
            version_match = re.search(r'-(\d+\.\d+\.\d+.*)$', stem)
            if version_match:
                name = stem[:version_match.start()]
            else:
                name = stem
        start = time.monotonic()
        return self._analyze_archive(
            archive_path=str(resolved),
            package_name=name,
            existing_phases={},
            existing_findings=[],
            dynamic=dynamic,
            timeout=timeout,
            start_time=start,
        )

    def analyze_directory(
        self,
        directory: str,
        *,
        package_name: str | None = None,
        dynamic: bool = False,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Analyse a pre-extracted package directory."""
        resolved = Path(directory).resolve()
        if not resolved.is_dir():
            raise NotADirectoryError(f"Not a valid directory: {directory}")

        name = package_name or resolved.name
        start = time.monotonic()
        return self._analyze_extracted(
            extraction_path=str(resolved),
            package_name=name,
            existing_phases={},
            existing_findings=[],
            dynamic=dynamic,
            timeout=timeout,
            start_time=start,
            archive_path=None,
        )

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _analyze_archive(
        self,
        archive_path: str,
        package_name: str,
        existing_phases: dict[str, Any],
        existing_findings: list[dict[str, Any]],
        dynamic: bool,
        timeout: int | None,
        start_time: float,
    ) -> dict[str, Any]:
        """Extract and analyse an archive."""
        phases = dict(existing_phases)
        all_findings = list(existing_findings)

        # Extraction phase
        extraction = self._extractor.extract_package(archive_path, package_name)
        phases["extraction"] = extraction

        if extraction.get("status") != "success":
            duration = time.monotonic() - start_time
            return self._build_result(
                package_name=package_name,
                status="error",
                phases=phases,
                findings=all_findings,
                duration=duration,
                error=extraction.get("error", "Extraction failed"),
            )

        extraction_path = extraction["data"]["extraction_path"]

        try:
            result = self._analyze_extracted(
                extraction_path=extraction_path,
                package_name=package_name,
                existing_phases=phases,
                existing_findings=all_findings,
                dynamic=dynamic,
                timeout=timeout,
                start_time=start_time,
                archive_path=archive_path,
            )
            if self._cache is not None and cache_key and not result.get("error"):
                self._cache.set(cache_key, result)
            return result
        finally:
            self._extractor.cleanup(package_name)

    def _analyze_extracted(
        self,
        extraction_path: str,
        package_name: str,
        existing_phases: dict[str, Any],
        existing_findings: list[dict[str, Any]],
        dynamic: bool,
        timeout: int | None,
        start_time: float,
        archive_path: str | None,
    ) -> dict[str, Any]:
        """Run all analysis phases on an extracted directory."""
        phases = dict(existing_phases)
        all_findings = list(existing_findings)
        base_path = Path(extraction_path)
        pkg_version = ""

        # Phase: Entropy analysis
        try:
            entropy_data = self._run_entropy(base_path, package_name)
            phases["entropy"] = entropy_data
            for ef in entropy_data.get("high_entropy_files", []):
                all_findings.append(_normalize_finding({
                    "id": "high-entropy-file",
                    "title": "High entropy content detected",
                    "severity": "high",
                    "confidence": 0.85,
                    "file": ef.get("path", ""),
                    "evidence": f"Shannon entropy {ef.get('entropy', 0):.2f} bits — possible obfuscation or binary payload",
                    "tags": ["entropy"],
                }, "entropy", "high"))
        except Exception as exc:
            phases["entropy"] = {"status": "error", "error": str(exc)}

        # Phase: Static analysis
        try:
            static_result = self._static.analyze_directory(extraction_path)
            phases["static"] = static_result
            pkg_version = static_result.get("package_version", "")
            for f in static_result.get("findings", []):
                all_findings.append(_normalize_finding(f, "static"))
        except Exception as exc:
            phases["static"] = {"status": "error", "error": str(exc)}

        # Phase: Obfuscation detection
        if _HAS_OBFUSCATION:
            try:
                obf = ObfuscationDetector()
                obf_results: list[dict[str, Any]] = []
                js_files = list(base_path.rglob("*.js")) + list(base_path.rglob("*.jsx"))
                js_files += list(base_path.rglob("*.ts")) + list(base_path.rglob("*.tsx"))
                for js_file in js_files[:200]:  # Cap at 200 files
                    try:
                        obf_result = obf.analyze_file(str(js_file))
                        if obf_result.get("score", 0) > 30:
                            obf_results.append(obf_result)
                            for det in obf_result.get("detections", []):
                                all_findings.append(_normalize_finding({
                                    "id": f"obfuscation-{det.get('type', 'unknown')}",
                                    "title": det.get("description", "Obfuscation detected"),
                                    "severity": "high" if obf_result["score"] > 60 else "medium",
                                    "confidence": min(obf_result["score"] / 100, 0.95),
                                    "file": str(js_file.relative_to(base_path)),
                                    "evidence": det.get("evidence", "")[:200],
                                    "tags": ["obfuscation"],
                                }, "obfuscation"))
                    except Exception:
                        continue
                phases["obfuscation"] = {
                    "files_scanned": len(js_files),
                    "suspicious_files": len(obf_results),
                    "results": obf_results[:20],
                }
            except Exception as exc:
                phases["obfuscation"] = {"status": "error", "error": str(exc)}

        # Phase: Network analysis (MUST run before threat intel so IPs/URLs are available)
        if _HAS_NETWORK:
            try:
                net = NetworkAnalyzer()
                net_result = net.analyze_directory(extraction_path)
                phases["network"] = net_result
                for f in net_result.get("findings", []):
                    all_findings.append(_normalize_finding(f, "network"))
            except Exception as exc:
                phases["network"] = {"status": "error", "error": str(exc)}

        # Phase: Threat Intelligence / VirusTotal lookup (runs AFTER network)
        if self._threat_intel and archive_path:
            try:
                import hashlib
                file_hash = hashlib.sha256(Path(archive_path).read_bytes()).hexdigest()
                
                # Extract IPs and URLs from network phase (now available)
                ips: list[str] = []
                urls: list[str] = []
                if "network" in phases and phases["network"].get("status") != "error":
                    net_data = phases["network"].get("data", phases["network"])
                    ips = list(net_data.get("ips", []))
                    urls = list(net_data.get("urls", []))
                
                # Check hash
                hash_report = self._threat_intel.check_hash(file_hash)
                reports = {"hash": [hash_report]} if hash_report.indicators else {}
                
                # Check network indicators
                net_reports = self._threat_intel.bulk_check_network_indicators(ips=ips, urls=urls)
                reports.update(net_reports)
                
                phases["threat_intel"] = {"reports": reports}
                
                # Add findings
                ti_findings = self._threat_intel.to_findings(reports)
                for f in ti_findings:
                    all_findings.append(_normalize_finding(f, "threat-intel", "critical"))
                    
            except Exception as exc:
                phases["threat_intel"] = {"status": "error", "error": str(exc)}

        # Phase: Evasion detection (initialize before dynamic to avoid scope issues)
        evasion: Any = None
        if _HAS_EVASION:
            try:
                evasion = EvasionDetector()
                static_evasion_findings = evasion.scan_source(extraction_path)
                for f in static_evasion_findings:
                    all_findings.append(_normalize_finding(f, "evasion"))
                phases["evasion"] = {"static_findings": len(static_evasion_findings)}
            except Exception as exc:
                phases["evasion"] = {"status": "error", "error": str(exc)}
                evasion = None  # Prevent use in dynamic phase

        # Phase: Dynamic sandbox (optional)
        if dynamic and _HAS_DYNAMIC and archive_path:
            sandbox_timeout = timeout or self.config.timeout_sandbox
            try:
                sandbox = DynamicSandbox(self.config)
                dyn_result = sandbox.analyze(
                    package_path=archive_path,
                    package_name=package_name,
                    timeout=sandbox_timeout,
                )
                phases["dynamic"] = dyn_result
                for f in dyn_result.get("behavioral_findings", []):
                    all_findings.append(_normalize_finding(f, "dynamic"))

                # Run behavior monitor on sandbox output
                if _HAS_BEHAVIOR:
                    try:
                        monitor = BehaviorMonitor()
                        behavior = monitor.analyze_execution_result(dyn_result)
                        phases["behavior_analysis"] = behavior
                        for f in behavior.get("findings", []):
                            all_findings.append(_normalize_finding(f, "behavior"))
                    except Exception as exc:
                        phases["behavior_analysis"] = {"status": "error", "error": str(exc)}
                        
                # Dynamic evasion checks (only if evasion detector was created)
                if evasion is not None and dyn_result.get("strace_output"):
                    try:
                        dyn_evasion_findings = evasion.scan_strace(dyn_result["strace_output"])
                        for f in dyn_evasion_findings:
                            all_findings.append(_normalize_finding(f, "evasion-dynamic"))
                        if "evasion" not in phases:
                            phases["evasion"] = {}
                        phases["evasion"]["dynamic_findings"] = len(dyn_evasion_findings)
                    except Exception as exc:
                        self.logger.warning("Dynamic evasion check failed: %s", exc)

            except Exception as exc:
                phases["dynamic"] = {"status": "error", "error": str(exc)}
                self.logger.error("Dynamic analysis failed", exc_info=True)

        duration = time.monotonic() - start_time
        all_findings = _dedupe_findings(all_findings)
        risk_score, risk_level = _compute_risk_score(all_findings)
        verdict_text, recommendation = _verdict(risk_level)

        # Phase: AI Analysis (Deep review of findings)
        if self._ai_analyzer and self._ai_analyzer.is_available():
            # Only run AI if requested by auto-enable logic (high risk) or forced
            auto_ai = getattr(self.config, "ai_enabled", False)
            if auto_ai and risk_score >= 50:
                try:
                    # Request explanation
                    explanation = self._ai_analyzer.explain_findings(all_findings, package_name=package_name)
                    phases["ai_analysis"] = {"explanation": explanation}
                    
                    # Request final verdict
                    ai_verdict = self._ai_analyzer.verdict({
                        "package_name": package_name,
                        "package_version": pkg_version,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                        "verdict": verdict_text,
                        "findings": all_findings,
                    })
                    phases["ai_analysis"]["verdict"] = ai_verdict
                    
                    # If AI has high confidence in a MORE SEVERE verdict, override
                    if ai_verdict.get("ai_confidence", 0) > 80:
                        if ai_verdict.get("ai_verdict") in ("MALICIOUS", "SUSPICIOUS"):
                            verdict_text = ai_verdict["ai_verdict"]
                            if verdict_text == "MALICIOUS":
                                risk_level = "CRITICAL"
                                risk_score = max(risk_score, 90)
                except Exception as exc:
                    phases["ai_analysis"] = {"status": "error", "error": str(exc)}
        return self._build_result(
            package_name=package_name,
            package_version=pkg_version,
            status="complete",
            phases=phases,
            findings=all_findings,
            duration=duration,
        )

    def _run_entropy(self, base_path: Path, package_name: str) -> dict[str, Any]:
        """Run entropy analysis across all files."""
        entropy_data: dict[str, Any] = {
            "engine": "cpp" if sentinel_core is not None else "python",
            "files": [],
            "high_entropy_files": [],
            "average_entropy": 0.0,
        }

        total_entropy = 0.0
        file_count = 0

        for file_path in base_path.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                file_data = file_path.read_bytes()
            except OSError:
                continue

            if sentinel_core is not None:
                entropy = float(sentinel_core.EntropyCalculator.calculate(file_data))
            else:
                entropy = ShannonEntropyCalculator.calculate(file_data)

            relative = str(file_path.relative_to(base_path))
            file_entry = {
                "path": relative,
                "size": len(file_data),
                "entropy": round(entropy, 2),
            }
            entropy_data["files"].append(file_entry)
            total_entropy += entropy
            file_count += 1

            if entropy >= self.config.entropy_threshold:
                entropy_data["high_entropy_files"].append(file_entry)

        if file_count > 0:
            entropy_data["average_entropy"] = round(total_entropy / file_count, 2)

        return entropy_data

    def _build_result(
        self,
        package_name: str,
        status: str,
        phases: dict[str, Any],
        findings: list[dict[str, Any]],
        duration: float,
        package_version: str = "",
        error: str | None = None,
    ) -> dict[str, Any]:
        """Build the final unified result dict."""
        if error:
            return {
                "package_name": package_name,
                "package_version": package_version,
                "status": "error",
                "analysis_time": round(duration, 2),
                "phases": phases,
                "findings": findings,
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "verdict": "ERROR",
                "recommendation": f"Analysis failed: {error}",
                "error": error,
            }

        risk_score, risk_level = _compute_risk_score(findings)
        verdict_text, recommendation = _verdict(risk_level)

        return {
            "package_name": package_name,
            "package_version": package_version,
            "status": status,
            "analysis_time": round(duration, 2),
            "phases": phases,
            "findings": findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "verdict": verdict_text,
            "recommendation": recommendation,
        }
