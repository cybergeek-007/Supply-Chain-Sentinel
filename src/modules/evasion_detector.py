"""Malware evasion technique detector.

Detects when package code contains anti-analysis / sandbox evasion patterns:
  - Docker/container detection
  - CI environment detection
  - VM/resource fingerprinting
  - Debugger detection
  - Time-based evasion (delayed payloads)
  - Sandbox fingerprinting

Both static (source code) and dynamic (strace output) analysis modes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.python.logger import get_logger

# ---------------------------------------------------------------------------
# Static evasion patterns — regex + metadata
# ---------------------------------------------------------------------------

@dataclass
class EvasionPattern:
    """A single evasion detection rule."""
    id: str
    title: str
    description: str
    pattern: re.Pattern[str]
    severity: str  # critical | high | medium
    category: str  # docker_detect | ci_detect | vm_detect | debug_detect | time_evasion | sandbox_fp
    confidence: float = 0.8


# Patterns are ordered from most to least specific to avoid false positives.
_STATIC_PATTERNS: list[EvasionPattern] = [
    # --- Docker / Container detection ---
    EvasionPattern(
        id="evasion.docker-env-file",
        title="Docker environment file check",
        description="Code checks for /.dockerenv or /.containerenv to detect container execution",
        pattern=re.compile(
            r"""(?:existsSync|readFileSync|accessSync|statSync)\s*\(\s*['"`]"""
            r"""(?:/\.dockerenv|/\.containerenv|/run/\.containerenv)['"`]""",
            re.IGNORECASE,
        ),
        severity="critical",
        category="docker_detect",
    ),
    EvasionPattern(
        id="evasion.docker-env-var",
        title="Docker environment variable probe",
        description="Code reads DOCKER, KUBERNETES, or container-related env vars",
        pattern=re.compile(
            r"""process\.env\s*(?:\.\s*|(?:\[\s*['"`]))"""
            r"""(?:DOCKER|KUBERNETES|CONTAINER|K8S|DOCKER_HOST|IS_DOCKER)""",
            re.IGNORECASE,
        ),
        severity="high",
        category="docker_detect",
    ),
    EvasionPattern(
        id="evasion.cgroup-check",
        title="cgroup container detection",
        description="Code reads /proc/1/cgroup to detect container environment",
        pattern=re.compile(
            r"""(?:readFileSync|readFile|createReadStream)\s*\(\s*['"`]/proc/(?:1|self)/cgroup""",
            re.IGNORECASE,
        ),
        severity="critical",
        category="docker_detect",
    ),

    # --- CI environment detection ---
    EvasionPattern(
        id="evasion.ci-env-check",
        title="CI environment detection",
        description="Code checks for CI/CD environment variables before executing payload",
        pattern=re.compile(
            r"""process\.env\s*(?:\.\s*|(?:\[\s*['"`]))"""
            r"""(?:CI|GITHUB_ACTIONS|JENKINS|TRAVIS|CIRCLECI|GITLAB_CI|"""
            r"""BUILDKITE|CODEBUILD|TF_BUILD|BITBUCKET_PIPELINE)(?:\b|['"`\]])""",
            re.IGNORECASE,
        ),
        severity="high",
        category="ci_detect",
        confidence=0.6,  # Lower confidence since legitimate packages check CI too
    ),

    # --- VM / Resource fingerprinting ---
    EvasionPattern(
        id="evasion.cpu-count-check",
        title="CPU count fingerprinting",
        description="Code checks os.cpus().length — low CPU count may indicate sandbox VM",
        pattern=re.compile(
            r"""os\.cpus\(\)\.length\s*(?:<|<=|===?|!==?)\s*\d""",
            re.IGNORECASE,
        ),
        severity="high",
        category="vm_detect",
    ),
    EvasionPattern(
        id="evasion.memory-check",
        title="System memory fingerprinting",
        description="Code checks os.totalmem() — low memory may indicate sandbox",
        pattern=re.compile(
            r"""os\.totalmem\(\)\s*(?:<|<=|===?)\s*\d""",
            re.IGNORECASE,
        ),
        severity="high",
        category="vm_detect",
    ),
    EvasionPattern(
        id="evasion.hostname-check",
        title="Hostname fingerprinting",
        description="Code reads os.hostname() — may be checking for sandbox hostnames",
        pattern=re.compile(
            r"""os\.hostname\(\).*(?:includes?|match|test|indexOf|===?)\s*\(?\s*['"`]""",
            re.IGNORECASE,
        ),
        severity="medium",
        category="sandbox_fp",
        confidence=0.5,
    ),
    EvasionPattern(
        id="evasion.uptime-check",
        title="System uptime fingerprinting",
        description="Code checks os.uptime() — short uptime may indicate fresh VM",
        pattern=re.compile(
            r"""os\.uptime\(\)\s*(?:<|<=)\s*\d""",
            re.IGNORECASE,
        ),
        severity="high",
        category="vm_detect",
    ),

    # --- Debugger / Inspection detection ---
    EvasionPattern(
        id="evasion.debugger-check",
        title="Debugger detection",
        description="Code checks for --inspect or debugging flags",
        pattern=re.compile(
            r"""(?:process\.execArgv|process\.argv).*(?:inspect|debug-brk|debug)""",
            re.IGNORECASE,
        ),
        severity="high",
        category="debug_detect",
    ),
    EvasionPattern(
        id="evasion.debugger-statement",
        title="Anti-debug: debugger statement in install script",
        description="Debugger statement found in install/preinstall/postinstall script",
        pattern=re.compile(
            r"""\bdebugger\s*;""",
            re.IGNORECASE,
        ),
        severity="medium",
        category="debug_detect",
        confidence=0.4,  # Common in dev code too
    ),

    # --- Time-based evasion ---
    EvasionPattern(
        id="evasion.long-settimeout",
        title="Delayed payload execution",
        description="setTimeout with delay > 30s — may be waiting for sandbox timeout",
        pattern=re.compile(
            r"""setTimeout\s*\([^,]+,\s*(\d{5,})""",  # 5+ digits = 100000ms+ = 100s+
            re.IGNORECASE,
        ),
        severity="critical",
        category="time_evasion",
    ),
    EvasionPattern(
        id="evasion.date-based-trigger",
        title="Date-conditional payload",
        description="Code uses Date.now() or new Date() in conditional before executing actions",
        pattern=re.compile(
            r"""(?:Date\.now\(\)|new\s+Date\(\)).*(?:getMonth|getDay|getFullYear|getTime).*(?:if|&&|\|\||[?])""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        category="time_evasion",
        confidence=0.5,
    ),

    # --- Sandbox fingerprinting ---
    EvasionPattern(
        id="evasion.username-check",
        title="Username fingerprinting",
        description="Code reads os.userInfo() — may be checking for sandbox user accounts",
        pattern=re.compile(
            r"""os\.userInfo\(\).*(?:username|uid).*(?:===?|!==?|includes|match)\s*['"`]""",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="medium",
        category="sandbox_fp",
    ),
    EvasionPattern(
        id="evasion.network-interface-check",
        title="Network interface fingerprinting",
        description="Code enumerates os.networkInterfaces() to detect sandbox",
        pattern=re.compile(
            r"""os\.networkInterfaces\(\)""",
            re.IGNORECASE,
        ),
        severity="medium",
        category="sandbox_fp",
        confidence=0.3,  # Legitimate use in many packages
    ),
    EvasionPattern(
        id="evasion.process-exit-on-detect",
        title="Anti-analysis: exit on environment detection",
        description="Code calls process.exit() after environment checks",
        pattern=re.compile(
            r"""(?:\.dockerenv|process\.env\.CI|os\.cpus)[\s\S]{0,200}process\.exit\s*\(""",
            re.IGNORECASE,
        ),
        severity="critical",
        category="sandbox_fp",
    ),
]


# ---------------------------------------------------------------------------
# Strace-based dynamic evasion patterns
# ---------------------------------------------------------------------------

@dataclass
class StraceEvasionRule:
    """Rule for detecting evasion in strace output."""
    id: str
    title: str
    description: str
    pattern: re.Pattern[str]
    severity: str
    category: str


_STRACE_PATTERNS: list[StraceEvasionRule] = [
    StraceEvasionRule(
        id="evasion.strace.dockerenv-probe",
        title="Sandbox detection via /.dockerenv access",
        description="Process attempted to stat/open /.dockerenv to detect Docker",
        pattern=re.compile(r"""(?:openat|stat|access)\(.*["']?/\.dockerenv["']?""", re.IGNORECASE),
        severity="critical",
        category="docker_detect",
    ),
    StraceEvasionRule(
        id="evasion.strace.cgroup-probe",
        title="Container detection via cgroup read",
        description="Process read /proc/1/cgroup to detect container runtime",
        pattern=re.compile(r"""openat\(.*["']?/proc/(?:1|self)/cgroup["']?""", re.IGNORECASE),
        severity="critical",
        category="docker_detect",
    ),
    StraceEvasionRule(
        id="evasion.strace.sleep-evasion",
        title="Long sleep during install (possible timeout evasion)",
        description="Process slept for extended period — may be waiting for sandbox timeout",
        pattern=re.compile(r"""nanosleep\(\{(?:tv_sec=(\d+))"""),
        severity="high",
        category="time_evasion",
    ),
    StraceEvasionRule(
        id="evasion.strace.proc-scan",
        title="Process enumeration via /proc",
        description="Process scanned /proc entries — may be looking for analysis tools",
        pattern=re.compile(r"""openat\(.*["']?/proc/\d+/(?:cmdline|comm|status)["']?"""),
        severity="high",
        category="sandbox_fp",
    ),
    StraceEvasionRule(
        id="evasion.strace.clock-spam",
        title="Rapid clock reads (anti-timing analysis)",
        description="Excessive clock_gettime calls detected — potential anti-debug timing",
        pattern=re.compile(r"""clock_gettime\("""),
        severity="medium",
        category="debug_detect",
    ),
]

# Clock spam needs count-based detection, not just presence
_CLOCK_SPAM_THRESHOLD = 500  # More than 500 clock calls is suspicious


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EvasionDetector:
    """Detect sandbox/analysis evasion techniques in package code.

    Provides both static (source scan) and dynamic (strace) analysis modes.
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def scan_source(self, extracted_dir: str) -> list[dict[str, Any]]:
        """Scan extracted package source files for evasion patterns.

        Parameters
        ----------
        extracted_dir:
            Path to the extracted package directory.

        Returns
        -------
        list[dict]
            List of finding dicts with keys: id, title, description,
            severity, category, confidence, file, evidence.
        """
        findings: list[dict[str, Any]] = []
        root = Path(extracted_dir)

        if not root.is_dir():
            self.logger.warning("Evasion scan skipped: %s is not a directory", extracted_dir)
            return findings

        # Only scan JS/TS source files
        extensions = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"}
        scanned = 0

        for filepath in root.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in extensions:
                continue
            # Skip node_modules inside the package
            if "node_modules" in filepath.parts:
                continue
            # Size guard — skip huge files
            try:
                if filepath.stat().st_size > 1_000_000:  # 1 MB
                    continue
            except OSError:
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            scanned += 1
            rel_path = str(filepath.relative_to(root))

            for rule in _STATIC_PATTERNS:
                matches = rule.pattern.findall(content)
                if matches:
                    evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    findings.append({
                        "id": rule.id,
                        "title": rule.title,
                        "description": rule.description,
                        "severity": rule.severity,
                        "category": rule.category,
                        "confidence": rule.confidence,
                        "file": rel_path,
                        "evidence": evidence[:200],
                        "source": "evasion-static",
                        "tags": ["evasion", rule.category],
                    })

        self.logger.info("Evasion scan: scanned %d files, found %d patterns", scanned, len(findings))
        return findings

    def scan_strace(self, strace_output: str) -> list[dict[str, Any]]:
        """Analyse strace output for dynamic evasion patterns.

        Parameters
        ----------
        strace_output:
            Raw strace log text from the Docker sandbox.

        Returns
        -------
        list[dict]
            List of finding dicts.
        """
        findings: list[dict[str, Any]] = []

        if not strace_output:
            return findings

        for rule in _STRACE_PATTERNS:
            if rule.id == "evasion.strace.clock-spam":
                # Count-based detection
                count = len(rule.pattern.findall(strace_output))
                if count > _CLOCK_SPAM_THRESHOLD:
                    findings.append({
                        "id": rule.id,
                        "title": rule.title,
                        "description": rule.description,
                        "severity": rule.severity,
                        "category": rule.category,
                        "confidence": min(0.9, count / 2000),
                        "file": "",
                        "evidence": f"clock_gettime called {count} times (threshold: {_CLOCK_SPAM_THRESHOLD})",
                        "source": "evasion-dynamic",
                        "tags": ["evasion", rule.category],
                    })
                continue

            if rule.id == "evasion.strace.sleep-evasion":
                # Check for long sleeps
                sleep_matches = rule.pattern.findall(strace_output)
                total_sleep = sum(int(s) for s in sleep_matches if s.isdigit())
                if total_sleep > 30:
                    findings.append({
                        "id": rule.id,
                        "title": rule.title,
                        "description": rule.description,
                        "severity": "critical" if total_sleep > 120 else rule.severity,
                        "category": rule.category,
                        "confidence": 0.85,
                        "file": "",
                        "evidence": f"Total sleep: {total_sleep}s across {len(sleep_matches)} calls",
                        "source": "evasion-dynamic",
                        "tags": ["evasion", rule.category],
                    })
                continue

            # Standard pattern match
            matches = rule.pattern.findall(strace_output)
            if matches:
                evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                findings.append({
                    "id": rule.id,
                    "title": rule.title,
                    "description": rule.description,
                    "severity": rule.severity,
                    "category": rule.category,
                    "confidence": 0.85,
                    "file": "",
                    "evidence": evidence[:200],
                    "source": "evasion-dynamic",
                    "tags": ["evasion", rule.category],
                })

        self.logger.info("Strace evasion scan: found %d patterns", len(findings))
        return findings
