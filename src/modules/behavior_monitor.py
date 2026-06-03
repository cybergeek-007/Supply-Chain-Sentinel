"""Post-execution behavioural analysis for dynamic sandbox results.

This module takes the raw output dict produced by
:class:`~src.modules.dynamic_sandbox.DynamicSandbox` and applies a
multi-pass analysis to produce richly structured behavioural findings.

Analysis passes
---------------
1. **Network connection attempts** – HTTP/HTTPS URLs that are not the npm
   registry, WebSocket endpoints, IP-literal connections.
2. **Credential access** – honeypot token leakage, SSH key references, AWS
   credential file paths, git config access, .npmrc reads.
3. **Filesystem anomalies** – files created/modified outside the expected
   ``node_modules`` tree, suspicious filenames (drop scripts, payloads,
   backdoors).
4. **Shell spawning** – invocation of ``cmd.exe``, ``powershell``,
   ``/bin/sh``, ``/bin/bash``, etc.
5. **Download attempts** – ``curl``, ``wget``, ``Invoke-WebRequest``,
   ``fetch()``, ``axios.get()``, ``https.get()``.
6. **Base64 decode + exec patterns** – ``Buffer.from(…, 'base64')`` combined
   with ``eval`` or ``Function``, ``atob`` + exec.
7. **Persistence mechanisms** – Windows registry writes, ``crontab``
   modifications, macOS ``launchctl`` / plist drops, systemd unit installs.
8. **Process injection / code execution** – ``child_process.exec``,
   ``spawn``, ``fork``, ``vm.runInNewContext``, ``new Function``.

Each pass produces zero or more :class:`BehavioralFinding` instances that
are aggregated into a summary report.

Usage
-----
::

    from src.modules.behavior_monitor import BehaviorMonitor

    monitor = BehaviorMonitor()
    report = monitor.analyze_execution_result(sandbox_result)
    print(report["threat_level"])
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from src.core.python.logger import get_logger

# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_RANK_TO_LEVEL: dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BehavioralFinding:
    """A single behavioural indicator extracted from sandbox output.

    Attributes
    ----------
    category:
        Broad category string (e.g. ``"network"``, ``"credential"``).
    finding_id:
        Unique machine-readable identifier (e.g. ``"network.non-registry-url"``).
    description:
        Human-readable description of what was observed.
    severity:
        One of ``"info"``, ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.
    evidence:
        List of supporting strings (matched substrings, file paths, etc.).
    source:
        Where the evidence came from: ``"stdout"``, ``"stderr"``,
        ``"filesystem"``, or ``"combined"``.
    confidence:
        ``"low"``, ``"medium"``, or ``"high"`` – how confident we are that
        this is malicious and not a false positive.
    mitre_technique:
        Optional MITRE ATT&CK for Supply Chain / Enterprise technique ID.
    """

    category: str
    finding_id: str
    description: str
    severity: str
    evidence: list[str] = field(default_factory=list)
    source: str = "combined"
    confidence: str = "medium"
    mitre_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Compiled regex patterns per analysis pass
# ---------------------------------------------------------------------------

# 1. Network
_NET_NON_REGISTRY = re.compile(
    r"https?://(?!registry\.npmjs\.org)[^\s\"'`\)>]{4,}",
    re.IGNORECASE,
)
_NET_WEBSOCKET = re.compile(r"wss?://[^\s\"'`\)>]{4,}", re.IGNORECASE)
_NET_IP_LITERAL = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?[^\s\"'`\)>]*",
    re.IGNORECASE,
)
_NET_DNS_EXFIL = re.compile(
    r"\b(?:nslookup|dig|host)\s+[^\s]+",
    re.IGNORECASE,
)

# 2. Credentials
_CRED_HONEYPOT = re.compile(r"SENTINEL_FAKE", re.IGNORECASE)
_CRED_SSH_PATH = re.compile(r"[/\\]\.ssh[/\\]|id_rsa|id_ed25519|known_hosts", re.IGNORECASE)
_CRED_AWS_PATH = re.compile(r"\.aws[/\\]credentials|aws_access_key_id|aws_secret_access_key", re.IGNORECASE)
_CRED_NPMRC = re.compile(r"\.npmrc", re.IGNORECASE)
_CRED_GITCONFIG = re.compile(r"\.gitconfig|\.git-credentials", re.IGNORECASE)
_CRED_ENV_SECRET = re.compile(
    r"process\.env\.[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS|CREDENTIAL)[A-Z_]*",
    re.IGNORECASE,
)
_CRED_DOCKER_CONFIG = re.compile(r"\.docker[/\\]config\.json", re.IGNORECASE)

# 3. Filesystem anomalies – suspicious filenames
_FS_SUSPICIOUS_NAME = re.compile(
    r"(?:backdoor|payload|dropper|loader|stager|rootkit|keylogger|rat\b|"
    r"cryptominer|miner|stealer|exfil|pwned|shell(?:code)?)\.",
    re.IGNORECASE,
)
_FS_HIDDEN_DOTFILE = re.compile(r"/\.[^/]+$|\\\.([^\\]+)$")  # files starting with '.'

# 4. Shell spawning
_SHELL_WIN = re.compile(r"\bcmd(?:\.exe)?\b|\bpowershell(?:\.exe)?\b|\bwscript(?:\.exe)?\b|\bcscript(?:\.exe)?\b", re.IGNORECASE)
_SHELL_POSIX = re.compile(r"/bin/(?:sh|bash|zsh|dash|fish|ksh)\b|execve\s*\(", re.IGNORECASE)

# 5. Download attempts
_DL_CURL = re.compile(r"\bcurl\s+[^\s]", re.IGNORECASE)
_DL_WGET = re.compile(r"\bwget\s+[^\s]", re.IGNORECASE)
_DL_IWR = re.compile(r"\bInvoke-WebRequest\b|\biwr\b", re.IGNORECASE)
_DL_NODE_FETCH = re.compile(r"\bfetch\s*\(\s*['\"]https?://", re.IGNORECASE)
_DL_AXIOS = re.compile(r"\baxios\s*\.\s*(?:get|post|put|delete)\s*\(\s*['\"]https?://", re.IGNORECASE)
_DL_HTTPS_GET = re.compile(r"\bhttps?\s*\.\s*get\s*\(\s*['\"]https?://", re.IGNORECASE)

# 6. Base64 + exec
_B64_BUFFER = re.compile(r"Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]\s*\)", re.IGNORECASE)
_B64_ATOB = re.compile(r"\batob\s*\(", re.IGNORECASE)
_EXEC_EVAL = re.compile(r"\beval\s*\(", re.IGNORECASE)
_EXEC_NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)
_EXEC_VM = re.compile(r"\bvm\s*\.\s*runIn(?:New)?Context\s*\(|\bvm\s*\.\s*Script\s*\(", re.IGNORECASE)

# 7. Persistence mechanisms
_PERSIST_REGISTRY = re.compile(
    r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)[\\][^\s\"'`]+",
    re.IGNORECASE,
)
_PERSIST_REG_EXE = re.compile(r"\breg(?:\.exe)?\s+(?:add|delete|import)\b", re.IGNORECASE)
_PERSIST_CRONTAB = re.compile(r"\bcrontab\s+-[le]\b|\bcrontab\s+[^\s]|\(/etc/cron", re.IGNORECASE)
_PERSIST_LAUNCHCTL = re.compile(r"\blaunchctl\s+(?:load|bootstrap|kickstart)\b", re.IGNORECASE)
_PERSIST_PLIST = re.compile(r"Library/LaunchAgents|Library/LaunchDaemons", re.IGNORECASE)
_PERSIST_SYSTEMD = re.compile(r"systemctl\s+(?:enable|start|daemon-reload)\b|\b\.service\b", re.IGNORECASE)
_PERSIST_STARTUP = re.compile(
    r"\\Microsoft\\Windows\\CurrentVersion\\Run\b|"
    r"\\Startup\\[^\s]+\.(?:bat|vbs|ps1|exe|cmd)\b",
    re.IGNORECASE,
)

# 8. Process injection / dangerous code execution APIs
_PROC_CHILD_PROCESS = re.compile(
    r"\bchild_process\b.*\b(?:exec|spawn|fork|execFile|execSync|spawnSync)\b|"
    r"\b(?:exec|spawn|fork|execFile|execSync|spawnSync)\s*\(",
    re.IGNORECASE,
)
_PROC_REQUIRE_CHILD = re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helper: extract matched lines with surrounding context
# ---------------------------------------------------------------------------

def _find_matches_in_text(pattern: re.Pattern[str], text: str, max_matches: int = 5) -> list[str]:
    """Return up to *max_matches* unique non-empty match strings."""
    results: list[str] = []
    seen: set[str] = set()
    for m in pattern.finditer(text):
        raw = m.group(0).strip()
        if raw and raw not in seen:
            results.append(raw[:200])   # truncate very long matches
            seen.add(raw)
            if len(results) >= max_matches:
                break
    return results


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class BehaviorMonitor:
    """Post-execution behavioural analysis engine.

    Takes the structured result dict produced by
    :class:`~src.modules.dynamic_sandbox.DynamicSandbox` and applies
    multiple targeted analysis passes to produce a comprehensive threat
    report.

    Examples
    --------
    >>> monitor = BehaviorMonitor()
    >>> report = monitor.analyze_execution_result(sandbox_result)
    >>> for finding in report["findings"]:
    ...     print(finding["finding_id"], finding["severity"])
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def analyze_execution_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Perform post-execution behavioural analysis.

        Parameters
        ----------
        result:
            The dict returned by
            :meth:`~src.modules.dynamic_sandbox.DynamicSandbox.analyze`.
            Expected keys: ``stdout``, ``stderr``, ``filesystem_changes``,
            ``behavioral_findings``, ``honeypot_triggered``, ``platform``,
            ``node_version``, ``status``, ``exit_code``.

        Returns
        -------
        dict with keys:

        * ``threat_level`` – ``"CLEAN"`` | ``"LOW"`` | ``"MEDIUM"`` | ``"HIGH"`` | ``"CRITICAL"``
        * ``findings`` – list of serialised :class:`BehavioralFinding` dicts
        * ``finding_count`` – total number of findings
        * ``finding_by_severity`` – ``{severity: count}`` breakdown
        * ``finding_by_category`` – ``{category: count}`` breakdown
        * ``honeypot_triggered`` – bool
        * ``network_indicators`` – deduplicated list of non-registry URLs
        * ``credential_indicators`` – list of credential-access evidence strings
        * ``persistence_indicators`` – list of persistence-mechanism evidence strings
        * ``summary`` – human-readable summary string
        * ``mitre_techniques`` – deduplicated list of technique IDs observed
        * ``sandbox_status`` – original ``status`` from sandbox result
        * ``exit_code`` – original exit code from sandbox result
        """
        stdout: str = result.get("stdout", "") or ""
        stderr: str = result.get("stderr", "") or ""
        fs_changes: dict[str, list[str]] = result.get(
            "filesystem_changes",
            {"created": [], "modified": [], "deleted": []},
        )
        honeypot_triggered: bool = bool(result.get("honeypot_triggered", False))
        platform_str: str = result.get("platform", "unknown")
        sandbox_status: str = result.get("status", "unknown")
        exit_code: int = result.get("exit_code", -1)

        # Merge stdout + stderr for most passes
        combined = f"{stdout}\n{stderr}"

        # Existing behavioral findings from the sandbox (from pattern scan)
        existing_findings: list[dict[str, Any]] = result.get("behavioral_findings", []) or []

        # Accumulate new findings from the behaviour monitor passes
        findings: list[BehavioralFinding] = []

        # --- Pass 1: Network ---
        findings.extend(self._analyze_network(combined, stdout, stderr))

        # --- Pass 2: Credentials ---
        findings.extend(self._analyze_credentials(combined, honeypot_triggered))

        # --- Pass 3: Filesystem anomalies ---
        findings.extend(self._analyze_filesystem(fs_changes))

        # --- Pass 4: Shell spawning ---
        findings.extend(self._analyze_shell_spawning(combined, platform_str))

        # --- Pass 5: Download attempts ---
        findings.extend(self._analyze_downloads(combined))

        # --- Pass 6: Base64 + exec ---
        findings.extend(self._analyze_base64_exec(combined))

        # --- Pass 7: Persistence mechanisms ---
        findings.extend(self._analyze_persistence(combined, platform_str))

        # --- Pass 8: Process injection / code execution ---
        findings.extend(self._analyze_process_injection(combined))

        # --- Incorporate existing sandbox-level findings (avoid duplication) ---
        existing_ids = {f.finding_id for f in findings}
        for raw in existing_findings:
            fid = raw.get("finding_id", "")
            if fid and fid not in existing_ids:
                findings.append(
                    BehavioralFinding(
                        category=self._category_for_finding_id(fid),
                        finding_id=fid,
                        description=raw.get("description", fid),
                        severity=raw.get("severity", "medium"),
                        evidence=raw.get("evidence", []),
                        source=raw.get("source", "combined"),
                        confidence="medium",
                    )
                )
                existing_ids.add(fid)

        # --- Compute aggregate metrics ---
        threat_level = self._compute_threat_level(findings, honeypot_triggered, sandbox_status)

        by_severity: dict[str, int] = {s: 0 for s in _SEVERITY_RANK}
        by_category: dict[str, int] = {}
        network_indicators: list[str] = []
        credential_indicators: list[str] = []
        persistence_indicators: list[str] = []
        mitre_techniques: list[str] = []

        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
            if finding.mitre_technique and finding.mitre_technique not in mitre_techniques:
                mitre_techniques.append(finding.mitre_technique)
            if finding.category == "network":
                network_indicators.extend(finding.evidence)
            elif finding.category == "credential":
                credential_indicators.extend(finding.evidence)
            elif finding.category == "persistence":
                persistence_indicators.extend(finding.evidence)

        # De-duplicate indicator lists
        network_indicators = list(dict.fromkeys(network_indicators))[:20]
        credential_indicators = list(dict.fromkeys(credential_indicators))[:20]
        persistence_indicators = list(dict.fromkeys(persistence_indicators))[:20]

        summary = self._build_summary(
            findings=findings,
            threat_level=threat_level,
            honeypot_triggered=honeypot_triggered,
            sandbox_status=sandbox_status,
            exit_code=exit_code,
        )

        self.logger.info(
            "BehaviorMonitor complete: threat=%s findings=%d honeypot=%s",
            threat_level, len(findings), honeypot_triggered,
        )

        return {
            "threat_level": threat_level,
            "findings": [f.to_dict() for f in findings],
            "finding_count": len(findings),
            "finding_by_severity": by_severity,
            "finding_by_category": by_category,
            "honeypot_triggered": honeypot_triggered,
            "network_indicators": network_indicators,
            "credential_indicators": credential_indicators,
            "persistence_indicators": persistence_indicators,
            "summary": summary,
            "mitre_techniques": mitre_techniques,
            "sandbox_status": sandbox_status,
            "exit_code": exit_code,
        }

    # ------------------------------------------------------------------
    # Analysis passes
    # ------------------------------------------------------------------

    def _analyze_network(
        self, combined: str, stdout: str, stderr: str
    ) -> list[BehavioralFinding]:
        """Detect network connection attempts in sandbox output."""
        findings: list[BehavioralFinding] = []

        # Non-registry HTTP/HTTPS URLs
        urls = _find_matches_in_text(_NET_NON_REGISTRY, combined)
        if urls:
            findings.append(BehavioralFinding(
                category="network",
                finding_id="network.non-registry-url",
                description=(
                    "Package install script made HTTP(S) requests to a non-npm-registry "
                    "endpoint, indicating possible exfiltration or C2 communication"
                ),
                severity="high",
                evidence=urls,
                source="combined",
                confidence="high",
                mitre_technique="T1071.001",  # Application Layer Protocol: Web Protocols
            ))

        # WebSocket connections
        ws = _find_matches_in_text(_NET_WEBSOCKET, combined)
        if ws:
            findings.append(BehavioralFinding(
                category="network",
                finding_id="network.websocket-connection",
                description="WebSocket connection attempt detected",
                severity="high",
                evidence=ws,
                source="combined",
                confidence="high",
                mitre_technique="T1071.001",
            ))

        # IP-literal connections (bypasses DNS)
        ip_conns = _find_matches_in_text(_NET_IP_LITERAL, combined)
        if ip_conns:
            findings.append(BehavioralFinding(
                category="network",
                finding_id="network.ip-literal-connection",
                description=(
                    "Direct IP-address connection detected (no DNS hostname), "
                    "often used to avoid domain-based detection"
                ),
                severity="critical",
                evidence=ip_conns,
                source="combined",
                confidence="high",
                mitre_technique="T1571",  # Non-Standard Port
            ))

        # DNS exfiltration via dig/nslookup/host
        dns = _find_matches_in_text(_NET_DNS_EXFIL, combined)
        if dns:
            findings.append(BehavioralFinding(
                category="network",
                finding_id="network.dns-lookup-tool",
                description="DNS lookup tool invoked; may indicate DNS-based data exfiltration",
                severity="high",
                evidence=dns,
                source="combined",
                confidence="medium",
                mitre_technique="T1041",  # Exfiltration Over C2 Channel
            ))

        return findings

    def _analyze_credentials(
        self, combined: str, honeypot_triggered: bool
    ) -> list[BehavioralFinding]:
        """Detect credential access patterns."""
        findings: list[BehavioralFinding] = []

        # Honeypot token leakage
        if honeypot_triggered:
            hp_matches = _find_matches_in_text(_CRED_HONEYPOT, combined)
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.honeypot-token-leaked",
                description=(
                    "A Sentinel honeypot credential was found in the install output. "
                    "The package read and leaked injected fake credentials."
                ),
                severity="critical",
                evidence=hp_matches,
                source="combined",
                confidence="high",
                mitre_technique="T1552.001",  # Credentials In Files
            ))
        else:
            # Still check for the pattern even if honeypot_triggered is False
            hp_matches = _find_matches_in_text(_CRED_HONEYPOT, combined)
            if hp_matches:
                findings.append(BehavioralFinding(
                    category="credential",
                    finding_id="credential.honeypot-token-leaked",
                    description=(
                        "Sentinel honeypot credential marker found in output"
                    ),
                    severity="critical",
                    evidence=hp_matches,
                    source="combined",
                    confidence="high",
                    mitre_technique="T1552.001",
                ))

        # SSH key paths
        ssh = _find_matches_in_text(_CRED_SSH_PATH, combined)
        if ssh:
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.ssh-key-access",
                description="SSH key file path referenced; possible private key theft attempt",
                severity="critical",
                evidence=ssh,
                source="combined",
                confidence="high",
                mitre_technique="T1552.004",  # Private Keys
            ))

        # AWS credential paths
        aws = _find_matches_in_text(_CRED_AWS_PATH, combined)
        if aws:
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.aws-credentials-access",
                description="AWS credential path or key identifier found in output",
                severity="critical",
                evidence=aws,
                source="combined",
                confidence="high",
                mitre_technique="T1552.001",
            ))

        # .npmrc access
        npmrc = _find_matches_in_text(_CRED_NPMRC, combined)
        if npmrc:
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.npmrc-access",
                description=".npmrc file accessed; may contain registry tokens",
                severity="high",
                evidence=npmrc,
                source="combined",
                confidence="medium",
                mitre_technique="T1552.001",
            ))

        # .gitconfig / .git-credentials
        git_cred = _find_matches_in_text(_CRED_GITCONFIG, combined)
        if git_cred:
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.git-credentials-access",
                description="Git credential file path detected in output",
                severity="high",
                evidence=git_cred,
                source="combined",
                confidence="medium",
                mitre_technique="T1552.001",
            ))

        # Environment variable secret enumeration
        env_enum = _find_matches_in_text(_CRED_ENV_SECRET, combined)
        if env_enum:
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.env-secret-enumeration",
                description=(
                    "Install script enumerates environment variables with sensitive names "
                    "(TOKEN, KEY, SECRET, PASSWORD)"
                ),
                severity="high",
                evidence=env_enum,
                source="combined",
                confidence="medium",
                mitre_technique="T1552.007",  # Container API
            ))

        # Docker config.json
        docker_cfg = _find_matches_in_text(_CRED_DOCKER_CONFIG, combined)
        if docker_cfg:
            findings.append(BehavioralFinding(
                category="credential",
                finding_id="credential.docker-config-access",
                description="Docker config.json path detected; may contain registry credentials",
                severity="high",
                evidence=docker_cfg,
                source="combined",
                confidence="medium",
                mitre_technique="T1552.001",
            ))

        return findings

    def _analyze_filesystem(
        self, fs_changes: dict[str, list[str]]
    ) -> list[BehavioralFinding]:
        """Detect suspicious filesystem changes from the snapshot diff."""
        findings: list[BehavioralFinding] = []
        created = fs_changes.get("created", [])
        modified = fs_changes.get("modified", [])
        deleted = fs_changes.get("deleted", [])

        all_changed = created + modified

        # Files with inherently suspicious names
        suspicious_named = [p for p in all_changed if _FS_SUSPICIOUS_NAME.search(p)]
        if suspicious_named:
            findings.append(BehavioralFinding(
                category="filesystem",
                finding_id="filesystem.suspicious-filename",
                description=(
                    "Files with suspicious names (dropper, payload, backdoor, etc.) "
                    "were created or modified during install"
                ),
                severity="critical",
                evidence=suspicious_named[:10],
                source="filesystem",
                confidence="medium",
                mitre_technique="T1105",  # Ingress Tool Transfer
            ))

        # Files written outside node_modules
        non_modules = [
            p for p in all_changed
            if "node_modules" not in p
            and "npm_cache" not in p
            and "fake_home" not in p
            and "install" not in p.split("/")[0]
        ]
        if non_modules:
            findings.append(BehavioralFinding(
                category="filesystem",
                finding_id="filesystem.write-outside-node-modules",
                description=(
                    "Files were written outside the expected node_modules directory, "
                    "suggesting the script is modifying host filesystem locations"
                ),
                severity="high",
                evidence=non_modules[:10],
                source="filesystem",
                confidence="medium",
                mitre_technique="T1565.001",  # Stored Data Manipulation
            ))

        # Hidden dot-files created
        hidden_files = [p for p in created if _FS_HIDDEN_DOTFILE.search(p)]
        # Exclude normal npm artifacts
        hidden_files = [
            p for p in hidden_files
            if not any(ok in p for ok in (".npmrc", ".package-lock", ".cache", ".npm"))
        ]
        if hidden_files:
            findings.append(BehavioralFinding(
                category="filesystem",
                finding_id="filesystem.hidden-file-created",
                description="Hidden dot-file(s) created during install (may be persistence or implant)",
                severity="medium",
                evidence=hidden_files[:10],
                source="filesystem",
                confidence="low",
                mitre_technique="T1564.001",  # Hide Artifacts: Hidden Files
            ))

        # File deletions (unexpected)
        if deleted:
            findings.append(BehavioralFinding(
                category="filesystem",
                finding_id="filesystem.files-deleted",
                description="Files were deleted during the install process",
                severity="medium",
                evidence=deleted[:10],
                source="filesystem",
                confidence="low",
                mitre_technique="T1070.004",  # File Deletion
            ))

        # Executable files created (Unix .sh / Windows .bat/.ps1/.exe)
        executable_exts = {".sh", ".bash", ".bat", ".cmd", ".ps1", ".exe", ".vbs", ".js"}
        exec_files = [
            p for p in created
            if any(p.lower().endswith(ext) for ext in executable_exts)
            and "node_modules" not in p
        ]
        if exec_files:
            findings.append(BehavioralFinding(
                category="filesystem",
                finding_id="filesystem.executable-dropped",
                description=(
                    "Executable script or binary dropped outside node_modules during install"
                ),
                severity="critical",
                evidence=exec_files[:10],
                source="filesystem",
                confidence="high",
                mitre_technique="T1105",
            ))

        return findings

    def _analyze_shell_spawning(
        self, combined: str, platform_str: str
    ) -> list[BehavioralFinding]:
        """Detect shell process invocations in sandbox output."""
        findings: list[BehavioralFinding] = []

        win_shell = _find_matches_in_text(_SHELL_WIN, combined)
        if win_shell:
            findings.append(BehavioralFinding(
                category="shell",
                finding_id="shell.windows-shell-invocation",
                description=(
                    "Windows shell (cmd.exe, powershell, wscript, cscript) invoked "
                    "during npm install"
                ),
                severity="high",
                evidence=win_shell,
                source="combined",
                confidence="high",
                mitre_technique="T1059.001",  # PowerShell / T1059.003 Windows Command Shell
            ))

        posix_shell = _find_matches_in_text(_SHELL_POSIX, combined)
        if posix_shell:
            findings.append(BehavioralFinding(
                category="shell",
                finding_id="shell.posix-shell-invocation",
                description="POSIX shell (/bin/sh, /bin/bash, etc.) invoked during npm install",
                severity="high",
                evidence=posix_shell,
                source="combined",
                confidence="high",
                mitre_technique="T1059.004",  # Unix Shell
            ))

        return findings

    def _analyze_downloads(self, combined: str) -> list[BehavioralFinding]:
        """Detect download tool invocations and programmatic download calls."""
        findings: list[BehavioralFinding] = []

        curl = _find_matches_in_text(_DL_CURL, combined)
        if curl:
            findings.append(BehavioralFinding(
                category="download",
                finding_id="download.curl-invocation",
                description="curl invoked during npm install – possible remote payload download",
                severity="critical",
                evidence=curl,
                source="combined",
                confidence="high",
                mitre_technique="T1105",
            ))

        wget = _find_matches_in_text(_DL_WGET, combined)
        if wget:
            findings.append(BehavioralFinding(
                category="download",
                finding_id="download.wget-invocation",
                description="wget invoked during npm install – possible remote payload download",
                severity="critical",
                evidence=wget,
                source="combined",
                confidence="high",
                mitre_technique="T1105",
            ))

        iwr = _find_matches_in_text(_DL_IWR, combined)
        if iwr:
            findings.append(BehavioralFinding(
                category="download",
                finding_id="download.invoke-webrequest",
                description="PowerShell Invoke-WebRequest used to download remote content",
                severity="critical",
                evidence=iwr,
                source="combined",
                confidence="high",
                mitre_technique="T1105",
            ))

        fetch = _find_matches_in_text(_DL_NODE_FETCH, combined)
        if fetch:
            findings.append(BehavioralFinding(
                category="download",
                finding_id="download.node-fetch",
                description="Node.js fetch() used to download from external URL",
                severity="high",
                evidence=fetch,
                source="combined",
                confidence="medium",
                mitre_technique="T1071.001",
            ))

        axios = _find_matches_in_text(_DL_AXIOS, combined)
        if axios:
            findings.append(BehavioralFinding(
                category="download",
                finding_id="download.axios-request",
                description="axios HTTP request to external URL detected",
                severity="high",
                evidence=axios,
                source="combined",
                confidence="medium",
                mitre_technique="T1071.001",
            ))

        https_get = _find_matches_in_text(_DL_HTTPS_GET, combined)
        if https_get:
            findings.append(BehavioralFinding(
                category="download",
                finding_id="download.node-https-get",
                description="Node.js https.get() used to fetch from external URL",
                severity="high",
                evidence=https_get,
                source="combined",
                confidence="medium",
                mitre_technique="T1071.001",
            ))

        return findings

    def _analyze_base64_exec(self, combined: str) -> list[BehavioralFinding]:
        """Detect base64-decode-then-execute patterns (code obfuscation)."""
        findings: list[BehavioralFinding] = []

        # Check for both the decode AND execute step together
        has_b64_buffer = bool(_B64_BUFFER.search(combined))
        has_atob = bool(_B64_ATOB.search(combined))
        has_eval = bool(_EXEC_EVAL.search(combined))
        has_new_function = bool(_EXEC_NEW_FUNCTION.search(combined))
        has_vm = bool(_EXEC_VM.search(combined))

        any_decode = has_b64_buffer or has_atob
        any_exec = has_eval or has_new_function or has_vm

        if any_decode and any_exec:
            # High-confidence: decode + execute combo
            evidence: list[str] = []
            evidence.extend(_find_matches_in_text(_B64_BUFFER, combined))
            evidence.extend(_find_matches_in_text(_B64_ATOB, combined))
            evidence.extend(_find_matches_in_text(_EXEC_EVAL, combined))
            evidence.extend(_find_matches_in_text(_EXEC_NEW_FUNCTION, combined))
            evidence.extend(_find_matches_in_text(_EXEC_VM, combined))

            findings.append(BehavioralFinding(
                category="obfuscation",
                finding_id="obfuscation.base64-decode-execute",
                description=(
                    "Base64 decoding combined with eval/new Function/vm.runInContext – "
                    "classic payload obfuscation pattern"
                ),
                severity="critical",
                evidence=evidence[:8],
                source="combined",
                confidence="high",
                mitre_technique="T1027",  # Obfuscated Files or Information
            ))
        elif any_decode:
            evidence = []
            evidence.extend(_find_matches_in_text(_B64_BUFFER, combined))
            evidence.extend(_find_matches_in_text(_B64_ATOB, combined))
            findings.append(BehavioralFinding(
                category="obfuscation",
                finding_id="obfuscation.base64-decode",
                description="Base64 decoding detected (potential payload decoding)",
                severity="medium",
                evidence=evidence[:5],
                source="combined",
                confidence="low",
                mitre_technique="T1027",
            ))
        elif any_exec:
            evidence = []
            evidence.extend(_find_matches_in_text(_EXEC_EVAL, combined))
            evidence.extend(_find_matches_in_text(_EXEC_NEW_FUNCTION, combined))
            evidence.extend(_find_matches_in_text(_EXEC_VM, combined))
            findings.append(BehavioralFinding(
                category="obfuscation",
                finding_id="obfuscation.dynamic-code-execution",
                description="Dynamic code execution via eval/new Function/vm API detected",
                severity="high",
                evidence=evidence[:5],
                source="combined",
                confidence="medium",
                mitre_technique="T1059.007",  # JavaScript
            ))

        return findings

    def _analyze_persistence(
        self, combined: str, platform_str: str
    ) -> list[BehavioralFinding]:
        """Detect persistence-mechanism indicators in sandbox output."""
        findings: list[BehavioralFinding] = []

        # Windows registry
        reg_paths = _find_matches_in_text(_PERSIST_REGISTRY, combined)
        if reg_paths:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.windows-registry-write",
                description=(
                    "Windows registry path referenced during install – "
                    "possible Run key or COM hijacking persistence"
                ),
                severity="critical",
                evidence=reg_paths,
                source="combined",
                confidence="high",
                mitre_technique="T1547.001",  # Registry Run Keys / Startup Folder
            ))

        reg_exe = _find_matches_in_text(_PERSIST_REG_EXE, combined)
        if reg_exe:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.reg-exe-invocation",
                description="reg.exe add/delete/import invoked – direct registry manipulation",
                severity="critical",
                evidence=reg_exe,
                source="combined",
                confidence="high",
                mitre_technique="T1547.001",
            ))

        # Windows Startup folder
        startup = _find_matches_in_text(_PERSIST_STARTUP, combined)
        if startup:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.windows-startup-folder",
                description="Windows Startup folder or CurrentVersion\\Run key referenced",
                severity="critical",
                evidence=startup,
                source="combined",
                confidence="high",
                mitre_technique="T1547.001",
            ))

        # Linux crontab
        cron = _find_matches_in_text(_PERSIST_CRONTAB, combined)
        if cron:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.crontab-modification",
                description="crontab modification detected – possible scheduled task persistence",
                severity="critical",
                evidence=cron,
                source="combined",
                confidence="high",
                mitre_technique="T1053.003",  # Scheduled Task/Job: Cron
            ))

        # macOS launchctl / LaunchAgents
        launchctl = _find_matches_in_text(_PERSIST_LAUNCHCTL, combined)
        if launchctl:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.macos-launchctl",
                description="macOS launchctl load/bootstrap invoked – LaunchAgent/Daemon persistence",
                severity="critical",
                evidence=launchctl,
                source="combined",
                confidence="high",
                mitre_technique="T1543.001",  # Launch Agent
            ))

        plist = _find_matches_in_text(_PERSIST_PLIST, combined)
        if plist:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.macos-launchagent-plist",
                description="macOS LaunchAgent/LaunchDaemon plist path referenced",
                severity="critical",
                evidence=plist,
                source="combined",
                confidence="high",
                mitre_technique="T1543.001",
            ))

        # Linux systemd
        systemd = _find_matches_in_text(_PERSIST_SYSTEMD, combined)
        if systemd:
            findings.append(BehavioralFinding(
                category="persistence",
                finding_id="persistence.linux-systemd",
                description="systemd service enable/start detected – possible service persistence",
                severity="critical",
                evidence=systemd,
                source="combined",
                confidence="high",
                mitre_technique="T1543.002",  # Systemd Service
            ))

        return findings

    def _analyze_process_injection(self, combined: str) -> list[BehavioralFinding]:
        """Detect dangerous child-process spawning and code injection patterns."""
        findings: list[BehavioralFinding] = []

        # Requiring child_process (the module itself)
        req_cp = _find_matches_in_text(_PROC_REQUIRE_CHILD, combined)
        if req_cp:
            findings.append(BehavioralFinding(
                category="process",
                finding_id="process.child-process-require",
                description=(
                    "child_process module required during install script – "
                    "enables arbitrary command execution"
                ),
                severity="high",
                evidence=req_cp,
                source="combined",
                confidence="high",
                mitre_technique="T1059.007",
            ))

        # Actual exec/spawn calls
        cp_calls = _find_matches_in_text(_PROC_CHILD_PROCESS, combined)
        # Filter out the require() lines already captured
        cp_calls = [c for c in cp_calls if "require" not in c.lower()]
        if cp_calls:
            findings.append(BehavioralFinding(
                category="process",
                finding_id="process.child-process-spawn",
                description=(
                    "child_process exec/spawn/fork/execSync detected – "
                    "direct subprocess execution from install script"
                ),
                severity="critical",
                evidence=cp_calls[:5],
                source="combined",
                confidence="high",
                mitre_technique="T1059.007",
            ))

        return findings

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_threat_level(
        findings: list[BehavioralFinding],
        honeypot_triggered: bool,
        sandbox_status: str,
    ) -> str:
        """Compute an overall threat level label from findings.

        Returns one of: ``"CLEAN"``, ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``,
        ``"CRITICAL"``.
        """
        if honeypot_triggered:
            return "CRITICAL"

        if not findings:
            if sandbox_status == "timeout":
                return "MEDIUM"
            return "CLEAN"

        max_rank = max(
            _SEVERITY_RANK.get(f.severity.lower(), 0) for f in findings
        )

        if sandbox_status == "timeout":
            max_rank = max(max_rank, _SEVERITY_RANK["high"])

        # Map severity rank → threat level
        rank_to_threat = {
            0: "LOW",    # info
            1: "LOW",    # low
            2: "MEDIUM", # medium
            3: "HIGH",   # high
            4: "CRITICAL",  # critical
        }
        return rank_to_threat.get(max_rank, "LOW")

    @staticmethod
    def _category_for_finding_id(finding_id: str) -> str:
        """Derive a category label from a finding ID prefix."""
        prefix_map = {
            "network": "network",
            "credential": "credential",
            "honeypot": "credential",
            "filesystem": "filesystem",
            "fs": "filesystem",
            "shell": "shell",
            "download": "download",
            "obfuscation": "obfuscation",
            "persistence": "persistence",
            "process": "process",
            "crypto": "crypto-miner",
            "reverse": "shell",
            "env": "credential",
        }
        prefix = finding_id.split(".")[0].lower()
        return prefix_map.get(prefix, "general")

    @staticmethod
    def _build_summary(
        findings: list[BehavioralFinding],
        threat_level: str,
        honeypot_triggered: bool,
        sandbox_status: str,
        exit_code: int,
    ) -> str:
        """Build a concise human-readable summary of the analysis."""
        parts: list[str] = []

        if sandbox_status == "timeout":
            parts.append("Sandbox execution timed out (possible evasion or infinite loop).")
        elif sandbox_status == "error":
            parts.append(f"Sandbox encountered an error (exit code {exit_code}).")
        else:
            parts.append(f"Sandbox execution completed (exit code {exit_code}).")

        if honeypot_triggered:
            parts.append("⚠ CRITICAL: Honeypot credentials were leaked by the package.")

        if not findings:
            parts.append("No behavioural indicators detected.")
        else:
            critical = [f for f in findings if f.severity == "critical"]
            high = [f for f in findings if f.severity == "high"]
            medium = [f for f in findings if f.severity == "medium"]
            low_info = [f for f in findings if f.severity in ("low", "info")]

            count_parts: list[str] = []
            if critical:
                count_parts.append(f"{len(critical)} critical")
            if high:
                count_parts.append(f"{len(high)} high")
            if medium:
                count_parts.append(f"{len(medium)} medium")
            if low_info:
                count_parts.append(f"{len(low_info)} low/info")

            parts.append(
                f"Detected {len(findings)} behavioural indicator(s): "
                + ", ".join(count_parts) + "."
            )

            if critical:
                parts.append(
                    "Critical findings: "
                    + "; ".join(f.finding_id for f in critical[:3])
                    + ("..." if len(critical) > 3 else "")
                    + "."
                )

        parts.append(f"Overall threat level: {threat_level}.")
        return " ".join(parts)
