"""YARA-backed scanning with a safe fallback when yara-python is unavailable."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yara  # type: ignore[import-not-found]
except ModuleNotFoundError:
    yara = None


DEFAULT_RULES = """
rule suspicious_npm_postinstall {
    meta:
        description = "Suspicious postinstall script behavior"
    strings:
        $s1 = "exec(" nocase
        $s2 = "system(" nocase
        $s3 = "child_process" nocase
        $s4 = "process.env" nocase
    condition:
        any of ($s*)
}

rule credential_theft_pattern {
    meta:
        description = "Potential credential harvesting"
    strings:
        $s1 = ".ssh" nocase
        $s2 = "AWS_ACCESS_KEY" nocase
        $s3 = "github_token" nocase
        $s4 = ".npmrc" nocase
        $s5 = "/.kube/config" nocase
    condition:
        any of ($s*)
}

rule network_exfiltration_pattern {
    meta:
        description = "Potential data exfiltration"
    strings:
        $s1 = "fetch(" nocase
        $s2 = "http.post" nocase
        $s3 = "dns.resolve" nocase
        $s4 = "dns.lookup" nocase
    condition:
        any of ($s*)
}

rule reverse_shell_pattern {
    meta:
        description = "Reverse shell payload detection"
    strings:
        $s1 = "/dev/tcp/" nocase
        $s2 = "net.Socket()" nocase
        $s3 = "nc -e /bin/sh" nocase
        $s4 = "bash -i" nocase
    condition:
        any of ($s*)
}

rule crypto_miner_strings {
    meta:
        description = "Crypto-currency mining indicators"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "pool.minexmr.com" nocase
        $s3 = "xmrpool" nocase
        $s4 = "xmrig" nocase
    condition:
        any of ($s*)
}

rule obfuscated_payload_indicators {
    meta:
        description = "Indicators of heavily obfuscated payloads"
    strings:
        $s1 = "\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73" nocase
        $s2 = "Y2hpbGRfcHJvY2Vzcw==" nocase
        $s3 = "eval(Buffer.from(" nocase
    condition:
        any of ($s*)
}

rule sandbox_evasion_checks {
    meta:
        description = "Detects logic used to evade sandbox environments"
    strings:
        $s1 = "/.dockerenv" nocase
        $s2 = "/proc/1/cgroup" nocase
        $s3 = "os.cpus().length" nocase
    condition:
        any of ($s*)
}
""".strip()


@dataclass(frozen=True)
class _FallbackRule:
    name: str
    patterns: tuple[str, ...]


class YARAScanner:
    """YARA-based malware signature detection."""

    def __init__(self, rules_dir: str = "config/rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_path = self.rules_dir / "malware_signatures.yar"
        self.compiled_rules = self._load_rules()
        self._fallback_rules = (
            _FallbackRule(
                "suspicious_npm_postinstall", ("exec(", "system(", "child_process", "process.env")
            ),
            _FallbackRule("credential_theft_pattern", (".ssh", "aws_access_key", "github_token", ".npmrc", "/.kube/config")),
            _FallbackRule("network_exfiltration_pattern", ("fetch(", "http.post", "dns.resolve", "dns.lookup")),
            _FallbackRule("reverse_shell_pattern", ("/dev/tcp/", "net.Socket()", "nc -e /bin/sh", "bash -i")),
            _FallbackRule("crypto_miner_strings", ("stratum+tcp://", "pool.minexmr.com", "xmrpool", "xmrig")),
            _FallbackRule("obfuscated_payload_indicators", ("\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73", "Y2hpbGRfcHJvY2Vzcw==", "eval(Buffer.from(")),
            _FallbackRule("sandbox_evasion_checks", ("/.dockerenv", "/proc/1/cgroup", "os.cpus().length")),
        )

    def _load_rules(self) -> Any:
        if not self.rules_path.exists():
            self._create_default_rules()
        if yara is None:
            return None
        return yara.compile(filepath=str(self.rules_path))

    def _create_default_rules(self) -> None:
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.rules_path.write_text(DEFAULT_RULES, encoding="utf-8")

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return []

        if self.compiled_rules is not None:
            return self._scan_with_yara(path)
        return self._scan_with_fallback(path)

    def _scan_with_yara(self, path: Path) -> list[dict[str, Any]]:
        matches = self.compiled_rules.match(str(path))
        results: list[dict[str, Any]] = []
        for match in matches:
            results.append(
                {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                }
            )
        return results

    def _scan_with_fallback(self, path: Path) -> list[dict[str, Any]]:
        content = path.read_text(encoding="utf-8", errors="ignore").lower()
        results: list[dict[str, Any]] = []
        for rule in self._fallback_rules:
            matched = [pattern for pattern in rule.patterns if pattern.lower() in content]
            if matched:
                results.append(
                    {
                        "rule": rule.name,
                        "namespace": "fallback",
                        "tags": [],
                        "strings": [{"matches": matched}],
                    }
                )
        return results

    def scan_directory(self, directory: str) -> dict[str, Any]:
        root = Path(directory)
        results: dict[str, Any] = {
            "scan_root": str(root),
            "files_scanned": 0,
            "matches_found": 0,
            "detections": [],
        }

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix in {".bin", ".so", ".a"}:
                continue

            results["files_scanned"] += 1
            matches = self.scan_file(str(file_path))
            if matches:
                results["matches_found"] += 1
                results["detections"].append(
                    {"file": str(file_path.relative_to(root)), "matches": matches}
                )
        return results
