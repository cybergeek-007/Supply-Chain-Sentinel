"""Bounded, explainable static heuristics. Co-occurrence is not taint analysis."""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from difflib import SequenceMatcher

from .config import Config
from .models import Artifact, Finding, ScanError
from .shell_rules import JS_STRING, install_host_exfil

POPULAR = (
    "lodash",
    "react",
    "express",
    "axios",
    "chalk",
    "commander",
    "typescript",
    "webpack",
    "eslint",
    "prettier",
    "dotenv",
    "cross-env",
    "requests",
)
RULES = {
    "install-script": "Package declares an install lifecycle script",
    "secret-network": "Credential access and outbound capability in nearby source",
    "env-network": "Environment enumeration and outbound capability in nearby source",
    "encoded-execution": "Encoded content combined with dynamic code execution",
    "download-execute": "Download command piped into a shell",
    "install-host-exfil": "Install hook transmits multiple host identity command results",
    "remote-response-execution": "Fetched response text flows directly into an eval callback",
    "reverse-shell": "Reverse-shell command pattern",
    "install-secret-exfil": "Install hook sends a credential expression through a download client",
    "destructive-install": "Install hook contains a root filesystem destruction command",
    "typosquat": "Name resembles a popular package; verify intended dependency",
    "private-name": "Public package matches an explicitly configured private name",
    "high-entropy": "High-entropy source; packaging/minification can explain this",
    "known-malicious": "Exact version appears in a public malicious-package advisory",
    "known-vulnerability": "Exact version appears in a public vulnerability advisory",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum(
        (count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values()
    )


def _remote_response_execution(source: str, path: str) -> list[Finding]:
    # Match two explicit promise-chain shapes, preserving the callback variable
    # relationship. This is a narrow lexical recognizer, not general taint analysis.
    code = JS_STRING.sub(lambda match: re.sub(r"[^\n]", " ", match.group()), source)
    pattern = (
        r"(?<![\w$.])fetch\s*\([^()\n]{1,512}\)\s*\.then\s*\(\s*"
        r"\(?\s*(?P<response>[A-Za-z_$][\w$]*)\s*\)?\s*=>\s*"
        r"(?P=response)\s*\.text\s*\(\s*\)\s*\)?\s*\.then\s*\(\s*"
        r"(?:eval\s*(?=\))|\(?\s*(?P<body>[A-Za-z_$][\w$]*)\s*\)?\s*=>\s*"
        r"eval\s*\(\s*(?P=body)\s*\))"
    )
    return [
        Finding(
            "remote-response-execution",
            "high",
            0.95,
            RULES["remote-response-execution"],
            path,
            source.count("\n", 0, match.start()) + 1,
            "fetch -> response.text() -> eval callback; literals were masked, not executed",
        )
        for match in list(re.finditer(pattern, code))[:3]
    ]


def mask_comments(source: str) -> str:
    """Lexically mask JS comments while preserving strings and line positions.

    This is deliberately not a full JS parser (regex/template interpolation remain limits).
    """
    pattern = r"('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`)|//[^\n]*|/\*[\s\S]*?\*/"
    return re.sub(
        pattern, lambda m: m.group(1) if m.group(1) else re.sub(r"[^\n]", " ", m.group()), source
    )


def _matches(source: str, rule: str, path: str) -> list[Finding]:
    secret = r"(?:\.npmrc|\.ssh[/\\]|\.aws[/\\]|AWS_SECRET_ACCESS_KEY|NPM_TOKEN|GITHUB_TOKEN)"
    network = r"(?:\bfetch\s*\(|\bhttps?\s*\.\s*(?:request|get)\s*\(|\baxios\s*\.|\bdns\s*\.(?:resolve|lookup)|\bnet\s*\.(?:connect|createConnection))"
    patterns = {
        "secret-network": secret,
        "env-network": r"(?:JSON\.stringify\s*\(\s*process\.env|Object\.(?:keys|entries|values)\s*\(\s*process\.env|(?:body|data)\s*:\s*process\.env)",
        "encoded-execution": r"(?:\b(?:eval|Function)\s*\(\s*(?:Buffer\.from|atob|String\.fromCharCode)\s*\(|\bvm\.(?:runInNewContext|runInThisContext)\s*\(\s*(?:Buffer\.from|atob)\s*\()",
        "download-execute": r"\b(?:curl|wget)\b[^\n;]{0,400}\|\s*(?:sh|bash)\b",
        "reverse-shell": r"(?:/dev/tcp/[^\s'\"]+|\bnc\s+[^\n]{0,100}\s-e\s+/bin/(?:sh|bash))",
    }
    findings = []
    # JS identifiers are case-sensitive: matching `function()` as `Function()`
    # made normal generated code look like dynamic evaluation.
    flags = 0 if rule == "encoded-execution" else re.I
    for match in re.finditer(patterns[rule], source, flags):
        region = source[max(0, match.start() - 800) : match.end() + 800]
        if rule in {"secret-network", "env-network"} and not re.search(network, region, re.I):
            continue
        if rule == "encoded-execution" and not re.search(
            r"(?:\batob\s*\(|['\"]base64['\"]|\\x[0-9a-f]{2}|String\.fromCharCode)", region, re.I
        ):
            continue
        findings.append(
            Finding(
                rule,
                "high",
                0.9,
                RULES[rule],
                path,
                source.count("\n", 0, match.start()) + 1,
                source[max(0, match.start() - 60) : match.end() + 100][:180],
            )
        )
        if len(findings) >= 3:
            break
    return findings


def analyze(artifact: Artifact, config: Config) -> list[Finding]:
    manifest = json.loads(artifact.files["package.json"])
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict) or not all(isinstance(v, str) for v in scripts.values()):
        raise ScanError("package.json scripts must map names to strings")
    findings: list[Finding] = []
    for name in ("preinstall", "install", "postinstall", "prepare"):
        if name in scripts:
            findings.append(
                Finding(
                    "install-script",
                    "info",
                    1.0,
                    RULES["install-script"],
                    evidence=f"{name}: {scripts[name][:200]}",
                )
            )
            for rule in ("download-execute", "reverse-shell", "encoded-execution"):
                findings.extend(_matches(scripts[name], rule, "package.json"))
            command = scripts[name]
            if install_host_exfil(command):
                findings.append(
                    Finding(
                        "install-host-exfil",
                        "high",
                        0.8,
                        RULES["install-host-exfil"],
                        evidence=f"{name}: multiple host identity substitutions in curl URL/data",
                    )
                )
            if re.search(r"\b(?:curl|wget)\b", command) and re.search(
                r"gh\s+auth\s+token|\$(?:NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)", command
            ):
                findings.append(
                    Finding(
                        "install-secret-exfil",
                        "high",
                        0.95,
                        RULES["install-secret-exfil"],
                        evidence=f"{name}: credential command in outbound hook",
                    )
                )
            if re.search(r"\brm\s+[^;\n]*(?:--no-preserve-root\s+/|-[rf]+\s+/\s*(?:;|$))", command):
                findings.append(
                    Finding(
                        "destructive-install",
                        "high",
                        0.95,
                        RULES["destructive-install"],
                        evidence=f"{name}: root deletion command",
                    )
                )
    if artifact.name in config.private_names:
        findings.append(Finding("private-name", "high", 1.0, RULES["private-name"]))
    bare = artifact.name.rsplit("/", 1)[-1]
    if bare not in POPULAR and len(bare) >= 5:
        for popular in POPULAR:
            if len(popular) >= 5 and SequenceMatcher(None, bare, popular).ratio() >= 0.83:
                findings.append(
                    Finding(
                        "typosquat",
                        "medium",
                        0.5,
                        RULES["typosquat"],
                        evidence=f"{artifact.name} resembles {popular}",
                    )
                )
                break
    for path, data in artifact.files.items():
        if not path.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".sh")):
            continue
        source = mask_comments(data.decode("utf-8", errors="replace"))
        if not path.endswith(".sh"):
            findings.extend(_remote_response_execution(source, path))
        for rule in (
            "secret-network",
            "env-network",
            "encoded-execution",
            "download-execute",
            "reverse-shell",
        ):
            findings.extend(_matches(source, rule, path))
        if len(data) > 1000 and entropy(data) >= 7.2:
            findings.append(Finding("high-entropy", "info", 0.3, RULES["high-entropy"], path))
        # Decode a bounded number of literal base64 strings; never evaluate decoded code.
        for encoded in re.findall(r"['\"]([A-Za-z0-9+/]{40,8192}={0,2})['\"]", source)[:20]:
            try:
                decoded = base64.b64decode(encoded, validate=True).decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                continue
            for rule in ("secret-network", "env-network", "download-execute", "reverse-shell"):
                for finding in _matches(decoded, rule, path):
                    finding.evidence = "Decoded literal (not executed): " + finding.evidence
                    finding.line = 1
                    findings.append(finding)
    # Keep evidence bounded without directory/popularity downgrades.
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.rule_id, finding.file, finding.line), finding)
    return list(unique.values())
