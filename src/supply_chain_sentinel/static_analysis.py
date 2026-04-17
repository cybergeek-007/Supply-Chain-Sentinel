from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
from collections import Counter
from pathlib import Path

from .models import Finding, PackageArtifact, StaticAnalysisResult

TEXT_SUFFIXES = {".js", ".cjs", ".mjs", ".json", ".sh", ".ts"}
DANGEROUS_PATTERNS = [
    "eval",
    "Function",
    "child_process",
    "exec(",
    "spawn(",
    "curl ",
    "wget ",
    "nc ",
    "fetch(",
    "XMLHttpRequest",
]
MIN_ENTROPY_BYTES = 64
MAX_ENTROPY_BYTES = 512 * 1024


def run_static_analysis(
    artifact: PackageArtifact,
    risk_threshold: int,
    high_entropy: float,
    medium_entropy: float = 6.5,
    yara_rules_path: Path | None = None,
) -> StaticAnalysisResult:
    findings: list[Finding] = []
    fingerprints: list[dict[str, object]] = []
    package_json = _load_package_json(artifact.extracted_path)
    lifecycle_scripts = _extract_lifecycle_scripts(package_json)

    for script_name, command in lifecycle_scripts:
        findings.append(
            Finding(
                category="obfuscation",
                kind="lifecycle_script",
                severity="medium",
                message=f"Lifecycle script '{script_name}' will execute during installation.",
                score=12,
                evidence={"script": script_name, "command": command},
            )
        )

    for path in artifact.extracted_path.rglob("*"):
        if not path.is_file():
            continue
        findings.extend(_analyze_entropy(path, artifact.extracted_path, high_entropy, medium_entropy))
        if path.suffix.lower() in TEXT_SUFFIXES or path.name == "package.json":
            findings.extend(_scan_dangerous_patterns(path, artifact.extracted_path))
            fingerprint = _build_js_fingerprint(path, artifact.extracted_path)
            if fingerprint:
                fingerprints.append(fingerprint)

    if yara_rules_path:
        findings.extend(_run_optional_yara_scan(artifact.extracted_path, yara_rules_path))

    score = min(sum(finding.score for finding in findings), 100)
    if score >= risk_threshold:
        findings.append(
            Finding(
                category="obfuscation",
                kind="static_threshold_exceeded",
                severity="high",
                message=f"Static analysis exceeded configured risk threshold ({risk_threshold}).",
                score=0,
                evidence={"threshold": risk_threshold, "score": score},
            )
        )

    return StaticAnalysisResult(
        score=score,
        findings=findings,
        fingerprints=fingerprints,
        package_json=package_json,
        lifecycle_scripts=[name for name, _ in lifecycle_scripts],
    )


def compute_shannon_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = Counter(blob)
    total = len(blob)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _load_package_json(package_dir: Path) -> dict[str, object]:
    package_json_path = package_dir / "package.json"
    if not package_json_path.exists():
        return {}
    try:
        return json.loads(package_json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _extract_lifecycle_scripts(package_json: dict[str, object]) -> list[tuple[str, str]]:
    scripts = package_json.get("scripts", {})
    if not isinstance(scripts, dict):
        return []
    lifecycle = []
    for name in ("preinstall", "install", "postinstall"):
        command = scripts.get(name)
        if isinstance(command, str):
            lifecycle.append((name, command))
    return lifecycle


def _analyze_entropy(path: Path, root: Path, high_entropy: float, medium_entropy: float) -> list[Finding]:
    blob = path.read_bytes()
    if len(blob) < MIN_ENTROPY_BYTES or len(blob) > MAX_ENTROPY_BYTES:
        return []
    entropy = compute_shannon_entropy(blob)
    relative = str(path.relative_to(root))
    findings: list[Finding] = []
    if entropy >= high_entropy:
        findings.append(
            Finding(
                category="obfuscation",
                kind="entropy_high",
                severity="high",
                message=f"High entropy detected in {relative}.",
                score=45,
                evidence={"file": relative, "entropy": round(entropy, 3)},
            )
        )
    elif entropy >= medium_entropy:
        findings.append(
            Finding(
                category="obfuscation",
                kind="entropy_medium",
                severity="medium",
                message=f"Moderately high entropy detected in {relative}.",
                score=20,
                evidence={"file": relative, "entropy": round(entropy, 3)},
            )
        )
    return findings


def _scan_dangerous_patterns(path: Path, root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    relative = str(path.relative_to(root))
    findings: list[Finding] = []
    for pattern in DANGEROUS_PATTERNS:
        if pattern in text:
            findings.append(
                Finding(
                    category="obfuscation",
                    kind="dangerous_ast_pattern",
                    severity="medium",
                    message=f"Suspicious JavaScript pattern '{pattern}' found in {relative}.",
                    score=15,
                    evidence={"file": relative, "pattern": pattern},
                )
            )
    return findings


def _build_js_fingerprint(path: Path, root: Path) -> dict[str, object] | None:
    if path.suffix.lower() not in {".js", ".cjs", ".mjs"}:
        return None

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None

    node_types: list[str] = []
    if importlib.util.find_spec("esprima"):
        import esprima  # type: ignore

        try:
            parsed = esprima.parseScript(text, tolerant=True)
            node_types = _walk_esprima_tree(parsed)
        except Exception:
            node_types = []

    if not node_types:
        node_types = re.findall(r"[A-Za-z_]+", text)
        node_types = [token for token in node_types if token[0].isalpha()]

    digest = hashlib.sha256("->".join(node_types).encode("utf-8")).hexdigest()
    return {
        "file": str(path.relative_to(root)),
        "fingerprint": digest,
        "node_count": len(node_types),
    }


def _walk_esprima_tree(node: object) -> list[str]:
    node_types: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current is None:
            continue
        node_type = getattr(current, "type", None)
        if node_type:
            node_types.append(str(node_type))
        if hasattr(current, "__dict__"):
            for value in current.__dict__.values():
                if isinstance(value, list):
                    stack.extend(reversed(value))
                else:
                    stack.append(value)
    return node_types


def _run_optional_yara_scan(package_dir: Path, yara_rules_path: Path) -> list[Finding]:
    if not importlib.util.find_spec("yara"):
        return []

    import yara  # type: ignore

    compiled = yara.compile(filepath=str(yara_rules_path))
    findings: list[Finding] = []
    for path in package_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            matches = compiled.match(str(path))
        except yara.Error:
            continue
        for match in matches:
            findings.append(
                Finding(
                    category="obfuscation",
                    kind="yara_match",
                    severity="high",
                    message=f"YARA signature '{match.rule}' matched {path.name}.",
                    score=40,
                    evidence={"file": str(path.relative_to(package_dir)), "rule": match.rule},
                )
            )
    return findings
