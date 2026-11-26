"""Stable, JSON-serializable evidence and result types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

RULESET_VERSION = "2026.11.3"


class ScanError(Exception):
    """An inspection could not be completed; never treat as a clean package."""


@dataclass
class Artifact:
    name: str
    version: str
    sha256: str
    files: dict[str, bytes]
    source: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: float
    message: str
    file: str = "package.json"
    line: int = 1
    evidence: str = ""
    suppressed: bool = False
    suppression_reason: str = ""


@dataclass
class ScanReport:
    package: str
    version: str = ""
    sha256: str = ""
    status: str = "complete"
    verdict: str = "clean"
    score: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0
    ruleset: str = RULESET_VERSION
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def classify(findings: list[Finding]) -> tuple[int, str]:
    """Cap each rule's contribution; confidence is evidence strength, not probability."""
    weights = {"info": 0, "low": 5, "medium": 20, "high": 55, "critical": 100}
    contributions: dict[str, int] = {}
    for finding in findings:
        if finding.suppressed:
            continue
        value = round(weights[finding.severity] * finding.confidence)
        contributions[finding.rule_id] = max(contributions.get(finding.rule_id, 0), value)
    score = min(100, sum(contributions.values()))
    if contributions.get("known-malicious", 0):
        return max(score, 95), "blocked"
    return score, "review" if score >= 40 else "clean"
