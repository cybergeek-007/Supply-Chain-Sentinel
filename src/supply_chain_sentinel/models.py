from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

Decision = Literal["allow", "warn", "block"]


@dataclass(slots=True)
class Finding:
    category: str
    kind: str
    severity: str
    message: str
    score: int
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuleHit:
    rule_id: str
    action: Decision
    severity: str
    category: str
    finding_kind: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PackageArtifact:
    package: str
    version: str
    tarball_path: Path
    extracted_path: Path
    artifact_sha256: str
    metadata: dict[str, Any]


@dataclass(slots=True)
class StaticAnalysisResult:
    score: int
    findings: list[Finding]
    fingerprints: list[dict[str, Any]]
    package_json: dict[str, Any]
    lifecycle_scripts: list[str]


@dataclass(slots=True)
class SandboxResult:
    findings: list[Finding]
    metadata: dict[str, Any]


@dataclass(slots=True)
class ScanReport:
    package: str
    version: str
    artifact_sha256: str
    static_score: int
    static_findings: list[Finding]
    dynamic_findings: list[Finding]
    rule_hits: list[RuleHit]
    decision: Decision
    duration_ms: int
    sandbox_metadata: dict[str, Any]
    installation: dict[str, Any] = field(default_factory=dict)
    ai_analysis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "static_score": self.static_score,
            "static_findings": [finding.to_dict() for finding in self.static_findings],
            "dynamic_findings": [finding.to_dict() for finding in self.dynamic_findings],
            "rule_hits": [rule_hit.to_dict() for rule_hit in self.rule_hits],
            "decision": self.decision,
            "duration_ms": self.duration_ms,
            "sandbox_metadata": self.sandbox_metadata,
            "installation": self.installation,
            "ai_analysis": self.ai_analysis,
        }
