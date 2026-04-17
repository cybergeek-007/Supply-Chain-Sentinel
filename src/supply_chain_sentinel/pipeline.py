from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from .ai_analysis import maybe_generate_ai_analysis
from .artifact import ArtifactError, ensure_workspace, install_vetted_artifact, prepare_artifact
from .models import ScanReport
from .rules import evaluate_rules, load_rules
from .sandbox import SandboxError, run_sandbox
from .static_analysis import run_static_analysis


def execute_install_scan(
    package_spec: str,
    project_root: Path,
    rules_path: Path,
    json_report_path: Path | None,
    timeout: int,
    risk_threshold: int,
    high_entropy: float = 7.2,
    perform_install: bool = True,
    ai_summary: bool = False,
    ai_model: str | None = None,
) -> ScanReport:
    started_at = time.perf_counter()
    workspace_root = ensure_workspace(project_root / "artifacts")
    artifact = None
    staging_dir = None
    static_result = None
    dynamic_result = None

    try:
        artifact, staging_dir = prepare_artifact(package_spec, workspace_root, timeout)
        static_result = run_static_analysis(
            artifact,
            risk_threshold=risk_threshold,
            high_entropy=high_entropy,
            yara_rules_path=project_root / "config" / "basic_signatures.yar",
        )

        if static_result.score < risk_threshold and static_result.lifecycle_scripts:
            dynamic_result = run_sandbox(artifact, project_root, timeout)

        rules = load_rules(rules_path)
        all_findings = list(static_result.findings)
        if dynamic_result:
            all_findings.extend(dynamic_result.findings)

        decision, rule_hits = evaluate_rules(
            rules=rules,
            findings=all_findings,
            static_score=static_result.score,
            static_threshold=risk_threshold,
        )

        installation = {"attempted": False, "skipped": not perform_install}
        sandbox_metadata = dynamic_result.metadata if dynamic_result else {"skipped": True}
        if decision == "allow" and perform_install:
            installation = install_vetted_artifact(artifact, Path.cwd(), timeout)

        report = ScanReport(
            package=artifact.package,
            version=artifact.version,
            artifact_sha256=artifact.artifact_sha256,
            static_score=static_result.score,
            static_findings=static_result.findings,
            dynamic_findings=dynamic_result.findings if dynamic_result else [],
            rule_hits=rule_hits,
            decision=decision,
            duration_ms=int((time.perf_counter() - started_at) * 1000),
            sandbox_metadata=sandbox_metadata
            | {"fingerprints": static_result.fingerprints, "lifecycle_scripts": static_result.lifecycle_scripts},
            installation=installation,
        )
        report.ai_analysis = maybe_generate_ai_analysis(
            report=report,
            enabled=ai_summary,
            model=ai_model,
        )
        if json_report_path:
            _write_report(report, json_report_path)
        return report
    except (ArtifactError, SandboxError, FileNotFoundError, ValueError) as exc:
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        static_findings = static_result.findings if static_result else []
        dynamic_findings = dynamic_result.findings if dynamic_result else []
        report = ScanReport(
            package=artifact.package if artifact else package_spec,
            version=artifact.version if artifact else "unknown",
            artifact_sha256=artifact.artifact_sha256 if artifact else "",
            static_score=static_result.score if static_result else 0,
            static_findings=static_findings,
            dynamic_findings=dynamic_findings,
            rule_hits=[],
            decision="block",
            duration_ms=duration_ms,
            sandbox_metadata={
                "error": str(exc),
                "fingerprints": static_result.fingerprints if static_result else [],
                "lifecycle_scripts": static_result.lifecycle_scripts if static_result else [],
            },
            installation={"attempted": False},
        )
        report.ai_analysis = maybe_generate_ai_analysis(
            report=report,
            enabled=ai_summary,
            model=ai_model,
        )
        if json_report_path:
            _write_report(report, json_report_path)
        return report
    finally:
        if staging_dir and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)


def _write_report(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
