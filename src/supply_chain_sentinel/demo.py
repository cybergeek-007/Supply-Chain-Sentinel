from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import ScanReport
from .pipeline import execute_install_scan


@dataclass(frozen=True, slots=True)
class FixtureScenario:
    package_dir: str
    expected_decision: str
    rationale: str


FIXTURE_SCENARIOS = [
    FixtureScenario(
        package_dir="benign-logger",
        expected_decision="allow",
        rationale="No lifecycle scripts should keep the package in the safe path.",
    ),
    FixtureScenario(
        package_dir="entropy-dropper",
        expected_decision="block",
        rationale="A binary high-entropy payload should be blocked statically without sandbox execution.",
    ),
    FixtureScenario(
        package_dir="credential-hunter",
        expected_decision="block",
        rationale="Lifecycle script plus sandbox-required behavior should fail closed or block.",
    ),
    FixtureScenario(
        package_dir="network-beacon",
        expected_decision="block",
        rationale="Lifecycle script plus network behavior should fail closed or block.",
    ),
]


def run_fixture_demo(
    project_root: Path,
    output_dir: Path,
    rules_path: Path,
    timeout: int,
    risk_threshold: int,
    high_entropy: float,
) -> dict[str, object]:
    fixtures_root = project_root / "samples" / "packages"
    output_dir.mkdir(parents=True, exist_ok=True)

    runs: list[dict[str, object]] = []
    for scenario in FIXTURE_SCENARIOS:
        package_path = fixtures_root / scenario.package_dir
        report_path = output_dir / f"{scenario.package_dir}.json"
        report = execute_install_scan(
            package_spec=str(package_path),
            project_root=project_root,
            rules_path=rules_path,
            json_report_path=report_path,
            timeout=timeout,
            risk_threshold=risk_threshold,
            high_entropy=high_entropy,
            perform_install=False,
        )
        runs.append(_build_run_summary(scenario, report, report_path))

    summary = {
        "fixture_count": len(runs),
        "match_count": sum(1 for run in runs if run["matched_expectation"]),
        "runs": runs,
    }
    summary["mismatches"] = [run["fixture"] for run in runs if not run["matched_expectation"]]
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def render_fixture_demo(summary: dict[str, object]) -> str:
    lines = [
        f"fixtures: {summary['fixture_count']}",
        f"matched_expectations: {summary['match_count']}",
    ]
    mismatches = summary.get("mismatches", [])
    if mismatches:
        lines.append(f"mismatches: {', '.join(mismatches)}")
    else:
        lines.append("mismatches: none")

    for run in summary["runs"]:
        lines.append(
            f"{run['fixture']}: expected={run['expected_decision']} actual={run['actual_decision']} matched={run['matched_expectation']}"
        )
    return "\n".join(lines)


def _build_run_summary(scenario: FixtureScenario, report: ScanReport, report_path: Path) -> dict[str, object]:
    return {
        "fixture": scenario.package_dir,
        "expected_decision": scenario.expected_decision,
        "actual_decision": report.decision,
        "matched_expectation": report.decision == scenario.expected_decision,
        "rationale": scenario.rationale,
        "package": report.package,
        "version": report.version,
        "static_score": report.static_score,
        "static_findings": len(report.static_findings),
        "dynamic_findings": len(report.dynamic_findings),
        "rule_hits": len(report.rule_hits),
        "duration_ms": report.duration_ms,
        "report_path": str(report_path),
        "sandbox_error": report.sandbox_metadata.get("error"),
    }
