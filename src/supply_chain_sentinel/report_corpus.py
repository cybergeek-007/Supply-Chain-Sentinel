from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .ai_analysis import maybe_generate_ai_corpus_analysis


REQUIRED_REPORT_KEYS = {
    "package",
    "version",
    "decision",
    "static_score",
    "static_findings",
    "dynamic_findings",
    "rule_hits",
}


def load_reports_from_dir(input_dir: Path) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for path in sorted(input_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if not REQUIRED_REPORT_KEYS.issubset(payload.keys()):
            continue
        payload["_report_path"] = str(path)
        reports.append(payload)
    return reports


def summarize_report_corpus(reports: list[dict[str, Any]]) -> dict[str, Any]:
    decision_counts = Counter()
    finding_kinds = Counter()
    rule_ids = Counter()
    sandbox_errors: list[dict[str, str]] = []
    watchlist_candidates: list[str] = []
    package_rows: list[dict[str, Any]] = []

    for report in reports:
        decision = str(report.get("decision", "unknown"))
        decision_counts[decision] += 1

        static_findings = report.get("static_findings", [])
        dynamic_findings = report.get("dynamic_findings", [])
        all_findings = []
        if isinstance(static_findings, list):
            all_findings.extend(static_findings)
        if isinstance(dynamic_findings, list):
            all_findings.extend(dynamic_findings)
        for finding in all_findings:
            if isinstance(finding, dict):
                kind = finding.get("kind")
                if isinstance(kind, str):
                    finding_kinds[kind] += 1

        for rule_hit in report.get("rule_hits", []):
            if isinstance(rule_hit, dict):
                rule_id = rule_hit.get("rule_id")
                if isinstance(rule_id, str):
                    rule_ids[rule_id] += 1

        sandbox_metadata = report.get("sandbox_metadata", {})
        sandbox_error = sandbox_metadata.get("error") if isinstance(sandbox_metadata, dict) else None
        if isinstance(sandbox_error, str):
            sandbox_errors.append(
                {
                    "package": str(report.get("package", "unknown")),
                    "error": sandbox_error,
                }
            )

        decision = str(report.get("decision", "unknown"))
        if decision in {"block", "warn"}:
            watchlist_candidates.append(str(report.get("package", "unknown")))

        package_rows.append(
            {
                "package": str(report.get("package", "unknown")),
                "version": str(report.get("version", "unknown")),
                "decision": decision,
                "static_score": int(report.get("static_score", 0)),
                "static_finding_count": len(static_findings) if isinstance(static_findings, list) else 0,
                "dynamic_finding_count": len(dynamic_findings) if isinstance(dynamic_findings, list) else 0,
                "report_path": report.get("_report_path"),
            }
        )

    summary = {
        "report_count": len(reports),
        "decision_counts": dict(decision_counts),
        "top_finding_kinds": _counter_rows(finding_kinds, "kind"),
        "top_rule_hits": _counter_rows(rule_ids, "rule_id"),
        "sandbox_errors": sandbox_errors,
        "watchlist_packages": sorted(set(watchlist_candidates)),
        "packages": package_rows,
    }
    return summary


def triage_report_corpus(
    input_dir: Path,
    output_path: Path,
    ai_summary: bool = False,
    ai_model: str | None = None,
) -> dict[str, Any]:
    reports = load_reports_from_dir(input_dir)
    summary = summarize_report_corpus(reports)
    summary["source_dir"] = str(input_dir.resolve())
    summary["ai_analysis"] = maybe_generate_ai_corpus_analysis(
        corpus_summary=summary,
        enabled=ai_summary,
        model=ai_model,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def render_corpus_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"reports: {summary['report_count']}",
        f"decisions: {summary['decision_counts']}",
        f"watchlist_packages: {', '.join(summary['watchlist_packages']) or 'none'}",
    ]
    if summary["top_finding_kinds"]:
        top_kinds = ", ".join(f"{row['kind']}={row['count']}" for row in summary["top_finding_kinds"])
        lines.append(f"top_finding_kinds: {top_kinds}")
    else:
        lines.append("top_finding_kinds: none")

    if summary["sandbox_errors"]:
        lines.append(f"sandbox_errors: {len(summary['sandbox_errors'])}")
    else:
        lines.append("sandbox_errors: 0")

    ai_analysis = summary.get("ai_analysis", {})
    if ai_analysis.get("status"):
        lines.append(f"ai_status: {ai_analysis['status']}")
    if ai_analysis.get("summary"):
        lines.append(f"ai_summary: {ai_analysis['summary']}")
    elif ai_analysis.get("reason"):
        lines.append(f"ai_note: {ai_analysis['reason']}")
    return "\n".join(lines)


def _counter_rows(counter: Counter[str], key_name: str) -> list[dict[str, Any]]:
    return [{key_name: key, "count": count} for key, count in counter.most_common(10)]
