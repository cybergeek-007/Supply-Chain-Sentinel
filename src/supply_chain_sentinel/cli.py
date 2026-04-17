from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .dashboard import build_dashboard
from .demo import render_fixture_demo, run_fixture_demo
from .env_loader import load_env_files
from .environment import overall_status, render_doctor_report, run_doctor
from .pipeline import execute_install_scan
from .report_corpus import render_corpus_summary, triage_report_corpus


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="Supply Chain Sentinel CLI")
    subparsers = parser.add_subparsers(dest="command_group", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check local runtime readiness")
    doctor_parser.add_argument("--timeout", type=int, default=20, help="Timeout in seconds for runtime probes")

    reports_parser = subparsers.add_parser("reports", help="Work with saved Sentinel JSON reports")
    reports_subparsers = reports_parser.add_subparsers(dest="reports_command", required=True)
    triage_parser = reports_subparsers.add_parser("triage", help="Summarize and triage a directory of reports")
    triage_parser.add_argument("input_dir", type=Path, help="Directory containing Sentinel JSON reports")
    triage_parser.add_argument(
        "--output",
        type=Path,
        default=Path("tmp") / "report-triage.json",
        help="Path for the aggregate triage summary JSON",
    )
    triage_parser.add_argument(
        "--ai-summary",
        action="store_true",
        help="Generate an optional Grok-powered corpus triage summary",
    )
    triage_parser.add_argument("--ai-model", help="Override the Grok model used for corpus triage")
    dashboard_parser = reports_subparsers.add_parser("dashboard", help="Render a static HTML dashboard from reports")
    dashboard_parser.add_argument("input_dir", type=Path, help="Directory containing Sentinel JSON reports")
    dashboard_parser.add_argument(
        "--output",
        type=Path,
        default=Path("tmp") / "report-dashboard.html",
        help="Path for the generated HTML dashboard",
    )

    demo_parser = subparsers.add_parser("demo", help="Run repeatable project demo flows")
    demo_subparsers = demo_parser.add_subparsers(dest="demo_command", required=True)
    fixtures_parser = demo_subparsers.add_parser("fixtures", help="Scan the bundled fixture packages")
    fixtures_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("tmp") / "demo-fixtures",
        help="Directory for per-fixture reports and the summary JSON",
    )
    fixtures_parser.add_argument(
        "--rules",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "config" / "default_rules.json",
        help="Path to JSON rules configuration",
    )
    fixtures_parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds for scan operations")
    fixtures_parser.add_argument("--risk-threshold", type=int, default=80, help="Static risk threshold")
    fixtures_parser.add_argument("--entropy-threshold", type=float, default=7.2, help="High-risk entropy threshold")

    npm_parser = subparsers.add_parser("npm", help="Scan npm packages before installation")
    npm_subparsers = npm_parser.add_subparsers(dest="command", required=True)

    install_parser = npm_subparsers.add_parser("install", help="Inspect and install an npm package")
    install_parser.add_argument("package", help="npm package spec to install")
    install_parser.add_argument("--json-report", type=Path, help="Write a JSON report to this path")
    install_parser.add_argument(
        "--rules",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "config" / "default_rules.json",
        help="Path to JSON rules configuration",
    )
    install_parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds for Docker operations")
    install_parser.add_argument(
        "--risk-threshold",
        type=int,
        default=80,
        help="Static risk threshold above which the package is blocked before sandbox execution",
    )
    install_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=7.2,
        help="High-risk Shannon entropy threshold",
    )
    install_parser.add_argument(
        "--no-install",
        action="store_true",
        help="Stop after evaluation and do not install approved packages",
    )
    install_parser.add_argument(
        "--ai-summary",
        action="store_true",
        help="Generate an optional Grok-powered analyst summary after the scan",
    )
    install_parser.add_argument(
        "--ai-model",
        help="Override the Grok model used for AI summaries",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    project_root = Path(__file__).resolve().parents[2]
    load_env_files(project_root)
    args = parser.parse_args(argv)

    if args.command_group == "doctor":
        checks = run_doctor(project_root=project_root, timeout=args.timeout)
        print(render_doctor_report(checks))
        return 0 if overall_status(checks) != "fail" else 1

    if args.command_group == "reports" and args.reports_command == "triage":
        summary = triage_report_corpus(
            input_dir=args.input_dir,
            output_path=args.output,
            ai_summary=args.ai_summary,
            ai_model=args.ai_model,
        )
        print(render_corpus_summary(summary))
        return 0

    if args.command_group == "reports" and args.reports_command == "dashboard":
        result = build_dashboard(args.input_dir, args.output)
        print(f"reports: {result['report_count']}")
        print(f"output: {result['output_path']}")
        print(f"source: {result['source_dir']}")
        return 0

    if args.command_group == "demo" and args.demo_command == "fixtures":
        summary = run_fixture_demo(
            project_root=project_root,
            output_dir=args.output_dir,
            rules_path=args.rules,
            timeout=args.timeout,
            risk_threshold=args.risk_threshold,
            high_entropy=args.entropy_threshold,
        )
        print(render_fixture_demo(summary))
        return 0 if not summary["mismatches"] else 1

    if args.command_group == "npm" and args.command == "install":
        report = execute_install_scan(
            package_spec=args.package,
            project_root=project_root,
            rules_path=args.rules,
            json_report_path=args.json_report,
            timeout=args.timeout,
            risk_threshold=args.risk_threshold,
            high_entropy=args.entropy_threshold,
            perform_install=not args.no_install,
            ai_summary=args.ai_summary,
            ai_model=args.ai_model,
        )
        print(_render_report(report))
        return 0 if report.decision == "allow" else 1

    parser.error("unsupported command")
    return 2


def _render_report(report) -> str:
    lines = [
        f"decision: {report.decision}",
        f"package: {report.package}@{report.version}",
        f"static_score: {report.static_score}",
        f"static_findings: {len(report.static_findings)}",
        f"dynamic_findings: {len(report.dynamic_findings)}",
        f"rule_hits: {len(report.rule_hits)}",
        f"duration_ms: {report.duration_ms}",
    ]
    install_method = report.installation.get("method")
    if install_method:
        lines.append(f"install_method: {install_method}")
    if report.installation.get("stderr"):
        lines.append(f"install_note: {report.installation['stderr']}")
    if report.sandbox_metadata.get("error"):
        lines.append(f"error: {report.sandbox_metadata['error']}")
    ai_status = report.ai_analysis.get("status")
    if ai_status:
        lines.append(f"ai_status: {ai_status}")
    if report.ai_analysis.get("model"):
        lines.append(f"ai_model: {report.ai_analysis['model']}")
    if report.ai_analysis.get("summary"):
        lines.append(f"ai_summary: {report.ai_analysis['summary']}")
    elif report.ai_analysis.get("reason"):
        lines.append(f"ai_note: {report.ai_analysis['reason']}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
