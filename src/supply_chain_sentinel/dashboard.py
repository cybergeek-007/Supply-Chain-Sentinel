from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .report_corpus import load_reports_from_dir, summarize_report_corpus


def build_dashboard(input_dir: Path, output_path: Path) -> dict[str, Any]:
    reports = load_reports_from_dir(input_dir)
    summary = summarize_report_corpus(reports)
    summary["source_dir"] = str(input_dir.resolve())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_dashboard_html(summary, reports), encoding="utf-8")
    return {
        "report_count": summary["report_count"],
        "output_path": str(output_path.resolve()),
        "source_dir": summary["source_dir"],
    }


def render_dashboard_html(summary: dict[str, Any], reports: list[dict[str, Any]]) -> str:
    decision_cards = "".join(
        _metric_card(name, count)
        for name, count in sorted(summary.get("decision_counts", {}).items())
    )
    top_finding_kinds = summary.get("top_finding_kinds", [])
    top_rule_hits = summary.get("top_rule_hits", [])
    watchlist = summary.get("watchlist_packages", [])
    sandbox_errors = summary.get("sandbox_errors", [])
    report_cards = "".join(_render_report_card(report) for report in reports)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Supply Chain Sentinel Dashboard</title>
  <style>
    :root {{
      --paper: #f5ede1;
      --panel: rgba(255, 251, 246, 0.86);
      --ink: #201918;
      --muted: #685e5a;
      --line: rgba(32, 25, 24, 0.10);
      --allow: #2f7d4b;
      --warn: #c7791b;
      --block: #a02b35;
      --shadow: 0 24px 60px rgba(59, 35, 20, 0.12);
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      font-family: "Aptos", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(47, 125, 75, 0.14), transparent 26%),
        radial-gradient(circle at top right, rgba(160, 43, 53, 0.10), transparent 30%),
        linear-gradient(180deg, #fbf4ea 0%, var(--paper) 100%);
    }}

    .wrap {{
      width: min(1220px, calc(100vw - 28px));
      margin: 20px auto 40px;
    }}

    .hero {{
      background: linear-gradient(145deg, rgba(255,255,255,0.82), rgba(255,244,226,0.88));
      border: 1px solid rgba(255,255,255,0.55);
      border-radius: 32px;
      box-shadow: var(--shadow);
      padding: 30px;
    }}

    .eyebrow {{
      margin: 0 0 10px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      font-size: 12px;
      font-weight: 700;
      color: #8f5d2b;
    }}

    h1 {{
      margin: 0;
      font-size: clamp(32px, 5vw, 56px);
      line-height: 1;
      font-family: Georgia, "Times New Roman", serif;
    }}

    .hero p {{
      max-width: 760px;
      color: var(--muted);
      line-height: 1.6;
      margin: 16px 0 0;
    }}

    .meta {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 18px;
    }}

    .chip {{
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(32, 25, 24, 0.06);
      color: var(--muted);
      font-size: 13px;
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 18px;
      margin-top: 18px;
    }}

    .panel {{
      grid-column: span 12;
      background: var(--panel);
      border-radius: 26px;
      border: 1px solid rgba(255,255,255,0.55);
      box-shadow: var(--shadow);
      padding: 22px;
    }}

    .half {{ grid-column: span 6; }}
    .third {{ grid-column: span 4; }}

    .panel h2 {{
      margin: 0 0 14px;
      font-size: 18px;
    }}

    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px;
    }}

    .metric {{
      border-radius: 22px;
      padding: 18px;
      color: white;
      min-height: 120px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      background: linear-gradient(140deg, #4f413d, #312824);
    }}

    .metric.allow {{ background: linear-gradient(140deg, #295f3e, #3a8c58); }}
    .metric.warn {{ background: linear-gradient(140deg, #9b5814, #db8b26); }}
    .metric.block {{ background: linear-gradient(140deg, #7d1f29, #c54652); }}

    .metric .label {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      opacity: 0.82;
    }}

    .metric .value {{
      font-size: 42px;
      font-weight: 800;
      line-height: 1;
    }}

    .stack {{
      display: grid;
      gap: 10px;
    }}

    .item {{
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.58);
      padding: 14px 16px;
    }}

    .item strong {{
      display: block;
      margin-bottom: 4px;
      font-size: 14px;
    }}

    .item span {{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
      word-break: break-word;
    }}

    .report-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(285px, 1fr));
      gap: 16px;
    }}

    .report-card {{
      border-radius: 22px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.72);
      padding: 18px;
    }}

    .report-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      margin-bottom: 14px;
    }}

    .package {{
      margin: 0;
      font-size: 20px;
      font-family: Georgia, "Times New Roman", serif;
    }}

    .version {{
      color: var(--muted);
      font-size: 13px;
      margin-top: 4px;
    }}

    .pill {{
      color: white;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .pill.allow {{ background: var(--allow); }}
    .pill.warn {{ background: var(--warn); }}
    .pill.block {{ background: var(--block); }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }}

    .stat {{
      border-radius: 16px;
      padding: 12px;
      background: rgba(32, 25, 24, 0.05);
    }}

    .stat .k {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 5px;
    }}

    .stat .v {{
      font-size: 20px;
      font-weight: 800;
      line-height: 1.1;
    }}

    .finding-list {{
      margin: 0;
      padding-left: 18px;
      color: var(--muted);
      display: grid;
      gap: 6px;
      font-size: 13px;
    }}

    .error {{
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(160, 43, 53, 0.08);
      border: 1px solid rgba(160, 43, 53, 0.18);
      color: #7d1f29;
      font-size: 13px;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    @media (max-width: 920px) {{
      .half, .third {{ grid-column: span 12; }}
      .hero {{ padding: 24px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <p class="eyebrow">Supply Chain Sentinel</p>
      <h1>Deterministic Scan Dashboard</h1>
      <p>
        A static visual snapshot built from saved Sentinel scan reports. Use it for demos, CI artifacts,
        or DPR appendices when you want a clear picture of decisions, recurring signals, and package-level evidence.
      </p>
      <div class="meta">
        <span class="chip">Source: {html.escape(str(summary.get("source_dir", "unknown")))}</span>
        <span class="chip">Reports: {summary.get("report_count", 0)}</span>
        <span class="chip">Watchlist: {len(watchlist)}</span>
      </div>
    </section>

    <section class="grid">
      <div class="panel">
        <h2>Decision Overview</h2>
        <div class="metrics">{decision_cards or _metric_card("reports", 0)}</div>
      </div>

      <div class="panel half">
        <h2>Top Finding Kinds</h2>
        <div class="stack">{_render_counter_items(top_finding_kinds, "kind", "Observed {count} time(s) across this corpus.")}</div>
      </div>

      <div class="panel half">
        <h2>Top Rule Hits</h2>
        <div class="stack">{_render_counter_items(top_rule_hits, "rule_id", "Triggered {count} time(s) across this corpus.")}</div>
      </div>

      <div class="panel third">
        <h2>Watchlist</h2>
        <div class="stack">{_render_watchlist(watchlist)}</div>
      </div>

      <div class="panel third">
        <h2>Sandbox Reliability</h2>
        <div class="stack">{_render_sandbox_errors(sandbox_errors)}</div>
      </div>

      <div class="panel third">
        <h2>Corpus Notes</h2>
        <div class="stack">
          <div class="item"><strong>Report volume</strong><span>{summary.get("report_count", 0)} reports included in this snapshot.</span></div>
          <div class="item"><strong>Blocked or warned</strong><span>{len(watchlist)} packages are currently on the watchlist.</span></div>
          <div class="item"><strong>Runtime stability</strong><span>{len(sandbox_errors)} reports recorded sandbox runtime issues.</span></div>
        </div>
      </div>

      <div class="panel">
        <h2>Package Reports</h2>
        <div class="report-grid">{report_cards}</div>
      </div>
    </section>
  </div>
</body>
</html>
"""


def _metric_card(label: str, count: int) -> str:
    cls = str(label).lower()
    if cls not in {"allow", "warn", "block"}:
        cls = "unknown"
    return (
        f'<article class="metric {html.escape(cls)}">'
        f'<span class="label">{html.escape(str(label))}</span>'
        f'<span class="value">{count}</span>'
        "</article>"
    )


def _render_counter_items(rows: list[dict[str, Any]], key_name: str, text_template: str) -> str:
    if not rows:
        return '<div class="item"><strong>No data yet</strong><span>Run more scans to populate this panel.</span></div>'
    items = []
    for row in rows:
        label = html.escape(str(row.get(key_name, "unknown")))
        count = int(row.get("count", 0))
        items.append(
            f'<div class="item"><strong>{label}</strong><span>{html.escape(text_template.format(count=count))}</span></div>'
        )
    return "".join(items)


def _render_watchlist(watchlist: list[str]) -> str:
    if not watchlist:
        return '<div class="item"><strong>None</strong><span>No warned or blocked packages in this snapshot.</span></div>'
    return "".join(
        f'<div class="item"><strong>{html.escape(package)}</strong><span>Keep this package under review.</span></div>'
        for package in watchlist
    )


def _render_sandbox_errors(errors: list[dict[str, str]]) -> str:
    if not errors:
        return '<div class="item"><strong>Stable</strong><span>No sandbox errors were recorded in this corpus.</span></div>'
    return "".join(
        f'<div class="item"><strong>{html.escape(error["package"])}</strong><span>{html.escape(error["error"])}</span></div>'
        for error in errors
    )


def _render_report_card(report: dict[str, Any]) -> str:
    package = html.escape(str(report.get("package", "unknown")))
    version = html.escape(str(report.get("version", "unknown")))
    decision = str(report.get("decision", "unknown"))
    static_findings = report.get("static_findings", [])
    dynamic_findings = report.get("dynamic_findings", [])
    report_path = html.escape(str(report.get("_report_path", "")))
    sandbox_metadata = report.get("sandbox_metadata", {})
    error = sandbox_metadata.get("error") if isinstance(sandbox_metadata, dict) else None
    finding_messages = []
    for finding in static_findings[:2]:
        if isinstance(finding, dict):
            finding_messages.append(str(finding.get("message", finding.get("kind", "static finding"))))
    for finding in dynamic_findings[:2]:
        if isinstance(finding, dict):
            finding_messages.append(str(finding.get("message", finding.get("kind", "dynamic finding"))))
    if not finding_messages:
        finding_messages = ["No major findings were recorded."]
    finding_markup = "".join(f"<li>{html.escape(message)}</li>" for message in finding_messages)
    error_markup = f'<div class="error">{html.escape(str(error))}</div>' if isinstance(error, str) and error else ""

    return f"""
    <article class="report-card">
      <div class="report-header">
        <div>
          <h3 class="package">{package}</h3>
          <div class="version">Version {version}</div>
        </div>
        <span class="pill {html.escape(decision if decision in {'allow', 'warn', 'block'} else 'warn')}">{html.escape(decision)}</span>
      </div>
      <div class="stats">
        <div class="stat"><span class="k">Static Score</span><span class="v">{int(report.get('static_score', 0))}</span></div>
        <div class="stat"><span class="k">Static Findings</span><span class="v">{len(static_findings) if isinstance(static_findings, list) else 0}</span></div>
        <div class="stat"><span class="k">Dynamic Findings</span><span class="v">{len(dynamic_findings) if isinstance(dynamic_findings, list) else 0}</span></div>
        <div class="stat"><span class="k">Report Path</span><span class="v" style="font-size:13px;">{report_path or "&mdash;"}</span></div>
      </div>
      <ul class="finding-list">{finding_markup}</ul>
      {error_markup}
    </article>
    """
