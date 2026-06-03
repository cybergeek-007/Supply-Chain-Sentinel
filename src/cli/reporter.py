"""Report exporters for Supply Chain Sentinel.

Provides :func:`export_json` and :func:`export_html` to persist analysis
results to disk in machine-readable and human-readable formats.

The HTML report uses an embedded dark-theme CSS stylesheet and requires
no external assets – the output file is fully self-contained.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def export_json(result: dict[str, Any], path: str) -> None:
    """Write the full analysis result to a pretty-printed JSON file.

    Args:
        result: Normalised pipeline result dict as returned by
            :class:`~src.core.python.pipeline.AnalysisPipeline`.
        path:   Destination file path.  Parent directories are created
                automatically if they do not exist.

    Raises:
        OSError: If the file cannot be written (e.g. permission denied).
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    with dest.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

_SEVERITY_BADGE_CSS: dict[str, str] = {
    "critical": "badge-critical",
    "high":     "badge-high",
    "medium":   "badge-medium",
    "low":      "badge-low",
    "info":     "badge-info",
}

_RISK_BAR_CSS: dict[str, str] = {
    "critical": "#ff2020",
    "high":     "#ff5555",
    "medium":   "#ffb86c",
    "low":      "#50fa7b",
}


def _badge(severity: str) -> str:
    """Return an HTML severity badge ``<span>``.

    Args:
        severity: Severity level string (case-insensitive).

    Returns:
        str: An HTML ``<span>`` element with the appropriate CSS class.
    """
    cls = _SEVERITY_BADGE_CSS.get(severity.lower(), "badge-info")
    return f'<span class="badge {cls}">{escape(severity.upper())}</span>'


def _risk_bar_html(risk_score: float, risk_level: str) -> str:
    """Return an HTML risk-score progress bar.

    Args:
        risk_score: Numeric score in [0, 100].
        risk_level: Textual risk level for colour selection.

    Returns:
        str: HTML markup string for the progress bar widget.
    """
    pct = max(0.0, min(100.0, float(risk_score)))
    color = _RISK_BAR_CSS.get(risk_level.lower(), "#6272a4")
    return (
        f'<div class="risk-bar-wrap">'
        f'<div class="risk-bar-fill" style="width:{pct:.1f}%;background:{color};">'
        f'</div>'
        f'<span class="risk-bar-label">{pct:.1f} / 100</span>'
        f'</div>'
    )


def _findings_table_html(findings: list[dict[str, Any]]) -> str:
    """Render the findings list as an HTML ``<table>``.

    Rows are sorted highest severity first.

    Args:
        findings: List of normalised finding dicts.

    Returns:
        str: HTML table markup, or a ``<p>`` element if there are no findings.
    """
    if not findings:
        return '<p class="no-findings">✔ No findings detected.</p>'

    _ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sorted_f = sorted(
        findings,
        key=lambda f: _ORDER.get(str(f.get("severity", "info")).lower(), 0),
        reverse=True,
    )

    rows: list[str] = []
    for idx, f in enumerate(sorted_f, start=1):
        sev  = str(f.get("severity", "info")).lower()
        file_val = escape(str(f.get("file", "")))
        line_val = f.get("line")
        if line_val:
            file_val = f"{file_val}:{escape(str(line_val))}"
        rows.append(
            f"<tr>"
            f"<td class='col-num'>{idx}</td>"
            f"<td class='col-sev'>{_badge(sev)}</td>"
            f"<td class='col-title'>{escape(str(f.get('title', '')))}</td>"
            f"<td class='col-file'><code>{file_val}</code></td>"
            f"<td class='col-desc'>{escape(str(f.get('description', '')))}</td>"
            f"<td class='col-src'>{escape(str(f.get('source', '')))}</td>"
            f"</tr>"
        )

    return textwrap.dedent(f"""\
        <table class="findings-table">
          <thead>
            <tr>
              <th>#</th>
              <th>SEVERITY</th>
              <th>RULE / TITLE</th>
              <th>FILE</th>
              <th>DESCRIPTION</th>
              <th>SOURCE</th>
            </tr>
          </thead>
          <tbody>
            {"".join(rows)}
          </tbody>
        </table>
    """)


_HTML_CSS = """\
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

/* ── Base ── */
:root {
  --bg:        #0d1117;
  --bg-card:   #161b22;
  --bg-table:  #1c2128;
  --border:    #30363d;
  --text:      #c9d1d9;
  --text-muted:#8b949e;
  --green:     #3fb950;
  --cyan:      #79c0ff;
  --yellow:    #e3b341;
  --red:       #ff7b72;
  --critical:  #ff2020;
  --high:      #ff5555;
  --medium:    #ffb86c;
  --low:       #50fa7b;
  --info:      #8be9fd;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Consolas, monospace;
  font-size: 14px;
  line-height: 1.6;
  padding: 2rem;
}

/* ── Header ── */
header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 1rem;
  margin-bottom: 2rem;
}
header h1 {
  color: var(--green);
  font-size: 1.8rem;
  letter-spacing: 2px;
  text-transform: uppercase;
}
header .subtitle {
  color: var(--text-muted);
  font-size: 0.85rem;
  margin-top: 0.25rem;
}

/* ── Section headings ── */
h2 {
  color: var(--cyan);
  font-size: 1rem;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  margin: 2rem 0 0.75rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.35rem;
}

/* ── Summary card ── */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.summary-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.9rem 1rem;
}
.summary-card .label {
  color: var(--text-muted);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 0.3rem;
}
.summary-card .value {
  font-size: 1.15rem;
  font-weight: 600;
  color: var(--text);
}

/* ── Risk bar ── */
.risk-bar-wrap {
  position: relative;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 4px;
  height: 22px;
  width: 100%;
  max-width: 320px;
  overflow: hidden;
  margin-top: 0.4rem;
}
.risk-bar-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.4s ease;
}
.risk-bar-label {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 0.75rem;
  font-weight: 700;
  color: #fff;
  text-shadow: 0 0 3px #000;
}

/* ── Severity badges ── */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.5px;
}
.badge-critical { background: #3d0000; color: var(--critical); border: 1px solid var(--critical); }
.badge-high     { background: #2d0000; color: var(--high);     border: 1px solid var(--high); }
.badge-medium   { background: #2d1a00; color: var(--medium);   border: 1px solid var(--medium); }
.badge-low      { background: #001a05; color: var(--low);      border: 1px solid var(--low); }
.badge-info     { background: #001a26; color: var(--info);     border: 1px solid var(--info); }

/* ── Findings table ── */
.findings-table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg-table);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
  font-size: 0.82rem;
}
.findings-table th {
  background: var(--bg-card);
  color: var(--cyan);
  text-transform: uppercase;
  letter-spacing: 1px;
  padding: 0.55rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  font-size: 0.72rem;
}
.findings-table td {
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  color: var(--text);
}
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:hover td { background: rgba(255,255,255,0.03); }
.col-num  { width: 40px;  color: var(--text-muted); text-align: right; }
.col-sev  { width: 90px;  text-align: center; }
.col-title{ min-width: 180px; }
.col-file { min-width: 180px; }
.col-file code { font-size: 0.78rem; color: var(--text-muted); word-break: break-all; }
.col-desc { color: var(--text-muted); }
.col-src  { width: 80px;  color: var(--text-muted); text-align: center; font-size: 0.75rem; }

.no-findings { color: var(--green); padding: 1rem 0; }

/* ── Footer ── */
footer {
  margin-top: 3rem;
  border-top: 1px solid var(--border);
  padding-top: 0.75rem;
  color: var(--text-muted);
  font-size: 0.78rem;
  text-align: center;
}
"""


def _severity_breakdown_html(findings: list[dict[str, Any]]) -> str:
    """Return an HTML summary block with per-severity finding counts.

    Args:
        findings: List of normalised finding dicts.

    Returns:
        str: HTML ``<div>`` markup with the severity breakdown cards.
    """
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    cards: list[str] = []
    for sev, cnt in counts.items():
        cards.append(
            f'<div class="summary-card">'
            f'<div class="label">{sev.upper()}</div>'
            f'<div class="value">{_badge(sev)}&nbsp;&nbsp;{cnt}</div>'
            f'</div>'
        )
    return '<div class="summary-grid">' + "".join(cards) + "</div>"


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------


def export_html(result: dict[str, Any], path: str) -> None:
    """Write a self-contained HTML analysis report to disk.

    The report includes:

    * A dark-themed header with tool name and timestamp
    * Summary cards (package, status, risk score, finding count)
    * A colour-coded risk-score progress bar
    * Per-severity finding breakdown
    * A sortable findings table with severity badges

    Args:
        result: Normalised pipeline result dict as returned by
            :class:`~src.core.python.pipeline.AnalysisPipeline`.
        path:   Destination file path.  Parent directories are created
                automatically.

    Raises:
        OSError: If the file cannot be written.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    package_name = escape(str(result.get("package_name", "unknown")))
    status       = escape(str(result.get("status", "unknown")).upper())
    risk_level   = str(result.get("risk_level", "low")).lower()
    risk_score   = float(result.get("risk_score", 0))
    duration     = result.get("duration_seconds")
    error        = result.get("error", "")
    findings: list[dict[str, Any]] = result.get("findings", [])

    now_utc = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Summary cards
    duration_str = f"{float(duration):.2f}s" if duration is not None else "n/a"
    summary_cards = textwrap.dedent(f"""\
        <div class="summary-grid">
          <div class="summary-card">
            <div class="label">Package</div>
            <div class="value">{package_name}</div>
          </div>
          <div class="summary-card">
            <div class="label">Status</div>
            <div class="value">{status}</div>
          </div>
          <div class="summary-card">
            <div class="label">Risk Level</div>
            <div class="value">{_badge(risk_level)}</div>
          </div>
          <div class="summary-card">
            <div class="label">Findings</div>
            <div class="value">{len(findings)}</div>
          </div>
          <div class="summary-card">
            <div class="label">Duration</div>
            <div class="value">{duration_str}</div>
          </div>
        </div>
    """)

    error_section = ""
    if error:
        error_section = (
            f'<h2>Errors</h2>'
            f'<p style="color:var(--red);padding:0.5rem 0;">{escape(str(error))}</p>'
        )

    html = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Supply Chain Sentinel – {package_name}</title>
          <style>{_HTML_CSS}</style>
        </head>
        <body>
          <header>
            <h1>&#x1F6E1; Supply Chain Sentinel</h1>
            <div class="subtitle">
              Static &amp; Dynamic Package Analysis &nbsp;|&nbsp; Report generated: {now_utc}
            </div>
          </header>

          <h2>Summary</h2>
          {summary_cards}

          <h2>Risk Score</h2>
          {_risk_bar_html(risk_score, risk_level)}
          <p style="color:var(--text-muted);font-size:0.8rem;margin-top:0.4rem;">
            Risk level: {_badge(risk_level)}
          </p>

          <h2>Severity Breakdown</h2>
          {_severity_breakdown_html(findings)}

          <h2>Findings ({len(findings)})</h2>
          {_findings_table_html(findings)}

          {error_section}

          <footer>
            Supply Chain Sentinel &nbsp;|&nbsp; github.com/cybergeek-007/Supply-Chain-Sentinel
            &nbsp;|&nbsp; {now_utc}
          </footer>
        </body>
        </html>
    """)

    with dest.open("w", encoding="utf-8") as fh:
        fh.write(html)
