"""Terminal output and display utilities for Supply Chain Sentinel.

Provides a Kali Linux / nmap-style aesthetic using the ``rich`` library.
All output is routed through a single shared :class:`rich.console.Console`
instance so that colour can be toggled globally via :func:`disable_color`.

Color palette:
    - Bright green  (#00FF41) – success / safe
    - Bright red              – errors / critical
    - Bright yellow           – warnings / medium severity
    - Cyan                    – informational / phase headers
    - Dim white               – secondary info / timestamps
"""

from __future__ import annotations

import math
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich import box

import sys
import os

# Force UTF-8 on Windows to avoid cp1252 encoding errors with rich
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

# ---------------------------------------------------------------------------
# Shared console
# ---------------------------------------------------------------------------

_console = Console(highlight=False)


def get_console() -> Console:
    """Return the shared :class:`rich.console.Console` instance.

    All display functions route through this single instance so that
    callers can swap in a no-color or file-backed console if needed.

    Returns:
        Console: The global rich Console object.
    """
    return _console


def disable_color() -> None:
    """Replace the global console with a no-color variant.

    Called when ``--no-color`` is passed on the command line.
    """
    global _console  # noqa: PLW0603
    _console = Console(highlight=False, no_color=True)


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

_BANNER = r"""
   _____ _           _          ____             _   _            _
  / ____| |         (_)        / ___|  ___ _ __ | |_(_)_ __   ___| |
 | |    | |__   __ _ _ _ __    \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |    | '_ \ / _` | | '_ \    ___) |  __/ | | | |_| | | | |  __/ |
  \____|_| |_|\__,_|_|_| |_|  |____/ \___|_| |_|\__|_|_| |_|\___|_|"""

_SUBTITLE = "[ Supply Chain Threat Detection & Analysis Framework ]"
_VERSION  = "v0.2.0"
_AUTHOR   = "github.com/cybergeek-007/Supply-Chain-Sentinel"


def print_banner() -> None:
    """Print the Supply Chain Sentinel ASCII art banner to the console.

    Renders the tool name in bright green with subtitle and version
    metadata in dim/cyan tones — matching the nmap/nuclei aesthetic.
    """
    console = get_console()
    banner_text = Text(_BANNER, style="bright_green bold")
    console.print(banner_text)
    console.print(f"  [cyan]{_SUBTITLE}[/cyan]")
    console.print(f"  [dim white]{_AUTHOR}[/dim white]  [bright_green]{_VERSION}[/bright_green]")
    console.print()


# ---------------------------------------------------------------------------
# Phase / status helpers
# ---------------------------------------------------------------------------


def print_phase(name: str) -> None:
    """Print a phase header in nmap/nuclei style.

    Example output::

        [*] Running static analysis...

    Args:
        name: Short description of the analysis phase being started.
    """
    get_console().print(f"[cyan]\\[*][/cyan] [bold]{name}[/bold]")


def print_success(msg: str) -> None:
    """Print a success message with a bright-green [+] prefix.

    Args:
        msg: The message body to display.
    """
    get_console().print(f"[bright_green]\\[+][/bright_green] {msg}")


def print_info(msg: str) -> None:
    """Print an informational message with a cyan [*] prefix.

    Args:
        msg: The message body to display.
    """
    get_console().print(f"[cyan]\\[*][/cyan] {msg}")


def print_warning(msg: str) -> None:
    """Print a warning message with a bright-yellow [!] prefix.

    Args:
        msg: The message body to display.
    """
    get_console().print(f"[bright_yellow]\\[!][/bright_yellow] {msg}")


def print_error(msg: str) -> None:
    """Print an error message with a bright-red [-] prefix.

    Args:
        msg: The message body to display.
    """
    get_console().print(f"[bright_red]\\[-][/bright_red] {msg}")


# ---------------------------------------------------------------------------
# Severity utilities
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high":     "bright_red",
    "medium":   "bright_yellow",
    "low":      "dim white",
    "info":     "cyan",
}

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


def _severity_style(severity: str) -> str:
    """Map a severity string to a rich style tag.

    Args:
        severity: Severity level string (case-insensitive).

    Returns:
        str: A rich markup style string.
    """
    return _SEVERITY_STYLE.get(severity.lower(), "white")


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------


def print_findings_table(findings: list[dict[str, Any]], title: str = "FINDINGS") -> None:
    """Render a rich table of analysis findings to the console.

    Rows are sorted by severity (critical → info) and each row receives
    a color that matches the finding's severity level.

    Columns: ``#`` | ``SEVERITY`` | ``RULE / TITLE`` | ``FILE`` | ``DESCRIPTION``

    Args:
        findings: List of finding dicts. Expected keys per entry:

            * ``severity``    – ``"critical" | "high" | "medium" | "low" | "info"``
            * ``title``       – Short rule or finding name
            * ``file``        – Source file path (may be empty string)
            * ``description`` – Human-readable description (may be empty)
            * ``line``        – Source line number (optional)

        title: Table header title. Defaults to ``"FINDINGS"``.
    """
    console = get_console()

    if not findings:
        print_info("No findings detected.")
        return

    # Sort by severity descending
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 0),
        reverse=True,
    )

    table = Table(
        title=f" {title} ",
        title_style="bold bright_green",
        box=box.DOUBLE_EDGE,
        border_style="bright_green",
        header_style="bold cyan",
        show_lines=True,
        expand=False,
        min_width=80,
    )

    table.add_column("#",           style="dim white", width=4,  justify="right")
    table.add_column("SEVERITY",    width=10, justify="center")
    table.add_column("RULE / TITLE", width=30)
    table.add_column("FILE",        width=30, overflow="fold")
    table.add_column("DESCRIPTION", overflow="fold")

    for idx, finding in enumerate(sorted_findings, start=1):
        sev   = str(finding.get("severity", "info")).lower()
        style = _severity_style(sev)

        sev_cell = Text(sev.upper(), style=style + " bold")
        title_cell = Text(str(finding.get("title", "")), style=style)
        file_part  = str(finding.get("file", ""))
        line_part  = finding.get("line")
        if line_part:
            file_part = f"{file_part}:{line_part}"
        file_cell  = Text(file_part, style="dim white")
        desc_cell  = Text(str(finding.get("description", "")), style="dim white")

        table.add_row(
            str(idx),
            sev_cell,
            title_cell,
            file_cell,
            desc_cell,
        )

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Risk score bar
# ---------------------------------------------------------------------------


def _risk_bar(score: float, width: int = 40) -> Text:
    """Build a colour-coded ASCII progress bar for a risk score (0-100).

    Args:
        score: Numeric risk score in the range [0, 100].
        width: Total character width of the bar. Defaults to 40.

    Returns:
        Text: A rich :class:`~rich.text.Text` object ready to print.
    """
    score = max(0.0, min(100.0, float(score)))
    filled = math.ceil(score / 100 * width)
    empty  = width - filled

    if score >= 75:
        bar_style = "bold bright_red"
    elif score >= 50:
        bar_style = "bold bright_yellow"
    elif score >= 25:
        bar_style = "bold cyan"
    else:
        bar_style = "bold bright_green"

    bar = Text()
    bar.append("[", style="dim white")
    bar.append("█" * filled, style=bar_style)
    bar.append("░" * empty,  style="dim white")
    bar.append("]", style="dim white")
    bar.append(f"  {score:.1f}/100", style=bar_style + " bold")
    return bar


_VERDICT_MAP: dict[str, tuple[str, str]] = {
    "clean":      ("✔  CLEAN",     "bold bright_green"),
    "safe":       ("✔  SAFE",      "bold bright_green"),
    "low":        ("✔  LOW RISK",  "bold bright_green"),
    "medium":     ("⚠  SUSPICIOUS","bold bright_yellow"),
    "high":       ("✘  HIGH RISK", "bold bright_red"),
    "critical":   ("✘  CRITICAL",  "bold red"),
    "suspicious": ("⚠  SUSPICIOUS","bold bright_yellow"),
    "failed":     ("✘  ERROR",     "bold red"),
    "partial":    ("⚠  PARTIAL",   "bold bright_yellow"),
    "unknown":    ("?  UNKNOWN",   "bold dim white"),
}


def print_summary_panel(result: dict[str, Any]) -> None:
    """Print the final analysis summary as a rich bordered panel.

    Displays:
    - Package name, version, status
    - Risk score bar (coloured by score range)
    - Verdict badge
    - Phase-level finding counts
    - Analysis duration (if available)

    Args:
        result: The top-level analysis result dict as returned by
            :class:`src.core.python.pipeline.AnalysisPipeline`.
    """
    console = get_console()

    package_name    = str(result.get("package_name", "unknown"))
    pkg_version     = str(result.get("package_version", ""))
    status          = str(result.get("status", "unknown")).lower()
    risk_score      = float(result.get("risk_score", 0))
    risk_level      = str(result.get("risk_level", "unknown")).lower()
    duration        = result.get("analysis_time") or result.get("duration_seconds")
    error_msg       = result.get("error", "")
    verdict_from    = str(result.get("verdict", "")).upper()
    recommendation  = str(result.get("recommendation", ""))
    all_findings: list[dict[str, Any]] = result.get("findings", [])

    # Severity bucket counts
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        sev = str(f.get("severity", "low")).lower()
        if sev in counts:
            counts[sev] += 1

    # Verdict — prefer pipeline verdict, fall back to risk level map
    if verdict_from and verdict_from not in {"", "UNKNOWN"}:
        verdict_map_key = verdict_from.lower()
    else:
        verdict_map_key = risk_level
    verdict_text, verdict_style = _VERDICT_MAP.get(
        verdict_map_key,
        _VERDICT_MAP.get(status, ("?  UNKNOWN", "bold dim white")),
    )
    # Override for specific pipeline verdicts
    if verdict_from == "MALICIOUS":
        verdict_text, verdict_style = "✘  MALICIOUS", "bold red"
    elif verdict_from == "SUSPICIOUS":
        verdict_text, verdict_style = "⚠  SUSPICIOUS", "bold bright_yellow"
    elif verdict_from == "SAFE":
        verdict_text, verdict_style = "✔  SAFE", "bold bright_green"
    elif verdict_from == "CAUTION":
        verdict_text, verdict_style = "⚠  CAUTION", "bold bright_yellow"

    # Display name
    display_name = package_name
    if pkg_version:
        display_name = f"{package_name}@{pkg_version}"

    # Build panel content
    lines = Text()
    lines.append("  Package  : ", style="dim white")
    lines.append(display_name + "\n", style="bold cyan")

    lines.append("  Status   : ", style="dim white")
    lines.append(status.upper() + "\n", style="bold white")

    lines.append("  Risk     : ", style="dim white")
    lines.append(_risk_bar(risk_score))
    lines.append("\n")

    lines.append("  Verdict  : ", style="dim white")
    lines.append(verdict_text + "\n", style=verdict_style)

    lines.append("\n")
    lines.append("  Findings : ", style="dim white")
    lines.append(f"{len(all_findings)} total  ", style="bold white")
    lines.append(f"CRIT:{counts['critical']}  ", style="bold red")
    lines.append(f"HIGH:{counts['high']}  ",     style="bright_red")
    lines.append(f"MED:{counts['medium']}  ",    style="bright_yellow")
    lines.append(f"LOW:{counts['low']}\n",       style="dim white")

    if recommendation:
        lines.append("\n")
        lines.append("  Advice   : ", style="dim white")
        lines.append(recommendation + "\n", style="bold white")

    # Threat intel breakdown
    if "threat_intel" in result.get("phases", {}) and result["phases"]["threat_intel"].get("reports"):
        reports = result["phases"]["threat_intel"]["reports"]
        lines.append("\n  Intel    : ", style="dim white")
        for type_, rep_list in reports.items():
            malicious_count = sum(1 for r in rep_list if getattr(r, "overall_malicious", False) or (isinstance(r, dict) and r.get("overall_malicious")))
            if malicious_count > 0:
                lines.append(f"{malicious_count} flagged {type_}s  ", style="bold red")
        lines.append("\n")

    # AI Explanation
    if "ai_analysis" in result.get("phases", {}):
        ai_data = result["phases"]["ai_analysis"]
        if ai_data.get("explanation"):
            lines.append("\n  AI Review:\n", style="bold cyan")
            for line in ai_data["explanation"].split("\n"):
                lines.append(f"    {line}\n", style="dim white")
                
    if duration is not None:
        lines.append("\n  Duration : ", style="dim white")
        lines.append(f"{float(duration):.2f}s\n", style="dim white")

    if error_msg:
        lines.append("\n")
        lines.append("  Error    : ", style="dim white")
        lines.append(str(error_msg) + "\n", style="bright_red")

    panel = Panel(
        lines,
        title="[bold bright_green]  ANALYSIS COMPLETE  [/bold bright_green]",
        border_style="bright_green",
        box=box.DOUBLE_EDGE,
        expand=False,
        padding=(0, 1),
    )

    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Progress context manager
# ---------------------------------------------------------------------------


def create_progress() -> Progress:
    """Create and return a rich :class:`~rich.progress.Progress` context manager.

    The progress display includes:
    - A spinner (dots style)
    - Task description text (green)
    - Bar column
    - Percentage complete
    - Items-of-total counter
    - Elapsed time

    Usage::

        with create_progress() as progress:
            task = progress.add_task("Extracting...", total=100)
            progress.advance(task, 10)

    Returns:
        Progress: A configured rich Progress instance (not yet started).
    """
    return Progress(
        SpinnerColumn(spinner_name="dots", style="bright_green"),
        TextColumn("[bright_green]{task.description}[/bright_green]"),
        BarColumn(bar_width=36, style="cyan", complete_style="bright_green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=get_console(),
        transient=False,
    )
