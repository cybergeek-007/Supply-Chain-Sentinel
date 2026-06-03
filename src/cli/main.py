"""Supply Chain Sentinel – main Click CLI entry point.

Usage::

    sentinel [OPTIONS] COMMAND [ARGS]

Commands
--------
npm     Analyse an npm package fetched directly from the registry.
file    Analyse a local ``.tgz`` package archive.
scan    Analyse an already-extracted package directory.

Global options apply before any command (``--no-color``, ``--quiet``,
``--verbose``, ``--version``).  Each command also accepts
``--static-only``, ``--dynamic``, ``--output``, ``--report``, and
``--timeout``.

Exit codes:

* ``0`` – analysis complete, no significant findings
* ``1`` – one or more findings / package flagged as suspicious
* ``2`` – unrecoverable error during analysis

"""

from __future__ import annotations

import json
import sys
from typing import Any

import click

from src.cli.display import (
    disable_color,
    get_console,
    print_banner,
    print_error,
    print_findings_table,
    print_info,
    print_phase,
    print_summary_panel,
    print_warning,
)
from src.core.python.config import SentinelConfig
from src.core.python.pipeline import AnalysisPipeline

# Package version – single source of truth via importlib.metadata when
# the project is installed; falls back to a literal during development.
try:
    from importlib.metadata import version as _pkg_version

    _VERSION = _pkg_version("supply-chain-sentinel")
except Exception:
    _VERSION = "0.2.0"


# ---------------------------------------------------------------------------
# Shared option decorator helpers
# ---------------------------------------------------------------------------

_analysis_options = [
    click.option(
        "--static-only",
        is_flag=True,
        default=False,
        help="Run static analysis only (skip dynamic sandbox).",
    ),
    click.option(
        "--dynamic",
        is_flag=True,
        default=False,
        help="Include dynamic sandbox analysis (requires Docker).",
    ),
    click.option(
        "--output",
        "-o",
        "output_format",
        type=click.Choice(["table", "json"], case_sensitive=False),
        default="table",
        show_default=True,
        help="Output format for findings.",
    ),
    click.option(
        "--json",
        "json_output",
        is_flag=True,
        default=False,
        help="Shortcut for --output json.",
    ),
    click.option(
        "--explain",
        is_flag=True,
        default=False,
        help="Force AI explanation regardless of risk score.",
    ),
    click.option(
        "--report",
        "-r",
        "report_file",
        metavar="FILE",
        default=None,
        help="Write a report to FILE (.json or .html auto-detected).",
    ),
    click.option(
        "--timeout",
        "-t",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Override sandbox timeout (default: from config).",
    ),
]


def _add_analysis_options(func: Any) -> Any:
    """Attach shared analysis options to a Click command.

    Args:
        func: The Click command function to decorate.

    Returns:
        The decorated function with analysis options attached.
    """
    for option in reversed(_analysis_options):
        func = option(func)
    return func


# ---------------------------------------------------------------------------
# Result handling helpers
# ---------------------------------------------------------------------------


def _emit_results(
    result: dict[str, Any],
    output_format: str,
    report_file: str | None,
    quiet: bool,
    verbose: bool,
) -> None:
    """Render analysis results to the terminal and optionally to a report file.

    Args:
        result:        Normalised pipeline result dict.
        output_format: ``"table"`` or ``"json"``.
        report_file:   Optional path for the output report. Suffix
                       determines format (``.json`` → JSON, ``.html`` → HTML).
        quiet:         Suppress all output except errors.
        verbose:       Show all finding details regardless of count.
    """
    from src.cli.reporter import export_html, export_json  # local import avoids circular

    if output_format == "json":
        click.echo(json.dumps(result, indent=2, default=str))
    elif not quiet:
        findings = result.get("findings", [])
        if findings:
            print_findings_table(findings, title="FINDINGS")
        elif verbose:
            print_info("No findings detected.")

        print_summary_panel(result)

    if report_file:
        rfile = report_file.lower()
        try:
            if rfile.endswith(".html"):
                export_html(result, report_file)
                if not quiet:
                    print_info(f"HTML report written → {report_file}")
            else:
                export_json(result, report_file)
                if not quiet:
                    print_info(f"JSON report written → {report_file}")
        except OSError as exc:
            print_error(f"Could not write report: {exc}")


def _exit_code(result: dict[str, Any]) -> int:
    """Determine the CLI exit code from the analysis result.

    Args:
        result: Normalised pipeline result dict.

    Returns:
        int: ``0`` (clean), ``1`` (findings / suspicious), or ``2`` (error).
    """
    status = str(result.get("status", "")).lower()
    if status in {"failed", "error"}:
        return 2
    risk = str(result.get("risk_level", "LOW")).upper()
    verdict = str(result.get("verdict", "")).upper()
    if risk in {"HIGH", "CRITICAL"} or verdict in {"MALICIOUS", "SUSPICIOUS"}:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group(
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 120},
    invoke_without_command=True,
)
@click.option("--no-color",  is_flag=True, default=False, help="Disable ANSI color output.")
@click.option("--quiet",  "-q", is_flag=True, default=False, help="Suppress banner and non-essential output.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose / debug output.")
@click.version_option(_VERSION, "--version", prog_name="sentinel")
@click.pass_context
def cli(ctx: click.Context, no_color: bool, quiet: bool, verbose: bool) -> None:
    """Supply Chain Sentinel – npm package threat analysis tool.

    \b
    Detect malicious code, obfuscated payloads, and supply-chain
    attacks in npm packages using static and dynamic analysis.

    \b
    Examples:
      sentinel npm lodash@4.17.21
      sentinel npm react --dynamic --report report.html
      sentinel file ./package.tgz --output json
      sentinel scan ./extracted/ --static-only
    """
    # Persist shared state for sub-commands
    ctx.ensure_object(dict)
    ctx.obj["quiet"]   = quiet
    ctx.obj["verbose"] = verbose

    if no_color:
        disable_color()

    if ctx.invoked_subcommand is None:
        if not quiet:
            print_banner()
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# npm command
# ---------------------------------------------------------------------------


@cli.command("npm")
@click.argument("package_spec", metavar="PACKAGE[@VERSION]")
@_add_analysis_options
@click.pass_context
def cmd_npm(
    ctx: click.Context,
    package_spec: str,
    static_only: bool,
    dynamic: bool,
    output_format: str,
    json_output: bool,
    explain: bool,
    report_file: str | None,
    timeout: int | None,
) -> None:
    """Fetch and analyse an npm package from the registry.

    \b
    PACKAGE[@VERSION] examples:
      lodash
      lodash@4.17.21
      @types/node@18.0.0
    """
    quiet:   bool = ctx.obj.get("quiet",   False)
    verbose: bool = ctx.obj.get("verbose", False)

    # --json is a shortcut for --output json
    if json_output:
        output_format = "json"

    if not quiet:
        print_banner()
        print_phase(f"Fetching npm package: [bold cyan]{package_spec}[/bold cyan]")

    use_dynamic = dynamic and not static_only

    try:
        config   = SentinelConfig.from_sentinel_config()

        # --explain: force AI analysis regardless of risk score
        if explain and hasattr(config, "ai_enabled"):
            config.ai_enabled = True

        pipeline = AnalysisPipeline(config)

        if not quiet:
            print_phase("Running static analysis ...")

        result = pipeline.analyze_npm(
            package_spec,
            dynamic=use_dynamic,
            timeout=timeout,
        )

    except FileNotFoundError as exc:
        print_error(f"Package not found: {exc}")
        sys.exit(2)
    except RuntimeError as exc:
        print_error(f"Runtime error: {exc}")
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        print_error(f"Unexpected error: {exc}")
        if verbose:
            import traceback
            get_console().print_exception()
        sys.exit(2)

    _emit_results(result, output_format, report_file, quiet, verbose)
    sys.exit(_exit_code(result))


# ---------------------------------------------------------------------------
# file command
# ---------------------------------------------------------------------------


@cli.command("file")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, readable=True))
@_add_analysis_options
@click.pass_context
def cmd_file(
    ctx: click.Context,
    path: str,
    static_only: bool,
    dynamic: bool,
    output_format: str,
    json_output: bool,
    explain: bool,
    report_file: str | None,
    timeout: int | None,
) -> None:
    """Analyse a local .tgz package archive.

    \b
    PATH must be a readable file (typically an npm .tgz tarball).

    \b
    Examples:
      sentinel file ./lodash-4.17.21.tgz
      sentinel file ./package.tgz --dynamic --report report.html
    """
    quiet:   bool = ctx.obj.get("quiet",   False)
    verbose: bool = ctx.obj.get("verbose", False)

    if json_output:
        output_format = "json"

    if not quiet:
        print_banner()
        print_phase(f"Analysing local archive: [bold cyan]{path}[/bold cyan]")

    use_dynamic = dynamic and not static_only

    try:
        config   = SentinelConfig.from_sentinel_config()
        if explain and hasattr(config, "ai_enabled"):
            config.ai_enabled = True
        pipeline = AnalysisPipeline(config)

        if not quiet:
            print_phase("Running static analysis ...")

        result = pipeline.analyze_file(
            path,
            dynamic=use_dynamic,
            timeout=timeout,
        )

    except FileNotFoundError as exc:
        print_error(f"File not found: {exc}")
        sys.exit(2)
    except RuntimeError as exc:
        print_error(f"Runtime error: {exc}")
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        print_error(f"Unexpected error: {exc}")
        if verbose:
            get_console().print_exception()
        sys.exit(2)

    _emit_results(result, output_format, report_file, quiet, verbose)
    sys.exit(_exit_code(result))


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@cli.command("scan")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, readable=True))
@_add_analysis_options
@click.pass_context
def cmd_scan(
    ctx: click.Context,
    directory: str,
    static_only: bool,
    dynamic: bool,
    output_format: str,
    json_output: bool,
    explain: bool,
    report_file: str | None,
    timeout: int | None,
) -> None:
    """Analyse an already-extracted package directory.

    \b
    DIRECTORY must be a readable directory containing an extracted npm
    package (i.e. with a package.json at the top level or one level deep).

    \b
    Examples:
      sentinel scan ./node_modules/lodash/
      sentinel scan /tmp/extracted-pkg --static-only --output json
    """
    quiet:   bool = ctx.obj.get("quiet",   False)
    verbose: bool = ctx.obj.get("verbose", False)

    if json_output:
        output_format = "json"

    if not quiet:
        print_banner()
        print_phase(f"Scanning directory: [bold cyan]{directory}[/bold cyan]")

    use_dynamic = dynamic and not static_only

    try:
        config   = SentinelConfig.from_sentinel_config()
        if explain and hasattr(config, "ai_enabled"):
            config.ai_enabled = True
        pipeline = AnalysisPipeline(config)

        if not quiet:
            print_phase("Running static analysis ...")

        result = pipeline.analyze_directory(
            directory,
            dynamic=use_dynamic,
            timeout=timeout,
        )

    except NotADirectoryError as exc:
        print_error(f"Not a valid directory: {exc}")
        sys.exit(2)
    except RuntimeError as exc:
        print_error(f"Runtime error: {exc}")
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        print_error(f"Unexpected error: {exc}")
        if verbose:
            get_console().print_exception()
        sys.exit(2)

    _emit_results(result, output_format, report_file, quiet, verbose)
    sys.exit(_exit_code(result))


# ---------------------------------------------------------------------------
# setup command
# ---------------------------------------------------------------------------

@cli.command("setup")
def cmd_setup() -> None:
    """Run the interactive setup wizard for AI and Threat Intel."""
    from src.cli.setup import run_setup
    run_setup()

# ---------------------------------------------------------------------------
# Register remaining commands
# ---------------------------------------------------------------------------

from src.cli.audit import cmd_audit
from src.cli.sbom import cmd_sbom

cli.add_command(cmd_audit)
cli.add_command(cmd_sbom)

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
