"""``sentinel audit`` – batch-scan every dependency in a project lockfile.

Parses ``package-lock.json`` (lockfile v2/v3) **or** ``yarn.lock`` to
extract dependency names + versions, then analyses each package through
the static analysis pipeline using a configurable thread-pool.

Usage::

    sentinel audit                           # auto-detect lockfile in cwd
    sentinel audit --lockfile yarn.lock      # explicit lockfile
    sentinel audit --concurrency 8 --json    # 8 threads, JSON output
    sentinel audit --fail-on suspicious      # exit 1 on SUSPICIOUS+

Exit codes:

* ``0`` – all packages SAFE
* ``1`` – at least one package met or exceeded the ``--fail-on`` threshold
* ``2`` – unrecoverable error
"""

from __future__ import annotations

import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click

from src.core.python.config import SentinelConfig
from src.core.python.pipeline import AnalysisPipeline

# Rich imports for pretty table output
from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Lockfile parsers
# ---------------------------------------------------------------------------

# Verdict severity ordering used by --fail-on
_VERDICT_SEVERITY: dict[str, int] = {
    "SAFE":       0,
    "CAUTION":    1,
    "SUSPICIOUS": 2,
    "MALICIOUS":  3,
}


def _parse_package_lock(path: Path) -> list[dict[str, str]]:
    """Parse ``package-lock.json`` (lockfile v2 or v3).

    Handles two layouts:
      - **v3 / v2-with-packages**: the ``packages`` object contains keys
        like ``node_modules/lodash`` with a ``version`` field.
      - **v2-only**: the top-level ``dependencies`` object has package
        names as keys, each with a ``version`` field.

    Args:
        path: Resolved path to the lockfile.

    Returns:
        A list of ``{"name": ..., "version": ...}`` dicts.

    Raises:
        json.JSONDecodeError: When the file is not valid JSON.
        KeyError: When neither ``packages`` nor ``dependencies`` is present.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # v3 / v2-with-packages: prefer the `packages` field
    packages: dict[str, Any] = data.get("packages", {})
    if packages:
        for key, info in packages.items():
            if not key:
                # The root package entry (empty string key) – skip it
                continue
            if not isinstance(info, dict):
                continue
            # Key format: "node_modules/<name>" or
            #             "node_modules/@scope/name"
            name = key.rsplit("node_modules/", 1)[-1] if "node_modules/" in key else key
            version = str(info.get("version", ""))
            if name and version and (name, version) not in seen:
                seen.add((name, version))
                deps.append({"name": name, "version": version})
        return deps

    # Fallback: v2 top-level `dependencies`
    dependencies: dict[str, Any] = data.get("dependencies", {})
    for name, info in dependencies.items():
        if not isinstance(info, dict):
            continue
        version = str(info.get("version", ""))
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            deps.append({"name": name, "version": version})

    return deps


def _parse_yarn_lock(path: Path) -> list[dict[str, str]]:
    """Parse a ``yarn.lock`` file (v1 format).

    The v1 yarn.lock format consists of blocks like::

        lodash@^4.17.21:
          version "4.17.21"
          resolved "https://..."
          integrity sha512-...

    Scoped packages appear as::

        "@babel/core@^7.0.0":
          version "7.24.0"

    Args:
        path: Resolved path to ``yarn.lock``.

    Returns:
        A list of ``{"name": ..., "version": ...}`` dicts.
    """
    content = path.read_text(encoding="utf-8")
    deps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # Match block headers: name@specifier, name@specifier:
    # Captures: optional quotes, package name, then @specifier
    header_re = re.compile(
        r'^"?(?P<name>@?[a-zA-Z0-9][\w./-]*)@[^:]+:?\s*$',
        re.MULTILINE,
    )
    version_re = re.compile(r'^\s+version\s+"(?P<ver>[^"]+)"', re.MULTILINE)

    for match in header_re.finditer(content):
        name = match.group("name")
        # Find the *next* version line after this header
        remaining = content[match.end():]
        ver_match = version_re.search(remaining)
        if ver_match:
            version = ver_match.group("ver")
            if (name, version) not in seen:
                seen.add((name, version))
                deps.append({"name": name, "version": version})

    return deps


def _detect_lockfile(directory: Path) -> Path:
    """Auto-detect a lockfile in *directory*.

    Checks in order: ``package-lock.json``, ``yarn.lock``.

    Args:
        directory: Project root to search.

    Returns:
        The resolved lockfile path.

    Raises:
        FileNotFoundError: When no supported lockfile is found.
    """
    for candidate in ("package-lock.json", "yarn.lock"):
        p = directory / candidate
        if p.is_file():
            return p
    raise FileNotFoundError(
        f"No package-lock.json or yarn.lock found in {directory}"
    )


def _parse_lockfile(path: Path) -> list[dict[str, str]]:
    """Dispatch to the correct parser based on filename.

    Args:
        path: Resolved path to the lockfile.

    Returns:
        Parsed dependency list.

    Raises:
        ValueError: For unsupported lockfile types.
    """
    name = path.name.lower()
    if name == "package-lock.json":
        return _parse_package_lock(path)
    if name == "yarn.lock":
        return _parse_yarn_lock(path)
    raise ValueError(f"Unsupported lockfile type: {path.name}")


# ---------------------------------------------------------------------------
# Single-package analysis wrapper
# ---------------------------------------------------------------------------


def _analyze_one(
    pipeline: AnalysisPipeline,
    name: str,
    version: str,
) -> dict[str, Any]:
    """Analyse a single npm package and return a summary dict.

    This is the unit of work submitted to the thread pool.  It wraps
    :meth:`AnalysisPipeline.analyze_npm` and normalises the result into
    a flat summary suitable for the audit table.

    Args:
        pipeline: A pre-configured :class:`AnalysisPipeline`.
        name:     npm package name (e.g. ``lodash``).
        version:  Resolved version string (e.g. ``4.17.21``).

    Returns:
        A dict with keys: ``name``, ``version``, ``verdict``,
        ``risk_score``, ``risk_level``, ``top_finding``, ``error``,
        and the full ``result``.
    """
    spec = f"{name}@{version}" if version else name
    try:
        result = pipeline.analyze_npm(spec, dynamic=False)
        findings = result.get("findings", [])
        top = findings[0]["title"] if findings else "—"
        return {
            "name": name,
            "version": version,
            "verdict": result.get("verdict", "UNKNOWN"),
            "risk_score": result.get("risk_score", 0),
            "risk_level": result.get("risk_level", "LOW"),
            "top_finding": top,
            "error": None,
            "result": result,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": name,
            "version": version,
            "verdict": "ERROR",
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "top_finding": str(exc)[:80],
            "error": str(exc),
            "result": None,
        }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_VERDICT_COLORS: dict[str, str] = {
    "SAFE":       "green",
    "CAUTION":    "yellow",
    "SUSPICIOUS": "bright_red",
    "MALICIOUS":  "bold red",
    "ERROR":      "dim",
    "UNKNOWN":    "dim",
}


def _render_table(summaries: list[dict[str, Any]], elapsed: float) -> None:
    """Print a rich summary table to the console.

    Args:
        summaries: List of per-package summary dicts from :func:`_analyze_one`.
        elapsed:   Total wall-clock time in seconds.
    """
    console = Console()
    table = Table(
        title="🔍 Supply Chain Sentinel – Audit Results",
        caption=f"{len(summaries)} packages scanned in {elapsed:.1f}s",
        show_lines=True,
    )
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="dim")
    table.add_column("Verdict", justify="center")
    table.add_column("Risk", justify="right")
    table.add_column("Top Finding", max_width=50)

    for s in summaries:
        color = _VERDICT_COLORS.get(s["verdict"], "white")
        table.add_row(
            s["name"],
            s["version"],
            f"[{color}]{s['verdict']}[/{color}]",
            str(s["risk_score"]),
            s["top_finding"],
        )

    console.print()
    console.print(table)


def _render_json(summaries: list[dict[str, Any]], elapsed: float) -> None:
    """Print machine-readable JSON to stdout.

    Each entry in the ``packages`` array contains the full pipeline
    result under ``result`` and the flattened summary fields at the
    top level.

    Args:
        summaries: List of per-package summary dicts.
        elapsed:   Total wall-clock time in seconds.
    """
    output = {
        "audit": {
            "total_packages": len(summaries),
            "scan_time_seconds": round(elapsed, 2),
            "packages": [
                {
                    "name": s["name"],
                    "version": s["version"],
                    "verdict": s["verdict"],
                    "risk_score": s["risk_score"],
                    "risk_level": s["risk_level"],
                    "top_finding": s["top_finding"],
                    "error": s["error"],
                    "result": s["result"],
                }
                for s in summaries
            ],
        },
    }
    click.echo(json.dumps(output, indent=2, default=str))


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------


@click.command("audit")
@click.option(
    "--lockfile",
    "-l",
    "lockfile_path",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    default=None,
    help="Path to package-lock.json or yarn.lock.  Auto-detected if omitted.",
)
@click.option(
    "--concurrency",
    "-c",
    type=int,
    default=4,
    show_default=True,
    help="Number of packages to analyse in parallel.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Emit results as JSON to stdout.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(
        ["caution", "suspicious", "malicious"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit 1 if any package reaches this verdict or worse.",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Disable result caching for this scan.",
)
@click.pass_context
def cmd_audit(
    ctx: click.Context,
    lockfile_path: str | None,
    concurrency: int,
    json_output: bool,
    fail_on: str | None,
    no_cache: bool,
) -> None:
    """Scan all dependencies in a project lockfile.

    \b
    Parses package-lock.json (v2/v3) or yarn.lock, then runs each
    dependency through the Sentinel analysis pipeline concurrently.

    \b
    Examples:
      sentinel audit
      sentinel audit --lockfile package-lock.json --concurrency 8
      sentinel audit --json --fail-on suspicious
    """
    console = Console()
    quiet: bool = ctx.obj.get("quiet", False) if ctx.obj else False

    # ---- Resolve lockfile ------------------------------------------------
    try:
        if lockfile_path:
            lockfile = Path(lockfile_path).resolve()
        else:
            lockfile = _detect_lockfile(Path.cwd())
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)

    if not quiet:
        console.print(
            f"[bold]📦 Parsing lockfile:[/bold] {lockfile.name}  "
            f"[dim]({lockfile.parent})[/dim]"
        )

    # ---- Parse -----------------------------------------------------------
    try:
        deps = _parse_lockfile(lockfile)
    except (json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        console.print(f"[bold red]Failed to parse lockfile:[/bold red] {exc}")
        sys.exit(2)

    if not deps:
        console.print("[yellow]No dependencies found in lockfile.[/yellow]")
        sys.exit(0)

    if not quiet:
        console.print(f"[bold]Found {len(deps)} dependencies — scanning …[/bold]\n")

    # ---- Build pipeline --------------------------------------------------
    try:
        config = SentinelConfig.from_sentinel_config()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        sys.exit(2)

    pipeline = AnalysisPipeline(config, no_cache=no_cache)

    # ---- Concurrent scan -------------------------------------------------
    summaries: list[dict[str, Any]] = []
    start = time.monotonic()

    max_workers = max(1, min(concurrency, len(deps)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_dep = {
            pool.submit(_analyze_one, pipeline, dep["name"], dep["version"]): dep
            for dep in deps
        }

        completed = 0
        for future in as_completed(future_to_dep):
            completed += 1
            summary = future.result()
            summaries.append(summary)

            # Live progress (non-JSON mode only)
            if not json_output and not quiet:
                color = _VERDICT_COLORS.get(summary["verdict"], "white")
                console.print(
                    f"  [{completed}/{len(deps)}] "
                    f"[cyan]{summary['name']}@{summary['version']}[/cyan] → "
                    f"[{color}]{summary['verdict']}[/{color}]"
                )

    elapsed = time.monotonic() - start

    # Sort by risk score descending for readability
    summaries.sort(key=lambda s: (-s["risk_score"], s["name"]))

    # ---- Output ----------------------------------------------------------
    if json_output:
        _render_json(summaries, elapsed)
    else:
        _render_table(summaries, elapsed)

    # ---- Exit code -------------------------------------------------------
    if fail_on:
        threshold = _VERDICT_SEVERITY.get(fail_on.upper(), 0)
        for s in summaries:
            pkg_severity = _VERDICT_SEVERITY.get(s["verdict"], 0)
            if pkg_severity >= threshold:
                if not json_output and not quiet:
                    console.print(
                        f"\n[bold red]⚠  Failing:[/bold red] "
                        f"{s['name']}@{s['version']} is "
                        f"[bold]{s['verdict']}[/bold] "
                        f"(threshold: {fail_on.upper()})"
                    )
                sys.exit(1)

    sys.exit(0)
