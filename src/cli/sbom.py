"""``sentinel sbom`` – generate Software Bill of Materials from lockfiles.

Produces SBOM documents in either **CycloneDX 1.5** or **SPDX 2.3** JSON
format.  No external SBOM libraries are required — JSON is constructed
manually for a zero-dependency approach.

Usage::

    sentinel sbom package-lock.json
    sentinel sbom package-lock.json --format spdx -o sbom.spdx.json
    sentinel sbom yarn.lock --format cyclonedx -o sbom.cdx.json --analyze

Exit codes:

* ``0`` – SBOM generated successfully
* ``2`` – unrecoverable error
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console

# Re-use the lockfile parsers from the audit command
from src.cli.audit import _parse_lockfile

# Optional: pipeline for vulnerability enrichment
try:
    from src.core.python.config import SentinelConfig
    from src.core.python.pipeline import AnalysisPipeline

    _HAS_PIPELINE = True
except ImportError:
    _HAS_PIPELINE = False

# Package version — mirrors src.cli.main
try:
    from importlib.metadata import version as _pkg_version

    _TOOL_VERSION = _pkg_version("supply-chain-sentinel")
except Exception:
    _TOOL_VERSION = "0.2.0"


# ---------------------------------------------------------------------------
# CycloneDX 1.5 generator
# ---------------------------------------------------------------------------


def _generate_cyclonedx(
    deps: list[dict[str, str]],
    lockfile_name: str,
    vulnerabilities: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 JSON SBOM from a dependency list.

    Follows the CycloneDX 1.5 specification:
    https://cyclonedx.org/docs/1.5/json/

    Args:
        deps:            List of ``{"name": ..., "version": ...}`` dicts.
        lockfile_name:   Name of the source lockfile for metadata.
        vulnerabilities: Optional mapping of ``"name@version"`` to lists
                         of finding dicts from the Sentinel pipeline.

    Returns:
        A CycloneDX 1.5-compliant dict ready for ``json.dumps``.
    """
    serial = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    components: list[dict[str, Any]] = []
    for dep in deps:
        name = dep["name"]
        version = dep["version"]

        # Build Package URL (purl) — npm namespace
        # Scoped packages: pkg:npm/%40scope/name@version
        if name.startswith("@"):
            purl = f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"
        else:
            purl = f"pkg:npm/{name}@{version}"

        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "bom-ref": f"{name}@{version}",
        }
        components.append(component)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "supply-chain-sentinel",
                        "version": _TOOL_VERSION,
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": lockfile_name,
                "bom-ref": "root-application",
            },
        },
        "components": components,
    }

    # Append vulnerability data if available
    if vulnerabilities:
        vuln_entries: list[dict[str, Any]] = []
        for spec, findings in vulnerabilities.items():
            for finding in findings:
                vuln_entry: dict[str, Any] = {
                    "id": finding.get("id", "unknown"),
                    "source": {
                        "name": "supply-chain-sentinel",
                        "url": "https://github.com/supply-chain-sentinel",
                    },
                    "description": finding.get("title", ""),
                    "recommendation": finding.get("evidence", ""),
                    "ratings": [
                        {
                            "severity": _cdx_severity(finding.get("severity", "low")),
                            "score": finding.get("confidence", 0.0),
                            "method": "other",
                        }
                    ],
                    "affects": [
                        {
                            "ref": spec,
                        }
                    ],
                }
                vuln_entries.append(vuln_entry)
        if vuln_entries:
            bom["vulnerabilities"] = vuln_entries

    return bom


def _cdx_severity(sentinel_severity: str) -> str:
    """Map Sentinel severity to CycloneDX severity.

    Args:
        sentinel_severity: One of ``critical``, ``high``, ``medium``,
                           ``low``, ``info``.

    Returns:
        CycloneDX-compatible severity string.
    """
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(sentinel_severity.lower(), "unknown")


# ---------------------------------------------------------------------------
# SPDX 2.3 generator
# ---------------------------------------------------------------------------


def _generate_spdx(
    deps: list[dict[str, str]],
    lockfile_name: str,
) -> dict[str, Any]:
    """Build an SPDX 2.3 JSON SBOM from a dependency list.

    Follows the SPDX 2.3 specification:
    https://spdx.github.io/spdx-spec/v2.3/

    Args:
        deps:          List of ``{"name": ..., "version": ...}`` dicts.
        lockfile_name: Name of the source lockfile for metadata.

    Returns:
        An SPDX 2.3-compliant dict ready for ``json.dumps``.
    """
    doc_uuid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages: list[dict[str, Any]] = []

    # Document-level package (root)
    packages.append({
        "SPDXID": "SPDXRef-RootPackage",
        "name": lockfile_name,
        "versionInfo": "",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "NOASSERTION",
    })

    relationships: list[dict[str, Any]] = []

    for idx, dep in enumerate(deps, start=1):
        name = dep["name"]
        version = dep["version"]

        # Sanitise name for SPDX ID (only letters, digits, dots, hyphens)
        safe_name = "".join(
            c if c.isalnum() or c in ".-" else "-" for c in name
        )
        spdx_id = f"SPDXRef-Package-{safe_name}-{idx}"

        # Build Package URL
        if name.startswith("@"):
            purl = f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"
        else:
            purl = f"pkg:npm/{name}@{version}"

        pkg: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ],
        }
        packages.append(pkg)

        # Relationship: root DEPENDS_ON this package
        relationships.append({
            "spdxElementId": "SPDXRef-RootPackage",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id,
        })

    # Document describes the root package
    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-RootPackage",
    })

    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sentinel-sbom-{lockfile_name}",
        "documentNamespace": (
            f"https://spdx.org/spdxdocs/sentinel-{doc_uuid}"
        ),
        "creationInfo": {
            "created": now,
            "creators": [
                f"Tool: supply-chain-sentinel-{_TOOL_VERSION}",
                "Organization: Supply Chain Sentinel",
            ],
            "licenseListVersion": "3.22",
        },
        "packages": packages,
        "relationships": relationships,
    }

    return doc


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------


@click.command("sbom")
@click.argument(
    "lockfile",
    type=click.Path(exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--format",
    "-f",
    "sbom_format",
    type=click.Choice(["cyclonedx", "spdx"], case_sensitive=False),
    default="cyclonedx",
    show_default=True,
    help="SBOM output format.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write SBOM to file instead of stdout.",
)
@click.option(
    "--analyze",
    is_flag=True,
    default=False,
    help="Run Sentinel analysis and include vulnerabilities (CycloneDX only).",
)
@click.pass_context
def cmd_sbom(
    ctx: click.Context,
    lockfile: str,
    sbom_format: str,
    output_file: str | None,
    analyze: bool,
) -> None:
    """Generate a Software Bill of Materials (SBOM) from a lockfile.

    \b
    Supports CycloneDX 1.5 JSON and SPDX 2.3 JSON formats.
    No external SBOM libraries required — JSON is constructed manually.

    \b
    Examples:
      sentinel sbom package-lock.json
      sentinel sbom package-lock.json --format spdx -o sbom.spdx.json
      sentinel sbom yarn.lock --format cyclonedx -o sbom.cdx.json
      sentinel sbom package-lock.json --analyze -o sbom.cdx.json
    """
    console = Console()
    quiet: bool = ctx.obj.get("quiet", False) if ctx.obj else False

    lockfile_path = Path(lockfile).resolve()

    # ---- Parse lockfile --------------------------------------------------
    try:
        deps = _parse_lockfile(lockfile_path)
    except (json.JSONDecodeError, KeyError, ValueError, OSError) as exc:
        console.print(f"[bold red]Failed to parse lockfile:[/bold red] {exc}")
        sys.exit(2)

    if not deps:
        console.print("[yellow]No dependencies found in lockfile.[/yellow]")
        sys.exit(0)

    if not quiet:
        console.print(
            f"[bold]📦 Parsed {len(deps)} dependencies from[/bold] "
            f"{lockfile_path.name}"
        )

    # ---- Optional vulnerability analysis ---------------------------------
    vulnerabilities: dict[str, list[dict[str, Any]]] | None = None
    if analyze and sbom_format.lower() == "cyclonedx" and _HAS_PIPELINE:
        if not quiet:
            console.print("[bold]🔍 Running Sentinel analysis for vulnerability enrichment …[/bold]")
        try:
            config = SentinelConfig.from_sentinel_config()
            pipeline = AnalysisPipeline(config)
            vulnerabilities = {}
            for dep in deps:
                spec = f"{dep['name']}@{dep['version']}"
                try:
                    result = pipeline.analyze_npm(spec, dynamic=False)
                    findings = result.get("findings", [])
                    if findings:
                        vulnerabilities[spec] = findings
                except Exception:  # noqa: BLE001
                    continue  # Skip packages that fail analysis
        except Exception as exc:  # noqa: BLE001
            console.print(
                f"[yellow]Warning: analysis failed, generating SBOM without vulnerabilities: {exc}[/yellow]"
            )
            vulnerabilities = None

    # ---- Generate SBOM ---------------------------------------------------
    if sbom_format.lower() == "spdx":
        sbom = _generate_spdx(deps, lockfile_path.name)
    else:
        sbom = _generate_cyclonedx(
            deps, lockfile_path.name, vulnerabilities=vulnerabilities
        )

    sbom_json = json.dumps(sbom, indent=2, ensure_ascii=False)

    # ---- Output ----------------------------------------------------------
    if output_file:
        out_path = Path(output_file)
        try:
            out_path.write_text(sbom_json + "\n", encoding="utf-8")
            if not quiet:
                console.print(
                    f"[bold green]✅ SBOM written to[/bold green] {out_path}"
                )
        except OSError as exc:
            console.print(
                f"[bold red]Failed to write SBOM:[/bold red] {exc}"
            )
            sys.exit(2)
    else:
        click.echo(sbom_json)

    sys.exit(0)
