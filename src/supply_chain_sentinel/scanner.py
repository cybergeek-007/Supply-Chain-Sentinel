"""One deterministic scan path with explicit completeness and policy semantics."""

from __future__ import annotations

import time
import json
from pathlib import Path
from typing import Any

from .adapters.npm import NpmAdapter, split_spec
from .archive import inspect_archive, inspect_directory
from .config import Config, suppress
from .feeds import load_snapshot, lookup
from .models import Artifact, ScanError, ScanReport, classify
from .rules import analyze


class Scanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.adapter = NpmAdapter(config)
        self.snapshot = load_snapshot(config)

    def scan(
        self,
        target: str,
        *,
        offline: bool = False,
        integrity: str = "",
        identity_only: bool = False,
        require_advisories: bool = False,
    ) -> ScanReport:
        started = time.perf_counter()
        report = ScanReport(target)
        try:
            path = Path(target)
            # Fresh exact known-malware records can block before acquisition, including
            # removed registry versions. This is explicit identity-only coverage.
            if not identity_only and not path.exists():
                name, version = split_spec(target)
                if version:
                    known, coverage = lookup(self.snapshot, self.config, name, version)
                    suppress(known, self.config, name, version, "")
                    score, verdict = classify(known)
                    if verdict == "blocked" and not coverage.get("advisory_stale"):
                        report.package, report.version = name, version
                        report.findings, report.coverage = known, coverage
                        report.coverage["source"] = "not-scanned (known-malicious identity)"
                        report.score, report.verdict = score, verdict
                        report.duration_ms = round((time.perf_counter() - started) * 1000, 3)
                        return report
            if identity_only:
                name, version = split_spec(target, exact=True)
                report.package, report.version = name, version
                report.findings, report.coverage = lookup(self.snapshot, self.config, name, version)
                report.coverage["source"] = "not-scanned (identity-only)"
                require_advisories = True
            else:
                artifact: Artifact
                if path.is_dir():
                    artifact = inspect_directory(path, self.config)
                elif path.is_file():
                    if path.stat().st_size > self.config.max_archive_bytes:
                        raise ScanError("Archive exceeds size limit")
                    artifact = inspect_archive(path.read_bytes(), self.config)
                else:
                    artifact = self.adapter.acquire(target, offline=offline, integrity=integrity)
                report.package, report.version, report.sha256 = (
                    artifact.name,
                    artifact.version,
                    artifact.sha256,
                )
                report.findings = analyze(artifact, self.config)
                manifest = json.loads(artifact.files["package.json"])
                dependency_names: set[str] = set()
                for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                    declared = manifest.get(field, {})
                    if isinstance(declared, dict):
                        dependency_names.update(declared)
                advisory_findings, coverage = lookup(
                    self.snapshot, self.config, artifact.name, artifact.version
                )
                report.findings.extend(advisory_findings)
                report.coverage = {
                    **coverage,
                    "source": "static-js-ts-shell-manifest",
                    "source_files": len(artifact.files),
                    "artifact": artifact.source,
                    "dynamic": "not-run",
                    "ai": "disabled",
                    "dependency_resolution": "not-performed",
                    "declared_runtime_dependencies": len(dependency_names),
                }
                if dependency_names:
                    report.warnings.append(
                        "This artifact scan does not resolve or inspect declared dependencies; "
                        "scan-lockfile covers the exact entries listed in a lockfile."
                    )
            if report.coverage.get("advisory_stale"):
                report.warnings.append(
                    "Advisories are missing or stale; run update-rules explicitly"
                )
                if require_advisories:
                    raise ScanError("Fresh advisory coverage required by policy")
            suppress(report.findings, self.config, report.package, report.version, report.sha256)
            report.score, report.verdict = classify(report.findings)
        except (ScanError, OSError, ValueError) as exc:
            report.status, report.verdict = "error", "error"
            report.errors.append(str(exc))
        report.duration_ms = round((time.perf_counter() - started) * 1000, 3)
        return report


def exit_code(reports: list[ScanReport], fail_on: str = "review") -> int:
    if any(report.status == "error" for report in reports):
        return 2
    order = {"clean": 0, "review": 1, "blocked": 2}
    if fail_on == "never":
        return 0
    return int(any(order[r.verdict] >= order[fail_on] for r in reports))


def summary(reports: list[ScanReport]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "results": [r.to_dict() for r in reports],
        "counts": {
            key: sum(r.verdict == key for r in reports)
            for key in ("clean", "review", "blocked", "error")
        },
    }
