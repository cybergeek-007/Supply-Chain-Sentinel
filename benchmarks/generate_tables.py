"""Generate per-package Markdown and metric JSON from recorded result metadata."""

from __future__ import annotations

import json
from pathlib import Path

from report import metrics

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks/results"


def main() -> None:
    final = json.loads((RESULTS / "final.json").read_text())
    initial = json.loads((RESULTS / "initial.json").read_text())
    metric_data = {}
    for name, data in (("initial", initial), ("final", final)):
        public = [r for r in data["results"] if r["cohort"] in ("benign", "malicious")]
        metric_data[name] = metrics(public)
    consistent = [
        r
        for r in final["results"]
        if r["cohort"] in ("benign", "malicious")
        and not (r["cohort"] == "malicious" and r.get("version") != r["path"].split("/")[-2])
    ]
    metric_data["final_excluding_version_mismatch"] = metrics(consistent)
    (RESULTS / "metrics.json").write_text(json.dumps(metric_data, indent=2) + "\n")
    lines = [
        "# Per-package measured results",
        "",
        "Generated with `python benchmarks/generate_tables.py`. Times are measured milliseconds, not estimates. "
        "Advisory lookups are excluded from these source-only verdicts. Error rows are excluded from FPR denominators. "
        "A dataset path/manifest version mismatch is explicitly noted; see the main benchmark report.",
        "",
        "| Cohort | Exact identity / selected path | Verdict | Scan ms | Acquisition ms | Rule IDs / error |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in final["results"]:
        identity = (
            row.get("spec") or f"{row.get('package', row.get('path'))}@{row.get('version', '')}"
        )
        detail = row.get("error", ", ".join(row.get("rules", []))) or "none"
        if row["cohort"] == "malicious" and row.get("version") != row["path"].split("/")[-2]:
            detail += "; manifest/path version mismatch"
        values = [
            row["cohort"],
            identity,
            row.get("verdict", row["status"]),
            str(row.get("scan_ms", "—")),
            str(row.get("acquire_ms", "—")),
            detail,
        ]
        lines.append(
            "| " + " | ".join(str(v).replace("|", "\\|").replace("\n", " ") for v in values) + " |"
        )
    lines.extend(
        [
            "",
            "## Every final source miss",
            "",
            "The explanations below distinguish observed feature coverage from unresolved forensic attribution. "
            "They do not claim to have reconstructed every payload. Counts/locations and upstream artifact hashes are in final.json.",
            "",
            "| Dataset-labeled identity | Observed limitation / remaining investigation |",
            "| --- | --- |",
        ]
    )
    for row in final["results"]:
        if row["cohort"] != "malicious" or row.get("verdict") != "clean":
            continue
        feature = row.get("diagnostic_features", {})
        if row.get("version") != row["path"].split("/")[-2]:
            explanation = "Dataset path says a different version than the manifest; artifact-level label is uncertain. Excluded in the conservative sensitivity calculation."
        elif feature.get("encoding", 0) and feature.get("shell", 0):
            explanation = "Bundled encoding/shell/network capabilities are present, but no modeled direct execution or nearby secret-flow chain matched. Needs interprocedural/alias-aware analysis; exact payload attribution remains unresolved."
        elif feature.get("encoding", 0):
            explanation = "Encoding/network symbols occur without a modeled direct execution or exfiltration chain. Counting those symbols alone would recreate false positives; payload attribution remains unresolved."
        elif feature.get("environment", 0) or feature.get("shell", 0):
            explanation = "Environment/process/network capabilities occur without the direct correlated patterns modeled by this engine. Alias/cross-file behavior is outside coverage; payload attribution remains unresolved."
        else:
            explanation = "No modeled sensitive-read/encoded-execution chain in the inspected source set. Needs full upstream artifact and runtime investigation; no specific evasion technique is asserted."
        lines.append(f"| {row['package']}@{row['version']} | {explanation} |")
    (ROOT / "docs/BENCHMARK_RESULTS.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
