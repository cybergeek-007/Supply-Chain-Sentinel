"""Derive holdout metrics from sanitized scanner output; never reads samples."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path
from typing import Any


def _wilson(success: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.96
    p = success / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [center - margin, center + margin]


def _method(rows: list[dict[str, Any]], name: str) -> dict[str, Any]:
    completed = [
        row
        for row in rows
        if row["status"] == "complete"
        and (name == "baseline" or row["candidate"]["status"] == "complete")
    ]
    positive = [row for row in completed if row["cohort"] == "malicious"]
    negative = [row for row in completed if row["cohort"] == "benign"]
    verdict = (
        (lambda row: row["baseline"]["verdict"])
        if name == "baseline"
        else (lambda row: row["candidate"]["verdict"])
    )
    tp = sum(verdict(row) in {"review", "blocked"} for row in positive)
    fp = sum(verdict(row) in {"review", "blocked"} for row in negative)
    fn, tn = len(positive) - tp, len(negative) - fp
    selected_positive = sum(row["cohort"] == "malicious" for row in rows)
    selected_negative = sum(row["cohort"] == "benign" for row in rows)
    times = sorted(
        float(row[name]["scan_ms"] if name == "baseline" else row["candidate"]["scan_ms"])
        for row in completed
    )
    metrics = {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "completed_benign": len(negative),
        "completed_malicious": len(positive),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "FPR": fp / (fp + tn) if fp + tn else None,
        "FNR": fn / (tp + fn) if tp + fn else None,
        "operational_recall_all_selected": tp / selected_positive if selected_positive else None,
        "acquisition_or_analysis_errors": len(rows) - len(completed),
        "benign_errors": selected_negative - len(negative),
        "malicious_errors": selected_positive - len(positive),
        "recall_wilson95_completed": _wilson(tp, len(positive)),
        "FPR_wilson95_completed": _wilson(fp, len(negative)),
        "scan_median_ms": statistics.median(times) if times else None,
        "scan_p95_ms": times[max(0, math.ceil(0.95 * len(times)) - 1)] if times else None,
    }
    if name == "candidate":
        same_cohort_baseline = sorted(float(row["baseline"]["scan_ms"]) for row in completed)
        combined = sorted(
            float(row["baseline"]["scan_ms"]) + float(row["candidate"]["scan_ms"])
            for row in completed
        )
        metrics["scan_timing_scope"] = "incremental AST pass; baseline findings are reused"
        metrics["combined_scan_median_ms"] = statistics.median(combined) if combined else None
        metrics["combined_scan_p95_ms"] = (
            combined[max(0, math.ceil(0.95 * len(combined)) - 1)] if combined else None
        )
        metrics["baseline_same_cohort_median_ms"] = (
            statistics.median(same_cohort_baseline) if same_cohort_baseline else None
        )
        metrics["baseline_same_cohort_p95_ms"] = (
            same_cohort_baseline[max(0, math.ceil(0.95 * len(same_cohort_baseline)) - 1)]
            if same_cohort_baseline
            else None
        )
    else:
        metrics["scan_timing_scope"] = "full lexical source inspection"
    return metrics


def _identity(row: dict[str, Any]) -> str:
    if "spec" in row:
        return row["spec"]
    return f"{row.get('package', row.get('path', 'unknown'))}@{row.get('version', '?')}"


def build_report(data: dict[str, Any]) -> dict[str, Any]:
    rows = data["results"]
    malicious = [row for row in rows if row["cohort"] == "malicious"]
    benign = [row for row in rows if row["cohort"] == "benign"]
    false_positives = []
    new_hits = []
    misses = []
    timings = []
    for row in rows:
        if row["status"] != "complete":
            continue
        candidate = row["candidate"]
        if candidate["status"] != "complete":
            if row["cohort"] == "malicious":
                misses.append(
                    {
                        "identity": _identity(row),
                        "status": "candidate-analysis-error",
                        "error": candidate.get("error", "unspecified candidate error"),
                        "baseline_rules": row["baseline"]["rules"],
                    }
                )
            continue
        timings.append(
            {
                "identity": _identity(row),
                "baseline_full_scan_ms": row["baseline"]["scan_ms"],
                "candidate_incremental_scan_ms": candidate["scan_ms"],
                "candidate_combined_scan_ms": round(
                    float(row["baseline"]["scan_ms"]) + float(candidate["scan_ms"]), 3
                ),
            }
        )
        positive = candidate["verdict"] in {"review", "blocked"}
        baseline_positive = row["baseline"]["verdict"] in {"review", "blocked"}
        item = {
            "identity": _identity(row),
            "baseline_verdict": row["baseline"]["verdict"],
            "baseline_rules": row["baseline"]["rules"],
            "candidate_verdict": candidate["verdict"],
            "candidate_rules": candidate["rules"],
        }
        if row["cohort"] == "benign" and positive:
            false_positives.append(item)
        if row["cohort"] == "malicious":
            if positive and not baseline_positive:
                new_hits.append(item)
            if not positive:
                misses.append({**item, "status": "completed-below-threshold"})
    for row in rows:
        if row["cohort"] == "malicious" and row["status"] == "acquisition-error":
            misses.append(
                {
                    "identity": _identity(row),
                    "status": "acquisition-error",
                    "error": row.get("error", "unspecified acquisition error"),
                }
            )
    return {
        "holdout_status": "evaluated-once",
        "candidate_commit": "f14878de48a67e9bd756c29cc4680316f4a8cb3a",
        "selected": {"benign": len(benign), "malicious": len(malicious)},
        "results": {name: _method(rows, name) for name in ("baseline", "candidate")},
        "candidate_false_positives": false_positives,
        "candidate_only_true_positives": new_hits,
        "candidate_malicious_misses_and_errors": misses,
        "per_package_timings": timings,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "results", type=Path, nargs="?", default=Path("benchmarks/results/holdout.json")
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = build_report(json.loads(args.results.read_text()))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
