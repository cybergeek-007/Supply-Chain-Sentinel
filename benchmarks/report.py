"""Derive transparent metrics from recorded metadata; no sample handling."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path


def divide(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def wilson(success: int, total: int) -> list[float] | None:
    if not total:
        return None
    z = 1.96
    p = success / total
    center = (p + z * z / (2 * total)) / (1 + z * z / total)
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return [center - margin, center + margin]


def metrics(rows: list[dict[str, object]]) -> dict[str, object]:
    completed = [r for r in rows if r["status"] == "complete"]
    positives = [r for r in completed if r["cohort"] == "malicious"]
    negatives = [r for r in completed if r["cohort"] == "benign"]
    tp = sum(r["verdict"] in ("review", "blocked") for r in positives)
    fp = sum(r["verdict"] in ("review", "blocked") for r in negatives)
    fn, tn = len(positives) - tp, len(negatives) - fp
    times = sorted(float(str(r["scan_ms"])) for r in completed if "scan_ms" in r)
    acquisition = sorted(float(str(r["acquire_ms"])) for r in completed if "acquire_ms" in r)
    all_positive = sum(r["cohort"] == "malicious" for r in rows)
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "errors": len(rows) - len(completed),
        "precision": divide(tp, tp + fp),
        "recall": divide(tp, tp + fn),
        "FPR": divide(fp, fp + tn),
        "FNR": divide(fn, tp + fn),
        "operational_recall": divide(tp, all_positive),
        "recall_wilson95": wilson(tp, len(positives)),
        "FPR_wilson95": wilson(fp, len(negatives)),
        "scan_median_ms": statistics.median(times) if times else None,
        "scan_p95_ms": times[max(0, math.ceil(len(times) * 0.95) - 1)] if times else None,
        "acquire_median_ms": statistics.median(acquisition) if acquisition else None,
        "acquire_p95_ms": acquisition[max(0, math.ceil(len(acquisition) * 0.95) - 1)]
        if acquisition
        else None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    data = json.loads(args.results.read_text())
    public = [r for r in data["results"] if r["cohort"] in ("benign", "malicious")]
    print(json.dumps(metrics(public), indent=2))
