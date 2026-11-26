from __future__ import annotations

import runpy
from pathlib import Path


def test_metrics_keep_scan_errors_out_of_true_negatives() -> None:
    metrics = runpy.run_path(str(Path(__file__).parents[1] / "benchmarks/report.py"))["metrics"]
    rows = [
        {"cohort": "malicious", "status": "complete", "verdict": "review", "scan_ms": 10},
        {"cohort": "malicious", "status": "complete", "verdict": "clean", "scan_ms": 20},
        {"cohort": "malicious", "status": "scan-error"},
        {"cohort": "benign", "status": "complete", "verdict": "review", "scan_ms": 30},
        {"cohort": "benign", "status": "complete", "verdict": "clean", "scan_ms": 40},
    ]
    result = metrics(rows)
    assert (result["TP"], result["FP"], result["TN"], result["FN"], result["errors"]) == (
        1,
        1,
        1,
        1,
        1,
    )
    assert result["recall"] == 0.5 and result["operational_recall"] == 1 / 3
    assert result["precision"] == 0.5 and result["FPR"] == 0.5
    assert metrics([])["recall"] is None
