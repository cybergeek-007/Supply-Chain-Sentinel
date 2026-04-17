from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from supply_chain_sentinel.report_corpus import (
    load_reports_from_dir,
    render_corpus_summary,
    summarize_report_corpus,
    triage_report_corpus,
)


class ReportCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1] / "tmp" / "report-corpus-tests"
        self.root.mkdir(parents=True, exist_ok=True)
        self.report_one = self.root / "one.json"
        self.report_two = self.root / "two.json"
        self.other = self.root / "summary.json"

        self.report_one.write_text(
            json.dumps(
                {
                    "package": "entropy-dropper",
                    "version": "1.0.0",
                    "decision": "block",
                    "static_score": 45,
                    "static_findings": [{"kind": "entropy_high"}],
                    "dynamic_findings": [],
                    "rule_hits": [{"rule_id": "entropy-block"}],
                    "sandbox_metadata": {},
                }
            ),
            encoding="utf-8",
        )
        self.report_two.write_text(
            json.dumps(
                {
                    "package": "credential-hunter",
                    "version": "1.0.0",
                    "decision": "block",
                    "static_score": 12,
                    "static_findings": [{"kind": "lifecycle_script"}],
                    "dynamic_findings": [],
                    "rule_hits": [],
                    "sandbox_metadata": {"error": "docker unavailable"},
                }
            ),
            encoding="utf-8",
        )
        self.other.write_text(json.dumps({"not": "a report"}), encoding="utf-8")

    def tearDown(self) -> None:
        for child in self.root.glob("*"):
            child.unlink(missing_ok=True)
        self.root.rmdir()

    def test_load_reports_filters_non_reports(self) -> None:
        reports = load_reports_from_dir(self.root)
        self.assertEqual(len(reports), 2)

    def test_summarize_report_corpus_counts_decisions_and_kinds(self) -> None:
        reports = load_reports_from_dir(self.root)
        summary = summarize_report_corpus(reports)
        self.assertEqual(summary["report_count"], 2)
        self.assertEqual(summary["decision_counts"]["block"], 2)
        self.assertEqual(summary["watchlist_packages"], ["credential-hunter", "entropy-dropper"])

    @patch("supply_chain_sentinel.report_corpus.maybe_generate_ai_corpus_analysis")
    def test_triage_report_corpus_writes_output(self, mock_ai) -> None:
        mock_ai.return_value = {"status": "skipped", "reason": "not requested"}
        output_path = self.root / "triage.json"
        summary = triage_report_corpus(self.root, output_path, ai_summary=False)
        self.assertTrue(output_path.exists())
        self.assertEqual(summary["report_count"], 2)

    def test_render_corpus_summary_mentions_watchlist(self) -> None:
        rendered = render_corpus_summary(
            {
                "report_count": 2,
                "decision_counts": {"block": 2},
                "watchlist_packages": ["credential-hunter"],
                "top_finding_kinds": [{"kind": "entropy_high", "count": 1}],
                "sandbox_errors": [{"package": "credential-hunter", "error": "docker unavailable"}],
                "ai_analysis": {"status": "skipped", "reason": "OPENAI_API_KEY is not set"},
            }
        )
        self.assertIn("watchlist_packages: credential-hunter", rendered)
        self.assertIn("ai_note: OPENAI_API_KEY is not set", rendered)


if __name__ == "__main__":
    unittest.main()
