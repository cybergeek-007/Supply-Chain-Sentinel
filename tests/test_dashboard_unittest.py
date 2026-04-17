from __future__ import annotations

import json
import unittest
from pathlib import Path

from supply_chain_sentinel.dashboard import build_dashboard, render_dashboard_html
from supply_chain_sentinel.report_corpus import load_reports_from_dir, summarize_report_corpus


class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1] / "tmp" / "dashboard-tests"
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "allow.json").write_text(
            json.dumps(
                {
                    "package": "benign-logger",
                    "version": "1.0.0",
                    "decision": "allow",
                    "static_score": 0,
                    "static_findings": [],
                    "dynamic_findings": [],
                    "rule_hits": [],
                    "sandbox_metadata": {},
                }
            ),
            encoding="utf-8",
        )
        (self.root / "block.json").write_text(
            json.dumps(
                {
                    "package": "credential-hunter",
                    "version": "1.0.0",
                    "decision": "block",
                    "static_score": 12,
                    "static_findings": [{"message": "Lifecycle script 'postinstall' will execute during installation."}],
                    "dynamic_findings": [],
                    "rule_hits": [],
                    "sandbox_metadata": {"error": "docker unavailable"},
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        for child in self.root.glob("*"):
            child.unlink(missing_ok=True)
        self.root.rmdir()

    def test_render_dashboard_contains_sections(self) -> None:
        reports = load_reports_from_dir(self.root)
        summary = summarize_report_corpus(reports)
        html_doc = render_dashboard_html(summary, reports)
        self.assertIn("Deterministic Scan Dashboard", html_doc)
        self.assertIn("credential-hunter", html_doc)
        self.assertIn("Lifecycle script", html_doc)

    def test_build_dashboard_writes_output(self) -> None:
        output_path = self.root / "dashboard.html"
        result = build_dashboard(self.root, output_path)
        self.assertTrue(output_path.exists())
        self.assertEqual(result["report_count"], 2)


if __name__ == "__main__":
    unittest.main()
