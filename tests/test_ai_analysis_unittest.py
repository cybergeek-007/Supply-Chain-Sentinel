from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from supply_chain_sentinel.ai_analysis import maybe_generate_ai_analysis, maybe_generate_ai_corpus_analysis
from supply_chain_sentinel.models import ScanReport


def make_report() -> ScanReport:
    return ScanReport(
        package="demo-pkg",
        version="1.0.0",
        artifact_sha256="abc123",
        static_score=12,
        static_findings=[],
        dynamic_findings=[],
        rule_hits=[],
        decision="warn",
        duration_ms=100,
        sandbox_metadata={},
        installation={"attempted": False},
    )


class AIAnalysisTests(unittest.TestCase):
    def test_skips_when_not_requested(self) -> None:
        analysis = maybe_generate_ai_analysis(make_report(), enabled=False)
        self.assertEqual(analysis["status"], "skipped")

    @patch.dict("os.environ", {}, clear=True)
    def test_skips_without_api_key(self) -> None:
        analysis = maybe_generate_ai_analysis(make_report(), enabled=True)
        self.assertEqual(analysis["status"], "skipped")
        self.assertIn("XAI_API_KEY", analysis["reason"])

    @patch.dict("os.environ", {"XAI_API_KEY": "test-key"}, clear=True)
    @patch("supply_chain_sentinel.ai_analysis.importlib.util.find_spec", return_value=True)
    @patch("supply_chain_sentinel.ai_analysis._sample_grok_response")
    def test_parses_completed_response(self, mock_sample_grok_response, _mock_find_spec) -> None:
        mock_sample_grok_response.return_value = json.dumps(
            {
                "summary": "The package is suspicious because of lifecycle scripts.",
                "severity_label": "high",
                "confidence": "high",
                "likely_intent": "credential theft",
                "notable_signals": ["Lifecycle script present"],
                "remediation": ["Review the package before use"],
            }
        )

        analysis = maybe_generate_ai_analysis(make_report(), enabled=True, model="grok-4.20-reasoning")

        self.assertEqual(analysis["status"], "completed")
        self.assertEqual(analysis["model"], "grok-4.20-reasoning")
        self.assertEqual(analysis["severity_label"], "high")
        self.assertEqual(analysis["provider"], "xai")

    @patch.dict("os.environ", {"XAI_API_KEY": "test-key"}, clear=True)
    @patch("supply_chain_sentinel.ai_analysis.importlib.util.find_spec", return_value=True)
    @patch("supply_chain_sentinel.ai_analysis._sample_grok_response")
    def test_parses_completed_corpus_response(self, mock_sample_grok_response, _mock_find_spec) -> None:
        mock_sample_grok_response.return_value = json.dumps(
            {
                "summary": "Two blocked packages show repeated install-hook risk.",
                "risk_posture": "high",
                "confidence": "high",
                "recurring_patterns": ["Lifecycle scripts", "Sandbox failures"],
                "priority_actions": ["Fix Docker access", "Keep blocked packages quarantined"],
                "watchlist_packages": ["credential-hunter", "network-beacon"],
            }
        )

        analysis = maybe_generate_ai_corpus_analysis(
            {"report_count": 2, "decision_counts": {"block": 2}},
            enabled=True,
            model="grok-4.20-reasoning",
        )

        self.assertEqual(analysis["status"], "completed")
        self.assertEqual(analysis["risk_posture"], "high")

    @patch.dict("os.environ", {"XAI_API_KEY": "test-key"}, clear=True)
    @patch("supply_chain_sentinel.ai_analysis.importlib.util.find_spec", return_value=None)
    def test_reports_missing_xai_sdk(self, _mock_find_spec) -> None:
        analysis = maybe_generate_ai_analysis(make_report(), enabled=True)
        self.assertEqual(analysis["status"], "error")
        self.assertIn("xai_sdk", analysis["reason"])


if __name__ == "__main__":
    unittest.main()
