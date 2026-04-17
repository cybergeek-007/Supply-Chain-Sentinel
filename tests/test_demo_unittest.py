from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from supply_chain_sentinel.demo import render_fixture_demo, run_fixture_demo
from supply_chain_sentinel.models import ScanReport


class DemoCommandTests(unittest.TestCase):
    def test_render_fixture_demo_reports_mismatches(self) -> None:
        summary = {
            "fixture_count": 2,
            "match_count": 1,
            "mismatches": ["network-beacon"],
            "runs": [
                {
                    "fixture": "benign-logger",
                    "expected_decision": "allow",
                    "actual_decision": "allow",
                    "matched_expectation": True,
                },
                {
                    "fixture": "network-beacon",
                    "expected_decision": "block",
                    "actual_decision": "warn",
                    "matched_expectation": False,
                },
            ],
        }
        rendered = render_fixture_demo(summary)
        self.assertIn("fixtures: 2", rendered)
        self.assertIn("mismatches: network-beacon", rendered)

    @patch("supply_chain_sentinel.demo.execute_install_scan")
    def test_run_fixture_demo_writes_summary(self, mock_execute_install_scan) -> None:
        mock_execute_install_scan.return_value = ScanReport(
            package="fixture",
            version="1.0.0",
            artifact_sha256="abc",
            static_score=0,
            static_findings=[],
            dynamic_findings=[],
            rule_hits=[],
            decision="allow",
            duration_ms=10,
            sandbox_metadata={},
            installation={"attempted": False, "skipped": True},
        )
        project_root = Path(__file__).resolve().parents[1]
        output_dir = project_root / "tmp" / "demo-test"
        if output_dir.exists():
            for child in output_dir.glob("*"):
                child.unlink(missing_ok=True)
            output_dir.rmdir()

        summary = run_fixture_demo(
            project_root=project_root,
            output_dir=output_dir,
            rules_path=project_root / "config" / "default_rules.json",
            timeout=1,
            risk_threshold=80,
            high_entropy=7.2,
        )

        self.assertEqual(summary["fixture_count"], 4)
        self.assertTrue((output_dir / "summary.json").exists())
        for child in output_dir.glob("*"):
            child.unlink(missing_ok=True)
        output_dir.rmdir()


if __name__ == "__main__":
    unittest.main()
