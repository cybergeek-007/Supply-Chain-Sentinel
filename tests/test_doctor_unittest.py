from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from supply_chain_sentinel.environment import HealthCheck, overall_status, render_doctor_report, run_doctor


class DoctorTests(unittest.TestCase):
    def test_overall_status_prefers_fail(self) -> None:
        checks = [
            HealthCheck(name="python", status="ok", detail="ready"),
            HealthCheck(name="docker_daemon", status="fail", detail="not reachable"),
            HealthCheck(name="esprima", status="warn", detail="missing"),
        ]
        self.assertEqual(overall_status(checks), "fail")

    def test_render_doctor_report_includes_overall(self) -> None:
        checks = [
            HealthCheck(name="python", status="ok", detail="ready"),
            HealthCheck(name="npm_cli", status="warn", detail="broken"),
        ]
        report = render_doctor_report(checks)
        self.assertIn("python: ok - ready", report)
        self.assertIn("npm_cli: warn - broken", report)
        self.assertIn("overall: warn", report)

    @patch("supply_chain_sentinel.environment.resolve_npm_runner")
    def test_doctor_reports_corepack_runtime(self, mock_resolve_npm_runner) -> None:
        mock_resolve_npm_runner.return_value = (["corepack", "npm"], "corepack-npm")
        checks = run_doctor(Path(__file__).resolve().parents[1], timeout=1)
        npm_runtime = next(check for check in checks if check.name == "npm_runtime")
        self.assertEqual(npm_runtime.status, "ok")
        self.assertIn("corepack-npm", npm_runtime.detail)


if __name__ == "__main__":
    unittest.main()
