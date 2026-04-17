from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from supply_chain_sentinel.artifact import resolve_npm_runner


class ArtifactRuntimeTests(unittest.TestCase):
    @patch("supply_chain_sentinel.artifact.shutil.which")
    @patch("supply_chain_sentinel.artifact.subprocess.run")
    def test_prefers_working_npm(self, mock_run, mock_which) -> None:
        mock_which.side_effect = lambda name: {
            "npm": r"C:\Program Files\nodejs\npm.cmd",
            "corepack": r"C:\Program Files\nodejs\corepack.cmd",
        }.get(name)
        mock_run.return_value = subprocess.CompletedProcess(["npm", "--version"], 0, stdout="10.9.0", stderr="")

        runner, method = resolve_npm_runner(timeout=5)

        self.assertEqual(runner, [r"C:\Program Files\nodejs\npm.cmd"])
        self.assertEqual(method, "local-npm")

    @patch("supply_chain_sentinel.artifact.shutil.which")
    @patch("supply_chain_sentinel.artifact.subprocess.run")
    def test_falls_back_to_corepack(self, mock_run, mock_which) -> None:
        mock_which.side_effect = lambda name: {
            "npm": r"C:\Program Files\nodejs\npm.cmd",
            "corepack": r"C:\Program Files\nodejs\corepack.cmd",
        }.get(name)
        mock_run.side_effect = [
            subprocess.CompletedProcess(["npm", "--version"], 1, stdout="", stderr="broken"),
            subprocess.CompletedProcess(["corepack", "--version"], 0, stdout="0.34.2", stderr=""),
        ]

        runner, method = resolve_npm_runner(timeout=5)

        self.assertEqual(runner, [r"C:\Program Files\nodejs\corepack.cmd", "npm"])
        self.assertEqual(method, "corepack-npm")

    @patch("supply_chain_sentinel.artifact.shutil.which")
    def test_reports_unavailable_when_no_runner_exists(self, mock_which) -> None:
        mock_which.return_value = None

        runner, method = resolve_npm_runner(timeout=5)

        self.assertIsNone(runner)
        self.assertEqual(method, "unavailable")


if __name__ == "__main__":
    unittest.main()
