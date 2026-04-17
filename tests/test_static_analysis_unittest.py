from __future__ import annotations

import unittest

from supply_chain_sentinel.static_analysis import compute_shannon_entropy, run_static_analysis

from tests.helpers import cleanup, create_artifact, repo_tmp_dir


class StaticAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_dir = repo_tmp_dir()

    def tearDown(self) -> None:
        cleanup(self.case_dir)

    def test_entropy_detects_obfuscated_payload(self) -> None:
        artifact = create_artifact(
            self.case_dir,
            {"name": "danger", "version": "1.0.0"},
            {"postinstall.js": bytes(range(256)) * 4},
        )
        result = run_static_analysis(artifact, risk_threshold=80, high_entropy=7.2)
        self.assertTrue(any(finding.kind == "entropy_high" for finding in result.findings))

    def test_lifecycle_script_is_flagged(self) -> None:
        artifact = create_artifact(
            self.case_dir,
            {
                "name": "scripted",
                "version": "1.0.0",
                "scripts": {"postinstall": "node postinstall.js"},
            },
            {"postinstall.js": b"console.log('hi');"},
        )
        result = run_static_analysis(artifact, risk_threshold=80, high_entropy=7.2)
        self.assertIn("postinstall", result.lifecycle_scripts)
        self.assertTrue(any(finding.kind == "lifecycle_script" for finding in result.findings))

    def test_entropy_detects_small_binary_payload_even_without_script_suffix(self) -> None:
        artifact = create_artifact(
            self.case_dir,
            {"name": "packed", "version": "1.0.0"},
            {"payload.bin": bytes(range(256)) * 4},
        )
        result = run_static_analysis(artifact, risk_threshold=80, high_entropy=7.2)
        self.assertTrue(any(finding.kind == "entropy_high" for finding in result.findings))

    def test_entropy_helper_handles_text_and_binary(self) -> None:
        text_entropy = compute_shannon_entropy(b"console.log('hello world')")
        binary_entropy = compute_shannon_entropy(bytes(range(64)) * 10)
        self.assertLess(text_entropy, 5.5)
        self.assertGreater(binary_entropy, text_entropy)


if __name__ == "__main__":
    unittest.main()
