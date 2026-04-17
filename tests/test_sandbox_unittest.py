from __future__ import annotations

import unittest
from pathlib import Path

from supply_chain_sentinel.sandbox import _parse_trace_file


class SandboxTraceParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_dir = Path(__file__).resolve().parents[1] / "tmp" / "sandbox-tests"
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.trace_file = self.case_dir / "postinstall.strace.log"

    def tearDown(self) -> None:
        if self.trace_file.exists():
            self.trace_file.unlink()
        if self.case_dir.exists():
            self.case_dir.rmdir()

    def test_trace_parser_detects_network_process_and_credentials(self) -> None:
        self.trace_file.write_text(
            '\n'.join(
                [
                    '123 execve("/usr/bin/curl", ["curl", "https://example.com"], 0x0) = 0',
                    '124 connect(5, {sa_family=AF_INET, sin_port=htons(443)}, 16) = 0',
                    '125 openat(AT_FDCWD, "/workspace/output/home/.aws/credentials", O_RDONLY) = 3',
                ]
            ),
            encoding="utf-8",
        )
        findings = _parse_trace_file(self.trace_file)
        kinds = {finding.kind for finding in findings}
        self.assertIn("network_connect", kinds)
        self.assertIn("suspicious_process", kinds)
        self.assertIn("honeypot_credential_access", kinds)


if __name__ == "__main__":
    unittest.main()
