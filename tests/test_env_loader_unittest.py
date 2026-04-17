from __future__ import annotations

import os
import unittest
from pathlib import Path

from supply_chain_sentinel.env_loader import load_env_files


class EnvLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1] / "tmp" / "env-loader-tests"
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / ".vscode").mkdir(parents=True, exist_ok=True)
        (self.root / ".env").write_text(
            "XAI_API_KEY=test-key\nSENTINEL_XAI_MODEL=grok-4.20-reasoning\n",
            encoding="utf-8",
        )
        (self.root / ".vscode" / ".env").write_text(
            "PYTHONPATH=src\n",
            encoding="utf-8",
        )
        self.previous = {
            "XAI_API_KEY": os.environ.get("XAI_API_KEY"),
            "SENTINEL_XAI_MODEL": os.environ.get("SENTINEL_XAI_MODEL"),
            "PYTHONPATH": os.environ.get("PYTHONPATH"),
        }
        for key in self.previous:
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for child in (self.root / ".vscode").glob("*"):
            child.unlink(missing_ok=True)
        (self.root / ".vscode").rmdir()
        for child in self.root.glob("*"):
            if child.is_file():
                child.unlink(missing_ok=True)
        self.root.rmdir()

    def test_loads_root_and_vscode_env_files(self) -> None:
        loaded = load_env_files(self.root)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(os.environ.get("XAI_API_KEY"), "test-key")
        self.assertEqual(os.environ.get("SENTINEL_XAI_MODEL"), "grok-4.20-reasoning")
        self.assertEqual(os.environ.get("PYTHONPATH"), "src")

    def test_does_not_override_existing_environment(self) -> None:
        os.environ["XAI_API_KEY"] = "already-set"
        load_env_files(self.root)
        self.assertEqual(os.environ.get("XAI_API_KEY"), "already-set")


if __name__ == "__main__":
    unittest.main()
