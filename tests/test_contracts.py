from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from supply_chain_sentinel import feeds
from supply_chain_sentinel.cli import main
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import Finding, ScanReport
from supply_chain_sentinel.scanner import summary


def test_json_contract() -> None:
    schema = json.loads((Path(__file__).parents[1] / "docs/schemas/report-v1.json").read_text())
    reports = [
        ScanReport("demo", "1.0.0", findings=[Finding("env-network", "high", 0.9, "test")]),
        ScanReport("bad", status="error", verdict="error", errors=["offline miss"]),
    ]
    jsonschema.validate(summary(reports), schema)


def test_ci_isolated_import_ignores_target_repository(tmp_path: Path) -> None:
    shadow = tmp_path / "supply_chain_sentinel"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("raise RuntimeError('untrusted checkout imported')")
    result = subprocess.run(
        [sys.executable, "-I", "-m", "supply_chain_sentinel", "--version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0 and "0.3.0a1" in result.stdout


def test_cli_update_then_identity_offline(
    config: Config, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        feeds,
        "request_bytes",
        lambda *a, **kw: json.dumps(
            {
                "vulns": [
                    {
                        "id": "GHSA-embedded",
                        "database_specific": {"github_reviewed": True, "cwe_ids": ["CWE-506"]},
                    }
                ]
            }
        ).encode(),
    )
    assert (
        main(["--cache-dir", str(config.cache_dir), "update-rules", "--package", "demo@1.0.0"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["identities"] == 1
    assert (
        main(
            [
                "--cache-dir",
                str(config.cache_dir),
                "scan",
                "demo@1.0.0",
                "--identity-only",
                "--offline",
                "--format",
                "json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)["results"][0]
    assert report["verdict"] == "blocked"
    assert report["coverage"]["source"].startswith("not-scanned")
    # Ordinary scan also blocks a fresh known-malicious identity without a tarball/cache.
    assert (
        main(
            [
                "--cache-dir",
                str(config.cache_dir),
                "scan",
                "demo@1.0.0",
                "--offline",
                "--format",
                "json",
            ]
        )
        == 1
    )
    assert (
        json.loads(capsys.readouterr().out)["results"][0]["coverage"]["source"]
        == "not-scanned (known-malicious identity)"
    )


def test_output_file_and_empty_lock(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"lockfileVersion":3,"packages":{"":{}}}')
    output = tmp_path / "report.sarif"
    assert (
        main(
            [
                "--cache-dir",
                str(tmp_path / "cache"),
                "scan-lockfile",
                str(lock),
                "--offline",
                "--format",
                "sarif",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["runs"][0]["results"] == []
    assert not capsys.readouterr().out
    assert (
        main(["--cache-dir", str(tmp_path / "cache"), "update-rules", "--lockfile", str(lock)]) == 0
    )
    assert json.loads(capsys.readouterr().out)["identities"] == 0
