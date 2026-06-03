from __future__ import annotations

import asyncio
import tarfile
from pathlib import Path

from src.core.python.config import SentinelConfig
from src.core.python.orchestrator import SentinelOrchestrator


def _create_package_tarball(tmp_path: Path) -> str:
    package_dir = tmp_path / "package"
    package_dir.mkdir()
    (package_dir / "package.json").write_text('{"name":"demo","version":"1.0.0"}', encoding="utf-8")
    (package_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

    tgz_path = tmp_path / "demo-1.0.0.tgz"
    with tarfile.open(tgz_path, "w:gz") as tar:
        tar.add(package_dir, arcname="package")
    return str(tgz_path)


def _create_suspicious_package_tarball(tmp_path: Path) -> str:
    package_dir = tmp_path / "suspicious_package"
    package_dir.mkdir()
    (package_dir / "package.json").write_text(
        '{"name":"suspicious","version":"1.0.0","scripts":{"postinstall":"node index.js"}}',
        encoding="utf-8",
    )
    (package_dir / "index.js").write_text(
        "const cp = require('child_process'); eval('cp.exec(\"whoami\")');",
        encoding="utf-8",
    )
    tgz_path = tmp_path / "suspicious-1.0.0.tgz"
    with tarfile.open(tgz_path, "w:gz") as tar:
        tar.add(package_dir, arcname="package")
    return str(tgz_path)


def test_analyze_package_success(tmp_path: Path) -> None:
    config = SentinelConfig(staging_dir=str(tmp_path / "staging"), entropy_threshold=0.1)
    orchestrator = SentinelOrchestrator(config)
    package_path = _create_package_tarball(tmp_path)

    result = asyncio.run(orchestrator.analyze_package(package_path, "demo"))

    assert result["status"] == "success"
    assert "extraction" in result["phases"]
    assert "entropy" in result["phases"]
    assert "static" in result["phases"]
    assert result["phases"]["entropy"]["files"]


def test_analyze_package_failure_for_missing_file(tmp_path: Path) -> None:
    config = SentinelConfig(staging_dir=str(tmp_path / "staging"))
    orchestrator = SentinelOrchestrator(config)

    result = asyncio.run(orchestrator.analyze_package(str(tmp_path / "missing.tgz"), "missing"))
    assert result["status"] == "failed"
    assert "error" in result


def test_analyze_package_detects_static_risks(tmp_path: Path) -> None:
    config = SentinelConfig(staging_dir=str(tmp_path / "staging"), entropy_threshold=0.1)
    orchestrator = SentinelOrchestrator(config)
    package_path = _create_suspicious_package_tarball(tmp_path)

    result = asyncio.run(orchestrator.analyze_package(package_path, "suspicious"))
    static_phase = result["phases"]["static"]
    assert static_phase["summary"]["yara_files_with_matches"] >= 1
    assert static_phase["summary"]["suspicious_keywords_found"] >= 1
    assert static_phase["risk_level"] in {"HIGH", "CRITICAL"}
    assert any(finding["category"] == "manifest" for finding in static_phase["findings"])
    assert any(finding["category"] == "execution" for finding in static_phase["findings"])
