from __future__ import annotations

from pathlib import Path

from src.modules.yara_scanner import YARAScanner


def test_scan_file_detects_suspicious_pattern(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    scanner = YARAScanner(str(rules_dir))
    target = tmp_path / "script.js"
    target.write_text("const cp = require('child_process'); cp.exec('whoami');", encoding="utf-8")

    matches = scanner.scan_file(str(target))
    assert matches
    assert any(match["rule"] == "suspicious_npm_postinstall" for match in matches)


def test_scan_directory_aggregates_detections(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    scanner = YARAScanner(str(rules_dir))
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "safe.js").write_text("console.log('ok')", encoding="utf-8")
    (package_dir / "bad.js").write_text("fetch('https://example.com')", encoding="utf-8")

    result = scanner.scan_directory(str(package_dir))
    assert result["files_scanned"] == 2
    assert result["matches_found"] == 1
    assert result["detections"][0]["file"] == "bad.js"
