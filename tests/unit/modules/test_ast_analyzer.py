from __future__ import annotations

from pathlib import Path

from src.modules.ast_analyzer import ASTAnalyzer


def test_analyze_python_file_detects_dangerous_calls(tmp_path: Path) -> None:
    source = """
import os

def run(value):
    eval(value)
    os.system("echo hi")
"""
    target = tmp_path / "sample.py"
    target.write_text(source, encoding="utf-8")

    analyzer = ASTAnalyzer()
    result = analyzer.analyze_python_file(str(target))

    assert result["language"] == "python"
    assert result["functions"][0]["name"] == "run"
    calls = {entry["function"] for entry in result["dangerous_calls"]}
    assert "eval" in calls
    assert "os.system" in calls


def test_analyze_javascript_file_flags_keywords_and_lifecycle(tmp_path: Path) -> None:
    source = "postinstall && eval('x'); const cp = require('child_process');"
    target = tmp_path / "sample.js"
    target.write_text(source, encoding="utf-8")

    analyzer = ASTAnalyzer()
    result = analyzer.analyze_javascript_file(str(target))

    assert "eval" in result["suspicious_keywords"]
    assert "require" in result["suspicious_keywords"]
    assert any(pattern["severity"] in {"high", "critical"} for pattern in result["risk_patterns"])
    assert any(finding["category"] == "execution" for finding in result["findings"])


def test_analyze_package_directory_summarizes_results(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "a.py").write_text("def one():\n    return 1\n", encoding="utf-8")
    (package_dir / "b.js").write_text("console.log('ok')", encoding="utf-8")
    (package_dir / "package.json").write_text(
        '{"scripts":{"postinstall":"node install.js"},"dependencies":{"left-pad":"1.3.0"}}',
        encoding="utf-8",
    )

    analyzer = ASTAnalyzer()
    result = analyzer.analyze_package_directory(str(package_dir))

    assert result["files_analyzed"] == 2
    assert result["summary"]["total_functions"] == 1
    assert result["summary"]["install_script_detected"] is True
    assert result["summary"]["dependency_count"] == 1
    assert result["summary"]["languages"]["javascript"] == 1
