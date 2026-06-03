from __future__ import annotations

from pathlib import Path

from src.modules.static_analyzer import StaticAnalyzer


def test_static_analyzer_aggregates_outputs(tmp_path: Path) -> None:
    package_dir = tmp_path / "pkg"
    package_dir.mkdir()
    (package_dir / "package.json").write_text(
        '{"name":"demo","version":"1.0.0","scripts":{"postinstall":"node index.js"}}',
        encoding="utf-8",
    )
    (package_dir / "index.js").write_text(
        "postinstall; const cp = require('child_process'); eval('x'); fetch('https://example.com');",
        encoding="utf-8",
    )

    analyzer = StaticAnalyzer(rules_dir=str(tmp_path / "rules"))
    result = analyzer.analyze_directory(str(package_dir))

    assert result["package_name"] == "demo"
    assert result["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert result["summary"]["findings_count"] >= 1
    assert result["manifest"]["install_scripts"][0]["name"] == "postinstall"
    assert any(finding["category"] == "manifest" for finding in result["findings"])
    assert any(finding["category"] == "execution" for finding in result["findings"])
    assert result["summary"]["files_analyzed_ast"] == 1
