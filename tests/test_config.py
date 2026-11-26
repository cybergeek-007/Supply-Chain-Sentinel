from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from supply_chain_sentinel.config import Config, load_config, suppress
from supply_chain_sentinel.models import Finding, ScanError, classify


@pytest.mark.parametrize(
    "text",
    [
        "unknown=true",
        "max_files=0",
        "timeout='x'",
        "private_names='x'",
        "suppressions=[{}]",
        "suppressions=4",
        "max_files=true",
    ],
)
def test_invalid_config(text: str, tmp_path: Path) -> None:
    path = tmp_path / "sentinel.toml"
    path.write_text(text)
    with pytest.raises(ScanError):
        load_config(path)


def test_config_and_expiring_suppression(tmp_path: Path) -> None:
    path = tmp_path / "sentinel.toml"
    path.write_text('cache_dir="cache"\nprivate_names=["@corp/internal"]')
    config = load_config(path)
    assert config.private_names == ["@corp/internal"]
    finding = Finding("env-network", "high", 0.9, "test")
    entry = {
        "package": "demo",
        "version": "1.0.0",
        "rule_id": "env-network",
        "reason": "reviewed fixture",
        "expires": (date.today() + timedelta(days=2)).isoformat(),
    }
    config.suppressions = [entry]
    suppress([finding], config, "demo", "2.0.0", "")
    assert not finding.suppressed
    suppress([finding], config, "demo", "1.0.0", "")
    assert finding.suppressed and classify([finding])[1] == "clean"
    entry["expires"] = "2000-01-01"
    other = Finding("env-network", "high", 0.9, "test")
    suppress([other], config, "demo", "1.0.0", "")
    assert not other.suppressed


def test_defaults_do_not_read_project_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sentinel.toml").write_text("invalid=true")
    assert isinstance(load_config(), Config)
