from __future__ import annotations

from pathlib import Path

import pytest

from src.core.python.config import SentinelConfig
from src.core.python.exceptions import ConfigError


def test_from_environment_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_ENV", raising=False)
    monkeypatch.delenv("SENTINEL_DEBUG", raising=False)
    config = SentinelConfig.from_environment()
    assert config.environment == "production"
    assert config.debug is False


def test_from_environment_bool_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("SENTINEL_DEBUG", "true")
    config = SentinelConfig.from_environment()
    assert config.environment == "production"
    assert config.debug is True


def test_from_file_overrides_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_TIMEOUT", "60")
    config_file = tmp_path / "config.yaml"
    config_file.write_text("timeout_sandbox: 120\nlog_level: debug\n", encoding="utf-8")

    config = SentinelConfig.from_file(str(config_file))
    assert config.timeout_sandbox == 120
    assert config.log_level == "debug"


def test_missing_config_file_raises() -> None:
    with pytest.raises(ConfigError):
        SentinelConfig.from_file("this-file-does-not-exist.yaml")


def test_invalid_debug_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_DEBUG", "definitely")
    with pytest.raises(ConfigError):
        SentinelConfig.from_environment()
