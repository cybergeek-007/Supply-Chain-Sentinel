"""Explicit TOML config; never load arbitrary project Python or dotenv secrets."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .models import Finding, ScanError


@dataclass
class Config:
    cache_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "SENTINEL_CACHE_DIR", str(Path.home() / ".cache" / "supply-chain-sentinel")
            )
        )
    )
    max_archive_bytes: int = 50 * 1024 * 1024
    max_unpacked_bytes: int = 128 * 1024 * 1024
    max_files: int = 10000
    max_source_bytes: int = 16 * 1024 * 1024
    timeout: int = 15
    advisory_max_age_days: int = 7
    private_names: list[str] = field(default_factory=list)
    suppressions: list[dict[str, str]] = field(default_factory=list)


def load_config(path: Path | None = None) -> Config:
    if path is None:
        return Config()
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        allowed = set(Config.__dataclass_fields__)
        if set(data) - allowed:
            raise ValueError(f"Unknown config keys: {sorted(set(data) - allowed)}")
        if "cache_dir" in data:
            data["cache_dir"] = Path(data["cache_dir"]).expanduser()
        config = Config(**data)
        for key in (
            "max_archive_bytes",
            "max_unpacked_bytes",
            "max_files",
            "max_source_bytes",
            "timeout",
            "advisory_max_age_days",
        ):
            value = getattr(config, key)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{key} must be a positive integer")
        if not isinstance(config.private_names, list) or not all(
            isinstance(n, str) for n in config.private_names
        ):
            raise ValueError("private_names must be an array of strings")
        if not isinstance(config.suppressions, list):
            raise ValueError("suppressions must be an array of tables")
        for suppression in config.suppressions:
            _validate_suppression(suppression)
        return config
    except (OSError, ValueError, TypeError) as exc:
        raise ScanError(f"Invalid config: {exc}") from exc


def _validate_suppression(item: Any) -> None:
    if not isinstance(item, dict) or not all(isinstance(v, str) for v in item.values()):
        raise ValueError("Suppression values must be strings")
    if set(item) - {"package", "version", "sha256", "rule_id", "reason", "expires"}:
        raise ValueError("Unknown suppression key")
    if not all(item.get(k) for k in ("rule_id", "reason", "expires")):
        raise ValueError("Suppressions require rule_id, reason, expires")
    if not item.get("sha256") and not (item.get("package") and item.get("version")):
        raise ValueError("Suppression needs sha256 or exact package+version")
    date.fromisoformat(item["expires"])


def suppress(findings: list[Finding], config: Config, name: str, version: str, digest: str) -> None:
    for entry in config.suppressions:
        if date.fromisoformat(entry["expires"]) < date.today():
            continue
        if entry.get("sha256"):
            matches = bool(digest) and entry["sha256"] == digest
        else:
            matches = entry.get("package") == name and entry.get("version") == version
        for finding in findings:
            if matches and entry["rule_id"] == finding.rule_id:
                finding.suppressed = True
                finding.suppression_reason = entry["reason"]
