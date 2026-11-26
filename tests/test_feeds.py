from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from supply_chain_sentinel import feeds
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import ScanError


def test_pagination_withdrawal_and_lookup(config: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        {
            "vulns": [{"id": "MAL-2025-1"}, {"id": "MAL-2025-2", "withdrawn": "2026-01-01"}],
            "next_page_token": "next",
        },
        {
            "vulns": [
                {"id": "GHSA-xxxx"},
                {
                    "id": "GHSA-malware",
                    "database_specific": {"github_reviewed": True, "cwe_ids": ["CWE-506"]},
                },
            ]
        },
    ]
    monkeypatch.setattr(feeds, "request_bytes", lambda *a, **kw: json.dumps(pages.pop(0)).encode())
    snapshot = feeds.update_snapshot(config, ["demo@1.0.0"])
    findings, coverage = feeds.lookup(feeds.load_snapshot(config), config, "demo", "1.0.0")
    assert {f.rule_id for f in findings} == {"known-malicious", "known-vulnerability"}
    assert not coverage["advisory_stale"]
    assert len(snapshot["entries"]["demo@1.0.0"]["advisories"]) == 3
    assert sum(f.rule_id == "known-malicious" for f in findings) == 2


def test_failed_update_preserves_snapshot(config: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(feeds, "request_bytes", lambda *a, **kw: b"{}")
    feeds.update_snapshot(config, ["demo@1.0.0"])
    original = (config.cache_dir / "advisories.json").read_bytes()
    monkeypatch.setattr(feeds, "request_bytes", lambda *a, **kw: b"not-json")
    with pytest.raises(ScanError):
        feeds.update_snapshot(config, ["other@2.0.0"])
    assert (config.cache_dir / "advisories.json").read_bytes() == original


def test_stale_missing_corrupted(config: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    assert (
        feeds.lookup(feeds.load_snapshot(config), config, "x", "1")[1]["advisories"]
        == "not-queried"
    )
    monkeypatch.setattr(feeds, "request_bytes", lambda *a, **kw: b"{}")
    snapshot = feeds.update_snapshot(config, ["demo@1.0.0"])
    snapshot["entries"]["demo@1.0.0"]["queried_at"] = (
        datetime.now(timezone.utc) - timedelta(days=10)
    ).isoformat()
    assert feeds.lookup(snapshot, config, "demo", "1.0.0")[1]["advisory_stale"]
    (config.cache_dir / "advisories.json").write_text('{"broken":1}')
    with pytest.raises(ScanError):
        feeds.load_snapshot(config)


def test_update_requires_exact_identities(config: Config) -> None:
    with pytest.raises(ScanError):
        feeds.update_snapshot(config, [])
    with pytest.raises(ScanError):
        feeds.update_snapshot(config, ["demo"])
