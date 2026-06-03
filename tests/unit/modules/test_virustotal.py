from __future__ import annotations

import json
from io import BytesIO

from src.modules.virustotal import VirusTotalClient


class _Response(BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


def test_virustotal_client_disabled_without_key() -> None:
    client = VirusTotalClient(api_key="")
    result = client.lookup_file_hash("abc123")
    assert result["status"] == "disabled"
    assert result["enabled"] is False


def test_virustotal_client_parses_report(monkeypatch: object) -> None:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 10,
                    "undetected": 55,
                },
                "reputation": -5,
                "meaningful_name": "fixture.tgz",
                "type_description": "GZIP archive",
            }
        }
    }

    def _fake_urlopen(request: object, timeout: int = 0) -> _Response:
        return _Response(json.dumps(payload).encode("utf-8"))

    import src.modules.virustotal as vt_module

    monkeypatch.setattr(vt_module, "urlopen", _fake_urlopen)
    client = VirusTotalClient(api_key="demo-key")
    result = client.lookup_file_hash("f" * 64)
    assert result["status"] == "ok"
    assert result["stats"]["malicious"] == 2
    assert result["meaningful_name"] == "fixture.tgz"
