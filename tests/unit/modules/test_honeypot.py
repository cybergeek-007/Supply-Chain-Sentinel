from __future__ import annotations

from pathlib import Path

from src.modules.honeypot import HoneypotModule


def test_create_honeypots(tmp_path: Path) -> None:
    module = HoneypotModule("config/honeypot_config.json")
    target = tmp_path / "sandbox"
    result = module.create_honeypots(target)

    assert result["total"] > 0
    created_paths = [Path(item["path"]) for item in result["honeypots"]]
    assert all(path.exists() for path in created_paths)


def test_detect_honeypot_access() -> None:
    module = HoneypotModule("config/honeypot_config.json")
    detections = module.detect_honeypot_access(
        ["/tmp/run/root/.ssh/id_rsa", "/tmp/run/root/.docker/config.json"]
    )
    assert len(detections) == 2
    assert detections[0]["confidence"] == "high"
