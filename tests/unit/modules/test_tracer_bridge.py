from __future__ import annotations

from pathlib import Path

from src.modules.tracer import TracerBridge


def test_tracer_bridge_returns_false_for_missing_source(tmp_path: Path) -> None:
    bridge = TracerBridge(str(tmp_path / "missing.c"))
    assert bridge.start(max_polls=1) is False
    assert bridge.stop() == []
