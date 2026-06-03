from __future__ import annotations

import zlib

import pytest

from src.core.python.exceptions import EntropyCalculationError
from src.modules.entropy import ShannonEntropyCalculator


def test_zero_entropy() -> None:
    data = b"\x00" * 100
    entropy = ShannonEntropyCalculator.calculate(data)
    assert entropy == 0.0


def test_max_entropy() -> None:
    data = bytes(range(256))
    entropy = ShannonEntropyCalculator.calculate(data)
    assert entropy == 8.0


def test_text_entropy() -> None:
    data = b"The quick brown fox jumps over the lazy dog" * 10
    entropy = ShannonEntropyCalculator.calculate(data)
    assert 4.0 < entropy < 5.5


def test_compressed_entropy() -> None:
    original = b"test data" * 1000
    compressed = zlib.compress(original)
    entropy = ShannonEntropyCalculator.calculate(compressed)
    assert entropy > 4.0


def test_windowed_entropy() -> None:
    data = bytes(range(50)) + bytes(range(50)) + bytes([0]) * 100
    avg, scores = ShannonEntropyCalculator.calculate_windowed(data, window_size=50)
    assert len(scores) == 4
    assert scores[0] > 5.0
    assert scores[2] == 0.0
    assert avg > 2.0


def test_entropy_heatmap() -> None:
    data = bytes(range(64)) + (b"\x00" * 64)
    heatmap = ShannonEntropyCalculator.entropy_heatmap(data, window_size=64)
    assert len(heatmap) == 2
    assert all("position" in item and "entropy" in item and "color" in item for item in heatmap)
    assert heatmap[0]["color"] == "yellow"
    assert heatmap[1]["color"] == "green"


def test_invalid_window_size_raises() -> None:
    with pytest.raises(EntropyCalculationError):
        ShannonEntropyCalculator.calculate_windowed(b"abc", window_size=0)
