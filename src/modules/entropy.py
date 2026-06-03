"""Shannon entropy analysis helpers."""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from src.core.python.exceptions import EntropyCalculationError


class ShannonEntropyCalculator:
    """
    Calculate Shannon entropy for binary data.

    H(X) = -Σ P(x) * log2(P(x))
    """

    @staticmethod
    def calculate(data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        if not data:
            return 0.0

        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0.0

        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def calculate_windowed(data: bytes, window_size: int = 1024) -> tuple[float, list[float]]:
        """Calculate average entropy and per-window entropy scores."""
        if window_size <= 0:
            raise EntropyCalculationError("window_size must be greater than zero")

        if len(data) < window_size:
            avg = ShannonEntropyCalculator.calculate(data)
            return avg, [avg]

        scores: list[float] = []
        for index in range(0, len(data), window_size):
            window = data[index : index + window_size]
            scores.append(ShannonEntropyCalculator.calculate(window))

        return sum(scores) / len(scores), scores

    @staticmethod
    def entropy_heatmap(data: bytes, window_size: int = 256) -> list[dict[str, Any]]:
        """Generate per-window entropy metadata for visualization."""
        if window_size <= 0:
            raise EntropyCalculationError("window_size must be greater than zero")

        heatmap: list[dict[str, Any]] = []
        for index in range(0, len(data), window_size):
            window = data[index : index + window_size]
            entropy = ShannonEntropyCalculator.calculate(window)
            if entropy >= 7.0:
                color = "red"
            elif entropy >= 5.0:
                color = "yellow"
            else:
                color = "green"

            heatmap.append({"position": index, "entropy": entropy, "color": color})
        return heatmap
