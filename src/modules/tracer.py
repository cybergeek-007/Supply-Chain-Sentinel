"""Tracer facade that wraps KernelTracer availability checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from src.modules.ebpf_tracer import KernelTracer


class TracerBridge:
    """Simple facade for starting/stopping kernel tracing sessions."""

    def __init__(self, ebpf_source_path: str):
        self.ebpf_source_path = ebpf_source_path
        self.tracer: KernelTracer | None = None

    def start(
        self,
        callback: Callable[[dict[str, Any]], None] | None = None,
        max_polls: int = 1000,
    ) -> bool:
        if not Path(self.ebpf_source_path).exists():
            return False
        try:
            self.tracer = KernelTracer(self.ebpf_source_path)
        except RuntimeError:
            return False

        self.tracer.start_tracing(callback=callback, max_polls=max_polls)
        return True

    def stop(self) -> list[dict[str, Any]]:
        if self.tracer is None:
            return []
        return self.tracer.stop_tracing()
