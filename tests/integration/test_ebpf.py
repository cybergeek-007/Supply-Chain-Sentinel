from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.modules.ebpf_tracer import KernelTracer


@pytest.mark.skipif(
    not Path("/sys/kernel/debug").exists(),
    reason="Requires Linux kernel tracing support",
)
def test_tracer_initializes_with_minimal_program() -> None:
    ebpf_code = """
    BPF_PERF_OUTPUT(events);
    TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
        return 0;
    }
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as handle:
        handle.write(ebpf_code)
        handle.flush()
        source = handle.name

    try:
        tracer = KernelTracer(source)
        assert tracer is not None
    except RuntimeError:
        pytest.skip("bcc/BPF not available in this environment")
    finally:
        Path(source).unlink(missing_ok=True)
