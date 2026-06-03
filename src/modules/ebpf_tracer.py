"""Kernel trace event bridge for eBPF/BCC with graceful availability checks."""

from __future__ import annotations

import ctypes
import socket
import struct
from pathlib import Path
from typing import Any, Callable

try:
    from bcc import BPF  # type: ignore[import-not-found]
except ModuleNotFoundError:
    BPF = None


class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("ts", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("syscall_id", ctypes.c_uint32),
        ("syscall_name", ctypes.c_char * 32),
        ("arg1", ctypes.c_uint64),
        ("arg2", ctypes.c_uint64),
        ("arg3", ctypes.c_uint64),
        ("path", ctypes.c_char * 256),
        ("dest_ip", ctypes.c_uint32),
        ("dest_port", ctypes.c_uint16),
    ]


class KernelTracer:
    """eBPF-based kernel syscall tracer."""

    def __init__(self, ebpf_source_path: str):
        if BPF is None:
            raise RuntimeError("bcc/BPF is not available in this environment")

        source = Path(ebpf_source_path).read_text(encoding="utf-8")
        self.bpf = BPF(text=source)
        self.events = self.bpf["events"]
        self.running = False
        self.trace_events: list[dict[str, Any]] = []

    def start_tracing(
        self,
        callback: Callable[[dict[str, Any]], None] | None = None,
        max_polls: int = 1000,
    ) -> None:
        self.running = True

        def handle_event(_cpu: Any, data: Any, _size: int) -> None:
            event = ctypes.cast(data, ctypes.POINTER(Event)).contents
            event_dict = {
                "pid": event.pid,
                "uid": event.uid,
                "ts": event.ts,
                "comm": event.comm.decode(errors="ignore").rstrip("\0"),
                "syscall": event.syscall_name.decode(errors="ignore").rstrip("\0"),
                "path": event.path.decode(errors="ignore").rstrip("\0"),
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port,
            }
            self.trace_events.append(event_dict)
            if callback:
                callback(event_dict)

        self.events.open_perf_buffer(handle_event)
        polls = 0
        while self.running and polls < max_polls:
            self.bpf.perf_buffer_poll(timeout=100)
            polls += 1

    def stop_tracing(self) -> list[dict[str, Any]]:
        self.running = False
        return list(self.trace_events)

    def format_event(self, event: dict[str, Any]) -> str:
        timestamp = float(event.get("ts", 0)) / 1e9
        syscall = event.get("syscall")
        if syscall == "openat":
            return f"[{timestamp:.2f}] PID {event.get('pid')}: openat('{event.get('path', '')}')"
        if syscall == "connect":
            dest = socket.inet_ntoa(struct.pack("!I", int(event.get("dest_ip", 0))))
            return f"[{timestamp:.2f}] PID {event.get('pid')}: connect({dest}:{event.get('dest_port', 0)})"
        if syscall == "execve":
            return f"[{timestamp:.2f}] PID {event.get('pid')}: execve('{event.get('path', '')}')"
        return str(event)
