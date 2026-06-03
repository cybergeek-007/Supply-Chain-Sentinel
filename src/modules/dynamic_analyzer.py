"""Dynamic sandbox analysis pipeline."""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from src.core.python.logger import get_logger
from src.modules.ebpf_tracer import KernelTracer
from src.modules.extractor import PackageExtractor
from src.modules.honeypot import HoneypotModule
from src.modules.rule_engine import BehavioralRuleEngine
from src.modules.sandbox import SandboxManager


class DynamicAnalyzer:
    """Execute and monitor package in sandbox."""

    def __init__(
        self,
        config: Any,
        sandbox: SandboxManager | None = None,
        rule_engine: BehavioralRuleEngine | None = None,
        honeypot: HoneypotModule | None = None,
        extractor: PackageExtractor | None = None,
    ):
        self.config = config
        self.logger = get_logger(__name__)
        self.sandbox = sandbox or SandboxManager(config)
        self.rule_engine = rule_engine or BehavioralRuleEngine()
        self.honeypot = honeypot or HoneypotModule()
        self.extractor = extractor or PackageExtractor(config.staging_dir)

    async def analyze_package_dynamic(self, package_path: str, package_name: str) -> dict[str, Any]:
        analysis_result: dict[str, Any] = {
            "status": "analyzing",
            "package_name": package_name,
            "phases": {},
        }

        container_id: str | None = None
        trace_events: list[dict[str, Any]] = []
        tracer: KernelTracer | None = None
        tracer_thread: threading.Thread | None = None
        extraction_name = f"{package_name}-dynamic"
        extraction = self.extractor.extract_package(package_path, extraction_name)
        if extraction["status"] != "success":
            return {
                "status": "failed",
                "package_name": package_name,
                "error": extraction.get("error", "Dynamic extraction failed"),
            }
        extraction_path = extraction["data"]["extraction_path"]
        analysis_result["phases"]["extraction"] = extraction

        honeypot_dir_path = self._create_honeypot_workspace(package_name)
        with_honeypot_dir = str(honeypot_dir_path)
        try:
            try:
                sandbox = self.sandbox.create_sandbox(
                    package_path=extraction_path,
                    package_name=package_name,
                    honeypots_dir=with_honeypot_dir,
                )
                if sandbox["status"] != "created":
                    return {
                        "status": "failed",
                        "error": f"Sandbox creation failed: {sandbox['error']}",
                    }

                container_id = sandbox["container_id"]
                analysis_result["phases"]["sandbox_setup"] = sandbox

                honeypots = self.honeypot.create_honeypots(honeypot_dir_path)
                analysis_result["phases"]["honeypots"] = honeypots

                package_root = self._detect_package_root(Path(extraction_path))
                analysis_result["phases"]["runtime_context"] = {
                    "package_root": package_root,
                    "trace_mode": "ebpf" if getattr(self.config, "enable_ebpf", True) else "disabled",
                }
                tracer, tracer_thread = self._start_trace_capture()
                start_time = time.time()
                execution = self.sandbox.execute_in_sandbox(
                    container_id=container_id,
                    command=self.sandbox.build_npm_install_command(package_root),
                    timeout=int(self.config.timeout_sandbox),
                )
                execution["duration_seconds"] = round(time.time() - start_time, 2)
                analysis_result["phases"]["execution"] = execution
                trace_events = self._stop_trace_capture(tracer, tracer_thread)
                trace_summary = {
                    "mode": "ebpf" if tracer is not None else "heuristic-only",
                    "event_count": len(trace_events),
                    "events": trace_events,
                }
                analysis_result["phases"]["trace_capture"] = trace_summary

                violations = self.rule_engine.evaluate_trace_events(trace_events)
                accessed_paths = [event.get("path", "") for event in trace_events]
                honeypot_detections = self.honeypot.detect_honeypot_access(accessed_paths)
                runtime_indicators = self._derive_runtime_indicators(execution, package_root)

                behavior = {
                    "rule_violations": violations,
                    "honeypot_detections": honeypot_detections,
                    "runtime_indicators": runtime_indicators,
                }
                analysis_result["phases"]["behavior_analysis"] = behavior

                is_malicious = (
                    violations["summary"]["should_block"]
                    or len(honeypot_detections) > 0
                    or any(ind["severity"] == "critical" for ind in runtime_indicators)
                )
                if execution.get("status") == "failed":
                    analysis_result["status"] = "failed"
                else:
                    analysis_result["status"] = "blocked" if is_malicious else "safe"
                analysis_result["risk_level"] = self._calculate_risk_level(
                    violations, honeypot_detections, runtime_indicators, execution
                )
                return analysis_result
            finally:
                if container_id:
                    self.sandbox.cleanup_sandbox(container_id)
                self.extractor.cleanup(extraction_name)
        finally:
            shutil.rmtree(honeypot_dir_path, ignore_errors=True)

    def _start_trace_capture(self) -> tuple[KernelTracer | None, threading.Thread | None]:
        if not getattr(self.config, "enable_ebpf", True):
            return None, None
        try:
            tracer = KernelTracer(str(getattr(self.config, "ebpf_source_path", "")))
        except (FileNotFoundError, RuntimeError):
            return None, None

        max_polls = max(10, int(getattr(self.config, "timeout_sandbox", 30)) * 20)
        tracer_thread = threading.Thread(
            target=tracer.start_tracing,
            kwargs={"max_polls": max_polls},
            daemon=True,
        )
        tracer_thread.start()
        return tracer, tracer_thread

    def _stop_trace_capture(
        self,
        tracer: KernelTracer | None,
        tracer_thread: threading.Thread | None,
    ) -> list[dict[str, Any]]:
        if tracer is None:
            return []
        events = tracer.stop_tracing()
        if tracer_thread is not None:
            tracer_thread.join(timeout=5)
        return events

    def _calculate_risk_level(
        self,
        violations: dict[str, Any],
        detections: list[dict[str, Any]],
        runtime_indicators: list[dict[str, Any]],
        execution: dict[str, Any],
    ) -> str:
        if violations["summary"]["critical_violations"] > 0 or len(detections) > 0:
            return "CRITICAL"
        if any(item["severity"] == "critical" for item in runtime_indicators):
            return "CRITICAL"
        if violations["summary"]["total_violations"] > 0:
            return "HIGH"
        if execution.get("exit_code") not in {None, 0}:
            return "HIGH"
        if any(item["severity"] == "high" for item in runtime_indicators):
            return "HIGH"
        if violations["summary"]["total_alerts"] > 0:
            return "MEDIUM"
        if runtime_indicators:
            return "MEDIUM"
        return "LOW"

    def _detect_package_root(self, extraction_path: Path) -> str:
        package_dir = extraction_path / "package"
        if package_dir.exists():
            return "/workspace/package"
        return "/workspace"

    def _derive_runtime_indicators(
        self, execution: dict[str, Any], package_root: str
    ) -> list[dict[str, Any]]:
        combined = "\n".join(
            [
                str(execution.get("stdout", "")),
                str(execution.get("stderr", "")),
                str(execution.get("error", "")),
            ]
        ).lower()
        indicators: list[dict[str, Any]] = []
        patterns = [
            (
                "dynamic-network-indicator",
                "Potential network-related runtime indicator",
                "high",
                ("http://", "https://", "fetch", "axios", "download"),
            ),
            (
                "dynamic-credential-indicator",
                "Potential credential-access runtime indicator",
                "critical",
                (".ssh", ".npmrc", ".aws", "github_token", "id_rsa"),
            ),
            (
                "dynamic-shell-indicator",
                "Potential shell or command execution runtime indicator",
                "high",
                ("powershell", "cmd.exe", "/bin/sh", "child_process", "exec"),
            ),
        ]
        for indicator_id, title, severity, tokens in patterns:
            for token in tokens:
                if token in combined:
                    indicators.append(
                        {
                            "id": indicator_id,
                            "title": title,
                            "severity": severity,
                            "evidence": token,
                            "source": "runtime-log-analysis",
                            "package_root": package_root,
                        }
                    )
                    break
        return indicators

    def _create_honeypot_workspace(self, package_name: str) -> Path:
        staging_root = Path(getattr(self.config, "staging_dir", ".dynamic_staging"))
        workspace = staging_root / f"honeypots-{package_name}-{uuid.uuid4().hex[:8]}"
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace
