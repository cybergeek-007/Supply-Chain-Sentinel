from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .artifact import resolve_npm_runner


@dataclass(slots=True)
class HealthCheck:
    name: str
    status: str
    detail: str


def run_doctor(project_root: Path, timeout: int = 20) -> list[HealthCheck]:
    npm_runner, npm_method = resolve_npm_runner(timeout)
    checks = [
        HealthCheck(
            name="python",
            status="ok",
            detail=f"Python {platform.python_version()} on {platform.system()}",
        ),
        _check_path("rules_config", project_root / "config" / "default_rules.json"),
        _check_path("yara_signatures", project_root / "config" / "basic_signatures.yar"),
        _check_command(["docker", "--version"], "docker_cli", timeout),
        _check_docker_daemon(timeout),
        _check_command(["npm", "--version"], "npm_cli", timeout, failure_status="warn"),
        _check_command(["corepack", "--version"], "corepack_cli", timeout, failure_status="warn"),
        _check_npm_runtime(npm_runner, npm_method),
        _check_xai_key(),
        _check_optional_module("xai_sdk"),
        _check_optional_module("esprima"),
        _check_optional_module("yara"),
    ]
    return checks


def render_doctor_report(checks: list[HealthCheck]) -> str:
    lines = []
    for check in checks:
        lines.append(f"{check.name}: {check.status} - {check.detail}")
    overall = overall_status(checks)
    lines.append(f"overall: {overall}")
    return "\n".join(lines)


def overall_status(checks: list[HealthCheck]) -> str:
    if any(check.status == "fail" for check in checks):
        return "fail"
    if any(check.status == "warn" for check in checks):
        return "warn"
    return "ok"


def _check_path(name: str, path: Path) -> HealthCheck:
    if path.exists():
        return HealthCheck(name=name, status="ok", detail=str(path))
    return HealthCheck(name=name, status="fail", detail=f"Missing path: {path}")


def _check_command(command: list[str], name: str, timeout: int, failure_status: str = "fail") -> HealthCheck:
    executable = shutil.which(command[0])
    if not executable:
        return HealthCheck(name=name, status=failure_status, detail=f"{command[0]} is not on PATH")
    resolved_command = [executable, *command[1:]]
    try:
        result = subprocess.run(
            resolved_command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return HealthCheck(name=name, status=failure_status, detail=str(exc))

    if result.returncode == 0:
        detail = (result.stdout or result.stderr).strip() or f"{command[0]} is available"
        return HealthCheck(name=name, status="ok", detail=detail)
    detail = (result.stderr or result.stdout).strip() or f"{command[0]} exited with {result.returncode}"
    return HealthCheck(name=name, status=failure_status, detail=detail)


def _check_docker_daemon(timeout: int) -> HealthCheck:
    if not shutil.which("docker"):
        return HealthCheck(name="docker_daemon", status="fail", detail="docker CLI is missing")
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return HealthCheck(name="docker_daemon", status="fail", detail=str(exc))

    if result.returncode == 0:
        detail = result.stdout.strip() or "Docker daemon is reachable"
        return HealthCheck(name="docker_daemon", status="ok", detail=detail)

    detail = (result.stderr or result.stdout).strip() or "Docker daemon is not reachable"
    return HealthCheck(name="docker_daemon", status="fail", detail=detail)


def _check_optional_module(module_name: str) -> HealthCheck:
    if importlib.util.find_spec(module_name):
        return HealthCheck(name=module_name, status="ok", detail=f"{module_name} is installed")
    return HealthCheck(
        name=module_name,
        status="warn",
        detail=f"{module_name} is not installed; Sentinel will run with reduced coverage",
    )


def _check_npm_runtime(runner: list[str] | None, method: str) -> HealthCheck:
    if runner:
        detail = " ".join(runner)
        return HealthCheck(name="npm_runtime", status="ok", detail=f"Sentinel will use {method} via {detail}")
    return HealthCheck(
        name="npm_runtime",
        status="fail",
        detail="No working npm runtime detected for registry fetches or approved installs",
    )


def _check_xai_key() -> HealthCheck:
    if os.getenv("XAI_API_KEY"):
        return HealthCheck(name="xai_api_key", status="ok", detail="XAI_API_KEY is set")
    return HealthCheck(
        name="xai_api_key",
        status="warn",
        detail="XAI_API_KEY is not set; Grok summaries will be skipped",
    )
