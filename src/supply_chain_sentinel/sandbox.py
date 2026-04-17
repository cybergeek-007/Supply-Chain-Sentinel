from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .models import Finding, PackageArtifact, SandboxResult


class SandboxError(RuntimeError):
    """Raised when sandbox execution fails."""


def run_sandbox(artifact: PackageArtifact, project_root: Path, timeout: int) -> SandboxResult:
    image_tag = "supply-chain-sentinel-runner:latest"
    _ensure_docker_image(project_root, image_tag, timeout)

    output_dir = Path(tempfile.mkdtemp(prefix="sentinel-sandbox-"))
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{artifact.extracted_path.resolve()}:/workspace/package:ro",
        "-v",
        f"{project_root.joinpath('docker', 'runner_entrypoint.py').resolve()}:/opt/sentinel/runner_entrypoint.py:ro",
        "-v",
        f"{output_dir.resolve()}:/workspace/output",
        image_tag,
        "python3",
        "/opt/sentinel/runner_entrypoint.py",
        "/workspace/package",
        "/workspace/output",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("sandbox execution timed out") from exc

    if result.returncode != 0:
        raise SandboxError(result.stderr.strip() or result.stdout.strip() or "sandbox execution failed")

    try:
        findings, metadata = _parse_sandbox_output(output_dir)
        metadata["container_stdout"] = result.stdout[-4000:]
        metadata["container_stderr"] = result.stderr[-4000:]
        return SandboxResult(findings=findings, metadata=metadata)
    finally:
        for path in sorted(output_dir.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink(missing_ok=True)
            else:
                path.rmdir()
        output_dir.rmdir()


def _ensure_docker_image(project_root: Path, image_tag: str, timeout: int) -> None:
    inspect = subprocess.run(
        ["docker", "image", "inspect", image_tag],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if inspect.returncode == 0:
        return

    build = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            image_tag,
            str(project_root / "docker"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if build.returncode != 0:
        raise SandboxError(build.stderr.strip() or build.stdout.strip() or "docker build failed")


def _parse_sandbox_output(output_dir: Path) -> tuple[list[Finding], dict[str, object]]:
    findings: list[Finding] = []
    metadata: dict[str, object] = {}
    events_path = output_dir / "events.json"
    if events_path.exists():
        events = json.loads(events_path.read_text(encoding="utf-8"))
        metadata["script_events"] = events
        for event in events:
            returncode = int(event.get("returncode", 0))
            if returncode != 0:
                findings.append(
                    Finding(
                        category="process",
                        kind="script_failure",
                        severity="medium",
                        message=f"Lifecycle script {event.get('script')} exited with code {returncode}.",
                        score=10,
                        evidence={"script": event.get("script"), "returncode": returncode},
                    )
                )

    for trace_path in sorted(output_dir.glob("*.strace.log")):
        metadata.setdefault("trace_files", []).append(trace_path.name)
        findings.extend(_parse_trace_file(trace_path))

    return findings, metadata


def _parse_trace_file(trace_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    text = trace_path.read_text(encoding="utf-8", errors="ignore")
    suspicious_processes = ("curl", "wget", "powershell", "bash", "sh", "python", "nc")
    honeypot_files = (".ssh/id_rsa", ".aws/credentials")

    for line in text.splitlines():
        if "connect(" in line:
            findings.append(
                Finding(
                    category="network",
                    kind="network_connect",
                    severity="high",
                    message=f"Network connection attempt observed in {trace_path.name}.",
                    score=45,
                    evidence={"trace": trace_path.name},
                )
            )
            continue

        if "openat(" in line or "open(" in line:
            for honeypot in honeypot_files:
                if honeypot in line:
                    findings.append(
                        Finding(
                            category="credentials",
                            kind="honeypot_credential_access",
                            severity="critical",
                            message=f"Honeypot credential access observed in {trace_path.name}.",
                            score=55,
                            evidence={"trace": trace_path.name, "path_fragment": honeypot},
                        )
                    )
                    break
            if ".bash" in line or ".profile" in line:
                findings.append(
                    Finding(
                        category="filesystem",
                        kind="sensitive_file_access",
                        severity="medium",
                        message=f"Sensitive shell profile access observed in {trace_path.name}.",
                        score=25,
                        evidence={"trace": trace_path.name, "path_fragment": ".bash"},
                    )
                )

        if "execve(" in line:
            for name in suspicious_processes:
                if f'"{name}"' in line:
                    findings.append(
                        Finding(
                            category="process",
                            kind="suspicious_process",
                            severity="high",
                            message=f"Suspicious subprocess '{name}' observed in {trace_path.name}.",
                            score=35,
                            evidence={"trace": trace_path.name, "process": name},
                        )
                    )
                    break

    return _deduplicate_findings(findings)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (
            finding.category,
            finding.kind,
            json.dumps(finding.evidence, sort_keys=True),
        )
        unique.setdefault(key, finding)
    return list(unique.values())
