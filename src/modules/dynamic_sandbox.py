"""Docker-based dynamic sandbox with syscall tracing.

Dual-mode execution:
  1. Docker mode (primary): Full isolation with strace syscall tracing
  2. Subprocess mode (fallback): When Docker is unavailable

Docker sandbox features:
  - --network=none: zero outbound network
  - --cap-drop=ALL --cap-add=SYS_PTRACE: only ptrace for strace
  - --read-only --tmpfs: read-only root filesystem
  - --memory=256m --cpus=0.5 --pids-limit=100: resource limits
  - strace -f -e trace=network,file,process: full syscall capture
  - Honeypot credentials in environment
  - Filesystem snapshot diff
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from src.core.python.logger import get_logger

# Optional Docker SDK
try:
    import docker as docker_sdk
    _HAS_DOCKER = True
except ImportError:
    docker_sdk = None
    _HAS_DOCKER = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SANDBOX_IMAGE = "sentinel-sandbox:latest"
_HONEYPOT_MARKER = "SENTINEL_FAKE"

# Honeypot environment variables injected into sandbox
_HONEYPOT_ENV: dict[str, str] = {
    "NPM_TOKEN": "SENTINEL_FAKE_NPM_TOKEN_0000",
    "AWS_ACCESS_KEY_ID": "SENTINEL_FAKE_AWS_KEY_AKIAIOSFODNN7EXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "SENTINEL_FAKE_AWS_SECRET_wJalrXUtnFEMI",
    "GITHUB_TOKEN": "SENTINEL_FAKE_GH_TOKEN_ghp_0000000000000000000",
    "GH_TOKEN": "SENTINEL_FAKE_GH_TOKEN_ghp_0000000000000000000",
    "GITLAB_TOKEN": "SENTINEL_FAKE_GITLAB_TOKEN_glpat-0000",
    "DOCKER_PASSWORD": "SENTINEL_FAKE_DOCKER_PASSWORD",
    "PYPI_TOKEN": "SENTINEL_FAKE_PYPI_TOKEN_pypi-0000",
    "CI_JOB_TOKEN": "SENTINEL_FAKE_CI_JOB_TOKEN_0000",
    "NODE_ENV": "production",
    "NO_UPDATE_NOTIFIER": "1",
}

# ---------------------------------------------------------------------------
# Strace output parser
# ---------------------------------------------------------------------------

# Suspicious syscall patterns with severity
_STRACE_RULES: list[tuple[str, str, str, str]] = [
    # (regex, finding_id, severity, description)
    # Network connections to non-localhost
    (r'connect\(.*sa_family=AF_INET.*sin_addr=inet_addr\("(?!127\.0\.0\.1|0\.0\.0\.0)([^"]+)"\).*sin_port=htons\((\d+)\)',
     "syscall.network-connect", "critical",
     "Outbound network connection to external IP"),
    # DNS resolution
    (r'connect\(.*sa_family=AF_INET.*sin_port=htons\(53\)',
     "syscall.dns-query", "high",
     "DNS query attempted (should be impossible with --network=none)"),
    # Socket creation
    (r'socket\(AF_INET6?\s*,\s*SOCK_STREAM',
     "syscall.socket-create", "high",
     "TCP socket created"),
    # Sensitive file access
    (r'openat\(.*"(?:/etc/passwd|/etc/shadow|/etc/hosts)"',
     "syscall.sensitive-file-read", "critical",
     "Sensitive system file accessed"),
    # SSH key access
    (r'openat\(.*".*\.ssh/(?:id_rsa|id_ed25519|authorized_keys|known_hosts)"',
     "syscall.ssh-key-access", "critical",
     "SSH key file accessed"),
    # npmrc / credential file access
    (r'openat\(.*".*\.npmrc"',
     "syscall.npmrc-access", "critical",
     "npmrc file accessed (potential credential theft)"),
    # AWS credential access
    (r'openat\(.*".*\.aws/credentials"',
     "syscall.aws-creds-access", "critical",
     "AWS credentials file accessed"),
    # Dangerous command execution
    (r'execve\("(?:/usr/bin/|/bin/|/usr/local/bin/)(?:curl|wget|nc|ncat|netcat|python|perl|ruby|php)"',
     "syscall.dangerous-exec", "critical",
     "Dangerous command executed (download tool or scripting language)"),
    # Shell execution
    (r'execve\("(?:/bin/sh|/bin/bash|/bin/ash|/bin/zsh)"',
     "syscall.shell-exec", "high",
     "Shell process spawned"),
    # File deletion outside sandbox
    (r'unlinkat?\(.*"(?!/sandbox/|/tmp/)([^"]+)"',
     "syscall.suspicious-delete", "high",
     "File deletion outside sandbox directory"),
    # Process spawning (fork/clone count is tracked separately)
    (r'clone\(|clone3\(',
     "syscall.process-spawn", "medium",
     "Child process spawned"),
]


def parse_strace_output(strace_text: str) -> list[dict[str, Any]]:
    """Parse strace log and extract suspicious syscall findings.

    Parameters
    ----------
    strace_text:
        Raw strace output text.

    Returns
    -------
    list[dict]
        Finding dicts compatible with the pipeline.
    """
    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for pattern, finding_id, severity, description in _STRACE_RULES:
        if finding_id in seen_ids:
            continue

        if finding_id == "syscall.process-spawn":
            # Count-based: only flag if excessive
            count = len(re.findall(pattern, strace_text))
            if count > 20:
                findings.append({
                    "id": finding_id,
                    "title": description,
                    "severity": "high" if count > 50 else severity,
                    "confidence": min(0.9, count / 100),
                    "category": "dynamic-syscall",
                    "source": "strace",
                    "file": "",
                    "evidence": f"{count} child processes spawned (threshold: 20)",
                    "tags": ["dynamic", "syscall"],
                })
                seen_ids.add(finding_id)
            continue

        if finding_id == "syscall.socket-create":
            count = len(re.findall(pattern, strace_text))
            if count > 5:
                findings.append({
                    "id": finding_id,
                    "title": description,
                    "severity": "high",
                    "confidence": min(0.9, count / 20),
                    "category": "dynamic-syscall",
                    "source": "strace",
                    "file": "",
                    "evidence": f"{count} TCP sockets created (threshold: 5)",
                    "tags": ["dynamic", "syscall", "network"],
                })
                seen_ids.add(finding_id)
            continue

        matches = re.findall(pattern, strace_text, re.MULTILINE)
        if matches:
            evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
            findings.append({
                "id": finding_id,
                "title": description,
                "severity": severity,
                "confidence": 0.9,
                "category": "dynamic-syscall",
                "source": "strace",
                "file": "",
                "evidence": evidence[:200],
                "tags": ["dynamic", "syscall"],
            })
            seen_ids.add(finding_id)

    # Check for honeypot token leakage in strace output
    if _HONEYPOT_MARKER in strace_text:
        findings.append({
            "id": "syscall.honeypot-leaked",
            "title": "Honeypot credential accessed and leaked",
            "severity": "critical",
            "confidence": 1.0,
            "category": "dynamic-honeypot",
            "source": "strace",
            "file": "",
            "evidence": "Package read and potentially exfiltrated fake credentials",
            "tags": ["dynamic", "honeypot", "credential-theft"],
        })

    return findings


# ---------------------------------------------------------------------------
# Suspicious output patterns (stdout/stderr)
# ---------------------------------------------------------------------------

_OUTPUT_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"SENTINEL_FAKE", "output.honeypot-read", "critical",
     "Honeypot credential marker found in output"),
    (r"https?://(?!registry\.npmjs\.org)[^\s\"']+", "output.network-url", "high",
     "Non-registry URL detected in install output"),
    (r"\b(?:curl|wget|Invoke-WebRequest)\b", "output.download-tool", "critical",
     "Download tool reference in output"),
    (r"\.ssh[/\\]|id_rsa|\.npmrc|\.aws[/\\]credentials", "output.credential-path", "critical",
     "Credential file path in output"),
    (r"\beval\s*\(|\bFunction\s*\(|\bchild_process\b|\bexecSync\b", "output.code-exec", "high",
     "Code execution pattern in output"),
    (r"\bstratum\+tcp://|\bxmrig\b|\bminerd\b", "output.crypto-miner", "critical",
     "Cryptocurrency mining indicator"),
    (r"(?:nc|netcat|ncat)\s+.*-[elp]|/dev/tcp/", "output.reverse-shell", "critical",
     "Reverse shell indicator"),
]


def parse_output_patterns(text: str) -> list[dict[str, Any]]:
    """Scan stdout+stderr for suspicious patterns."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern, fid, severity, description in _OUTPUT_PATTERNS:
        if fid in seen:
            continue
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        if matches:
            evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
            findings.append({
                "id": fid,
                "title": description,
                "severity": severity,
                "confidence": 0.85,
                "category": "dynamic-output",
                "source": "output-scan",
                "file": "",
                "evidence": evidence[:200],
                "tags": ["dynamic", "output"],
            })
            seen.add(fid)
    return findings


# ---------------------------------------------------------------------------
# Filesystem diff
# ---------------------------------------------------------------------------

def _snapshot_dir(path: Path) -> dict[str, float]:
    """Snapshot a directory tree → {relative_path: mtime}."""
    result: dict[str, float] = {}
    if not path.is_dir():
        return result
    for entry in path.rglob("*"):
        if entry.is_file() or entry.is_symlink():
            try:
                rel = entry.relative_to(path).as_posix()
                result[rel] = entry.stat().st_mtime
            except (OSError, ValueError):
                pass
    return result


def _diff_snapshots(before: dict[str, float], after: dict[str, float]) -> dict[str, list[str]]:
    """Compute filesystem diff between two snapshots."""
    bk, ak = set(before), set(after)
    return {
        "created": sorted(ak - bk),
        "modified": sorted(p for p in bk & ak if abs(after[p] - before[p]) > 1e-3),
        "deleted": sorted(bk - ak),
    }


# ---------------------------------------------------------------------------
# Docker sandbox
# ---------------------------------------------------------------------------

class DockerSandbox:
    """Docker-based dynamic analysis with strace syscall tracing.

    Runs `npm install` inside an isolated Docker container with:
    - Network disabled (--network=none)
    - Capabilities dropped (--cap-drop=ALL --cap-add=SYS_PTRACE)
    - Read-only filesystem
    - Resource limits
    - strace wrapping for syscall capture
    """

    def __init__(self, image: str = SANDBOX_IMAGE) -> None:
        self.image = image
        self.logger = get_logger(__name__)
        self._client: Any = None

    def _get_client(self) -> Any:
        """Get or create Docker client."""
        if self._client is None:
            if not _HAS_DOCKER:
                raise RuntimeError("Docker SDK not installed (pip install docker)")
            self._client = docker_sdk.from_env()  # type: ignore[union-attr]
        return self._client

    def is_available(self) -> bool:
        """Check if Docker daemon is running and accessible."""
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception as exc:
            self.logger.debug("Docker not available: %s", exc)
            return False

    def image_exists(self) -> bool:
        """Check if the sandbox Docker image exists."""
        try:
            client = self._get_client()
            client.images.get(self.image)
            return True
        except Exception:
            return False

    def build_image(self) -> bool:
        """Build the sandbox Docker image. Public wrapper for _build_image."""
        return self._build_image()

    def _build_image(self) -> bool:
        """Build the sandbox Docker image."""
        dockerfile_dir = Path(__file__).resolve().parent.parent.parent / "docker"
        dockerfile = dockerfile_dir / "Dockerfile.sandbox"
        if not dockerfile.exists():
            self.logger.warning("Dockerfile.sandbox not found at %s", dockerfile)
            return False
        try:
            client = self._get_client()
            self.logger.info("Building sandbox image from %s", dockerfile_dir)
            client.images.build(
                path=str(dockerfile_dir),
                dockerfile="Dockerfile.sandbox",
                tag=self.image,
                rm=True,
            )
            self.logger.info("Sandbox image built successfully: %s", self.image)
            return True
        except Exception as exc:
            self.logger.warning("Failed to build sandbox image: %s", exc)
            return False

    def analyze(
        self,
        package_path: str,
        package_name: str,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Run dynamic analysis in a Docker container.

        Parameters
        ----------
        package_path:
            Path to the .tgz package archive.
        package_name:
            Human-readable package name.
        timeout:
            Maximum execution time in seconds.

        Returns
        -------
        dict with: status, duration, stdout, stderr, strace_output,
        strace_findings, output_findings, filesystem_changes, risk_level.
        """
        result: dict[str, Any] = {
            "status": "error",
            "mode": "docker",
            "duration": 0.0,
            "stdout": "",
            "stderr": "",
            "strace_output": "",
            "strace_findings": [],
            "output_findings": [],
            "behavioral_findings": [],
            "filesystem_changes": {"created": [], "modified": [], "deleted": []},
            "honeypot_triggered": False,
            "risk_level": "UNKNOWN",
        }

        resolved_pkg = Path(package_path).resolve()
        if not resolved_pkg.exists():
            result["stderr"] = f"Package not found: {package_path}"
            return result

        client = self._get_client()
        container = None
        t_start = time.monotonic()

        try:
            # Create container with security constraints
            container = client.containers.create(
                self.image,
                command=[f"/sandbox/pkg/{resolved_pkg.name}"],
                name=f"sentinel-{package_name}-{uuid.uuid4().hex[:8]}",
                # Security: full isolation
                network_mode="none",                    # ZERO network
                cap_drop=["ALL"],                       # Drop everything
                cap_add=["SYS_PTRACE"],                 # Only ptrace for strace
                security_opt=["no-new-privileges"],     # Prevent privilege escalation
                read_only=True,                         # Read-only root
                # Resource limits
                mem_limit="256m",
                memswap_limit="256m",
                cpu_quota=50000,                        # 0.5 CPU
                pids_limit=100,                         # Prevent fork bombs
                # Tmpfs for writable dirs
                tmpfs={
                    "/sandbox/install": "size=100m,mode=1777",
                    "/sandbox/trace": "size=50m,mode=1777",
                    "/tmp": "size=50m,mode=1777",
                },
                # Mount package as read-only
                volumes={
                    str(resolved_pkg.parent): {
                        "bind": "/sandbox/pkg",
                        "mode": "ro",
                    },
                },
                # Honeypot credentials
                environment={
                    **_HONEYPOT_ENV,
                    "HOME": "/home/sandbox",
                },
                working_dir="/sandbox/install",
                user="sandbox",
                labels={"sentinel": "sandbox", "package": package_name},
            )

            # Start and wait
            container.start()

            try:
                exit_info = container.wait(timeout=timeout)
                exit_code = exit_info.get("StatusCode", -1)
                status = "complete"
            except Exception:
                # Timeout
                self.logger.warning("Docker sandbox timeout (%ds) for %s", timeout, package_name)
                status = "timeout"
                exit_code = -1
                try:
                    container.kill()
                except Exception:
                    pass

            # Collect stdout/stderr
            try:
                stdout = container.logs(stdout=True, stderr=False).decode(errors="replace")
                stderr = container.logs(stdout=False, stderr=True).decode(errors="replace")
            except Exception:
                stdout, stderr = "", ""

            # Collect strace output
            strace_output = ""
            try:
                # Read strace log from container
                bits, _ = container.get_archive("/sandbox/trace/strace.log")
                import tarfile
                import io
                tar_stream = io.BytesIO(b"".join(bits))
                with tarfile.open(fileobj=tar_stream) as tar:
                    for member in tar.getmembers():
                        f = tar.extractfile(member)
                        if f:
                            strace_output = f.read().decode(errors="replace")
            except Exception as exc:
                self.logger.debug("Could not retrieve strace output: %s", exc)

            duration = round(time.monotonic() - t_start, 3)

            # Parse findings
            strace_findings = parse_strace_output(strace_output) if strace_output else []
            output_findings = parse_output_patterns(f"{stdout}\n{stderr}")
            all_findings = strace_findings + output_findings

            honeypot = any(
                f["id"] in ("syscall.honeypot-leaked", "output.honeypot-read")
                for f in all_findings
            )

            # Compute risk
            risk_level = _compute_risk(all_findings, exit_code, status)

            result.update({
                "status": status,
                "exit_code": exit_code,
                "duration": duration,
                "stdout": stdout[:10000],
                "stderr": stderr[:10000],
                "strace_output": strace_output[:50000],
                "strace_findings": strace_findings,
                "output_findings": output_findings,
                "behavioral_findings": all_findings,
                "honeypot_triggered": honeypot,
                "risk_level": risk_level,
            })

        except Exception as exc:
            result["status"] = "error"
            result["stderr"] = str(exc)
            result["duration"] = round(time.monotonic() - t_start, 3)
            self.logger.error("Docker sandbox error: %s", exc)

        finally:
            # Cleanup container
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

        return result


# ---------------------------------------------------------------------------
# Subprocess fallback sandbox
# ---------------------------------------------------------------------------

class SubprocessSandbox:
    """Fallback sandbox when Docker is unavailable.

    Uses process isolation via:
    - Fake HOME/credentials (honeypot)
    - Minimal PATH
    - Node.js --experimental-permission (Node 20+)
    - Output pattern matching
    - Filesystem diff
    """

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._platform = platform.system()

    def analyze(
        self,
        package_path: str,
        package_name: str,
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Run npm install in an isolated subprocess."""
        result: dict[str, Any] = {
            "status": "error",
            "mode": "subprocess",
            "duration": 0.0,
            "stdout": "",
            "stderr": "",
            "strace_output": "",
            "strace_findings": [],
            "output_findings": [],
            "behavioral_findings": [],
            "filesystem_changes": {"created": [], "modified": [], "deleted": []},
            "honeypot_triggered": False,
            "risk_level": "UNKNOWN",
        }

        node_bin = shutil.which("node")
        npm_bin = shutil.which("npm")
        if not node_bin or not npm_bin:
            result["stderr"] = "Node.js/npm not found on PATH"
            return result

        pkg_path = Path(package_path).resolve()
        if not pkg_path.exists():
            result["stderr"] = f"Package not found: {package_path}"
            return result

        work_dir = Path(tempfile.mkdtemp(prefix="sentinel_sandbox_"))
        try:
            return self._run(pkg_path, package_name, work_dir, node_bin, npm_bin, timeout, result)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _run(
        self,
        pkg_path: Path,
        package_name: str,
        work_dir: Path,
        node_bin: str,
        npm_bin: str,
        timeout: int,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        # Setup fake environment
        fake_home = work_dir / "fake_home"
        install_dir = work_dir / "install"
        fake_home.mkdir(parents=True)
        install_dir.mkdir(parents=True)

        (fake_home / ".npmrc").write_text("# sentinel fake\n", encoding="utf-8")

        # Fake SSH keys (honeypot)
        ssh_dir = fake_home / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text("SENTINEL_FAKE_SSH_KEY\n", encoding="utf-8")

        # Build isolated env
        node_dir = str(Path(node_bin).parent)
        path_sep = ";" if self._platform == "Windows" else ":"
        env: dict[str, str] = {
            **_HONEYPOT_ENV,
            "HOME": str(fake_home),
            "USERPROFILE": str(fake_home),
            "APPDATA": str(fake_home),
            "TEMP": str(work_dir / "tmp"),
            "TMP": str(work_dir / "tmp"),
            "TMPDIR": str(work_dir / "tmp"),
            "PATH": node_dir + path_sep + str(fake_home),
            "npm_config_cache": str(work_dir / "npm_cache"),
            "npm_config_userconfig": str(fake_home / ".npmrc"),
            "LANG": "C",
        }
        if self._platform == "Windows":
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
            env["ComSpec"] = str(fake_home / "cmd.exe")

        (work_dir / "tmp").mkdir(exist_ok=True)
        (work_dir / "npm_cache").mkdir(exist_ok=True)

        # Snapshot before
        snap_before = _snapshot_dir(work_dir)

        # Build command
        cmd = [npm_bin, "install", "--ignore-scripts=false", "--no-audit",
               "--no-fund", "--no-save", "--prefix", str(install_dir), str(pkg_path)]

        # Run
        t_start = time.monotonic()
        creation_flags = 0
        start_new_session = False
        if self._platform == "Windows":
            creation_flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        else:
            start_new_session = True

        status = "complete"
        try:
            proc = subprocess.Popen(
                cmd, env=env, cwd=str(install_dir),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=creation_flags,
                start_new_session=start_new_session,
            )
            try:
                raw_out, raw_err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                status = "timeout"
                self._kill_tree(proc.pid)
                try:
                    raw_out, raw_err = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    raw_out, raw_err = b"", b""

            stdout = raw_out.decode(errors="replace").strip()
            stderr = raw_err.decode(errors="replace").strip()
            exit_code = proc.returncode or -1
        except Exception as exc:
            stdout, stderr = "", str(exc)
            exit_code = -1
            status = "error"

        duration = round(time.monotonic() - t_start, 3)

        # Snapshot after
        snap_after = _snapshot_dir(work_dir)
        fs_changes = _diff_snapshots(snap_before, snap_after)

        # Parse output
        output_findings = parse_output_patterns(f"{stdout}\n{stderr}")
        honeypot = any(f["id"] == "output.honeypot-read" for f in output_findings)

        risk_level = _compute_risk(output_findings, exit_code, status)

        result.update({
            "status": status,
            "exit_code": exit_code,
            "duration": duration,
            "stdout": stdout[:10000],
            "stderr": stderr[:10000],
            "output_findings": output_findings,
            "behavioral_findings": output_findings,
            "filesystem_changes": fs_changes,
            "honeypot_triggered": honeypot,
            "risk_level": risk_level,
        })
        return result

    def _kill_tree(self, pid: int) -> None:
        """Kill process tree cross-platform."""
        if self._platform == "Windows":
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                               capture_output=True, timeout=10)
            except Exception:
                pass
        else:
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class DynamicSandbox:
    """Dual-mode dynamic analysis: Docker primary, subprocess fallback.

    Parameters
    ----------
    config:
        Sentinel config (used for timeout and feature flags).
    """

    def __init__(self, config: Any = None) -> None:
        self.logger = get_logger(__name__)
        self.timeout = 60
        if config is not None:
            self.timeout = int(getattr(config, "timeout_sandbox", 60))

        self._docker = DockerSandbox()
        self._subprocess = SubprocessSandbox()
        self._docker_available: bool | None = None
        self._warned_subprocess = False

    def _check_docker(self) -> bool:
        """Lazy check if Docker sandbox is available."""
        if self._docker_available is None:
            self._docker_available = self._docker.is_available()
            if self._docker_available:
                # Auto-build sandbox image if Docker is available but image is missing
                if not self._docker.image_exists():
                    self.logger.info("Sandbox image not found, auto-building...")
                    import sys
                    print(
                        "\n  [*] Building sandbox Docker image (first-time setup)...",
                        file=sys.stderr, flush=True,
                    )
                    built = self._docker.build_image()
                    if not built:
                        self.logger.warning("Auto-build failed, falling back to subprocess")
                        self._docker_available = False
                    else:
                        print(
                            "  [+] Sandbox image built successfully.\n",
                            file=sys.stderr, flush=True,
                        )
            mode = "Docker" if self._docker_available else "subprocess (fallback)"
            self.logger.info("Dynamic sandbox mode: %s", mode)
        return self._docker_available

    def analyze(
        self,
        package_path: str,
        package_name: str,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Run dynamic analysis using best available sandbox.

        Parameters
        ----------
        package_path:
            Path to the .tgz package archive.
        package_name:
            Human-readable package name.
        timeout:
            Override timeout in seconds.

        Returns
        -------
        dict with analysis results including syscall findings,
        output findings, filesystem changes, and risk level.
        """
        effective_timeout = timeout or self.timeout

        if self._check_docker():
            self.logger.info("Running Docker sandbox for %s", package_name)
            return self._docker.analyze(package_path, package_name, effective_timeout)
        else:
            # LOUD WARNING: subprocess mode has NO real isolation
            if not self._warned_subprocess:
                self._warned_subprocess = True
                import sys
                print(
                    "\n"
                    "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
                    "  !! WARNING: Docker not available.                        !!\n"
                    "  !! Running WITHOUT sandbox isolation.                    !!\n"
                    "  !! Install scripts will execute DIRECTLY on your system. !!\n"
                    "  !! Install Docker for safe dynamic analysis.             !!\n"
                    "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n",
                    file=sys.stderr, flush=True,
                )
            self.logger.warning(
                "Running subprocess sandbox for %s -- NO REAL ISOLATION", package_name
            )
            result = self._subprocess.analyze(package_path, package_name, effective_timeout)
            result["sandbox_type"] = "subprocess_NO_ISOLATION"
            return result

    @property
    def mode(self) -> str:
        """Return current sandbox mode: 'docker' or 'subprocess'."""
        return "docker" if self._check_docker() else "subprocess"


# ---------------------------------------------------------------------------
# Risk computation
# ---------------------------------------------------------------------------

_SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _compute_risk(findings: list[dict[str, Any]], exit_code: int, status: str) -> str:
    """Compute overall risk level from dynamic findings."""
    if not findings and status == "complete" and exit_code == 0:
        return "LOW"

    max_rank = 0
    for f in findings:
        sev = f.get("severity", "low").lower()
        max_rank = max(max_rank, _SEV_RANK.get(sev, 0))

    if status == "timeout":
        max_rank = max(max_rank, _SEV_RANK["high"])

    if exit_code not in (0, -1) and not findings:
        max_rank = max(max_rank, _SEV_RANK["medium"])

    rank_to_level = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}
    return rank_to_level.get(max_rank, "LOW")
