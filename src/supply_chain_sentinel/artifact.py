from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .models import PackageArtifact


class ArtifactError(RuntimeError):
    """Raised when package acquisition fails."""


def ensure_workspace(root: Path | None = None) -> Path:
    base = root or (Path.cwd() / "artifacts")
    base.mkdir(parents=True, exist_ok=True)
    return base


def prepare_artifact(package_spec: str, workspace_root: Path, timeout: int) -> tuple[PackageArtifact, Path]:
    staging_dir = Path(tempfile.mkdtemp(prefix="sentinel-", dir=str(workspace_root)))
    tarball_dir = staging_dir / "tarballs"
    extracted_dir = staging_dir / "extracted"
    tarball_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)

    local_candidate = Path(package_spec)
    if local_candidate.exists():
        tarball_path, package_dir, package_json, metadata = _prepare_local_artifact(
            local_candidate,
            tarball_dir,
            extracted_dir,
        )
    else:
        metadata = _run_npm_pack(package_spec, tarball_dir, timeout)
        tarball_name = metadata.get("filename")
        if not tarball_name:
            raise ArtifactError("npm pack did not return a tarball filename")

        tarball_path = tarball_dir / tarball_name
        if not tarball_path.exists():
            raise ArtifactError(f"expected tarball was not created: {tarball_path}")

        with tarfile.open(tarball_path, "r:gz") as archive:
            _safe_extract(archive, extracted_dir)

        package_dir = extracted_dir / "package"
        package_json_path = package_dir / "package.json"
        package_json = {}
        if package_json_path.exists():
            package_json = json.loads(package_json_path.read_text(encoding="utf-8"))

    artifact_sha256 = _sha256_file(tarball_path)

    artifact = PackageArtifact(
        package=package_json.get("name", metadata.get("name", package_spec)),
        version=package_json.get("version", metadata.get("version", "unknown")),
        tarball_path=tarball_path,
        extracted_path=package_dir,
        artifact_sha256=artifact_sha256,
        metadata=metadata | {"staging_dir": str(staging_dir)},
    )
    return artifact, staging_dir


def install_vetted_artifact(artifact: PackageArtifact, install_root: Path, timeout: int) -> dict[str, object]:
    install_root.mkdir(parents=True, exist_ok=True)
    local_runner, local_method = resolve_npm_runner(timeout)
    if local_runner:
        command = [*local_runner, "install", str(artifact.tarball_path), "--ignore-scripts"]
        method = local_method
    elif _docker_is_available(timeout):
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{install_root.resolve()}:/workspace",
            "-v",
            f"{artifact.tarball_path.resolve()}:/workspace/vetted.tgz:ro",
            "-w",
            "/workspace",
            "node:20-bookworm-slim",
            "npm",
            "install",
            "/workspace/vetted.tgz",
            "--ignore-scripts",
        ]
        method = "docker-npm"
    else:
        return {
            "attempted": False,
            "returncode": None,
            "stdout": "",
            "stderr": "Neither a working local npm installation nor Docker was available.",
            "method": "unavailable",
            "install_root": str(install_root.resolve()),
        }
    result = subprocess.run(
        command,
        cwd=install_root,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return {
        "attempted": True,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "method": method,
        "install_root": str(install_root.resolve()),
    }


def resolve_npm_runner(timeout: int) -> tuple[list[str] | None, str]:
    npm_path = shutil.which("npm")
    if npm_path:
        probe = subprocess.run(
            [npm_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if probe.returncode == 0:
            return [npm_path], "local-npm"

    corepack_path = shutil.which("corepack")
    if corepack_path:
        probe = subprocess.run(
            [corepack_path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if probe.returncode == 0:
            return [corepack_path, "npm"], "corepack-npm"

    return None, "unavailable"


def _run_npm_pack(package_spec: str, tarball_dir: Path, timeout: int) -> dict[str, object]:
    local_runner, local_method = resolve_npm_runner(timeout)
    errors: list[str] = []
    if local_runner:
        try:
            return _run_npm_pack_locally(local_runner, local_method, package_spec, tarball_dir, timeout)
        except ArtifactError as exc:
            errors.append(str(exc))

    if _docker_is_available(timeout):
        try:
            return _run_npm_pack_in_docker(package_spec, tarball_dir, timeout)
        except ArtifactError as exc:
            errors.append(str(exc))
    else:
        errors.append("Docker daemon is not available for npm pack fallback")

    raise ArtifactError(" ; ".join(errors))


def _run_npm_pack_locally(
    runner: list[str],
    method: str,
    package_spec: str,
    tarball_dir: Path,
    timeout: int,
) -> dict[str, object]:
    command = [
        *runner,
        "pack",
        package_spec,
        "--json",
        "--pack-destination",
        str(tarball_dir.resolve()),
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
        raise ArtifactError(f"{method} timed out fetching package {package_spec}") from exc

    if result.returncode != 0:
        raise ArtifactError(
            f"{method} pack failed for {package_spec}: {result.stderr.strip() or result.stdout.strip()}"
        )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ArtifactError(f"{method} could not decode npm pack output: {result.stdout}") from exc

    if not payload or not isinstance(payload, list):
        raise ArtifactError(f"{method} returned an unexpected npm pack payload")
    metadata = payload[0]
    metadata["source_type"] = method
    return metadata


def _run_npm_pack_in_docker(package_spec: str, tarball_dir: Path, timeout: int) -> dict[str, object]:
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{tarball_dir.resolve()}:/workspace",
        "-w",
        "/workspace",
        "node:20-bookworm-slim",
        "npm",
        "pack",
        package_spec,
        "--json",
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
        raise ArtifactError(f"timed out fetching package {package_spec}") from exc

    if result.returncode != 0:
        raise ArtifactError(
            f"npm pack failed for {package_spec}: {result.stderr.strip() or result.stdout.strip()}"
        )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ArtifactError(f"could not decode npm pack output: {result.stdout}") from exc

    if not payload or not isinstance(payload, list):
        raise ArtifactError("npm pack returned an unexpected payload")
    metadata = payload[0]
    metadata["source_type"] = "docker-npm"
    return metadata


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _docker_is_available(timeout: int) -> bool:
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return probe.returncode == 0


def _prepare_local_artifact(
    source: Path,
    tarball_dir: Path,
    extracted_dir: Path,
) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    source = source.resolve()
    if source.is_dir():
        package_json_path = source / "package.json"
        if not package_json_path.exists():
            raise ArtifactError(f"local package directory is missing package.json: {source}")
        package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
        package_dir = extracted_dir / "package"
        shutil.copytree(source, package_dir, dirs_exist_ok=True)
        name = str(package_json.get("name", source.name)).replace("/", "-")
        version = str(package_json.get("version", "0.0.0"))
        tarball_path = tarball_dir / f"{name}-{version}.tgz"
        with tarfile.open(tarball_path, "w:gz") as archive:
            archive.add(package_dir, arcname="package")
        return tarball_path, package_dir, package_json, {
            "name": package_json.get("name", source.name),
            "version": version,
            "filename": tarball_path.name,
            "source": str(source),
            "source_type": "local-directory",
        }

    if source.is_file() and source.suffix in {".tgz", ".gz"}:
        tarball_path = tarball_dir / source.name
        shutil.copy2(source, tarball_path)
        with tarfile.open(tarball_path, "r:gz") as archive:
            _safe_extract(archive, extracted_dir)
        package_dir = extracted_dir / "package"
        package_json_path = package_dir / "package.json"
        package_json = {}
        if package_json_path.exists():
            package_json = json.loads(package_json_path.read_text(encoding="utf-8"))
        return tarball_path, package_dir, package_json, {
            "name": package_json.get("name", source.stem),
            "version": package_json.get("version", "unknown"),
            "filename": tarball_path.name,
            "source": str(source),
            "source_type": "local-tarball",
        }

    raise ArtifactError(f"unsupported local package source: {source}")


def _safe_extract(archive: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if destination not in target.parents and target != destination:
            raise ArtifactError(f"unsafe tar entry detected: {member.name}")
    archive.extractall(destination)
