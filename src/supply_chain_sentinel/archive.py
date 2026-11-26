"""Bounded tar reading; never extract archive paths or execute package tools."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import tarfile
from pathlib import Path, PurePosixPath

from .config import Config
from .models import Artifact, ScanError

SOURCE_EXTENSIONS = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".sh", ".json"}


def inspect_archive(data: bytes, config: Config, source: str = "archive") -> Artifact:
    if len(data) > config.max_archive_bytes:
        raise ScanError("Compressed archive exceeds size limit")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    try:
        # Bound decompression before tar parses PAX/long-name metadata into memory.
        limit = config.max_unpacked_bytes + config.max_files * 1024 + 1024 * 1024
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            unpacked = compressed.read(limit + 1)
        if len(unpacked) > limit:
            raise ScanError("Archive exceeds decompression limit")
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
            for index, member in enumerate(archive):
                if index >= config.max_files:
                    raise ScanError("Archive exceeds member limit")
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                    raise ScanError("Unsafe archive path")
                if not (member.isfile() or member.isdir()):
                    raise ScanError("Archive links and special files are forbidden")
                name = str(path)
                if name.startswith("package/"):
                    name = name[8:]
                if member.isdir():
                    continue
                if name in seen:
                    raise ScanError("Duplicate archive path")
                seen.add(name)
                total += member.size
                if total > config.max_unpacked_bytes:
                    raise ScanError("Archive exceeds unpacked size limit")
                if PurePosixPath(name).suffix.lower() not in SOURCE_EXTENSIONS:
                    continue
                if member.size > config.max_source_bytes:
                    raise ScanError(f"Source exceeds per-file limit: {name}")
                handle = archive.extractfile(member)
                if handle is not None:
                    files[name] = handle.read(config.max_source_bytes + 1)
        return artifact_from_files(files, hashlib.sha256(data).hexdigest(), source)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ScanError(f"Invalid gzip tar archive: {exc}") from exc


def inspect_directory(root: Path, config: Config) -> Artifact:
    """Read local source without following links; local manifests are untrusted data."""
    if root.is_symlink():
        raise ScanError("Directory symlinks are forbidden")
    files: dict[str, bytes] = {}
    total = 0
    count = 0
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ScanError("Directory contains a symlink")
        if not path.is_file():
            continue
        count += 1
        if count > config.max_files:
            raise ScanError("Directory exceeds file limit")
        size = path.stat().st_size
        total += size
        if total > config.max_unpacked_bytes:
            raise ScanError("Directory exceeds size limit")
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if size > config.max_source_bytes:
            raise ScanError(f"Source exceeds per-file limit: {path.name}")
        name = path.relative_to(root).as_posix()
        content = path.read_bytes()
        files[name] = content
        digest.update(name.encode() + b"\0" + hashlib.sha256(content).digest())
    return artifact_from_files(files, digest.hexdigest(), "directory (source-tree digest)")


def artifact_from_files(files: dict[str, bytes], digest: str, source: str) -> Artifact:
    try:
        manifest = json.loads(files.get("package.json", b"{}"))
        if not isinstance(manifest, dict):
            raise ValueError("Manifest must be an object")
        name, version = manifest.get("name", "unknown"), manifest.get("version", "unknown")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("Manifest name/version must be strings")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScanError(f"Invalid package.json: {exc}") from exc
    if "package.json" not in files:
        raise ScanError("No root package.json; pass the package directory itself")
    return Artifact(name, version, digest, files, source)
