"""Package extraction with tarball safety checks."""

from __future__ import annotations

import hashlib
import shutil
import tarfile
from pathlib import Path
from typing import Any

from src.core.python.exceptions import ExtractionError


class PackageExtractor:
    """Extract and validate npm packages safely."""

    def __init__(self, staging_dir: str = "sentinel_staging") -> None:
        self.staging_dir = Path(staging_dir)
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    def calculate_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate a cryptographic hash for the package archive."""
        hasher = hashlib.new(algorithm)
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def extract_package(self, tgz_path: str, package_name: str) -> dict[str, Any]:
        """Extract a package tarball and return extraction metadata."""
        extraction_path = self.staging_dir / package_name
        extraction_path.mkdir(parents=True, exist_ok=True)

        try:
            archive_path = Path(tgz_path)
            with tarfile.open(archive_path, "r:gz") as tar:
                members = tar.getmembers()
                self._validate_members(members, extraction_path)
                for member in members:
                    tar.extract(member, path=extraction_path)

            extracted_files = self._enumerate_files(extraction_path)
            metadata = {
                "package_name": package_name,
                "extraction_path": str(extraction_path),
                "extracted_files": extracted_files,
                "total_size_bytes": sum(
                    (extraction_path / file_info["path"]).stat().st_size
                    for file_info in extracted_files
                ),
                "hash_sha256": self.calculate_file_hash(archive_path),
                "file_count": len(extracted_files),
            }
            return {"status": "success", "data": metadata}
        except (ExtractionError, OSError, tarfile.TarError, ValueError) as exc:
            self.cleanup(package_name)
            return {"status": "error", "error": str(exc)}

    def _validate_members(self, members: list[tarfile.TarInfo], extraction_path: Path) -> None:
        base_path = extraction_path.resolve()
        for member in members:
            if member.issym() or member.islnk():
                raise ExtractionError(f"Symlinks and hard links are not allowed: {member.name}")

            target = (extraction_path / member.name).resolve()
            if not self._is_within_directory(target, base_path):
                raise ExtractionError(f"Malicious path in tarball: {member.name}")

    def _is_within_directory(self, target: Path, base_path: Path) -> bool:
        try:
            target.relative_to(base_path)
            return True
        except ValueError:
            return False

    def _enumerate_files(self, path: Path, max_files: int = 1000) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        for item in path.rglob("*"):
            if item.is_file():
                files.append(
                    {
                        "path": str(item.relative_to(path)),
                        "size": item.stat().st_size,
                        "extension": item.suffix,
                    }
                )
            if len(files) >= max_files:
                break
        return files

    def cleanup(self, package_name: str) -> None:
        """Remove extracted package from staging."""
        extraction_path = self.staging_dir / package_name
        shutil.rmtree(extraction_path, ignore_errors=True)
