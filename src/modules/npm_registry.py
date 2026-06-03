"""Helpers for staging npm packages from the public registry."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


def split_package_spec(package_spec: str) -> tuple[str, str | None]:
    """Split npm package spec into (name, version)."""
    normalized = package_spec.strip()
    if not normalized:
        raise ValueError("Package spec is required")

    if normalized.startswith("@"):
        slash_index = normalized.find("/")
        if slash_index < 2:
            raise ValueError(f"Invalid scoped package spec: {package_spec}")
        version_index = normalized.rfind("@")
        if version_index > slash_index:
            version = normalized[version_index + 1 :].strip()
            if not version:
                raise ValueError(f"Invalid package version in spec: {package_spec}")
            return normalized[:version_index], version
        return normalized, None

    if "@" in normalized:
        name, version = normalized.rsplit("@", 1)
        if not name or not version:
            raise ValueError(f"Invalid package spec: {package_spec}")
        return name, version
    return normalized, None


def stage_npm_package_archive(
    package_spec: str,
    staging_dir: Path,
    analysis_id: str,
    max_size_bytes: int,
) -> tuple[str, Path]:
    """Download a package tarball from npm registry into a staging path."""
    package_name, requested_version = split_package_spec(package_spec)
    metadata_url = f"https://registry.npmjs.org/{quote(package_name, safe='@/')}"
    metadata_request = Request(
        metadata_url,
        headers={"Accept": "application/json", "User-Agent": "SupplyChainSentinel/1.0"},
    )

    try:
        with urlopen(metadata_request, timeout=30) as response:  # nosec B310
            package_metadata = json.load(response)
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise ValueError(f"Unable to fetch npm metadata for '{package_name}': {exc}") from exc

    versions = package_metadata.get("versions", {})
    dist_tags = package_metadata.get("dist-tags", {})
    resolved_version = requested_version or dist_tags.get("latest")
    if not resolved_version:
        raise ValueError(f"No version found for package '{package_name}'")

    version_entry = versions.get(resolved_version)
    tarball_url = (version_entry or {}).get("dist", {}).get("tarball")
    if not tarball_url:
        raise ValueError(f"Unable to resolve tarball for '{package_name}@{resolved_version}'")

    # Security: validate tarball URL to prevent SSRF
    if not tarball_url.startswith("https://"):
        raise ValueError(
            f"Refusing to download tarball from non-HTTPS URL: {tarball_url[:100]}"
        )

    staging_dir.mkdir(parents=True, exist_ok=True)
    archive_path = staging_dir / f"{analysis_id}.tgz"
    tarball_request = Request(
        tarball_url,
        headers={"Accept": "application/octet-stream", "User-Agent": "SupplyChainSentinel/1.0"},
    )
    total_bytes = 0

    try:
        with urlopen(tarball_request, timeout=60) as response:  # nosec B310
            with archive_path.open("wb") as handle:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_size_bytes:
                        raise ValueError(
                            f"Package exceeds size limit ({max_size_bytes} bytes): "
                            f"{package_name}@{resolved_version}"
                        )
                    handle.write(chunk)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        archive_path.unlink(missing_ok=True)
        raise ValueError(f"Unable to download npm package '{package_spec}': {exc}") from exc

    return f"{package_name}@{resolved_version}", archive_path
