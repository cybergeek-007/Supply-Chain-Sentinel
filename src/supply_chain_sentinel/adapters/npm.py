"""Public npm acquisition with exact identity, SRI verification and an offline cache."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..archive import inspect_archive
from ..config import Config
from ..models import Artifact, ScanError

NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")


def split_spec(spec: str, *, exact: bool = False) -> tuple[str, str]:
    position = spec.rfind("@")
    if position > 0 and position == len(spec) - 1:
        raise ScanError("Empty npm version")
    name, version = (spec[:position], spec[position + 1 :]) if position > 0 else (spec, "")
    if not NAME.fullmatch(name) or len(name) > 214:
        raise ScanError("Invalid npm name; URLs, git and local package specs are unsupported")
    if version and not VERSION.fullmatch(version):
        raise ScanError("Use an exact semantic version, not a tag or range")
    if exact and not version:
        raise ScanError("An exact package@version is required")
    return name, version


def validate_url(url: str, host: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != host
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ScanError(f"Only HTTPS resources on {host} are allowed")


class RestrictedRedirect(HTTPRedirectHandler):
    def __init__(self, host: str) -> None:
        self.host = host

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Request | None:
        validate_url(newurl, self.host)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request_bytes(
    url: str, *, host: str, limit: int, timeout: int, payload: dict[str, Any] | None = None
) -> bytes:
    validate_url(url, host)
    request = Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"User-Agent": "SupplyChainSentinel/0.3", "Content-Type": "application/json"},
    )
    try:
        with build_opener(RestrictedRedirect(host)).open(request, timeout=timeout) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ScanError("HTTP response exceeds size limit")
        return bytes(data)
    except (OSError, ValueError) as exc:
        raise ScanError(f"Request failed for {host}: {exc}") from exc


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".sentinel-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def verify_integrity(data: bytes, integrity: str) -> None:
    supported: dict[str, list[str]] = {"sha512": [], "sha384": [], "sha256": [], "sha1": []}
    for token in integrity.split():
        algorithm, separator, expected = token.partition("-")
        if separator and algorithm in supported:
            supported[algorithm].append(expected)
    for algorithm, candidates in supported.items():
        if candidates:
            actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode()
            if not any(hmac.compare_digest(actual, value) for value in candidates):
                raise ScanError("Archive integrity mismatch")
            return
    raise ScanError("Missing or unsupported archive integrity")


class NpmAdapter:
    def __init__(self, config: Config) -> None:
        self.config = config

    def acquire(self, spec: str, *, offline: bool = False, integrity: str = "") -> Artifact:
        name, version = split_spec(spec)
        if offline and not version:
            raise ScanError("Offline registry scans require an exact version")
        cache = self.config.cache_dir / "npm"
        if version:
            key = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()
            index = cache / f"{key}.json"
            if index.exists():
                try:
                    record = json.loads(index.read_bytes())
                    digest = record["sha256"]
                    if not re.fullmatch(r"[a-f0-9]{64}", digest):
                        raise ValueError("Bad digest")
                    archive_path = cache / f"{digest}.tgz"
                    if archive_path.stat().st_size > self.config.max_archive_bytes:
                        raise ScanError("Cached archive exceeds size limit")
                    data = archive_path.read_bytes()
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise ScanError("Cached archive digest mismatch")
                    verify_integrity(data, integrity or record["integrity"])
                    artifact = inspect_archive(data, self.config, "npm cache")
                    self._check_identity(artifact, name, version)
                    return artifact
                except (OSError, KeyError, ValueError, TypeError) as exc:
                    raise ScanError(f"Invalid npm cache: {exc}") from exc
        if offline:
            raise ScanError(f"Offline cache miss: {name}@{version}")
        endpoint = f"https://registry.npmjs.org/{quote(name, safe='@')}/{version or 'latest'}"
        try:
            metadata = json.loads(
                request_bytes(
                    endpoint,
                    host="registry.npmjs.org",
                    limit=10 * 1024 * 1024,
                    timeout=self.config.timeout,
                )
            )
            resolved = metadata["version"]
            split_spec(f"{name}@{resolved}", exact=True)
            if metadata["name"] != name or (version and resolved != version):
                raise ScanError("Registry metadata identity mismatch")
            dist = metadata["dist"]
            url = dist["tarball"]
            sri = dist.get("integrity", "")
            if not sri and dist.get("shasum"):
                sri = "sha1-" + base64.b64encode(bytes.fromhex(dist["shasum"])).decode()
        except (KeyError, TypeError, ValueError) as exc:
            raise ScanError(f"Invalid registry metadata: {exc}") from exc
        data = request_bytes(
            url,
            host="registry.npmjs.org",
            limit=self.config.max_archive_bytes,
            timeout=self.config.timeout,
        )
        verify_integrity(data, sri)
        if integrity:
            verify_integrity(data, integrity)
        artifact = inspect_archive(data, self.config, "npm registry")
        self._check_identity(artifact, name, resolved)
        key = hashlib.sha256(f"{name}@{resolved}".encode()).hexdigest()
        atomic_write(cache / f"{artifact.sha256}.tgz", data)
        atomic_write(
            cache / f"{key}.json",
            json.dumps(
                {"name": name, "version": resolved, "sha256": artifact.sha256, "integrity": sri}
            ).encode(),
        )
        return artifact

    @staticmethod
    def _check_identity(artifact: Artifact, name: str, version: str) -> None:
        if (artifact.name, artifact.version) != (name, version):
            raise ScanError("Archive manifest identity does not match requested package/version")
