from __future__ import annotations

import base64
import hashlib
import json

import pytest

from conftest import make_archive
from supply_chain_sentinel.adapters import npm
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import ScanError


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("react", ("react", "")),
        ("@scope/pkg@1.2.3", ("@scope/pkg", "1.2.3")),
        ("x@1.0.0-beta.1", ("x", "1.0.0-beta.1")),
    ],
)
def test_specs(spec: str, expected: tuple[str, str]) -> None:
    assert npm.split_spec(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "../foo",
        "https://example.com/a",
        "pkg@latest",
        "pkg@^1",
        "pkg@",
        "@scope",
        "a;echo",
        "Pkg",
        "pkg@1.0.0\n",
    ],
)
def test_invalid_specs(spec: str) -> None:
    with pytest.raises(ScanError):
        npm.split_spec(spec)


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.npmjs.org/a",
        "https://localhost/a",
        "https://registry.npmjs.org.evil/a",
        "https://x@registry.npmjs.org/a",
        "https://registry.npmjs.org:444/a",
        "file:///etc/passwd",
    ],
)
def test_ssrf_and_redirect_rejected(url: str) -> None:
    with pytest.raises(ScanError):
        npm.validate_url(url, "registry.npmjs.org")
    with pytest.raises(ScanError):
        npm.RestrictedRedirect("registry.npmjs.org").redirect_request(None, None, 302, "", {}, url)


def test_strongest_integrity_required() -> None:
    weak = "sha1-" + base64.b64encode(hashlib.sha1(b"data").digest()).decode()
    npm.verify_integrity(b"data", weak)
    with pytest.raises(ScanError):
        npm.verify_integrity(b"data", weak + " sha512-invalid")
    with pytest.raises(ScanError):
        npm.verify_integrity(b"data", "")


def test_acquire_offline_and_tamper(config: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    data = make_archive()
    sri = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    calls = []

    def request(url: str, **kwargs: object) -> bytes:
        calls.append(url)
        if url.endswith("/1.0.0"):
            return json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                        "integrity": sri,
                    },
                }
            ).encode()
        return data

    monkeypatch.setattr(npm, "request_bytes", request)
    adapter = npm.NpmAdapter(config)
    online = adapter.acquire("demo@1.0.0")
    assert adapter.acquire("demo@1.0.0", offline=True).sha256 == online.sha256
    assert len(calls) == 2
    with pytest.raises(ScanError, match="integrity"):
        adapter.acquire("demo@1.0.0", offline=True, integrity="sha512-bad")
    blob = next((config.cache_dir / "npm").glob("*.tgz"))
    blob.write_bytes(b"tampered")
    with pytest.raises(ScanError, match="digest"):
        adapter.acquire("demo@1.0.0", offline=True)


def test_offline_miss_does_not_network(config: Config) -> None:
    with pytest.raises(ScanError, match="cache miss"):
        npm.NpmAdapter(config).acquire("demo@1.0.0", offline=True)
    with pytest.raises(ScanError, match="exact"):
        npm.NpmAdapter(config).acquire("demo", offline=True)
