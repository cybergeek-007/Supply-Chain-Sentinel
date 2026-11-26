from __future__ import annotations

import io
import json
import socket
import tarfile
from pathlib import Path

import pytest

from supply_chain_sentinel.config import Config


def make_archive(files: dict[str, bytes] | None = None) -> bytes:
    files = files or {
        "package.json": b'{"name":"demo","version":"1.0.0"}',
        "index.js": b"module.exports = {};",
    }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo("package/" + name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return stream.getvalue()


@pytest.fixture(autouse=True)
def deny_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*args: object, **kwargs: object) -> None:
        raise AssertionError("Tests may not open network sockets")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(cache_dir=tmp_path / "cache")


@pytest.fixture
def package(tmp_path: Path) -> Path:
    root = tmp_path / "package"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "demo", "version": "1.0.0"}))
    (root / "index.js").write_text("module.exports = {};")
    return root
