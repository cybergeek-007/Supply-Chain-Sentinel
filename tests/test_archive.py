from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from conftest import make_archive
from supply_chain_sentinel.archive import inspect_archive, inspect_directory
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import ScanError


def test_roundtrip(config: Config) -> None:
    result = inspect_archive(make_archive(), config)
    assert (result.name, result.version) == ("demo", "1.0.0")
    assert len(result.sha256) == 64


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("package/link", tarfile.SYMTYPE),
        ("package/link", tarfile.LNKTYPE),
        ("package/device", tarfile.CHRTYPE),
        ("package/pipe", tarfile.FIFOTYPE),
        ("package/..\\escape", tarfile.REGTYPE),
    ],
)
def test_reject_unsafe_members(name: str, kind: bytes, config: Config) -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo(name)
        info.type, info.linkname = kind, "/etc/passwd"
        archive.addfile(info)
    with pytest.raises(ScanError):
        inspect_archive(stream.getvalue(), config)


@pytest.mark.parametrize(
    "setting,value",
    [
        ("max_files", 1),
        ("max_source_bytes", 10),
        ("max_unpacked_bytes", 10),
        ("max_archive_bytes", 10),
    ],
)
def test_resource_limits(setting: str, value: int, config: Config) -> None:
    setattr(config, setting, value)
    with pytest.raises(ScanError):
        inspect_archive(make_archive(), config)


def test_duplicates(config: Config) -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for _ in range(2):
            archive.addfile(tarfile.TarInfo("package/package.json"))
    with pytest.raises(ScanError, match="Duplicate"):
        inspect_archive(stream.getvalue(), config)


@pytest.mark.parametrize(
    "data",
    [
        b"bad",
        b"",
        make_archive({"package.json": b"[]"}),
        make_archive({"index.js": b"x"}),
        make_archive({"package.json": b'{"name":[]}'}),
    ],
)
def test_invalid_archives(data: bytes, config: Config) -> None:
    with pytest.raises(ScanError):
        inspect_archive(data, config)


def test_directory_symlinks(package: Path, config: Config) -> None:
    try:
        (package / "secret.js").symlink_to("/etc/passwd")
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ScanError, match="symlink"):
        inspect_directory(package, config)


def test_directory_content_changes_digest(package: Path, config: Config) -> None:
    old = inspect_directory(package, config)
    (package / "index.js").write_text("changed")
    assert inspect_directory(package, config).sha256 != old.sha256
