from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from src.modules.extractor import PackageExtractor


@pytest.fixture
def extractor(tmp_path: Path) -> PackageExtractor:
    return PackageExtractor(str(tmp_path / "staging"))


@pytest.fixture
def sample_package(tmp_path: Path) -> str:
    package_dir = tmp_path / "package"
    package_dir.mkdir()

    (package_dir / "package.json").write_text(
        '{"name":"test-pkg","version":"1.0.0"}', encoding="utf-8"
    )
    (package_dir / "index.js").write_text("module.exports = {};", encoding="utf-8")

    tgz_path = tmp_path / "test-pkg-1.0.0.tgz"
    with tarfile.open(tgz_path, "w:gz") as tar:
        tar.add(package_dir, arcname="package")

    return str(tgz_path)


def test_extraction_success(extractor: PackageExtractor, sample_package: str) -> None:
    result = extractor.extract_package(sample_package, "test-pkg")
    assert result["status"] == "success"
    assert result["data"]["package_name"] == "test-pkg"
    assert result["data"]["file_count"] >= 2


def test_path_traversal_detection(extractor: PackageExtractor, tmp_path: Path) -> None:
    tgz_path = tmp_path / "malicious.tgz"
    with tarfile.open(tgz_path, "w:gz") as tar:
        tarinfo = tarfile.TarInfo(name="../../../etc/passwd")
        tarinfo.size = 0
        tar.addfile(tarinfo)

    result = extractor.extract_package(str(tgz_path), "malicious")
    assert result["status"] == "error"
    assert "Malicious path" in result["error"]


def test_cleanup(extractor: PackageExtractor, sample_package: str) -> None:
    extractor.extract_package(sample_package, "test-pkg")
    extractor.cleanup("test-pkg")
    assert not (extractor.staging_dir / "test-pkg").exists()
