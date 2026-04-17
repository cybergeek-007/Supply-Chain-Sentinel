from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from supply_chain_sentinel.models import PackageArtifact


def repo_tmp_dir() -> Path:
    root = Path(__file__).resolve().parents[1] / "tmp" / "tests"
    root.mkdir(parents=True, exist_ok=True)
    case_dir = root / uuid.uuid4().hex
    case_dir.mkdir(parents=True, exist_ok=True)
    return case_dir


def cleanup(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def create_artifact(case_dir: Path, package_json: dict[str, object], files: dict[str, bytes]) -> PackageArtifact:
    package_dir = case_dir / "package"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "package.json").write_text(json.dumps(package_json), encoding="utf-8")
    for relative, content in files.items():
        path = package_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return PackageArtifact(
        package=str(package_json.get("name", "example")),
        version=str(package_json.get("version", "1.0.0")),
        tarball_path=case_dir / "example.tgz",
        extracted_path=package_dir,
        artifact_sha256="deadbeef",
        metadata={},
    )
