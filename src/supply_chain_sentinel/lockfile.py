"""Exact npm package-lock v2/v3 support; reject sources we cannot faithfully scan."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .adapters.npm import split_spec, validate_url
from .models import ScanError


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    integrity: str
    line: int

    @property
    def spec(self) -> str:
        return f"{self.name}@{self.version}"


def parse_lockfile(path: Path) -> list[Dependency]:
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ScanError("Lockfile exceeds 20 MiB limit")
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("lockfileVersion") not in (2, 3):
            raise ScanError("Only npm package-lock v2/v3 is supported")
        packages = data.get("packages")
        if not isinstance(packages, dict):
            raise ScanError("Lockfile packages must be an object")
        results: dict[tuple[str, str], Dependency] = {}
        for key, info in packages.items():
            if not key:
                continue
            if not isinstance(info, dict) or info.get("link"):
                raise ScanError(f"Workspace/link entry unsupported: {key}")
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = info.get("version", "")
            split_spec(f"{name}@{version}", exact=True)
            resolved = info.get("resolved", "")
            if resolved:
                validate_url(resolved, "registry.npmjs.org")
            integrity = info.get("integrity", "")
            if not isinstance(integrity, str) or not integrity:
                raise ScanError(f"Missing integrity for {name}@{version}")
            line = text.count("\n", 0, text.find(json.dumps(key))) + 1
            dep = Dependency(name, version, integrity, line)
            previous = results.get((name, version))
            if previous and previous.integrity != integrity:
                raise ScanError(f"Conflicting integrity for {dep.spec}")
            results[(name, version)] = dep
        return list(results.values())
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ScanError(f"Invalid lockfile: {exc}") from exc


def changed_dependencies(current: list[Dependency], base: list[Dependency]) -> list[Dependency]:
    previous = {(d.spec, d.integrity) for d in base}
    return [d for d in current if (d.spec, d.integrity) not in previous]
