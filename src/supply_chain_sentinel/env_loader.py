from __future__ import annotations

from pathlib import Path


def load_env_files(project_root: Path) -> list[Path]:
    loaded: list[Path] = []
    for candidate in (project_root / ".env", project_root / ".vscode" / ".env"):
        if candidate.exists() and candidate.is_file():
            _load_env_file(candidate)
            loaded.append(candidate)
    return loaded


def _load_env_file(path: Path) -> None:
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        # Import os lazily to keep this module tiny and focused.
        import os

        os.environ.setdefault(key, value)
