#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def load_scripts(package_dir: Path) -> list[str]:
    package_json = package_dir / "package.json"
    if not package_json.exists():
        return []
    data = json.loads(package_json.read_text(encoding="utf-8"))
    scripts = data.get("scripts", {})
    return [name for name in ("preinstall", "install", "postinstall") if name in scripts]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: runner_entrypoint.py <package_dir> <output_dir>", file=sys.stderr)
        return 2

    package_dir = Path(sys.argv[1]).resolve()
    output_dir = Path(sys.argv[2]).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    home_dir = output_dir / "home"
    ssh_dir = home_dir / ".ssh"
    aws_dir = home_dir / ".aws"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    aws_dir.mkdir(parents=True, exist_ok=True)
    (ssh_dir / "id_rsa").write_text("SENTINEL_FAKE_PRIVATE_KEY", encoding="utf-8")
    (aws_dir / "credentials").write_text(
        "[default]\naws_access_key_id=FAKEKEY\naws_secret_access_key=FAKESECRET\n",
        encoding="utf-8",
    )

    scripts = load_scripts(package_dir)
    if not scripts:
        (output_dir / "events.json").write_text("[]", encoding="utf-8")
        return 0

    events: list[dict[str, object]] = []
    base_env = os.environ.copy()
    base_env["HOME"] = str(home_dir)
    base_env["npm_config_cache"] = str(output_dir / ".npm-cache")
    base_env["npm_config_update_notifier"] = "false"
    base_env["npm_config_fund"] = "false"
    base_env["npm_config_audit"] = "false"
    base_env["CI"] = "true"

    for script_name in scripts:
        trace_path = output_dir / f"{script_name}.strace.log"
        command = [
            "strace",
            "-f",
            "-s",
            "256",
            "-o",
            str(trace_path),
            "npm",
            "run",
            "--if-present",
            script_name,
        ]
        result = subprocess.run(
            command,
            cwd=package_dir,
            env=base_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        events.append(
            {
                "script": script_name,
                "returncode": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
                "trace_file": trace_path.name,
            }
        )
        if result.returncode != 0:
            break

    (output_dir / "events.json").write_text(json.dumps(events, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
