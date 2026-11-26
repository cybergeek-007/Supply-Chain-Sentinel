"""Small, noninteractive CLI. No install hooks, subprocess fallback, or implicit uploads."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .adapters.npm import atomic_write
from .config import load_config
from .feeds import update_snapshot
from .lockfile import changed_dependencies, parse_lockfile
from .models import ScanError
from .output import render, safe_text
from .scanner import Scanner, exit_code


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Experimental static npm package triage")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument(
        "--config", type=Path, help="Explicit TOML config (no implicit project config)"
    )
    root.add_argument("--cache-dir", type=Path)
    root.add_argument("--verbose", action="store_true")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "scan-lockfile"):
        scan = commands.add_parser(name)
        scan.add_argument("target", help="Exact npm spec, .tgz, directory, or lockfile")
        scan.add_argument("--offline", action="store_true")
        scan.add_argument(
            "--identity-only", action="store_true", help="Advisory lookup; no source download"
        )
        scan.add_argument("--require-advisories", action="store_true")
        scan.add_argument("--format", choices=("text", "json", "sarif"), default="text")
        scan.add_argument("--output", type=Path)
        scan.add_argument("--fail-on", choices=("review", "blocked", "never"), default="review")
        scan.add_argument(
            "--dynamic", action="store_true", help="Unavailable: dynamic execution was removed"
        )
        if name == "scan-lockfile":
            scan.add_argument(
                "--base", type=Path, help="Only scan new/changed identities vs base lockfile"
            )
            scan.add_argument("--concurrency", type=int, default=4)
    update = commands.add_parser(
        "update-rules", help="Refresh OSV data for selected exact identities"
    )
    update.add_argument("--package", action="append", default=[])
    update.add_argument("--lockfile", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stderr)
    try:
        config = load_config(args.config)
        if args.cache_dir:
            config.cache_dir = args.cache_dir.expanduser()
        if args.command == "update-rules":
            specs = args.package + (
                [d.spec for d in parse_lockfile(args.lockfile)] if args.lockfile else []
            )
            if args.lockfile is not None and not specs:
                print(json.dumps({"identities": 0, "message": "Lockfile has no dependencies"}))
                return 0
            snapshot = update_snapshot(config, specs)
            print(
                json.dumps(
                    {
                        "identities": len(snapshot["entries"]),
                        "sha256": snapshot["sha256"],
                        "generated_at": snapshot["generated_at"],
                    }
                )
            )
            return 0
        if args.dynamic:
            raise ScanError(
                "Dynamic execution is unavailable. There is no host execution fallback."
            )
        scanner = Scanner(config)
        locations = {}
        if args.command == "scan-lockfile":
            if not 1 <= args.concurrency <= 16:
                raise ScanError("Concurrency must be between 1 and 16")
            dependencies = parse_lockfile(Path(args.target))
            if args.base:
                dependencies = changed_dependencies(dependencies, parse_lockfile(args.base))
            with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                reports = list(
                    pool.map(
                        lambda dep: scanner.scan(
                            dep.spec,
                            offline=args.offline,
                            integrity=dep.integrity,
                            identity_only=args.identity_only,
                            require_advisories=args.require_advisories,
                        ),
                        dependencies,
                    )
                )
            target = Path(args.target).resolve()
            try:
                uri = target.relative_to(Path.cwd().resolve()).as_posix()
                locations = {d.spec: (uri, d.line) for d in dependencies}
            except ValueError:
                pass
        else:
            reports = [
                scanner.scan(
                    args.target,
                    offline=args.offline,
                    identity_only=args.identity_only,
                    require_advisories=args.require_advisories,
                )
            ]
        content = render(reports, args.format, locations)
        if args.output:
            atomic_write(args.output, (content + "\n").encode())
        else:
            print(content)
        return exit_code(reports, args.fail_on)
    except (ScanError, OSError, ValueError) as exc:
        print(f"sentinel: {safe_text(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
