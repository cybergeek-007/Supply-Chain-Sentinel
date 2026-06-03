"""Manual validation runner for real npm packages against the static analyzer."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from src.core.python.config import SentinelConfig
from src.core.python.orchestrator import SentinelOrchestrator
from src.modules.npm_registry import stage_npm_package_archive


DEFAULT_PACKAGES = [
    "left-pad@1.3.0",
    "chalk@5.3.0",
    "ua-parser-js@0.7.29",
    "eslint-config-prettier@9.1.0",
]


async def _run(package_specs: list[str], staging_dir: Path) -> list[dict[str, object]]:
    config = SentinelConfig(staging_dir=str(staging_dir), entropy_threshold=7.0)
    orchestrator = SentinelOrchestrator(config)
    results: list[dict[str, object]] = []

    for package_spec in package_specs:
        analysis_id = package_spec.replace("/", "_").replace("@", "_")
        resolved_name, archive_path = stage_npm_package_archive(
            package_spec=package_spec,
            staging_dir=staging_dir,
            analysis_id=analysis_id,
            max_size_bytes=int(config.max_package_size),
        )
        try:
            result = await orchestrator.analyze_package(str(archive_path), resolved_name)
            static_phase = result.get("phases", {}).get("static", {})
            results.append(
                {
                    "package": resolved_name,
                    "status": result.get("status"),
                    "risk_level": static_phase.get("risk_level"),
                    "risk_score": static_phase.get("risk_score"),
                    "findings": len(static_phase.get("findings", [])),
                }
            )
        finally:
            archive_path.unlink(missing_ok=True)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate static analysis on live npm packages")
    parser.add_argument("packages", nargs="*", default=DEFAULT_PACKAGES)
    parser.add_argument("--staging-dir", default=".validation_staging")
    args = parser.parse_args()

    results = asyncio.run(_run(args.packages, Path(args.staging_dir)))
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
