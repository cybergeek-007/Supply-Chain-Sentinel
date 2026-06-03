"""CLI entry point and orchestration pipeline for package analysis."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from src.modules.entropy import ShannonEntropyCalculator
from src.modules.extractor import PackageExtractor
from src.modules.static_analyzer import StaticAnalyzer
from src.modules.virustotal import VirusTotalClient

from .config import SentinelConfig
from .logger import analysis_context, get_logger, setup_logging

try:
    import sentinel_core  # type: ignore[import-not-found]
except ModuleNotFoundError:
    sentinel_core = None


class SentinelOrchestrator:
    """Main orchestration engine for Supply Chain Sentinel."""

    def __init__(self, config: SentinelConfig):
        self.config = config
        setup_logging(getattr(logging, config.log_level, logging.INFO))
        self.logger = get_logger(__name__)
        self.extractor = PackageExtractor(config.staging_dir)
        self.static_analyzer = StaticAnalyzer()
        self.virustotal = VirusTotalClient(api_key=config.virustotal_api_key)

    async def analyze_package(
        self, package_path: str, package_name: str, cleanup: bool = True
    ) -> dict[str, Any]:
        """Execute extraction + entropy analysis pipeline."""
        analysis_result: dict[str, Any] = {
            "status": "pending",
            "package_name": package_name,
            "phases": {},
        }

        extraction = self.extractor.extract_package(package_path, package_name)
        if extraction["status"] != "success":
            return {"status": "failed", "error": extraction["error"], "package_name": package_name}

        analysis_result["phases"]["extraction"] = extraction

        try:
            entropy_analysis = await self._analyze_entropy(
                extraction_path=extraction["data"]["extraction_path"],
                package_name=package_name,
            )
            analysis_result["phases"]["entropy"] = entropy_analysis
            static_analysis = self._analyze_static(extraction["data"]["extraction_path"])
            static_analysis["virustotal"] = self._analyze_virustotal(
                extraction["data"].get("hash_sha256", "")
            )
            analysis_result["phases"]["static"] = static_analysis
            analysis_result["status"] = "success"
            return analysis_result
        finally:
            if cleanup:
                self.extractor.cleanup(package_name)

    async def _analyze_entropy(self, extraction_path: str, package_name: str) -> dict[str, Any]:
        """Analyze entropy for extracted files and flag high-entropy content."""
        entropy_data: dict[str, Any] = {
            "engine": "cpp" if sentinel_core is not None else "python",
            "files": [],
            "high_entropy_files": [],
            "average_entropy": 0.0,
        }

        base_path = Path(extraction_path)
        total_entropy = 0.0
        file_count = 0

        for file_path in base_path.rglob("*"):
            if not file_path.is_file():
                continue
            file_data = file_path.read_bytes()
            entropy = self._calculate_entropy(file_data)
            file_entry = {
                "path": str(file_path.relative_to(base_path)),
                "size": len(file_data),
                "entropy": round(entropy, 2),
                "classification": self._classify_entropy(entropy),
            }
            entropy_data["files"].append(file_entry)
            total_entropy += entropy
            file_count += 1

            if entropy >= self.config.entropy_threshold:
                entropy_data["high_entropy_files"].append(file_entry)
                self.logger.warning(
                    "High entropy detected",
                    extra={
                        "package_name": package_name,
                        "analysis_id": "runtime",
                        "version": "n/a",
                        "file": file_entry["path"],
                        "entropy": entropy,
                    },
                )

        if file_count > 0:
            entropy_data["average_entropy"] = round(total_entropy / file_count, 2)

        return entropy_data

    @staticmethod
    def _classify_entropy(entropy: float) -> str:
        if entropy < 2:
            return "low"
        if entropy < 5:
            return "medium"
        if entropy < 7:
            return "high"
        return "critical"

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if sentinel_core is not None:
            return float(sentinel_core.EntropyCalculator.calculate(data))
        return ShannonEntropyCalculator.calculate(data)

    def _analyze_static(self, extraction_path: str) -> dict[str, Any]:
        return self.static_analyzer.analyze_directory(extraction_path)

    def _analyze_virustotal(self, file_hash: str) -> dict[str, Any]:
        if not file_hash:
            return {
                "enabled": False,
                "status": "unavailable",
                "message": "Package hash unavailable for VirusTotal lookup",
                "permalink": "",
            }
        return self.virustotal.lookup_file_hash(file_hash)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Supply Chain Sentinel")
    parser.add_argument("package", help="Path to npm package .tgz")
    parser.add_argument("--name", required=True, help="Package name")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    parser.add_argument("--analysis-id", default="cli-run", help="Analysis identifier")
    parser.add_argument("--version", default="unknown", help="Package version")
    return parser.parse_args()


async def main() -> int:
    args = _parse_args()
    config = (
        SentinelConfig.from_file(args.config) if args.config else SentinelConfig.from_environment()
    )
    config.log_level = args.log_level

    logger = get_logger(__name__)
    logger.info(
        "Starting package analysis",
        extra=analysis_context(
            analysis_id=args.analysis_id,
            package_name=args.name,
            version=args.version,
        ),
    )

    orchestrator = SentinelOrchestrator(config)
    result = await orchestrator.analyze_package(args.package, args.name)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
