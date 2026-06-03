"""Honeypot artifact management for deception-based detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class HoneypotModule:
    """Create and manage honeypot artifacts."""

    def __init__(self, config_path: str = "config/honeypot_config.json"):
        with Path(config_path).open("r", encoding="utf-8") as handle:
            self.config: dict[str, Any] = json.load(handle)

    def create_honeypots(self, target_dir: Path) -> dict[str, Any]:
        created: dict[str, Any] = {"honeypots": [], "total": 0}
        for honeypot_type, honeypot_config in self.config.get("honeypots", {}).items():
            for path_template in honeypot_config["paths"]:
                honeypot_path = target_dir / path_template.lstrip("/")
                honeypot_path.parent.mkdir(parents=True, exist_ok=True)
                honeypot_path.write_text(honeypot_config["content_template"], encoding="utf-8")
                created["honeypots"].append(
                    {
                        "path": str(honeypot_path),
                        "type": honeypot_type,
                        "severity": honeypot_config["severity"],
                    }
                )
                created["total"] += 1
        return created

    def detect_honeypot_access(self, accessed_paths: list[str]) -> list[dict[str, Any]]:
        detections: list[dict[str, Any]] = []
        for path in accessed_paths:
            for honeypot_type, honeypot_config in self.config.get("honeypots", {}).items():
                if any(pattern in path for pattern in honeypot_config["paths"]):
                    detections.append(
                        {
                            "path": path,
                            "type": honeypot_type,
                            "severity": honeypot_config["severity"],
                            "confidence": "high",
                        }
                    )
        return detections
