"""Optional VirusTotal hash lookup support."""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class VirusTotalClient:
    """Look up existing VirusTotal file reports by SHA-256."""

    def __init__(
        self,
        api_key: str | None = None,
        endpoint_template: str = "https://www.virustotal.com/api/v3/files/{file_hash}",
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
        self.endpoint_template = endpoint_template

    def lookup_file_hash(self, file_hash: str) -> dict[str, Any]:
        if not self.api_key:
            return {
                "enabled": False,
                "status": "disabled",
                "message": "VirusTotal API key not configured",
                "permalink": "",
            }

        request = Request(
            self.endpoint_template.format(file_hash=file_hash),
            headers={"Accept": "application/json", "x-apikey": self.api_key},
            method="GET",
        )

        try:
            with urlopen(request, timeout=20) as response:  # nosec B310
                payload = json.load(response)
        except HTTPError as exc:
            if exc.code == 404:
                return {
                    "enabled": True,
                    "status": "not_found",
                    "message": "No VirusTotal report found for this hash",
                    "file_hash": file_hash,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                }
            return {
                "enabled": True,
                "status": "error",
                "message": f"VirusTotal request failed: HTTP {exc.code}",
                "file_hash": file_hash,
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }
        except (URLError, TimeoutError, ValueError, OSError) as exc:
            return {
                "enabled": True,
                "status": "error",
                "message": f"VirusTotal request failed: {exc}",
                "file_hash": file_hash,
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            }

        data = payload.get("data", {})
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        return {
            "enabled": True,
            "status": "ok",
            "message": "VirusTotal report retrieved",
            "file_hash": file_hash,
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            "stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            },
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "popular_threat_classification": attributes.get("popular_threat_classification", {}),
            "meaningful_name": attributes.get("meaningful_name", ""),
            "type_description": attributes.get("type_description", ""),
        }
