"""Text, JSON and SARIF 2.1.0 output; untrusted terminal controls are escaped."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from . import __version__
from .models import ScanReport
from .rules import RULES
from .scanner import summary


def safe_text(value: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda m: repr(m.group())[1:-1], value)


def sarif(
    reports: list[ScanReport], locations: dict[str, tuple[str, int]] | None = None
) -> dict[str, Any]:
    identifiers = sorted(RULES)
    results: list[dict[str, Any]] = []
    for report in reports:
        for finding in report.findings:
            result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "ruleIndex": identifiers.index(finding.rule_id),
                "level": {
                    "critical": "error",
                    "high": "warning",
                    "medium": "warning",
                    "low": "note",
                    "info": "note",
                }[finding.severity],
                "message": {"text": f"{report.package}@{report.version}: {finding.message}"},
                "partialFingerprints": {
                    "sentinel/v1": hashlib.sha256(
                        f"{report.package}@{report.version}:{finding.rule_id}:{finding.file}:{finding.line}".encode()
                    ).hexdigest()
                },
                "properties": {"confidence": finding.confidence, "evidence": finding.evidence},
            }
            location = locations.get(f"{report.package}@{report.version}") if locations else None
            if location:
                uri, line = location
                if not PurePosixPath(uri).is_absolute() and ".." not in PurePosixPath(uri).parts:
                    result["locations"] = [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": quote(uri, safe="/"),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {"startLine": line},
                            }
                        }
                    ]
            if finding.suppressed:
                result["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "accepted",
                        "justification": finding.suppression_reason,
                    }
                ]
            results.append(result)
    errors = [error for report in reports for error in report.errors]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Supply Chain Sentinel",
                        "version": __version__,
                        "rules": [
                            {"id": key, "shortDescription": {"text": RULES[key]}}
                            for key in identifiers
                        ],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": e}} for e in errors
                        ],
                    }
                ],
            }
        ],
    }


def render(
    reports: list[ScanReport], format_name: str, locations: dict[str, tuple[str, int]] | None = None
) -> str:
    if format_name == "json":
        return json.dumps(summary(reports), indent=2)
    if format_name == "sarif":
        return json.dumps(sarif(reports, locations), indent=2)
    lines = []
    for report in reports:
        lines.append(
            f"{report.package}@{report.version}: {report.verdict.upper()} "
            f"score={report.score}/100 {report.duration_ms:.1f}ms"
        )
        for finding in report.findings:
            tag = "suppressed" if finding.suppressed else finding.severity
            lines.append(
                f"  [{tag}] {finding.rule_id} {finding.file}:{finding.line} {finding.message}"
            )
        lines.extend(f"  ERROR: {error}" for error in report.errors)
        lines.extend(f"  Note: {warning}" for warning in report.warnings)
    lines.append(
        "Static triage only. CLEAN means no policy-level signal observed; it is not a safety guarantee."
    )
    return "\n".join(safe_text(line) for line in lines)
