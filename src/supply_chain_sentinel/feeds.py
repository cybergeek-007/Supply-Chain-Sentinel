"""Explicit, atomic OSV snapshots for exact versions; scans never query OSV implicitly."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .adapters.npm import atomic_write, request_bytes, split_spec
from .config import Config
from .models import Finding, ScanError
from .rules import RULES


def _digest(entries: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def load_snapshot(config: Config) -> dict[str, Any]:
    path = config.cache_dir / "advisories.json"
    if not path.exists():
        return {"entries": {}, "generated_at": None}
    try:
        data = json.loads(path.read_bytes())
        if (
            data["schema_version"] != 1
            or not isinstance(data["entries"], dict)
            or _digest(data["entries"]) != data["sha256"]
        ):
            raise ValueError("Snapshot schema/digest mismatch")
        for spec, item in data["entries"].items():
            split_spec(spec, exact=True)
            if not isinstance(item, dict) or not isinstance(item.get("advisories"), list):
                raise ValueError("Malformed advisory entry")
            datetime.fromisoformat(item["queried_at"])
            for advisory in item["advisories"]:
                if (
                    not isinstance(advisory, dict)
                    or not isinstance(advisory.get("id"), str)
                    or type(advisory.get("malicious")) is not bool
                    or not isinstance(advisory.get("url"), str)
                ):
                    raise ValueError("Malformed advisory record")
        return dict(data)
    except (ValueError, KeyError, TypeError, OSError, AttributeError) as exc:
        raise ScanError(f"Invalid advisory snapshot: {exc}") from exc


def update_snapshot(config: Config, specs: list[str]) -> dict[str, Any]:
    if not specs:
        raise ScanError("Provide --package or --lockfile; updates cover only selected identities")
    existing = load_snapshot(config)
    entries = dict(existing["entries"])
    for spec in dict.fromkeys(specs):
        name, version = split_spec(spec, exact=True)
        advisories: dict[str, Any] = {}
        page = ""
        pages: set[str] = set()
        while True:
            query: dict[str, Any] = {
                "package": {"ecosystem": "npm", "name": name},
                "version": version,
            }
            if page:
                query["page_token"] = page
            try:
                response = json.loads(
                    request_bytes(
                        "https://api.osv.dev/v1/query",
                        host="api.osv.dev",
                        limit=10 * 1024 * 1024,
                        timeout=config.timeout,
                        payload=query,
                    )
                )
                if not isinstance(response, dict):
                    raise ValueError("Response must be an object")
                for advisory in response.get("vulns", []):
                    if advisory.get("withdrawn"):
                        continue
                    identifier = advisory["id"]
                    if not isinstance(identifier, str):
                        raise ValueError("Invalid advisory ID")
                    metadata = advisory.get("database_specific", {})
                    reviewed_malware = metadata.get(
                        "github_reviewed"
                    ) is True and "CWE-506" in metadata.get("cwe_ids", [])
                    advisories[identifier] = {
                        "id": identifier,
                        "modified": advisory.get("modified", ""),
                        "summary": str(advisory.get("summary", ""))[:500],
                        "malicious": identifier.startswith("MAL-") or reviewed_malware,
                        "classification_basis": "MAL report"
                        if identifier.startswith("MAL-")
                        else "reviewed CWE-506"
                        if reviewed_malware
                        else "vulnerability",
                        "url": f"https://osv.dev/vulnerability/{identifier}",
                    }
                page = response.get("next_page_token", "")
                if not page:
                    break
                if page in pages or len(pages) >= 100:
                    raise ValueError("Repeated/excessive pagination")
                pages.add(page)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise ScanError(f"Invalid OSV response: {exc}") from exc
        entries[spec] = {
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "advisories": list(advisories.values()),
        }
    snapshot = {
        "schema_version": 1,
        "source": "https://api.osv.dev/v1/query",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
        "sha256": _digest(entries),
    }
    atomic_write(config.cache_dir / "advisories.json", json.dumps(snapshot, indent=2).encode())
    return snapshot


def lookup(
    snapshot: dict[str, Any], config: Config, name: str, version: str
) -> tuple[list[Finding], dict[str, Any]]:
    entry = snapshot["entries"].get(f"{name}@{version}")
    if entry is None:
        return [], {"advisories": "not-queried", "advisory_stale": True}
    queried = datetime.fromisoformat(entry["queried_at"])
    if queried.tzinfo is None:
        raise ScanError("Advisory timestamp must include timezone")
    age = (datetime.now(timezone.utc) - queried).total_seconds() / 86400
    if age < -1:
        raise ScanError("Advisory timestamp is in the future")
    findings = []
    for advisory in entry["advisories"]:
        # MAL is a report namespace, not a calibrated malware ground-truth label.
        rule = "known-malicious" if advisory["malicious"] else "known-vulnerability"
        severity = "critical" if advisory["malicious"] else "medium"
        findings.append(
            Finding(
                rule, severity, 1.0, RULES[rule], evidence=f"{advisory['id']}: {advisory['url']}"
            )
        )
    return findings, {
        "advisories": "queried",
        "advisory_queried_at": entry["queried_at"],
        "advisory_stale": age > config.advisory_max_age_days,
    }
