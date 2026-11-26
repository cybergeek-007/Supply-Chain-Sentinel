"""Public-record lookup only: no executable samples are acquired or opened."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from supply_chain_sentinel.config import Config
from supply_chain_sentinel.feeds import lookup, update_snapshot
from supply_chain_sentinel.models import classify


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache-dir", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.results.read_text())
    rows = [
        row
        for row in data["results"]
        if row["cohort"] == "malicious" and row["status"] == "complete"
    ]
    config = Config(cache_dir=args.cache_dir, timeout=30)
    snapshot = update_snapshot(config, [f"{r['package']}@{r['version']}" for r in rows])
    output = []
    for row in rows:
        findings, coverage = lookup(snapshot, config, row["package"], row["version"])
        score, verdict = classify(findings)
        output.append(
            {
                "package": row["package"],
                "version": row["version"],
                "source_verdict": row["verdict"],
                "identity_verdict": verdict,
                "identity_score": score,
                "coverage": coverage,
                "advisories": snapshot["entries"][f"{row['package']}@{row['version']}"][
                    "advisories"
                ],
            }
        )
    args.output.write_text(
        json.dumps(
            {
                "source": "https://api.osv.dev/v1/query",
                "generated_at": snapshot["generated_at"],
                "snapshot_sha256": snapshot["sha256"],
                "results": output,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
