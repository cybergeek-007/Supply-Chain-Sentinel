"""Isolated acquisition/investigation companion; never execute package code."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import worker
from ast_candidate import analyze_candidate
from supply_chain_sentinel.adapters.npm import NpmAdapter
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import RULESET_VERSION, classify
from supply_chain_sentinel.rules import analyze


def fetch_holdout() -> None:
    plan = json.loads(Path("/opt/benchmarks/holdout-plan.json").read_text())
    development = json.loads(Path("/opt/benchmarks/corpus.json").read_text())
    exclude = {
        r["path"].split("/")[1] for r in development["records"] if r["cohort"] == "malicious"
    }
    config = Config(cache_dir=worker.ROOT / "cache", timeout=30)
    specs = [
        s
        for s in Path("/opt/benchmarks/holdout-benign.txt").read_text().splitlines()
        if s and not s.startswith("#")
    ]
    dev_specs = {r["spec"] for r in development["records"] if r["cohort"] == "benign"}
    if set(specs) & dev_specs:
        raise RuntimeError("Benign identities overlap development")

    def benign(spec: str) -> dict[str, object]:
        try:
            result = NpmAdapter(config).acquire(spec)
            return {"cohort": "benign", "spec": spec, "sha256": result.sha256}
        except Exception as exc:
            return {"cohort": "benign", "spec": spec, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=5) as pool:
        records = list(pool.map(benign, specs))
    commit, repo = plan["dataset_commit"], worker.REPO
    tree = json.loads(worker.get(f"https://api.github.com/repos/{repo}/git/trees/{commit}"))
    for component in ("samples", "npm"):
        sha = next(item["sha"] for item in tree["tree"] if item["path"] == component)
        tree = json.loads(worker.get(f"https://api.github.com/repos/{repo}/git/trees/{sha}"))
    rng = random.Random(plan["seed"])
    selected = []
    seen = set(exclude)
    for category in ("compromised_lib", "malicious_intent"):
        category_sha = next(item["sha"] for item in tree["tree"] if item["path"] == category)
        group = json.loads(
            worker.get(f"https://api.github.com/repos/{repo}/git/trees/{category_sha}")
        )
        packages = sorted(
            (item for item in group["tree"] if item["type"] == "tree" and item["path"] not in seen),
            key=lambda item: item["path"],
        )
        rng.shuffle(packages)
        for package in packages[: plan["malicious_selection"][category]]:
            seen.add(package["path"])
            subtree = json.loads(
                worker.get(
                    f"https://api.github.com/repos/{repo}/git/trees/{package['sha']}?recursive=1"
                )
            )
            if subtree.get("truncated"):
                raise RuntimeError("Holdout subtree truncated")
            zips = sorted(
                item["path"]
                for item in subtree["tree"]
                if item["path"].endswith(".zip") and item.get("size", 0) <= 25 * 1024 * 1024
            )
            if not zips:
                records.append(
                    {
                        "cohort": "malicious",
                        "path": f"{category}/{package['path']}",
                        "error": "Selected package has no ZIP within predeclared limit",
                    }
                )
                continue
            selected.append(f"{category}/{package['path']}/{rng.choice(zips)}")
    (worker.ROOT / "samples").mkdir(exist_ok=True)
    for path in selected:
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/samples/npm/{path}"
        filename = hashlib.sha256(path.encode()).hexdigest() + ".zip"
        try:
            data = worker.get(url, 25 * 1024 * 1024)
            (worker.ROOT / "samples" / filename).write_bytes(data)
            records.append(
                {
                    "cohort": "malicious",
                    "path": path,
                    "file": filename,
                    "url": url,
                    "dataset_commit": commit,
                    "zip_sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        except Exception as exc:
            records.append({"cohort": "malicious", "path": path, "error": str(exc)})
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_commit": commit,
        "selection_seed": plan["seed"],
        "partition": "holdout-unopened",
        "selection_note": plan["separation"],
        "records": records,
    }
    (worker.ROOT / "manifest.json").write_text(json.dumps(manifest))
    print(json.dumps(manifest, indent=2), flush=True)


def evaluate_holdout() -> None:
    """One-shot evaluation; run only after candidate code has been frozen."""
    manifest = json.loads((worker.ROOT / "manifest.json").read_text())
    if manifest.get("partition") != "holdout-unopened":
        raise RuntimeError("Unexpected or already modified holdout manifest")
    config = Config(cache_dir=worker.ROOT / "cache")
    results = []
    for record in manifest["records"]:
        if record.get("error"):
            results.append({**record, "status": "acquisition-error"})
            continue
        base = {
            key: record[key]
            for key in ("cohort", "spec", "path", "file", "zip_sha256")
            if key in record
        }
        try:
            artifact = (
                NpmAdapter(config).acquire(record["spec"], offline=True)
                if record["cohort"] == "benign"
                else worker.read_sample(worker.ROOT / "samples" / record["file"], config)
            )
            baseline_start = time.perf_counter()
            baseline_findings = analyze(artifact, config)
            baseline_ms = round((time.perf_counter() - baseline_start) * 1000, 3)
            candidate_start = time.perf_counter()
            baseline_score, baseline_verdict = classify(baseline_findings)
            try:
                candidate_findings = baseline_findings + analyze_candidate(artifact)
                candidate_ms = round((time.perf_counter() - candidate_start) * 1000, 3)
                candidate_score, candidate_verdict = classify(candidate_findings)
                candidate = {
                    "status": "complete",
                    "score": candidate_score,
                    "verdict": candidate_verdict,
                    "rules": sorted({item.rule_id for item in candidate_findings}),
                    "scan_ms": candidate_ms,
                }
            except Exception as exc:
                candidate = {
                    "status": "analysis-error",
                    "error": str(exc),
                    "scan_ms": round((time.perf_counter() - candidate_start) * 1000, 3),
                }
            results.append(
                {
                    **base,
                    "package": artifact.name,
                    "version": artifact.version,
                    "sha256": artifact.sha256,
                    "status": "complete",
                    "baseline": {
                        "score": baseline_score,
                        "verdict": baseline_verdict,
                        "rules": sorted({item.rule_id for item in baseline_findings}),
                        "scan_ms": baseline_ms,
                    },
                    "candidate": candidate,
                }
            )
        except Exception as exc:
            results.append({**base, "status": "scan-error", "error": str(exc)})
    output = {
        "manifest": {key: value for key, value in manifest.items() if key != "records"},
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_ruleset": RULESET_VERSION,
        "candidate": "file-local tree-sitter JavaScript taint prototype",
        "results": results,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("fetch-holdout", "evaluate-holdout"))
    args = parser.parse_args()
    if args.command == "fetch-holdout":
        fetch_holdout()
    else:
        evaluate_holdout()
