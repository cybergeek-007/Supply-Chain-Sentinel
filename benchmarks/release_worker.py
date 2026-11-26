"""Fresh predeclared evaluation, restricted to the isolated benchmark runtime."""

from __future__ import annotations
import argparse
import hashlib
import json
import random
from pathlib import Path
import worker
from supply_chain_sentinel.adapters.npm import NpmAdapter
from supply_chain_sentinel.config import Config


def fetch() -> None:
    plan = json.loads(Path("/opt/benchmarks/release-plan.json").read_text())
    config = Config(cache_dir=worker.ROOT / "cache", timeout=30)
    records = []
    for spec in plan["benign"]:
        try:
            artifact = NpmAdapter(config).acquire(spec)
            records.append({"cohort": "benign", "spec": spec, "sha256": artifact.sha256})
        except Exception as exc:
            records.append({"cohort": "benign", "spec": spec, "error": str(exc)})
    commit = plan["dataset_commit"]
    tree = json.loads(worker.get(f"https://api.github.com/repos/{worker.REPO}/git/trees/{commit}"))
    for part in ("samples", "npm"):
        sha = next(row["sha"] for row in tree["tree"] if row["path"] == part)
        tree = json.loads(worker.get(f"https://api.github.com/repos/{worker.REPO}/git/trees/{sha}"))
    rng = random.Random(plan["seed"])
    seen = set(plan["excluded_package_directories"])
    (worker.ROOT / "samples").mkdir(exist_ok=True)
    for category, count in plan["counts"].items():
        sha = next(row["sha"] for row in tree["tree"] if row["path"] == category)
        group = json.loads(
            worker.get(f"https://api.github.com/repos/{worker.REPO}/git/trees/{sha}")
        )
        packages = sorted(
            [row for row in group["tree"] if row["type"] == "tree" and row["path"] not in seen],
            key=lambda row: row["path"],
        )
        rng.shuffle(packages)
        for package in packages[:count]:
            seen.add(package["path"])
            path = f"{category}/{package['path']}"
            try:
                sub = json.loads(
                    worker.get(
                        f"https://api.github.com/repos/{worker.REPO}/git/trees/{package['sha']}?recursive=1"
                    )
                )
                if sub.get("truncated"):
                    raise ValueError("Truncated package subtree")
                choices = sorted(
                    row["path"]
                    for row in sub["tree"]
                    if row["path"].endswith(".zip") and row.get("size", 0) <= 25 * 1024 * 1024
                )
                if not choices:
                    raise ValueError("No eligible ZIP; no replacement")
                path += "/" + rng.choice(choices)
                url = f"https://raw.githubusercontent.com/{worker.REPO}/{commit}/samples/npm/{path}"
                data = worker.get(url, 25 * 1024 * 1024)
                name = hashlib.sha256(path.encode()).hexdigest() + ".zip"
                (worker.ROOT / "samples" / name).write_bytes(data)
                records.append(
                    {
                        "cohort": "malicious",
                        "path": path,
                        "file": name,
                        "url": url,
                        "zip_sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
            except Exception as exc:
                records.append({"cohort": "malicious", "path": path, "error": str(exc)})
    manifest = {"selection_plan": plan, "records": records}
    (worker.ROOT / "manifest.json").write_text(json.dumps(manifest))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("fetch", "evaluate"))
    args = parser.parse_args()
    fetch() if args.command == "fetch" else worker.evaluate()
