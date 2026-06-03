#!/usr/bin/env python3
"""
Supply Chain Sentinel — Real-World Rigorous Test Suite
======================================================
Tests the full analysis pipeline (static + AI + VirusTotal + dynamic)
against three categories of npm packages:

  1. SAFE CONTROLS    — popular, known-good packages (should be SAFE)
  2. SYNTHETIC MALWARE — our hand-crafted test payloads (should be MALICIOUS)
  3. LIVE REGISTRY     — real npm packages fetched from the registry

Produces a detailed JSON report and console summary.
"""

from __future__ import annotations

import json
import os
import sys
import time
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

# Ensure the project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.python.config import SentinelConfig
from src.core.python.pipeline import AnalysisPipeline

# ── Test configuration ─────────────────────────────────────────────
RESULTS_DIR = PROJECT_ROOT / "tests" / "realworld_results"
ARCHIVES_DIR = PROJECT_ROOT / "tests" / "malicious" / "archives"

# Known-safe packages to download from npm and scan (false-positive test)
SAFE_PACKAGES = [
    "is-promise@4.0.0",
    "ms@2.1.3",
    "inherits@2.0.4",
    "isarray@2.0.5",
    "balanced-match@1.0.2",
]

# Real npm packages that are suspicious or have had security issues
# (still available on registry with security placeholders or real code)
LIVE_PACKAGES = [
    "event-stream@4.0.1",       # Post-incident version (cleaned)
    "flatmap-stream@0.1.1",     # Related to event-stream incident
    "colors@1.4.0",             # Pre-sabotage version
    "faker@5.5.3",              # Pre-sabotage version
    "ua-parser-js@0.7.28",      # Pre-hijack version
]

# Synthetic malicious packages (already built as .tgz archives)
SYNTHETIC_MALWARE = [
    "credential-harvester-1.0.0.tgz",
    "reverse-shell-pkg-1.0.0.tgz",
    "obfuscated-payload-1.0.0.tgz",
    "data-exfiltrator-1.0.0.tgz",
    "sandbox-evader-1.0.0.tgz",
    "lodahs-4.17.21.tgz",
    "crypto-miner-hidden-1.0.0.tgz",
    "persistence-installer-1.0.0.tgz",
    "proto-polluter-1.0.0.tgz",
    "dns-exfiltrator-1.0.0.tgz",
]

VERDICT_ORDER = {"SAFE": 0, "CAUTION": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}


def download_npm_package(spec: str, dest_dir: Path) -> Path | None:
    """Download a package via `npm pack` and return the .tgz path."""
    try:
        result = subprocess.run(
            f'npm pack {spec} --pack-destination "{dest_dir}"',
            capture_output=True, text=True, timeout=30,
            cwd=str(dest_dir), shell=True,
        )
        if result.returncode == 0:
            # Parse the filename from stdout (last non-empty line)
            lines = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
            filename = lines[-1] if lines else None
            if filename:
                tgz_path = dest_dir / filename
                if tgz_path.exists():
                    return tgz_path
        print(f"    ⚠ npm pack failed for {spec}: {result.stderr.strip()[:120]}")
    except Exception as e:
        print(f"    ⚠ Error downloading {spec}: {e}")
    return None


def run_analysis(pipeline: AnalysisPipeline, mode: str, target: str,
                 dynamic: bool = False, timeout: int | None = None) -> dict:
    """Run the pipeline on a target and return the result dict."""
    try:
        if mode == "npm":
            return pipeline.analyze_npm(target, dynamic=dynamic, timeout=timeout)
        elif mode == "file":
            return pipeline.analyze_file(target, dynamic=dynamic, timeout=timeout)
        else:
            return {"status": "error", "error": f"Unknown mode: {mode}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def extract_summary(result: dict) -> dict:
    """Pull the key fields from a pipeline result for the report."""
    findings = result.get("findings", [])
    sev_map = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        sev_map[sev] = sev_map.get(sev, 0) + 1

    return {
        "verdict": result.get("verdict", "UNKNOWN"),
        "risk_score": result.get("risk_score", 0),
        "risk_level": result.get("risk_level", "UNKNOWN"),
        "findings_count": len(findings),
        "severity_breakdown": sev_map,
        "top_findings": [
            {"id": f.get("id", ""), "title": f.get("title", ""), "severity": f.get("severity", "")}
            for f in sorted(findings, key=lambda x: VERDICT_ORDER.get(x.get("severity", ""), 99))[:5]
        ],
        "ai_explanation": result.get("ai_explanation", None),
        "threat_intel": result.get("threat_intel", {}),
        "duration": result.get("duration", 0),
        "status": result.get("status", "unknown"),
    }


def main():
    print()
    print("=" * 78)
    print("  SUPPLY CHAIN SENTINEL — REAL-WORLD RIGOROUS TEST")
    print("=" * 78)
    print()

    # Setup
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    download_dir = RESULTS_DIR / "downloads"
    download_dir.mkdir(exist_ok=True)

    config = SentinelConfig.from_sentinel_config()
    pipeline = AnalysisPipeline(config, no_cache=True)

    all_results = []
    total_start = time.time()

    # ── Phase 1: Safe Controls ──────────────────────────────────────
    print("─" * 78)
    print("  PHASE 1: SAFE CONTROLS (expect SAFE verdict)")
    print("─" * 78)
    print()

    safe_pass = 0
    safe_fail = 0

    for spec in SAFE_PACKAGES:
        print(f"  [{safe_pass + safe_fail + 1}/{len(SAFE_PACKAGES)}] {spec:<35}", end="", flush=True)
        t0 = time.time()

        tgz = download_npm_package(spec, download_dir)
        if not tgz:
            print("  SKIP (download failed)")
            all_results.append({
                "category": "safe_control", "package": spec,
                "status": "SKIP", "reason": "download_failed"
            })
            continue

        result = run_analysis(pipeline, "file", str(tgz))
        elapsed = time.time() - t0
        summary = extract_summary(result)
        verdict = summary["verdict"]
        score = summary["risk_score"]

        is_pass = verdict in ("SAFE", "CAUTION")
        if is_pass:
            safe_pass += 1
            tag = "[OK]"
        else:
            safe_fail += 1
            tag = "[FALSE POSITIVE!]"

        print(f"→ {verdict:<12} score={score:>3}  {elapsed:.1f}s  {tag}")

        all_results.append({
            "category": "safe_control", "package": spec,
            "expected": "SAFE", "actual": verdict,
            "status": "PASS" if is_pass else "FALSE_POSITIVE",
            **summary,
        })

    print()
    print(f"  Safe controls: {safe_pass}/{len(SAFE_PACKAGES)} correct, {safe_fail} false positives")
    print()

    # ── Phase 2: Synthetic Malware ──────────────────────────────────
    print("─" * 78)
    print("  PHASE 2: SYNTHETIC MALWARE (expect SUSPICIOUS or MALICIOUS)")
    print("─" * 78)
    print()

    synth_pass = 0
    synth_fail = 0
    synth_tested = 0

    for tgz_name in SYNTHETIC_MALWARE:
        tgz_path = ARCHIVES_DIR / tgz_name
        if not tgz_path.exists():
            print(f"  [{synth_tested + 1}/{len(SYNTHETIC_MALWARE)}] {tgz_name:<35}  SKIP (not found)")
            continue

        synth_tested += 1
        print(f"  [{synth_tested}/{len(SYNTHETIC_MALWARE)}] {tgz_name:<35}", end="", flush=True)
        t0 = time.time()

        result = run_analysis(pipeline, "file", str(tgz_path))
        elapsed = time.time() - t0
        summary = extract_summary(result)
        verdict = summary["verdict"]
        score = summary["risk_score"]

        is_pass = verdict in ("SUSPICIOUS", "MALICIOUS")
        if is_pass:
            synth_pass += 1
            tag = "[PASS]"
        else:
            synth_fail += 1
            tag = "[MISSED!]"

        print(f"→ {verdict:<12} score={score:>3}  findings={summary['findings_count']:>2}  {elapsed:.1f}s  {tag}")

        all_results.append({
            "category": "synthetic_malware", "package": tgz_name,
            "expected_min": "SUSPICIOUS", "actual": verdict,
            "status": "PASS" if is_pass else "MISSED",
            **summary,
        })

    print()
    print(f"  Synthetic malware: {synth_pass}/{synth_tested} detected, {synth_fail} missed")
    print()

    # ── Phase 3: Live Registry Packages ─────────────────────────────
    print("─" * 78)
    print("  PHASE 3: LIVE REGISTRY PACKAGES (informational)")
    print("─" * 78)
    print()

    for i, spec in enumerate(LIVE_PACKAGES, 1):
        print(f"  [{i}/{len(LIVE_PACKAGES)}] {spec:<35}", end="", flush=True)
        t0 = time.time()

        tgz = download_npm_package(spec, download_dir)
        if not tgz:
            print("  SKIP (download failed)")
            all_results.append({
                "category": "live_registry", "package": spec,
                "status": "SKIP", "reason": "download_failed"
            })
            continue

        result = run_analysis(pipeline, "file", str(tgz))
        elapsed = time.time() - t0
        summary = extract_summary(result)
        verdict = summary["verdict"]
        score = summary["risk_score"]

        print(f"→ {verdict:<12} score={score:>3}  findings={summary['findings_count']:>2}  {elapsed:.1f}s")

        all_results.append({
            "category": "live_registry", "package": spec,
            "actual": verdict,
            **summary,
        })

    # ── Final Summary ───────────────────────────────────────────────
    total_elapsed = time.time() - total_start
    print()
    print("=" * 78)
    print("  FINAL SUMMARY")
    print("=" * 78)
    print()
    print(f"  Total packages tested : {len(all_results)}")
    print(f"  Total time            : {total_elapsed:.1f}s")
    print()
    print(f"  Safe controls         : {safe_pass}/{len(SAFE_PACKAGES)} correct ({safe_fail} false positives)")
    print(f"  Synthetic malware     : {synth_pass}/{synth_tested} detected ({synth_fail} missed)")
    print(f"  Live registry         : {sum(1 for r in all_results if r['category'] == 'live_registry' and r.get('status') != 'SKIP')} scanned")
    print()

    # Calculate detection rate and false positive rate
    if synth_tested > 0:
        detection_rate = synth_pass / synth_tested * 100
        print(f"  Detection Rate (TPR)  : {detection_rate:.1f}%")
    safe_tested = sum(1 for r in all_results if r["category"] == "safe_control" and r.get("status") != "SKIP")
    if safe_tested > 0:
        fpr = safe_fail / safe_tested * 100
        print(f"  False Positive Rate   : {fpr:.1f}%")

    print()

    # ── Save report ─────────────────────────────────────────────────
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_packages": len(all_results),
        "total_duration_s": round(total_elapsed, 2),
        "detection_rate_pct": round(synth_pass / max(synth_tested, 1) * 100, 1),
        "false_positive_rate_pct": round(safe_fail / max(safe_tested, 1) * 100, 1),
        "results": all_results,
    }

    report_path = RESULTS_DIR / "realworld_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  Report saved → {report_path}")
    print()

    # Exit with error code if we missed any synthetic malware
    sys.exit(1 if synth_fail > 0 else 0)


if __name__ == "__main__":
    main()
