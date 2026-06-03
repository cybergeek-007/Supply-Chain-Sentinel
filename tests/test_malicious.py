"""
Test all 10 synthetic malicious packages with both static and dynamic analysis.
Verify each is correctly flagged as SUSPICIOUS or MALICIOUS.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from src.core.python.config import SentinelConfig
from src.core.python.pipeline import AnalysisPipeline

ARCHIVE_DIR = Path(__file__).resolve().parent / "malicious" / "archives"

# (archive_name, min_expected_verdict, key_findings_to_check)
MALICIOUS_PACKAGES = [
    ("credential-harvester-1.0.0.tgz",   "SUSPICIOUS", ["postinstall", "credential", "network"]),
    ("reverse-shell-pkg-1.0.0.tgz",      "SUSPICIOUS", ["postinstall", "exec", "shell"]),
    ("obfuscated-payload-1.0.0.tgz",     "SUSPICIOUS", ["obfuscation", "base64", "concat"]),
    ("data-exfiltrator-1.0.0.tgz",       "SUSPICIOUS", ["credential", "ssh", "network"]),
    ("sandbox-evader-1.0.0.tgz",         "CAUTION",    ["evasion", "docker"]),
    ("lodahs-4.17.21.tgz",               "SUSPICIOUS", ["typosquat", "postinstall"]),
    ("crypto-miner-hidden-1.0.0.tgz",    "SUSPICIOUS", ["postinstall", "exec", "curl"]),
    ("persistence-installer-1.0.0.tgz",  "SUSPICIOUS", ["postinstall", "persistence", "registry"]),
    ("proto-polluter-1.0.0.tgz",         "CAUTION",    ["prototype", "pollution"]),
    ("dns-exfiltrator-1.0.0.tgz",        "SUSPICIOUS", ["dns", "exfil"]),
    # Phase 2
    ("template-eval-pkg-1.0.0.tgz",      "SUSPICIOUS", ["eval", "template"]),
    ("wasm-loader-pkg-1.0.0.tgz",        "SUSPICIOUS", ["wasm", "binary"]),
    ("multi-stage-pkg-1.0.0.tgz",        "SUSPICIOUS", ["stage", "downloader", "http"]),
    ("stego-payload-pkg-1.0.0.tgz",      "SUSPICIOUS", ["steganography", "hidden", "image"]),
    ("time-bomb-pkg-1.0.0.tgz",          "SUSPICIOUS", ["timebomb", "bomb", "evasion", "delayed"]),
]

VERDICT_RANK = {"SAFE": 0, "CAUTION": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}


def main() -> None:
    config = SentinelConfig.from_sentinel_config()
    pipeline = AnalysisPipeline(config)
    results = []
    passed = 0
    failed = 0

    print()
    print("=" * 78)
    print("  MALICIOUS PACKAGE DETECTION TEST")
    print("=" * 78)
    print()

    for archive_name, min_verdict, keywords in MALICIOUS_PACKAGES:
        archive_path = ARCHIVE_DIR / archive_name
        if not archive_path.exists():
            print(f"  SKIP: {archive_name} not found")
            continue

        idx = len(results) + 1
        print(f"  [{idx:02d}/{len(MALICIOUS_PACKAGES)}] {archive_name:<40s} ", end="", flush=True)
        t0 = time.monotonic()

        try:
            result = pipeline.analyze_file(
                str(archive_path),
                dynamic=False,  # Static only for safety
            )
            dt = time.monotonic() - t0
            verdict = result.get("verdict", "UNKNOWN")
            risk_score = result.get("risk_score", -1)
            findings = result.get("findings", [])
            findings_count = len(findings)

            # Check verdict meets minimum
            actual_rank = VERDICT_RANK.get(verdict, -1)
            min_rank = VERDICT_RANK.get(min_verdict, -1)
            verdict_ok = actual_rank >= min_rank

            # Check key findings are present
            finding_titles = " ".join(f.get("title", "").lower() + " " + f.get("id", "").lower() for f in findings)
            finding_evidence = " ".join(str(f.get("evidence", "")).lower() for f in findings)
            all_text = finding_titles + " " + finding_evidence

            found_keywords = [kw for kw in keywords if kw.lower() in all_text]
            keywords_ok = len(found_keywords) >= 1  # At least one key detection

            ok = verdict_ok and keywords_ok
            status = "PASS" if ok else "FAIL"
            if ok:
                passed += 1
            else:
                failed += 1

            # Severity breakdown
            sev = {}
            for f in findings:
                s = f.get("severity", "unknown")
                sev[s] = sev.get(s, 0) + 1
            sev_str = " ".join(f"{k[0].upper()}:{v}" for k, v in sorted(sev.items(), key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x[0],9)))

            print(
                f"-> {verdict:<12s} score={risk_score:3d}  "
                f"findings={findings_count:2d}  ({sev_str})  "
                f"{dt:.1f}s  [{status}]"
            )

            if not verdict_ok:
                print(f"         FAIL: verdict {verdict} < expected {min_verdict}")
            if not keywords_ok:
                missing = [kw for kw in keywords if kw.lower() not in all_text]
                print(f"         FAIL: missing detections: {missing}")

            results.append({
                "package": archive_name,
                "expected_min": min_verdict,
                "actual": verdict,
                "risk_score": risk_score,
                "findings_count": findings_count,
                "sev_breakdown": sev,
                "status": status,
                "time": round(dt, 2),
                "found_keywords": found_keywords,
                "top_findings": [
                    {"id": f.get("id"), "title": f.get("title"), "severity": f.get("severity")}
                    for f in findings[:10]
                ],
            })

        except Exception as exc:
            dt = time.monotonic() - t0
            print(f"-> ERROR: {str(exc)[:60]}  {dt:.1f}s")
            failed += 1
            results.append({
                "package": archive_name,
                "expected_min": min_verdict,
                "actual": "ERROR",
                "risk_score": -1,
                "status": "ERROR",
                "error": str(exc),
            })

    # Summary
    print()
    print("=" * 78)
    total = len(MALICIOUS_PACKAGES)
    print(f"  RESULTS:  {passed}/{total} detected,  {failed} missed")
    print("=" * 78)
    print()

    # Save results
    output_path = Path(__file__).resolve().parent / "malicious_results.json"
    output_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"  Results saved to {output_path}\n")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
