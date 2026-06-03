"""
Batch test script — runs Supply Chain Sentinel against a curated list of
legitimate and known-suspicious npm packages, collecting JSON results.

Usage:
    python tests/batch_test.py

Output:
    tests/batch_results.json  — aggregated results for all packages
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure project root is on sys.path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from src.core.python.config import SentinelConfig
from src.core.python.pipeline import AnalysisPipeline

# ── Test packages ──────────────────────────────────────────────────────
# Format: (package_spec, expected_verdict)
#   SAFE      = well-known, universally trusted
#   CAUTION   = small / low-download but legitimate
#   SUSPICIOUS/MALICIOUS = known malicious (already removed from npm)

PACKAGES: list[tuple[str, str]] = [
    # ── SAFE: Popular, well-maintained packages ──
    ("lodash",              "SAFE"),
    ("chalk@5.3.0",         "SAFE"),
    ("express",             "SAFE"),
    ("axios",               "SAFE"),
    ("commander",           "SAFE"),
    ("debug",               "SAFE"),
    ("uuid",                "SAFE"),
    ("minimist",            "SAFE"),
    ("semver",              "SAFE"),
    ("yargs",               "SAFE"),
    ("dotenv",              "SAFE"),
    ("ms",                  "SAFE"),
    ("glob",                "SAFE"),
    ("rimraf",              "SAFE"),
    ("mkdirp",              "SAFE"),

    # ── SAFE: Tiny, minimal packages ──
    ("is-odd",              "SAFE"),
    ("is-number",           "SAFE"),
    ("left-pad",            "SAFE"),
    ("is-even",             "SAFE"),
    ("is-positive",         "SAFE"),

    # ── SAFE: Packages with legitimate network/process usage ──
    ("node-fetch",          "SAFE"),
    ("cross-env",           "SAFE"),
    ("execa",               "SAFE"),
    ("got",                 "SAFE"),
    ("http-proxy",          "SAFE"),
]

def main() -> None:
    config = SentinelConfig.from_sentinel_config()
    pipeline = AnalysisPipeline(config)

    results: list[dict] = []
    passed = 0
    failed = 0
    errors = 0

    print()
    print("=" * 72)
    print("  SUPPLY CHAIN SENTINEL — BATCH TEST")
    print("=" * 72)
    print()

    for pkg_spec, expected in PACKAGES:
        print(f"  [{len(results)+1:02d}/{len(PACKAGES)}] {pkg_spec:<30s} ", end="", flush=True)
        t0 = time.monotonic()
        try:
            result = pipeline.analyze_npm(pkg_spec)
            dt = time.monotonic() - t0
            verdict = result.get("verdict", "UNKNOWN")
            risk_score = result.get("risk_score", -1)
            findings_count = len(result.get("findings", []))

            # Determine pass/fail
            ok = _verdict_acceptable(verdict, expected)
            status = "PASS" if ok else "FAIL"
            if ok:
                passed += 1
            else:
                failed += 1

            # Summarize findings by severity
            sev_counts: dict[str, int] = {}
            for f in result.get("findings", []):
                s = f.get("severity", "unknown")
                sev_counts[s] = sev_counts.get(s, 0) + 1

            print(
                f"-> {verdict:<12s} score={risk_score:3d}  "
                f"findings={findings_count:2d}  "
                f"({_sev_summary(sev_counts)})  "
                f"{dt:.1f}s  [{status}]"
            )

            results.append({
                "package": pkg_spec,
                "expected": expected,
                "actual_verdict": verdict,
                "risk_score": risk_score,
                "findings_count": findings_count,
                "severity_breakdown": sev_counts,
                "analysis_time": round(dt, 2),
                "status": status,
                # Include top findings for tuning
                "top_findings": [
                    {
                        "id": f.get("id"),
                        "title": f.get("title"),
                        "severity": f.get("severity"),
                        "confidence": f.get("confidence"),
                        "file": f.get("file"),
                        "source": f.get("source"),
                    }
                    for f in result.get("findings", [])[:10]
                ],
            })

        except Exception as exc:
            dt = time.monotonic() - t0
            print(f"-> ERROR: {exc!s:.60s}  {dt:.1f}s")
            errors += 1
            results.append({
                "package": pkg_spec,
                "expected": expected,
                "actual_verdict": "ERROR",
                "risk_score": -1,
                "findings_count": 0,
                "severity_breakdown": {},
                "analysis_time": round(dt, 2),
                "status": "ERROR",
                "error": str(exc),
                "top_findings": [],
            })

    # ── Summary ──
    print()
    print("=" * 72)
    total = len(PACKAGES)
    print(f"  RESULTS:  {passed}/{total} passed,  {failed} failed,  {errors} errors")
    print("=" * 72)

    # Show failures
    for r in results:
        if r["status"] == "FAIL":
            print(f"  FAIL: {r['package']}")
            print(f"         expected={r['expected']}, got={r['actual_verdict']} (score={r['risk_score']})")
            for f in r.get("top_findings", [])[:5]:
                print(f"         → [{f['severity']}] {f['title']} ({f['file']})")

    # Save results
    output_path = Path(__file__).resolve().parent / "batch_results.json"
    output_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\n  Results saved to {output_path}\n")


def _verdict_acceptable(actual: str, expected: str) -> bool:
    """Check if actual verdict is acceptable given expected."""
    actual = actual.upper()
    expected = expected.upper()

    if expected == "SAFE":
        # SAFE packages should not be SUSPICIOUS or MALICIOUS
        return actual in ("SAFE", "CAUTION")
    elif expected == "CAUTION":
        return actual in ("SAFE", "CAUTION")
    elif expected == "SUSPICIOUS":
        return actual in ("SUSPICIOUS", "CAUTION", "MALICIOUS")
    elif expected == "MALICIOUS":
        return actual in ("MALICIOUS", "SUSPICIOUS")
    return True


def _sev_summary(counts: dict[str, int]) -> str:
    """Format severity counts into a compact string."""
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        if c:
            parts.append(f"{sev[0].upper()}:{c}")
    return " ".join(parts) or "clean"


if __name__ == "__main__":
    main()
