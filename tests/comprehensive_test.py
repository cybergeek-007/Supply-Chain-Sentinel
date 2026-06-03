"""
Comprehensive batch test — static + dynamic analysis with all APIs enabled.
Tests 25 packages including edge cases.
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

# Format: (package_spec, expected_verdict, use_dynamic)
PACKAGES: list[tuple[str, str, bool]] = [
    # -- SAFE: Popular, universally trusted --
    ("lodash",              "SAFE",    False),
    ("chalk@5.3.0",         "SAFE",    False),
    ("express",             "SAFE",    False),
    ("axios",               "SAFE",    False),
    ("commander",           "SAFE",    False),
    ("debug",               "SAFE",    False),
    ("uuid",                "SAFE",    False),
    ("dotenv",              "SAFE",    False),
    ("semver",              "SAFE",    False),
    ("yargs",               "SAFE",    False),

    # -- SAFE: Tiny/minimal packages --
    ("is-odd",              "SAFE",    False),
    ("is-number",           "SAFE",    False),
    ("left-pad",            "SAFE",    False),
    ("is-even",             "SAFE",    False),

    # -- SAFE: Packages with legitimate network/process usage --
    ("node-fetch",          "SAFE",    False),
    ("cross-env",           "SAFE",    False),
    ("execa",               "SAFE",    False),
    ("got",                 "SAFE",    False),
    ("http-proxy",          "SAFE",    False),

    # -- SAFE with DYNAMIC: Test sandbox doesn't false-positive --
    ("ms",                  "SAFE",    True),
    ("minimist",            "SAFE",    True),
    ("mkdirp",              "SAFE",    True),
    ("rimraf",              "SAFE",    True),
    ("glob",                "SAFE",    True),
    ("is-positive",         "SAFE",    True),
]

def main() -> None:
    config = SentinelConfig.from_sentinel_config()
    pipeline = AnalysisPipeline(config)

    results: list[dict] = []
    passed = 0
    failed = 0
    errors = 0

    # Check what APIs are available
    api_status = []
    if config.virustotal_api_key:
        api_status.append("VT")
    if config.abuseipdb_api_key:
        api_status.append("AbuseIPDB")
    if config.ai_api_key:
        api_status.append(f"AI({config.ai_provider})")
    api_str = ", ".join(api_status) if api_status else "none"

    print()
    print("=" * 78)
    print("  SUPPLY CHAIN SENTINEL -- COMPREHENSIVE BATCH TEST")
    print(f"  APIs: {api_str}")
    print("=" * 78)
    print()

    for pkg_spec, expected, use_dynamic in PACKAGES:
        idx = len(results) + 1
        mode = "S+D" if use_dynamic else "S  "
        print(f"  [{idx:02d}/{len(PACKAGES)}] [{mode}] {pkg_spec:<28s} ", end="", flush=True)
        t0 = time.monotonic()
        try:
            result = pipeline.analyze_npm(pkg_spec, dynamic=use_dynamic)
            dt = time.monotonic() - t0
            verdict = result.get("verdict", "UNKNOWN")
            risk_score = result.get("risk_score", -1)
            findings_count = len(result.get("findings", []))

            ok = _verdict_acceptable(verdict, expected)
            status = "PASS" if ok else "FAIL"
            if ok:
                passed += 1
            else:
                failed += 1

            sev_counts: dict[str, int] = {}
            for f in result.get("findings", []):
                s = f.get("severity", "unknown")
                sev_counts[s] = sev_counts.get(s, 0) + 1

            # Check which phases ran
            phases = result.get("phases", {})
            phase_flags = []
            if "threat_intel" in phases and phases["threat_intel"].get("reports"):
                phase_flags.append("TI")
            if "dynamic" in phases:
                dyn_status = phases["dynamic"].get("sandbox_type", phases["dynamic"].get("status", "?"))
                phase_flags.append(f"DYN:{dyn_status}")
            if "ai_analysis" in phases:
                phase_flags.append("AI")
            phase_str = " ".join(phase_flags)

            print(
                f"-> {verdict:<12s} score={risk_score:3d}  "
                f"findings={findings_count:2d}  "
                f"({_sev_summary(sev_counts)})  "
                f"{dt:.1f}s  [{status}]"
            )
            if phase_str:
                print(f"         phases: {phase_str}")

            results.append({
                "package": pkg_spec,
                "expected": expected,
                "dynamic": use_dynamic,
                "actual_verdict": verdict,
                "risk_score": risk_score,
                "findings_count": findings_count,
                "severity_breakdown": sev_counts,
                "analysis_time": round(dt, 2),
                "status": status,
                "phases_active": phase_flags,
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
            print(f"-> ERROR: {str(exc)[:60]}  {dt:.1f}s")
            errors += 1
            results.append({
                "package": pkg_spec,
                "expected": expected,
                "dynamic": use_dynamic,
                "actual_verdict": "ERROR",
                "risk_score": -1,
                "findings_count": 0,
                "severity_breakdown": {},
                "analysis_time": round(dt, 2),
                "status": "ERROR",
                "error": str(exc),
                "top_findings": [],
            })

    # Summary
    print()
    print("=" * 78)
    total = len(PACKAGES)
    print(f"  RESULTS:  {passed}/{total} passed,  {failed} failed,  {errors} errors")
    print("=" * 78)

    # Show failures
    for r in results:
        if r["status"] == "FAIL":
            print(f"  FAIL: {r['package']}")
            print(f"         expected={r['expected']}, got={r['actual_verdict']} (score={r['risk_score']})")
            for f in r.get("top_findings", [])[:5]:
                print(f"         -> [{f['severity']}] {f['title']} ({f['file']})")

    # Show errors
    for r in results:
        if r["status"] == "ERROR":
            print(f"  ERROR: {r['package']}: {r.get('error', '?')[:80]}")

    # Save results
    output_path = Path(__file__).resolve().parent / "comprehensive_results.json"
    output_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\n  Results saved to {output_path}\n")


def _verdict_acceptable(actual: str, expected: str) -> bool:
    actual = actual.upper()
    expected = expected.upper()
    if expected == "SAFE":
        return actual in ("SAFE", "CAUTION")
    elif expected == "CAUTION":
        return actual in ("SAFE", "CAUTION")
    elif expected == "SUSPICIOUS":
        return actual in ("SUSPICIOUS", "CAUTION", "MALICIOUS")
    elif expected == "MALICIOUS":
        return actual in ("MALICIOUS", "SUSPICIOUS")
    return True


def _sev_summary(counts: dict[str, int]) -> str:
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        c = counts.get(sev, 0)
        if c:
            parts.append(f"{sev[0].upper()}:{c}")
    return " ".join(parts) or "clean"


if __name__ == "__main__":
    main()
