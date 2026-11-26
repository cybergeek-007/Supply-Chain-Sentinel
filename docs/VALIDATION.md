# Validation actually performed

Date: 16 November 2026. Local working branch: `oss-static-foundation`, derived from m2. Local checks and configured remote checks are distinguished below.

| Check | Observed result |
| --- | --- |
| Original baseline | 36 pytest passes, one eBPF skip; active fixture had a network error despite complete status |
| Replacement runtime tests | 90 passed on host Python 3.14.8, 91.11% runtime line coverage |
| Ruff lint / format | Passed for src, tests and benchmarks |
| Strict mypy | Passed for all 13 runtime source modules |
| JSON contract | Reports validated against committed `docs/schemas/report-v1.json` |
| SARIF contract | Benign lockfile plus findings/locations/suppression/error examples validated against the public SARIF 2.1.0 JSON schema |
| Live npm | chalk 5.3.0 downloaded without Node/npm; registry SRI and manifest identity checked; full scan completed |
| Offline npm | Exact version scanned from verified cache; offline miss and tamper cases fail in tests |
| Live intelligence | OSV queries for chalk/four incident versions and 36 dataset identities; snapshots retained as metadata |
| Known-malicious early gate | ua-parser-js 0.7.29 and flatmap-stream 0.1.1 blocked from fresh local intelligence without source acquisition |
| Lockfile | Real chalk SRI scanned offline with fresh-coverage policy; SARIF mapped to lockfile; aliases, unsupported sources, diff selection and failure exits tested |
| Action scan shell | Actual composite Action shell block ran locally with real chalk lockfile, refreshed OSV, emitted valid SARIF and exited 0 |
| Untrusted checkout import | Regression test proved isolated Python imports ignore a planted target-repository package |
| Docker isolation | Non-root UID, no egress, read-only root, absent host home, memory/CPU/PID controls observed with harmless probes |
| Real source benchmark | 126 benign candidates, 36 dataset-labeled malicious samples, seven synthetic controls; raw metadata and limitations published |
| Dynamic execution | Not implemented/tested; removed from runtime with explicit CLI error |

Wheel and source distribution built successfully. The wheel installed into a fresh virtual environment using --no-index --no-deps, pip check passed, sentinel --version returned 0.3.0a1, and a real chalk scan completed offline with fresh-advisory policy. This does not prove a PyPI publication or installation on every OS.

## Not verified

- GitHub-hosted workflows, upload-artifact/code-scanning integration and the Linux/macOS/Windows Python 3.11–3.14 matrix have not run here. They are configured, not claimed passing. The Action and branch are not published/pushed.
- No incident sample was detonated, no fake-network dynamic mode exists, and no sandbox-escape proof is claimed. Malicious source was inspected only inside isolated containers.
- No calibrated risk probability, broad zero-FPR guarantee, independent family holdout, full feed mirror, private registry, provenance-signature verifier, PyPI adapter, AI integration or JS taint analysis is claimed.
- Some misses have unresolved payload attribution; one sample has a manifest/path version mismatch. These block a stable security-release claim.

```bash
python -m ruff check src tests benchmarks
python -m ruff format --check src tests benchmarks
python -m mypy
python -m pytest --cov=src/supply_chain_sentinel --cov-fail-under=85
python -m build
python benchmarks/report.py benchmarks/results/final.json
python benchmarks/generate_tables.py
```

Pytest tests prohibit network sockets. Live checks ran separately. The source benchmark uses container Python 3.11; host tests use 3.14. Other configured runtimes remain unverified until hosted CI runs.
