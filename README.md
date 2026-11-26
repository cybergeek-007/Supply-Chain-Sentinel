# Supply Chain Sentinel

Experimental, local-first static triage for npm packages. Inspect exact package versions and lockfiles without installing or executing the target package. Outputs include source evidence, advisory coverage, JSON, and SARIF.

**Status: alpha (0.3.0a1), not a complete malware detector.** A `clean` result means no policy-level signal was observed. It does not establish that a dependency is safe. Read the [measured benchmark and limitations](docs/BENCHMARK.md) before using the tool as a CI gate.

A review snapshot is published on `release-validation-static-alpha` in [draft PR #1](https://github.com/cybergeek-007/Supply-Chain-Sentinel/pull/1). Local logical implementation history remains on `oss-static-foundation`. This alpha has not been released to PyPI or merged. See the [release validation report](docs/RELEASE_VALIDATION.md).

## Install

Requires Python 3.11+. Node, npm, Docker, C++ and API keys are unnecessary for ordinary scans. Runtime dependencies: Python standard library only.

```bash
git clone https://github.com/cybergeek-007/Supply-Chain-Sentinel.git
cd Supply-Chain-Sentinel
git switch release-validation-static-alpha # published review snapshot
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
sentinel --version
sentinel scan chalk@5.3.0
```

On Windows use `py -3 -m venv .venv` and `.venv\Scripts\Activate.ps1` in PowerShell. Source installation is documented here; this alpha has not been published to PyPI. Build/install needs setuptools from the package index once; installed scanning needs no third-party Python runtime packages.

## Workflows

```bash
# Registry package: exact version recommended; a bare name resolves current latest.
sentinel scan chalk@5.3.0

# Local archive or package directory; no extraction or execution.
sentinel scan ./package.tgz --format json
sentinel scan ./extracted-package --format json --output report.json

# All dev/transitive entries in an npm package-lock v2/v3, before npm ci.
sentinel scan-lockfile package-lock.json --concurrency 4 --format json

# Only additions/version or integrity changes versus a trusted base lockfile.
sentinel scan-lockfile package-lock.json --base /tmp/base-package-lock.json

# Explicitly query public OSV records for selected exact versions.
sentinel update-rules --lockfile package-lock.json
sentinel update-rules --package flatmap-stream@0.1.1

# No registry/archive download: advisory identity lookup only.
sentinel scan flatmap-stream@0.1.1 --identity-only --offline

# Warm offline cache; error if artifact absent or advisories missing/stale.
sentinel scan chalk@5.3.0 --offline --require-advisories

# SARIF maps findings to lockfile lines; no cache-directory source paths.
sentinel scan-lockfile package-lock.json --format sarif --output sentinel.sarif
```

A single-package scan inspects that artifact only. It does not resolve its declared dependencies; the report shows this coverage limit. Use an npm lockfile to inspect the exact dependency entries available in your project.

Offline mode makes no network calls. A prior successful exact-version scan populates the archive cache; `update-rules` populates advisory records independently. `update-rules` refreshes **selected identities**, not a global malware feed or executable rules. Withdrawal is reflected on the next successful refresh of that identity. Code heuristics are versioned with the tool. Advisory lookup without an updated snapshot is explicitly marked `not-queried`/stale; use `--require-advisories` to make this an error.

Exit codes: **0** completed below threshold; **1** review/block findings; **2** scan, config, unsupported-input, or coverage error. `--fail-on blocked` gates only known-malicious findings. `--fail-on never` still fails on errors. JSON goes only to stdout (or the output file), errors to stderr. A no-dependency lockfile produces an empty successful result.

## What is supported

- npm exact versions, public registry integrity verification and identity checks; local gzip tar archives and directories.
- npm package-lock v2/v3 including duplicate versions and aliases with recorded real names. Workspaces, Yarn, pnpm, private registries and git/file dependencies are rejected, not silently omitted.
- Install-script inventory; nearby secret/environment and outbound-capability correlation; encoded execution, explicit fetch-response-to-eval chains, host-identity upload hooks, literal base64 decoding, download-to-shell, reverse-shell patterns; low-confidence typo hints; configured private-name policy.
- Read-only bounded archive inspection, explicit cache, expiring exact suppressions, public advisory snapshots, text/JSON/SARIF.

This engine uses lexical/regex heuristics, **not JavaScript AST or taint analysis**. Co-occurrence may be legitimate. It can miss indirection, cross-file chains, encrypted payloads, native binaries, delayed behavior and publisher takeovers. It does not recursively resolve transitive dependencies from a direct tarball; use a lockfile. Non-source binaries and other languages are outside source coverage. Install hooks and entropy alone do not imply malware.

Dynamic execution, eBPF, PyQt6, API service, automatic installation, hosted AI, VirusTotal enrichment and SBOM generation are absent in this alpha. `--dynamic` returns an explicit error. A separate Docker research harness evaluates source samples without executing them; it is not a supported detonation sandbox. [Why this scope changed](docs/ASSESSMENT.md).

## Configuration and suppressions

```bash
cp sentinel.example.toml sentinel.toml
sentinel --config sentinel.toml scan package@1.2.3
sentinel --cache-dir .sentinel-cache scan chalk@5.3.0
```

Configuration is never implicitly loaded from target repositories. CLI `--cache-dir` overrides explicit TOML, which overrides defaults. The `SENTINEL_CACHE_DIR` environment variable controls the default cache location. No dotenv secrets are loaded. Suppressions must specify exact package+version or artifact digest, rule ID, reason, and expiration date; suppressed evidence remains in JSON/SARIF. Do not accept policy config supplied by an untrusted PR.

## GitHub Actions and hooks

The root [composite Action](action.yml) scans a lockfile and uploads SARIF as an artifact. Pin it to a reviewed commit; it is not published as a Marketplace release. It does not automatically upload to GitHub code scanning. That optional upload needs `security-events: write` and repository eligibility. Do not grant that permission to untrusted code.

```yaml
permissions:
  contents: read
jobs:
  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
        with:
          persist-credentials: false
      # Use cybergeek-007/Supply-Chain-Sentinel@<reviewed-commit> after publishing.
      - uses: ./
        with:
          lockfile: package-lock.json
          fail-on: review
```

The local `uses: ./` example applies when this tool itself is checked out. Consumer projects must use the published reviewed tool commit, not their own repository root. [Workflow recipes](docs/WORKFLOWS.md) describe PR, offline, pre-commit and scheduled update tradeoffs. The hosted Action/OS matrix has not run during local development; see [validation](docs/VALIDATION.md).

## Development and evidence

See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md), [architecture](docs/ARCHITECTURE.md), [sandbox threat model](docs/SANDBOX.md), [assessment](docs/ASSESSMENT.md), [benchmark](docs/BENCHMARK.md), and the separate [package-disjoint holdout results](docs/HOLDOUT_RESULTS.md). The old implementation plan is [archived](docs/history/implementation-plan.md); it does not describe completed features. Migration is documented in [MIGRATION](docs/MIGRATION.md).

MIT for project code ([reasoning](docs/ASSESSMENT.md)); public intelligence and samples retain their upstream licenses. This repository does not redistribute live malware samples.
