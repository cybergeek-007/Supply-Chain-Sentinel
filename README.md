# Supply Chain Sentinel

Supply Chain Sentinel is a Python-first npm package inspection pipeline that analyzes dependencies before they are trusted. It combines deterministic static analysis, rule-based enforcement, optional dynamic sandbox execution, corpus-level triage, and static reporting artifacts for demos and evaluation.

The project is designed as a practical MVP for academic review, technical demos, and future product expansion. The current implementation is intentionally conservative: deterministic logic makes the `allow`, `warn`, or `block` decision, while optional AI features only explain results and never override enforcement.

## What Sentinel Does

Sentinel sits in front of npm package installation and evaluates a package in stages:

1. Acquire the exact package artifact.
2. Hash and unpack the artifact into a staging directory.
3. Run static analysis across package metadata and source files.
4. If lifecycle scripts exist and the package is not already blocked, execute those scripts inside an isolated Docker sandbox.
5. Evaluate all findings against JSON-defined rules.
6. Emit a structured report and optionally install the vetted artifact.

In the current MVP, Sentinel focuses on npm packages and Linux-style sandbox behavior through Docker.

## Current Feature Set

- npm package acquisition from the registry or local fixture directories
- SHA-256 artifact integrity tracking
- Shannon entropy analysis with a default high-risk threshold of `7.2`
- suspicious code-pattern detection for JavaScript and install hooks
- optional YARA signatures
- optional JavaScript AST fingerprinting
- Docker sandbox runner with fake credentials and `strace`
- rule-based `allow`, `warn`, and `block` decisions
- JSON report generation
- repeatable fixture evaluation workflow
- corpus-level report triage
- static HTML dashboard generation
- optional Grok-powered explanation layers for single reports and report corpora
- VS Code tasks and launch configurations for end-to-end testing

## Project Status

This repository is an MVP, not a production endpoint security product.

What is solid today:

- deterministic static analysis
- rule evaluation
- fixture-based demo flow
- report triage and dashboarding
- local development workflow

What is still environment-dependent:

- dynamic sandbox execution requires a working Docker daemon
- optional `esprima` and `yara-python` integrations may be absent on a fresh system
- AI summaries require `XAI_API_KEY`

## Architecture Overview

### Artifact Gateway

The artifact gateway is responsible for acquiring the package without executing install scripts, unpacking it, and preserving the exact tarball that was analyzed.

Responsibilities:

- acquire registry packages via npm-compatible tooling
- package local fixture directories into tarballs for testing
- compute SHA-256 hashes
- unpack the package into a staging area

Key implementation:

- `src/supply_chain_sentinel/artifact.py`

### Static Analysis Engine

The static analysis stage scans the unpacked package before any installation script is allowed to run.

Signals currently supported:

- lifecycle script presence in `package.json`
- Shannon entropy across text files and small binary payloads
- suspicious JavaScript patterns such as `eval`, `Function`, `child_process`, and similar constructs
- optional YARA matches
- optional AST-style structural fingerprints

Key implementation:

- `src/supply_chain_sentinel/static_analysis.py`

### Sandbox Runner

If a package contains install hooks and static analysis does not already block it, Sentinel attempts to run those hooks inside Docker. The sandbox plants fake SSH and AWS credentials and traces system behavior with `strace`.

Signals currently derived from sandbox traces:

- outbound connection attempts
- suspicious subprocess execution
- honeypot credential access
- sensitive shell-profile access

Key implementation:

- `src/supply_chain_sentinel/sandbox.py`
- `docker/Dockerfile`
- `docker/runner_entrypoint.py`

### Rule Engine

The rule engine evaluates static and dynamic findings against declarative rules.

Current rule categories:

- `obfuscation`
- `network`
- `filesystem`
- `process`
- `credentials`

Actions:

- `allow`
- `warn`
- `block`

Key implementation:

- `src/supply_chain_sentinel/rules.py`
- `config/default_rules.json`

### Reporting Layer

Sentinel produces structured JSON reports for individual scans, aggregate JSON for corpora, and static HTML dashboards for visual review.

Key implementation:

- `src/supply_chain_sentinel/pipeline.py`
- `src/supply_chain_sentinel/report_corpus.py`
- `src/supply_chain_sentinel/dashboard.py`

## Repository Layout

```text
.
|-- .vscode/                         VS Code tasks, launch configs, env file
|-- config/
|   |-- default_rules.json           Default enforcement rules
|   `-- basic_signatures.yar         Starter YARA signatures
|-- docker/
|   |-- Dockerfile                   Sandbox image
|   `-- runner_entrypoint.py         Sandbox execution wrapper
|-- docs/
|   |-- DPR_draft.md                 Implementation-aligned DPR draft
|   `-- mvp_implementation_notes.md  Current MVP notes
|-- samples/
|   |-- packages/                    Benign and malicious fixture packages
|   |-- malware/                     Notes on the fixture corpus
|   `-- reports/                     Example report outputs
|-- src/supply_chain_sentinel/
|   |-- ai_analysis.py               Optional Grok/xAI-powered explanation layer
|   |-- artifact.py                  Artifact acquisition and vetted install path
|   |-- cli.py                       Main CLI entrypoint
|   |-- dashboard.py                 Static HTML dashboard renderer
|   |-- demo.py                      Fixture evaluation flow
|   |-- environment.py               Local readiness checks
|   |-- models.py                    Shared data models
|   |-- pipeline.py                  End-to-end orchestration
|   |-- report_corpus.py             Batch report triage
|   |-- rules.py                     Rule loading and evaluation
|   |-- sandbox.py                   Dynamic execution and trace parsing
|   `-- static_analysis.py           Static analysis engine
|-- tests/                           Built-in unittest suite
|-- tmp/                             Generated outputs during local runs
`-- pyproject.toml                   Project metadata
```

## Installation

### Requirements

- Python `>= 3.11`
- Node.js available on `PATH`
- npm or Corepack available on `PATH`
- Docker Desktop or a compatible Docker daemon for sandbox execution

### Local Setup

```powershell
cd "D:\Cyber\Projects\Supply Chain Sentinel"
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

Optional extras:

```powershell
pip install -e .[ast]
pip install -e .[yara]
```

Those extras enable:

- `esprima` for stronger JavaScript AST parsing
- `yara-python` for signature-based matches

### Environment Variables

Sentinel now auto-loads environment variables from:

- `.env`
- `.vscode/.env`

The root `.env` is the right place for secrets like `XAI_API_KEY`.

Example `.env`:

```env
XAI_API_KEY=your-key
SENTINEL_XAI_MODEL=grok-4.20-reasoning
```

Existing shell environment variables still win over `.env` values.

## Quick Start

```powershell
python -m supply_chain_sentinel.cli doctor
python -m supply_chain_sentinel.cli npm install left-pad --json-report .\reports\left-pad.json --no-install
python -m supply_chain_sentinel.cli demo fixtures
python -m supply_chain_sentinel.cli reports triage .\tmp\demo-fixtures --output .\tmp\demo-triage.json
python -m supply_chain_sentinel.cli reports dashboard .\tmp\demo-fixtures --output .\tmp\demo-dashboard.html
python -m unittest discover -s tests -p "*_unittest.py"
```

## Command Reference

### `doctor`

Check local runtime readiness before scanning:

```powershell
python -m supply_chain_sentinel.cli doctor
```

This reports:

- Python runtime availability
- rules and YARA config presence
- Docker CLI and daemon reachability
- npm CLI health
- Corepack CLI health
- resolved npm runtime used by Sentinel
- xAI API key readiness
- optional module availability for `esprima` and `yara`

Expected behavior:

- command exits non-zero if a required runtime is unavailable
- warnings are used for optional capabilities

### `npm install`

Inspect a package before installation:

```powershell
python -m supply_chain_sentinel.cli npm install left-pad --json-report .\reports\left-pad.json
```

Pure evaluation mode:

```powershell
python -m supply_chain_sentinel.cli npm install left-pad --json-report .\reports\left-pad.json --no-install
```

Important flags:

- `--json-report <path>` writes the structured report
- `--rules <path>` overrides the default rules file
- `--timeout <seconds>` changes the operation timeout
- `--risk-threshold <0-100>` changes the static block threshold
- `--entropy-threshold <float>` changes the high-risk entropy cutoff
- `--no-install` skips installation even if the package is allowed
- `--ai-summary` asks for an optional Grok explanation after the scan
- `--ai-model <model>` overrides the default AI model

Supported inputs:

- registry package specs such as `left-pad`
- local fixture or package directories such as `.\samples\packages\credential-hunter`
- local tarballs

### `demo fixtures`

Run the bundled evaluation corpus:

```powershell
python -m supply_chain_sentinel.cli demo fixtures
```

Outputs:

- one JSON report per fixture under `tmp/demo-fixtures/`
- `tmp/demo-fixtures/summary.json`

Current fixture packages:

- `benign-logger`
- `entropy-dropper`
- `credential-hunter`
- `network-beacon`

### `reports triage`

Summarize a directory of prior Sentinel JSON reports:

```powershell
python -m supply_chain_sentinel.cli reports triage .\tmp\demo-fixtures --output .\tmp\demo-triage.json
```

What the triage summary includes:

- report count
- decision counts
- top finding kinds
- top rule hits
- sandbox error hotspots
- watchlist packages
- package-level summary rows
- optional corpus-level Grok analysis under `ai_analysis`

### `reports dashboard`

Render a static HTML dashboard from saved reports:

```powershell
python -m supply_chain_sentinel.cli reports dashboard .\tmp\demo-fixtures --output .\tmp\demo-dashboard.html
```

The dashboard includes:

- decision posture cards
- top finding kinds
- top rule hits
- watchlist section
- sandbox reliability section
- package evidence cards

## Report Output

### Single Scan JSON

Each scan report includes fields such as:

- `package`
- `version`
- `artifact_sha256`
- `static_score`
- `static_findings[]`
- `dynamic_findings[]`
- `rule_hits[]`
- `decision`
- `duration_ms`
- `sandbox_metadata`
- `installation`
- `ai_analysis`

### Corpus Triage JSON

Aggregate triage output includes:

- `report_count`
- `decision_counts`
- `top_finding_kinds`
- `top_rule_hits`
- `sandbox_errors`
- `watchlist_packages`
- `packages`
- `source_dir`
- `ai_analysis`

## VS Code Workflow

The repository includes a ready-made workspace setup under `.vscode/`.

Useful tasks:

- `Terminal > Run Task > Sentinel: Doctor`
- `Terminal > Run Task > Sentinel: Unit Tests`
- `Terminal > Run Task > Sentinel: Demo Fixtures`
- `Terminal > Run Task > Sentinel: Reports Triage`
- `Terminal > Run Task > Sentinel: Reports Dashboard`
- `Terminal > Run Task > Sentinel: Full Local Validation`

Useful launch profiles:

- `Sentinel: Doctor`
- `Sentinel: Demo Fixtures`
- `Sentinel: Reports Triage`
- `Sentinel: Reports Dashboard`
- `Sentinel: Scan Fixture With AI`

The workspace also:

- enables Python `unittest` discovery
- sets `PYTHONPATH=src` automatically through `.vscode/.env`
- recommends the Python and Pylance VS Code extensions

## Testing

Run the full unittest suite:

```powershell
python -m unittest discover -s tests -p "*_unittest.py"
```

What is currently covered:

- static analysis behavior
- rule-engine behavior
- sandbox trace parsing
- doctor output logic
- npm/Corepack fallback detection
- demo fixture orchestration
- AI-analysis response parsing
- report-corpus triage
- dashboard rendering

Recommended local validation sequence:

```powershell
python -m supply_chain_sentinel.cli doctor
python -m unittest discover -s tests -p "*_unittest.py"
python -m supply_chain_sentinel.cli demo fixtures
python -m supply_chain_sentinel.cli reports triage .\tmp\demo-fixtures --output .\tmp\demo-triage.json
python -m supply_chain_sentinel.cli reports dashboard .\tmp\demo-fixtures --output .\tmp\demo-dashboard.html
```

## Optional AI Features

Grok integration is optional and non-authoritative in this repository.

What AI currently does:

- generate a security-analyst summary for a single scan report
- generate a corpus-level triage summary for a directory of reports

What AI does not do:

- decide `allow`, `warn`, or `block`
- replace rules
- replace static or dynamic findings

Example:

```powershell
$env:XAI_API_KEY="your-key"
python -m supply_chain_sentinel.cli npm install left-pad --no-install --ai-summary --json-report .\reports\left-pad-ai.json
```

Notes:

- AI output is written under `ai_analysis`
- the default model is `grok-4.20-reasoning`
- override the model with `--ai-model` or `SENTINEL_XAI_MODEL`

## Demo and DPR Workflow

If you are using this project for a presentation, capstone, or DPR:

1. Run `doctor` and capture the environment state.
2. Run `demo fixtures` to generate package-level evidence.
3. Run `reports triage` to create a corpus-level summary.
4. Run `reports dashboard` to produce a visual artifact.
5. Use the generated JSON and HTML outputs as appendix material.

Helpful documents:

- `docs/DPR_draft.md`
- `docs/mvp_implementation_notes.md`

## Troubleshooting

### Docker daemon is unavailable

Symptom:

- `doctor` reports Docker daemon failure
- packages that require sandbox execution fail closed and become `block`

Why:

- dynamic analysis depends on a reachable Docker engine

Fix:

- start Docker Desktop
- ensure Linux containers are enabled
- rerun `python -m supply_chain_sentinel.cli doctor`

### npm is broken on Windows

Sentinel already tries to detect a working npm-compatible runtime and can fall back across available options. Use `doctor` to see which runtime Sentinel resolved.

### AI summaries are skipped

Symptom:

- `ai_status: skipped`

Fix:

- set `XAI_API_KEY`

### Optional modules are missing

Symptom:

- `doctor` warns that `esprima` or `yara` are not installed

Impact:

- Sentinel still runs, but with reduced analysis coverage

Fix:

```powershell
pip install -e .[ast]
pip install -e .[yara]
```

## Current Limitations

- npm only
- Linux-style dynamic analysis depends on Docker
- runtime tracing is `strace`-based, not eBPF-based
- no time acceleration for delayed payloads
- no advanced network deception beyond basic isolation and planted credentials
- no production agent, daemon, or enterprise deployment layer yet

## Roadmap Ideas

- richer deception artifacts inside the sandbox
- proxy-assisted network observation
- CI/CD integration
- rule suggestion from report corpora
- richer HTML dashboard views
- eBPF-based tracing
- multi-ecosystem support beyond npm

## License / Project Context

This repository is currently structured as a project prototype and academic MVP. If you plan to publish or distribute it broadly, add an explicit license and security review before production use.
