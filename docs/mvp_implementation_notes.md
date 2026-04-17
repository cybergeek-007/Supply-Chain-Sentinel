# Supply Chain Sentinel MVP Notes

This note captures the implementation state that should drive the next DPR rewrite.

## Implemented MVP Flow

1. `sentinel npm install <package>` fetches the exact npm tarball with `npm pack` inside a Dockerized Node runtime.
2. The tarball is hashed with SHA-256 and unpacked into a staging directory.
3. Static analysis inspects package metadata and source files for:
   - lifecycle scripts
   - Shannon entropy
   - optional YARA matches
   - optional JavaScript AST fingerprints
   - suspicious code patterns
4. If the static score stays below the configured risk threshold and lifecycle scripts exist, the package runs inside a Docker sandbox with:
   - `--network none`
   - fake SSH and AWS credentials
   - `strace` syscall tracing
5. Findings are evaluated against the JSON rule engine and the package receives an `allow`, `warn`, or `block` decision.
6. Approved packages attempt installation from the vetted tarball using local npm or a Docker npm fallback.

## Actual Public Interface

```text
sentinel doctor
sentinel reports triage <input-dir> [--output <path>] [--ai-summary] [--ai-model <model>]
sentinel reports dashboard <input-dir> [--output <path>]
sentinel demo fixtures [--output-dir <path>]
sentinel npm install <package> [--json-report <path>] [--rules <path>] [--timeout <seconds>] [--risk-threshold <0-100>] [--entropy-threshold <float>] [--no-install] [--ai-summary] [--ai-model <model>]
```

## Implemented Modules

- `artifact.py`: package fetch, tarball hashing, extraction, and approved-install path
- `static_analysis.py`: entropy analysis, optional YARA scan, lifecycle script detection, and JS fingerprinting
- `sandbox.py`: Docker image management, sandbox execution, and trace parsing
- `rules.py`: rule loading and finding-to-action evaluation
- `pipeline.py`: end-to-end orchestration and report generation
- `cli.py`: command-line interface
- `demo.py`: repeatable fixture evaluation flow for demos and DPR evidence
- `ai_analysis.py`: optional Grok/xAI-powered analyst summary layer that explains findings without affecting enforcement
- `report_corpus.py`: aggregate triage across previously saved JSON reports, with optional AI corpus analysis
- `dashboard.py`: static HTML dashboard for saved scan report corpora

## Current Scope Limits

- npm only
- Linux-style execution model through Docker
- runtime behavior detection from `strace`, not eBPF
- no time acceleration or deep deception beyond fake credentials and isolated networking
- optional integrations degrade gracefully when `esprima` or `yara-python` are unavailable

## DPR Update Guidance

The DPR should now describe advanced features like eBPF tracing, time acceleration, and deeper network deception as roadmap work rather than MVP scope. The architecture and evaluation sections should reflect:

- Shannon entropy default high-risk threshold: `7.2`
- static risk threshold default: `80`
- sandbox runtime using Docker plus `strace`
- rule categories: obfuscation, network, filesystem, process, credentials
- measurable outputs: JSON report, SHA-256 artifact integrity, rule hits, and install decision
