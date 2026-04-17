# Detailed Project Report

## Project Title

Supply Chain Sentinel: Automated Pre-Execution Sandbox with Polymorphic Malware Heuristics

## Domain

DevSecOps / Advanced Malware Analysis / Systems Engineering

## Executive Summary

Modern software development depends heavily on third-party packages obtained through registries such as npm. This convenience also enlarges the software supply-chain attack surface: malicious maintainers, typo-squatted packages, credential-stealing install scripts, and obfuscated post-install payloads can compromise developer machines before application code is even executed. Traditional dependency auditing tools primarily focus on known vulnerable versions and published advisories, which leaves a gap around malicious installation-time behavior.

Supply Chain Sentinel addresses this gap with a zero-trust package inspection workflow. Instead of allowing dependency install scripts to execute immediately on the host, Sentinel first acquires the exact package artifact, inspects it statically, and only then permits controlled execution inside an isolated Docker sandbox. The current MVP combines Shannon entropy analysis, suspicious pattern detection, optional YARA signatures, JavaScript structure fingerprinting, and `strace`-based runtime observation. The system ultimately returns an `allow`, `warn`, or `block` decision together with a machine-readable JSON report.

## Problem Statement

Package ecosystems optimize for speed and developer convenience, but many tooling flows still assume installation scripts are trustworthy by default. This assumption is dangerous because:

- install hooks such as `preinstall`, `install`, and `postinstall` run automatically
- obfuscated payloads can evade naive string matching
- malicious packages can read local credentials or beacon to remote servers during installation
- current auditing tools are not primarily designed to stop first-seen malicious behavior

The result is a need for a pre-execution inspection layer that focuses on package behavior rather than only vulnerability databases.

## Objectives

- Intercept npm package installation before lifecycle scripts run on the host
- Preserve the exact package artifact being evaluated through SHA-256 hashing
- Score suspicious packages with static heuristics before execution
- Execute risky lifecycle scripts inside an isolated Linux-style sandbox
- Detect runtime behaviors such as outbound network access, suspicious subprocesses, and honeypot credential reads
- Produce a reproducible report and a final enforcement decision

## Proposed Solution

The proposed solution is a Python-first orchestration tool exposed through the command:

```text
sentinel npm install <package> [--json-report <path>] [--rules <path>] [--timeout <seconds>] [--risk-threshold <0-100>] [--entropy-threshold <float>]
```

The package flow is:

1. Acquire the exact npm package artifact.
2. Hash and unpack the artifact in a staging area.
3. Run static analysis on source files and package metadata.
4. If warranted, execute lifecycle scripts inside a Docker sandbox with fake credentials and `strace`.
5. Evaluate all findings against JSON-defined enforcement rules.
6. Return an `allow`, `warn`, or `block` decision and emit a JSON report.

## System Architecture

### 1. Artifact Gateway

- Fetches npm packages without executing install scripts
- Supports registry packages and local fixture packages
- Computes SHA-256 for artifact integrity
- Unpacks the tarball into a staging directory for further inspection

### 2. Static Analysis Engine

- Inspects `.js`, `.cjs`, `.mjs`, `.json`, `.sh`, and related package files
- Detects lifecycle scripts from `package.json`
- Computes Shannon entropy to identify packed or heavily obfuscated payloads
- Flags suspicious JavaScript patterns such as `eval`, `Function`, `child_process`, and network-related code
- Supports optional YARA signatures and optional AST-based JavaScript fingerprinting

### 3. Sandbox Runner

- Builds and runs a Docker container based on a Node runtime
- Disables network access for controlled dynamic analysis in the MVP
- Plants honeypot credentials such as fake SSH and AWS files
- Executes lifecycle scripts under `strace` to capture system-level behavior

### 4. Rule Engine and Reporting

- Loads policy from `config/default_rules.json`
- Groups rules by `obfuscation`, `network`, `filesystem`, `process`, and `credentials`
- Maps findings to actions of `allow`, `warn`, or `block`
- Emits structured reports with artifact hash, findings, rule hits, duration, and installation outcome

## Mathematical and Heuristic Foundation

### Shannon Entropy

Shannon entropy is used to estimate the randomness of byte distributions inside a file. Higher entropy can indicate compression, encryption, or obfuscation. For this project, entropy is used as a fast pre-execution heuristic:

- below `6.5`: usually normal source text
- `6.5` to `< 7.2`: suspicious and worth closer inspection
- `>= 7.2`: high-risk by default

This threshold is intentionally configurable because acceptable values depend on the validation dataset.

### Structural Fingerprinting

When available, Sentinel uses JavaScript AST parsing to reduce source files to structural node sequences and then hashes those sequences into a fingerprint. This helps compare scripts based on logical shape rather than only raw text, making it more resistant to trivial renaming and string-level mutation.

## Current Implementation Status

The current repository implementation already includes:

- Python CLI and orchestration pipeline
- artifact acquisition and hashing
- static analysis with entropy and suspicious pattern detection
- optional YARA and optional AST fingerprinting
- Docker sandbox scaffolding with `strace`
- JSON rule evaluation
- sample benign and malicious fixture packages
- built-in `unittest` coverage

This means the project has advanced beyond concept-only design into an MVP suitable for demonstration and incremental evaluation.

## Evaluation Plan

The evaluation strategy focuses on both effectiveness and practicality.

### Metrics

- Detection rate / recall on known malicious fixture packages
- False positive rate on benign fixture packages
- End-to-end scan and install overhead
- Rule-hit fidelity for network, process, filesystem, and credential events
- Integrity preservation through stable artifact hashing

### Scenarios

- Benign package with no lifecycle script should be allowed
- Package with high-entropy payload should trigger strong static findings
- Package attempting credential access should be blocked
- Package attempting outbound connections should be blocked
- Packages requiring sandbox execution should fail closed when the sandbox runtime is unavailable

## Security Considerations

- The sandbox is treated as a defense layer, not a perfect guarantee
- MVP tracing uses `strace`, which is practical but less comprehensive than eBPF-based observability
- Docker runtime availability is a hard dependency for dynamic analysis
- Fake credentials reduce accidental exposure while still revealing suspicious access behavior
- Reports preserve evidence for later review instead of relying only on a binary allow/block outcome

## Limitations

- npm only in the current MVP
- Linux-style dynamic analysis depends on Docker availability
- No eBPF tracing in the MVP
- No time acceleration or advanced deception beyond planted credentials
- Optional modules such as `esprima` and `yara-python` may be absent on a fresh system

## Future Roadmap

### Phase 2

- richer deception artifacts
- proxy-assisted network observation
- larger malicious fixture corpus
- CI/CD integration

### Phase 3

- eBPF-based tracing
- time-acceleration experiments for delayed payloads
- multi-ecosystem support beyond npm
- stronger policy authoring and enterprise deployment features

## Deliverables

- Source code repository for Supply Chain Sentinel
- JSON rule configuration and YARA signature starter set
- Docker runtime assets for sandbox execution
- benign and malicious fixture packages for evaluation
- automated unit tests
- implementation-aligned DPR and demonstration outputs

## Conclusion

Supply Chain Sentinel provides a practical path toward zero-trust dependency installation by combining static heuristics, controlled dynamic analysis, and explicit enforcement policy. The MVP already demonstrates the core workflow needed for academic presentation and future expansion, while still leaving room for deeper tracing and broader ecosystem support in later phases.
