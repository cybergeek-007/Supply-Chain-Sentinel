# Security policy

This is experimental static triage, not a complete malware detector or an installation firewall. No source finding is proof of intent. No finding is not proof of safety.

## Report a vulnerability

Use the repository's [private vulnerability reporting page](https://github.com/cybergeek-007/Supply-Chain-Sentinel/security/advisories/new) if enabled. If unavailable, open an issue requesting a private reporting channel without disclosing exploit details, credentials or live malware. Maintainers must enable private reporting before a public release; no response-time SLA is promised yet.

Do not attach executable malware or private package contents to public issues. Provide exact tool version, platform, config with secrets removed, rule ID, and a minimized inert reproduction.

## Trust boundaries

- Acquisition uses HTTPS to the public npm registry, restricts redirects and checks SRI plus manifest identity. This trusts the registry's metadata; it is not publisher-signature verification. Lockfile integrity adds an independent expected digest.
- Archives are read with compressed/uncompressed/member/source limits, never extracted or executed. Links, special files, path traversal and duplicates are rejected. Static parsers still consume untrusted bytes; use an isolated environment for known malicious samples.
- Local directory scans assume files are not being concurrently replaced. Do not scan an attacker-writable live directory as a privileged user. Directory hashes cover inspected source only, not uninspected binaries.
- Cache/snapshot writers are trusted local users. Snapshot digests detect corruption, not a malicious local writer. The OSV cache covers only selected identities, can be stale, and does not implement a global mirror.
- Config is explicit. Suppressions require identity, reason and expiry. Do not accept suppressions/config supplied by an untrusted PR in a privileged scanner workflow.
- There is no dynamic execution, host subprocess fallback, AI upload, Node/npm invocation, automatic plugin import, or implicit third-party reputation lookup in the released CLI.

## CI

Use `pull_request`, minimal read permissions, a scanner pinned to a reviewed commit, and no install of the target project before scanning. Do not use `pull_request_target` to execute PR code. Scanning one package does not recursively resolve its dependencies. Unsupported workspace/private/git lockfile entries fail with exit 2.

## Isolated research

See [the sandbox threat model](docs/SANDBOX.md). The benchmark worker is a research harness, not a supported dynamic-analysis product. It does not execute any sample. Docker shares the host kernel and is weaker than a VM boundary. Public release testing must include maintained image/runtime versions and independent adversarial review.
