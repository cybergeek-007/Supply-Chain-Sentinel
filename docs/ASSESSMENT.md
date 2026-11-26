# Assessment and product decision

Research date: 16 November 2026. Baseline: `m2` at `8f1b515`. Recommendations below are engineering judgments, not claims of measured superiority. This assessment precedes the implementation commits. The separate `main` branch has unrelated history and a different installation/reporting pipeline.

## 0. What the repository actually does

The active entry point is `src.cli.main:cli`, not the implementation plan's GUI or API. The Python static analyzer, entropy calculation, fallback string signatures, manifest checks and selected helper modules run. Baseline unit/integration execution produced 36 passes and one eBPF skip on Python 3.14.8. A real invocation on the bundled incident-style fixture produced 23 findings, score 47/CAUTION, but silently retained a `complete` status despite a network-stage exception. This is a correctness defect, not a passing end-to-end scan.

The JavaScript “AST” implementation uses regular expressions. Python genuinely uses `ast`. Native YARA is optional; the fallback is simple substring matching, not equivalent YARA evaluation. The optional C++ entropy source exists, but its output/import paths and Python API shape differ, and no validated performance need justifies making it a release dependency. VirusTotal HTTP lookup has tests with mocked responses; its live utility was not established. The newer threat-intelligence pipeline has a schema mismatch with network extraction.

Caching fails import (`logging_config` does not exist), and restoring it exposes an out-of-scope `cache_key`. AI endpoint/explain/verdict wiring is incomplete. The old dynamic analyzer imports a missing `SandboxManager`; eBPF C/Python event layouts disagree. The active Docker path uses strace, not eBPF; without Docker it executes npm lifecycle scripts directly on the host. The latter must be removed. The GUI and API are code examples in the 3,172-line implementation plan, not implemented components on this branch. Their launchers, Compose/Kubernetes manifests, and app image refer to absent modules. Main's HTML dashboard is a different branch, not a PyQt6 GUI.

The plan is useful historical design material, not a completion record. It proposes kernel tracing, Qt, FastAPI, deployment, native builds and monitoring before demonstrating detector accuracy. That ordering is wrong for a small OSS tool. Existing tests mostly exercise the older orchestrator; they do not justify the README's broad claims. Baseline failure inventory is preserved in `docs/BASELINE.md`.

## 1. Concrete developer workflows and priorities

| Workflow | Concrete use | Priority and limitation |
| --- | --- | --- |
| Terminal / reported suspicious package | `sentinel scan name@version`, inspect file/line evidence and advisory provenance | P0; smallest useful workflow, seconds for small cached packages |
| CI/CD | Scan exact lockfile versions before executing `npm ci`; fail distinctly on findings and scan errors | P0; no target project's code or install hooks should run |
| Pull request | Scan changed lockfile entries against the base lockfile; emit SARIF attached to the lockfile | P0/P1; diff-aware scanning cuts repeated work; scanner/action must be trusted separately from PR code |
| Before npm install | Inspect exact direct package and resolved lockfile separately; then user installs with scripts disabled where feasible | P1; inspecting only one direct tarball does not vet transitive resolution; do not advertise a security boundary around arbitrary `npm install` |
| Lockfile audit | `sentinel scan-lockfile package-lock.json`; include dev and transitive entries | P0; validate integrity, aliases, unsupported sources, duplicate versions and failures |
| Pre-commit | Local hook scans lockfile changes using populated offline cache | P2; network downloads make hooks slow; never auto-install target dependencies |
| “On the go” | Install Python tool once or run in a disposable tool environment; scan an exact spec | P0; no accounts, AI keys or Docker required for static triage |

Decision: ship CLI + exact npm lockfile + transparent CI output first. Target <5 seconds warm for small packages; measure rather than promise this for large bundles or cold downloads. Validate adoption by 5–10 external users, repeat usage and dismissed-alert rates, not badge count.

## 2. Competition and feasible differentiation

| Tool | What to respect | Sentinel's choice |
| --- | --- | --- |
| [Socket](https://docs.socket.dev/docs/socket-cli) | Broad package intelligence, API/CLI and CI integration | Do not claim comparable intelligence. Offer an inspectable local engine and offline evidence with no account |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | Strong known-vulnerability matching and supported artifacts | Complement it with code-risk heuristics; do not rebuild remediation or all vulnerability ecosystems |
| [npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/) | Native advisory lookup | Keep advisory matches separate from previously unseen suspicious behavior |
| [Snyk](https://docs.snyk.io/developer-tools/snyk-cli/scan-and-maintain-projects-using-the-cli/snyk-cli-for-open-source) | Mature vulnerability workflows/integrations | Do not compete on enterprise inventory, policy administration or remediation breadth |
| [GuardDog](https://github.com/DataDog/guarddog) | Existing OSS source/metadata heuristics and multi-ecosystem support | Strongest direct comparison; offline reproducibility and low-noise evidence are goals, not established differentiators |
| [Phylum / Veracode](https://docs.phylum.io/) | Automated package analysis | Phylum is part of Veracode; its free Community edition was sunset February 2025. Do not design around an assumed free live feed |
| [OpenSSF Package Analysis](https://github.com/ossf/package-analysis) | Ecosystem analysis infrastructure with gVisor and behavioral data | Reuse research/data; do not reproduce a distributed detonation service |
| [Packj](https://github.com/ossillate-inc/packj) | Package risk inspection and sandboxing approach | Avoid “first supply-chain scanner” claims; focus on maintainability and documented limits |

Recommendation: a modest npm triage tool, deterministic local findings, reproducible benchmarks, strict failure semantics and offline operation. This is feasible. A comprehensive malicious-package detection platform, universal install firewall, or vendor-grade takeover detection is not feasible for this repository's present evidence and maintenance capacity.

## 3. Ecosystems and adapter boundary

Stay npm-only for the first release. Next consider PyPI (strong demand, but wheels/sdists and build metadata have distinct risks), then RubyGems, then crates.io/Go/Maven based on actual contributors. VS Code and Chrome extensions come later: permissions, browser APIs, store policies and signed archive formats need dedicated rules and trust models; they are not just npm packages.

Use a typed adapter boundary: parse exact identifiers, resolve metadata, acquire/verify bytes without executing tools, parse a lockfile, return an Artifact. Shared layers handle bounded archive reading, evidence models, policy, advisory snapshots, output and caching. Register adapters explicitly in code; avoid importing untrusted Python entry points or automatically downloaded plugins. Do not expose seven empty adapters as “support.” Exact version semantics belong to the adapter; OSV range evaluation should be delegated to the OSV API rather than improvised across ecosystems.

## 4. Interface decision

CLI first, repository GitHub Action next, a pre-commit recipe after offline caching. JSON is the integration contract; SARIF maps findings to checked-in lockfiles. A GUI adds packaging/testing burden and does not improve detection. A public API requires authentication, rate limiting, tenant isolation and a queue, so defer it. A VS Code extension should consume the CLI JSON later. A pre-install wrapper must preserve exact resolution and disable target scripts during acquisition; it cannot infer complete transitive safety from one direct scan. Cut the Qt/API scaffolding and unsupported UI claims now.

## 5. Static versus dynamic coverage

| Attack | Static strengths / failure | Dynamic strengths / failure |
| --- | --- | --- |
| Install hooks / droppers | Manifest + referenced source + download/execution correlation; indirect imports/encoding can evade | Sees executed hooks and file/process effects; no-network mode prevents second-stage fetch and can hide payload |
| Obfuscation | Decode literal encodings within limits; high entropy alone is weak | Captures deobfuscated behavior if triggered; delays/environment checks evade |
| Typosquatting | Name similarity is a review hint; legitimate similar names are common | Runtime generally cannot establish name intent |
| Dependency confusion | Requires organization-specific private names/scopes and registry policy | Runtime behavior is insufficient without organizational context |
| Credential/env exfiltration | Correlate secret reads and outbound capability in a bounded region; co-occurrence is not data flow | Fake credentials, file access and attempted connections provide stronger evidence; can miss conditional paths |
| Reverse shells / persistence | Useful high-signal code chains; shell/regex context can confuse it | Can observe spawned shell/files, but network-disabled sessions cannot complete |
| Maintainer takeover | Known bad version, provenance changes or version diff can signal; popularity is no safety exemption | Captures only behavior that executes; cannot identify who controlled publisher |

Static-first is the default. Dynamic review should be explicit and separate, never a host subprocess fallback, and never a requirement for routine CI. It is acceptable to cut it from v0.1 rather than ship an unverified sandbox. A future runner needs a disposable VM/gVisor boundary, no host bind mounts or socket, dropped capabilities, non-root execution, resource/time/output limits, strace/file/network collection and explicit unavailable/error results. A controlled fake network must terminate DNS/HTTP inside a network with no route to host/internet; merely adding a proxy to Docker bridge networking is not sufficient.

## 6. False positives, negatives and evaluation design

Prior expectation: current broad regex/substring rules will overflag native installers, HTTP libraries, bundlers and minified files. There is no defensible numerical FPR/FNR estimate without data; “36 passing tests” measures neither. Report measured rates and confidence intervals in the benchmark, keeping three populations separate: presumed-benign public tarballs, independent public malicious source samples, and synthetic controls. Advisory lookup recall is a fourth, different metric, not source-detection recall.

Use a version-pinned, stratified benign corpus (popular utilities, network clients, CLI/build tools, native/install-script packages and minified browser bundles). Popularity is only a sampling heuristic; it is not proof of benignness. Record hashes, downloads ranking provenance if available, scan errors, cold/warm times, and every result. Do not claim a curated set is the statistically sampled “top N” list. For malicious source, record independent advisory IDs, affected versions, artifact hashes, sampling rules and missing-artifact exclusions; keep all handling inside verified isolation. Split future tuning and holdout sets; in-session tuning is exploratory, not independent validation.

Scoring: capabilities alone are informational, combinations request review, known exact malicious-advisory matches block; never call a no-finding package SAFE. Confidence describes rule evidence strength, not calibrated probability. Cap duplicate evidence per rule so large files do not accumulate arbitrary risk. No mass downgrades based on directory names or package popularity. Support exact package/version/rule or artifact-hash suppressions with reasons and expiry; keep suppressed findings visible. A threshold change must show the effect on both FPR and misses. No blanket package-name allowlist.

Metrics: precision=TP/(TP+FP), recall=TP/(TP+FN), FPR=FP/(FP+TN), FNR=FN/(TP+FN); undefined denominators are N/A. Count errors separately and never turn them into true negatives. Also publish an error-as-miss operational recall when a malicious cohort is actually available. Report per-package latency, median/p95, sample sizes and cohort caveats.

## 7. AI decision

AI may explain evidence, suggest deobfuscation, or summarize investigator triage. It must not decide policy, silently rewrite findings, execute generated code, or fetch URLs suggested by package text. It is unnecessary for routine local scanning. Default is offline deterministic operation with no AI dependency and no code upload. Initial release should omit untested provider integrations rather than claim eight working backends.

Future optional helper: explicit consent and provider/endpoint, bounded evidence-only payload, secret redaction, structured schema validation, timeout/token budget, malicious content treated as quoted untrusted data, separate `ai_analysis` output, local model support and no model tools. Prompt filtering alone is not a reliable injection defense. Explain that snippets may contain private code; users can preview the payload. Track explanation failures separately without changing enforcement.

## 8. Public intelligence and updates

| Source | Use and restriction |
| --- | --- |
| [OSV API](https://google.github.io/osv.dev/post-v1-querybatch/) | Exact package/version query, pagination, IDs and timestamps; cache matching results for offline use |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Reviewed/unreviewed advisories and provenance; OSV already aggregates much of this, deduplicate rather than double-score |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | OSV-format malicious reports; withdrawn and research/borderline records need careful labeling; records are not executable samples |
| npm metadata / [provenance](https://docs.npmjs.com/generating-provenance-statements/) | Exact version/integrity and publisher/build signals; provenance establishes linkage, not that code is harmless |
| Socket/Phylum public information | Investigator context subject to API terms/availability; do not scrape blog HTML as a trusted rule feed |
| YARA feeds | Review licensing, accuracy, provenance and compute limits; no arbitrary unreviewed remote rules in default engine |

Version detector rules with tool releases. Update data snapshots independently using exact queried identities, atomic replacement, schema version, UTC fetch time, source, digest and per-record IDs; this digest is integrity metadata, not a signature proving authenticity. Offline mode never sends network traffic and explicitly reports absent/stale coverage. Begin with explicit `update-rules` on the selected lockfile/packages, rather than claiming a full global mirror. Scheduled sync is opt-in CI with no secrets required. Later signed release packs can add verified global intelligence; handle withdrawal and rollback explicitly.

## 9. Recommended architecture

`CLI -> config -> npm adapter/cache -> bounded Artifact -> static evidence engine -> exact advisory snapshot -> policy/suppressions -> ScanReport -> text/JSON/SARIF`.

Use `src/supply_chain_sentinel/` with models, config, archive, adapters/npm, rules, feeds, scanner, lockfile, output and cli modules. Python 3.11+ enables stdlib TOML configuration and reduces dependencies. Keep runtime dependencies empty initially; pin test/build tools separately. Preserve the old implementation in Git history and baseline notes instead of maintaining two conflicting runtime APIs. This is a deliberate CLI/schema break and must be documented.

Return `clean` (no blocking signals observed), `review`, `blocked` and `error`, with coverage/completeness flags and stable rule IDs. Exit 0 = completed below policy threshold, 1 = policy finding, 2 = scan/config/update error. In aggregate reports any error takes priority over policy findings. Never label partial scans clean. Known-malicious identity lookup may stop before fetching a malicious tarball; this must be reported as identity-only coverage. SARIF needs repository-relative locations, deterministic fingerprints and valid rule indexes. Do not expose cache paths as code-scanning locations.

MIT is a reasonable code license for easy adoption; adding a license expresses the maintainer's intent for owned code, not ownership of third-party intelligence or fixtures. Preserve third-party licenses and list feed provenance. A release still requires owner confirmation of contribution rights and the chosen license.

## Prioritized roadmap and gates

1. **P0 foundation:** truthful documentation; replace unsafe/duplicated runtime; bounded archives, integrity checks, exact specs, typed results, failure semantics, no target execution.
2. **P0 workflows:** CLI, lockfile scanning, offline cache, per-identity advisory updates, evidence/suppressions, JSON/SARIF, safe Action/pre-commit recipe.
3. **P0 validation:** meaningful tests for every new module, packaging smoke test, schema validation, real benign benchmark, separate advisory/synthetic cohorts; publish misses, exclusions and latency.
4. **P1 isolation research:** create a rootless disposable environment if host supports it; validate it with harmless escape/egress/resource probes before handling malicious archives. Add source-sample evaluation only after this gate. Do not quietly weaken isolation if unavailable.
5. **P1 release gate:** independent malicious-source holdout, 100+ stratified benign packages, acceptable reviewed-alert burden, reproducible CI across supported Python/OS versions, several external testers. Until met, label experimental.
6. **P2:** version-diff analysis, parsed JS data flow, signed rule packs, PyPI adapter. GUI, API service, kernel tracing and editor extension wait for demonstrated demand.

The first implementation is a usable experimental static triage tool, not a production malware prevention claim. A v0.1-style public preview can be useful if these limits are prominent; a credible stable release needs the independent evidence above.
