# Measured benchmark and release decision

Measured on 16 November 2026. **Decision: experimental preview only; not ready for a stable malware-prevention release.** The final source engine is usable for local triage, but misses too much of this malicious corpus. No claim of outperforming Socket, GuardDog, or another scanner is supported.

A later package-disjoint, one-shot evaluation of a syntax-aware candidate is
reported separately in [HOLDOUT_RESULTS.md](HOLDOUT_RESULTS.md). It does not
replace or retroactively tune the measurements below.

## Actual data and environment

- **126** curated, exact-version presumed-benign npm controls: utilities, HTTP clients, native addons/installers, build tools, parsers, minified browser bundles and test tools. These are established public package versions, not a probability sample of top downloads and not proof of benignness. Selection is in `benchmarks/benign.txt`.
- **36** encrypted public npm source samples from [Datadog's malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), Git commit `72c723be547033c558244520524b117c8d71663b`. One fixed-seed version per selected package. The acquired cohort is **compromised_lib only**: its category name differed from the initial sampler's assumption. The bug was corrected for future selection, but this run is reported as acquired, not relabeled balanced. Families/campaigns overlap; this is not 36 independent attack techniques.
- **7** explicitly synthetic controls, separate from public-source metrics: env exfiltration, literal base64 evaluation, download-to-shell, reverse shell, a configured private package name, a typo hint, and an intentionally indirect exfiltration miss.
- One source artifact (`@yoobic/jpeg-camera-es6`) has manifest version **1.0.12**, while its dataset path identifies **1.0.13**. Its artifact-level label is uncertain. Raw dataset-label metrics and a conservative calculation excluding that sample are both retained.
- Rootless Docker, pinned Python 3.11 image, one CPU quota, 1 GiB memory/swap, 64 PIDs, read-only root, no host mounts, analysis network disabled. Samples were downloaded/decrypted/read only in containers, never installed or executed. See [isolation checks and threat model](SANDBOX.md).

This dataset is primarily curated using GuardDog, which introduces selection bias, as [its own documentation explains](https://github.com/DataDog/malicious-software-packages-dataset#disclaimers). A sample labeled malicious by a dataset is a working evaluation label, not independent forensic verification by this project. Findings below were tuned against the same exploratory cohort; this is **not an untouched holdout**.

## Source-only results

Positive means `review` or `blocked` at the default policy threshold. Advisory lookup is disabled in these measurements; no known-malware name list contributes to source detection.

| Measurement | TP | FP | TN | FN | Errors | Precision | Recall | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Initial experimental rules, same corpus | 22 | 29 | 96 | 14 | 1 | 43.14% | 61.11% | 23.20% | 38.89% |
| Final rules 2026.11.2, raw dataset labels | 16 | 0 | 125 | 20 | 1 | 100% | 44.44% | 0/125 = 0% | 55.56% |
| Final, excluding uncertain version label | 16 | 0 | 125 | 19 | 1 | 100% | 45.71% | 0/125 = 0% | 54.29% |

Precision here is conditional on this selected, dataset-labeled corpus and its class mix. It is not a real-world precision estimate. Zero observed FPs does not establish a zero population FPR: Wilson 95% interval is **0–2.98%** for 125 completed negatives. Raw source recall Wilson interval is **29.54–60.42%**. One benign acquisition/inspection error is excluded from the FPR denominator and reported separately; it is not a true negative. There were no malware acquisition/scan errors in the final run, so error-as-miss operational recall equals the raw recall. No runtime/dynamic recall is measured.

Formulas: precision=TP/(TP+FP); recall=TP/(TP+FN); FPR=FP/(FP+TN); FNR=FN/(TP+FN). Undefined denominators are N/A, never zero. Exact formulas and Wilson calculations are in `benchmarks/report.py`; generated numbers are in `benchmarks/results/metrics.json`.

## False positives, errors, and fixes

All **29 initial false positives** were driven by `encoded-execution`. The expression was case-insensitive and treated normal lowercase `function(...)` as the JavaScript `Function(...)` constructor. It also correlated unrelated encoding/evaluation anywhere within a broad context window. This affected axios, webpack, Prettier, protobufjs, grpc, core-js, react-dom, angular, jquery, moment, rxjs, joi, fastify, socket.io, undici, qs, Vite, Terser, uglify-js, acorn, esprima, convert-source-map, source-map-support, webpack-dev-server, mocha, sinon, vitest, brace-expansion and iconv-lite. The exact original locations are preserved in `initial.json`.

The fix respects case-sensitive JS identifiers and requires a direct decode-to-execution expression. Regression tests cover ordinary generated functions, encoding libraries, legitimate install scripts, and explicit malicious chains. It removed the observed FPs, but also removed several accidental detections in malware; that recall loss is shown above rather than hidden by a threshold change. No blanket package allowlist or benign-name exemption was introduced.

`webpack-cli@5.1.4` is the **one error**: its tarball has duplicate paths, which this conservative archive reader rejects. It is an unsupported-input failure, not an FP, TN, or malware detection. A future change could allow byte-identical duplicates after independently verifying every occurrence; ambiguous replacement entries must remain errors.

The initial 4 MiB source cap rejected TypeScript's generated files during an aborted acquisition attempt. The bounded cap was raised to 16 MiB before the reported frozen corpus was acquired. The failed attempt is not misreported as a valid benchmark. A truncated GitHub tree also stopped the first sampler; complete package subtrees were used on the successful attempt.

## Every miss and what remains unresolved

Every final miss is listed individually in [the generated results table](BENCHMARK_RESULTS.md#every-final-source-miss), with observed feature limitations. Some samples contain bundled environment, process and encoding capabilities without the direct chain modeled by this small engine. Others contain no modeled chain in the inspected source set. Symbol counts cannot establish which bytes are malicious; exact payload attribution for those cases remains unresolved and is a release blocker. We do **not** claim that all misses were fully deobfuscated or explained forensically.

A concrete manifest-level miss was fixed: an install hook used `curl` with `gh auth token` and a root-deletion command. Dedicated correlated manifest rules now request review and have benign/malicious counterexample tests. This adds one detection without downgrading arbitrary install scripts. Remaining gaps require better JS parsing, alias/interprocedural analysis, version diffs and carefully isolated runtime research, not a rule saying “any HTTP, eval, base64 or install hook is malware.”

Synthetic controls: **5/7 request review**. The typo-only case produces an explicit low-confidence finding but intentionally stays below the review threshold. The computed-property/aliased `process['env']` and `globalThis['fetch']` case is missed, demonstrating limited data-flow coverage. A typo name alone is insufficient evidence of maliciousness. These results are controls written during development, not independent recall evidence.

## Known-record lookup, measured separately

OSV exact-version queries were run for the 36 completed malicious-cohort identities, without acquiring any new source. **32/36** were blocked using a MAL report or GitHub-reviewed **CWE-506** metadata. The four unmatched identities were `@mastra/voice-cloudflare@0.12.3`, `@mastra/codemod@1.0.4`, `@mastra/voice-gladia@0.12.2`, and the version-mismatched `@yoobic/jpeg-camera-es6@1.0.12`. Excluding that uncertain sample gives **32/35** matched. Source+advisory union was also **32/36** in this cohort.

This is cached known-record matching, **not novel-malware detection**. No negative-cohort OSV sweep was performed, so combined precision/FPR is not claimed. Queried identities, record IDs, modification/provenance, classification basis and timestamps are retained in `advisory-lookup.json`.

Additional live workflow checks covered flatmap-stream 0.1.1 and ua-parser-js 0.7.29 (malware advisories); colors 1.4.44 and faker 6.6.6 returned separate vulnerability/sabotage records rather than being inferred malicious from their names. Chalk 5.3.0 returned no advisory. This prompted a fix: GHSA IDs with reviewed CWE-506 metadata now classify as known malware; MAL prefixes alone were insufficient. Advisory absence is never proof of safety. The old historical incident artifacts were **not** detonated or independently source-evaluated here.

## Measured latency

| Operation / cohort | Median | p95 |
| --- | ---: | ---: |
| Warm static public-corpus inspection, combined | 24.553 ms | 2,655.004 ms |
| Benign controls, warm static | 11.937 ms | 445.607 ms |
| Malicious source samples, warm static | 1,180.010 ms | 2,835.428 ms |
| Benign acquisition in six-worker download phase | 1,054.649 ms | 2,498.903 ms |

One complete live `chalk@5.3.0` scan reported **902.445 ms** cold and **5.684 ms** from an offline verified cache. Source-correlated timing includes in-memory parsing; encrypted malware ZIP processing is included for that cohort. Acquisition concurrency and cache state differ from the serial one-CPU analysis, so acquisition+warm times must not be presented as a separately measured end-to-end distribution. Timing excludes interpreter startup and remote OSV update latency. No claim that every package finishes in seconds is made.

## Reproduce and inspect

Raw metadata: `benchmarks/results/initial.json`, `revised.json`, `final.json`, `advisory-lookup.json`; exact selected identities/URLs/hashes: `benchmarks/corpus.json`. No live sample bytes are in Git. Use [the isolated recipe](SANDBOX.md) with `fetch --frozen` to reproduce the exact cohort; default fresh selection is a different experiment. Keep source and advisory cohorts separate.

```bash
python benchmarks/report.py benchmarks/results/final.json
python benchmarks/generate_tables.py
```

[Per-package times, findings, errors and every miss](BENCHMARK_RESULTS.md) are generated from measured data. These files preserve the unsuccessful tradeoffs as well as the final run. Next gates: independently verify uncertain artifacts, manually resolve remaining misses, establish a family-separated holdout, expand benign sampling beyond convenience controls, compare mature scanners under the same methodology, and run the hosted OS/Python CI matrix. Until then, use this as an investigator aid alongside established tools, not the sole dependency admission control.

Targeted development fixes after the holdout are documented in [MISS_INVESTIGATION.md](MISS_INVESTIGATION.md). These selected replays are not fresh validation or replacements for either recorded benchmark.

Full regression replay and a later frozen, fresh package-disjoint evaluation
are reported in [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md), along with hosted CI.
