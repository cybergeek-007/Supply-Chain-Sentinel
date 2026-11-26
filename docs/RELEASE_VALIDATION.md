# Release validation — 26 November 2026

The frozen runtime is ruleset 2026.11.3 at local commit b794bb5. The fresh
selection plan was committed before acquisition. No rules were changed after
viewing this evaluation. The original exploratory and first holdout results
remain unchanged.

## Fresh package-disjoint set

20 presumed-benign exact npm versions and 20 dataset-labeled malicious packages
were acquired without errors. All selected malicious package directories were
excluded from both prior cohorts. Benign identities were also checked for overlap.
The set is curated, small, and drawn from the same dataset; independence of
campaigns and families is not established. Dataset labels are not independent
forensic verification. No negative-cohort advisory sweep was performed.

| TP | FP | TN | FN | Errors | Precision | Recall | FPR | FNR |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 9 | 0 | 20 | 11 | 0 | 100% | 45% | 0/20 | 55% |

Precision is conditional on this selected class mix. The 95% Wilson recall
interval is 25.82–65.79%; the FPR interval is approximately 0–16.11%. Zero observed
false positives is not a population zero-FPR claim. Median warm static inspection
was 62.716 ms; p95 was 3,157.192 ms. Acquisition/startup/advisory update times are
excluded. Seven synthetic controls remain separately labeled in raw output.

Samples were acquired as encrypted archives in a dedicated rootless Docker
daemon, then decrypted/read offline with read-only root, UID 65532, no host
mounts, dropped capabilities, no-new-privileges, one CPU, 1 GiB memory and
64 PIDs. No package code was executed. Archive paths and hashes are in
`benchmarks/release-fresh-manifest.json`; metadata-only results and metrics
are in `benchmarks/results/release-fresh*.json`. Reproduce selection with
`release_worker.py fetch`, then evaluate only in the isolated runtime.

## Every fresh source outcome

A clean result below means no implemented rule reached the review threshold.
For the eleven dataset-labeled source misses, exact malicious payload attribution
remains unresolved; the recorded symbols/rules do not justify claiming an evasion
technique. Each needs independent investigation. No miss is silently excluded.

| Cohort | Identity | Verdict | Scan ms | Rules / error |
| --- | --- | --- | ---: | --- |
| benign | nanoid@5.0.8 | clean | 3.165 | none |
| benign | pako@2.1.0 | clean | 270.541 | none |
| benign | jszip@3.10.1 | clean | 110.693 | none |
| benign | fuse.js@7.0.0 | clean | 66.142 | install-script |
| benign | date-fns@4.1.0 | clean | 2069.826 | none |
| benign | luxon@3.5.0 | clean | 349.779 | install-script |
| benign | immutable@5.0.3 | clean | 86.011 | none |
| benign | immer@10.1.1 | clean | 31.873 | none |
| benign | decimal.js@10.4.3 | clean | 40.211 | none |
| benign | big.js@6.2.2 | clean | 7.778 | none |
| benign | marked@15.0.0 | clean | 59.29 | none |
| benign | markdown-it@14.1.0 | clean | 133.311 | none |
| benign | sanitize-html@2.13.1 | clean | 9.286 | none |
| benign | dompurify@3.2.0 | clean | 41.365 | none |
| benign | cheerio@1.0.0 | clean | 148.93 | install-script |
| benign | xml2js@0.6.2 | clean | 855.892 | none |
| benign | yaml@2.6.0 | clean | 103.355 | none |
| benign | toml@3.0.0 | clean | 27.975 | none |
| benign | ini@5.0.0 | clean | 1.442 | none |
| benign | archiver@7.0.1 | clean | 5.888 | none |
| malicious | @strapbuild/react-native-date-time-picker@2.0.4 | review | 2847.316 | download-execute, install-script |
| malicious | posthog-node@5.13.3 | review | 3197.252 | download-execute, install-script |
| malicious | @supersurkhet/cli@0.0.2 | clean | 806.57 | install-script |
| malicious | @xene/core@0.4.1 | review | 19.851 | destructive-install, install-script, install-secret-exfil |
| malicious | @asyncapi/avro-schema-parser@3.0.26 | review | 3157.192 | download-execute, install-script |
| malicious | @quick-start-soft/quick-remove-image-background@1.4.2511142126 | review | 2631.436 | download-execute, install-script |
| malicious | react-jam-icons@1.0.2 | review | 3832.398 | download-execute, install-script |
| malicious | @seung-ju/react-hooks@0.0.2 | review | 2864.236 | download-execute, install-script |
| malicious | @asyncapi/java-template@0.3.5 | review | 2610.142 | download-execute, install-script |
| malicious | @voiceflow/logger@2.4.3 | review | 2866.932 | download-execute, install-script |
| malicious | fb-error-lite@2.7.0 | clean | 7.215 | install-script |
| malicious | @solana-launchpads/sdk@1.0.12 | clean | 1120.873 | none |
| malicious | @3stripes/shared@999.0.2 | clean | 2.216 | install-script |
| malicious | transform-for-of@7.28.1 | clean | 0.796 | none |
| malicious | @ing-web-es/application@99.9.0 | clean | 2.077 | install-script |
| malicious | kiki-lontong50-sukiwir@4.3.4 | clean | 10.137 | none |
| malicious | lisa-ongol-ongol40-miaww@3.2.4 | clean | 10.02 | none |
| malicious | html-webpack-plugin-v4@9.9.99 | clean | 1.041 | install-script |
| malicious | @custom-widget/sdk@0.1.0 | clean | 0.919 | none |
| malicious | stripe-testfb-v3@1.0.0 | clean | 0.803 | install-script |

## Public release decision

Experimental triage alpha only. Source recall remains insufficient for a stable
malware-prevention release. Aliased and interprocedural flows, complex bundles,
transitive dependency payloads and Yarn false positives remain limitations.
No claim of superiority to established scanners is supported.

## Build and hosted CI

117 local tests, Ruff, strict mypy and source/wheel builds passed. A new venv
installed the wheel with no dependencies and no index; pip check and CLI version
checks passed. All 12 jobs in the hosted [CI run](https://github.com/cybergeek-007/Supply-Chain-Sentinel/actions/runs/45787050762)
passed for review snapshot `3b6a0f43244e269c3887feb8253ea837478951ff`: Python
3.11–3.14 on Ubuntu, Windows and macOS. This snapshot has the same runtime and
selection/evaluator code as local `b794bb5`; the connector published one review
commit atop m2 because local Git has no credentials. The original logical local
commits remain intact. Later report-only additions are not part of that CI SHA.

## Complete original corpus regression

All 126 presumed-benign and 36 malicious selections were replayed with pinned
archive hashes. Results were TP=16, FP=0, TN=125, FN=20, with one benign
archive error (webpack-cli duplicate paths). Source recall is 44.44%,
precision 100% conditional on this corpus, FPR 0/125, FNR 55.56%. Verdicts
were unchanged from the recorded exploratory run. The known uncertain
@yoobic manifest/path version label is retained; excluding it gives 16/35 recall.
Warm median inspection was 29.259 ms, p95 2,752.167 ms. Acquisition was
measured separately at median 878.125 ms and p95 1,460.417 ms; these are not
an end-to-end latency distribution. Per-package times/rules/errors are in
`benchmarks/results/release-regression.json`, with reproducible metrics in
`release-regression-metrics.json`. This is regression evidence on previously
examined data, not fresh detection validation.

## Cleanup

Both acquisition containers, all four temporary benchmark images and the
rootless build cache were removed after exporting sanitized metadata. The
final inventory contained no images or containers.
The dedicated rootless daemon was then stopped. System Docker was not changed.
