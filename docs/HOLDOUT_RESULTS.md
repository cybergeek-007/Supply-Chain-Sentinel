# Package-disjoint holdout results

Evaluated once on 17 November 2026 after candidate commit `f14878d` was frozen.
This is **source-only**: neither OSV nor another known-record feed contributed to
the results. Samples were decrypted and read inside the rootless, network-disabled
analysis container; no package code was executed. Sanitized outcomes are in
[`holdout.json`](../benchmarks/results/holdout.json), and counts plus every
false positive, hit, miss, and error are reproducibly derived in
[`holdout-metrics.json`](../benchmarks/results/holdout-metrics.json) with
[`holdout_report.py`](../benchmarks/holdout_report.py).

## Results

Positive means `review` or `blocked`. Standard rates below use completed scans;
acquisition and parser errors are excluded from those denominators and shown
separately. Operational recall divides detections by all 32 selected malicious
directories, including errors.

| Source analyzer | TP | FP | TN | FN | Completed | Errors | Precision | Recall | FPR | FNR | Operational recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Frozen lexical baseline | 4 | 1 | 28 | 27 | 60 | 2 | 80.00% | 12.90% | 3.45% | 87.10% | 12.50% |
| Baseline + AST candidate | 6 | 5 | 21 | 24 | 56 | 6 | 54.55% | 20.00% | 19.23% | 80.00% | 18.75% |

The candidate adds **three** completed malicious detections but also **four**
new false positives. One baseline detection became a candidate parse error.
Candidate Wilson 95% intervals are 9.50–37.31% for completed-sample recall and
8.51–37.88% for FPR. The small, curated, package-disjoint sample does not support
a population performance claim. The earlier cohort remains the tuning cohort;
this holdout is only family/campaign unverified, not an independent field trial.

For the 56 artifacts where both passes completed, the lexical baseline took a
median 9.317 ms (p95 1,677.903 ms); the combined baseline plus AST candidate
took 24.798 ms (p95 2,824.301 ms). The AST pass alone added a median 3.842 ms
(p95 1,108.062 ms). These timers exclude acquisition and interpreter startup.
Per-package full and incremental timings are in `holdout-metrics.json`.

The 30 selected benign controls yielded 29 acquired archives. The 32 selected
malicious directories yielded 31 archives. One selected item in each cohort was
an acquisition error; neither was replaced. The baseline completed all 60
acquired artifacts. The candidate had four additional parse errors: three
benign (`amplitude-js`, `pino`, `npm`) and one malicious (`zapier-platform-cli`).
Those four are not clean verdicts. The benign `ssh2` archive layout and the
missing malicious ZIP are described in the acquisition manifest.

## False positives

The candidate reported five benign controls:

- `@sentry/node@8.35.0`, `pnpm@9.12.3`, `tsx@4.19.2`, and
  `playwright@1.49.0` matched only `ast-sensitive-egress`.
- `yarn@1.22.22` was already flagged by the baseline's install-script and
  download-execute rules; the AST pass added nothing for it.

The four new reports show that “environment value reaches an outbound call” is
too broad on real developer tooling. The output establishes a candidate-rule
match, not malicious intent. Tightening this rule after seeing these holdout
results would invalidate this run; the candidate is therefore not promoted.

## New detections

The AST candidate newly moved three dataset-labeled artifacts to `review`:

- `@antv/t8@0.5.0`
- `@antv/ava-react@3.5.2`
- `nemo-reporter@1.8.2`

All three also had the baseline's informational install-script finding. This
small sample does not show that the candidate generalizes to other campaigns.

## Every candidate miss and error

For the 24 completed malicious-labeled artifacts below, the candidate did not
reach the review threshold. Fourteen produced only the informational
`install-script` rule; ten produced no candidate finding. These are observed
rule outcomes, not forensic explanations of each payload. The exact per-package
rules, score inputs, and hashes are in the results JSON.

**Install-script only (14):**

`@squawk/fixes@0.3.3`, `@bitwarden/cli@2026.4.0`,
`@ctrl/tinycolor@4.1.2`, `@bun-sh/types@1.3.11`,
`dva-loading-hide-rce@1.0.0`, `postman-json@339.52.1`,
`underarmour@0.0.0-dev-202603280606`, `ufo-rocks2@3.99.99`,
`@add-wallet-exchange/import-type@1.0.0`, `intercom-intermoji@10.0.1`,
`archon5@1.2.0`, `accumulateinfo@1337.0.0`, `@rbacore/errors@2.2.2`,
`@grafanacloud/test-utils@1.0.0`.

**No candidate findings (10):**

`@mastra/auth-clerk@1.0.3`, `@mastra/modal@0.2.2`,
`astra-db-recommendations-starter@1.0.0`, `ggajsvjsg@1.0.0`,
`ocha-wajit2-sukiwir@2.4.2`, `latin_whale_z3n@1.4.3`,
`mahesa-miebogor31-sluey@4.4.4`, `facts-base@1.0.0`,
`ade-menjes66-breki@1.3.4`, `node-server-sdk@9.9.9`.

**Candidate analysis error:** `zapier-platform-cli@18.0.2` had a JavaScript
parse error in a scaffold template. The baseline did request review for this
artifact, but the candidate produced no usable verdict.

**Acquisition error:** one selected `compromised_lib` directory had no eligible
ZIP under the predeclared cap. No replacement was selected. This is not counted
as a clean scan or a false negative in the completed-scan table; it is included
as an operational non-detection.

## Release decision

This experiment does not justify shipping the AST pass. It trades a modest
recall increase for a much higher measured FPR and more parser errors. Keep it
as benchmark research, improve scope-aware flow modeling and parser coverage on
development data, then predeclare a **new** package-disjoint holdout before any
future performance claim. Do not change this frozen candidate and continue
reporting its original result.
