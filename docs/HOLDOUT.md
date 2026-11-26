# Package-disjoint analysis holdout

This is a one-shot research evaluation, separate from the earlier exploratory
corpus. The selection protocol was committed before acquisition in
`benchmarks/holdout-plan.json` (commit `64400f8`) and the analyzer/evaluator was
frozen before source inspection in local commit `f14878d`.
The encrypted source samples stay inside the dedicated rootless Docker daemon;
the repository contains only selection metadata, hashes, and result summaries.
The one-shot outcome and release decision are in
[`HOLDOUT_RESULTS.md`](HOLDOUT_RESULTS.md).

## Frozen protocol and candidate

- Dataset: DataDog malicious software packages dataset, commit
  `72c723be547033c558244520524b117c8d71663b`.
- Malicious selection: fixed seed `20261117`; 12 `compromised_lib` and 20
  `malicious_intent` package directories, excluding package directory names in
  the development corpus. One eligible ZIP per package, selected by the
  predeclared sorted-list/random-choice procedure.
- Benign controls: 30 exact npm identities in `benchmarks/holdout-benign.txt`,
  disjoint from the development benign set.
- Separation is package-disjoint. It does not establish campaign, family,
  maintainer, or technique independence. Dataset labels are not independent
  forensic verification.
- Candidate: shipping lexical rules plus an experimental Tree-sitter
  JavaScript, file-local alias/taint pass. It follows simple environment or
  credential-file reads through local assignments into selected outbound calls.
  It does not resolve imports, cross-file or interprocedural flows, scopes,
  TypeScript, or runtime behavior. Identifier scope is intentionally
  over-approximated, so false positives are possible. Parse errors count as
  candidate errors, not clean results.
- Candidate was not promoted to the supported package. It is benchmark code
  only. Synthetic tests passed before the holdout was opened.

## Acquisition record

`benchmarks/results/holdout-manifest.json` contains exact selected identities,
archive hashes, and acquisition outcomes. There were 32 selected malicious
directories: 31 archives acquired; one selected directory had no ZIP under the
predeclared size limit. Of 30 benign packages, 29 archives were acquired; one
tarball had a non-root `package.json` layout the adapter does not support. Neither
error was replaced. Thus 60 source artifacts were available for evaluation.

## Evaluation and interpretation

The evaluation emits both baseline and candidate verdicts for every completed
artifact and records parser/scan errors separately. Positive means `review` or
`blocked` at the existing score threshold. Report TP/FP/TN/FN, errors, precision,
recall, FPR, FNR, and latency for the completed cohort; do not silently treat
errors as clean packages. The candidate is exploratory and its outputs are not
an independent estimate of real-world performance.

After the evaluation, sample-bearing containers and images were removed from
the dedicated rootless daemon. Encrypted archives are intentionally not
committed or exported. To reproduce, first use the dedicated rootless daemon
described in [SANDBOX.md](SANDBOX.md), then reacquire the fixed set and compare
its identities and hashes with `benchmarks/results/holdout-manifest.json` before
opening it. Do not substitute missing or mismatched artifacts.

```bash
docker build --network host -f benchmarks/Dockerfile.research -t sentinel-research:acquire .
docker run --name sentinel-holdout-acquire --network host --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --memory 1g --memory-swap 1g \
  --cpus 1 --pids-limit 64 --entrypoint python sentinel-research:acquire \
  /opt/benchmarks/research_worker.py fetch-holdout
docker commit sentinel-holdout-acquire sentinel-benchmark:holdout-v1
docker build --network none -f benchmarks/Dockerfile.holdout -t sentinel-benchmark:holdout-candidate .
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --memory 1g --memory-swap 1g \
  --cpus 1 --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --entrypoint python sentinel-benchmark:holdout-candidate \
  /opt/benchmarks/research_worker.py evaluate-holdout
```
