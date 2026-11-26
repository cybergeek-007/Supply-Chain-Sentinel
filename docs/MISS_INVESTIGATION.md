# Targeted miss investigation and rules 2026.11.3

Completed 18 November 2026. This is development work after inspecting the
holdout outcomes. It is not fresh validation; original holdout files and the
frozen AST candidate are unchanged. Seven selected misses, four previous
source detections and five presumed-benign controls were reacquired using the
recorded artifact hashes. Only encrypted samples were downloaded in the
rootless acquisition container. Source parsing ran separately with network
none, read-only root, UID 65532, no host mounts, dropped capabilities, one CPU,
1 GiB memory and 64 PIDs. No package code was executed.

## What the investigation established

- `dva-loading-hide-rce@1.0.0`: preinstall uses curl data to transmit multiple
  host identity command substitutions. The old secret rule recognized named
  credential variables but not this host fingerprint collection.
- `accumulateinfo@1337.0.0`: preinstall puts multiple host identity command
  substitutions in an outbound URL. It had the same coverage gap.
- `@bun-sh/types@1.3.11`: an inline postinstall launches `post.d.ts` with Bun.
  The 110-byte file fetches response text and passes it to eval. The old
  encoded-execution rule required an encoding primitive. A `.d.ts` extension
  did not prevent inspection; the missing behavior rule caused the miss.
- `@mastra/auth-clerk@1.0.3`: the manifest adds `easy-day-js: ^1.11.21`.
  No corresponding local source payload was established. This agrees with the
  [maintainer incident report](https://github.com/mastra-ai/mastra/issues/18044).
  A source scan of the wrapper cannot establish behavior in an unresolved child.
- `@ctrl/tinycolor@4.1.2`: postinstall launches a 3.7 MB bundle with many
  credential, filesystem and network symbols. The
  [maintainer report](https://github.com/scttcper/tinycolor/issues/257) confirms
  the affected release. Exact payload data flow in this artifact remains
  unresolved by this investigation; symbol counts alone do not establish it.
- `@squawk/fixes@0.3.3`: preinstall launches `setup.mjs`; the source set also
  contains a 2.35 MB file with extensive hexadecimal identifier obfuscation.
  Complete payload attribution and cross-file execution flow remain unresolved.
- `node-server-sdk@9.9.9`: a short source file contains host-identity reads and
  an HTTPS request, but this investigation has not established the complete
  field-to-request mapping. It remains a source miss.

Hashes, file sizes, referenced-file structure and redacted syntax are retained
in `benchmarks/results/investigation-after.json`. Payloads and source excerpts
are not exported. Archive inventory is limited to the reader's supported
formats; these observations do not establish runtime behavior.

## Changes and tradeoffs

Rules 2026.11.3 add a narrow curl hook rule: at least two distinct explicit
host-identity substitutions must occur in URL/data arguments. Literal
single-quoted or escaped substitutions, unrelated later shell commands and a
single hostname do not trigger it. Legitimate opt-in fingerprint uploads can
still require review; this finding is not proof of malicious intent.

A second lexical rule recognizes explicit fetch -> response.text() -> eval
promise callbacks. Tests require matching callback variables and include
ordinary response display, unrelated eval, comments and strings as negatives.
It does not resolve shadowed globals, imports, arbitrary callbacks, computed
properties or interprocedural flow.

Single-artifact reports now state that dependency resolution was not performed,
count declared runtime dependencies and warn when dependencies are present.
Lockfile scanning covers the exact entries listed; it does not independently
prove the lockfile is complete or resolve missing entries.

An attempted shell false-positive fix was rejected during development: requiring
an immediate process-launch call removed Yarn's false positive, but also lost
all four prior dropper detections because their shell command was assigned to
a variable first. The accepted rules retain the existing download-execute
behavior. Yarn remains a false positive. Scope-aware command flow is needed
before revisiting this change; no package-name exception was added.

## Validation

117 project tests passed with 91.74% source coverage; Ruff and strict mypy passed.
The real-artifact replay below uses a selected development set, so its counts
are regression evidence only. No population precision, recall or FPR claim is
made. The full original development corpus and a new untouched holdout have
not been run with these rules. Hosted CI remains unverified.

| Package | Prior source verdict | Rules 2026.11.3 | Scan ms |
| --- | --- | --- | ---: |
| @sentry/node@8.35.0 | clean | clean | 124.788 |
| pnpm@9.12.3 | clean | clean | 2439.409 |
| yarn@1.22.22 | review | review | 964.982 |
| node-sass@9.0.0 | clean | clean | 34.409 |
| electron@33.2.0 | clean | clean | 161.569 |
| @squawk/fixes@0.3.3 | clean | clean | 466.17 |
| @mastra/auth-clerk@1.0.3 | clean | clean | 1.956 |
| @ntnx/passport-wso2@0.0.3 | review | review | 1755.719 |
| go-template@0.1.9 | review | review | 1893.583 |
| zapier-platform-cli@18.0.2 | review | review | 1970.576 |
| @seung-ju/react-native-action-sheet@0.2.1 | review | review | 1951.789 |
| @ctrl/tinycolor@4.1.2 | clean | clean | 682.823 |
| @bun-sh/types@1.3.11 | clean | review | 136.071 |
| dva-loading-hide-rce@1.0.0 | clean | review | 0.372 |
| accumulateinfo@1337.0.0 | clean | review | 0.212 |
| node-server-sdk@9.9.9 | clean | clean | 0.437 |

After exporting sanitized results, both acquisition containers, all ten
investigation images and the dedicated daemon's build cache were removed.
Inventory verification showed only the original no-sample research helper and
pinned Python base image, with no containers. The dedicated daemon was stopped.
