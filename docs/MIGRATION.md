# Migration from m2 0.2.0

This is a deliberate breaking alpha, versioned 0.3.0a1 to avoid regressing the existing 0.2.0 package version. It is a candidate for a small public preview, not a declaration that the requested release gates have passed.

| Previous interface | Alpha replacement |
| --- | --- |
| `sentinel npm NAME@VERSION` | `sentinel scan NAME@VERSION` |
| `sentinel file ARCHIVE` / `scan DIRECTORY` | `sentinel scan ARCHIVE_OR_DIRECTORY` |
| `sentinel audit --lockfile FILE` | `sentinel scan-lockfile FILE` |
| `--json` / `--output json` | `--format json` |
| `--report FILE` | `--format json --output FILE` (HTML output removed) |
| `setup` / implicit JSON + dotenv config | explicit `--config sentinel.toml` |
| dynamic / AI / API / GUI / SBOM / native tracing | removed from supported runtime |

The JSON schema has changed: result envelope `schema_version`, `results`, `counts`; each report includes identity/digest, findings, status/verdict/score, errors, warnings, coverage and duration. Verdicts are `clean`, `review`, `blocked`, `error`; the previous SAFE/MALICIOUS severity labels were too strong for uncalibrated heuristics. Exit 2 now consistently signals incomplete scanning.

Old source/tests/deployment scripts are available in Git at `8f1b515`. The implementation plan is archived under `docs/history`. Existing config/cache formats are not reused. The separate main branch retains its different installation/reporting architecture and has not been merged.
