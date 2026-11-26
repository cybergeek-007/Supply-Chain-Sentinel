# Workflow recipes

## Before installation and one-off triage

Scan `name@exact-version`. For local packages, scan the directory containing the root package.json. Do not install the suspicious package to inspect it. Before `npm ci`, inspect a reviewed exact lockfile; direct tarball scans do not vet transitive resolution. Use OSV-Scanner/npm audit alongside Sentinel for vulnerability coverage and existing install-script restrictions as separate controls.

## CI and PR checks

The composite Action runs installed scanner code with Python isolated mode (`-I`) so target-repository modules cannot shadow it. Its default cache is outside the checkout under `runner.temp`; do not restore untrusted cache entries from a PR. By default it explicitly refreshes OSV identities and requires fresh advisory coverage. Set `update-advisories: 'false'` for source-only/previously cached use, with the coverage limitation visible. OSV updates disclose package identities and add network latency.

Run the tool from a reviewed immutable commit/environment before installing the target project's dependencies. The repository Action accepts an exact npm lockfile, produces SARIF, and propagates policy/error exit codes. Permissions default to contents:read; it uses no secrets. Uploading SARIF to GitHub code scanning is a separate, eligibility-dependent step.

For diff-aware scans, obtain the base lockfile as data (for example `git show <trusted-base-sha>:package-lock.json > /tmp/base-lock.json`) and use `scan-lockfile ... --base /tmp/base-lock.json`. Do not interpolate raw PR text into shell commands. Omitted entries are recorded by the diff selection, not claimed scanned. An entire unsupported workspace/link/private source causes an explicit error rather than a falsely complete result.

## Local pre-commit

Run `update-rules --lockfile package-lock.json` and a successful online lockfile scan to populate the cache first. A local hook can then execute:

```yaml
repos:
  - repo: local
    hooks:
      - id: sentinel-lockfile
        name: Sentinel offline dependency triage
        entry: sentinel scan-lockfile package-lock.json --offline
        language: system
        pass_filenames: false
        files: ^package-lock\.json$
```

This assumes a trusted installed `sentinel`. A new dependency absent from cache returns exit 2; the developer must explicitly populate it. Do not make hooks auto-install dependencies or silently fall back online.

## Scheduled intelligence refresh

Use a trusted scheduled CI job to run `sentinel --cache-dir <persistent-cache> update-rules --lockfile package-lock.json`, then retain the advisory snapshot for subsequent offline checks. No scheduled task was installed in a user account by this implementation. Updates are scoped to supplied exact identities; there is no claim of a complete live public-record mirror. Serialize updates to one cache; use repository-controlled policy, preserve advisory provenance and monitor failures. Never convert a failed refresh into fresh empty intelligence.

## Investigation and privacy

JSON retains file/line/evidence, suppressions and coverage. It may contain package source excerpts; do not upload reports from private code without reviewing them. Advisory refresh sends package name/version to OSV. Registry acquisition sends package identity to npm. Offline scanning sends neither. AI integrations are deliberately absent; the design for a future opt-in evidence-only explainer is in the assessment.
