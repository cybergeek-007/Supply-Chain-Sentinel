# Incident-Style Fixture

This fixture is a safe npm package for static-analysis testing.

It intentionally mimics patterns commonly reported in past supply-chain incidents:
- lifecycle hooks such as `prepare` and `postinstall`
- references to `child_process`, shell commands, and encoded PowerShell
- token and workstation-secret access strings
- network and DNS exfiltration indicators
- persistence-related strings
- a hidden cache directory with suspicious artifact names

Safety constraints:
- no credential access is performed
- no network requests are performed
- no subprocesses are spawned
- no files are dropped or modified outside the fixture itself
- all suspicious content is inert string data or logging-only code

Use it by either:
- selecting the `package` directory for direct static scans
- or packing `package/` into a `.tgz` for end-to-end npm archive analysis
