# Baseline before refactor

Original branch: m2, commit 8f1b5155f9272274efb4078ec9758f9bb91f40d0.

Verified during onboarding: 36 tests passed, one eBPF integration skipped. CLI help worked after installing editable into `.venv`. Fixture scan returned complete/CAUTION (47), 23 findings, while network phase failed with `_NetworkIndicator has no attribute get`. Cache import failed on missing `src.core.python.logging_config`.

Source defects: inconsistent network result schema; undefined cache_key after restoring cache; phase errors could produce normal verdicts; shared package-name extraction races in audit; errors could pass audit policy; host npm execution fallback; scoped name parsing bug; successful subprocess exit 0 became -1; AI explain/endpoint/final override wiring defects; missing old SandboxManager; C/Python eBPF event layout mismatch; C++ output/import/API mismatch; stale API/Qt launchers; deployment ran privileged and referenced nonexistent API. CI excluded default m2 pushes. README referenced missing license/contribution files and unsupported audit syntax. No Qt GUI exists in m2 source; the plan contains proposed code blocks.

These components and the original 3,172-line plan remain available with `git show 8f1b515:<path>`. Removal from the active tree is deliberate; passing tests for a retired orchestrator are not carried forward as validation of the replacement.
