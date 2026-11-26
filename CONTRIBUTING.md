# Contributing

Start with [the assessment](docs/ASSESSMENT.md), [architecture](docs/ARCHITECTURE.md), and [benchmark report](docs/BENCHMARK.md). The current work derives from m2; main has a different API and unrelated Git history.

Use Python 3.11+:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e . -r requirements-dev.txt
python -m ruff check src tests benchmarks
python -m ruff format --check src tests benchmarks
python -m mypy
python -m pytest --cov=src/supply_chain_sentinel --cov-fail-under=85
python -m build
```

Unit tests prohibit network sockets. Add minimized inert attack-chain and legitimate counterexample fixtures for detector changes. Test behavioral contracts rather than regex implementation details. Preserve stable rule IDs and JSON schema compatibility, or document migration. Every module needs meaningful tests; a successful mock response does not prove a provider works live.

Never add live malware, credentials, tarballs from incident datasets, or private code to Git. The separate benchmark harness keeps samples in container storage. Publish per-package metadata, exclusions, hashes and methodology. Keep tuning and independent holdout evaluations separate. Do not tune against a benchmark and call the same run independent validation.

Use small commits explaining behavior and validation. MIT applies to project code; third-party data and sample code keep their own licenses. New adapters require a maintainer and real lockfile/archive fixtures before being advertised. Do not add an ecosystem stub just to expand a supported-ecosystems list.
