<p align="center">
  <img src="https://img.shields.io/badge/Supply_Chain-Sentinel-00FF41?style=for-the-badge&logo=npm&logoColor=white" alt="Supply Chain Sentinel" />
</p>

<h1 align="center">Supply Chain Sentinel</h1>

<p align="center">
  <strong>Catch malicious npm packages before they reach your production systems.</strong>
</p>

<p align="center">
  <a href="https://github.com/cybergeek-007/Supply-Chain-Sentinel/actions"><img src="https://img.shields.io/github/actions/workflow/status/cybergeek-007/Supply-Chain-Sentinel/ci.yml?branch=main&style=flat-square&label=CI" alt="CI" /></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License" /></a>
  <img src="https://img.shields.io/badge/version-0.2.0-00FF41?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform" />
</p>

---

## Demo

```
   _____ _           _          ____             _   _            _
  / ____| |         (_)        / ___|  ___ _ __ | |_(_)_ __   ___| |
 | |    | |__   __ _ _ _ __    \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |____| '_ \ / _` | | '_ \    ___) |  __/ | | | |_| | | | |  __/ |
  \_____|_| |_|\__,_|_|_| |_|  |____/ \___|_| |_|\__|_|_| |_|\___|_|
  [ Supply Chain Threat Detection & Analysis Framework ]
  github.com/cybergeek-007/Supply-Chain-Sentinel  v0.2.0

[*] Fetching npm package: chalk
[*] Running static analysis …

╔═════════════════════   ANALYSIS COMPLETE   ══════════════════════╗
║   Package  : chalk@5.6.2                                         ║
║   Status   : COMPLETE                                            ║
║   Risk     : [██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  3.0/100 ║
║   Verdict  : ✔  SAFE                                             ║
║                                                                  ║
║   Findings : 15 total  CRIT:0  HIGH:0  MED:0  LOW:14             ║
║   Advice   : No significant risk indicators detected.            ║
║   Duration : 2.78s                                               ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Features

- **Static Analysis Engine** — AST parsing, YARA-style signatures, and code-pattern heuristics scan for `eval()`, `child_process`, obfuscated payloads, and suspicious lifecycle scripts
- **Docker Sandbox (Dynamic Analysis)** — runs `npm install` inside a locked-down Alpine container with `--network=none`, `--cap-drop=ALL`, read-only filesystem, and `strace` syscall interception
- **Honeypot Credential Traps** — injects fake AWS, SSH, npm, and GitHub tokens into the sandbox environment; catches credential-theft malware that reads and exfiltrates them
- **Malware Evasion Detection** — identifies 22+ sandbox evasion techniques including `/.dockerenv` checks, `process.env.CI` fingerprinting, time-based delays, and anti-debugging flags
- **Unified Threat Intelligence** — aggregates reputation data from VirusTotal, AbuseIPDB, IP-API, URLhaus, and MalwareBazaar in a single pass
- **AI-Powered Analysis** — connects to OpenAI, Anthropic, Gemini, Groq, Ollama, OpenRouter, Cloudflare Workers AI, or Cohere to explain findings and validate risk severity
- **Typosquat Detection** — catches packages with names suspiciously similar to popular libraries (e.g., `lod-ash`, `reacct`)
- **Advanced Signature Engine** — Expanded YARA rules catch reverse shells, crypto miners, credential theft, and DNS exfiltration

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| CLI Framework | [Click](https://click.palletsprojects.com/) |
| Terminal UX | [Rich](https://github.com/Textualize/rich) (tables, panels, progress) · [Questionary](https://github.com/tmbo/questionary) (setup wizard) |
| Sandbox | Docker (Alpine + Node 20 + strace) |
| Threat Intel | VirusTotal API · AbuseIPDB API · IP-API · URLhaus · MalwareBazaar |
| AI Providers | OpenAI · Anthropic · Google Gemini · Groq · Ollama · OpenRouter · Cloudflare · Cohere |
| Testing | pytest · pytest-cov |

---

## Getting Started

### Prerequisites

| Requirement | Purpose | Required? |
|---|---|---|
| **Python 3.10+** | Core runtime | ✅ Yes |
| **Node.js 18+** | Subprocess fallback analysis | ✅ Yes |
| **Docker** | Full dynamic sandbox isolation | ⭐ Recommended |

### Installation

#### Windows (PowerShell)

```powershell
git clone https://github.com/cybergeek-007/Supply-Chain-Sentinel.git
cd Supply-Chain-Sentinel
python -m venv venv
.\venv\Scripts\activate
pip install -e .
```

#### Linux / macOS

```bash
git clone https://github.com/cybergeek-007/Supply-Chain-Sentinel.git
cd Supply-Chain-Sentinel
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Configuration

Run the interactive setup wizard on first use:

```bash
sentinel setup
```

It configures:
- AI provider (OpenAI / Anthropic / Gemini / Groq / Ollama / OpenRouter / Cloudflare / Cohere) + API key
- Threat intelligence keys (VirusTotal, AbuseIPDB)
- Default analysis mode (static-only or static+dynamic)
- Docker sandbox image build

Configuration is saved to `~/.sentinel/config.json`.

<details>
<summary><strong>Manual configuration via environment variables</strong></summary>

```env
# Core
SENTINEL_ENV=production
SENTINEL_DEBUG=false
SENTINEL_LOG_LEVEL=WARNING
SENTINEL_TIMEOUT=60

# Threat Intelligence (optional — free tiers available)
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here

# AI Provider (optional)
GROQ_API_KEY=your_key_here
GROQ_MODEL=mixtral-8x7b-32768
```

</details>

---

## Usage

### Analyze an npm package

```bash
# Static analysis (default — fast, no Docker needed)
sentinel npm lodash

# Static + Dynamic analysis (runs in Docker sandbox)
sentinel npm express --dynamic

# Specific version
sentinel npm left-pad@1.3.0
```

### Analyze a local archive

```bash
sentinel file ./suspicious-package.tgz --dynamic
```

### Scan an extracted directory

```bash
sentinel scan ./node_modules/some-package/
```

### Audit project dependencies

```bash
# Scan all packages in package-lock.json with concurrency
sentinel audit ./package-lock.json --concurrency 8

# Exit with non-zero code if any package is suspicious
sentinel audit ./package-lock.json --fail-on suspicious
```

### Generate SBOM

```bash
# Generate CycloneDX (default) or SPDX SBOM
sentinel sbom ./package-lock.json -o sbom.json
sentinel sbom ./package-lock.json --format spdx -o sbom.spdx.json
```

### Output formats

```bash
# Rich terminal table (default)
sentinel npm chalk --output table

# Machine-readable JSON (logs go to stderr)
sentinel npm chalk --output json

# Generate an HTML or JSON report file
sentinel npm react --report report.html
sentinel npm react --report report.json
```

### Example output

```
sentinel npm is-odd

╔═════════════════════   ANALYSIS COMPLETE   ══════════════════════╗
║   Package  : is-odd@3.0.1                                        ║
║   Status   : COMPLETE                                            ║
║   Risk     : [██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░]  35/100  ║
║   Verdict  : ⚠  CAUTION                                         ║
║                                                                  ║
║   Findings : 8 total  CRIT:0  HIGH:1  MED:0  LOW:6               ║
║   Advice   : Some indicators found. Review findings before       ║
║              proceeding.                                         ║
║   Duration : 3.06s                                               ║
╚══════════════════════════════════════════════════════════════════╝
```

### All CLI options

```bash
sentinel --help            # Root help
sentinel npm --help        # npm subcommand
sentinel file --help       # Local archive
sentinel scan --help       # Extracted directory
sentinel audit --help      # Audit project lockfile dependencies
sentinel sbom --help       # Generate CycloneDX/SPDX SBOM
sentinel setup             # Interactive setup wizard
sentinel --version         # Print version
```

---

## Project Structure

```
Supply-Chain-Sentinel/
├── config/
│   ├── rules/                     # YARA signatures & static analysis rules
│   └── honeypot_config.json       # Honeypot credential templates
├── docker/
│   ├── Dockerfile.sandbox         # Alpine + Node 20 + strace sandbox image
│   └── entrypoint.sh              # strace-wrapped npm install entrypoint
├── src/
│   ├── cli/
│   │   ├── main.py                # Click CLI — npm, file, scan, setup commands
│   │   ├── display.py             # Rich terminal rendering (tables, panels, banner)
│   │   ├── reporter.py            # HTML & JSON report generation
│   │   └── setup.py               # Interactive setup wizard (questionary)
│   ├── core/python/
│   │   ├── config.py              # Environment + YAML config loading
│   │   ├── pipeline.py            # Analysis pipeline orchestrator
│   │   └── logger.py              # Structured JSON logging (stderr)
│   └── modules/
│       ├── static_analyzer.py     # AST + pattern-based static analysis
│       ├── dynamic_sandbox.py     # Docker sandbox + subprocess fallback
│       ├── evasion_detector.py    # 22+ sandbox evasion technique detection
│       ├── threat_intel.py        # VT, AbuseIPDB, IP-API, URLhaus, MalwareBazaar
│       ├── ai_explainer.py        # Multi-provider AI analysis engine
│       ├── entropy.py             # Shannon entropy anomaly detection
│       ├── obfuscation_detector.py# JavaScript obfuscation scoring
│       ├── typosquat_detector.py  # Package name similarity checks
│       ├── metadata_analyzer.py   # Registry metadata risk signals
│       ├── network_analyzer.py    # URL/IP extraction and classification
│       └── npm_registry.py        # npm registry client & package staging
├── tests/                         # pytest unit & integration tests (36 passing)
├── pyproject.toml                 # Package metadata & build config
├── requirements.txt               # Runtime dependencies
└── requirements-dev.txt           # Development dependencies
```

---

## How It Works

```
                         ┌──────────────┐
                         │  npm / file  │
                         │   / scan     │
                         └──────┬───────┘
                                │
                    ┌───────────▼───────────┐
                    │   Analysis Pipeline   │
                    └───────────┬───────────┘
                                │
         ┌──────────────────────┼─────────────────────┐
         │                      │                     │
   ┌─────▼──────┐        ┌──────▼────┐         ┌──────▼──────┐
   │  Metadata  │        │  Static   │         │  Dynamic    │
   │  Typosquat │        │  Entropy  │         │  (Docker)   │
   │  Detection │        │  YARA/AST │         │  strace     │
   └─────┬──────┘        │  Obfusc.  │         │  Honeypots  │
         │               └─────┬─────┘         └──────┬──────┘
         │                     │                      │
         └─────────────────────┼──────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Evasion Detector  │
                    │   Threat Intel APIs │
                    │   AI Explainer      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Risk Score 0-100  │
                    │   Verdict & Report  │
                    └─────────────────────┘
```

---

## Contributing

Pull requests are welcome — whether you're adding detection rules, improving sandbox isolation, or fixing false positives. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on the development workflow and code style.

```bash
# Development setup
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v

# Format
python -m black src tests

# Type check
python -m mypy src
```

---

## License

[MIT](LICENSE)
