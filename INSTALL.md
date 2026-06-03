# Supply Chain Sentinel — Installation Guide

Supply Chain Sentinel is a cross-platform CLI tool for detecting malicious npm packages.

## Prerequisites

- **Python 3.9+**
- **Node.js 18+** (for subprocess fallback analysis)
- **Docker** (optional, but **highly recommended** for full dynamic sandbox isolation)

---

## 1. Installation

### Windows
```powershell
# Clone the repository
git clone https://github.com/cybergeek-007/Supply-Chain-Sentinel.git
cd Supply-Chain-Sentinel

# Create a virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install the package
pip install -e .
```

### Linux / macOS
```bash
# Clone the repository
git clone https://github.com/cybergeek-007/Supply-Chain-Sentinel.git
cd Supply-Chain-Sentinel

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install -e .
```

---

## 2. Initial Setup

Run the interactive setup wizard to configure AI providers, Threat Intelligence APIs, and Docker settings.

```bash
sentinel setup
```

The setup wizard will guide you through:
1. **System Checks:** Verifies Docker and Node.js availability.
2. **AI Configuration:** Select your preferred AI provider (OpenAI, Anthropic, Gemini, Groq, Ollama) and enter your API key.
3. **Threat Intelligence:** Configure VirusTotal and AbuseIPDB API keys (optional, free tiers available).
4. **Analysis Defaults:** Choose between static-only or dynamic analysis.
5. **Docker Build:** Optionally build the Docker sandbox image immediately.

---

## 3. Verifying Installation

Verify the tool is installed correctly:
```bash
sentinel --version
```

Analyze a test package:
```bash
sentinel npm left-pad
```

---

## 4. Setting up the Sandbox (Optional but Recommended)

If you chose not to build the sandbox image during `sentinel setup`, you can build it manually at any time:

```bash
docker build -f docker/Dockerfile.sandbox -t sentinel-sandbox:latest docker/
```

Once built, you can run dynamic analysis using the `--dynamic` flag:
```bash
sentinel npm react --dynamic
```
