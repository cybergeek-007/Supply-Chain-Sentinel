"""Interactive first-run setup wizard for Supply Chain Sentinel.

Uses questionary for a polished terminal UX. Configures:
  - AI provider + API key + model
  - Threat intelligence API keys (VirusTotal, AbuseIPDB)
  - Default analysis mode
  - Docker availability check

Config is saved to ~/.sentinel/config.json
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import questionary
    from questionary import Style

    _HAS_QUESTIONARY = True
except ImportError:
    _HAS_QUESTIONARY = False
    questionary = None  # type: ignore[assignment]
    Style = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Config path
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".sentinel"
CONFIG_FILE = CONFIG_DIR / "config.json"

# ---------------------------------------------------------------------------
# Theme (Kali-inspired green-on-dark)
# ---------------------------------------------------------------------------

_STYLE = None
if _HAS_QUESTIONARY and Style is not None:
    _STYLE = Style([
        ("qmark", "fg:#00ff00 bold"),
        ("question", "fg:#ffffff bold"),
        ("answer", "fg:#00ff00 bold"),
        ("pointer", "fg:#00ff00 bold"),
        ("highlighted", "fg:#00ff00 bold"),
        ("selected", "fg:#00ff00"),
        ("separator", "fg:#555555"),
        ("instruction", "fg:#888888"),
        ("text", "fg:#ffffff"),
    ])

# ---------------------------------------------------------------------------
# AI provider models
# ---------------------------------------------------------------------------

_MODELS: dict[str, list[str]] = {
    "OpenAI": ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
    "Anthropic": ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"],
    "Gemini": ["gemini-2.0-flash", "gemini-2.5-pro-preview-05-06", "gemini-2.5-flash-preview-05-20"],
    "Groq": ["mixtral-8x7b-32768", "llama-3.1-70b-versatile", "llama-3.1-8b-instant"],
    "Ollama (local)": ["llama3", "codellama", "mistral", "phi3"],
    "OpenRouter": ["meta-llama/llama-3-8b-instruct:free", "google/gemini-flash-1.5", "anthropic/claude-3-haiku"],
    "Cloudflare": ["@cf/meta/llama-2-7b-chat-int8", "@cf/mistral/mistral-7b-instruct-v0.1"],
    "Cohere": ["command-r-plus", "command-r"],
}

_PROVIDER_MAP: dict[str, str] = {
    "OpenAI": "openai",
    "Anthropic": "anthropic",
    "Gemini": "gemini",
    "Groq": "groq",
    "Ollama (local)": "ollama",
    "OpenRouter": "openrouter",
    "Cloudflare": "cloudflare",
    "Cohere": "cohere",
}


# ---------------------------------------------------------------------------
# Docker check
# ---------------------------------------------------------------------------

def _check_docker() -> tuple[bool, str]:
    """Check if Docker is available and running."""
    docker_path = shutil.which("docker")
    if not docker_path:
        return False, "Docker not found on PATH"

    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            return True, f"Docker {version}"
        return False, f"Docker found but not running: {result.stderr.strip()[:80]}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Docker check failed: {exc}"


def _check_node() -> tuple[bool, str]:
    """Check if Node.js is available."""
    node_path = shutil.which("node")
    if not node_path:
        return False, "Node.js not found on PATH"
    try:
        result = subprocess.run(
            ["node", "--version"], capture_output=True, text=True, timeout=5,
        )
        return True, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False, "Node.js check failed"


# ---------------------------------------------------------------------------
# Config load/save
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    """Load existing config, or return empty dict."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(config: dict[str, Any]) -> Path:
    """Save config to ~/.sentinel/config.json with restricted permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    # Restrict file permissions on non-Windows (chmod 600)
    if platform.system() != "Windows":
        CONFIG_FILE.chmod(0o600)
    return CONFIG_FILE


# ---------------------------------------------------------------------------
# Main wizard
# ---------------------------------------------------------------------------

def run_setup() -> None:
    """Run the interactive setup wizard."""
    if not _HAS_QUESTIONARY:
        print("Error: questionary package not installed.")
        print("Install it with: pip install questionary")
        sys.exit(1)

    # Banner
    print()
    print("  \033[92m╔══════════════════════════════════════════════════════╗\033[0m")
    print("  \033[92m║\033[0m  \033[1m◆ Supply Chain Sentinel — Setup Wizard\033[0m              \033[92m║\033[0m")
    print("  \033[92m║\033[0m    Configure AI, threat intel, and analysis settings \033[92m║\033[0m")
    print("  \033[92m╚══════════════════════════════════════════════════════╝\033[0m")
    print()

    existing = load_config()
    config: dict[str, Any] = {}

    # ---- System checks ----
    print("  \033[93m[*] System checks\033[0m")
    docker_ok, docker_info = _check_docker()
    node_ok, node_info = _check_node()
    sys_platform = platform.system()

    if docker_ok:
        print(f"  \033[92m✔\033[0m Docker:  {docker_info}")
    else:
        print(f"  \033[91m✘\033[0m Docker:  {docker_info}")
        print(f"    \033[90m→ Dynamic analysis (--dynamic) requires Docker\033[0m")

    if node_ok:
        print(f"  \033[92m✔\033[0m Node.js: {node_info}")
    else:
        print(f"  \033[91m✘\033[0m Node.js: {node_info}")

    print(f"  \033[92m✔\033[0m Platform: {sys_platform} ({platform.machine()})")
    print()

    # ---- AI Provider ----
    ai_provider = questionary.select(
        "Choose AI provider for code analysis:",
        choices=["OpenAI", "Anthropic", "Gemini", "Groq", "Ollama (local)", "OpenRouter", "Cloudflare", "Cohere", "None (skip AI)"],
        style=_STYLE,
    ).ask()

    if ai_provider is None:
        print("\n  Setup cancelled.")
        return

    ai_config: dict[str, Any] = {"enabled": False}

    if ai_provider != "None (skip AI)":
        provider_key = _PROVIDER_MAP.get(ai_provider, "")
        ai_config["provider"] = provider_key

        # API key
        if ai_provider != "Ollama (local)":
            existing_key = existing.get("ai", {}).get("api_key", "")
            key_hint = f" (current: ...{existing_key[-8:]})" if existing_key else ""
            api_key = questionary.password(
                f"Enter your {ai_provider} API key{key_hint}:",
                style=_STYLE,
            ).ask()
            if api_key is None:
                print("\n  Setup cancelled.")
                return
            ai_config["api_key"] = api_key or existing_key
            
            if ai_provider == "Cloudflare":
                existing_endpoint = existing.get("ai", {}).get("endpoint", "")
                print("  \033[90m→ Cloudflare requires your Account ID in the endpoint URL.\033[0m")
                endpoint = questionary.text(
                    "Enter Cloudflare endpoint (e.g. https://api.cloudflare.com/...):",
                    default=existing_endpoint or "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1/chat/completions",
                    style=_STYLE,
                ).ask()
                if endpoint is None:
                    print("\n  Setup cancelled.")
                    return
                ai_config["endpoint"] = endpoint
        else:
            ai_config["api_key"] = ""
            # Check if Ollama is running
            print("  \033[90m→ Make sure Ollama is running: ollama serve\033[0m")

        # Model selection
        models = _MODELS.get(ai_provider, ["default"])
        model = questionary.select(
            "Default AI model:",
            choices=models,
            style=_STYLE,
        ).ask()
        if model is None:
            print("\n  Setup cancelled.")
            return
        ai_config["model"] = model
        ai_config["enabled"] = True

    config["ai"] = ai_config
    print()

    # ---- Threat Intelligence ----
    print("  \033[93m[*] Threat Intelligence APIs\033[0m")
    print("  \033[90m  All APIs are optional. Free tiers are available.\033[0m")
    print()

    threat_config: dict[str, str] = {}

    # VirusTotal
    existing_vt = existing.get("threat_intel", {}).get("virustotal_key", "")
    vt_hint = f" (current: ...{existing_vt[-8:]})" if existing_vt else ""
    vt_key = questionary.text(
        f"VirusTotal API key{vt_hint} (Enter to skip):",
        style=_STYLE,
    ).ask()
    if vt_key is None:
        print("\n  Setup cancelled.")
        return
    threat_config["virustotal_key"] = vt_key or existing_vt

    # AbuseIPDB
    existing_abuse = existing.get("threat_intel", {}).get("abuseipdb_key", "")
    abuse_hint = f" (current: ...{existing_abuse[-8:]})" if existing_abuse else ""
    abuse_key = questionary.text(
        f"AbuseIPDB API key{abuse_hint} (Enter to skip):",
        style=_STYLE,
    ).ask()
    if abuse_key is None:
        print("\n  Setup cancelled.")
        return
    threat_config["abuseipdb_key"] = abuse_key or existing_abuse

    print("  \033[92m✔\033[0m ip-api.com:     Free (no key needed)")
    print("  \033[92m✔\033[0m URLhaus:        Free (no key needed)")
    print("  \033[92m✔\033[0m MalwareBazaar:  Free (no key needed)")
    print()

    config["threat_intel"] = threat_config

    # ---- Analysis defaults ----
    default_mode = questionary.select(
        "Default analysis mode:",
        choices=[
            "Static only (fast, no Docker needed)",
            "Static + Dynamic (requires Docker)",
        ],
        style=_STYLE,
    ).ask()
    if default_mode is None:
        print("\n  Setup cancelled.")
        return

    auto_ai = False
    if ai_config.get("enabled"):
        auto_ai = questionary.confirm(
            "Auto-enable AI analysis for high-risk packages?",
            default=True,
            style=_STYLE,
        ).ask()
        if auto_ai is None:
            print("\n  Setup cancelled.")
            return

    config["analysis"] = {
        "default_mode": "dynamic" if "Dynamic" in default_mode else "static",
        "timeout": 60,
        "auto_ai": bool(auto_ai),
    }

    # ---- Save ----
    saved_path = save_config(config)

    print()
    print(f"  \033[92m✔ Config saved to {saved_path}\033[0m")

    # Summary
    print()
    print("  \033[93m╔═══════════ Configuration Summary ═══════════╗\033[0m")
    if ai_config.get("enabled"):
        print(f"  \033[93m║\033[0m  AI:          {ai_config.get('provider', '')} / {ai_config.get('model', '')}")
    else:
        print("  \033[93m║\033[0m  AI:          Disabled")
    vt_status = "Configured" if threat_config.get("virustotal_key") else "Not set"
    abuse_status = "Configured" if threat_config.get("abuseipdb_key") else "Not set"
    print(f"  \033[93m║\033[0m  VirusTotal:  {vt_status}")
    print(f"  \033[93m║\033[0m  AbuseIPDB:   {abuse_status}")
    print(f"  \033[93m║\033[0m  Mode:        {config['analysis']['default_mode']}")
    print(f"  \033[93m║\033[0m  Docker:      {'Available' if docker_ok else 'Not available'}")
    print("  \033[93m╚═════════════════════════════════════════════╝\033[0m")
    print()

    # Docker image build hint
    if docker_ok and config["analysis"]["default_mode"] == "dynamic":
        build_image = questionary.confirm(
            "Build the Docker sandbox image now?",
            default=True,
            style=_STYLE,
        ).ask()
        if build_image:
            print("  \033[93m[*] Building sentinel-sandbox image...\033[0m")
            try:
                subprocess.run(
                    ["docker", "build", "-f", "docker/Dockerfile.sandbox",
                     "-t", "sentinel-sandbox:latest", "docker/"],
                    check=True,
                    timeout=300,
                )
                print("  \033[92m✔ Sandbox image built successfully\033[0m")
            except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
                print(f"  \033[91m✘ Image build failed: {exc}\033[0m")
                print("  \033[90m→ You can build it later: docker build -f docker/Dockerfile.sandbox -t sentinel-sandbox:latest docker/\033[0m")

    print("\n  \033[92mSetup complete! Run 'sentinel npm <package>' to analyze a package.\033[0m\n")
