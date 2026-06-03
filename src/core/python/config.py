"""
Configuration for Supply Chain Sentinel CLI.

Loaded from (in priority order, highest wins):
  1. ``~/.sentinel/config.json`` (from ``sentinel setup`` wizard)
  2. Environment variables (``SENTINEL_*`` prefixed)
  3. YAML file override (``from_file``)
  4. Dataclass defaults

Environment variables
---------------------
SENTINEL_ENV               - runtime environment label (default: production)
SENTINEL_DEBUG             - enable debug mode: 1/true/yes or 0/false/no
SENTINEL_LOG_LEVEL         - logging level: DEBUG/INFO/WARNING/ERROR/CRITICAL
SENTINEL_STAGING_DIR       - directory for package extraction staging
SENTINEL_ENTROPY_THRESHOLD - float Shannon entropy threshold (default: 7.0)
SENTINEL_MAX_PACKAGE_SIZE  - maximum package bytes to download (default: 100 MB)
SENTINEL_TIMEOUT           - sandbox execution timeout in seconds (default: 30)
SENTINEL_ENABLE_DYNAMIC    - enable Docker-based dynamic analysis
SENTINEL_RULES_DIR         - path to YARA/static-analysis rules directory
VIRUSTOTAL_API_KEY         - VirusTotal API key for hash lookups
ABUSEIPDB_API_KEY          - AbuseIPDB API key for IP reputation
SENTINEL_AI_PROVIDER       - AI provider: openai/anthropic/gemini/groq/ollama/openrouter/cloudflare/cohere
SENTINEL_AI_API_KEY        - AI provider API key
SENTINEL_AI_MODEL          - AI model identifier
SENTINEL_AI_ENDPOINT       - Custom API endpoint URL
SENTINEL_AI_ENABLED        - enable AI analysis: 1/true/yes or 0/false/no
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .exceptions import ConfigError


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _as_bool(value: str | bool | None, default: bool) -> bool:
    """Coerce a string or bool env-var value to a Python bool.

    Accepted truthy strings: ``1``, ``true``, ``yes``, ``y``, ``on``.
    Accepted falsy strings:  ``0``, ``false``, ``no``, ``n``, ``off``.

    Args:
        value:   Raw value from ``os.getenv`` or a YAML override.
        default: Fallback when *value* is ``None``.

    Returns:
        Parsed boolean.

    Raises:
        ConfigError: When *value* is a non-empty string that doesn't match
                     any recognised truthy/falsy token.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value

    normalized = value.strip().lower()
    truthy = {"1", "true", "yes", "y", "on"}
    falsy = {"0", "false", "no", "n", "off"}

    if normalized in truthy:
        return True
    if normalized in falsy:
        return False
    raise ConfigError(f"Invalid boolean value for configuration: {value!r}")


def _as_float(value: str | float | None, default: float) -> float:
    """Coerce a string or float env-var value to a Python float.

    Args:
        value:   Raw string from ``os.getenv`` or a YAML override.
        default: Fallback when *value* is ``None``.

    Returns:
        Parsed float.

    Raises:
        ConfigError: When *value* cannot be parsed as a float.
    """
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except ValueError as exc:
        raise ConfigError(f"Invalid float value for configuration: {value!r}") from exc


def _as_int(value: str | int | None, default: int) -> int:
    """Coerce a string or int env-var value to a Python int.

    Args:
        value:   Raw string from ``os.getenv`` or a YAML override.
        default: Fallback when *value* is ``None``.

    Returns:
        Parsed integer.

    Raises:
        ConfigError: When *value* cannot be parsed as an integer.
    """
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"Invalid integer value for configuration: {value!r}") from exc


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class SentinelConfig:
    """CLI-mode configuration for Supply Chain Sentinel.

    All fields have safe defaults and can be overridden via environment
    variables or a YAML configuration file.  See :meth:`from_environment`
    and :meth:`from_file` for loading strategies.

    Attributes:
        environment:       Named runtime environment (e.g. ``production``).
        debug:             When ``True``, verbose tracebacks are printed.
        log_level:         Logging level string (``WARNING`` by default).
        staging_dir:       Directory used for temporary package extraction.
        entropy_threshold: Shannon entropy score above which a file is
                           flagged as high-entropy.
        max_package_size:  Maximum allowable package archive size in bytes.
                           Downloads exceeding this limit are aborted.
        timeout_sandbox:   Seconds before a Docker sandbox execution is
                           forcefully terminated.
        enable_dynamic:    When ``True``, the Docker-based dynamic analysis
                           phase is enabled by default.
        groq_api_key:      Optional Groq API key for AI-assisted finding
                           explanations.
        groq_model:        Groq model identifier used for AI explanations.
        virustotal_api_key: Optional VirusTotal API key for hash lookups.
        rules_dir:         Path to directory containing YARA rules and static
                           analysis configuration.
    """

    # ---- General ----------------------------------------------------------
    environment: str = "production"
    debug: bool = False
    log_level: str = "WARNING"

    # ---- Staging / temp ---------------------------------------------------
    staging_dir: str = field(
        default_factory=lambda: str(Path(tempfile.gettempdir()) / "sentinel_staging")
    )

    # ---- Analysis settings ------------------------------------------------
    entropy_threshold: float = 7.0
    max_package_size: int = 100 * 1024 * 1024  # 100 MB
    timeout_sandbox: int = 30
    enable_dynamic: bool = False

    # ---- External integrations (all optional) -----------------------------
    groq_api_key: str = ""
    groq_model: str = "mixtral-8x7b-32768"
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ---- AI analysis (all optional) ---------------------------------------
    ai_provider: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    ai_endpoint: str = ""
    ai_enabled: bool = False

    # ---- Paths ------------------------------------------------------------
    rules_dir: str = "config/rules"

    # -----------------------------------------------------------------------
    # Factory methods
    # -----------------------------------------------------------------------

    @classmethod
    def from_environment(cls) -> "SentinelConfig":
        """Build a :class:`SentinelConfig` from environment variables.

        Each field has a corresponding ``SENTINEL_``-prefixed environment
        variable (see module docstring for the full list).  Missing variables
        fall back to the dataclass field defaults.

        Before reading env vars, attempts to load ``.env`` files in order:
          1. ``./.env`` (project root)
          2. ``~/.sentinel/.env`` (user config dir)

        Returns:
            A fully populated :class:`SentinelConfig` instance.

        Raises:
            ConfigError: When a variable is present but cannot be coerced to
                         the required type (e.g. a non-numeric entropy
                         threshold).
        """
        # Load .env files (lower priority loaded first, higher overrides)
        try:
            from dotenv import load_dotenv
            sentinel_env = Path.home() / ".sentinel" / ".env"
            if sentinel_env.exists():
                load_dotenv(sentinel_env, override=False)
            load_dotenv(override=False)  # ./.env (project root)
        except ImportError:
            pass  # python-dotenv not installed, skip silently

        environment = os.getenv("SENTINEL_ENV", "production")
        debug_default = environment == "development"

        # Resolve the staging_dir default once so the lambda isn't re-called.
        default_staging = str(Path(tempfile.gettempdir()) / "sentinel_staging")

        return cls(
            environment=environment,
            debug=_as_bool(os.getenv("SENTINEL_DEBUG"), debug_default),
            log_level=os.getenv("SENTINEL_LOG_LEVEL", "WARNING").upper(),
            staging_dir=os.getenv("SENTINEL_STAGING_DIR", default_staging),
            entropy_threshold=_as_float(
                os.getenv("SENTINEL_ENTROPY_THRESHOLD"), 7.0
            ),
            max_package_size=_as_int(
                os.getenv("SENTINEL_MAX_PACKAGE_SIZE"), 100 * 1024 * 1024
            ),
            timeout_sandbox=_as_int(os.getenv("SENTINEL_TIMEOUT"), 30),
            enable_dynamic=_as_bool(os.getenv("SENTINEL_ENABLE_DYNAMIC"), False),
            rules_dir=os.getenv("SENTINEL_RULES_DIR", "config/rules"),
            groq_api_key=os.getenv("GROQ_API_KEY", ""),
            groq_model=os.getenv("GROQ_MODEL", "mixtral-8x7b-32768"),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            ai_provider=os.getenv("SENTINEL_AI_PROVIDER", ""),
            ai_api_key=os.getenv("SENTINEL_AI_API_KEY", ""),
            ai_model=os.getenv("SENTINEL_AI_MODEL", ""),
            ai_endpoint=os.getenv("SENTINEL_AI_ENDPOINT", ""),
            ai_enabled=_as_bool(os.getenv("SENTINEL_AI_ENABLED"), False),
        )

    @classmethod
    def from_sentinel_config(cls) -> "SentinelConfig":
        """Build config by merging ``~/.sentinel/config.json`` over env vars.

        Priority (highest wins):
          1. ``~/.sentinel/config.json``  (from ``sentinel setup``)
          2. Environment variables
          3. Dataclass defaults

        The JSON file is written by the interactive setup wizard and has
        the following structure::

            {
              "ai": {"provider": "openai", "api_key": "...", "model": "gpt-4o-mini", "enabled": true},
              "threat_intel": {"virustotal_key": "...", "abuseipdb_key": "..."},
              "analysis": {"default_mode": "static", "timeout": 60, "auto_ai": true}
            }

        Returns:
            A fully populated :class:`SentinelConfig` instance.
        """
        # Start from env-var defaults
        base = cls.from_environment()

        # Attempt to load ~/.sentinel/config.json
        config_file = Path.home() / ".sentinel" / "config.json"
        if not config_file.exists():
            return base

        try:
            data = json.loads(config_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return base

        if not isinstance(data, dict):
            return base

        # Map JSON keys to dataclass fields
        ai = data.get("ai", {})
        if isinstance(ai, dict):
            if ai.get("provider") and not base.ai_provider:
                base.ai_provider = str(ai["provider"])
            if ai.get("api_key") and not base.ai_api_key:
                base.ai_api_key = str(ai["api_key"])
            if ai.get("model") and not base.ai_model:
                base.ai_model = str(ai["model"])
            if ai.get("endpoint") and not base.ai_endpoint:
                base.ai_endpoint = str(ai["endpoint"])
            if ai.get("enabled") and not base.ai_enabled:
                base.ai_enabled = bool(ai["enabled"])

        ti = data.get("threat_intel", {})
        if isinstance(ti, dict):
            if ti.get("virustotal_key") and not base.virustotal_api_key:
                base.virustotal_api_key = str(ti["virustotal_key"])
            if ti.get("abuseipdb_key") and not base.abuseipdb_api_key:
                base.abuseipdb_api_key = str(ti["abuseipdb_key"])

        analysis = data.get("analysis", {})
        if isinstance(analysis, dict):
            if analysis.get("timeout"):
                base.timeout_sandbox = int(analysis["timeout"])
            if analysis.get("auto_ai") and base.ai_enabled:
                base.ai_enabled = True

        return base

    @classmethod
    def from_file(cls, config_path: str) -> "SentinelConfig":
        """Load a :class:`SentinelConfig` from a YAML file.

        The YAML file values are overlaid on top of whatever
        :meth:`from_sentinel_config` returns, so env vars and
        ``~/.sentinel/config.json`` act as base layers.

        Args:
            config_path: Path to the YAML configuration file.

        Returns:
            A fully populated :class:`SentinelConfig` instance.

        Raises:
            ConfigError: When the file does not exist or is invalid.
        """
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"Configuration file not found: {config_path}")
        if not path.is_file():
            raise ConfigError(f"Configuration path is not a file: {config_path}")

        try:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse configuration file {config_path!r}: {exc}") from exc

        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(
                f"Configuration file {config_path!r} must contain a top-level mapping, "
                f"got {type(data).__name__!r}"
            )

        # Start from the sentinel config (env + config.json) as the base.
        base = cls.from_sentinel_config()
        merged = _merge_dataclass_dict(base, data)

        try:
            return cls(**merged)
        except TypeError as exc:
            raise ConfigError(f"Invalid configuration keys in {config_path!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# Internal merge helper
# ---------------------------------------------------------------------------

def _merge_dataclass_dict(
    config: SentinelConfig,
    override: dict[str, Any],
) -> dict[str, Any]:
    """Return a merged dict of *config* fields with *override* values applied.

    Args:
        config:   The base :class:`SentinelConfig` instance.
        override: Key/value pairs from a YAML file (or any external source).

    Returns:
        A plain ``dict`` suitable for unpacking into ``SentinelConfig(**...)``.
    """
    current: dict[str, Any] = {
        name: getattr(config, name) for name in config.__dataclass_fields__
    }
    current.update(override)
    return current
