"""
Result caching for Supply Chain Sentinel.

Uses diskcache for persistent, thread-safe caching of analysis results.
Cache key is derived from package name + version + analysis mode.
Default TTL: 24 hours.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from src.core.python.logging_config import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Cache configuration
# ---------------------------------------------------------------------------

_DEFAULT_TTL = 86400  # 24 hours
_DEFAULT_CACHE_DIR = str(Path.home() / ".sentinel" / "cache")


def _get_cache_dir() -> str:
    return os.getenv("SENTINEL_CACHE_DIR", _DEFAULT_CACHE_DIR)


def _get_ttl() -> int:
    try:
        return int(os.getenv("SENTINEL_CACHE_TTL", str(_DEFAULT_TTL)))
    except ValueError:
        return _DEFAULT_TTL


def _cache_key(package_name: str, version: str, mode: str) -> str:
    """Generate a deterministic cache key."""
    raw = f"{package_name}@{version}:{mode}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Cache class
# ---------------------------------------------------------------------------

class ResultCache:
    """Persistent analysis result cache backed by diskcache.

    Usage::

        cache = ResultCache()
        key = cache.make_key("lodash", "4.17.21", "static")

        # Check cache
        result = cache.get(key)
        if result is not None:
            return result

        # ... run analysis ...
        cache.set(key, result)
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled
        self._cache = None

        if not enabled:
            return

        try:
            import diskcache
            cache_dir = _get_cache_dir()
            Path(cache_dir).mkdir(parents=True, exist_ok=True)
            self._cache = diskcache.Cache(
                cache_dir,
                size_limit=500 * 1024 * 1024,  # 500 MB max
                eviction_policy="least-recently-used",
            )
            _logger.debug("Cache initialized at %s", cache_dir)
        except Exception as exc:
            _logger.warning("Failed to initialize cache: %s", exc)
            self.enabled = False

    @staticmethod
    def make_key(package_name: str, version: str, mode: str) -> str:
        """Create a cache key from package info."""
        return _cache_key(package_name, version or "latest", mode)

    def get(self, key: str) -> dict[str, Any] | None:
        """Retrieve cached result, or None if not cached / expired."""
        if not self.enabled or self._cache is None:
            return None

        try:
            cached = self._cache.get(key)
            if cached is None:
                return None

            # Validate structure
            if not isinstance(cached, dict):
                return None

            # Check TTL
            cached_at = cached.get("_cached_at", 0)
            ttl = _get_ttl()
            if time.time() - cached_at > ttl:
                self._cache.delete(key)
                return None

            _logger.info("Cache HIT for key %s", key[:12])
            result = cached.get("result")
            if result:
                result["_from_cache"] = True
                result["_cached_at"] = cached_at
            return result

        except Exception as exc:
            _logger.debug("Cache read error: %s", exc)
            return None

    def set(self, key: str, result: dict[str, Any]) -> None:
        """Store analysis result in cache."""
        if not self.enabled or self._cache is None:
            return

        try:
            entry = {
                "result": result,
                "_cached_at": time.time(),
            }
            ttl = _get_ttl()
            self._cache.set(key, entry, expire=ttl)
            _logger.debug("Cache SET for key %s (TTL=%ds)", key[:12], ttl)
        except Exception as exc:
            _logger.debug("Cache write error: %s", exc)

    def clear(self) -> int:
        """Clear all cached results. Returns count of items cleared."""
        if self._cache is None:
            return 0
        try:
            count = len(self._cache)
            self._cache.clear()
            _logger.info("Cache cleared (%d items)", count)
            return count
        except Exception:
            return 0

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        if self._cache is None:
            return {"enabled": False, "items": 0, "size_bytes": 0}

        try:
            return {
                "enabled": True,
                "items": len(self._cache),
                "size_bytes": self._cache.volume(),
                "directory": _get_cache_dir(),
                "ttl_seconds": _get_ttl(),
            }
        except Exception:
            return {"enabled": True, "items": 0, "size_bytes": 0}

    def close(self) -> None:
        """Close the cache database."""
        if self._cache is not None:
            try:
                self._cache.close()
            except Exception:
                pass
