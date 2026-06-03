"""Logging setup for Supply Chain Sentinel."""

from __future__ import annotations

import logging
from typing import Any

from pythonjsonlogger import jsonlogger


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure structured JSON logging for process-wide root logger."""
    root_logger = logging.getLogger()

    for handler in root_logger.handlers:
        if getattr(handler, "_sentinel_json_handler", False):
            root_logger.setLevel(level)
            return root_logger

    import sys
    handler = logging.StreamHandler(stream=sys.stderr)
    formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(analysis_id)s %(package_name)s %(version)s"
    )
    handler.setFormatter(formatter)
    setattr(handler, "_sentinel_json_handler", True)

    root_logger.addHandler(handler)
    root_logger.setLevel(level)
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger, ensuring root is configured first."""
    setup_logging()
    return logging.getLogger(name)


def analysis_context(
    *,
    analysis_id: str,
    package_name: str,
    version: str,
) -> dict[str, Any]:
    """Context payload helper for structured log extras."""
    return {
        "analysis_id": analysis_id,
        "package_name": package_name,
        "version": version,
    }
