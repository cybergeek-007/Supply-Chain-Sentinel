from __future__ import annotations

from src.core.python.logger import analysis_context, get_logger, setup_logging


def test_setup_logging_is_idempotent() -> None:
    root = setup_logging()
    count_before = len(root.handlers)
    setup_logging()
    count_after = len(root.handlers)
    assert count_before == count_after


def test_analysis_context_shape() -> None:
    payload = analysis_context(analysis_id="a1", package_name="lodash", version="1.0.0")
    assert payload["analysis_id"] == "a1"
    assert payload["package_name"] == "lodash"
    assert payload["version"] == "1.0.0"


def test_get_logger_returns_named_logger() -> None:
    logger = get_logger("sentinel.tests")
    assert logger.name == "sentinel.tests"
