from __future__ import annotations

import importlib.util
import json
import os
from typing import Any

from .models import ScanReport

DEFAULT_MODEL = "grok-4.20-reasoning"

AI_ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "severity_label": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "likely_intent": {"type": "string"},
        "notable_signals": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 6,
        },
        "remediation": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 5,
        },
    },
    "required": [
        "summary",
        "severity_label",
        "confidence",
        "likely_intent",
        "notable_signals",
        "remediation",
    ],
}

CORPUS_ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string"},
        "risk_posture": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "recurring_patterns": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 6,
        },
        "priority_actions": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 5,
        },
        "watchlist_packages": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 8,
        },
    },
    "required": [
        "summary",
        "risk_posture",
        "confidence",
        "recurring_patterns",
        "priority_actions",
        "watchlist_packages",
    ],
}


def maybe_generate_ai_analysis(
    report: ScanReport,
    enabled: bool,
    model: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    if not enabled:
        return {"status": "skipped", "reason": "AI summary not requested"}

    return _run_structured_ai_analysis(
        enabled=enabled,
        model=model,
        schema=AI_ANALYSIS_SCHEMA,
        developer_prompt=(
            "You are Grok, a highly intelligent, helpful AI assistant acting as a supply-chain security analyst. "
            "Summarize scan reports clearly and conservatively. "
            "Do not change the reported allow/warn/block decision. "
            "Base your answer only on the provided scan report."
        ),
        user_prompt=_build_report_prompt(report),
    )


def maybe_generate_ai_corpus_analysis(
    corpus_summary: dict[str, Any],
    enabled: bool,
    model: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    if not enabled:
        return {"status": "skipped", "reason": "AI corpus triage not requested"}

    return _run_structured_ai_analysis(
        enabled=enabled,
        model=model,
        schema=CORPUS_ANALYSIS_SCHEMA,
        developer_prompt=(
            "You are Grok, a highly intelligent, helpful AI assistant acting as a supply-chain incident triage analyst. "
            "Review batches of scan reports, identify recurring patterns, and propose concrete next actions. "
            "Do not invent evidence and do not override deterministic scan decisions."
        ),
        user_prompt=_build_corpus_prompt(corpus_summary),
    )


def _run_structured_ai_analysis(
    enabled: bool,
    model: str | None,
    schema: dict[str, Any],
    developer_prompt: str,
    user_prompt: str,
) -> dict[str, Any]:
    if not enabled:
        return {"status": "skipped", "reason": "AI analysis not requested"}

    api_key = os.getenv("XAI_API_KEY")
    if not api_key:
        return {"status": "skipped", "reason": "XAI_API_KEY is not set"}

    if not importlib.util.find_spec("xai_sdk"):
        return {"status": "error", "reason": "xai_sdk is not installed"}

    target_model = model or os.getenv("SENTINEL_XAI_MODEL") or DEFAULT_MODEL

    try:
        content = _sample_grok_response(
            api_key=api_key,
            model=target_model,
            developer_prompt=developer_prompt,
            user_prompt=_wrap_json_instruction(user_prompt, schema),
        )
        structured = json.loads(content)
    except json.JSONDecodeError as exc:
        return {
            "status": "error",
            "reason": f"Could not parse Grok JSON response: {exc}",
            "model": target_model,
            "raw_output": content[-2000:] if isinstance(content, str) else "",
        }
    except Exception as exc:  # pragma: no cover - kept broad for SDK/runtime failures
        return {
            "status": "error",
            "reason": f"xAI request failed: {exc}",
            "model": target_model,
        }

    return {
        "status": "completed",
        "provider": "xai",
        "model": target_model,
        **structured,
    }


def _sample_grok_response(api_key: str, model: str, developer_prompt: str, user_prompt: str) -> str:
    from xai_sdk import Client
    from xai_sdk.chat import system, user

    client = Client(api_key=api_key)
    chat = client.chat.create(model=model)
    chat.append(system(developer_prompt))
    chat.append(user(user_prompt))
    response = chat.sample()
    return str(response.content)


def _wrap_json_instruction(prompt: str, schema: dict[str, Any]) -> str:
    return (
        f"{prompt}\n\n"
        "Return only valid JSON matching this schema. "
        "Do not include markdown fences or extra commentary.\n\n"
        f"{json.dumps(schema, indent=2)}"
    )


def _build_report_prompt(report: ScanReport) -> str:
    compact_report = {
        "package": report.package,
        "version": report.version,
        "decision": report.decision,
        "static_score": report.static_score,
        "static_findings": [finding.to_dict() for finding in report.static_findings],
        "dynamic_findings": [finding.to_dict() for finding in report.dynamic_findings],
        "rule_hits": [rule_hit.to_dict() for rule_hit in report.rule_hits],
        "sandbox_metadata": report.sandbox_metadata,
        "installation": report.installation,
    }
    return (
        "Analyze this Supply Chain Sentinel report. "
        "Explain the likely risk, key signals, and next actions. "
        "Keep the analysis grounded in the provided findings.\n\n"
        f"{json.dumps(compact_report, indent=2)}"
    )


def _build_corpus_prompt(corpus_summary: dict[str, Any]) -> str:
    return (
        "Analyze this batch summary of Supply Chain Sentinel reports. "
        "Highlight recurring signals, overall risk posture, priority follow-up actions, "
        "and any packages that should stay on a watchlist.\n\n"
        f"{json.dumps(corpus_summary, indent=2)}"
    )
