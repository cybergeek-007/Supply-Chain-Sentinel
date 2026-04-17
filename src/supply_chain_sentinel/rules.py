from __future__ import annotations

import json
from pathlib import Path

from .models import Decision, Finding, RuleHit

ACTION_PRIORITY = {"allow": 0, "warn": 1, "block": 2}


def load_rules(path: Path) -> dict[str, list[dict[str, object]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("rules file must contain an object keyed by category")
    normalized: dict[str, list[dict[str, object]]] = {}
    for category, rules in payload.items():
        if not isinstance(category, str) or not isinstance(rules, list):
            raise ValueError("each rule category must map to a list of rules")
        normalized[category] = [rule for rule in rules if isinstance(rule, dict)]
    return normalized


def evaluate_rules(
    rules: dict[str, list[dict[str, object]]],
    findings: list[Finding],
    static_score: int,
    static_threshold: int,
) -> tuple[Decision, list[RuleHit]]:
    hits: list[RuleHit] = []
    decision: Decision = "allow"

    if static_score >= static_threshold:
        decision = "block"

    for finding in findings:
        for rule in rules.get(finding.category, []):
            if not rule.get("enabled", True):
                continue
            if _matches_rule(rule, finding):
                action = str(rule.get("action", "warn"))
                if action not in ACTION_PRIORITY:
                    continue
                decision = _higher_action(decision, action)  # type: ignore[arg-type]
                hits.append(
                    RuleHit(
                        rule_id=str(rule.get("id", "unknown-rule")),
                        action=action,  # type: ignore[arg-type]
                        severity=str(rule.get("severity", finding.severity)),
                        category=finding.category,
                        finding_kind=finding.kind,
                        message=str(rule.get("description", finding.message)),
                    )
                )
    return decision, hits


def _matches_rule(rule: dict[str, object], finding: Finding) -> bool:
    conditions = rule.get("conditions", {})
    if not isinstance(conditions, dict):
        return False

    finding_kinds = conditions.get("finding_kinds")
    if finding_kinds and finding.kind not in set(finding_kinds):
        return False

    minimum_score = conditions.get("minimum_score")
    if isinstance(minimum_score, (int, float)) and finding.score < minimum_score:
        return False

    severities = conditions.get("severities")
    if severities and finding.severity not in set(severities):
        return False

    evidence_contains = conditions.get("evidence_contains")
    if isinstance(evidence_contains, dict):
        for key, needle in evidence_contains.items():
            haystack = str(finding.evidence.get(key, ""))
            if str(needle) not in haystack:
                return False

    return True


def _higher_action(left: Decision, right: Decision) -> Decision:
    return left if ACTION_PRIORITY[left] >= ACTION_PRIORITY[right] else right
