"""Behavioral rule engine for syscall/file/capability traces."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Rule:
    """Single behavioral rule."""

    name: str
    action: str
    conditions: list[dict[str, Any]]
    severity: str


DEFAULT_RULES: dict[str, Any] = {
    "rules": [
        {
            "name": "no_network_egress",
            "action": "BLOCK",
            "severity": "CRITICAL",
            "conditions": [
                {
                    "type": "syscall",
                    "name": "connect",
                    "allowed_ports": [80, 443],
                    "allowed_domains": ["registry.npmjs.org"],
                }
            ],
        },
        {
            "name": "no_credential_access",
            "action": "BLOCK",
            "severity": "CRITICAL",
            "conditions": [
                {
                    "type": "file_access",
                    "paths": [
                        "/root/.ssh/id_rsa",
                        "/root/.aws/credentials",
                        "/etc/shadow",
                        "/etc/passwd",
                    ],
                    "operation": "openat",
                }
            ],
        },
        {
            "name": "no_privilege_escalation",
            "action": "BLOCK",
            "severity": "CRITICAL",
            "conditions": [
                {
                    "type": "capability_check",
                    "denied": ["CAP_SYS_ADMIN", "CAP_SETUID", "CAP_NET_ADMIN"],
                }
            ],
        },
        {
            "name": "detect_sandbox_escape",
            "action": "ALERT",
            "severity": "HIGH",
            "conditions": [
                {
                    "type": "file_access",
                    "paths": ["/.dockerenv", "/.containerenv"],
                    "operation": "openat",
                }
            ],
        },
    ]
}


class BehavioralRuleEngine:
    """Enforce behavioral contracts during package analysis."""

    def __init__(self, rules_file: str = "config/rules/behavioral_rules.json"):
        self.rules_file = Path(rules_file)
        self.rules: list[Rule] = []
        self.load_rules()

    def load_rules(self) -> None:
        if not self.rules_file.exists():
            self._create_default_rules()
        with self.rules_file.open("r", encoding="utf-8") as handle:
            rules_dict = json.load(handle)

        self.rules = [
            Rule(
                name=rule_data["name"],
                action=rule_data["action"],
                conditions=rule_data["conditions"],
                severity=rule_data.get("severity", "MEDIUM"),
            )
            for rule_data in rules_dict.get("rules", [])
        ]

    def _create_default_rules(self) -> None:
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
        with self.rules_file.open("w", encoding="utf-8") as handle:
            json.dump(DEFAULT_RULES, handle, indent=2)

    def evaluate_trace_events(self, trace_events: list[dict[str, Any]]) -> dict[str, Any]:
        violations: dict[str, Any] = {
            "total_events": len(trace_events),
            "violations": [],
            "alerts": [],
            "summary": {},
        }

        for event in trace_events:
            for rule in self.rules:
                if not self._check_rule(rule, event):
                    continue
                record = {
                    "rule": rule.name,
                    "action": rule.action,
                    "severity": rule.severity,
                    "event": event,
                }
                if rule.action == "BLOCK":
                    violations["violations"].append(record)
                else:
                    violations["alerts"].append(record)

        violations["summary"] = {
            "critical_violations": len(
                [entry for entry in violations["violations"] if entry["severity"] == "CRITICAL"]
            ),
            "total_violations": len(violations["violations"]),
            "total_alerts": len(violations["alerts"]),
            "should_block": len(violations["violations"]) > 0,
        }
        return violations

    def _check_rule(self, rule: Rule, event: dict[str, Any]) -> bool:
        for condition in rule.conditions:
            condition_type = condition.get("type")
            if condition_type == "syscall" and self._check_syscall_condition(condition, event):
                return True
            if condition_type == "file_access" and self._check_file_condition(condition, event):
                return True
            if condition_type == "capability_check" and self._check_capability_condition(
                condition, event
            ):
                return True
        return False

    def _check_syscall_condition(self, condition: dict[str, Any], event: dict[str, Any]) -> bool:
        if event.get("syscall") != condition.get("name"):
            return False
        port = event.get("port")
        destination = str(event.get("destination", ""))
        allowed_ports = condition.get("allowed_ports", [])
        allowed_domains = condition.get("allowed_domains", [])
        if port in allowed_ports and any(domain in destination for domain in allowed_domains):
            return False
        return True

    def _check_file_condition(self, condition: dict[str, Any], event: dict[str, Any]) -> bool:
        if event.get("syscall") != condition.get("operation"):
            return False
        file_path = str(event.get("path", ""))
        return any(file_path.startswith(pattern) for pattern in condition.get("paths", []))

    def _check_capability_condition(self, condition: dict[str, Any], event: dict[str, Any]) -> bool:
        if event.get("type") != "capability_change":
            return False
        return event.get("capability") in condition.get("denied", [])
