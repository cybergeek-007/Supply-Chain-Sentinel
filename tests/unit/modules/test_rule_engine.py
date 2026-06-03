from __future__ import annotations

from pathlib import Path

from src.modules.rule_engine import BehavioralRuleEngine


def test_load_default_rules(tmp_path: Path) -> None:
    engine = BehavioralRuleEngine(str(tmp_path / "rules.json"))
    names = [rule.name for rule in engine.rules]
    assert "no_network_egress" in names
    assert "no_credential_access" in names


def test_detect_credential_theft_attempt(tmp_path: Path) -> None:
    engine = BehavioralRuleEngine(str(tmp_path / "rules.json"))
    trace_events = [{"syscall": "openat", "path": "/root/.ssh/id_rsa", "pid": 12345}]
    result = engine.evaluate_trace_events(trace_events)
    assert result["summary"]["should_block"] is True
    assert result["summary"]["critical_violations"] > 0


def test_allow_legitimate_network_access(tmp_path: Path) -> None:
    engine = BehavioralRuleEngine(str(tmp_path / "rules.json"))
    trace_events = [{"syscall": "connect", "destination": "registry.npmjs.org:443", "port": 443}]
    result = engine.evaluate_trace_events(trace_events)
    assert result["summary"]["should_block"] is False


def test_detect_privilege_escalation(tmp_path: Path) -> None:
    engine = BehavioralRuleEngine(str(tmp_path / "rules.json"))
    trace_events = [{"type": "capability_change", "capability": "CAP_SYS_ADMIN"}]
    result = engine.evaluate_trace_events(trace_events)
    assert result["summary"]["should_block"] is True
