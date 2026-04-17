from __future__ import annotations

import unittest
from pathlib import Path

from supply_chain_sentinel.models import Finding
from supply_chain_sentinel.rules import evaluate_rules, load_rules


class RuleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = load_rules(Path(__file__).resolve().parents[1] / "config" / "default_rules.json")

    def test_block_rule_triggers_on_network_findings(self) -> None:
        findings = [
            Finding(
                category="network",
                kind="network_connect",
                severity="high",
                message="Outbound connection attempt",
                score=45,
                evidence={},
            )
        ]
        decision, hits = evaluate_rules(self.rules, findings, static_score=10, static_threshold=80)
        self.assertEqual(decision, "block")
        self.assertTrue(hits)

    def test_static_threshold_blocks_even_without_rule_hits(self) -> None:
        decision, hits = evaluate_rules({}, [], static_score=90, static_threshold=80)
        self.assertEqual(decision, "block")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
