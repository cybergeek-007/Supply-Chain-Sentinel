"""Post-score development investigation. Run only in isolated containers.

Emit hashes, file metadata and semantic categories, never payloads or snippets.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shlex
import tarfile
import time
import zipfile
from collections import Counter
from pathlib import Path

import tree_sitter_javascript as javascript
from tree_sitter import Language, Parser

import worker
from supply_chain_sentinel.adapters.npm import NpmAdapter
from supply_chain_sentinel.config import Config
from supply_chain_sentinel.models import RULESET_VERSION, classify
from supply_chain_sentinel.models import ScanError
from supply_chain_sentinel.rules import analyze, mask_comments

ROOT = worker.ROOT
PATTERNS = {
    "environment": r"process\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])",
    "shell_module": r"child_process",
    "exec": r"\bexec(?:Sync)?\s*\(",
    "spawn": r"\bspawn(?:Sync)?\s*\(",
    "network": r"https?|\bfetch\b|\baxios\b|\bdns\b",
    "eval": r"\b(?:eval|Function)\s*\(",
    "encoding": r"base64|\batob\b|fromCharCode",
    "hex_identifiers": r"\b_0x[0-9a-fA-F]+",
    "filesystem": r"readFile|writeFile|readdir",
    "credential_paths": r"\.npmrc|\.aws|\.ssh",
    "host_identity": r"hostname|userInfo|homedir|whoami",
    "curl_wget": r"\b(?:curl|wget)\b",
}


def features(text: str) -> dict[str, int]:
    return {key: len(re.findall(pattern, text)) for key, pattern in PATTERNS.items()}


def semantic_details(text: str) -> dict[str, object]:
    words = re.findall(r"[A-Za-z_][A-Za-z_0-9]*", text)
    vocabulary = set(
        "node bun Bun spawn spawnSync exec execSync powershell cmd sh bash curl wget whoami hostname uname pwd id base64 eval require import https http dns os net fetch request get lookup resolve write end userInfo homedir username cwd POST GET env process".split()
    )
    return {
        "known_symbols": {word: words.count(word) for word in sorted(vocabulary) if word in words},
        "shell_data_flag": bool(
            re.search(r"(?<!\S)(?:-d|--data(?:-raw|-binary|-urlencode)?)(?:\s|=)", text)
        ),
        "command_substitution": bool(re.search(r"\$\(|`", text)),
        "url_command_substitution": bool(re.search(r"https?://[^\s]*\$\(", text)),
        "dollar_variables": len(re.findall(r"\$[A-Za-z_][\w]*", text)),
        "base64_option": bool(re.search(r"(?i)-(?:enc|encodedcommand)\b", text)),
    }


def inline_spawn_arguments(command: str) -> list[dict[str, object]]:
    """Describe argv literals without exporting nested code or executing it."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    if "-e" not in tokens or tokens.index("-e") + 1 >= len(tokens):
        return []
    script = tokens[tokens.index("-e") + 1]
    tree = Parser(Language(javascript.language())).parse(script.encode())
    stack = [tree.root_node]
    calls = []
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if not function or not function.text.decode().endswith(".spawn"):
            continue
        args = node.child_by_field_name("arguments")
        if not args:
            continue
        arrays = [child for child in args.named_children if child.type == "array"]
        for array in arrays:
            values = []
            for item in array.named_children:
                text = item.text.decode()
                value = text[1:-1] if item.type == "string" else ""
                if re.fullmatch(r"[A-Za-z0-9_@./:-]{1,160}", value):
                    values.append({"kind": "argv-or-package-identifier", "value": value})
                else:
                    values.append(
                        {
                            "kind": item.type,
                            "bytes": len(item.text),
                            "sha256": hashlib.sha256(item.text).hexdigest(),
                        }
                    )
            calls.append({"operation": "spawn", "argv": values})
    return calls


def referenced_file_structure(files: dict[str, bytes], scripts: dict[str, dict]) -> list[dict]:
    references = set()
    for script in scripts.values():
        references.update(script["node_files"])
        for call in script["inline_spawn_arguments"]:
            references.update(arg["value"] for arg in call["argv"] if "value" in arg)
    output = []
    for name in sorted(references):
        name = name.removeprefix("./")
        if name not in files:
            continue
        data = files[name]
        source = data.decode("utf-8", errors="replace")
        details = {
            "file": name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "hex_escapes": len(re.findall(r"\\x[0-9a-fA-F]{2}", source)),
            "unicode_escapes": len(re.findall(r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\})", source)),
            "non_ascii_characters": sum(ord(char) > 127 for char in source),
            "features": features(source),
        }
        if len(data) <= 1024 * 1024:
            tree = Parser(Language(javascript.language())).parse(data)
            stack = [tree.root_node]
            types: Counter[str] = Counter()
            largest_string = 0
            while stack:
                node = stack.pop()
                types[node.type] += 1
                stack.extend(node.named_children)
                if node.type in {"string", "template_string"}:
                    largest_string = max(largest_string, node.end_byte - node.start_byte)
            details.update(
                {
                    "javascript_parse_error": tree.root_node.has_error,
                    "node_types": dict(types.most_common(15)),
                    "largest_string_bytes": largest_string,
                }
            )
            if len(data) < 512:
                labels: dict[bytes, int] = {}

                def shape(node):
                    if node.type in {"identifier", "property_identifier"}:
                        name = node.text.decode()
                        return {
                            "type": node.type,
                            "symbol": name
                            if name in {"fetch", "eval", "then", "text", "json", "Function"}
                            else f"local-{labels.setdefault(node.text, len(labels))}",
                        }
                    if node.type == "string":
                        return {"type": "string", "bytes": len(node.text), "value": "redacted"}
                    return {
                        "type": node.type,
                        "children": [shape(child) for child in node.named_children],
                    }

                details["normalized_syntax"] = shape(tree.root_node)
        output.append(details)
    return output


def archive_inventory(record: dict[str, object], config: Config) -> list[dict[str, object]]:
    if record["cohort"] == "benign":
        return []
    entries = []
    with zipfile.ZipFile(ROOT / "samples" / str(record["file"])) as archive:
        for member in archive.infolist():
            if member.filename.endswith((".tgz", ".tar.gz")):
                data = archive.read(member, pwd=b"infected")
                limit = config.max_unpacked_bytes + config.max_files * 1024 + 1024 * 1024
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as zipped:
                    raw = zipped.read(limit + 1)
                if len(raw) > limit:
                    raise ValueError("Archive exceeds decompression cap")
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
                    for entry in tar:
                        if entry.isfile() and not entry.name.endswith(
                            (
                                ".js",
                                ".mjs",
                                ".cjs",
                                ".jsx",
                                ".ts",
                                ".tsx",
                                ".json",
                                ".md",
                                ".map",
                                ".txt",
                                ".yml",
                                ".yaml",
                                ".html",
                                ".css",
                                ".png",
                                ".svg",
                                ".jpg",
                            )
                        ):
                            entries.append({"file": entry.name, "bytes": entry.size})
    return entries[:100]


def fetch() -> None:
    manifest = json.loads(Path("/opt/benchmarks/investigation-manifest.json").read_text())
    (ROOT / "samples").mkdir(exist_ok=True)
    for record in manifest["records"]:
        if record["cohort"] == "benign":
            adapter = NpmAdapter(Config(cache_dir=ROOT / "cache"))
            try:
                artifact = adapter.acquire(record["spec"], offline=True)
            except ScanError:
                artifact = adapter.acquire(record["spec"])
            if artifact.sha256 != record["sha256"]:
                raise RuntimeError("Benign archive hash differs from recorded holdout")
        else:
            existing = ROOT / "samples" / record["file"]
            data = (
                existing.read_bytes()
                if existing.exists()
                else worker.get(record["url"], 25 * 1024 * 1024)
            )
            if hashlib.sha256(data).hexdigest() != record["zip_sha256"]:
                raise RuntimeError("Encrypted sample hash differs from recorded holdout")
            (ROOT / "samples" / record["file"]).write_bytes(data)
        print(json.dumps({"verified": record.get("spec", record.get("path"))}), flush=True)
    (ROOT / "manifest.json").write_text(json.dumps(manifest))
    print(json.dumps({"acquired": len(manifest["records"]), "hashes_verified": True}))


def shell_context(source: str) -> list[dict[str, object]]:
    matches = list(
        re.finditer(r"\b(?:curl|wget)\b[^\n;]{0,400}\|\s*(?:sh|bash)\b", mask_comments(source))
    )[:10]
    if not matches:
        return []
    tree = Parser(Language(javascript.language())).parse(source.encode())
    result = []
    for match in matches:
        offset = len(source[: match.start()].encode())
        node = tree.root_node.descendant_for_byte_range(offset, offset + 1)
        chain = []
        while node is not None and len(chain) < 10:
            entry = {"node": node.type}
            if node.type in {"call_expression", "new_expression"}:
                callee = node.child_by_field_name("function") or node.child_by_field_name(
                    "constructor"
                )
                terminal = (
                    re.findall(r"[A-Za-z_$][\w$]*", callee.text.decode())[-1:] if callee else []
                )
                entry["callee_category"] = (
                    terminal[0]
                    if terminal
                    and terminal[0]
                    in {"exec", "execSync", "spawn", "spawnSync", "log", "warn", "error", "Error"}
                    else "other"
                )
            chain.append(entry)
            node = node.parent
        result.append({"line": source.count("\n", 0, match.start()) + 1, "ancestors": chain})
    return result


def inspect() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    config = Config(cache_dir=ROOT / "cache")
    output = []
    for record in manifest["records"]:
        artifact = (
            NpmAdapter(config).acquire(record["spec"], offline=True)
            if record["cohort"] == "benign"
            else worker.read_sample(ROOT / "samples" / record["file"], config)
        )
        package = json.loads(artifact.files["package.json"])
        sources = []
        for name, data in artifact.files.items():
            if not name.endswith((".js", ".mjs", ".cjs", ".ts", ".sh")):
                continue
            source = data.decode("utf-8", errors="replace")
            counts = features(source)
            if any(counts.values()):
                sources.append(
                    {
                        "file": name,
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "features": counts,
                        "semantics": semantic_details(source) if len(data) < 10000 else {},
                        "shell_context": shell_context(source),
                    }
                )
        scripts = {
            name: {
                "features": features(command),
                "semantics": semantic_details(command),
                "inline_spawn_arguments": inline_spawn_arguments(command),
                "node_files": re.findall(r'\bnode\s+["\']?([\w./-]+)', command),
            }
            for name, command in package.get("scripts", {}).items()
            if name in {"preinstall", "install", "postinstall", "prepare"}
        }
        start = time.perf_counter()
        findings = analyze(artifact, config)
        score, verdict = classify(findings)
        duration = round((time.perf_counter() - start) * 1000, 3)
        output.append(
            {
                "package": artifact.name,
                "version": artifact.version,
                "sha256": artifact.sha256,
                "cohort": record["cohort"],
                "ruleset": RULESET_VERSION,
                "score": score,
                "verdict": verdict,
                "scan_ms": duration,
                "lifecycle": scripts,
                "referenced_file_structure": referenced_file_structure(artifact.files, scripts),
                "dependencies": package.get("dependencies", {}),
                "source_file_count": len(artifact.files),
                "other_archive_files": archive_inventory(record, config),
                "interesting_files": sorted(
                    sources, key=lambda item: sum(item["features"].values()), reverse=True
                )[:15],
                "findings": [{"rule": f.rule_id, "file": f.file, "line": f.line} for f in findings],
            }
        )
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("fetch", "inspect"))
    args = parser.parse_args()
    fetch() if args.command == "fetch" else inspect()
