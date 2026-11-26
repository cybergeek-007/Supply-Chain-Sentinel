"""Experimental bounded JavaScript data-flow candidate for the sealed benchmark.

This module is deliberately outside the supported runtime. It is a conservative,
file-local taint prototype used to test whether syntax-aware alias tracking adds
useful evidence over the shipping lexical rules. It never executes source.
"""

from __future__ import annotations

from collections.abc import Iterator

import tree_sitter_javascript as javascript
from tree_sitter import Language, Node, Parser

from supply_chain_sentinel.models import Artifact, Finding

MAX_SOURCE_BYTES = 2 * 1024 * 1024
SENSITIVE_EGRESS = "Sensitive data reaches an outbound network call (experimental AST rule)"


def _walk(root: Node) -> Iterator[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _text(node: Node | None) -> str:
    if node is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _string_value(node: Node | None) -> str:
    value = _text(node)
    if len(value) >= 2 and value[0] in "'\"`" and value[-1] == value[0]:
        return value[1:-1]
    return value


def _property(node: Node) -> str:
    if node.type == "member_expression":
        return _text(node.child_by_field_name("property"))
    if node.type == "subscript_expression":
        return _string_value(node.child_by_field_name("index"))
    return ""


def _object(node: Node) -> Node | None:
    if node.type in {"member_expression", "subscript_expression"}:
        return node.child_by_field_name("object")
    return None


def _is_env_access(node: Node) -> bool:
    return (
        node.type in {"member_expression", "subscript_expression"}
        and _text(_object(node)) == "process"
        and _property(node) == "env"
    )


def _is_sensitive_source(node: Node) -> bool:
    if _is_env_access(node):
        return True
    if node.type == "call_expression":
        function = _text(node.child_by_field_name("function"))
        if function.endswith(("readFile", "readFileSync", "readFileSync")):
            args = node.child_by_field_name("arguments")
            if args and any(
                token in _text(child).lower()
                for child in _walk(args)
                for token in (".npmrc", ".aws/credentials", ".ssh/id_rsa")
            ):
                return True
    return any(_is_env_access(child) for child in _walk(node))


def _contains_taint(node: Node, names: set[str]) -> bool:
    return _is_sensitive_source(node) or any(
        child.type in {"identifier", "shorthand_property_identifier"} and _text(child) in names
        for child in _walk(node)
    )


def _network_alias(node: Node) -> bool:
    text = _text(node)
    compact = text.replace(" ", "")
    if compact in {
        "fetch",
        "globalThis.fetch",
        "globalThis['fetch']",
        'globalThis["fetch"]',
        "window.fetch",
        "window['fetch']",
        'window["fetch"]',
        "axios",
    }:
        return True
    return any(
        compact.endswith("." + method)
        for method in ("request", "get", "post", "put", "patch", "createConnection")
    )


def _network_call(node: Node, aliases: set[str]) -> bool:
    if node.type != "call_expression":
        return False
    function = node.child_by_field_name("function")
    if function is None:
        return False
    if function.type == "identifier" and _text(function) in aliases:
        return True
    return _network_alias(function)


def analyze_candidate(artifact: Artifact) -> list[Finding]:
    """Find file-local sensitive-source-to-network flows using syntax nodes.

    This is a benchmark-only prototype. It intentionally over-approximates
    identifier scope and does not resolve imports, interprocedural calls, or
    JavaScript coercion. Results must not be represented as sound taint analysis.
    """
    parser = Parser(Language(javascript.language()))
    findings: list[Finding] = []
    for path, data in artifact.files.items():
        if not path.endswith((".js", ".mjs", ".cjs", ".jsx")) or len(data) > MAX_SOURCE_BYTES:
            continue
        tree = parser.parse(data)
        if tree.root_node.has_error:
            raise ValueError(f"JavaScript parse error in {path}")
        nodes = list(_walk(tree.root_node))
        tainted: set[str] = set()
        network_aliases: set[str] = set()

        # Bounded fixed point for simple local aliases. Over-approximate scope is
        # deliberate in this experiment and should be measured for false alarms.
        for _ in range(8):
            changed = False
            for node in nodes:
                if node.type == "variable_declarator":
                    name = node.child_by_field_name("name")
                    value = node.child_by_field_name("value")
                    if name and name.type == "identifier" and value:
                        identifier = _text(name)
                        if _network_alias(value) and identifier not in network_aliases:
                            network_aliases.add(identifier)
                            changed = True
                        if _contains_taint(value, tainted) and identifier not in tainted:
                            tainted.add(identifier)
                            changed = True
                elif node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left and left.type == "identifier" and right:
                        identifier = _text(left)
                        if _contains_taint(right, tainted) and identifier not in tainted:
                            tainted.add(identifier)
                            changed = True
                        if _network_alias(right) and identifier not in network_aliases:
                            network_aliases.add(identifier)
                            changed = True
            if not changed:
                break

        for node in nodes:
            if not _network_call(node, network_aliases):
                continue
            args = node.child_by_field_name("arguments")
            if args is None or not _contains_taint(args, tainted):
                continue
            findings.append(
                Finding(
                    "ast-sensitive-egress",
                    "high",
                    0.8,
                    SENSITIVE_EGRESS,
                    path,
                    node.start_point.row + 1,
                    "Local syntax tree links a sensitive source to a network call; inspect data flow.",
                )
            )
            break
    return findings
