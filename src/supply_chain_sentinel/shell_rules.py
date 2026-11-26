"""Small lexical checks for shell evidence; never interpret or execute commands."""

from __future__ import annotations

import re
import shlex

JS_STRING = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`")
SUBSTITUTION = re.compile(
    r"(?<!\\)\$\(\s*(hostname|whoami|pwd|id\s+-un)\s*\)"
    r"|(?<!\\)`\s*(hostname|whoami|pwd|id\s+-un)\s*`"
)


def _unquote(word: str) -> str:
    if len(word) >= 2 and word[0] in "'\"" and word[-1] == word[0]:
        return word[1:-1]
    return word


def _identities(word: str) -> set[str]:
    # Single-quoted content and escaped substitutions were masked before lexing.
    # Retain a conservative fallback for unsupported mixed quote forms.
    if "'" in word:
        return set()
    return {re.sub(r"\s+", " ", a or b) for a, b in SUBSTITUTION.findall(word)}


def _mask_shell_literals(command: str) -> str:
    """Hide inactive substitutions before shlex removes shell quote markers."""
    result = []
    quote = ""
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = ""
                result.append(char)
            else:
                result.append("_" if char in "$`" else char)
        elif char == "\\" and index + 1 < len(command):
            following = command[index + 1]
            result.append("__" if following in "$`" else char + following)
            index += 1
        else:
            if char == '"':
                quote = "" if quote == '"' else '"'
            elif char == "'" and not quote:
                quote = "'"
            result.append(char)
        index += 1
    return "".join(result)


def install_host_exfil(command: str) -> bool:
    """Match curl transmitting at least two explicit host identity substitutions.

    Recognizes simple HTTP(S) URL arguments and curl data flags in one shell
    command. No variable expansion, alias inference, or name-based exemptions.
    """
    lexer = shlex.shlex(_mask_shell_literals(command), posix=True, punctuation_chars=";&|\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return False
    groups: list[list[str]] = [[]]
    for token in tokens:
        if token and all(char in ";&|\n" for char in token):
            groups.append([])
        else:
            groups[-1].append(token)
    data_flags = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"}
    for group in groups:
        if not group or _unquote(group[0]).rsplit("/", 1)[-1] != "curl":
            continue
        identities: set[str] = set()
        has_url = False
        for index, word in enumerate(group[1:], 1):
            value = _unquote(word)
            if value.startswith(("https://", "http://")):
                has_url = True
                identities.update(_identities(word))
            if group[index - 1] in data_flags or any(
                value.startswith(flag + "=") for flag in data_flags if flag.startswith("--")
            ):
                identities.update(_identities(word))
        if has_url and len(identities) >= 2:
            return True
    return False
