"""
obfuscation_detector.py
-----------------------
Advanced static obfuscation detector for JavaScript / TypeScript source files.

Scoring heuristics (each contributes a weighted sub-score that is clamped and
combined into a final 0-100 score):

  1.  Identifier entropy        – short random variable names (minification) or
                                  long random names (packer / obfuscator output)
  2.  Hex literal density       – \\x41\\x42 style character escapes
  3.  Bracket notation ratio    – obj['prop'] vs obj.prop
  4.  Base64 string density     – long base64 strings embedded in source
  5.  Hex string density        – long hex strings (deadbeef…)
  6.  Array string packing      – _0x1a=['str1','str2'] patterns (common obfuscator output)
  7.  String.fromCharCode chains
  8.  Unicode escape sequences  – \\u0065\\u0076\\u0061\\u006c spelling out 'eval'
  9.  eval + atob/btoa          – runtime base64 decode then eval
  10. Self-executing complexity  – IIFEs with very high cyclomatic-like complexity
  11. Character frequency        – abnormal character distributions
  12. Anti-analysis tricks       – Date, Math.random() in critical paths, debugger statements
"""

from __future__ import annotations

import collections
import math
import os
import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights (must sum ≤ 100; individual caps prevent single signal
# from dominating the score).
# ---------------------------------------------------------------------------
_WEIGHTS: dict[str, int] = {
    "identifier_entropy":    12,
    "hex_literals":          10,
    "bracket_notation":       8,
    "base64_strings":        12,
    "hex_strings":           10,
    "array_packing":         14,
    "fromcharcode":          10,
    "unicode_escapes":        8,
    "eval_atob":             12,
    "iife_complexity":        6,
    "char_frequency":         4,
    "anti_analysis":          4,
}
assert sum(_WEIGHTS.values()) == 100, "Weights must sum to 100"

# ---------------------------------------------------------------------------
# Pre-compiled patterns
# ---------------------------------------------------------------------------
# Hex character escapes  \x41
_RE_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
# Unicode escapes  \u0041
_RE_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")
# Bracket property access  obj['prop']  or  obj["prop"]
_RE_BRACKET_ACCESS = re.compile(r"""\[\s*['"][^'"]{1,64}['"]\s*\]""")
# Dot property access  obj.prop
_RE_DOT_ACCESS = re.compile(r"\.[a-zA-Z_$][a-zA-Z0-9_$]{0,63}")
# Base64 string: at least 40 chars of valid base64 inside quotes
_RE_BASE64_STR = re.compile(
    r"""['"][A-Za-z0-9+/]{40,}={0,2}['"]"""
)
# Hex string: at least 32 hex chars in a row (looks like a key / hash / payload)
_RE_HEX_STR = re.compile(r"""['"][0-9a-fA-F]{32,}['"]""")
# Array string packing: var _0x1a=['...','...']
_RE_ARRAY_PACK = re.compile(
    r"""(?:var|let|const)\s+_0x[0-9a-fA-F]+\s*=\s*\[(?:\s*['"][^'"]*['"]\s*,?\s*){2,}\]"""
)
# Generic hex-named var: _0x1a2b
_RE_HEX_VAR = re.compile(r"\b_0x[0-9a-fA-F]{2,}\b")
# String.fromCharCode(...)
_RE_FROMCHARCODE = re.compile(
    r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){2,}\d+\s*\)", re.IGNORECASE
)
# eval(atob(...)) or eval(Buffer.from(...,'base64'))
_RE_EVAL_ATOB = re.compile(
    r"""eval\s*\(\s*(?:atob|btoa|Buffer\.from)\s*\(""", re.IGNORECASE
)
# Self-executing / immediately invoked function expressions
_RE_IIFE = re.compile(r"\(function\s*\(", re.IGNORECASE)
# debugger statement
_RE_DEBUGGER = re.compile(r"\bdebugger\b")
# Math.random() or Date usage near control flow
_RE_ANTI_ANALYSIS = re.compile(
    r"""(?:Math\.random\(\)|new\s+Date\s*\(|Date\.now\(\))""", re.IGNORECASE
)
# JS identifiers (exclude keywords) – rough extraction
_RE_IDENTIFIER = re.compile(r"\b([a-zA-Z_$][a-zA-Z0-9_$]{0,64})\b")

_JS_KEYWORDS = frozenset(
    """break case catch class const continue debugger default delete do else export
    extends finally for from function if import in instanceof let new of return
    static super switch this throw try typeof var void while with yield
    undefined null true false async await""".split()
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    counter = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def _is_base64_like(s: str) -> bool:
    """Return True if the string looks like base64 encoded data."""
    if len(s) < 40:
        return False
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    ratio = sum(1 for c in s if c in base64_chars) / len(s)
    return ratio > 0.97 and len(s) % 4 == 0


def _read_file_safe(file_path: str, max_bytes: int = 5 * 1024 * 1024) -> str:
    """Read a file, limiting to *max_bytes* to avoid memory issues."""
    size = os.path.getsize(file_path)
    read_bytes = min(size, max_bytes)
    with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read(read_bytes)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ObfuscationDetector:
    """
    Detect obfuscation in JavaScript / TypeScript source files using
    multiple static heuristics.

    Usage::

        detector = ObfuscationDetector()
        result = detector.analyze_file("dist/bundle.js")
        print(result['score'], result['verdict'])
    """

    VERDICT_THRESHOLDS = {
        "clean": 30,        # score < 30  → clean
        "suspicious": 60,   # 30 ≤ score < 60 → suspicious
        # score ≥ 60 → obfuscated
    }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: str) -> dict[str, Any]:
        """
        Analyse a single JS/TS file for obfuscation indicators.

        Parameters
        ----------
        file_path:
            Absolute or relative path to the file to analyse.

        Returns
        -------
        dict with keys:
            ``score``      – int 0-100 (higher = more obfuscated)
            ``verdict``    – 'clean' | 'suspicious' | 'obfuscated'
            ``detections`` – list of detection dicts (name, weight, evidence)
            ``file``       – canonical file path
        """
        canonical = os.path.realpath(file_path)
        detections: list[dict[str, Any]] = []

        try:
            source = _read_file_safe(canonical)
        except OSError as exc:
            logger.error("Cannot read %s: %s", canonical, exc)
            return {
                "score": 0,
                "verdict": "clean",
                "detections": [],
                "file": canonical,
                "error": str(exc),
            }

        # Strip single-line and block comments to reduce false positives
        # (we keep a copy of the raw source for comment-based detection)
        stripped = self._strip_comments(source)

        # Run each heuristic
        sub_scores: dict[str, float] = {}

        sub_scores["identifier_entropy"], det = self._check_identifier_entropy(stripped)
        detections.extend(det)

        sub_scores["hex_literals"], det = self._check_hex_literals(stripped)
        detections.extend(det)

        sub_scores["bracket_notation"], det = self._check_bracket_notation(stripped)
        detections.extend(det)

        sub_scores["base64_strings"], det = self._check_base64_strings(stripped)
        detections.extend(det)

        sub_scores["hex_strings"], det = self._check_hex_strings(stripped)
        detections.extend(det)

        sub_scores["array_packing"], det = self._check_array_packing(stripped)
        detections.extend(det)

        sub_scores["fromcharcode"], det = self._check_fromcharcode(stripped)
        detections.extend(det)

        sub_scores["unicode_escapes"], det = self._check_unicode_escapes(source)
        detections.extend(det)

        sub_scores["eval_atob"], det = self._check_eval_atob(stripped)
        detections.extend(det)

        sub_scores["iife_complexity"], det = self._check_iife_complexity(stripped)
        detections.extend(det)

        sub_scores["char_frequency"], det = self._check_char_frequency(stripped)
        detections.extend(det)

        sub_scores["anti_analysis"], det = self._check_anti_analysis(stripped)
        detections.extend(det)

        # Combine weighted sub-scores → total 0-100
        total = 0.0
        for key, weight in _WEIGHTS.items():
            raw = sub_scores.get(key, 0.0)
            # raw is 0.0-1.0 normalized; contribution = raw * weight
            total += min(raw, 1.0) * weight
        score = min(100, int(round(total)))

        verdict = self._score_to_verdict(score)

        return {
            "score": score,
            "verdict": verdict,
            "detections": detections,
            "file": canonical,
        }

    # ------------------------------------------------------------------
    # Private – comment stripping
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_comments(source: str) -> str:
        """Naively remove // and /* */ comments (good enough for heuristics)."""
        # Remove block comments
        source = re.sub(r"/\*.*?\*/", " ", source, flags=re.DOTALL)
        # Remove line comments
        source = re.sub(r"//[^\n]*", " ", source)
        return source

    # ------------------------------------------------------------------
    # Private – individual heuristics
    # ------------------------------------------------------------------

    def _check_identifier_entropy(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """
        Compute average Shannon entropy of all identifiers.

        Minified code → short names, low entropy.
        Packed/obfuscated code → _0x1a2b style names, high entropy.
        Return normalized score 0-1.
        """
        identifiers = [
            m for m in _RE_IDENTIFIER.findall(source)
            if m not in _JS_KEYWORDS and len(m) >= 2
        ]
        if not identifiers:
            return 0.0, []

        hex_var_count = len(_RE_HEX_VAR.findall(source))
        total = len(identifiers)
        hex_ratio = hex_var_count / total if total else 0.0

        entropies = [_shannon_entropy(name) for name in identifiers]
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

        findings: list[dict[str, Any]] = []
        score = 0.0

        if hex_ratio > 0.05:
            score += min(hex_ratio * 4, 0.8)
            findings.append(
                {
                    "check": "identifier_entropy",
                    "description": "High proportion of hex-named identifiers (_0xABCD pattern)",
                    "evidence": f"{hex_var_count}/{total} identifiers ({hex_ratio:.1%}) are hex-named",
                    "severity": "high",
                }
            )

        if avg_entropy > 3.5:
            score = max(score, min((avg_entropy - 3.5) / 2.0, 1.0))
            findings.append(
                {
                    "check": "identifier_entropy",
                    "description": "Unusually high average identifier entropy",
                    "evidence": f"avg entropy={avg_entropy:.2f} bits/char",
                    "severity": "medium",
                }
            )

        return min(score, 1.0), findings

    # ------------------------------------------------------------------

    def _check_hex_literals(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        r"""Detect high density of \xNN hex escape sequences."""
        matches = _RE_HEX_ESCAPE.findall(source)
        count = len(matches)
        char_total = max(len(source), 1)
        density = count / char_total  # escapes per character

        findings: list[dict[str, Any]] = []
        if count == 0:
            return 0.0, findings

        # Normalise: 1 escape per 50 chars is very high
        score = min(density * 500, 1.0)
        if count >= 10:
            sample = matches[:6]
            findings.append(
                {
                    "check": "hex_literals",
                    "description": r"High density of \xNN hex escape sequences",
                    "evidence": f"{count} occurrences, e.g. {sample}",
                    "severity": "high" if count >= 50 else "medium",
                }
            )
        return score, findings

    # ------------------------------------------------------------------

    def _check_bracket_notation(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """
        Compute ratio of bracket property accesses to dot accesses.
        Obfuscated code heavily prefers obj['prop'] over obj.prop.
        """
        bracket = len(_RE_BRACKET_ACCESS.findall(source))
        dot = len(_RE_DOT_ACCESS.findall(source))
        total = bracket + dot
        if total < 20:
            return 0.0, []

        ratio = bracket / total
        score = min(max(ratio - 0.25, 0.0) * 2.5, 1.0)

        findings: list[dict[str, Any]] = []
        if ratio > 0.4:
            findings.append(
                {
                    "check": "bracket_notation",
                    "description": "Excessive bracket notation property access (obfuscation indicator)",
                    "evidence": f"{bracket} bracket vs {dot} dot accesses ({ratio:.1%} bracket ratio)",
                    "severity": "medium",
                }
            )
        return score, findings

    # ------------------------------------------------------------------

    def _check_base64_strings(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """Detect long base64 strings embedded in source."""
        matches = _RE_BASE64_STR.findall(source)
        # Filter: strip surrounding quotes and validate
        valid = [m for m in matches if _is_base64_like(m.strip("'\"`"))]
        count = len(valid)
        total_length = sum(len(m) for m in valid)

        findings: list[dict[str, Any]] = []
        if count == 0:
            return 0.0, findings

        score = min((count * 0.2) + (total_length / 10000), 1.0)
        samples = [m[:40] + "…" for m in valid[:3]]
        findings.append(
            {
                "check": "base64_strings",
                "description": "Long base64 encoded strings detected in source",
                "evidence": f"{count} strings, total {total_length} chars, e.g. {samples}",
                "severity": "high" if count >= 5 else "medium",
            }
        )
        return score, findings

    # ------------------------------------------------------------------

    def _check_hex_strings(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """Detect long hex strings (keys, hashes, encoded payloads)."""
        matches = _RE_HEX_STR.findall(source)
        count = len(matches)
        total_length = sum(len(m.strip("'\"`")) for m in matches)

        findings: list[dict[str, Any]] = []
        if count == 0:
            return 0.0, findings

        score = min(count * 0.3 + total_length / 5000, 1.0)
        samples = [m[:40] + "…" for m in matches[:3]]
        findings.append(
            {
                "check": "hex_strings",
                "description": "Long hex-encoded strings found in source",
                "evidence": f"{count} strings, total {total_length} chars, e.g. {samples}",
                "severity": "high",
            }
        )
        return score, findings

    # ------------------------------------------------------------------

    def _check_array_packing(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """Detect _0x<hex>=[ 'str1','str2',… ] array string packing patterns."""
        array_matches = _RE_ARRAY_PACK.findall(source)
        hex_var_matches = _RE_HEX_VAR.findall(source)

        findings: list[dict[str, Any]] = []
        score = 0.0

        if array_matches:
            score += min(len(array_matches) * 0.5, 0.8)
            findings.append(
                {
                    "check": "array_packing",
                    "description": "String array packing (typical obfuscator output) detected",
                    "evidence": f"{len(array_matches)} array pack pattern(s); "
                                f"{len(hex_var_matches)} _0x* variable references",
                    "severity": "critical",
                }
            )
        elif len(hex_var_matches) > 20:
            score += min(len(hex_var_matches) / 100, 0.6)
            findings.append(
                {
                    "check": "array_packing",
                    "description": "Large number of _0x-prefixed hex variable names",
                    "evidence": f"{len(hex_var_matches)} _0x* references in source",
                    "severity": "high",
                }
            )

        return min(score, 1.0), findings

    # ------------------------------------------------------------------

    def _check_fromcharcode(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """Detect String.fromCharCode(...) chains used to build strings dynamically."""
        matches = _RE_FROMCHARCODE.findall(source)
        count = len(matches)

        findings: list[dict[str, Any]] = []
        if count == 0:
            return 0.0, findings

        score = min(count * 0.25, 1.0)
        findings.append(
            {
                "check": "fromcharcode",
                "description": "String.fromCharCode() chains used to construct strings at runtime",
                "evidence": f"{count} String.fromCharCode() call(s)",
                "severity": "high",
            }
        )
        return score, findings

    # ------------------------------------------------------------------

    def _check_unicode_escapes(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        r"""
        Detect suspicious use of \uXXXX sequences.
        High density suggests a keyword (e.g. 'eval', 'exec') is being spelled
        out character-by-character to evade simple regex detection.
        """
        matches = _RE_UNICODE_ESCAPE.findall(source)
        count = len(matches)
        char_total = max(len(source), 1)
        density = count / char_total

        findings: list[dict[str, Any]] = []
        if count < 5:
            return 0.0, findings

        score = min(density * 1000, 1.0)
        if density > 0.005:  # more than 0.5% of source is unicode escapes
            findings.append(
                {
                    "check": "unicode_escapes",
                    "description": r"High density of \uXXXX unicode escape sequences",
                    "evidence": f"{count} unicode escapes ({density:.3%} of source)",
                    "severity": "high",
                }
            )
        return score, findings

    # ------------------------------------------------------------------

    def _check_eval_atob(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """Detect eval(atob(...)) and similar runtime base64-decode-then-execute patterns."""
        matches = _RE_EVAL_ATOB.findall(source)
        count = len(matches)

        findings: list[dict[str, Any]] = []
        if count == 0:
            return 0.0, findings

        # Even a single occurrence is very suspicious
        score = min(0.5 + count * 0.25, 1.0)
        findings.append(
            {
                "check": "eval_atob",
                "description": "eval() used with atob/Buffer.from to execute decoded base64 payload",
                "evidence": f"{count} eval(atob/btoa/Buffer) pattern(s)",
                "severity": "critical",
            }
        )
        return score, findings

    # ------------------------------------------------------------------

    def _check_iife_complexity(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """
        Detect deeply nested IIFEs with high cyclomatic-like complexity.
        Obfuscators frequently wrap everything in self-executing functions
        and produce extremely long lines.
        """
        iife_count = len(_RE_IIFE.findall(source))
        lines = source.splitlines()
        long_line_count = sum(1 for ln in lines if len(ln) > 500)
        max_line = max((len(ln) for ln in lines), default=0)

        findings: list[dict[str, Any]] = []
        if iife_count == 0 and long_line_count == 0:
            return 0.0, findings

        score = 0.0
        if long_line_count > 5 or max_line > 2000:
            score += min(long_line_count * 0.1 + max_line / 10000, 0.7)
            findings.append(
                {
                    "check": "iife_complexity",
                    "description": "Extremely long lines suggesting minified / packed code",
                    "evidence": f"{long_line_count} lines >500 chars; longest line={max_line} chars",
                    "severity": "medium",
                }
            )
        if iife_count > 3:
            score += min(iife_count * 0.05, 0.3)
            findings.append(
                {
                    "check": "iife_complexity",
                    "description": "Multiple nested IIFE (immediately-invoked function expressions)",
                    "evidence": f"{iife_count} IIFE patterns found",
                    "severity": "medium",
                }
            )
        return min(score, 1.0), findings

    # ------------------------------------------------------------------

    def _check_char_frequency(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """
        Detect abnormal character distributions.
        Normal JS source has a fairly predictable character frequency;
        heavily obfuscated source skews toward hex digits, parentheses,
        brackets, and semicolons.
        """
        if not source:
            return 0.0, []

        total = len(source)
        counts = collections.Counter(source)

        # Characters heavily used in obfuscated JS
        suspicious_chars = set("[](){}\\;,+!|&^%~")
        suspicious_ratio = sum(counts[c] for c in suspicious_chars) / total

        # Printable ASCII ratio (low ratio → lots of escapes / non-printable)
        printable = sum(
            1 for c in source if 0x20 <= ord(c) <= 0x7E
        )
        printable_ratio = printable / total

        findings: list[dict[str, Any]] = []
        score = 0.0

        if suspicious_ratio > 0.25:
            score = min((suspicious_ratio - 0.25) * 3, 0.7)
            findings.append(
                {
                    "check": "char_frequency",
                    "description": "Abnormally high proportion of punctuation / operator characters",
                    "evidence": f"{suspicious_ratio:.1%} of source is punctuation/operators",
                    "severity": "medium",
                }
            )
        if printable_ratio < 0.85:
            score = max(score, min((0.85 - printable_ratio) * 5, 0.8))
            findings.append(
                {
                    "check": "char_frequency",
                    "description": "Low printable ASCII ratio (many escape sequences or binary data)",
                    "evidence": f"printable ratio={printable_ratio:.1%}",
                    "severity": "medium",
                }
            )

        return min(score, 1.0), findings

    # ------------------------------------------------------------------

    def _check_anti_analysis(
        self, source: str
    ) -> tuple[float, list[dict[str, Any]]]:
        """
        Detect anti-analysis / anti-debugger patterns.
        Includes explicit `debugger` statements and use of Date/Math.random()
        in non-obvious contexts that could be timing/environment checks.
        """
        debugger_count = len(_RE_DEBUGGER.findall(source))
        anti_count = len(_RE_ANTI_ANALYSIS.findall(source))

        findings: list[dict[str, Any]] = []
        score = 0.0

        if debugger_count > 0:
            score += min(debugger_count * 0.3, 0.6)
            findings.append(
                {
                    "check": "anti_analysis",
                    "description": "debugger statement(s) found (anti-debugger trap)",
                    "evidence": f"{debugger_count} debugger statement(s)",
                    "severity": "high",
                }
            )

        if anti_count > 5:
            score += min((anti_count - 5) * 0.05, 0.4)
            findings.append(
                {
                    "check": "anti_analysis",
                    "description": "Excessive use of Date/Math.random() (timing-based environment detection)",
                    "evidence": f"{anti_count} Date/Math.random() usage(s)",
                    "severity": "medium",
                }
            )

        return min(score, 1.0), findings

    # ------------------------------------------------------------------
    # Private – scoring helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_verdict(score: int) -> str:
        """Convert numeric score to a human-readable verdict string."""
        if score < ObfuscationDetector.VERDICT_THRESHOLDS["clean"]:
            return "clean"
        if score < ObfuscationDetector.VERDICT_THRESHOLDS["suspicious"]:
            return "suspicious"
        return "obfuscated"
