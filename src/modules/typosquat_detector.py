"""
typosquat_detector.py
---------------------
Detect typosquatting, dependency confusion, and combosquatting attacks
against the npm ecosystem.

Strategy
~~~~~~~~
1. Load a curated list of ~200 top npm packages (hardcoded).
2. Compute Levenshtein edit distance between the candidate name and each
   popular package.
3. Detect common typo patterns:
   - Character transposition   (lodash  →  lodahs)
   - Missing character         (lodash  →  lodas)
   - Extra character           (lodash  →  loodash)
   - Character substitution    (lodash  →  1odash)
   - Hyphen / underscore swap  (left-pad → left_pad)
4. Dependency confusion:
   - Unscoped version of a known scoped package
   - Name suggests internal use ('internal', 'private', 'corp', …)
5. Combosquatting:
   - Popular package + common suffix (lodash-utils, axios-helper, …)
   - Common prefix + popular package (my-lodash, fork-of-express, …)

Pure Python, zero external dependencies.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Top 200 popular npm packages (hardcoded – version-agnostic)
# ---------------------------------------------------------------------------

POPULAR_PACKAGES: list[str] = [
    # Core utilities
    "lodash", "underscore", "ramda", "async", "bluebird", "rxjs",
    # Request / HTTP
    "axios", "request", "node-fetch", "got", "superagent", "ky",
    "cross-fetch", "isomorphic-fetch", "node-http-proxy",
    # CLI / terminal
    "chalk", "commander", "yargs", "minimist", "inquirer", "ora",
    "cli-progress", "log-symbols", "boxen", "figlet", "meow",
    "table", "listr", "update-notifier", "conf", "execa",
    # Build / bundlers
    "webpack", "rollup", "parcel", "esbuild", "vite", "snowpack",
    "babel-core", "core-js", "babel-loader", "ts-loader",
    # Testing
    "jest", "mocha", "chai", "sinon", "jasmine", "vitest", "ava",
    "tape", "supertest", "nock", "msw",
    # React / UI
    "react", "react-dom", "react-router", "react-router-dom",
    "react-redux", "redux", "redux-saga", "redux-thunk", "recoil",
    "mobx", "zustand",
    # Vue / Angular
    "vue", "nuxt", "angular", "angularjs",
    # Express / frameworks
    "express", "koa", "fastify", "hapi", "restify", "sails",
    "next", "gatsby", "remix", "svelte", "sveltekit",
    # Database / ORM
    "mongoose", "sequelize", "typeorm", "prisma", "knex",
    "pg", "mysql", "mysql2", "redis", "ioredis", "mongodb",
    "level", "sqlite3",
    # Auth / crypto
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "passport-local",
    "passport-jwt", "crypto-js", "forge", "argon2",
    # Parsing / serialisation
    "moment", "dayjs", "date-fns", "luxon",
    "lodash-fp", "immutable", "immer",
    "cheerio", "jsdom", "parse5",
    "xml2js", "fast-xml-parser", "csv-parser",
    "marked", "showdown", "unified", "remark", "rehype",
    # File system / OS
    "fs-extra", "glob", "fast-glob", "chokidar", "rimraf", "mkdirp",
    "node-watch", "archiver", "adm-zip", "unzipper",
    "mime", "mime-types", "file-type",
    # Networking / server utils
    "socket.io", "ws", "nodemailer", "dotenv", "cross-env",
    "http-proxy-middleware", "morgan", "helmet", "cors",
    "compression", "body-parser", "cookie-parser", "multer",
    "busboy", "formidable",
    # Linting / formatting
    "eslint", "prettier", "tslint", "stylelint",
    "eslint-config-airbnb", "eslint-plugin-react",
    "husky", "lint-staged",
    # Typescript / type definitions
    "typescript", "ts-node", "ts-jest", "type-fest",
    # Misc popular
    "uuid", "nanoid", "shortid", "cuid",
    "validator", "joi", "yup", "zod", "ajv",
    "debug", "winston", "pino", "loglevel", "bunyan",
    "semver", "node-semver", "compare-versions",
    "deepmerge", "merge", "defaults", "extend",
    "sprintf-js", "numeral", "accounting",
    "slugify", "pluralize",
    "sharp", "jimp", "canvas",
    "pdf-lib", "pdfkit",
    "qrcode", "jsbarcode",
    "d3", "chart.js", "echarts",
    "three", "pixi.js",
    "left-pad", "is-odd", "is-even", "is-array", "is-string",
    "pad-left", "pad-right", "string-width",
    "camelcase", "snake-case", "kebab-case",
    "prop-types", "classnames", "clsx",
    "styled-components", "emotion", "tailwindcss",
    "autoprefixer", "postcss", "sass", "less",
    "copy-webpack-plugin", "html-webpack-plugin", "mini-css-extract-plugin",
    "babel-preset-env", "babel-plugin-transform-runtime",
    "webpack-cli", "webpack-dev-server",
]

# Remove duplicates while preserving order
POPULAR_PACKAGES = list(dict.fromkeys(POPULAR_PACKAGES))

# ---------------------------------------------------------------------------
# Common combosquatting suffixes and prefixes
# ---------------------------------------------------------------------------

_COMBO_SUFFIXES: list[str] = [
    "utils", "util", "tools", "helper", "helpers", "extra", "extras",
    "extended", "plus", "lite", "core", "base", "common", "shared",
    "fork", "clone", "copy", "mod", "modified", "patch", "patched",
    "wrapper", "wrapper-js", "js", "ts", "node", "npm",
    "client", "server", "api", "sdk", "lib", "library",
    "plugin", "middleware", "adapter", "connector", "driver",
    "mock", "stub", "fake", "test", "testing", "spec",
    "cli", "bin", "cmd", "command",
    "2", "3", "4", "v2", "v3", "v4",
    "next", "new", "latest", "modern", "stable",
]

_COMBO_PREFIXES: list[str] = [
    "my", "fork-of", "fork", "alt", "alternative", "better",
    "super", "ultra", "mega", "mini", "micro", "nano",
    "fast", "faster", "quick", "slim", "light", "tiny",
    "safe", "secure", "simple", "easy", "clean",
    "custom", "modified", "updated", "new", "old",
]

# ---------------------------------------------------------------------------
# Internal name indicators (dependency confusion)
# ---------------------------------------------------------------------------

_INTERNAL_RE = re.compile(
    r"\b(?:internal|private|corp|company|enterprise|intranet|local|dev-only|"
    r"in-house|proprietary|staff|employee|admin|backend|infra)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Pure-Python Levenshtein distance
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """
    Compute the Levenshtein (edit) distance between two strings.

    Uses the classic dynamic-programming algorithm.  Time complexity O(mn),
    space complexity O(min(m, n)).

    Parameters
    ----------
    a, b:
        Input strings.

    Returns
    -------
    int
        Minimum number of single-character edits (insert / delete / replace)
        to transform *a* into *b*.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Make sure len(a) >= len(b) for memory efficiency
    if len(a) < len(b):
        a, b = b, a

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            if ca == cb:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev = curr
    return prev[len(b)]


# ---------------------------------------------------------------------------
# Pattern checkers
# ---------------------------------------------------------------------------

def _is_transposition(a: str, b: str) -> bool:
    """Check if *a* is a single character transposition of *b*."""
    if len(a) != len(b):
        return False
    diffs = [(ca, cb) for ca, cb in zip(a, b) if ca != cb]
    if len(diffs) == 2:
        (c1, c2), (c3, c4) = diffs
        return c1 == c4 and c2 == c3
    return False


def _is_missing_char(candidate: str, popular: str) -> bool:
    """Check if *candidate* is *popular* with exactly one character removed."""
    if len(popular) - len(candidate) != 1:
        return False
    return levenshtein(candidate, popular) == 1


def _is_extra_char(candidate: str, popular: str) -> bool:
    """Check if *candidate* is *popular* with exactly one character inserted."""
    return _is_missing_char(popular, candidate)


def _is_substitution(candidate: str, popular: str) -> bool:
    """Check if *candidate* is *popular* with exactly one character replaced."""
    if len(candidate) != len(popular):
        return False
    diffs = sum(1 for ca, cb in zip(candidate, popular) if ca != cb)
    return diffs == 1


def _is_hyphen_underscore_swap(candidate: str, popular: str) -> bool:
    """Check if *candidate* differs from *popular* only in - vs _ usage."""
    return candidate.replace("-", "_") == popular.replace("-", "_") and candidate != popular


def _detect_typo_pattern(candidate: str, popular: str) -> str | None:
    """
    Return the name of the typo pattern if *candidate* looks like a typo
    of *popular*, else None.
    """
    if _is_hyphen_underscore_swap(candidate, popular):
        return "hyphen_underscore_swap"
    if _is_transposition(candidate, popular):
        return "transposition"
    if _is_missing_char(candidate, popular):
        return "missing_char"
    if _is_extra_char(candidate, popular):
        return "extra_char"
    if _is_substitution(candidate, popular):
        return "substitution"
    return None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class TyposquatDetector:
    """
    Detect typosquatting, dependency confusion, and combosquatting for npm
    package names.

    Usage::

        detector = TyposquatDetector()
        result = detector.analyze("lodahs")
        print(result['is_suspicious'], result['closest_matches'])
    """

    # Maximum edit distance to consider a name as a potential typosquat
    DISTANCE_THRESHOLD = 2
    # Minimum length of the candidate for distance checks (avoid false
    # positives on very short names like "fs", "os", "vm")
    MIN_LENGTH_FOR_DISTANCE = 4

    def analyze(self, package_name: str) -> dict[str, Any]:
        """
        Analyse a candidate npm package name for squatting indicators.

        Parameters
        ----------
        package_name:
            The npm package name to check (scoped or unscoped).

        Returns
        -------
        dict with keys:
            ``is_suspicious``          – bool
            ``closest_matches``        – list of {'name', 'distance', 'pattern'}
            ``dependency_confusion_risk`` – bool
            ``combosquatting``         – bool
            ``findings``               – list of finding dicts
        """
        # Normalise: strip version tag if present (e.g. "lodash@4.17.21")
        name = package_name.split("@")[0].strip().lower()
        if name.startswith("@"):
            # scoped package – check only the local name part
            name_to_check = name.split("/")[-1]
        else:
            name_to_check = name

        findings: list[dict[str, Any]] = []
        closest_matches: list[dict[str, Any]] = []
        dependency_confusion = False
        combosquatting = False

        # -----------------------------------------------------------------
        # 1. Exact match in popular list – it IS the real package
        # -----------------------------------------------------------------
        if name_to_check in POPULAR_PACKAGES or name in POPULAR_PACKAGES:
            return {
                "is_suspicious": False,
                "closest_matches": [],
                "dependency_confusion_risk": False,
                "combosquatting": False,
                "findings": [
                    {
                        "check": "exact_match",
                        "description": "Package name exactly matches a known popular package",
                        "severity": "info",
                    }
                ],
            }

        # -----------------------------------------------------------------
        # 2. Levenshtein distance – typosquatting
        # -----------------------------------------------------------------
        if len(name_to_check) >= self.MIN_LENGTH_FOR_DISTANCE:
            distance_results: list[tuple[int, str, str | None]] = []
            for popular in POPULAR_PACKAGES:
                dist = levenshtein(name_to_check, popular)
                if dist <= self.DISTANCE_THRESHOLD:
                    pattern = _detect_typo_pattern(name_to_check, popular)
                    distance_results.append((dist, popular, pattern))

            # Sort by distance, then alphabetically
            distance_results.sort(key=lambda x: (x[0], x[1]))

            for dist, popular, pattern in distance_results[:10]:  # top 10
                closest_matches.append(
                    {
                        "name": popular,
                        "distance": dist,
                        "pattern": pattern or "similar_name",
                    }
                )

            if closest_matches:
                top = closest_matches[0]
                severity = "critical" if top["distance"] == 1 else "high"
                findings.append(
                    {
                        "check": "typosquatting",
                        "description": (
                            f"Package '{name_to_check}' is very similar to popular package "
                            f"'{top['name']}' (edit distance={top['distance']}, "
                            f"pattern={top['pattern']})"
                        ),
                        "evidence": f"closest_matches={[m['name'] for m in closest_matches[:3]]}",
                        "severity": severity,
                    }
                )

        # -----------------------------------------------------------------
        # 3. Dependency confusion
        # -----------------------------------------------------------------
        dep_confusion = self._check_dependency_confusion(name, name_to_check)
        if dep_confusion:
            dependency_confusion = True
            findings.extend(dep_confusion)

        # -----------------------------------------------------------------
        # 4. Combosquatting
        # -----------------------------------------------------------------
        combo = self._check_combosquatting(name_to_check)
        if combo:
            combosquatting = True
            findings.extend(combo)

        is_suspicious = bool(closest_matches or dependency_confusion or combosquatting)

        return {
            "is_suspicious": is_suspicious,
            "closest_matches": closest_matches,
            "dependency_confusion_risk": dependency_confusion,
            "combosquatting": combosquatting,
            "findings": findings,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dependency_confusion(
        full_name: str, bare_name: str
    ) -> list[dict[str, Any]]:
        """
        Detect dependency confusion indicators:
        - Unscoped version of a known scoped package
        - Internal-sounding name published publicly
        """
        findings: list[dict[str, Any]] = []

        # Scoped-to-unscoped: does any popular package share the bare name?
        # E.g. candidate='types' while '@types/node' exists
        for popular in POPULAR_PACKAGES:
            # Check if popular package bare name matches candidate
            pop_bare = popular.split("/")[-1]
            if bare_name == pop_bare and not full_name.startswith("@"):
                findings.append(
                    {
                        "check": "dependency_confusion",
                        "description": (
                            f"'{full_name}' is the unscoped equivalent of popular package "
                            f"'{popular}' – potential dependency confusion attack"
                        ),
                        "evidence": f"popular_package={popular}",
                        "severity": "critical",
                    }
                )
                break

        # Internal-sounding name
        if _INTERNAL_RE.search(bare_name):
            findings.append(
                {
                    "check": "dependency_confusion",
                    "description": (
                        f"Package name '{bare_name}' contains internal/private keywords "
                        f"but is published to public registry"
                    ),
                    "evidence": f"matched pattern in name: {bare_name!r}",
                    "severity": "critical",
                }
            )

        return findings

    @staticmethod
    def _check_combosquatting(name: str) -> list[dict[str, Any]]:
        """
        Detect combosquatting: <popular>-<suffix> or <prefix>-<popular>.
        """
        findings: list[dict[str, Any]] = []
        matched_popular: list[str] = []

        # Check suffix pattern: lodash-utils, axios-helper
        for popular in POPULAR_PACKAGES:
            for suffix in _COMBO_SUFFIXES:
                if name == f"{popular}-{suffix}" or name == f"{popular}_{suffix}":
                    matched_popular.append(f"{popular} (+suffix: {suffix})")
                    break

        # Check prefix pattern: my-lodash, fast-axios
        for popular in POPULAR_PACKAGES:
            for prefix in _COMBO_PREFIXES:
                if name == f"{prefix}-{popular}" or name == f"{prefix}_{popular}":
                    matched_popular.append(f"{popular} (prefix: {prefix}+)")
                    break

        if matched_popular:
            findings.append(
                {
                    "check": "combosquatting",
                    "description": (
                        f"Package '{name}' looks like a combosquat of a popular package"
                    ),
                    "evidence": f"matched: {matched_popular[:5]}",
                    "severity": "high",
                }
            )

        return findings


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def check_package(package_name: str) -> dict[str, Any]:
    """
    Convenience wrapper: instantiate :class:`TyposquatDetector` and run
    :meth:`~TyposquatDetector.analyze`.

    Parameters
    ----------
    package_name:
        The npm package name to evaluate.

    Returns
    -------
    Analysis result dict (see :meth:`TyposquatDetector.analyze`).
    """
    return TyposquatDetector().analyze(package_name)
