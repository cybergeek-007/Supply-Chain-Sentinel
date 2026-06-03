"""High-level static analysis pipeline for npm package archives."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.modules.ast_analyzer import ASTAnalyzer
from src.modules.entropy import ShannonEntropyCalculator
from src.modules.yara_scanner import YARAScanner


DEFAULT_STATIC_CONFIG: dict[str, Any] = {
    "severity_weights": {"low": 10, "medium": 25, "high": 45, "critical": 70},
    "max_strings_per_file": 5,
    "long_string_length": 120,
    "hidden_path_segments": [".github", ".npm", ".ssh", ".config", ".cache"],
    "suspicious_extensions": [".node", ".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".zip"],
    "archive_extensions": [".tgz", ".gz", ".zip", ".tar", ".7z", ".rar"],
    "manifest_risky_bins": ["install", "setup", "update", "patch", "postinstall"],
}


class StaticAnalyzer:
    """Combine signatures, manifest heuristics, source analysis, and artifacts."""

    def __init__(self, rules_dir: str = "config/rules"):
        self.rules_dir = Path(rules_dir)
        self.yara = YARAScanner(rules_dir=rules_dir)
        self.ast = ASTAnalyzer()
        self.settings = self._load_static_config()

    def analyze_directory(self, directory: str) -> dict[str, Any]:
        root = Path(directory)
        package_json_path = self._locate_package_json(root)
        manifest = self._read_manifest(package_json_path)
        files = self._collect_files(root)
        signatures = self.yara.scan_directory(directory)
        source_result = self.ast.analyze_package_directory(directory)
        string_summary = self._collect_strings(root)
        artifact_summary = self._collect_artifacts(root, files)

        findings: list[dict[str, Any]] = []
        findings.extend(self._manifest_findings(manifest, root))
        findings.extend(source_result.get("source_findings", []))
        findings.extend(self._signature_findings(signatures))
        findings.extend(string_summary["findings"])
        findings.extend(artifact_summary["findings"])
        findings.extend(self._advanced_pattern_findings(root))

        findings = self._dedupe_findings(findings)
        risk_score = self._score_findings(findings)
        risk_level = self._risk_level(risk_score)
        languages = source_result.get("summary", {}).get("languages", {})

        return {
            "scan_root": str(root),
            "file_type": "npm-package",
            "archive_type": "directory",
            "package_name": manifest.get("name") or root.name,
            "package_version": manifest.get("version", ""),
            "manifest": manifest,
            "package_metadata": {
                "manifest_path": str(package_json_path.relative_to(root)) if package_json_path else "",
                "entry_points": self._entry_points(manifest),
                "install_scripts": manifest.get("install_scripts", []),
                "dependencies": manifest.get("dependencies", []),
                "detected_language_mix": languages,
            },
            "entry_points": self._entry_points(manifest),
            "install_scripts": manifest.get("install_scripts", []),
            "detected_language_mix": languages,
            "files": files,
            "strings": string_summary["strings"],
            "signatures": signatures,
            "source_findings": source_result.get("analysis_results", []),
            "artifacts": artifact_summary["artifacts"],
            "findings": findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": {
                "yara_files_with_matches": signatures.get("matches_found", 0),
                "files_analyzed_ast": source_result.get("files_analyzed", 0),
                "dangerous_calls_found": source_result.get("summary", {}).get(
                    "dangerous_calls_found", 0
                ),
                "suspicious_keywords_found": source_result.get("summary", {}).get(
                    "suspicious_keywords_found", 0
                ),
                "findings_count": len(findings),
                "embedded_artifacts": len(artifact_summary["artifacts"]["embedded"]),
            },
            "legacy": {"yara": signatures, "ast": source_result},
        }

    def _load_static_config(self) -> dict[str, Any]:
        config_path = self.rules_dir / "static_analysis_config.json"
        if not config_path.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            config_path.write_text(json.dumps(DEFAULT_STATIC_CONFIG, indent=2), encoding="utf-8")
            return DEFAULT_STATIC_CONFIG.copy()
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except ValueError:
            return DEFAULT_STATIC_CONFIG.copy()
        merged = DEFAULT_STATIC_CONFIG.copy()
        merged.update(data if isinstance(data, dict) else {})
        return merged

    def _locate_package_json(self, root: Path) -> Path | None:
        for path in root.rglob("package.json"):
            if path.is_file():
                return path
        return None

    def _read_manifest(self, package_json_path: Path | None) -> dict[str, Any]:
        if package_json_path is None:
            return {
                "name": "",
                "version": "",
                "main": "",
                "bin": {},
                "scripts": {},
                "dependencies": [],
                "install_scripts": [],
            }
        try:
            payload = json.loads(package_json_path.read_text(encoding="utf-8", errors="ignore"))
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        scripts = payload.get("scripts", {})
        if not isinstance(scripts, dict):
            scripts = {}
        install_scripts = []
        for key in ("preinstall", "install", "postinstall", "prepare"):
            value = scripts.get(key)
            if isinstance(value, str):
                install_scripts.append({"name": key, "command": value})
        dependencies = payload.get("dependencies", {})
        dependency_names = sorted(dependencies.keys()) if isinstance(dependencies, dict) else []
        return {
            "name": str(payload.get("name", "")),
            "version": str(payload.get("version", "")),
            "main": str(payload.get("main", "")),
            "bin": payload.get("bin", {}),
            "scripts": scripts,
            "dependencies": dependency_names,
            "install_scripts": install_scripts,
            "raw": payload,
        }

    def _collect_files(self, root: Path) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            relative = str(path.relative_to(root))
            files.append(
                {
                    "path": relative,
                    "size": path.stat().st_size,
                    "extension": path.suffix.lower(),
                    "entropy": round(self._safe_entropy(path), 2),
                    "kind": self._file_kind(path.suffix.lower(), relative),
                }
            )
        return files

    def _file_kind(self, extension: str, relative_path: str) -> str:
        if relative_path.endswith("package.json"):
            return "manifest"
        if extension in {".js", ".jsx", ".ts", ".tsx"}:
            return "source"
        if extension in {".json", ".yml", ".yaml", ".toml"}:
            return "config"
        if extension in set(self.settings["archive_extensions"]):
            return "archive"
        if extension in set(self.settings["suspicious_extensions"]):
            return "binary"
        return "file"

    def _collect_strings(self, root: Path) -> dict[str, Any]:
        string_records: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        max_per_file = int(self.settings["max_strings_per_file"])
        min_len = int(self.settings["long_string_length"])

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".json", ".txt", ".md"}:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            urls = re.findall(r"https?://[^\s\"'<>]+", text)
            long_strings = re.findall(rf"[A-Za-z0-9+/=_-]{{{min_len},}}", text)
            interesting = list(dict.fromkeys(urls + [item[:100] for item in long_strings]))[
                :max_per_file
            ]
            if not interesting:
                continue
            relative = str(path.relative_to(root))
            string_records.append({"file": relative, "strings": interesting})
            for value in interesting:
                findings.append(
                    self._finding(
                        finding_id="interesting-string",
                        title="Interesting string extracted from source",
                        severity="medium" if value.startswith("http") else "low",
                        confidence=0.7,
                        category="string-analysis",
                        source="string-extractor",
                        file=relative,
                        evidence=value,
                        tags=["strings"],
                    )
                )

        return {"strings": string_records, "findings": findings}

    def _collect_artifacts(self, root: Path, files: list[dict[str, Any]]) -> dict[str, Any]:
        embedded: list[dict[str, Any]] = []
        suspicious_paths: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        suspicious_extensions = set(self.settings["suspicious_extensions"])
        archive_extensions = set(self.settings["archive_extensions"])
        hidden_segments = set(self.settings["hidden_path_segments"])

        for file_info in files:
            rel = file_info["path"]
            extension = file_info["extension"]
            path_obj = Path(rel)
            if extension in suspicious_extensions or extension in archive_extensions:
                artifact_kind = "embedded-archive" if extension in archive_extensions else "binary"
                embedded.append(
                    {
                        "path": rel,
                        "kind": artifact_kind,
                        "size": file_info["size"],
                        "entropy": file_info["entropy"],
                    }
                )
                findings.append(
                    self._finding(
                        finding_id=f"artifact-{artifact_kind}",
                        title="Embedded artifact discovered",
                        severity="medium" if artifact_kind == "embedded-archive" else "high",
                        confidence=0.78,
                        category="artifact",
                        source="artifact-detector",
                        file=rel,
                        evidence=f"{artifact_kind} ({extension or 'no extension'})",
                        tags=[artifact_kind],
                    )
                )

            if any(segment.startswith(".") or segment in hidden_segments for segment in path_obj.parts):
                suspicious_paths.append({"path": rel, "reason": "hidden-or-unusual-path"})
                findings.append(
                    self._finding(
                        finding_id="suspicious-path",
                        title="Suspicious hidden or unusual path",
                        severity="medium",
                        confidence=0.68,
                        category="artifact",
                        source="artifact-detector",
                        file=rel,
                        evidence="hidden path segment detected",
                        tags=["path"],
                    )
                )

        return {"artifacts": {"embedded": embedded, "suspicious_paths": suspicious_paths}, "findings": findings}

    def _manifest_findings(self, manifest: dict[str, Any], root: Path) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        manifest_path = self._locate_package_json(root)
        manifest_file = str(manifest_path.relative_to(root)) if manifest_path else "package.json"

        for script in manifest.get("install_scripts", []):
            command = script["command"]
            severity = "critical" if re.search(r"https?://|curl|wget|Invoke-WebRequest", command, re.IGNORECASE) else "high"
            findings.append(
                self._finding(
                    finding_id=f"install-script-{script['name']}",
                    title=f"Lifecycle script: {script['name']}",
                    severity=severity,
                    confidence=0.95,
                    category="manifest",
                    source="manifest-analyzer",
                    file=manifest_file,
                    evidence=command,
                    tags=["manifest", "lifecycle"],
                )
            )

        bin_field = manifest.get("bin", {})
        risky_names = set(self.settings["manifest_risky_bins"])
        if isinstance(bin_field, dict):
            for name, target in bin_field.items():
                if any(token in name.lower() for token in risky_names):
                    findings.append(
                        self._finding(
                            finding_id="suspicious-bin-entry",
                            title="Suspicious binary entry in manifest",
                            severity="medium",
                            confidence=0.72,
                            category="manifest",
                            source="manifest-analyzer",
                            file="package.json",
                            evidence=f"{name} -> {target}",
                            tags=["manifest", "bin"],
                        )
                    )

        raw_manifest = manifest.get("raw", {})
        if manifest.get("install_scripts") and len(json.dumps(raw_manifest, separators=(",", ":"))) < 220:
            findings.append(
                self._finding(
                    finding_id="small-manifest-high-risk-hook",
                    title="Small manifest with high-risk lifecycle hook",
                    severity="high",
                    confidence=0.74,
                    category="manifest",
                    source="manifest-analyzer",
                    file="package.json",
                    evidence="Minimal package metadata with install-time execution",
                    tags=["manifest", "lifecycle"],
                )
            )
        return findings

    def _signature_findings(self, signatures: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for detection in signatures.get("detections", []):
            for match in detection.get("matches", []):
                findings.append(
                    self._finding(
                        finding_id=f"signature-{match.get('rule', 'unknown')}",
                        title=f"Signature match: {match.get('rule', 'unknown')}",
                        severity="high",
                        confidence=0.88,
                        category="signature",
                        source="yara",
                        file=detection.get("file", ""),
                        evidence=", ".join(match.get("tags", []) or ["signature match"]),
                        tags=["signature"],
                    )
                )
        return findings

    def _dedupe_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for finding in findings:
            key = (finding["id"], finding["file"], finding["evidence"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        deduped.sort(
            key=lambda item: (-severity_order.get(item["severity"], 0), item["file"], item["title"])
        )
        return deduped

    def _score_findings(self, findings: list[dict[str, Any]]) -> int:
        total = 0.0
        for finding in findings:
            total += float(self.settings["severity_weights"].get(finding["severity"], 0)) * float(
                finding["confidence"]
            )
        return int(min(100, round(total)))

    def _risk_level(self, risk_score: int) -> str:
        if risk_score >= 85:
            return "CRITICAL"
        if risk_score >= 60:
            return "HIGH"
        if risk_score >= 30:
            return "MEDIUM"
        return "LOW"

    def _safe_entropy(self, path: Path) -> float:
        try:
            return ShannonEntropyCalculator.calculate(path.read_bytes())
        except OSError:
            return 0.0

    def _entry_points(self, manifest: dict[str, Any]) -> list[str]:
        entries: list[str] = []
        main = manifest.get("main")
        if isinstance(main, str) and main:
            entries.append(main)
        bin_field = manifest.get("bin", {})
        if isinstance(bin_field, str):
            entries.append(bin_field)
        elif isinstance(bin_field, dict):
            entries.extend(str(value) for value in bin_field.values())
        return sorted(dict.fromkeys(entries))

    def _finding(
        self,
        *,
        finding_id: str,
        title: str,
        severity: str,
        confidence: float,
        category: str,
        source: str,
        file: str,
        evidence: str,
        tags: list[str],
    ) -> dict[str, Any]:
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "source": source,
            "file": file,
            "evidence": evidence,
            "tags": tags,
        }

    # ------------------------------------------------------------------
    # Advanced evasion / obfuscation pattern detection
    # ------------------------------------------------------------------

    # String concatenation patterns used to evade static analysis
    _RE_STRING_CONCAT_REQUIRE = re.compile(
        r"""require\s*\(\s*(?:"""
        r"""['"][a-z_]{1,8}['"]\s*\+\s*['"][a-z_]{1,15}['"]"""  # 'chi' + 'ld_process'
        r"""|['"][a-z_]+['"](?:\s*\+\s*['"][a-z_]+['"]){2,}"""  # 3+ segments
        r""")""",
        re.IGNORECASE,
    )
    _RE_FROM_CHAR_CODE = re.compile(
        r"""String\.fromCharCode\s*\(\s*\d{2,3}(?:\s*,\s*\d{2,3}){3,}""",
        re.IGNORECASE,
    )
    _RE_BUFFER_BASE64 = re.compile(
        r"""Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*,\s*['"]base64['"]""",
        re.IGNORECASE,
    )
    _RE_ARRAY_JOIN_REQUIRE = re.compile(
        r"""require\s*\(\s*\[.*?\]\.join\s*\(\s*['"]""",
        re.IGNORECASE | re.DOTALL,
    )
    # Dynamic require (non-literal argument)
    _RE_DYNAMIC_REQUIRE = re.compile(
        r"""require\s*\(\s*(?:"""
        r"""[a-zA-Z_$][a-zA-Z0-9_$]*"""  # require(variable)
        r"""|Buffer\.from\("""             # require(Buffer.from(...))
        r"""|.*\.join\("""                 # require(arr.join(''))
        r""")\s*\)""",
        re.IGNORECASE,
    )
    # Prototype pollution
    _RE_PROTO_ACCESS = re.compile(
        r"""__proto__\s*(?:\[|\.|\])""",
        re.IGNORECASE,
    )
    _RE_PROTO_CONSTRUCTOR = re.compile(
        r"""constructor\s*(?:\[['"]prototype['"]\]|\.prototype)""",
        re.IGNORECASE,
    )
    _RE_OBJECT_PROTO = re.compile(
        # Match ONLY new property assignments to Object.prototype
        # Exclude standard built-in methods (toString, hasOwnProperty, etc.)
        r"""Object\.prototype\."""
        r"""(?!toString|hasOwnProperty|valueOf|constructor|isPrototypeOf|"""
        r"""propertyIsEnumerable|toLocaleString|__defineGetter__|"""
        r"""__defineSetter__|__lookupGetter__|__lookupSetter__)"""
        r"""\w+\s*=""",
        re.IGNORECASE,
    )
    # DNS exfiltration
    _RE_DNS_REQUIRE = re.compile(
        r"""require\s*\(\s*['"]dns['"]\s*\)""",
        re.IGNORECASE,
    )
    _RE_DNS_RESOLVE = re.compile(
        r"""dns\s*\.\s*(?:resolve|lookup|resolve4|resolve6)\s*\(""",
        re.IGNORECASE,
    )
    # Hex-encoded strings
    _RE_HEX_DECODE = re.compile(
        r"""(?:Buffer\.from|toString)\s*\(\s*['"][0-9a-f]{20,}['"]\s*,\s*['"]hex['"]""",
        re.IGNORECASE,
    )

    # ---- NEW: Template literal eval (T1059.007) ----
    _RE_TEMPLATE_EVAL = re.compile(
        r"""(?:eval|Function|setTimeout|setInterval)\s*\(\s*`""",
        re.IGNORECASE,
    )
    _RE_TEMPLATE_NEW_FUNCTION = re.compile(
        r"""new\s+Function\s*\(\s*`""",
        re.IGNORECASE,
    )

    # ---- NEW: WebAssembly payload (T1027.002) ----
    _RE_WASM_INSTANTIATE = re.compile(
        r"""WebAssembly\s*\.\s*(?:instantiate|compile|instantiateStreaming|compileStreaming)\s*\(""",
        re.IGNORECASE,
    )
    _RE_WASM_FILE = re.compile(
        r"""(?:readFileSync|readFile|fetch)\s*\([^)]*\.wasm""",
        re.IGNORECASE,
    )

    # ---- NEW: Multi-stage download-and-execute (T1105) ----
    _RE_FETCH_EVAL = re.compile(
        r"""(?:fetch|https?\.get|https?\.request|axios\.get|got)\s*\("""
        r"""[^)]*\)\s*\.then\s*\([^)]*\b(?:eval|Function|exec)\b""",
        re.IGNORECASE | re.DOTALL,
    )
    _RE_DOWNLOAD_EXEC = re.compile(
        r"""(?:curl|wget|Invoke-WebRequest|downloadString)\s*[^;]*\|\s*(?:sh|bash|node|python|eval)""",
        re.IGNORECASE,
    )
    _RE_HTTP_EVAL = re.compile(
        r"""(?:http|https|request)\s*\.\s*(?:get|request)\s*\([^)]*,\s*(?:function|=>)[^}]*\b(?:eval|exec(?:Sync)?|Function)\s*\(""",
        re.IGNORECASE | re.DOTALL,
    )

    # ---- NEW: Steganography indicators (T1027.003) ----
    _RE_PIXEL_EXTRACTION = re.compile(
        r"""(?:getImageData|readPixels|getPixel)\s*\(""",
        re.IGNORECASE,
    )
    _RE_LSB_EXTRACTION = re.compile(
        r"""(?:&\s*(?:0x01|1|0b0+1)|\bLSB\b|bitwise|(?:>>|<<)\s*[0-7]\s*&\s*(?:0xff|255|0x1|1))""",
        re.IGNORECASE,
    )
    _RE_IMAGE_BUFFER_DECODE = re.compile(
        r"""(?:readFileSync|readFile)\s*\([^)]*\.(?:png|jpg|jpeg|gif|bmp|ico)\b[^)]*\)"""
        r"""[^;]*(?:slice|subarray|Buffer\.from)""",
        re.IGNORECASE | re.DOTALL,
    )

    # ---- NEW: Time-bomb / delayed execution (T1497.003) ----
    _RE_DATE_COMPARE = re.compile(
        r"""new\s+Date\s*\(\s*\)\s*[<>=!]+\s*new\s+Date\s*\(\s*['"][^'"]+['"]\s*\)""",
        re.IGNORECASE,
    )
    _RE_DATE_GETTIME_COMPARE = re.compile(
        r"""Date\.now\s*\(\s*\)\s*[<>=]+\s*\d{10,13}""",
        re.IGNORECASE,
    )
    _RE_LONG_SETTIMEOUT = re.compile(
        r"""setTimeout\s*\([^,]+,\s*(\d{5,})""",  # >=10000ms = 10s
        re.IGNORECASE,
    )


    @staticmethod
    def _strip_js_comments(text: str) -> str:
        """Remove single-line and multi-line JS comments from source text.

        This prevents false positives from documentation comments that
        mention attack patterns as examples (e.g., axios security docs).
        """
        # Remove multi-line comments /* ... */
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
        # Remove single-line comments // ... (but not URLs like https://)
        text = re.sub(r'(?<!:)//[^\n]*', ' ', text)
        return text

    def _advanced_pattern_findings(self, root: Path) -> list[dict[str, Any]]:
        """Scan JS/TS files for advanced evasion and obfuscation patterns.

        Detects:
        - String concatenation evasion (T1027.010)
        - Dynamic require (T1129)
        - Prototype pollution (T1055)
        - DNS exfiltration (T1048.003)
        - Hex/base64 encoded payloads
        """
        findings: list[dict[str, Any]] = []
        js_extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in js_extensions:
                continue
            if path.stat().st_size > 500_000:  # Skip very large files
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            relative = str(path.relative_to(root))

            # Strip comments to avoid false positives from documentation
            # (e.g., axios has comments like "// Object.prototype.baseURL = ...")
            text_no_comments = self._strip_js_comments(text)

            # --- String concatenation evasion ---
            for m in self._RE_STRING_CONCAT_REQUIRE.finditer(text):
                findings.append(self._finding(
                    finding_id="obfuscation-string-concat-require",
                    title="String concatenation in require() (evasion T1027.010)",
                    severity="critical",
                    confidence=0.90,
                    category="obfuscation",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["obfuscation", "evasion", "T1027"],
                ))
                break  # One per file

            for m in self._RE_FROM_CHAR_CODE.finditer(text):
                findings.append(self._finding(
                    finding_id="obfuscation-fromcharcode",
                    title="String.fromCharCode() obfuscation (T1027)",
                    severity="high",
                    confidence=0.85,
                    category="obfuscation",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["obfuscation", "T1027"],
                ))
                break

            for m in self._RE_BUFFER_BASE64.finditer(text):
                findings.append(self._finding(
                    finding_id="obfuscation-buffer-base64",
                    title="Buffer.from() base64 decoding (T1027.010)",
                    severity="high",
                    confidence=0.80,
                    category="obfuscation",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["obfuscation", "base64", "T1027"],
                ))
                break

            for m in self._RE_ARRAY_JOIN_REQUIRE.finditer(text):
                findings.append(self._finding(
                    finding_id="obfuscation-array-join-require",
                    title="Array.join() in require() (evasion T1027.010)",
                    severity="critical",
                    confidence=0.92,
                    category="obfuscation",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["obfuscation", "evasion", "T1027"],
                ))
                break

            for m in self._RE_HEX_DECODE.finditer(text):
                findings.append(self._finding(
                    finding_id="obfuscation-hex-decode",
                    title="Hex-encoded string decoding (T1027)",
                    severity="high",
                    confidence=0.80,
                    category="obfuscation",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["obfuscation", "hex", "T1027"],
                ))
                break

            # --- Prototype pollution (use comment-stripped text) ---
            for m in self._RE_PROTO_ACCESS.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="prototype-pollution-proto",
                    title="__proto__ access (prototype pollution T1055)",
                    severity="high",
                    confidence=0.75,
                    category="injection",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["prototype-pollution", "T1055"],
                ))
                break

            for m in self._RE_OBJECT_PROTO.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="prototype-pollution-object",
                    title="Object.prototype modification (T1055)",
                    severity="critical",
                    confidence=0.88,
                    category="injection",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["prototype-pollution", "T1055"],
                ))
                break

            # --- DNS exfiltration ---
            has_dns = self._RE_DNS_REQUIRE.search(text)
            if has_dns:
                for m in self._RE_DNS_RESOLVE.finditer(text):
                    findings.append(self._finding(
                        finding_id="dns-exfiltration",
                        title="DNS resolution with require('dns') (T1048.003)",
                        severity="critical",
                        confidence=0.88,
                        category="exfiltration",
                        source="advanced-pattern",
                        file=relative,
                        evidence=m.group(0)[:200],
                        tags=["dns", "exfiltration", "T1048"],
                    ))
                    break

            # --- Template literal eval (T1059.007) ---
            for m in self._RE_TEMPLATE_EVAL.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="template-literal-eval",
                    title="eval/Function with template literal (T1059.007)",
                    severity="critical",
                    confidence=0.92,
                    category="code-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["eval", "template-literal", "T1059"],
                ))
                break

            for m in self._RE_TEMPLATE_NEW_FUNCTION.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="template-new-function",
                    title="new Function() with template literal (T1059.007)",
                    severity="critical",
                    confidence=0.90,
                    category="code-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["eval", "template-literal", "T1059"],
                ))
                break

            # --- WebAssembly payload (T1027.002) ---
            for m in self._RE_WASM_INSTANTIATE.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="wasm-instantiate",
                    title="WebAssembly instantiation (T1027.002)",
                    severity="critical",
                    confidence=0.75,
                    category="binary-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["wasm", "binary", "T1027"],
                ))
                break

            for m in self._RE_WASM_FILE.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="wasm-file-load",
                    title="Loading .wasm binary file (T1027.002)",
                    severity="critical",
                    confidence=0.70,
                    category="binary-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["wasm", "binary", "T1027"],
                ))
                break

            # --- Multi-stage download-and-execute (T1105) ---
            for m in self._RE_FETCH_EVAL.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="multistage-fetch-eval",
                    title="Download-and-eval pattern (T1105)",
                    severity="critical",
                    confidence=0.92,
                    category="code-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["multistage", "download-exec", "T1105"],
                ))
                break

            for m in self._RE_DOWNLOAD_EXEC.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="multistage-download-pipe",
                    title="Download piped to shell (T1105)",
                    severity="critical",
                    confidence=0.95,
                    category="code-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["multistage", "download-exec", "T1105"],
                ))
                break

            for m in self._RE_HTTP_EVAL.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="multistage-http-eval",
                    title="HTTP response evaluated as code (T1105)",
                    severity="critical",
                    confidence=0.88,
                    category="code-execution",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["multistage", "download-exec", "T1105"],
                ))
                break

            # --- Steganography indicators (T1027.003) ---
            has_image_read = self._RE_IMAGE_BUFFER_DECODE.search(text_no_comments)
            has_pixel = self._RE_PIXEL_EXTRACTION.search(text_no_comments)
            if has_image_read or has_pixel:
                findings.append(self._finding(
                    finding_id="steganography-indicator",
                    title="Image data extraction pattern (steganography T1027.003)",
                    severity="critical",
                    confidence=0.65,
                    category="obfuscation",
                    source="advanced-pattern",
                    file=relative,
                    evidence=(has_image_read or has_pixel).group(0)[:200],
                    tags=["steganography", "image", "T1027"],
                ))

            # --- Time-bomb / delayed execution (T1497.003) ---
            for m in self._RE_DATE_COMPARE.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="timebomb-date-compare",
                    title="Date comparison gate (time-bomb T1497.003)",
                    severity="critical",
                    confidence=0.85,
                    category="evasion",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["timebomb", "evasion", "T1497"],
                ))
                break

            for m in self._RE_DATE_GETTIME_COMPARE.finditer(text_no_comments):
                findings.append(self._finding(
                    finding_id="timebomb-timestamp",
                    title="Unix timestamp gate (time-bomb T1497.003)",
                    severity="high",
                    confidence=0.80,
                    category="evasion",
                    source="advanced-pattern",
                    file=relative,
                    evidence=m.group(0)[:200],
                    tags=["timebomb", "evasion", "T1497"],
                ))
                break

            for m in self._RE_LONG_SETTIMEOUT.finditer(text_no_comments):
                delay_ms = int(m.group(1))
                if delay_ms >= 30000:  # 30s+ is suspicious
                    findings.append(self._finding(
                        finding_id="timebomb-long-timeout",
                        title=f"Long setTimeout delay ({delay_ms}ms) (T1497.003)",
                        severity="high",
                        confidence=0.70,
                        category="evasion",
                        source="advanced-pattern",
                        file=relative,
                        evidence=m.group(0)[:200],
                        tags=["timebomb", "delayed-exec", "T1497"],
                    ))
                    break

        return findings

