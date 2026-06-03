"""Language-aware source analysis for JavaScript/TypeScript and Python files."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any


class ASTAnalyzer:
    """Source analyzer focused on npm package contents."""

    JS_RULES: tuple[dict[str, Any], ...] = (
        {
            "id": "js-exec-eval",
            "title": "Dynamic code evaluation",
            "severity": "high",
            "confidence": 0.9,
            "category": "execution",
            "source": "source-analyzer",
            "patterns": (r"\beval\s*\(", r"\bFunction\s*\("),
            "tags": ("execution", "obfuscation"),
        },
        {
            "id": "js-child-process",
            "title": "Command execution capability",
            "severity": "critical",
            "confidence": 0.95,
            "category": "execution",
            "source": "source-analyzer",
            "patterns": (
                r"child_process",
                r"\bexec\s*\(",
                r"\bspawn\s*\(",
                r"\bexecSync\s*\(",
                r"powershell",
                r"cmd\.exe",
                r"/bin/sh",
            ),
            "tags": ("execution", "shell"),
        },
        {
            "id": "js-credential-access",
            "title": "Credential or workstation secret access",
            "severity": "critical",
            "confidence": 0.9,
            "category": "credential-access",
            "source": "source-analyzer",
            "patterns": (
                r"process\.env",
                r"\.npmrc",
                r"\.ssh",
                r"github_token",
                r"AWS_ACCESS_KEY",
                r"id_rsa",
                r"npm token",
            ),
            "tags": ("credentials", "secrets"),
        },
        {
            "id": "js-network-exfil",
            "title": "Network or exfiltration primitive",
            "severity": "high",
            "confidence": 0.8,
            "category": "network",
            "source": "source-analyzer",
            "patterns": (
                r"\bfetch\s*\(",
                r"\baxios\b",
                r"https?://",
                r"\bXMLHttpRequest\b",
                r"\bdns\.",
                r"\bnet\.",
            ),
            "tags": ("network", "exfiltration"),
        },
        {
            "id": "js-persistence",
            "title": "Persistence or defense-evasion primitive",
            "severity": "medium",
            "confidence": 0.72,
            "category": "persistence",
            "source": "source-analyzer",
            "patterns": (
                r"Run\\",
                r"Startup",
                r"scheduled task",
                r"reg add",
                r"launchctl",
                r"crontab",
            ),
            "tags": ("persistence", "evasion"),
        },
    )

    PY_DANGEROUS_PATTERNS = {
        "exec": "Direct code execution",
        "eval": "Dynamic code evaluation",
        "__import__": "Dynamic import",
        "compile": "Runtime compilation",
        "subprocess": "Shell command execution",
        "os.system": "OS-level command execution",
    }

    def analyze_python_file(self, file_path: str) -> dict[str, Any]:
        path = Path(file_path)
        source = path.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return {"file": file_path, "language": "python", "error": f"Syntax error: {exc}"}

        analysis: dict[str, Any] = {
            "file": file_path,
            "language": "python",
            "functions": [],
            "imports": [],
            "dangerous_calls": [],
            "ast_depth": self._calculate_depth(tree),
            "findings": [],
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                analysis["functions"].append(
                    {
                        "name": node.name,
                        "args": [arg.arg for arg in node.args.args],
                        "line": node.lineno,
                    }
                )
            elif isinstance(node, ast.Import):
                analysis["imports"].extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                analysis["imports"].extend(f"{module}.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name in self.PY_DANGEROUS_PATTERNS:
                    analysis["dangerous_calls"].append(
                        {
                            "function": call_name,
                            "risk": self.PY_DANGEROUS_PATTERNS[call_name],
                            "line": node.lineno,
                        }
                    )
                    analysis["findings"].append(
                        self._build_finding(
                            finding_id=f"py-{call_name.replace('.', '-')}",
                            title=self.PY_DANGEROUS_PATTERNS[call_name],
                            severity="high",
                            confidence=0.82,
                            category="execution",
                            source="source-analyzer",
                            file_path=file_path,
                            evidence=f"{call_name} at line {node.lineno}",
                            tags=("python", "execution"),
                        )
                    )
        return analysis

    def analyze_javascript_file(self, file_path: str) -> dict[str, Any]:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        suspicious_keywords = [
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "require",
            "child_process",
            "exec",
            "spawn",
            "fetch",
            "axios",
        ]

        findings: list[dict[str, Any]] = []
        risk_patterns: list[dict[str, Any]] = []
        matched_keywords = [keyword for keyword in suspicious_keywords if keyword in source]

        for rule in self.JS_RULES:
            matches = self._find_matches(source, rule["patterns"])
            if not matches:
                continue
            findings.append(
                self._build_finding(
                    finding_id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    confidence=float(rule["confidence"]),
                    category=rule["category"],
                    source=rule["source"],
                    file_path=file_path,
                    evidence=", ".join(matches[:5]),
                    tags=tuple(rule["tags"]),
                )
            )
            risk_patterns.append({"pattern": rule["title"], "severity": rule["severity"]})

        if "postinstall" in source or "preinstall" in source or "prepare" in source:
            risk_patterns.append({"pattern": "Lifecycle script detected", "severity": "high"})

        long_base64 = re.findall(r"[A-Za-z0-9+/]{120,}={0,2}", source)
        if long_base64:
            findings.append(
                self._build_finding(
                    finding_id="js-obfuscated-string",
                    title="Potentially obfuscated encoded string",
                    severity="medium",
                    confidence=0.76,
                    category="obfuscation",
                    source="source-analyzer",
                    file_path=file_path,
                    evidence=long_base64[0][:80],
                    tags=("encoding", "obfuscation"),
                )
            )

        return {
            "file": file_path,
            "language": "javascript",
            "risk_patterns": risk_patterns,
            "suspicious_keywords": matched_keywords,
            "findings": findings,
            "function_count": len(re.findall(r"\bfunction\b|=>", source)),
            "line_count": source.count("\n") + 1,
        }

    def analyze_package_directory(self, directory: str) -> dict[str, Any]:
        root = Path(directory)
        package_manifest = self._find_package_manifest(root)
        results: dict[str, Any] = {
            "directory": str(root),
            "files_analyzed": 0,
            "analysis_results": [],
            "package_manifest": package_manifest,
            "source_findings": [],
            "summary": {
                "total_functions": 0,
                "total_imports": 0,
                "dangerous_calls_found": 0,
                "suspicious_keywords_found": 0,
                "install_script_detected": bool(package_manifest.get("install_scripts")),
                "dependency_count": len(package_manifest.get("dependencies", [])),
                "languages": {"javascript": 0, "typescript": 0, "python": 0},
            },
        }

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue

            suffix = file_path.suffix.lower()
            if suffix == ".py":
                analysis = self.analyze_python_file(str(file_path))
                language_key = "python"
            elif suffix in {".js", ".jsx"}:
                analysis = self.analyze_javascript_file(str(file_path))
                language_key = "javascript"
            elif suffix in {".ts", ".tsx"}:
                analysis = self.analyze_javascript_file(str(file_path))
                analysis["language"] = "typescript"
                language_key = "typescript"
            else:
                continue

            if "error" in analysis:
                continue

            results["files_analyzed"] += 1
            results["summary"]["languages"][language_key] += 1
            results["analysis_results"].append(analysis)
            results["source_findings"].extend(analysis.get("findings", []))
            results["summary"]["total_functions"] += len(analysis.get("functions", []))
            results["summary"]["total_imports"] += len(analysis.get("imports", []))
            results["summary"]["dangerous_calls_found"] += len(analysis.get("dangerous_calls", []))
            results["summary"]["suspicious_keywords_found"] += len(
                analysis.get("suspicious_keywords", [])
            )

        return results

    def _find_package_manifest(self, root: Path) -> dict[str, Any]:
        for manifest in root.rglob("package.json"):
            try:
                payload = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            scripts = payload.get("scripts", {})
            dependencies = payload.get("dependencies", {})
            install_scripts = []
            if isinstance(scripts, dict):
                for key in ("preinstall", "install", "postinstall", "prepare"):
                    value = scripts.get(key)
                    if isinstance(value, str):
                        install_scripts.append({"name": key, "command": value})
            dep_names = []
            if isinstance(dependencies, dict):
                dep_names = sorted(str(name) for name in dependencies.keys())
            return {
                "path": str(manifest.relative_to(root)),
                "name": payload.get("name", ""),
                "version": payload.get("version", ""),
                "main": payload.get("main", ""),
                "bin": payload.get("bin", {}),
                "scripts": scripts if isinstance(scripts, dict) else {},
                "install_scripts": install_scripts,
                "dependencies": dep_names,
            }
        return {
            "path": "",
            "name": "",
            "version": "",
            "main": "",
            "bin": {},
            "scripts": {},
            "install_scripts": [],
            "dependencies": [],
        }

    def _find_matches(self, source: str, patterns: tuple[str, ...]) -> list[str]:
        matches: list[str] = []
        for pattern in patterns:
            if re.search(pattern, source, re.IGNORECASE):
                matches.append(pattern)
        return matches

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            value = node.func.value
            if isinstance(value, ast.Name):
                return f"{value.id}.{attr}"
            return attr
        return "unknown"

    def _calculate_depth(self, node: ast.AST, depth: int = 0) -> int:
        max_depth = depth
        for child in ast.iter_child_nodes(node):
            max_depth = max(max_depth, self._calculate_depth(child, depth + 1))
        return max_depth

    def _build_finding(
        self,
        *,
        finding_id: str,
        title: str,
        severity: str,
        confidence: float,
        category: str,
        source: str,
        file_path: str,
        evidence: str,
        tags: tuple[str, ...],
    ) -> dict[str, Any]:
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "source": source,
            "file": file_path,
            "evidence": evidence,
            "tags": list(tags),
        }
