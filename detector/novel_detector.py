#!/usr/bin/env python3
"""Novel code pattern detector -- finds structurally unusual code.

Catches what rule-based scanners miss: code that deviates from the
codebase's statistical norms. No LLM -- pure AST + statistics.

Detects:
  - Functions with abnormal complexity vs codebase average
  - Unusual import combinations (crypto + network + encoding = suspicious)
  - Entropy anomalies (obfuscated strings, packed data)
  - Structural outliers (deeply nested, excessively long, odd naming)
  - Anti-pattern clusters (multiple risky operations in one function)

    from novel_detector import NovelDetector
    nd = NovelDetector()
    findings = nd.scan_directory("src/")
"""
from __future__ import annotations

import ast
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, stdev

LANG_EXTS = {".py", ".pyw"}
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
ALL_EXTS = LANG_EXTS | JS_EXTS

RISKY_IMPORTS = {
    "crypto": {"cryptography", "Crypto", "pycryptodome", "hashlib", "hmac"},
    "network": {"socket", "requests", "urllib", "http", "aiohttp", "httpx",
                "paramiko", "ftplib", "smtplib", "telnetlib"},
    "encoding": {"base64", "binascii", "codecs", "struct", "pickle",
                 "marshal", "shelve"},
    "execution": {"subprocess", "os", "shlex", "ctypes", "importlib",
                  "exec", "eval", "compile"},
    "filesystem": {"shutil", "tempfile", "glob", "pathlib", "io"},
    "serialization": {"json", "yaml", "xml", "toml", "configparser",
                      "pickle", "marshal"},
}

SUSPICIOUS_COMBOS = [
    ({"crypto", "network"}, "MEDIUM",
     "combines cryptography with network I/O -- potential data exfiltration or C2 channel"),
    ({"crypto", "encoding"}, "LOW",
     "combines cryptography with encoding -- may indicate custom encryption or obfuscation"),
    ({"network", "encoding", "execution"}, "HIGH",
     "combines network + encoding + code execution -- classic payload download and execute"),
    ({"network", "execution"}, "HIGH",
     "combines network I/O with code execution -- potential remote code execution"),
    ({"encoding", "execution"}, "MEDIUM",
     "combines encoding with code execution -- potential obfuscated payload execution"),
    ({"crypto", "encoding", "network"}, "HIGH",
     "combines crypto + encoding + network -- encrypted C2 or exfiltration pattern"),
    ({"filesystem", "encoding", "execution"}, "MEDIUM",
     "combines filesystem + encoding + execution -- potential dropper pattern"),
]

OBFUSCATION_PATTERNS = [
    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}'), "hex-escaped byte sequence"),
    (re.compile(r'(?:chr\(\d+\)\s*\+\s*){4,}'), "chr() concatenation chain"),
    (re.compile(r'eval\s*\(\s*(?:compile|__import__|getattr)'), "eval wrapping dangerous call"),
    (re.compile(r'exec\s*\(\s*(?:base64|codecs|binascii)\b'), "exec with decoding"),
    (re.compile(r'lambda\s+\w+\s*:\s*lambda\s+\w+\s*:.*lambda'), "nested lambda chain"),
    (re.compile(r'getattr\s*\(\s*__builtins__'), "dynamic builtin access"),
    (re.compile(r'__import__\s*\(\s*["\']'), "dynamic import"),
    (re.compile(r'setattr\s*\(\s*\w+\s*,\s*["\']__'), "dunder attribute injection"),
]

JS_OBFUSCATION_PATTERNS = [
    (re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}'), "hex-escaped byte sequence"),
    (re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}'), "unicode escape sequence"),
    (re.compile(r'eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)'), "eval with decoding"),
    (re.compile(r'Function\s*\(\s*(?:atob|unescape|String\.fromCharCode)'), "Function constructor with decoding"),
    (re.compile(r'new\s+Function\s*\('), "dynamic Function constructor"),
    (re.compile(r'document\s*\[\s*["\']write["\']\s*\]'), "bracket notation document.write"),
    (re.compile(r'window\s*\[\s*["\']eval["\']\s*\]'), "bracket notation eval"),
    (re.compile(r'String\.fromCharCode\s*\((?:\s*\d+\s*,\s*){5,}'), "long fromCharCode chain"),
    (re.compile(r'\[\s*["\']constructor["\']\s*\]\s*\[\s*["\']constructor["\']\s*\]'), "constructor chain access"),
    (re.compile(r'with\s*\(\s*(?:document|window|this)\s*\)'), "with statement on global object"),
]

JS_RISKY_IMPORTS = {
    "crypto": {"crypto", "crypto-js", "bcrypt", "node-forge", "sjcl"},
    "network": {"http", "https", "net", "axios", "node-fetch", "request",
                "got", "superagent", "ws", "socket.io"},
    "execution": {"child_process", "vm", "worker_threads"},
    "filesystem": {"fs", "fs-extra", "path", "glob", "rimraf"},
    "serialization": {"serialize-javascript", "js-yaml", "xml2js"},
}

_JS_FUNC_RE = re.compile(
    r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))',
    re.MULTILINE,
)

_JS_IMPORT_RE = re.compile(
    r"""(?:require\s*\(\s*['"]([^'"]+)['"]|import\s+.*?\s+from\s+['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"])""",
    re.MULTILINE,
)


@dataclass
class NovelFinding:
    path: str
    line: int
    end_line: int
    category: str
    severity: str
    description: str
    evidence: str
    score: float
    function_name: str = ""
    metrics: dict = field(default_factory=dict)


@dataclass
class CodebaseProfile:
    avg_function_length: float = 0.0
    std_function_length: float = 0.0
    avg_complexity: float = 0.0
    std_complexity: float = 0.0
    avg_nesting: float = 0.0
    std_nesting: float = 0.0
    common_imports: set = field(default_factory=set)
    total_functions: int = 0
    total_files: int = 0


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def _cyclomatic_complexity(node: ast.AST) -> int:
    complexity = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.While, ast.For,
                              ast.ExceptHandler, ast.With,
                              ast.Assert, ast.comprehension)):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += len(child.values) - 1
        elif isinstance(child, (ast.IfExp,)):
            complexity += 1
    return complexity


def _max_nesting(node: ast.AST, depth: int = 0) -> int:
    max_d = depth
    nesting_types = (ast.If, ast.While, ast.For, ast.With,
                     ast.Try, ast.ExceptHandler, ast.FunctionDef,
                     ast.AsyncFunctionDef, ast.ClassDef)
    for child in ast.iter_child_nodes(node):
        child_depth = depth + 1 if isinstance(child, nesting_types) else depth
        max_d = max(max_d, _max_nesting(child, child_depth))
    return max_d


def _function_length(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    if hasattr(node, "end_lineno") and node.end_lineno:
        return node.end_lineno - node.lineno + 1
    return len(node.body)


def _extract_imports(tree: ast.AST) -> set[str]:
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    return imports


def _classify_imports(imports: set[str]) -> set[str]:
    categories = set()
    for cat, modules in RISKY_IMPORTS.items():
        if imports & modules:
            categories.add(cat)
    return categories


def _extract_strings(tree: ast.AST) -> list[tuple[int, str]]:
    strings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= 16:
                strings.append((getattr(node, "lineno", 0), node.value))
    return strings


def _name_entropy(name: str) -> float:
    clean = re.sub(r'[_\d]', '', name.lower())
    if len(clean) < 3:
        return 0.0
    return _shannon_entropy(clean)


class NovelDetector:
    def __init__(self, z_threshold: float = 2.0):
        self._z_threshold = z_threshold
        self._profile = CodebaseProfile()

    def _build_profile(self, root: str) -> CodebaseProfile:
        lengths, complexities, nestings = [], [], []
        all_imports = set()
        file_count = 0

        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if Path(fn).suffix not in LANG_EXTS:
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        source = f.read()
                    tree = ast.parse(source, filename=path)
                except (SyntaxError, UnicodeDecodeError):
                    continue

                file_count += 1
                all_imports.update(_extract_imports(tree))

                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        lengths.append(_function_length(node))
                        complexities.append(_cyclomatic_complexity(node))
                        nestings.append(_max_nesting(node))

        profile = CodebaseProfile()
        profile.total_files = file_count
        profile.total_functions = len(lengths)
        profile.common_imports = all_imports

        if len(lengths) >= 2:
            profile.avg_function_length = mean(lengths)
            profile.std_function_length = stdev(lengths) or 1.0
            profile.avg_complexity = mean(complexities)
            profile.std_complexity = stdev(complexities) or 1.0
            profile.avg_nesting = mean(nestings)
            profile.std_nesting = stdev(nestings) or 1.0

        return profile

    def _z_score(self, value: float, avg: float, sd: float) -> float:
        if sd == 0:
            return 0.0
        return (value - avg) / sd

    def _check_structural_outliers(self, path: str, tree: ast.AST,
                                   source: str) -> list[NovelFinding]:
        findings = []
        p = self._profile

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            length = _function_length(node)
            complexity = _cyclomatic_complexity(node)
            nesting = _max_nesting(node)
            fname = node.name
            end_line = getattr(node, "end_lineno", node.lineno + length)

            z_len = self._z_score(length, p.avg_function_length, p.std_function_length)
            z_cx = self._z_score(complexity, p.avg_complexity, p.std_complexity)
            z_nest = self._z_score(nesting, p.avg_nesting, p.std_nesting)

            anomaly_score = max(z_len, z_cx, z_nest)

            if anomaly_score < self._z_threshold:
                continue

            reasons = []
            if z_len >= self._z_threshold:
                reasons.append(f"length {length} lines ({z_len:.1f}σ above mean {p.avg_function_length:.0f})")
            if z_cx >= self._z_threshold:
                reasons.append(f"complexity {complexity} ({z_cx:.1f}σ above mean {p.avg_complexity:.0f})")
            if z_nest >= self._z_threshold:
                reasons.append(f"nesting depth {nesting} ({z_nest:.1f}σ above mean {p.avg_nesting:.0f})")

            severity = "LOW"
            if anomaly_score >= 4.0:
                severity = "HIGH"
            elif anomaly_score >= 3.0:
                severity = "MEDIUM"

            findings.append(NovelFinding(
                path=path, line=node.lineno, end_line=end_line,
                category="structural-outlier", severity=severity,
                description=f"function '{fname}' is a statistical outlier: {'; '.join(reasons)}",
                evidence=f"def {fname}(...)  # {length} lines, complexity={complexity}, nesting={nesting}",
                score=round(anomaly_score, 2),
                function_name=fname,
                metrics={"length": length, "complexity": complexity,
                         "nesting": nesting, "z_length": round(z_len, 2),
                         "z_complexity": round(z_cx, 2), "z_nesting": round(z_nest, 2)},
            ))

        return findings

    def _check_import_combos(self, path: str, tree: ast.AST) -> list[NovelFinding]:
        findings = []
        imports = _extract_imports(tree)
        categories = _classify_imports(imports)

        for combo, severity, desc in SUSPICIOUS_COMBOS:
            if combo.issubset(categories):
                matched_modules = set()
                for cat in combo:
                    matched_modules.update(imports & RISKY_IMPORTS[cat])

                findings.append(NovelFinding(
                    path=path, line=1, end_line=1,
                    category="suspicious-import-combo", severity=severity,
                    description=desc,
                    evidence=f"imports: {', '.join(sorted(matched_modules))}",
                    score=len(combo) / len(RISKY_IMPORTS),
                    metrics={"categories": sorted(combo),
                             "modules": sorted(matched_modules)},
                ))

        return findings

    def _check_entropy_anomalies(self, path: str, tree: ast.AST,
                                 source: str) -> list[NovelFinding]:
        findings = []
        strings = _extract_strings(tree)

        for line, s in strings:
            if len(s) < 32:
                continue
            entropy = _shannon_entropy(s)
            if entropy < 4.5:
                continue

            severity = "LOW"
            if entropy >= 5.5:
                severity = "HIGH"
            elif entropy >= 5.0:
                severity = "MEDIUM"

            preview = s[:60] + "..." if len(s) > 60 else s
            findings.append(NovelFinding(
                path=path, line=line, end_line=line,
                category="high-entropy-string", severity=severity,
                description=f"high-entropy string (H={entropy:.2f} bits) -- possible encoded/encrypted data",
                evidence=repr(preview),
                score=round(entropy, 2),
                metrics={"entropy": round(entropy, 2), "length": len(s)},
            ))

        return findings

    def _check_obfuscation(self, path: str, source: str) -> list[NovelFinding]:
        findings = []
        lines = source.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern, desc in OBFUSCATION_PATTERNS:
                if pattern.search(line):
                    findings.append(NovelFinding(
                        path=path, line=i, end_line=i,
                        category="obfuscation-pattern", severity="HIGH",
                        description=f"obfuscation detected: {desc}",
                        evidence=line.strip()[:100],
                        score=0.9,
                        metrics={"pattern": desc},
                    ))

        return findings

    def _check_naming_anomalies(self, path: str, tree: ast.AST) -> list[NovelFinding]:
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name
            if name.startswith("_"):
                continue

            entropy = _name_entropy(name)
            if entropy >= 3.5 and len(name) >= 8:
                findings.append(NovelFinding(
                    path=path, line=node.lineno,
                    end_line=node.lineno,
                    category="suspicious-naming", severity="LOW",
                    description=f"function '{name}' has unusually high name entropy ({entropy:.2f}) -- possible auto-generated or obfuscated name",
                    evidence=f"def {name}(...)",
                    score=round(entropy, 2),
                    function_name=name,
                    metrics={"name_entropy": round(entropy, 2)},
                ))

        return findings

    def _check_anti_pattern_clusters(self, path: str, tree: ast.AST,
                                     source: str) -> list[NovelFinding]:
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            risky_ops = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func_name = ""
                    if isinstance(child.func, ast.Name):
                        func_name = child.func.id
                    elif isinstance(child.func, ast.Attribute):
                        func_name = child.func.attr

                    if func_name in ("eval", "exec", "compile", "__import__",
                                     "getattr", "setattr", "delattr"):
                        risky_ops.append((getattr(child, "lineno", 0), func_name))

            if len(risky_ops) >= 3:
                ops_desc = ", ".join(f"{op}@L{ln}" for ln, op in risky_ops[:5])
                findings.append(NovelFinding(
                    path=path, line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    category="anti-pattern-cluster", severity="HIGH",
                    description=f"function '{node.name}' clusters {len(risky_ops)} dangerous operations",
                    evidence=ops_desc,
                    score=min(len(risky_ops) / 3.0, 1.0),
                    function_name=node.name,
                    metrics={"risky_op_count": len(risky_ops),
                             "operations": [op for _, op in risky_ops]},
                ))

        return findings

    def _scan_js_file(self, path: str, source: str) -> list[NovelFinding]:
        findings = []
        lines = source.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern, desc in JS_OBFUSCATION_PATTERNS:
                if pattern.search(line):
                    findings.append(NovelFinding(
                        path=path, line=i, end_line=i,
                        category="obfuscation-pattern", severity="HIGH",
                        description=f"JS obfuscation detected: {desc}",
                        evidence=line.strip()[:100],
                        score=0.9,
                        metrics={"pattern": desc},
                    ))

        imports = set()
        for m in _JS_IMPORT_RE.finditer(source):
            mod = m.group(1) or m.group(2) or m.group(3)
            if mod:
                imports.add(mod.split("/")[0])

        categories = set()
        for cat, modules in JS_RISKY_IMPORTS.items():
            if imports & modules:
                categories.add(cat)

        for combo, severity, desc in SUSPICIOUS_COMBOS:
            if combo.issubset(categories):
                matched = set()
                for cat in combo:
                    matched.update(imports & JS_RISKY_IMPORTS.get(cat, set()))
                findings.append(NovelFinding(
                    path=path, line=1, end_line=1,
                    category="suspicious-import-combo", severity=severity,
                    description=f"JS: {desc}",
                    evidence=f"imports: {', '.join(sorted(matched))}",
                    score=len(combo) / len(JS_RISKY_IMPORTS),
                    metrics={"categories": sorted(combo),
                             "modules": sorted(matched)},
                ))

        for i, line in enumerate(lines, 1):
            strings = re.findall(r'["\']([^"\']{32,})["\']', line)
            for s in strings:
                entropy = _shannon_entropy(s)
                if entropy >= 4.5:
                    severity = "HIGH" if entropy >= 5.5 else (
                        "MEDIUM" if entropy >= 5.0 else "LOW")
                    preview = s[:60] + "..." if len(s) > 60 else s
                    findings.append(NovelFinding(
                        path=path, line=i, end_line=i,
                        category="high-entropy-string", severity=severity,
                        description=f"high-entropy string (H={entropy:.2f} bits) -- possible encoded/encrypted data",
                        evidence=repr(preview),
                        score=round(entropy, 2),
                        metrics={"entropy": round(entropy, 2), "length": len(s)},
                    ))

        return findings

    def scan_file(self, path: str) -> list[NovelFinding]:
        suffix = Path(path).suffix
        if suffix not in ALL_EXTS:
            return []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (OSError, UnicodeDecodeError):
            return []

        if suffix in JS_EXTS:
            return self._scan_js_file(path, source)

        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            return []

        findings = []
        findings.extend(self._check_structural_outliers(path, tree, source))
        findings.extend(self._check_import_combos(path, tree))
        findings.extend(self._check_entropy_anomalies(path, tree, source))
        findings.extend(self._check_obfuscation(path, source))
        findings.extend(self._check_naming_anomalies(path, tree))
        findings.extend(self._check_anti_pattern_clusters(path, tree, source))

        return findings

    def scan_directory(self, root: str) -> list[NovelFinding]:
        self._profile = self._build_profile(root)
        findings = []

        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if Path(fn).suffix not in ALL_EXTS:
                    continue
                path = os.path.join(dirpath, fn)
                findings.extend(self.scan_file(path))

        findings.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.severity, 3),
                                     -f.score))
        return findings


def to_dict(findings: list[NovelFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "line": f.line,
            "end_line": f.end_line,
            "category": f.category,
            "severity": f.severity,
            "description": f.description,
            "evidence": f.evidence,
            "score": f.score,
            "function_name": f.function_name,
            "metrics": f.metrics,
        }
        for f in findings
    ]


def render(findings: list[NovelFinding]) -> str:
    if not findings:
        return "\n  No novel/anomalous patterns detected.\n"
    lines = [f"\n  Novel Pattern Detection -- {len(findings)} finding(s)\n"]
    for f in findings:
        sev = f"{f.severity:8s}"
        lines.append(f"  {sev}  {f.category:24s}  {f.path}:{f.line}")
        lines.append(f"           {f.description}")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence[:100]}")
        lines.append("")
    return "\n".join(lines)
