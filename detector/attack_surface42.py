#!/usr/bin/env python3
"""Attack surface mapper for Owen.

Walks a codebase and finds every input point an attacker could reach:
endpoints, file uploads, deserialization calls, admin panels, SQL sinks,
command sinks, authentication gates, and more. Produces a structured map
that other modules (PoC gen, fuzzer, chainer) can consume.

Usage:
    mapper = AttackSurfaceMapper()
    surface = mapper.scan("/path/to/project")
    print(surface.summary())
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Iterator


VERSION = "4.2"


class EntryType(Enum):
    HTTP_ENDPOINT = auto()
    FILE_UPLOAD = auto()
    DESERIALIZATION = auto()
    COMMAND_EXEC = auto()
    SQL_SINK = auto()
    FILE_READ = auto()
    FILE_WRITE = auto()
    ADMIN_PANEL = auto()
    AUTH_GATE = auto()
    CRYPTO_OPERATION = auto()
    TEMPLATE_RENDER = auto()
    REDIRECT = auto()
    HEADER_SET = auto()
    COOKIE_SET = auto()
    EVAL_EXEC = auto()
    LDAP_QUERY = auto()
    XML_PARSE = auto()
    SSRF_SINK = auto()
    WEBSOCKET = auto()
    GRAPHQL = auto()


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EntryPoint:
    """A single attackable surface element."""
    entry_type: EntryType
    file_path: str
    line: int
    code_snippet: str
    language: str
    severity: Severity = Severity.MEDIUM
    method: str = ""
    route: str = ""
    param_names: list[str] = field(default_factory=list)
    sink_function: str = ""
    requires_auth: bool = False
    framework: str = ""
    cwe: int = 0
    notes: str = ""

    @property
    def risk_score(self) -> int:
        scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        score = scores.get(self.severity, 5)
        if not self.requires_auth:
            score += 2
        return min(score, 10)


@dataclass
class AttackSurface:
    """Complete attack surface for a project."""
    project_path: str
    entries: list[EntryPoint] = field(default_factory=list)
    files_scanned: int = 0
    languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)

    def by_type(self, entry_type: EntryType) -> list[EntryPoint]:
        return [e for e in self.entries if e.entry_type == entry_type]

    def by_severity(self, severity: Severity) -> list[EntryPoint]:
        return [e for e in self.entries if e.severity == severity]

    def by_file(self, file_path: str) -> list[EntryPoint]:
        return [e for e in self.entries if e.file_path == file_path]

    def unauthenticated(self) -> list[EntryPoint]:
        return [e for e in self.entries if not e.requires_auth]

    def endpoints(self) -> list[EntryPoint]:
        return self.by_type(EntryType.HTTP_ENDPOINT)

    def high_value_targets(self) -> list[EntryPoint]:
        return [e for e in self.entries if e.risk_score >= 8]

    def summary(self) -> str:
        lines = [
            "=== Attack Surface Map ===",
            "Project: %s" % self.project_path,
            "Files scanned: %d" % self.files_scanned,
            "Languages: %s" % ", ".join(sorted(self.languages)) if self.languages else "Languages: none detected",
            "Frameworks: %s" % ", ".join(sorted(self.frameworks)) if self.frameworks else "Frameworks: none detected",
            "Total entry points: %d" % len(self.entries),
            "",
        ]

        type_counts = {}
        for e in self.entries:
            type_counts[e.entry_type.name] = type_counts.get(e.entry_type.name, 0) + 1
        if type_counts:
            lines.append("By type:")
            for name, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                lines.append("  %s: %d" % (name, count))

        sev_counts = {}
        for e in self.entries:
            sev_counts[e.severity.value] = sev_counts.get(e.severity.value, 0) + 1
        if sev_counts:
            lines.append("")
            lines.append("By severity:")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in sev_counts:
                    lines.append("  %s: %d" % (sev, sev_counts[sev]))

        unauth = self.unauthenticated()
        if unauth:
            lines.append("")
            lines.append("Unauthenticated entry points: %d" % len(unauth))

        hvt = self.high_value_targets()
        if hvt:
            lines.append("High-value targets (score >= 8): %d" % len(hvt))

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project_path,
            "files_scanned": self.files_scanned,
            "languages": sorted(self.languages),
            "frameworks": sorted(self.frameworks),
            "total_entries": len(self.entries),
            "entries": [
                {
                    "type": e.entry_type.name,
                    "file": e.file_path,
                    "line": e.line,
                    "severity": e.severity.value,
                    "method": e.method,
                    "route": e.route,
                    "params": e.param_names,
                    "sink": e.sink_function,
                    "auth_required": e.requires_auth,
                    "framework": e.framework,
                    "cwe": e.cwe,
                    "risk_score": e.risk_score,
                    "snippet": e.code_snippet[:200],
                }
                for e in self.entries
            ],
        }


# =========================================================================== #
#  PATTERN DEFINITIONS                                                         #
# =========================================================================== #

@dataclass
class ScanPattern:
    regex: str
    entry_type: EntryType
    severity: Severity
    cwe: int = 0
    sink: str = ""
    notes: str = ""
    languages: tuple[str, ...] = ()


PYTHON_PATTERNS = [
    ScanPattern(
        r'@app\.route\s*\(\s*["\']([^"\']+)["\']',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="Flask route", languages=("python",)),
    ScanPattern(
        r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="Flask method route", languages=("python",)),
    ScanPattern(
        r'path\s*\(\s*["\']([^"\']+)["\']',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="Django URL path", languages=("python",)),
    ScanPattern(
        r'@api_view\s*\(\s*\[',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="DRF api_view", languages=("python",)),
    ScanPattern(
        r'request\.files\[',
        EntryType.FILE_UPLOAD, Severity.HIGH, cwe=434,
        notes="Flask file upload", languages=("python",)),
    ScanPattern(
        r'pickle\.(loads?|Unpickler)\s*\(',
        EntryType.DESERIALIZATION, Severity.CRITICAL, cwe=502,
        sink="pickle", notes="Pickle deserialization", languages=("python",)),
    ScanPattern(
        r'yaml\.(unsafe_)?load\s*\(',
        EntryType.DESERIALIZATION, Severity.CRITICAL, cwe=502,
        sink="yaml.load", notes="YAML deserialization", languages=("python",)),
    ScanPattern(
        r'marshal\.loads?\s*\(',
        EntryType.DESERIALIZATION, Severity.CRITICAL, cwe=502,
        sink="marshal", languages=("python",)),
    ScanPattern(
        r'os\.system\s*\(',
        EntryType.COMMAND_EXEC, Severity.CRITICAL, cwe=78,
        sink="os.system", languages=("python",)),
    ScanPattern(
        r'subprocess\.(call|run|Popen|check_output)\s*\(',
        EntryType.COMMAND_EXEC, Severity.HIGH, cwe=78,
        sink="subprocess", languages=("python",)),
    ScanPattern(
        r'shell\s*=\s*True',
        EntryType.COMMAND_EXEC, Severity.HIGH, cwe=78,
        sink="shell=True", languages=("python",)),
    ScanPattern(
        r'eval\s*\(',
        EntryType.EVAL_EXEC, Severity.CRITICAL, cwe=94,
        sink="eval", languages=("python",)),
    ScanPattern(
        r'exec\s*\(',
        EntryType.EVAL_EXEC, Severity.CRITICAL, cwe=94,
        sink="exec", languages=("python",)),
    ScanPattern(
        r'cursor\.(execute|executemany)\s*\(',
        EntryType.SQL_SINK, Severity.HIGH, cwe=89,
        sink="cursor.execute", languages=("python",)),
    ScanPattern(
        r'\.raw\s*\(\s*["\']',
        EntryType.SQL_SINK, Severity.HIGH, cwe=89,
        sink="raw SQL", languages=("python",)),
    ScanPattern(
        r'open\s*\(\s*[^)]*\+',
        EntryType.FILE_READ, Severity.MEDIUM, cwe=22,
        sink="open()", languages=("python",)),
    ScanPattern(
        r'send_file\s*\(',
        EntryType.FILE_READ, Severity.HIGH, cwe=22,
        sink="send_file", languages=("python",)),
    ScanPattern(
        r'redirect\s*\(\s*[^)]*request\.',
        EntryType.REDIRECT, Severity.HIGH, cwe=601,
        sink="redirect", notes="Open redirect", languages=("python",)),
    ScanPattern(
        r'render_template_string\s*\(',
        EntryType.TEMPLATE_RENDER, Severity.CRITICAL, cwe=94,
        sink="render_template_string", notes="SSTI risk", languages=("python",)),
    ScanPattern(
        r'response\.headers\[',
        EntryType.HEADER_SET, Severity.MEDIUM, cwe=113,
        sink="header set", languages=("python",)),
    ScanPattern(
        r'set_cookie\s*\(',
        EntryType.COOKIE_SET, Severity.MEDIUM, cwe=614,
        sink="set_cookie", languages=("python",)),
    ScanPattern(
        r'(ldap|ldap3)\.\w*search\s*\(',
        EntryType.LDAP_QUERY, Severity.HIGH, cwe=90,
        sink="LDAP search", languages=("python",)),
    ScanPattern(
        r'(etree|minidom|sax|pulldom|xmlrpc)\.parse',
        EntryType.XML_PARSE, Severity.HIGH, cwe=611,
        sink="XML parse", languages=("python",)),
    ScanPattern(
        r'requests\.(get|post|put|delete|patch|head)\s*\(\s*[^)]*\+',
        EntryType.SSRF_SINK, Severity.HIGH, cwe=918,
        sink="requests", notes="Potential SSRF", languages=("python",)),
    ScanPattern(
        r'urllib\.(request\.)?urlopen\s*\(',
        EntryType.SSRF_SINK, Severity.HIGH, cwe=918,
        sink="urlopen", languages=("python",)),
    ScanPattern(
        r'hashlib\.(md5|sha1)\s*\(',
        EntryType.CRYPTO_OPERATION, Severity.MEDIUM, cwe=327,
        sink="weak hash", languages=("python",)),
    ScanPattern(
        r'random\.(randint|random|choice|randrange|seed)\s*\(',
        EntryType.CRYPTO_OPERATION, Severity.MEDIUM, cwe=338,
        sink="weak PRNG", languages=("python",)),
]

JS_PATTERNS = [
    ScanPattern(
        r'app\.(get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\']',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="Express route", languages=("javascript", "typescript")),
    ScanPattern(
        r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="Express router", languages=("javascript", "typescript")),
    ScanPattern(
        r'\.innerHTML\s*=',
        EntryType.TEMPLATE_RENDER, Severity.HIGH, cwe=79,
        sink="innerHTML", notes="XSS sink", languages=("javascript", "typescript")),
    ScanPattern(
        r'document\.write\s*\(',
        EntryType.TEMPLATE_RENDER, Severity.HIGH, cwe=79,
        sink="document.write", languages=("javascript", "typescript")),
    ScanPattern(
        r'eval\s*\(',
        EntryType.EVAL_EXEC, Severity.CRITICAL, cwe=94,
        sink="eval", languages=("javascript", "typescript")),
    ScanPattern(
        r'child_process\.(exec|spawn|execFile)\s*\(',
        EntryType.COMMAND_EXEC, Severity.CRITICAL, cwe=78,
        sink="child_process", languages=("javascript", "typescript")),
    ScanPattern(
        r'\.query\s*\(\s*[`"\'].*\$\{',
        EntryType.SQL_SINK, Severity.HIGH, cwe=89,
        sink="template SQL", languages=("javascript", "typescript")),
    ScanPattern(
        r'JSON\.parse\s*\(',
        EntryType.DESERIALIZATION, Severity.LOW, cwe=502,
        sink="JSON.parse", languages=("javascript", "typescript")),
    ScanPattern(
        r'multer\s*\(|upload\.(single|array|fields)\s*\(',
        EntryType.FILE_UPLOAD, Severity.HIGH, cwe=434,
        sink="multer", languages=("javascript", "typescript")),
    ScanPattern(
        r'res\.redirect\s*\(',
        EntryType.REDIRECT, Severity.MEDIUM, cwe=601,
        sink="redirect", languages=("javascript", "typescript")),
    ScanPattern(
        r'res\.cookie\s*\(',
        EntryType.COOKIE_SET, Severity.MEDIUM, cwe=614,
        sink="res.cookie", languages=("javascript", "typescript")),
    ScanPattern(
        r'__proto__|constructor\s*\[',
        EntryType.DESERIALIZATION, Severity.HIGH, cwe=1321,
        sink="prototype", notes="Prototype pollution", languages=("javascript", "typescript")),
    ScanPattern(
        r'WebSocket\s*\(|\.on\s*\(\s*["\']message["\']',
        EntryType.WEBSOCKET, Severity.MEDIUM,
        notes="WebSocket endpoint", languages=("javascript", "typescript")),
    ScanPattern(
        r'graphql|buildSchema|makeExecutableSchema',
        EntryType.GRAPHQL, Severity.MEDIUM,
        notes="GraphQL endpoint", languages=("javascript", "typescript")),
    ScanPattern(
        r'Math\.random\s*\(',
        EntryType.CRYPTO_OPERATION, Severity.MEDIUM, cwe=338,
        sink="Math.random", languages=("javascript", "typescript")),
]

JAVA_PATTERNS = [
    ScanPattern(
        r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*["\']?([^"\')\s]+)',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="Spring endpoint", languages=("java",)),
    ScanPattern(
        r'@(Path|GET|POST|PUT|DELETE)\s*\(\s*["\']([^"\']+)["\']',
        EntryType.HTTP_ENDPOINT, Severity.MEDIUM,
        notes="JAX-RS endpoint", languages=("java",)),
    ScanPattern(
        r'Runtime\.getRuntime\(\)\.exec\s*\(',
        EntryType.COMMAND_EXEC, Severity.CRITICAL, cwe=78,
        sink="Runtime.exec", languages=("java",)),
    ScanPattern(
        r'ProcessBuilder\s*\(',
        EntryType.COMMAND_EXEC, Severity.HIGH, cwe=78,
        sink="ProcessBuilder", languages=("java",)),
    ScanPattern(
        r'ObjectInputStream|readObject\s*\(',
        EntryType.DESERIALIZATION, Severity.CRITICAL, cwe=502,
        sink="Java deserialization", languages=("java",)),
    ScanPattern(
        r'(Statement|PreparedStatement)\s*.*\.execute',
        EntryType.SQL_SINK, Severity.HIGH, cwe=89,
        sink="JDBC", languages=("java",)),
    ScanPattern(
        r'@MultipartConfig|getPart\s*\(|getParts\s*\(',
        EntryType.FILE_UPLOAD, Severity.HIGH, cwe=434,
        sink="servlet upload", languages=("java",)),
    ScanPattern(
        r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"',
        EntryType.CRYPTO_OPERATION, Severity.MEDIUM, cwe=327,
        sink="weak hash", languages=("java",)),
    ScanPattern(
        r'new Random\s*\(',
        EntryType.CRYPTO_OPERATION, Severity.MEDIUM, cwe=338,
        sink="java.util.Random", languages=("java",)),
    ScanPattern(
        r'SAXParser|DocumentBuilder|XMLReader|TransformerFactory',
        EntryType.XML_PARSE, Severity.HIGH, cwe=611,
        sink="XML parse", languages=("java",)),
    ScanPattern(
        r'sendRedirect\s*\(',
        EntryType.REDIRECT, Severity.MEDIUM, cwe=601,
        sink="sendRedirect", languages=("java",)),
    ScanPattern(
        r'new Cookie\s*\(',
        EntryType.COOKIE_SET, Severity.MEDIUM, cwe=614,
        sink="Cookie", languages=("java",)),
]

C_PATTERNS = [
    ScanPattern(
        r'(strcpy|strcat|sprintf|gets)\s*\(',
        EntryType.COMMAND_EXEC, Severity.CRITICAL, cwe=120,
        sink="unsafe copy", notes="Buffer overflow", languages=("c", "cpp")),
    ScanPattern(
        r'system\s*\(',
        EntryType.COMMAND_EXEC, Severity.CRITICAL, cwe=78,
        sink="system()", languages=("c", "cpp")),
    ScanPattern(
        r'printf\s*\(\s*[^""]',
        EntryType.EVAL_EXEC, Severity.HIGH, cwe=134,
        sink="printf format", notes="Format string", languages=("c", "cpp")),
    ScanPattern(
        r'(malloc|calloc|realloc)\s*\(',
        EntryType.FILE_WRITE, Severity.LOW, cwe=120,
        sink="allocation", notes="Check bounds", languages=("c", "cpp")),
    ScanPattern(
        r'(fopen|fread|fwrite)\s*\(',
        EntryType.FILE_READ, Severity.MEDIUM, cwe=22,
        sink="file I/O", languages=("c", "cpp")),
]

GENERAL_PATTERNS = [
    ScanPattern(
        r'(admin|dashboard|management|control.?panel)',
        EntryType.ADMIN_PANEL, Severity.HIGH,
        notes="Admin panel reference", languages=()),
    ScanPattern(
        r'(login|authenticate|sign.?in|auth)',
        EntryType.AUTH_GATE, Severity.INFO,
        notes="Authentication gate", languages=()),
    ScanPattern(
        r'password\s*=\s*["\'][^"\']+["\']',
        EntryType.CRYPTO_OPERATION, Severity.CRITICAL, cwe=798,
        sink="hardcoded password", languages=()),
    ScanPattern(
        r'(api[_-]?key|secret[_-]?key|access[_-]?token)\s*=\s*["\'][^"\']+["\']',
        EntryType.CRYPTO_OPERATION, Severity.CRITICAL, cwe=798,
        sink="hardcoded secret", languages=()),
]

LANG_EXT_MAP = {
    ".py": "python", ".java": "java",
    ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".cc": "cpp", ".cxx": "cpp",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".venv", "venv",
    "vendor", "third_party", "dist", "build", ".eggs", "target",
}

FRAMEWORK_INDICATORS = {
    "flask": (r"from flask import|import flask", "python"),
    "django": (r"from django|import django|DJANGO_SETTINGS", "python"),
    "fastapi": (r"from fastapi import|import fastapi", "python"),
    "express": (r"require\(['\"]express['\"]\)|from ['\"]express['\"]", "javascript"),
    "spring": (r"@SpringBootApplication|import org\.springframework", "java"),
    "rails": (r"class.*<.*ApplicationController|Rails\.application", "ruby"),
    "react": (r"from ['\"]react['\"]|import React", "javascript"),
    "angular": (r"@Component|@NgModule|angular", "typescript"),
}


# =========================================================================== #
#  SCANNER                                                                     #
# =========================================================================== #

class AttackSurfaceMapper:
    """Scans a codebase and maps its entire attack surface."""

    def __init__(self, max_file_size: int = 2 * 1024 * 1024,
                 max_files: int = 50_000):
        self._max_file_size = max_file_size
        self._max_files = max_files
        self._patterns: dict[str, list[ScanPattern]] = {}
        self._build_pattern_index()

    def _build_pattern_index(self) -> None:
        all_patterns = (PYTHON_PATTERNS + JS_PATTERNS + JAVA_PATTERNS +
                        C_PATTERNS + GENERAL_PATTERNS)
        for p in all_patterns:
            if p.languages:
                for lang in p.languages:
                    self._patterns.setdefault(lang, []).append(p)
            else:
                self._patterns.setdefault("_general", []).append(p)

    def scan(self, project_path: str) -> AttackSurface:
        surface = AttackSurface(project_path=os.path.abspath(project_path))
        file_count = 0

        for fpath, lang in self._walk_files(project_path):
            if file_count >= self._max_files:
                break
            file_count += 1
            surface.languages.add(lang)

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except OSError as e:
                surface.errors.append("cannot read %s: %s" % (fpath, e))
                continue

            rel_path = os.path.relpath(fpath, project_path)
            content = "".join(lines)

            for fw_name, (fw_regex, fw_lang) in FRAMEWORK_INDICATORS.items():
                if lang == fw_lang and re.search(fw_regex, content):
                    surface.frameworks.add(fw_name)

            patterns = self._patterns.get(lang, []) + self._patterns.get("_general", [])
            for pattern in patterns:
                compiled = re.compile(pattern.regex, re.IGNORECASE)
                for i, line in enumerate(lines, 1):
                    if compiled.search(line):
                        route = ""
                        method = ""
                        m = compiled.search(line)
                        if m and m.lastindex:
                            if pattern.entry_type == EntryType.HTTP_ENDPOINT:
                                groups = m.groups()
                                if len(groups) >= 2:
                                    method = groups[0].upper()
                                    route = groups[1]
                                elif len(groups) == 1:
                                    route = groups[0]

                        auth = self._check_auth_context(lines, i, lang)

                        entry = EntryPoint(
                            entry_type=pattern.entry_type,
                            file_path=rel_path,
                            line=i,
                            code_snippet=line.strip()[:200],
                            language=lang,
                            severity=pattern.severity,
                            method=method,
                            route=route,
                            sink_function=pattern.sink,
                            requires_auth=auth,
                            cwe=pattern.cwe,
                            notes=pattern.notes,
                        )
                        surface.entries.append(entry)

        surface.files_scanned = file_count
        surface.entries.sort(key=lambda e: (-e.risk_score, e.file_path, e.line))
        return surface

    def _walk_files(self, root: str) -> Iterator[tuple[str, str]]:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                lang = LANG_EXT_MAP.get(ext)
                if not lang:
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    if os.path.getsize(fpath) > self._max_file_size:
                        continue
                except OSError:
                    continue
                yield fpath, lang

    def _check_auth_context(self, lines: list[str], line_num: int,
                            lang: str) -> bool:
        start = max(0, line_num - 10)
        context = "".join(lines[start:line_num])
        auth_patterns = [
            r"login_required", r"@auth", r"@permission",
            r"requireAuth", r"isAuthenticated", r"@PreAuthorize",
            r"@Secured", r"@RolesAllowed", r"passport\.",
            r"jwt\.verify", r"verify_jwt", r"current_user",
            r"session\[.user", r"req\.user",
        ]
        return any(re.search(p, context, re.IGNORECASE) for p in auth_patterns)

    def scan_file(self, file_path: str) -> list[EntryPoint]:
        """Scan a single file."""
        ext = os.path.splitext(file_path)[1].lower()
        lang = LANG_EXT_MAP.get(ext, "unknown")
        surface = AttackSurface(project_path=os.path.dirname(file_path))

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return []

        patterns = self._patterns.get(lang, []) + self._patterns.get("_general", [])
        entries = []
        for pattern in patterns:
            compiled = re.compile(pattern.regex, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    entries.append(EntryPoint(
                        entry_type=pattern.entry_type,
                        file_path=file_path,
                        line=i,
                        code_snippet=line.strip()[:200],
                        language=lang,
                        severity=pattern.severity,
                        sink_function=pattern.sink,
                        cwe=pattern.cwe,
                        notes=pattern.notes,
                    ))
        return entries
