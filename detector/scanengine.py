#!/usr/bin/env python3
"""Attestor 3.0 incremental, parallel, multi-language workspace scan engine.

The engine separates static findings, parser/compiler verification, unsupported
inputs, and operational failures so an empty result can never mean "nothing was
actually scanned". External tools are opt-in and are invoked only in non-running
syntax/check modes.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import advanced_rules
import deepscan
import detect
import multilang
import nativescan
import polyglot
import precision_catalog
import rarebugs

ENGINE_VERSION = "3.0.0"
CACHE_SCHEMA = 5
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_JOBS = max(1, min(8, os.cpu_count() or 1))
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", ".stack-work", ".terraform", "coverage",
    "generated_service", ".next", ".gradle", "bin", "obj",
}
SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp",
    ".hxx", ".s", ".asm", ".nasm", ".hs", ".lhs", ".js", ".jsx", ".mjs",
    ".cjs", ".ts", ".tsx", ".rs", ".go", ".java", ".cs", ".sql", ".tf",
    ".tfvars", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".xml", ".env", ".md", ".txt", ".sh", ".ps1", ".gradle",
    ".rb", ".php", ".kt", ".kts", ".swift", ".bash", ".zsh", ".sol",
    ".vue", ".svelte", ".nginx",
}
SOURCE_NAMES = {
    "Dockerfile", "Containerfile", "Makefile", "Jenkinsfile", ".gitignore",
    ".dockerignore", ".env", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "nginx.conf", "package.json",
}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass(frozen=True)
class Issue:
    path: str
    line: int
    rule: str
    severity: str
    message: str
    fix: str = ""
    language: str = ""
    confidence: float = 0.0
    source: str = ""
    category: str = ""
    cwe: str = ""
    owasp: str = ""
    pack: str = ""
    fingerprint: str = ""
    asvs: tuple[str, ...] = ()
    cwe_top25_2025_rank: int | None = None


@dataclass(frozen=True)
class ToolCheck:
    name: str
    status: str
    path: str
    command: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass
class FileResult:
    path: str
    digest: str
    language: str
    status: str
    verification: str
    issues: list[Issue] = field(default_factory=list)
    tools: list[ToolCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cached: bool = False
    elapsed_ms: int = 0


@dataclass
class WorkspaceResult:
    version: str
    roots: list[str]
    status: str
    files_discovered: int
    files_scanned: int
    cache_hits: int
    issues: list[Issue]
    files: list[FileResult]
    errors: list[str]
    skipped: list[str]
    elapsed_ms: int


def _language(path: Path) -> str:
    ext = path.suffix.lower()
    if path.name.lower().startswith(("dockerfile", "containerfile")):
        return "docker"
    return {
        ".py": "python", ".pyw": "python", ".c": "c", ".h": "c",
        ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hh": "cpp",
        ".hpp": "cpp", ".hxx": "cpp", ".s": "asm", ".asm": "asm",
        ".nasm": "asm", ".hs": "haskell", ".lhs": "haskell",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
        ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
        ".rs": "rust", ".go": "go", ".java": "java", ".cs": "csharp",
        ".kt": "kotlin", ".kts": "kotlin", ".rb": "ruby", ".php": "php",
        ".swift": "swift", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
        ".ps1": "powershell", ".sol": "solidity", ".vue": "javascript",
        ".svelte": "javascript", ".nginx": "nginx",
        ".sql": "sql", ".tf": "terraform", ".tfvars": "terraform",
        ".yaml": "yaml", ".yml": "yaml",
    }.get(ext, "text")


def _looks_text(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return sum(byte < 9 or 13 < byte < 32 for byte in sample) < max(2, len(sample) // 100)


def discover(paths: list[str], max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[list[Path], list[str], list[str]]:
    files: list[Path] = []
    errors: list[str] = []
    skipped: list[str] = []
    seen = set()
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.exists():
            errors.append("path does not exist: %s" % path)
            continue
        candidates = [path] if path.is_file() else (
            item for item in path.rglob("*")
            if item.is_file() and not any(part in SKIP_DIRS for part in item.parts)
        )
        for item in candidates:
            try:
                resolved = item.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                size = item.stat().st_size
            except OSError as exc:
                errors.append("cannot inspect %s: %s" % (item, exc))
                continue
            if size > max_bytes:
                skipped.append("oversized: %s (%d bytes)" % (item, size))
                continue
            if item.suffix.lower() not in SOURCE_EXTENSIONS and item.name not in SOURCE_NAMES:
                if not _looks_text(item):
                    continue
            if not _looks_text(item):
                skipped.append("binary: %s" % item)
                continue
            files.append(resolved)
    return sorted(files, key=lambda p: str(p).lower()), errors, skipped


def _digest(data: bytes, deep: bool, tools: bool, cross_file: str = "") -> str:
    """Cache identity for one file's result.

    `cross_file` is the identity of the project-wide taint seed, and it has to
    be part of the key. Once a finding in one file can depend on what another
    file declares, that file's own bytes no longer determine its result:
    editing the sink's file would leave the source's file matching a stale
    entry and the flow would silently stop being reported. Folding the seed in
    makes any change to the project's shape invalidate the files it could
    affect, which is the conservative direction.
    """
    h = hashlib.sha256()
    h.update((ENGINE_VERSION + ":%d:%d:" % (deep, tools)).encode("ascii"))
    if cross_file:
        h.update(("xf:" + cross_file + ":").encode("ascii"))
    h.update(data)
    return h.hexdigest()


def _java_cross_file_seed(files: list[Path], max_bytes: int):
    """Build the project-wide Java taint seed and an identity for the cache.

    Returns `(seed, identity)`. One Java file cannot carry a cross-file flow,
    so the seed is skipped below two and the identity stays empty -- which
    leaves every existing cache entry valid for the common case of a tree with
    little or no Java in it.

    Re-reading the Java sources is deliberate. The alternative is holding every
    decoded file in memory for the whole scan so the workers can share them,
    and this engine is pointed at trees measured in gigabytes.
    """
    sources: list[str] = []
    for path in files:
        if path.suffix.lower() != ".java":
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
            sources.append(path.read_bytes().decode("utf-8", "replace"))
        except OSError:
            continue
    if len(sources) < 2:
        return detect.CrossFileTaint(), ""
    seed = detect.java_cross_file_taint(sources)
    # Both directions go into the identity. `received` and `returned` are
    # different questions -- a source here with the sink elsewhere, and the
    # reverse -- so a change to either alters what every Java file can find.
    identity = hashlib.sha256("\x00".join(
        sorted(getattr(seed, "received", frozenset()))
        + ["\x01"]
        + sorted(getattr(seed, "returned", frozenset()))
    ).encode("utf-8")).hexdigest()[:24]
    return seed, identity


def _normalize(item, source: str, default_path: str, language: str) -> Issue:
    message = getattr(item, "message", "") or getattr(item, "detail", "") or str(item)
    return Issue(
        path=str(getattr(item, "path", default_path) or default_path),
        line=max(1, int(getattr(item, "line", 1) or 1)),
        rule=str(getattr(item, "rule", "unknown")),
        severity=str(getattr(item, "severity", "LOW")).upper(),
        message=str(message), fix=str(getattr(item, "fix", "") or ""),
        language=str(getattr(item, "language", language) or language),
        confidence=float(getattr(item, "confidence", 0.0) or 0.0), source=source,
        category=str(getattr(item, "category", "") or ""),
        cwe=str(getattr(item, "cwe", "") or ""),
        owasp=str(getattr(item, "owasp", "") or ""),
        pack=str(getattr(item, "pack", "") or ""),
        fingerprint=str(getattr(item, "fingerprint", "") or ""),
        asvs=tuple(str(value) for value in (getattr(item, "asvs", ()) or ())),
        cwe_top25_2025_rank=getattr(item, "cwe_top25_2025_rank", None),
    )


def _safe_tool_env() -> dict:
    allowed = {"PATH", "PATHEXT", "SystemRoot", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _run_tool(name: str, command: list[str], path: Path, cwd: Path | None = None) -> ToolCheck:
    try:
        proc = subprocess.run(
            command, cwd=str(cwd or path.parent), capture_output=True, text=True,
            errors="replace", timeout=30, env=_safe_tool_env(),
        )
    except subprocess.TimeoutExpired:
        return ToolCheck(name, "failed", str(path), command, "timed out after 30 seconds")
    except OSError as exc:
        return ToolCheck(name, "failed", str(path), command, str(exc))
    detail = ((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")).strip()
    if len(detail) > 12000:
        detail = "[truncated]\n" + detail[-12000:]
    return ToolCheck(name, "passed" if proc.returncode == 0 else "failed", str(path), command, detail)


def _tool_check(path: Path, language: str, text: str, enabled: bool) -> list[ToolCheck]:
    if language == "python":
        try:
            compile(text, str(path), "exec")
            return [ToolCheck("python-compile", "passed", str(path))]
        except SyntaxError as exc:
            return [ToolCheck("python-compile", "failed", str(path), detail="line %s: %s" % (exc.lineno, exc.msg))]
    if not enabled:
        return [ToolCheck("external-syntax", "not-run", str(path), detail="enable --tools")]
    ext = path.suffix.lower()
    if language in {"c", "cpp"}:
        tool = shutil.which("clang++" if language == "cpp" else "clang") or shutil.which("g++" if language == "cpp" else "gcc")
        if not tool:
            return [ToolCheck("native-compiler", "unavailable", str(path))]
        standard = "-std=c++20" if language == "cpp" else "-std=c11"
        return [_run_tool("native-compiler", [tool, standard, "-Wall", "-Wextra", "-fsyntax-only", str(path)], path)]
    if language == "javascript":
        tool = shutil.which("node")
        return [_run_tool("node-check", [tool, "--check", str(path)], path)] if tool else [ToolCheck("node-check", "unavailable", str(path))]
    if language == "typescript":
        tool = shutil.which("tsc")
        return [_run_tool("tsc", [tool, "--noEmit", "--pretty", "false", str(path)], path)] if tool else [ToolCheck("tsc", "unavailable", str(path))]
    with tempfile.TemporaryDirectory(prefix="attestor-tool-") as tmp:
        if language == "rust":
            tool = shutil.which("rustc")
            return [_run_tool("rustc", [tool, "--crate-type", "lib", "--emit", "metadata", "-o", str(Path(tmp) / "out.rmeta"), str(path)], path)] if tool else [ToolCheck("rustc", "unavailable", str(path))]
        if language == "go":
            tool = shutil.which("gofmt")
            return [_run_tool("gofmt-parse", [tool, "-d", str(path)], path)] if tool else [ToolCheck("gofmt", "unavailable", str(path))]
        if language == "java":
            tool = shutil.which("javac")
            return [_run_tool("javac", [tool, "-proc:none", "-d", tmp, str(path)], path)] if tool else [ToolCheck("javac", "unavailable", str(path))]
        if language == "csharp":
            tool = shutil.which("csc")
            return [_run_tool("csc", [tool, "/nologo", "/target:library", "/out:" + str(Path(tmp) / "out.dll"), str(path)], path)] if tool else [ToolCheck("csc", "unavailable", str(path))]
        if language == "haskell":
            tool = shutil.which("ghc")
            return [_run_tool("ghc", [tool, "-fno-code", "-outputdir", tmp, str(path)], path)] if tool else [ToolCheck("ghc", "unavailable", str(path))]
        if language == "ruby":
            tool = shutil.which("ruby")
            return [_run_tool("ruby-parse", [tool, "-c", str(path)], path)] if tool else [ToolCheck("ruby-parse", "unavailable", str(path))]
        if language == "php":
            tool = shutil.which("php")
            return [_run_tool("php-lint", [tool, "-n", "-l", str(path)], path)] if tool else [ToolCheck("php-lint", "unavailable", str(path))]
        if language == "kotlin":
            tool = shutil.which("kotlinc")
            return [_run_tool("kotlinc", [tool, str(path), "-d", str(Path(tmp) / "out.jar")], path)] if tool else [ToolCheck("kotlinc", "unavailable", str(path))]
        if language == "swift":
            tool = shutil.which("swiftc")
            return [_run_tool("swiftc-parse", [tool, "-parse", str(path)], path)] if tool else [ToolCheck("swiftc-parse", "unavailable", str(path))]
        if language == "shell":
            tool = shutil.which("bash") or shutil.which("sh")
            return [_run_tool("shell-parse", [tool, "-n", str(path)], path)] if tool else [ToolCheck("shell-parse", "unavailable", str(path))]
        if language == "solidity":
            tool = shutil.which("solc")
            return [_run_tool("solc-ast", [tool, "--ast-compact-json", str(path)], path)] if tool else [ToolCheck("solc-ast", "unavailable", str(path))]
    return [ToolCheck("external-syntax", "unsupported", str(path), detail="no safe adapter")]


def _scan_uncached(path: Path, deep: bool, tools: bool, max_bytes: int,
                   cross_file_taint=None, cross_file_id: str = "") -> FileResult:
    started = time.perf_counter()
    try:
        data = path.read_bytes()
    except OSError as exc:
        return FileResult(str(path), "", _language(path), "failed", "failed", errors=[str(exc)])
    digest = _digest(data, deep, tools, cross_file_id)
    if len(data) > max_bytes:
        return FileResult(str(path), digest, _language(path), "skipped", "unverified",
                          errors=["file exceeds configured size limit"])
    text = data.decode("utf-8", "replace")
    language = _language(path)
    issues: list[Issue] = []
    errors: list[str] = []
    try:
        detector_language = detect.language_for(str(path)) or "text"
        # A Java file is scanned with what the rest of the project declares, so
        # a source in one file reaches a sink in another. Without this the
        # engine could only ever see a flow that begins and ends in the same
        # file, which is not how controllers and data-access layers are
        # written. Every other language is unaffected and gets an empty seed.
        seed = (cross_file_taint if detector_language == "java" and cross_file_taint
                else detect.CrossFileTaint())
        for finding in detect.scan_source(text, str(path), detector_language,
                                          deep=deep, cross_file_taint=seed):
            issues.append(_normalize(finding, "detect", str(path), language))
    except (OSError, UnicodeError, ValueError) as exc:
        errors.append("detect: %s" % exc)
    if language == "python":
        for source, findings in (("deepscan", deepscan.analyze(text, str(path))),
                                 ("rarebugs", rarebugs.analyze(text, str(path)))):
            issues.extend(_normalize(item, source, str(path), language) for item in findings)
    if language in {"c", "cpp", "asm"}:
        try:
            issues.extend(_normalize(item, "nativescan", str(path), language)
                          for item in nativescan.scan_file(str(path)))
            issues.extend(_normalize(item, "polyglot", str(path), language)
                          for item in polyglot.scan_file(path))
        except (OSError, ValueError) as exc:
            errors.append("native scan: %s" % exc)
    issues.extend(_normalize(item, "multilang", str(path), language)
                  for item in multilang.analyze(text, str(path)))
    issues.extend(_normalize(item, "advanced_rules", str(path), language)
                  for item in advanced_rules.analyze(text, str(path)))
    try:
        issues.extend(_normalize(item, "precision_catalog", str(path), language)
                      for item in precision_catalog.analyze(text, str(path)))
    except (TypeError, ValueError) as exc:
        errors.append("precision catalog: %s" % exc)
    dedup = {}
    for issue in issues:
        key = (issue.path, issue.line, issue.rule, issue.message)
        dedup[key] = issue
    issues = sorted(dedup.values(), key=lambda item: (
        -SEVERITY_RANK.get(item.severity, 0), item.path.lower(), item.line, item.rule))
    checks = _tool_check(path, language, text, tools)
    verification = "failed" if any(check.status == "failed" for check in checks) else (
        "verified" if any(check.status == "passed" for check in checks) else "unverified")
    if errors or verification == "failed":
        status = "failed"
    elif issues:
        status = "findings"
    else:
        status = "clean"
    return FileResult(str(path), digest, language, status, verification, issues, checks, errors,
                      elapsed_ms=int((time.perf_counter() - started) * 1000))


class ScanCache:
    def __init__(self, path: Path | None):
        self.path = path
        self.data = {"schema": CACHE_SCHEMA, "engine": ENGINE_VERSION, "files": {}}
        self.lock = threading.Lock()
        if path and path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if loaded.get("schema") == CACHE_SCHEMA and loaded.get("engine") == ENGINE_VERSION:
                    self.data = loaded
            except (OSError, ValueError, TypeError):
                pass

    def get(self, path: Path, digest: str) -> FileResult | None:
        with self.lock:
            row = self.data["files"].get(str(path))
        if not row or row.get("digest") != digest:
            return None
        try:
            return FileResult(
                path=row["path"], digest=row["digest"], language=row["language"],
                status=row["status"], verification=row["verification"],
                issues=[Issue(**item) for item in row.get("issues", [])],
                tools=[ToolCheck(**item) for item in row.get("tools", [])],
                errors=list(row.get("errors", [])), cached=True,
                elapsed_ms=int(row.get("elapsed_ms", 0)),
            )
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, result: FileResult) -> None:
        row = asdict(result)
        row["cached"] = False
        with self.lock:
            self.data["files"][result.path] = row

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="attestor-cache-", suffix=".json", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, separators=(",", ":"))
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def default_cache_path(paths: list[str]) -> Path:
    identity = "\n".join(sorted(str(Path(path).expanduser().resolve()) for path in paths))
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    base = Path(os.environ.get("ATTESTOR_CACHE_DIR", str(Path.home() / ".attestor" / "cache")))
    return base / (key + ".json")


def scan(paths: list[str], jobs: int = DEFAULT_JOBS, deep: bool = False,
         tools: bool = False, use_cache: bool = True, cache_path: str = "",
         max_bytes: int = DEFAULT_MAX_BYTES) -> WorkspaceResult:
    started = time.perf_counter()
    files, errors, skipped = discover(paths, max_bytes=max_bytes)
    selected_cache = Path(cache_path) if cache_path else (default_cache_path(paths) if use_cache else None)
    if selected_cache:
        cache_resolved = selected_cache.expanduser().resolve()
        files = [path for path in files if path != cache_resolved]
    cache = ScanCache(selected_cache)
    # Computed once, before any worker starts: the seed describes the whole
    # project, so deriving it per file would be both wrong and quadratic.
    cross_file_taint, cross_file_id = _java_cross_file_seed(files, max_bytes)

    def one(path: Path) -> FileResult:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return FileResult(str(path), "", _language(path), "failed", "failed", errors=[str(exc)])
        digest = _digest(data, deep, tools, cross_file_id)
        cached = cache.get(path, digest) if use_cache else None
        if cached:
            return cached
        result = _scan_uncached(path, deep, tools, max_bytes,
                                cross_file_taint, cross_file_id)
        if use_cache:
            cache.put(result)
        return result

    workers = max(1, min(int(jobs or 1), 32))
    if workers == 1:
        results = [one(path) for path in files]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="attestor-scan") as pool:
            results = list(pool.map(one, files))
    if use_cache:
        cache.save()
    all_issues = sorted(
        (issue for result in results for issue in result.issues),
        key=lambda item: (-SEVERITY_RANK.get(item.severity, 0), item.path.lower(), item.line, item.rule),
    )
    operational_errors = errors + ["%s: %s" % (result.path, error)
                                   for result in results for error in result.errors]
    if operational_errors or any(result.status == "failed" for result in results):
        status = "failed"
    elif not files:
        status = "unsupported"
    elif all_issues:
        status = "findings"
    else:
        status = "clean"
    return WorkspaceResult(
        ENGINE_VERSION, [str(Path(path).expanduser()) for path in paths], status,
        len(files), len(results), sum(1 for result in results if result.cached),
        all_issues, results, operational_errors, skipped,
        int((time.perf_counter() - started) * 1000),
    )


def to_sarif(result: WorkspaceResult) -> dict:
    rows = []
    for issue in result.issues:
        rows.append({
            "ruleId": issue.rule,
            "level": "error" if issue.severity in {"CRITICAL", "HIGH"} else (
                "warning" if issue.severity == "MEDIUM" else "note"),
            "message": {"text": issue.message + ((" Fix: " + issue.fix) if issue.fix else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": issue.path.replace("\\", "/")},
                "region": {"startLine": issue.line},
            }}],
            "properties": {"source": issue.source, "confidence": issue.confidence,
                           "category": issue.category, "cwe": issue.cwe,
                           "owasp": issue.owasp, "pack": issue.pack,
                           "fingerprint": issue.fingerprint,
                           "asvs": list(issue.asvs),
                           "cwe_top25_2025_rank": issue.cwe_top25_2025_rank},
        })
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "Attestor", "version": ENGINE_VERSION}},
                      "results": rows}]}


def render_markdown(result: WorkspaceResult) -> str:
    lines = ["# Attestor 3.0 workspace scan", "", "- Status: **%s**" % result.status,
             "- Files: %d" % result.files_scanned, "- Findings: %d" % len(result.issues),
             "- Cache hits: %d" % result.cache_hits, "- Elapsed: %d ms" % result.elapsed_ms]
    if result.errors:
        lines += ["", "## Scan errors", ""] + ["- " + error for error in result.errors]
    if result.issues:
        lines += ["", "## Findings", ""]
        for issue in result.issues:
            metadata = " · ".join(item for item in (
                issue.category, issue.cwe, issue.owasp) if item)
            lines += ["### %s · %s" % (issue.severity, issue.rule), "",
                      "`%s:%d` — %s" % (issue.path, issue.line, issue.message), "",
                      (("Metadata: %s" % metadata) if metadata else ""),
                      "Fix: %s" % (issue.fix or "manual review required"), ""]
    return "\n".join(lines)


def render_html(result: WorkspaceResult) -> str:
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td><code>%s:%d</code></td><td>%s</td></tr>" % (
            html.escape(issue.severity), html.escape(issue.rule), html.escape(issue.path),
            issue.line, html.escape(issue.message)) for issue in result.issues)
    return ("<!doctype html><meta charset='utf-8'><title>Attestor 3.0 scan</title>"
            "<style>body{font:14px system-ui;margin:2rem;background:#111;color:#eee}"
            "table{border-collapse:collapse;width:100%%}td,th{padding:.5rem;border:1px solid #444}"
            "code{color:#8bc5ff}</style><h1>Attestor 3.0 workspace scan</h1>"
            "<p>Status: <strong>%s</strong> · %d files · %d findings · %d ms</p>"
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th>"
            "</tr></thead><tbody>%s</tbody></table>" % (
                html.escape(result.status), result.files_scanned, len(result.issues), result.elapsed_ms, rows))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="files or workspace roots")
    parser.add_argument("--jobs", type=int, default=DEFAULT_JOBS)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--tools", action="store_true", help="run safe external syntax/compiler adapters")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--cache", default="", help="explicit cache file")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--format", choices=("text", "json", "sarif", "markdown", "html"), default="text")
    args = parser.parse_args(argv)
    result = scan(args.paths, args.jobs, args.deep, args.tools, not args.no_cache,
                  args.cache, max(1024, args.max_bytes))
    if args.format == "json":
        print(json.dumps(asdict(result), indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(result), indent=2))
    elif args.format == "markdown":
        print(render_markdown(result))
    elif args.format == "html":
        print(render_html(result))
    else:
        print("Attestor 3.0 workspace scan: %s" % result.status)
        print("files=%d findings=%d cache_hits=%d elapsed_ms=%d" % (
            result.files_scanned, len(result.issues), result.cache_hits, result.elapsed_ms))
        for error in result.errors:
            print("ERROR: " + error, file=sys.stderr)
        for issue in result.issues:
            print("%s:%d [%s] %s — %s" % (
                issue.path, issue.line, issue.severity, issue.rule, issue.message))
    if result.status in {"failed", "unsupported"}:
        return 2
    return min(len(result.issues), 250)


if __name__ == "__main__":
    raise SystemExit(main())
