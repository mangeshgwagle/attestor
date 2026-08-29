#!/usr/bin/env python3
"""Deterministic, non-executing engineering analysis for Attestor 4.0.

The engine turns parser-observed repository facts into bounded engineering
guidance.  Python evidence comes from CPython's AST parser.  Other supported
languages use Attestor 3.5's bounded lexical polyglot IR.  JSON contracts use the
standard JSON parser and SQL migration evidence is deliberately lexical.

Nothing in this module imports target modules, invokes a compiler, starts a
process, accesses the network, installs dependencies, runs tests, or applies a
patch.  Plans describe work and gates; they are not proof that work succeeded.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

import polyglot_ir35


SCHEMA = "attestor-engineering/4.0"
VERSION = "4.0.0"
ANALYSIS_LEVEL = "parser-evidence-and-bounded-static-heuristics"

_SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_DIRECT_SUFFIXES = {".py": "python", ".pyw": "python", ".sql": "sql"}
_CONTRACT_NAMES = re.compile(r"(?:^|[._-])(schema|openapi|swagger)(?:[._-]|$)", re.I)
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv",
    "venv", "node_modules", "vendor", "dist", "build", "target", "bin",
    "obj", ".gradle", ".next", "coverage",
})
_ROUTE_METHODS = frozenset({
    "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ANY", "USE",
})
_JSON_METHODS = frozenset(method.casefold() for method in _ROUTE_METHODS - {"ANY", "USE"})
_BLOCKING_ASYNC_CALLS = frozenset({
    "time.sleep", "sleep", "requests.get", "requests.post", "requests.put",
    "requests.patch", "requests.delete", "urllib.request.urlopen", "urlopen",
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "os.system", "os.popen",
    "socket.create_connection", "open",
})
_REMEDIATION_BY_CATEGORY = {
    "api-contract": "Add compatibility-focused contract tests, resolve ownership, and version intentional breaking changes.",
    "architecture": "Characterize behavior, introduce a narrow dependency seam, and change one edge at a time.",
    "concurrency": "Create deterministic schedule/cancellation tests and enforce one documented ownership and lock order.",
    "correctness": "Add a failing regression test, make the smallest scoped correction, and rescan.",
    "data-contract": "Validate required/optional fields and backward-compatible serialization before changing the contract.",
    "debuggability": "Preserve failure context, add an observable error path, and freeze a minimized reproducer.",
    "maintainability": "Add characterization tests and refactor in small behavior-preserving steps.",
    "migration": "Use an expand/backfill/verify/contract rollout with rollback evidence.",
    "performance": "Measure representative baselines and complexity growth before and after a scoped change.",
}


class EngineeringError(ValueError):
    """The caller supplied an invalid boundary or unsupported IR document."""


@dataclass(frozen=True)
class Limits:
    max_files: int = 2_000
    max_file_bytes: int = 1 * 1024 * 1024
    max_direct_bytes: int = 24 * 1024 * 1024
    max_polyglot_bytes: int = 48 * 1024 * 1024
    max_ir_bytes: int = 64 * 1024 * 1024
    max_evidence: int = 20_000
    max_issues: int = 2_000
    max_graph_edges: int = 30_000
    max_impact: int = 5_000
    max_test_cases: int = 500
    max_plan_units: int = 200
    max_issue_chars: int = 8_192

    def __post_init__(self) -> None:
        boundaries = {
            "max_files": (self.max_files, 1, 20_000),
            "max_file_bytes": (self.max_file_bytes, 1_024, 16 * 1024 * 1024),
            "max_direct_bytes": (self.max_direct_bytes, 1_024, 256 * 1024 * 1024),
            "max_polyglot_bytes": (self.max_polyglot_bytes, 1_024, 256 * 1024 * 1024),
            "max_ir_bytes": (self.max_ir_bytes, 1_024, 256 * 1024 * 1024),
            "max_evidence": (self.max_evidence, 100, 100_000),
            "max_issues": (self.max_issues, 10, 20_000),
            "max_graph_edges": (self.max_graph_edges, 100, 200_000),
            "max_impact": (self.max_impact, 10, 50_000),
            "max_test_cases": (self.max_test_cases, 10, 5_000),
            "max_plan_units": (self.max_plan_units, 1, 2_000),
            "max_issue_chars": (self.max_issue_chars, 32, 65_536),
        }
        for name, (value, minimum, maximum) in boundaries.items():
            if (not isinstance(value, int) or isinstance(value, bool) or
                    not minimum <= value <= maximum):
                raise EngineeringError(
                    "%s must be an integer between %d and %d" %
                    (name, minimum, maximum))


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise EngineeringError("engineering evidence must be bounded JSON data") from exc


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def deterministic_json(value: Mapping[str, Any], *, pretty: bool = False) -> str:
    """Return canonical JSON suitable for report persistence or hashing."""
    if pretty:
        return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                          allow_nan=False) + "\n"
    return _canonical(value).decode("utf-8")


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Verify schema and deterministic digest; this is integrity, not authenticity."""
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["report is not a JSON object"]
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        errors.append("unsupported engineering schema or version")
    digest = report.get("report_sha256")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        expected = _sha(body)
    except EngineeringError:
        errors.append("report contains non-JSON evidence")
    else:
        if digest != expected:
            errors.append("report digest mismatch")
    return not errors, errors


def _bounded_text(value: Any, maximum: int = 1_000) -> str:
    text = str(value) if value is not None else ""
    text = _CONTROL_RE.sub(" ", text)
    return " ".join(text.split())[:maximum]


def _safe_relative(value: str | os.PathLike[str]) -> str:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise EngineeringError("changed path must be text or path-like") from exc
    if (not isinstance(raw, str) or not raw or len(raw) > 4_096 or
            _CONTROL_RE.search(raw)):
        raise EngineeringError("changed path is invalid")
    normalized = raw.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise EngineeringError("changed path escapes the analysis root")
    return pure.as_posix()


def _relative(base: Path, path: Path) -> str:
    return path.resolve(strict=False).relative_to(base).as_posix()


def _kind_for_direct(path: Path) -> str:
    suffix = path.suffix.casefold()
    if suffix in _DIRECT_SUFFIXES:
        return _DIRECT_SUFFIXES[suffix]
    if suffix == ".json" and _CONTRACT_NAMES.search(path.name):
        return "json-contract"
    return ""


class _EvidenceStore:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self._rows: dict[str, dict[str, Any]] = {}
        self.truncated = False

    def add(self, kind: str, path: str, line: int, parser: str, fact: str, *,
            symbol: str = "", precision: str = "observed") -> str:
        body = {
            "kind": _bounded_text(kind, 80),
            "path": _bounded_text(path, 4_096),
            "line": max(1, min(int(line) if isinstance(line, int) else 1, 1_000_000_000)),
            "parser": _bounded_text(parser, 80),
            "fact": _bounded_text(fact, 1_000),
            "symbol": _bounded_text(symbol, 512),
            "precision": precision if precision in {"observed", "parser-derived", "lexical"}
            else "lexical",
        }
        identifier = "eng40-ev-" + _sha(body)[:24]
        if identifier in self._rows:
            return identifier
        if len(self._rows) >= self.maximum:
            self.truncated = True
            return ""
        self._rows[identifier] = {"id": identifier, **body}
        return identifier

    def rows(self) -> list[dict[str, Any]]:
        return sorted(self._rows.values(), key=lambda row: (
            row["path"], row["line"], row["kind"], row["id"]))


class _IssueStore:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self._rows: dict[str, dict[str, Any]] = {}
        self.truncated = False

    def add(self, rule: str, severity: str, category: str, message: str, *,
            path: str = "", line: int = 1, evidence_ids: Iterable[str] = (),
            confidence: str = "review-required", limitation: str = "") -> str:
        severity = severity if severity in _SEVERITY_ORDER else "MEDIUM"
        normalized_category = _bounded_text(category, 80)
        body = {
            "rule": _bounded_text(rule, 160), "severity": severity,
            "category": normalized_category,
            "message": _bounded_text(message, 1_000),
            "path": _bounded_text(path, 4_096),
            "line": max(1, min(int(line) if isinstance(line, int) else 1, 1_000_000_000)),
            "confidence": confidence if confidence in {
                "parser-observed", "strong-static-indicator", "review-required"
            } else "review-required",
            "evidence_ids": sorted(set(item for item in evidence_ids if item))[:16],
            "limitation": _bounded_text(limitation, 1_000),
            "remediation": _REMEDIATION_BY_CATEGORY.get(
                normalized_category,
                "Review the evidence, add a failing regression test, and apply the smallest verified change."),
        }
        fingerprint = _sha(body)
        identifier = "eng40-issue-" + fingerprint[:24]
        if identifier in self._rows:
            return identifier
        if len(self._rows) >= self.maximum:
            self.truncated = True
            return ""
        self._rows[identifier] = {"id": identifier, "fingerprint": fingerprint, **body}
        return identifier

    def rows(self) -> list[dict[str, Any]]:
        return sorted(self._rows.values(), key=lambda row: (
            -_SEVERITY_ORDER[row["severity"]], row["path"], row["line"],
            row["rule"], row["id"]))


@dataclass(frozen=True)
class _DirectInput:
    path: str
    kind: str
    sha256: str
    size: int
    text: str


def _safe_read(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags | no_follow)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("input is not a regular file")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(descriptor, min(65_536, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _discover_direct(requested: Path, base: Path, limits: Limits,
                     gaps: list[dict[str, Any]]) -> tuple[list[_DirectInput], int, int]:
    candidates: list[Path] = []
    if requested.is_file():
        if _kind_for_direct(requested):
            candidates = [requested]
    else:
        boundary = False
        try:
            for current, directories, filenames in os.walk(requested, followlinks=False):
                if boundary:
                    directories[:] = []
                    continue
                here = Path(current)
                retained = []
                for name in sorted(directories, key=str.casefold):
                    child = here / name
                    if name in _SKIP_DIRS:
                        continue
                    if child.is_symlink():
                        try:
                            label = _relative(base, child)
                        except (OSError, ValueError):
                            label = name
                        gaps.append({"kind": "symlink-skipped", "path": label,
                                     "message": "directory symbolic link was not followed"})
                        continue
                    retained.append(name)
                directories[:] = retained
                for name in sorted(filenames, key=str.casefold):
                    item = here / name
                    if _kind_for_direct(item):
                        if len(candidates) >= limits.max_files:
                            try:
                                label = _relative(base, item)
                            except (OSError, ValueError):
                                label = name
                            gaps.append({"kind": "file-boundary", "path": label,
                                         "message": "direct-parser discovery stopped at its file boundary"})
                            boundary = True
                            directories[:] = []
                            break
                        candidates.append(item)
        except OSError as exc:
            gaps.append({"kind": "discovery-error", "path": ".",
                         "message": type(exc).__name__})
    candidates = sorted(candidates, key=lambda item: item.relative_to(base).as_posix().casefold())
    discovered = len(candidates)
    records: list[_DirectInput] = []
    total = 0
    for path in candidates:
        try:
            relative = _relative(base, path)
        except (OSError, ValueError):
            gaps.append({"kind": "path-escape", "path": path.name,
                         "message": "candidate resolved outside the analysis root"})
            continue
        if path.is_symlink():
            gaps.append({"kind": "symlink-skipped", "path": relative,
                         "message": "file symbolic link was not read"})
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            gaps.append({"kind": "unreadable", "path": relative,
                         "message": type(exc).__name__})
            continue
        if size > limits.max_file_bytes:
            gaps.append({"kind": "file-too-large", "path": relative,
                         "message": "file exceeds the direct-parser byte boundary"})
            continue
        if total + size > limits.max_direct_bytes:
            gaps.append({"kind": "direct-byte-boundary", "path": relative,
                         "message": "aggregate direct-parser byte boundary reached"})
            continue
        try:
            raw = _safe_read(path, limits.max_file_bytes)
        except OSError as exc:
            gaps.append({"kind": "unreadable", "path": relative,
                         "message": type(exc).__name__})
            continue
        if len(raw) > limits.max_file_bytes:
            gaps.append({"kind": "file-grew-too-large", "path": relative,
                         "message": "file grew across its byte boundary while read"})
            continue
        if b"\0" in raw[:8192]:
            gaps.append({"kind": "binary-skipped", "path": relative,
                         "message": "NUL byte indicated a non-text input"})
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            gaps.append({"kind": "decode-error", "path": relative,
                         "message": "direct-parser inputs require valid UTF-8"})
            continue
        total += len(raw)
        records.append(_DirectInput(relative, _kind_for_direct(path),
                                    hashlib.sha256(raw).hexdigest(), len(raw), text))
    return records, discovered, total


def _node_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id[:256]
    if isinstance(node, ast.Attribute):
        prefix = _node_name(node.value)
        return ((prefix + ".") if prefix else "") + node.attr[:256]
    if isinstance(node, ast.Subscript):
        prefix = _node_name(node.value)
        return (prefix + "[]")[:256]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return (_node_name(node.left) + "|" + _node_name(node.right))[:256]
    if isinstance(node, ast.Constant) and node.value is None:
        return "None"
    return ""


def _annotation_shape(node: ast.AST | None) -> str:
    if node is None:
        return ""
    name = _node_name(node)
    return name if name else type(node).__name__[:80]


def _module_name(path: str) -> str:
    pure = PurePosixPath(path)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or pure.stem


def _function_nodes(node: ast.AST) -> Iterable[ast.AST]:
    """Walk one function while excluding nested function and class bodies."""
    stack = list(reversed(getattr(node, "body", [])))
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                ast.ClassDef)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(current))))


def _function_metrics(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    complexity = 1
    maximum_loop_depth = 0
    calls: list[tuple[str, int]] = []

    def descend(current: ast.AST, loop_depth: int = 0) -> None:
        nonlocal complexity, maximum_loop_depth
        if current is not node and isinstance(current, (
                ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return
        next_depth = loop_depth
        if isinstance(current, (ast.For, ast.AsyncFor, ast.While)):
            complexity += 1
            next_depth += 1
            maximum_loop_depth = max(maximum_loop_depth, next_depth)
        elif isinstance(current, (ast.If, ast.IfExp, ast.With, ast.AsyncWith)):
            complexity += isinstance(current, (ast.If, ast.IfExp))
        elif isinstance(current, ast.Try):
            complexity += max(1, len(current.handlers))
        elif isinstance(current, ast.BoolOp):
            complexity += max(0, len(current.values) - 1)
        elif isinstance(current, ast.Match):
            complexity += len(current.cases)
        elif isinstance(current, (ast.ListComp, ast.SetComp, ast.DictComp,
                                  ast.GeneratorExp)):
            complexity += len(current.generators)
        if isinstance(current, ast.Call):
            calls.append((_node_name(current.func), getattr(current, "lineno", 1)))
        for child in ast.iter_child_nodes(current):
            descend(child, next_depth)

    descend(node)
    return {
        "complexity_estimate": complexity,
        "maximum_loop_depth": maximum_loop_depth,
        "calls": sorted(set(calls), key=lambda item: (item[1], item[0])),
    }


def _terminal_statement(node: ast.stmt) -> bool:
    return isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue))


def _route_from_decorator(decorator: ast.AST) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call):
        return None
    target = _node_name(decorator.func)
    short = target.rsplit(".", 1)[-1].casefold()
    if short not in {"get", "post", "put", "patch", "delete", "options", "head", "route"}:
        return None
    route = ""
    if decorator.args and isinstance(decorator.args[0], ast.Constant) \
            and isinstance(decorator.args[0].value, str):
        route = decorator.args[0].value
    if not route or len(route) > 1_024 or _CONTROL_RE.search(route):
        return None
    method = short.upper()
    if short == "route":
        methods = next((item.value for item in decorator.keywords if item.arg == "methods"), None)
        if isinstance(methods, (ast.List, ast.Tuple)) and methods.elts:
            first = methods.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                candidate = first.value.upper()
                method = candidate if candidate in _ROUTE_METHODS else "ANY"
        else:
            method = "ANY"
    return method, route


def _json_without_duplicates(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise EngineeringError("JSON contract contains a duplicate object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise EngineeringError("JSON contract contains a non-finite number: " + value)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _sql_without_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda match: "\n" * match.group(0).count("\n"),
                  text, flags=re.DOTALL)
    text = re.sub(r"(?m)--[^\r\n]*", "", text)
    return re.sub(r"'(?:''|[^'])*'", "''", text)


def _mutable_default(node: ast.AST | None) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return (isinstance(node, ast.Call) and
            _node_name(node.func) in {"list", "dict", "set", "defaultdict"})


def _lock_events(node: ast.FunctionDef | ast.AsyncFunctionDef,
                 path: str, evidence: _EvidenceStore) -> list[tuple[str, int, str]]:
    events: list[tuple[str, int, str]] = []
    for current in _function_nodes(node):
        lock_name = ""
        if isinstance(current, ast.Call):
            target = _node_name(current.func)
            if target.endswith((".acquire", ".lock")):
                lock_name = target.rsplit(".", 1)[0]
        elif isinstance(current, (ast.With, ast.AsyncWith)):
            for item in current.items:
                candidate = _node_name(item.context_expr)
                if re.search(r"(?:lock|mutex|semaphore|guard)", candidate, re.I):
                    event = evidence.add(
                        "lock-acquisition", path, getattr(current, "lineno", 1),
                        "python-ast", "context manager acquires a lock-like object",
                        symbol=candidate, precision="parser-derived")
                    events.append((candidate, getattr(current, "lineno", 1), event))
            continue
        if lock_name:
            event = evidence.add(
                "lock-acquisition", path, getattr(current, "lineno", 1),
                "python-ast", "call acquires a lock-like object", symbol=lock_name,
                precision="parser-derived")
            events.append((lock_name, getattr(current, "lineno", 1), event))
    unique: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()
    for event in events:
        identity = (event[0], event[1])
        if identity not in seen:
            seen.add(identity)
            unique.append(event)
    return [event for _index, event in sorted(
        enumerate(unique), key=lambda pair: (pair[1][1], pair[0]))]


def _unreachable_statements(body: Sequence[ast.stmt]) -> Iterable[ast.stmt]:
    terminated = False
    for statement in body:
        if terminated:
            yield statement
            break
        if _terminal_statement(statement):
            terminated = True


def _analyze_python(item: _DirectInput, evidence: _EvidenceStore,
                    issues: _IssueStore, gaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        tree = ast.parse(item.text, filename=item.path, type_comments=True)
    except (SyntaxError, ValueError, MemoryError) as exc:
        gaps.append({
            "kind": "python-parse-error", "path": item.path,
            "line": max(1, int(getattr(exc, "lineno", 1) or 1)),
            "message": type(exc).__name__,
        })
        return None
    parse_evidence = evidence.add(
        "parse-success", item.path, 1, "python-ast",
        "CPython AST parser accepted this file's syntax", precision="parser-derived")
    module = _module_name(item.path)
    result: dict[str, Any] = {
        "path": item.path, "module": module, "language": "python",
        "sha256": item.sha256, "bytes": item.size, "parser": "python-ast",
        "parse_evidence_id": parse_evidence, "imports": [], "functions": [],
        "types": [], "routes": [], "data_contracts": [], "lock_orders": [],
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                ev = evidence.add(
                    "import", item.path, getattr(node, "lineno", 1), "python-ast",
                    "module import declaration", symbol=alias.name,
                    precision="parser-derived")
                result["imports"].append({
                    "path": item.path, "line": getattr(node, "lineno", 1),
                    "specifier": alias.name[:512], "level": 0, "kind": "import",
                    "evidence_id": ev,
                })
        elif isinstance(node, ast.ImportFrom):
            name = node.module or ""
            ev = evidence.add(
                "import", item.path, getattr(node, "lineno", 1), "python-ast",
                "from-import declaration", symbol=("." * node.level + name)[:512],
                precision="parser-derived")
            result["imports"].append({
                "path": item.path, "line": getattr(node, "lineno", 1),
                "specifier": name[:512], "level": int(node.level), "kind": "from",
                "evidence_id": ev,
            })
        elif isinstance(node, ast.Dict):
            seen: dict[tuple[str, str], ast.AST] = {}
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(
                        key.value, (str, int, float, bool, type(None))):
                    identity = (type(key.value).__name__, repr(key.value))
                    if identity in seen:
                        ev = evidence.add(
                            "duplicate-literal-key", item.path,
                            getattr(key, "lineno", 1), "python-ast",
                            "dictionary literal repeats a constant key",
                            precision="parser-derived")
                        issues.add(
                            "python/duplicate-literal-dict-key", "MEDIUM", "correctness",
                            "Dictionary literal repeats a constant key; the earlier value is overwritten.",
                            path=item.path, line=getattr(key, "lineno", 1),
                            evidence_ids=[ev], confidence="parser-observed")
                    seen[identity] = key

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.classes: list[str] = []
            self.functions: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            qualified = ".".join([module, *self.classes, node.name])
            bases = sorted(filter(None, (_node_name(base) for base in node.bases)))
            decorators = sorted(filter(None, (_node_name(dec) for dec in node.decorator_list)))
            ev = evidence.add(
                "type-declaration", item.path, node.lineno, "python-ast",
                "class declaration", symbol=qualified, precision="parser-derived")
            record = {
                "path": item.path, "line": node.lineno, "name": node.name,
                "qualified_name": qualified, "kind": "class", "bases": bases[:32],
                "decorators": decorators[:32], "evidence_id": ev,
            }
            result["types"].append(record)
            is_contract = (any(name.endswith(("BaseModel", "TypedDict", "NamedTuple"))
                               for name in bases) or
                           any(name.endswith("dataclass") for name in decorators))
            fields = []
            for child in node.body:
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                    fields.append({
                        "name": child.target.id[:256],
                        "type": _annotation_shape(child.annotation),
                        "required": child.value is None,
                        "line": getattr(child, "lineno", node.lineno),
                    })
            if is_contract:
                contract_ev = evidence.add(
                    "data-contract", item.path, node.lineno, "python-ast",
                    "typed Python data-contract class", symbol=qualified,
                    precision="parser-derived")
                result["data_contracts"].append({
                    "kind": "python-typed-class", "name": qualified,
                    "path": item.path, "line": node.lineno,
                    "fields": sorted(fields, key=lambda row: row["name"])[:512],
                    "evidence_id": contract_ev,
                    "compatibility_proven": False,
                })
            self.classes.append(node.name)
            self.generic_visit(node)
            self.classes.pop()

        def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified = ".".join([module, *self.classes, *self.functions, node.name])
            args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            parameter_count = (len(args) + bool(node.args.vararg) + bool(node.args.kwarg))
            positional_required = max(
                0, len(node.args.posonlyargs) + len(node.args.args) - len(node.args.defaults))
            keyword_required = sum(default is None for default in node.args.kw_defaults)
            metrics = _function_metrics(node)
            ev = evidence.add(
                "function-signature", item.path, node.lineno, "python-ast",
                "function signature and control-flow shape", symbol=qualified,
                precision="parser-derived")
            record = {
                "path": item.path, "line": node.lineno, "name": node.name,
                "qualified_name": qualified,
                "kind": "async-function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                "parameter_count": parameter_count,
                "required_parameter_count": positional_required + keyword_required,
                "annotated_parameter_count": sum(arg.annotation is not None for arg in args),
                "return_annotation": _annotation_shape(node.returns),
                "complexity_estimate": metrics["complexity_estimate"],
                "maximum_loop_depth": metrics["maximum_loop_depth"],
                "public": not node.name.startswith("_"), "evidence_id": ev,
            }
            result["functions"].append(record)
            if parameter_count >= 8:
                issues.add(
                    "engineering/long-parameter-list", "LOW", "maintainability",
                    "Function has eight or more parameters; review whether a typed request object improves cohesion.",
                    path=item.path, line=node.lineno, evidence_ids=[ev],
                    confidence="parser-observed")
            if metrics["complexity_estimate"] >= 12:
                issues.add(
                    "engineering/high-branch-complexity", "MEDIUM", "maintainability",
                    "Function has a high parser-derived branch complexity estimate and needs focused tests before refactoring.",
                    path=item.path, line=node.lineno, evidence_ids=[ev],
                    confidence="strong-static-indicator",
                    limitation="The estimate is not a compiler control-flow graph or runtime complexity proof.")
            if metrics["maximum_loop_depth"] >= 2:
                issues.add(
                    "performance/nested-loop-review", "MEDIUM", "performance",
                    "Nested loops were observed; measure representative input growth before changing the algorithm.",
                    path=item.path, line=node.lineno, evidence_ids=[ev],
                    confidence="review-required",
                    limitation="Nested syntax alone does not establish an unacceptable complexity class.")
            for unreachable in _unreachable_statements(node.body):
                unreachable_ev = evidence.add(
                    "unreachable-after-terminal", item.path,
                    getattr(unreachable, "lineno", node.lineno), "python-ast",
                    "statement follows an unconditional terminal statement in the same block",
                    symbol=qualified, precision="parser-derived")
                issues.add(
                    "python/unreachable-after-terminal", "MEDIUM", "correctness",
                    "Statement follows return/raise/break/continue in the same block and is unreachable on that block path.",
                    path=item.path, line=getattr(unreachable, "lineno", node.lineno),
                    evidence_ids=[unreachable_ev], confidence="parser-observed")
            defaults: list[ast.AST | None] = [*node.args.defaults, *node.args.kw_defaults]
            if any(_mutable_default(default) for default in defaults):
                issues.add(
                    "python/mutable-default-argument", "HIGH", "api-contract",
                    "Function signature has a mutable default that can retain state across calls.",
                    path=item.path, line=node.lineno, evidence_ids=[ev],
                    confidence="parser-observed")
            if isinstance(node, ast.AsyncFunctionDef):
                for call_name, call_line in metrics["calls"]:
                    if call_name in _BLOCKING_ASYNC_CALLS:
                        blocking_ev = evidence.add(
                            "blocking-call-in-async", item.path, call_line, "python-ast",
                            "synchronous blocking-call name inside async function",
                            symbol=call_name, precision="parser-derived")
                        issues.add(
                            "concurrency/blocking-call-in-async", "HIGH", "concurrency",
                            "A synchronous blocking-call name appears inside an async function; verify event-loop behavior.",
                            path=item.path, line=call_line, evidence_ids=[blocking_ev, ev],
                            confidence="strong-static-indicator",
                            limitation="Name resolution is syntactic and can be shadowed.")
                for current in _function_nodes(node):
                    if (isinstance(current, ast.Expr) and isinstance(current.value, ast.Call)
                            and _node_name(current.value.func) in {
                                "asyncio.create_task", "create_task"}):
                        task_ev = evidence.add(
                            "discarded-task-handle", item.path,
                            getattr(current, "lineno", node.lineno), "python-ast",
                            "create_task call result is used as a bare expression",
                            symbol=qualified, precision="parser-derived")
                        issues.add(
                            "concurrency/discarded-task-handle", "MEDIUM", "concurrency",
                            "Created task handle is discarded; cancellation, exceptions, and lifecycle ownership need review.",
                            path=item.path, line=getattr(current, "lineno", node.lineno),
                            evidence_ids=[task_ev], confidence="parser-observed")
            for current in _function_nodes(node):
                if (isinstance(current, ast.While) and
                        isinstance(current.test, ast.Constant) and current.test.value is True):
                    loop_ev = evidence.add(
                        "syntactically-unbounded-loop", item.path,
                        getattr(current, "lineno", node.lineno), "python-ast",
                        "while condition is the literal True", symbol=qualified,
                        precision="parser-derived")
                    issues.add(
                        "performance/unbounded-loop-review", "MEDIUM", "performance",
                        "Literal while True loop requires an independently verified exit, cancellation, or backpressure path.",
                        path=item.path, line=getattr(current, "lineno", node.lineno),
                        evidence_ids=[loop_ev], confidence="review-required",
                        limitation="The body may contain a valid break or cancellation path.")
            locks = _lock_events(node, item.path, evidence)
            if len(locks) >= 2:
                result["lock_orders"].append({
                    "function": qualified,
                    "order": [name for name, _line_no, _ev in locks],
                    "evidence_ids": [event for _name, _line_no, event in locks if event],
                    "path": item.path, "line": node.lineno,
                })
            for decorator in node.decorator_list:
                route = _route_from_decorator(decorator)
                if route:
                    method, literal = route
                    route_ev = evidence.add(
                        "api-route", item.path, getattr(decorator, "lineno", node.lineno),
                        "python-ast", "literal API route decorator", symbol=method + " " + literal,
                        precision="parser-derived")
                    result["routes"].append({
                        "method": method, "route": literal, "path": item.path,
                        "line": getattr(decorator, "lineno", node.lineno),
                        "handler": qualified, "parser": "python-ast",
                        "evidence_id": route_ev,
                    })
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._function(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            broad = node.type is None or _node_name(node.type) in {"Exception", "BaseException"}
            suppresses = not node.body or all(isinstance(item_node, ast.Pass) for item_node in node.body)
            if broad and suppresses:
                ev = evidence.add(
                    "broad-exception-suppression", item.path, getattr(node, "lineno", 1),
                    "python-ast", "broad exception handler has no observable handling",
                    precision="parser-derived")
                issues.add(
                    "debug/broad-exception-suppression", "HIGH", "debuggability",
                    "Broad exception handler suppresses failures, reducing diagnosability and correctness evidence.",
                    path=item.path, line=getattr(node, "lineno", 1), evidence_ids=[ev],
                    confidence="parser-observed")
            self.generic_visit(node)

    Visitor().visit(tree)
    result["imports"] = sorted(result["imports"], key=lambda row: (
        row["line"], row["specifier"], row["kind"]))
    for key in ("functions", "types", "routes", "data_contracts", "lock_orders"):
        result[key] = sorted(result[key], key=lambda row: _canonical(row))
    return result


def _analyze_json_contract(item: _DirectInput, evidence: _EvidenceStore,
                           issues: _IssueStore,
                           gaps: list[dict[str, Any]]) -> tuple[list[dict[str, Any]],
                                                                list[dict[str, Any]]]:
    routes: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []
    try:
        value = _json_without_duplicates(item.text)
    except (json.JSONDecodeError, EngineeringError, RecursionError) as exc:
        gaps.append({"kind": "json-contract-parse-error", "path": item.path,
                     "line": int(getattr(exc, "lineno", 1) or 1),
                     "message": type(exc).__name__})
        return routes, contracts
    if not isinstance(value, dict):
        gaps.append({"kind": "json-contract-shape", "path": item.path, "line": 1,
                     "message": "top-level JSON contract is not an object"})
        return routes, contracts
    parse_ev = evidence.add(
        "parse-success", item.path, 1, "json",
        "standard JSON parser accepted this contract document", precision="parser-derived")

    def contract(name: str, document: Mapping[str, Any], kind: str) -> None:
        properties = document.get("properties")
        required = document.get("required")
        property_names = sorted(_bounded_text(key, 256) for key in properties) \
            if isinstance(properties, dict) else []
        required_names = sorted(_bounded_text(key, 256) for key in required) \
            if isinstance(required, list) and all(isinstance(key, str) for key in required) else []
        ev = evidence.add(
            "data-contract", item.path, 1, "json", "JSON data contract object",
            symbol=name, precision="parser-derived")
        contracts.append({
            "kind": kind, "name": _bounded_text(name, 512), "path": item.path,
            "line": 1, "fields": property_names[:2_000],
            "required": required_names[:2_000],
            "additional_properties": document.get("additionalProperties", "unspecified")
            if isinstance(document.get("additionalProperties", "unspecified"), bool)
            else "specified-non-boolean",
            "evidence_id": ev or parse_ev, "compatibility_proven": False,
        })
        missing = sorted(set(required_names) - set(property_names))
        if missing:
            issues.add(
                "contract/required-property-not-declared", "HIGH", "data-contract",
                "JSON contract requires properties that are absent from its properties object.",
                path=item.path, line=1, evidence_ids=[ev, parse_ev],
                confidence="parser-observed")

    if isinstance(value.get("openapi"), str) or isinstance(value.get("swagger"), str):
        paths = value.get("paths")
        if isinstance(paths, dict):
            for route, path_item in sorted(paths.items(), key=lambda pair: str(pair[0])):
                if not isinstance(route, str) or not isinstance(path_item, dict):
                    continue
                for method, operation in sorted(path_item.items(), key=lambda pair: str(pair[0])):
                    if str(method).casefold() not in _JSON_METHODS:
                        continue
                    ev = evidence.add(
                        "api-route", item.path, 1, "json",
                        "OpenAPI literal path and operation", symbol=str(method).upper() + " " + route,
                        precision="parser-derived")
                    routes.append({
                        "method": str(method).upper(), "route": _bounded_text(route, 1_024),
                        "path": item.path, "line": 1,
                        "handler": _bounded_text(operation.get("operationId", "")
                                                 if isinstance(operation, dict) else "", 512),
                        "parser": "json", "evidence_id": ev,
                    })
        components = value.get("components")
        schemas = components.get("schemas") if isinstance(components, dict) else None
        if isinstance(schemas, dict):
            for name, document in sorted(schemas.items(), key=lambda pair: str(pair[0])):
                if isinstance(name, str) and isinstance(document, dict):
                    contract(name, document, "openapi-schema")
    else:
        contract(PurePosixPath(item.path).stem, value, "json-schema")
    return routes, contracts


def _analyze_sql(item: _DirectInput, evidence: _EvidenceStore,
                 issues: _IssueStore) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = _sql_without_comments(item.text)
    contracts: list[dict[str, Any]] = []
    migrations: list[dict[str, Any]] = []
    create_pattern = re.compile(
        r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][\w.$-]*)\s*\((.{0,262144}?)\)\s*;",
        re.I | re.DOTALL)
    for match in create_pattern.finditer(text):
        name = match.group(1)[:512]
        fields = []
        for fragment in match.group(2).split(",")[:2_000]:
            column = re.match(r"\s*([A-Za-z_][\w$-]*)\s+([A-Za-z_][\w ()\[\],]*)", fragment)
            if column and column.group(1).casefold() not in {
                    "primary", "foreign", "unique", "constraint", "check"}:
                fields.append({"name": column.group(1)[:256],
                               "type": " ".join(column.group(2).split())[:256]})
        ev = evidence.add(
            "data-contract", item.path, _line(text, match.start()), "sql-lexical",
            "CREATE TABLE declaration", symbol=name, precision="lexical")
        contracts.append({
            "kind": "sql-table", "name": name, "path": item.path,
            "line": _line(text, match.start()), "fields": fields,
            "evidence_id": ev, "compatibility_proven": False,
        })
    destructive_patterns = [
        ("drop-table", r"\bDROP\s+TABLE\b", "DROP TABLE can remove stored data."),
        ("drop-column", r"\bDROP\s+COLUMN\b", "DROP COLUMN can remove stored data."),
        ("alter-type", r"\bALTER\s+(?:COLUMN\s+)?[A-Za-z_]\w*\s+(?:TYPE|SET\s+DATA\s+TYPE)\b",
         "Column type alteration can be incompatible or lossy."),
        ("rename", r"\bRENAME\s+(?:COLUMN|TABLE|TO)\b",
         "Rename can break callers without a compatibility phase."),
        ("add-not-null", r"\bADD\s+(?:COLUMN\s+)?[A-Za-z_]\w*[^;\n]{0,512}\bNOT\s+NULL\b(?![^;\n]*\bDEFAULT\b)",
         "Adding NOT NULL without an observed default can fail on existing rows."),
    ]
    for kind, pattern, message in destructive_patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            line_no = _line(text, match.start())
            ev = evidence.add(
                "migration-operation", item.path, line_no, "sql-lexical",
                message, symbol=kind, precision="lexical")
            migrations.append({
                "kind": kind, "path": item.path, "line": line_no,
                "risk": message, "evidence_id": ev,
                "transaction_observed": bool(re.search(r"\b(?:BEGIN|START\s+TRANSACTION)\b", text, re.I)),
            })
            issues.add(
                "migration/" + kind, "HIGH", "migration", message,
                path=item.path, line=line_no, evidence_ids=[ev],
                confidence="strong-static-indicator",
                limitation="SQL dialect and deployment ordering are not resolved by lexical analysis.")
    return contracts, migrations


def _empty_polyglot(root: str, limits: Limits, reason: str) -> dict[str, Any]:
    return {
        "schema": polyglot_ir35.SCHEMA,
        "analysis_level": polyglot_ir35.ANALYSIS_LEVEL,
        "root": root, "files": [], "modules": [], "imports": [], "types": [],
        "functions": [], "calls": [], "routes": [], "manifests": [],
        "parse_gaps": ([{"path": ".", "line": 1, "kind": "not-run",
                         "message": reason}] if reason else []),
        "coverage": {
            "complete": False, "semantic_complete": False,
            "supported_files_discovered": 0, "source_files_parsed": 0,
            "manifest_files_parsed": 0, "bytes_read": 0, "languages": {},
            "limits": {"max_files": limits.max_files,
                       "max_file_bytes": limits.max_file_bytes,
                       "max_total_bytes": limits.max_polyglot_bytes},
            "limitations": ["polyglot IR was unavailable"],
        },
    }


def _validated_ir(ir: Mapping[str, Any], requested: Path, base: Path,
                  limits: Limits) -> dict[str, Any]:
    if type(ir) is not dict or ir.get("schema") != polyglot_ir35.SCHEMA:
        raise EngineeringError("supplied IR does not use the supported Attestor 3.5 schema")
    encoded = _canonical(ir)
    if len(encoded) > limits.max_ir_bytes:
        raise EngineeringError("supplied IR exceeds its serialized byte boundary")
    copy = json.loads(encoded.decode("utf-8"))
    for key, maximum in {
            "files": limits.max_files, "modules": limits.max_files,
            "imports": limits.max_graph_edges * 2, "types": limits.max_evidence,
            "functions": limits.max_evidence, "calls": limits.max_evidence * 2,
            "routes": limits.max_evidence, "manifests": limits.max_files,
            "parse_gaps": limits.max_evidence}.items():
        value = copy.get(key)
        if not isinstance(value, list) or len(value) > maximum:
            raise EngineeringError("supplied IR %s list is absent or oversized" % key)
    for record in copy["files"]:
        if not isinstance(record, dict):
            raise EngineeringError("supplied IR file record is malformed")
        _safe_relative(record.get("path"))
    raw_root = copy.get("root")
    if not isinstance(raw_root, str) or _CONTROL_RE.search(raw_root):
        raise EngineeringError("supplied IR root is malformed")
    try:
        ir_root = Path(raw_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise EngineeringError("supplied IR root is not readable") from exc
    expected = requested if requested.is_dir() else requested
    if ir_root != expected:
        # A file IR is rooted at that file; repository IR is rooted at its directory.
        raise EngineeringError("supplied IR root does not match the selected analysis target")
    coverage = copy.get("coverage")
    if not isinstance(coverage, dict):
        raise EngineeringError("supplied IR coverage record is absent")
    return copy


def _local_polyglot_report(requested: Path, base: Path, limits: Limits,
                           gaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Run the inherited lexical parser one bounded file at a time.

    The Attestor 3.5 directory API builds a complete candidate list before applying
    its file boundary.  Attestor 4.0 instead stops discovery at the boundary, then
    re-bases each safe single-file IR into the selected repository namespace.
    """
    candidates: list[Path] = []
    discovery_gaps: list[dict[str, Any]] = []
    if requested.is_file():
        if polyglot_ir35.language_for(requested) or polyglot_ir35.manifest_kind(requested):
            candidates = [requested]
    else:
        boundary = False
        try:
            for current, directories, filenames in os.walk(requested, followlinks=False):
                if boundary:
                    directories[:] = []
                    continue
                here = Path(current)
                retained = []
                for name in sorted(directories, key=str.casefold):
                    child = here / name
                    if name in _SKIP_DIRS:
                        continue
                    if child.is_symlink():
                        try:
                            label = _relative(base, child)
                        except (OSError, ValueError):
                            label = name
                        discovery_gaps.append({
                            "path": label, "line": 1, "kind": "symlink-skipped",
                            "message": "directory symbolic link was not followed",
                        })
                        continue
                    retained.append(name)
                directories[:] = retained
                for name in sorted(filenames, key=str.casefold):
                    item = here / name
                    if not (polyglot_ir35.language_for(item) or
                            polyglot_ir35.manifest_kind(item)):
                        continue
                    if len(candidates) >= limits.max_files:
                        discovery_gaps.append({
                            "path": _relative(base, item), "line": 1,
                            "kind": "file-boundary",
                            "message": "polyglot discovery stopped at its file boundary",
                        })
                        boundary = True
                        directories[:] = []
                        break
                    candidates.append(item)
        except (OSError, ValueError) as exc:
            discovery_gaps.append({"path": ".", "line": 1,
                                   "kind": "discovery-error",
                                   "message": type(exc).__name__})
    aggregate = _empty_polyglot(str(requested), limits, "")
    aggregate["coverage"]["limitations"] = [
        "lexical extraction does not resolve types, overloads, macros, or dynamic dispatch",
        "generated, vendored, binary, oversized, unreadable, and linked files may be skipped",
        "no target code, build scripts, package hooks, compilers, or network services are run",
    ]
    aggregate["parse_gaps"] = list(discovery_gaps)
    aggregate["coverage"]["supported_files_discovered"] = len(candidates) + bool(
        any(row["kind"] == "file-boundary" for row in discovery_gaps))
    total = 0
    byte_boundary_reported = False
    for path in candidates:
        try:
            relative = _relative(base, path)
        except (OSError, ValueError):
            aggregate["parse_gaps"].append({
                "path": path.name, "line": 1, "kind": "path-escape",
                "message": "candidate resolved outside the selected root",
            })
            continue
        if path.is_symlink():
            aggregate["parse_gaps"].append({
                "path": relative, "line": 1, "kind": "symlink-skipped",
                "message": "file symbolic link was not read",
            })
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            aggregate["parse_gaps"].append({
                "path": relative, "line": 1, "kind": "unreadable",
                "message": type(exc).__name__,
            })
            continue
        if size > limits.max_file_bytes:
            aggregate["parse_gaps"].append({
                "path": relative, "line": 1, "kind": "file-too-large",
                "message": "file exceeds the polyglot byte boundary",
            })
            continue
        remaining = limits.max_polyglot_bytes - total
        if remaining <= 0 or size > remaining:
            if not byte_boundary_reported:
                aggregate["parse_gaps"].append({
                    "path": relative, "line": 1, "kind": "total-byte-boundary",
                    "message": "aggregate polyglot byte boundary reached",
                })
                byte_boundary_reported = True
            continue
        single = polyglot_ir35.analyze(
            path, max_files=1, max_file_bytes=limits.max_file_bytes,
            max_total_bytes=max(1, remaining))
        single_coverage = single.get("coverage", {})
        read = single_coverage.get("bytes_read", 0) \
            if isinstance(single_coverage, dict) else 0
        total += read if isinstance(read, int) and read >= 0 else 0
        raw_files = single.get("files", [])
        for record in raw_files if isinstance(raw_files, list) else []:
            if not isinstance(record, dict):
                continue
            copied = dict(record)
            copied["path"] = relative
            language = str(copied.get("language", ""))
            if language in {"javascript", "typescript", "rust", "c", "cpp"}:
                copied["module"] = PurePosixPath(relative).with_suffix("").as_posix().replace("/", ".")
            for key in ("imports", "types", "functions", "calls", "routes"):
                rows = copied.get(key, [])
                if isinstance(rows, list):
                    copied[key] = [{**row, "path": relative} if isinstance(row, dict) else row
                                   for row in rows]
            aggregate["files"].append(copied)
        raw_manifests = single.get("manifests", [])
        for record in raw_manifests if isinstance(raw_manifests, list) else []:
            if isinstance(record, dict):
                aggregate["manifests"].append({**record, "path": relative})
        raw_gaps = single.get("parse_gaps", [])
        for record in raw_gaps if isinstance(raw_gaps, list) else []:
            if isinstance(record, dict):
                aggregate["parse_gaps"].append({**record, "path": relative})
    for record in aggregate["files"]:
        aggregate["modules"].append({
            "path": record["path"], "language": record.get("language", "unknown"),
            "name": record.get("module", ""),
        })
        for key in ("imports", "types", "functions", "calls", "routes"):
            aggregate[key].extend(record.get(key, []))
    aggregate["coverage"]["bytes_read"] = total
    aggregate["coverage"]["source_files_parsed"] = len(aggregate["files"])
    aggregate["coverage"]["manifest_files_parsed"] = len(aggregate["manifests"])
    languages: dict[str, dict[str, Any]] = {}
    for record in aggregate["files"]:
        language = str(record.get("language", "unknown"))
        stats = languages.setdefault(language, {"files": 0, "bytes": 0,
                                                 "analysis_level": polyglot_ir35.ANALYSIS_LEVEL})
        stats["files"] += 1
        stats["bytes"] += int(record.get("bytes", 0) or 0)
    aggregate["coverage"]["languages"] = {key: languages[key] for key in sorted(languages)}
    aggregate["coverage"]["complete"] = not aggregate["parse_gaps"]
    for key in ("files", "modules", "imports", "types", "functions", "calls",
                "routes", "manifests", "parse_gaps"):
        aggregate[key] = sorted(aggregate[key], key=lambda row: _canonical(row))
    return aggregate


def _polyglot_report(requested: Path, base: Path, limits: Limits,
                     supplied: Mapping[str, Any] | None,
                     gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if supplied is not None:
        return _validated_ir(supplied, requested, base, limits)
    try:
        return _local_polyglot_report(requested, base, limits, gaps)
    except (OSError, RuntimeError, TypeError, ValueError, MemoryError) as exc:
        gaps.append({"kind": "polyglot-ir-failure", "path": ".",
                     "message": type(exc).__name__})
        return _empty_polyglot(str(requested), limits,
                               "bounded polyglot parser failed safely")


def _convert_polyglot(report: Mapping[str, Any], evidence: _EvidenceStore,
                      issues: _IssueStore,
                      limits: Limits) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    types: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    file_map: dict[str, Mapping[str, Any]] = {}
    for raw in report.get("files", [])[:limits.max_files]:
        if not isinstance(raw, dict):
            continue
        try:
            path = _safe_relative(raw.get("path"))
        except EngineeringError:
            continue
        language = _bounded_text(raw.get("language", "unknown"), 64)
        parse_ev = evidence.add(
            "lexical-index", path, 1, "polyglot-ir35",
            "bounded lexical source index was produced",
            precision="lexical")
        file = {
            "path": path, "module": _bounded_text(raw.get("module", ""), 1_024),
            "language": language, "sha256": _bounded_text(raw.get("sha256", ""), 64),
            "bytes": raw.get("bytes", 0) if isinstance(raw.get("bytes"), int) else 0,
            "parser": "polyglot-ir35/bounded-lexical",
            "parse_evidence_id": parse_ev,
        }
        files.append(file)
        file_map[path] = raw
        raw_imports = raw.get("imports", [])
        for item in raw_imports[:limits.max_evidence] if isinstance(raw_imports, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("specifier"), str):
                continue
            line_no = item.get("line", 1) if isinstance(item.get("line"), int) else 1
            ev = evidence.add(
                "import", path, line_no, "polyglot-ir35",
                "lexically extracted import/include declaration",
                symbol=item["specifier"], precision="lexical")
            imports.append({
                "path": path, "line": line_no, "specifier": item["specifier"][:512],
                "level": 0, "kind": _bounded_text(item.get("kind", "import"), 64),
                "language": language, "evidence_id": ev,
            })
        raw_functions = raw.get("functions", [])
        for item in raw_functions[:limits.max_evidence] if isinstance(raw_functions, list) else []:
            if not isinstance(item, dict):
                continue
            line_no = item.get("line", 1) if isinstance(item.get("line"), int) else 1
            name = _bounded_text(item.get("name", ""), 256)
            ev = evidence.add(
                "function-signature", path, line_no, "polyglot-ir35",
                "lexically extracted function-like declaration", symbol=name,
                precision="lexical")
            functions.append({
                "path": path, "line": line_no, "name": name,
                "qualified_name": (file["module"] + "." + name).strip("."),
                "kind": _bounded_text(item.get("kind", "function"), 80),
                "parameter_count": item.get("parameter_count")
                if isinstance(item.get("parameter_count"), int) else None,
                "required_parameter_count": None, "annotated_parameter_count": None,
                "return_annotation": "", "complexity_estimate": None,
                "maximum_loop_depth": None, "public": None, "evidence_id": ev,
                "analysis_level": "bounded-lexical-not-compiler",
            })
        raw_types = raw.get("types", [])
        for item in raw_types[:limits.max_evidence] if isinstance(raw_types, list) else []:
            if not isinstance(item, dict):
                continue
            line_no = item.get("line", 1) if isinstance(item.get("line"), int) else 1
            name = _bounded_text(item.get("name", ""), 256)
            ev = evidence.add(
                "type-declaration", path, line_no, "polyglot-ir35",
                "lexically extracted type-like declaration", symbol=name,
                precision="lexical")
            types.append({
                "path": path, "line": line_no, "name": name,
                "qualified_name": (file["module"] + "." + name).strip("."),
                "kind": _bounded_text(item.get("kind", "type"), 80),
                "bases": [], "decorators": [], "evidence_id": ev,
                "analysis_level": "bounded-lexical-not-compiler",
            })
        raw_routes = raw.get("routes", [])
        for item in raw_routes[:limits.max_evidence] if isinstance(raw_routes, list) else []:
            if not isinstance(item, dict):
                continue
            method = _bounded_text(item.get("method", "ANY"), 32).upper()
            method = method if method in _ROUTE_METHODS else "ANY"
            route = _bounded_text(item.get("route", ""), 1_024)
            line_no = item.get("line", 1) if isinstance(item.get("line"), int) else 1
            ev = evidence.add(
                "api-route", path, line_no, "polyglot-ir35",
                "lexically extracted literal API route", symbol=method + " " + route,
                precision="lexical")
            routes.append({
                "method": method, "route": route, "path": path, "line": line_no,
                "handler": "", "parser": "polyglot-ir35/bounded-lexical",
                "evidence_id": ev,
            })
        lock_calls = []
        raw_calls = raw.get("calls", [])
        for item in raw_calls[:limits.max_evidence] if isinstance(raw_calls, list) else []:
            if not isinstance(item, dict):
                continue
            target = _bounded_text(item.get("target", ""), 512)
            if re.search(r"(?:lock|mutex|semaphore)\.(?:lock|acquire|wait)$", target, re.I):
                lock_calls.append(item)
        if len(lock_calls) >= 2:
            evs = [evidence.add(
                "lock-like-call", path,
                call.get("line", 1) if isinstance(call.get("line"), int) else 1,
                "polyglot-ir35", "lexically extracted lock-like call target",
                symbol=call.get("target", ""), precision="lexical")
                for call in lock_calls[:16]]
            issues.add(
                "concurrency/polyglot-lock-order-review", "MEDIUM", "concurrency",
                "Multiple lock-like calls occur in one file; establish and test a single acquisition order.",
                path=path, line=min((call.get("line", 1) for call in lock_calls
                                    if isinstance(call.get("line"), int)), default=1),
                evidence_ids=evs, confidence="review-required",
                limitation="Lexical call extraction does not resolve objects, scopes, or actual lock ownership.")
    return {
        "files": sorted(files, key=lambda row: row["path"]),
        "functions": sorted(functions, key=lambda row: _canonical(row)),
        "types": sorted(types, key=lambda row: _canonical(row)),
        "imports": sorted(imports, key=lambda row: _canonical(row)),
        "routes": sorted(routes, key=lambda row: _canonical(row)),
        "manifests": sorted([{
            "path": _bounded_text(row.get("path", ""), 4_096),
            "kind": _bounded_text(row.get("kind", "manifest"), 80),
            "sha256": _bounded_text(row.get("sha256", ""), 64),
            "bytes": row.get("bytes", 0) if isinstance(row.get("bytes"), int) else 0,
            "keys": sorted(set(_bounded_text(item, 256) for item in row.get("keys", [])
                               if isinstance(item, str)))[:2_000]
            if isinstance(row.get("keys", []), list) else [],
            "dependencies": sorted(set(_bounded_text(item, 512)
                                        for item in row.get("dependencies", [])
                                        if isinstance(item, str)))[:5_000]
            if isinstance(row.get("dependencies", []), list) else [],
            "parse_gap": _bounded_text(row.get("parse_gap", ""), 300),
        } for row in report.get("manifests", [])[:limits.max_files]
            if isinstance(row, dict)], key=lambda row: _canonical(row)),
    }


def _join_relative(parent: PurePosixPath, specifier: str) -> str | None:
    parts = list(parent.parts)
    for part in specifier.replace("\\", "/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            if _CONTROL_RE.search(part):
                return None
            parts.append(part)
    return PurePosixPath(*parts).as_posix() if parts else None


def _candidate_source_paths(source: str, specifier: str, language: str,
                            known: set[str]) -> list[str]:
    source_parent = PurePosixPath(source).parent
    raw_candidates: list[str] = []
    suffixes = ("", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts",
                ".cts", ".java", ".cs", ".go", ".rs", ".c", ".h", ".cc",
                ".cpp", ".hpp", ".php")
    if specifier.startswith("."):
        joined = _join_relative(source_parent, specifier)
        if joined:
            raw_candidates.extend(joined + suffix for suffix in suffixes)
            raw_candidates.extend((joined + "/index" + suffix for suffix in suffixes[1:]))
    elif language in {"c", "cpp"}:
        local = _join_relative(source_parent, specifier)
        if local:
            raw_candidates.append(local)
        raw_candidates.append(specifier.replace("\\", "/"))
    elif language == "rust" and specifier.startswith(("crate::", "self::", "super::")):
        rust = specifier.replace("::", "/")
        rust = re.sub(r"^(?:crate|self)/", "", rust)
        joined = _join_relative(PurePosixPath("."), rust)
        if joined:
            raw_candidates.extend([joined + ".rs", joined + "/mod.rs"])
    return sorted(set(item for item in raw_candidates if item in known))


def _resolve_dependencies(files: Sequence[Mapping[str, Any]],
                          imports: Sequence[Mapping[str, Any]], limits: Limits,
                          gaps: list[dict[str, Any]]) -> tuple[list[dict[str, Any]],
                                                                list[dict[str, Any]]]:
    known = {str(row["path"]) for row in files}
    module_map: dict[str, list[str]] = defaultdict(list)
    language_by_path = {str(row["path"]): str(row.get("language", "")) for row in files}
    for row in files:
        module = str(row.get("module", ""))
        if module:
            module_map[module].append(str(row["path"]))
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for imported in sorted(imports, key=lambda row: _canonical(row)):
        source = str(imported.get("path", ""))
        specifier = str(imported.get("specifier", ""))
        language = str(imported.get("language") or language_by_path.get(source, ""))
        candidates: list[str] = []
        if language == "python":
            source_module = next((str(row.get("module", "")) for row in files
                                  if row.get("path") == source), "")
            package = source_module.split(".")
            if PurePosixPath(source).name not in {"__init__.py", "__init__.pyw"}:
                package = package[:-1]
            level = imported.get("level", 0)
            if isinstance(level, int) and level:
                climbs = max(0, level - 1)
                prefix = package[:max(0, len(package) - climbs)]
                target_module = ".".join([*prefix, *([specifier] if specifier else [])])
            else:
                target_module = specifier
            candidates = sorted(module_map.get(target_module, []))
        else:
            candidates = _candidate_source_paths(source, specifier, language, known)
            if not candidates:
                exact = sorted(module_map.get(specifier.replace("\\", "."), []))
                if len(exact) == 1:
                    candidates = exact
        if len(candidates) == 1:
            target = candidates[0]
            identity = (source, target, str(imported.get("kind", "import")))
            if identity in seen_edges:
                continue
            if len(edges) >= limits.max_graph_edges:
                gaps.append({"kind": "graph-edge-boundary", "path": source,
                             "message": "dependency edge boundary reached"})
                break
            seen_edges.add(identity)
            edges.append({
                "source": source, "target": target,
                "kind": _bounded_text(imported.get("kind", "import"), 64),
                "line": imported.get("line", 1) if isinstance(imported.get("line"), int) else 1,
                "evidence_id": str(imported.get("evidence_id", "")),
                "resolution": "exact-static-candidate",
            })
        else:
            unresolved.append({
                "source": source, "specifier": _bounded_text(specifier, 512),
                "line": imported.get("line", 1) if isinstance(imported.get("line"), int) else 1,
                "state": "ambiguous" if len(candidates) > 1 else "external-or-unresolved",
                "candidate_count": len(candidates),
                "evidence_id": str(imported.get("evidence_id", "")),
            })
    return (sorted(edges, key=lambda row: (
        row["source"], row["target"], row["kind"], row["line"])),
            sorted(unresolved, key=lambda row: _canonical(row))[:2_000])


def _strongly_connected(nodes: Iterable[str], edges: Sequence[Mapping[str, Any]]) -> list[list[str]]:
    graph: dict[str, list[str]] = {node: [] for node in sorted(set(nodes))}
    for edge in edges:
        graph.setdefault(str(edge["source"]), []).append(str(edge["target"]))
    for node in graph:
        graph[node] = sorted(set(graph[node]))
    reverse: dict[str, list[str]] = {node: [] for node in graph}
    for source, targets in graph.items():
        for target in targets:
            reverse.setdefault(target, []).append(source)
    for node in reverse:
        reverse[node] = sorted(set(reverse[node]))
    visited: set[str] = set()
    finish: list[str] = []
    for start in sorted(graph):
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, int]] = [(start, 0)]
        while stack:
            node, offset = stack[-1]
            targets = graph.get(node, [])
            if offset < len(targets):
                target = targets[offset]
                stack[-1] = (node, offset + 1)
                if target not in visited:
                    visited.add(target)
                    stack.append((target, 0))
            else:
                finish.append(node)
                stack.pop()
    assigned: set[str] = set()
    components: list[list[str]] = []
    for start in reversed(finish):
        if start in assigned:
            continue
        component = []
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            component.append(node)
            for target in reversed(reverse.get(node, [])):
                if target not in assigned:
                    assigned.add(target)
                    pending.append(target)
        if len(component) > 1 or start in graph.get(start, []):
            components.append(sorted(component))
    return sorted(components, key=lambda row: (len(row), row))


def _architecture(files: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]],
                  unresolved: Sequence[Mapping[str, Any]], evidence: _EvidenceStore,
                  issues: _IssueStore) -> dict[str, Any]:
    paths = sorted(str(row["path"]) for row in files)
    incoming = Counter(str(edge["target"]) for edge in edges)
    outgoing = Counter(str(edge["source"]) for edge in edges)
    cycles = _strongly_connected(paths, edges)
    cycle_rows = []
    for members in cycles:
        member_set = set(members)
        evs = sorted(set(str(edge.get("evidence_id", "")) for edge in edges
                         if edge["source"] in member_set and edge["target"] in member_set
                         and edge.get("evidence_id")))
        identifier = "eng40-cycle-" + _sha(members)[:20]
        cycle_rows.append({"id": identifier, "members": members,
                           "edge_evidence_ids": evs[:32]})
        issues.add(
            "architecture/dependency-cycle", "MEDIUM", "architecture",
            "Static dependency graph contains a cycle; define an interface boundary before a structural refactor.",
            path=members[0], line=1, evidence_ids=evs,
            confidence="strong-static-indicator",
            limitation="Only exactly resolved static imports are present in this graph.")
    components: dict[str, dict[str, Any]] = {}
    language_by_path = {str(row["path"]): str(row.get("language", "unknown")) for row in files}
    for path in paths:
        pure = PurePosixPath(path)
        name = pure.parts[0] if len(pure.parts) > 1 else "<root>"
        record = components.setdefault(name, {"name": name, "files": 0, "languages": {}})
        record["files"] += 1
        language = language_by_path[path]
        record["languages"][language] = record["languages"].get(language, 0) + 1
    component_rows = []
    for name in sorted(components):
        row = components[name]
        row["languages"] = {key: row["languages"][key] for key in sorted(row["languages"])}
        component_rows.append(row)
    hotspots = [{
        "path": path, "fan_in": incoming[path], "fan_out": outgoing[path],
        "reason": "high static dependency fan-in/out; prioritize compatibility tests",
    } for path in paths if incoming[path] >= 3 or outgoing[path] >= 5]
    hotspots.sort(key=lambda row: (-row["fan_in"], -row["fan_out"], row["path"]))
    return {
        "analysis_level": "exactly-resolved-static-edges-only",
        "modules": [{
            "path": str(row["path"]), "module": str(row.get("module", "")),
            "language": str(row.get("language", "unknown")),
            "fan_in": incoming[str(row["path"])],
            "fan_out": outgoing[str(row["path"])],
        } for row in sorted(files, key=lambda row: str(row["path"]))],
        "components": component_rows, "dependency_edges": list(edges),
        "cycles": cycle_rows, "hotspots": hotspots[:200],
        "unresolved_imports": list(unresolved),
        "limitations": [
            "dynamic loading, reflection, macros, generated code, aliases, and runtime dispatch can hide edges",
            "unresolved external imports are not treated as internal dependencies",
            "directory names describe grouping; they do not prove intended architectural layers",
        ],
    }


def _lock_order_checks(python_files: Sequence[Mapping[str, Any]],
                       issues: _IssueStore) -> None:
    orders: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for file in python_files:
        for record in file.get("lock_orders", []):
            order = record.get("order", [])
            for left, right in zip(order, order[1:]):
                if left != right:
                    orders[(str(left), str(right))].append(record)
    emitted: set[tuple[str, str]] = set()
    for (left, right), records in sorted(orders.items()):
        pair = tuple(sorted((left, right)))
        if pair in emitted or (right, left) not in orders:
            continue
        emitted.add(pair)
        reverse = orders[(right, left)]
        evidence_ids = [item for row in [*records, *reverse]
                        for item in row.get("evidence_ids", [])]
        first = sorted([*records, *reverse], key=lambda row: (
            str(row.get("path", "")), int(row.get("line", 1))))[0]
        issues.add(
            "concurrency/inconsistent-lock-order", "HIGH", "concurrency",
            "Different functions acquire the same lock-like objects in reverse order; deadlock testing is required.",
            path=str(first.get("path", "")), line=int(first.get("line", 1)),
            evidence_ids=evidence_ids, confidence="strong-static-indicator",
            limitation="AST name matching does not prove the expressions reference identical runtime locks.")


def _route_contract_checks(routes: Sequence[Mapping[str, Any]],
                           issues: _IssueStore) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for route in routes:
        grouped[(str(route.get("method", "ANY")), str(route.get("route", "")))].append(route)
    duplicates = []
    for (method, path), records in sorted(grouped.items()):
        # One OpenAPI declaration plus one implementation is expected, not a
        # duplicate.  Compare executable declarations with each other and
        # contract-document declarations with each other.
        partitions = {
            "contract": [row for row in records if row.get("parser") == "json"],
            "implementation": [row for row in records if row.get("parser") != "json"],
        }
        for declaration_kind, partition in partitions.items():
            locations = sorted({(str(row.get("path", "")), int(row.get("line", 1)))
                                for row in partition})
            if len(locations) <= 1:
                continue
            evs = [str(row.get("evidence_id", "")) for row in partition]
            duplicates.append({
                "method": method, "route": path,
                "declaration_kind": declaration_kind,
                "locations": [{"path": name, "line": line} for name, line in locations],
                "evidence_ids": sorted(set(filter(None, evs))),
                "resolution_proven": False,
            })
            issues.add(
                "api/duplicate-literal-route", "HIGH", "api-contract",
                "The same literal method and route are declared in multiple %s locations; precedence is framework-dependent."
                % declaration_kind,
                path=locations[0][0], line=locations[0][1], evidence_ids=evs,
                confidence="strong-static-indicator",
                limitation="Framework composition or versioning may intentionally permit duplicates.")
    return duplicates


def _issue_profile(issue: str, maximum: int) -> dict[str, Any]:
    if not isinstance(issue, str):
        raise EngineeringError("issue must be text")
    bounded = issue[:maximum]
    lowered = bounded.casefold()
    patterns = {
        "debug": r"\b(?:bug|debug|crash|error|fail|wrong|incorrect|exception)\b",
        "performance": r"\b(?:slow|latency|performance|memory|cpu|throughput|timeout)\b",
        "concurrency": r"\b(?:race|deadlock|thread|async|concurr|lock|hang)\w*\b",
        "api": r"\b(?:api|endpoint|route|request|response|http|contract)\b",
        "data": r"\b(?:schema|database|sql|migration|column|table|serialize|payload)\w*\b",
        "refactor": r"\b(?:refactor|architecture|modular|cleanup|split|coupling|dependency)\w*\b",
        "test": r"\b(?:test|regression|reproduce|coverage|fixture)\w*\b",
        "security": r"\b(?:security|vulnerability|exploit|injection|auth|secret)\w*\b",
    }
    categories = sorted(name for name, pattern in patterns.items()
                        if re.search(pattern, lowered))
    truncated = len(issue) > maximum
    return {
        "present": bool(issue), "sha256": hashlib.sha256(bounded.encode("utf-8")).hexdigest()
        if issue else "", "sha256_scope": "bounded-prefix" if truncated else "full-input",
        "characters": len(issue), "truncated_for_classification": truncated,
        "categories": categories,
        "raw_text_stored": False,
    }


def _impact(changed_paths: Sequence[str | os.PathLike[str]],
            files: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]],
            unresolved: Sequence[Mapping[str, Any]], limits: Limits,
            gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if isinstance(changed_paths, (str, bytes, os.PathLike)):
        changed_paths = (changed_paths,)  # type: ignore[assignment]
    supplied_list = []
    try:
        for index, value in enumerate(changed_paths):
            if index >= limits.max_impact:
                gaps.append({"kind": "changed-path-boundary", "path": "<request>",
                             "message": "changed path input boundary reached"})
                break
            supplied_list.append(value)
    except TypeError as exc:
        raise EngineeringError("changed_paths must be an iterable of relative paths") from exc
    supplied = tuple(supplied_list)
    if not supplied:
        return {
            "status": "not-requested", "changed_paths": [], "affected_paths": [],
            "paths": [], "truncated": False,
            "basis": "no explicit changed paths were supplied",
            "limitations": ["issue prose is never mined for paths or treated as a change set"],
        }
    seeds: list[str] = []
    invalid = []
    for value in supplied:
        try:
            seeds.append(_safe_relative(value))
        except EngineeringError:
            invalid.append(_bounded_text(value, 512))
    if invalid:
        gaps.append({"kind": "invalid-changed-path", "path": "<request>",
                     "message": "%d changed path(s) were rejected" % len(invalid)})
    seeds = sorted(set(seeds))
    known = {str(row["path"]) for row in files}
    reverse: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in edges:
        reverse[str(edge["target"])].append(
            (str(edge["source"]), str(edge.get("evidence_id", ""))))
    depth = {path: 0 for path in seeds}
    via: dict[str, list[str]] = {path: [] for path in seeds}
    queue = deque(seeds)
    truncated = False
    while queue:
        target = queue.popleft()
        for dependent, ev in sorted(reverse.get(target, [])):
            if dependent in depth:
                continue
            if len(depth) >= limits.max_impact:
                truncated = True
                queue.clear()
                break
            depth[dependent] = depth[target] + 1
            via[dependent] = [ev] if ev else []
            queue.append(dependent)
    unknown = sorted(set(seeds) - known)
    status = "complete-for-known-static-graph"
    if invalid or unknown or unresolved or truncated:
        status = "partial"
    rows = [{
        "path": path, "distance": depth[path],
        "reason": "explicitly-changed" if depth[path] == 0 else "reverse-static-dependency",
        "edge_evidence_ids": via[path], "present_in_index": path in known,
    } for path in sorted(depth, key=lambda name: (depth[name], name))]
    return {
        "status": status, "changed_paths": seeds,
        "affected_paths": [row["path"] for row in rows], "paths": rows,
        "unknown_changed_paths": unknown, "truncated": truncated,
        "basis": "explicit changed paths plus reverse traversal of exactly resolved static edges",
        "limitations": [
            "unresolved and dynamic dependencies can hide affected files",
            "an affected file is a review candidate, not proof that behavior changes",
        ],
    }


def _record_with_id(prefix: str, body: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": prefix + _sha(dict(body))[:24], **dict(body)}


def _framework_hints(manifests: Sequence[Mapping[str, Any]],
                     files: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    dependencies = {str(name).casefold() for manifest in manifests
                    for name in manifest.get("dependencies", [])
                    if isinstance(name, str)}
    candidates = []
    for dependency, framework in {
            "jest": "jest", "vitest": "vitest", "mocha": "mocha",
            "junit": "junit", "xunit": "xunit", "nunit": "nunit",
            "pytest": "pytest"}.items():
        if dependency in dependencies:
            candidates.append({"framework": framework,
                               "basis": "dependency name observed in parsed manifest"})
    suffix_counts = Counter(PurePosixPath(str(row["path"])).suffix.casefold() for row in files
                            if re.search(r"(?:^|[._/-])(?:test|spec)(?:[._/-]|$)",
                                         str(row["path"]), re.I))
    if suffix_counts and not candidates:
        candidates.append({"framework": "project-specific",
                           "basis": "test/spec file naming was observed; framework was not resolved"})
    return sorted(candidates, key=lambda row: (row["framework"], row["basis"]))


def _test_plan(functions: Sequence[Mapping[str, Any]], routes: Sequence[Mapping[str, Any]],
               contracts: Sequence[Mapping[str, Any]], issue_rows: Sequence[Mapping[str, Any]],
               impact: Mapping[str, Any], manifests: Sequence[Mapping[str, Any]],
               files: Sequence[Mapping[str, Any]], issue_profile: Mapping[str, Any],
               limits: Limits) -> dict[str, Any]:
    target_paths = set(str(path) for path in impact.get("affected_paths", []))
    if not target_paths:
        target_paths.update(str(row.get("path", "")) for row in issue_rows if row.get("path"))
    cases: dict[str, dict[str, Any]] = {}

    def add(kind: str, target: str, objective: str, oracle: str, *,
            priority: str = "MEDIUM", evidence_ids: Iterable[str] = ()) -> None:
        body = {
            "kind": kind, "target": _bounded_text(target, 1_024),
            "objective": _bounded_text(objective, 1_000),
            "oracle": _bounded_text(oracle, 1_000),
            "priority": priority if priority in _SEVERITY_ORDER else "MEDIUM",
            "evidence_ids": sorted(set(filter(None, evidence_ids)))[:16],
            "execution_state": "planned-not-run",
        }
        row = _record_with_id("eng40-test-", body)
        if len(cases) < limits.max_test_cases:
            cases[row["id"]] = row

    for function in functions:
        path = str(function.get("path", ""))
        if target_paths and path not in target_paths:
            continue
        if function.get("public") is False:
            continue
        name = str(function.get("qualified_name") or function.get("name", "function"))
        ev = [str(function.get("evidence_id", ""))]
        add("unit", name,
            "Exercise a representative valid input through the observed callable boundary.",
            "Assert the documented return state and externally observable side effects.",
            evidence_ids=ev)
        if (function.get("required_parameter_count") or 0) > 0:
            add("boundary", name,
                "Exercise empty, minimum, maximum, malformed, and omitted inputs permitted by the signature.",
                "Assert a stable typed result or documented validation error; never accept an unhandled exception as the oracle.",
                priority="HIGH", evidence_ids=ev)
    for route in routes:
        path = str(route.get("path", ""))
        if target_paths and path not in target_paths:
            continue
        target = "%s %s" % (route.get("method", "ANY"), route.get("route", ""))
        add("api-contract", target,
            "Exercise valid, invalid, unauthorized, and malformed requests at the literal route boundary.",
            "Assert status, content type, schema, and side-effect contract; derive exact values from project documentation.",
            priority="HIGH", evidence_ids=[str(route.get("evidence_id", ""))])
    for contract in contracts:
        path = str(contract.get("path", ""))
        if target_paths and path not in target_paths:
            continue
        add("data-contract", str(contract.get("name", "contract")),
            "Validate required fields, optional fields, unknown fields, type boundaries, and serialization round trips.",
            "Assert parser acceptance/rejection and backward-compatible wire/storage shape.",
            priority="HIGH", evidence_ids=[str(contract.get("evidence_id", ""))])
    for issue in issue_rows[:100]:
        add("regression", str(issue.get("rule", "observed issue")),
            "Create the smallest fixture that reaches the parser-observed issue location before any fix.",
            "The test must fail for the intended reason before the patch and pass afterward without weakening assertions.",
            priority=str(issue.get("severity", "MEDIUM")),
            evidence_ids=issue.get("evidence_ids", []))
    if issue_profile.get("present"):
        add("issue-reproducer", "issue/" + str(issue_profile.get("sha256", ""))[:16],
            "Encode the reported behavior as a minimized deterministic reproducer using explicit inputs and environment assumptions.",
            "Observe the reported failure before proposing code changes; abstain if it cannot be reproduced.",
            priority="HIGH")
    rows = sorted(cases.values(), key=lambda row: (
        -_SEVERITY_ORDER[row["priority"]], row["kind"], row["target"], row["id"]))
    return {
        "status": "plan-only", "cases": rows,
        "framework_candidates": _framework_hints(manifests, files),
        "truncated": len(cases) >= limits.max_test_cases,
        "tests_executed": False, "test_results_claimed": False,
        "invention_basis": "parser evidence, explicit impact scope, and issue categories",
        "limitations": [
            "test names and oracles are plans; framework APIs and fixtures require repository review",
            "generated tests are not considered valid until a human or separately authorized verifier runs them",
        ],
    }


def _refactor_plan(architecture: Mapping[str, Any], issue_rows: Sequence[Mapping[str, Any]],
                   migrations: Sequence[Mapping[str, Any]], issue_profile: Mapping[str, Any]) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    for cycle in architecture.get("cycles", [])[:50]:
        steps.append({
            "phase": "dependency-seam", "targets": list(cycle.get("members", [])),
            "action": "Define a narrow interface at one cycle edge, characterize behavior, then invert one dependency at a time.",
            "compatibility_gate": "Existing public behavior and import boundaries remain covered during each edge change.",
            "evidence_ids": list(cycle.get("edge_evidence_ids", [])),
            "state": "proposed-not-applied",
        })
    for issue in issue_rows:
        if issue.get("rule") in {"engineering/high-branch-complexity",
                                 "engineering/long-parameter-list"}:
            steps.append({
                "phase": "behavior-preserving-refactor", "targets": [str(issue.get("path", ""))],
                "action": "Characterize the observed callable, extract one cohesive decision or value object, and rescan after each small step.",
                "compatibility_gate": "Regression, mutation, and public-signature review pass before the next extraction.",
                "evidence_ids": list(issue.get("evidence_ids", [])),
                "state": "proposed-not-applied",
            })
    for migration in migrations:
        steps.append({
            "phase": "expand-contract-migration", "targets": [str(migration.get("path", ""))],
            "action": "Use an expand/backfill/dual-read-or-write/verify/contract sequence; keep rollback artifacts until production evidence is reviewed.",
            "compatibility_gate": "Old and new application versions can coexist and row-count/checksum invariants verify before contraction.",
            "evidence_ids": [str(migration.get("evidence_id", ""))],
            "state": "proposed-not-applied",
        })
    if "refactor" in issue_profile.get("categories", []) and not steps:
        steps.append({
            "phase": "scope-characterization", "targets": [],
            "action": "Select an explicit changed-path scope, add characterization tests, and define measurable coupling goals before moving code.",
            "compatibility_gate": "Public API/data contracts and reverse-dependency candidates are reviewed.",
            "evidence_ids": [], "state": "proposed-not-applied",
        })
    unique = {_sha(step): step for step in steps}
    rows = sorted(unique.values(), key=lambda row: (
        row["phase"], row["targets"], _sha(row)))
    return {
        "status": "plan-only" if rows else "no-static-trigger",
        "steps": rows[:200], "changes_applied": False,
        "compatibility_proven": False,
        "limitations": [
            "static structure cannot prove a refactor preserves runtime behavior",
            "migration ordering, production data distribution, and deployment topology were not executed or observed",
        ],
    }


def _debug_plan(issue_profile: Mapping[str, Any], issue_rows: Sequence[Mapping[str, Any]],
                impact: Mapping[str, Any]) -> dict[str, Any]:
    categories = set(issue_profile.get("categories", []))
    steps = [
        {"order": 1, "gate": "reproduce", "action":
         "Capture the smallest deterministic input, expected result, actual result, and relevant configuration without secrets.",
         "success_criterion": "The failure repeats for the same explicit fixture before code changes."},
        {"order": 2, "gate": "localize", "action":
         "Trace from the observed boundary through only the exact static impact candidates; instrument values and state transitions in an isolated test.",
         "success_criterion": "One violated invariant is tied to a file/line and a failing assertion."},
        {"order": 3, "gate": "hypothesis", "action":
         "Change one condition in the fixture or implementation at a time and retain disconfirming observations.",
         "success_criterion": "The proposed cause predicts both failing and non-failing cases."},
        {"order": 4, "gate": "regression", "action":
         "Freeze the minimized reproducer as a regression test before implementing the smallest patch.",
         "success_criterion": "Test fails before the patch and passes after it for the intended reason."},
    ]
    if "concurrency" in categories or any(row.get("category") == "concurrency" for row in issue_rows):
        steps.append({"order": len(steps) + 1, "gate": "schedule-control",
                      "action": "Use barriers/fakes to force relevant interleavings and record lock/task ownership; do not rely on sleep-based timing.",
                      "success_criterion": "The problematic ordering is deterministic and cancellation/timeout paths are asserted."})
    if "performance" in categories or any(row.get("category") == "performance" for row in issue_rows):
        steps.append({"order": len(steps) + 1, "gate": "measurement",
                      "action": "Define representative input sizes, warmup, baseline distribution, allocation/CPU counters, and an explicit regression threshold.",
                      "success_criterion": "Repeated measurements distinguish algorithmic work from I/O and environment noise."})
    return {
        "status": "guidance-only", "steps": steps,
        "candidate_paths": list(impact.get("affected_paths", []))[:500],
        "debugging_performed": False, "reproducer_executed": False,
        "limitations": ["Static evidence cannot observe runtime values, schedules, environment, or external services."],
    }


def _patch_workflow(issue_profile: Mapping[str, Any], issue_rows: Sequence[Mapping[str, Any]],
                    impact: Mapping[str, Any], files: Sequence[Mapping[str, Any]],
                    routes: Sequence[Mapping[str, Any]], contracts: Sequence[Mapping[str, Any]],
                    limits: Limits) -> dict[str, Any]:
    file_map = {str(row["path"]): row for row in files}
    candidates = list(impact.get("changed_paths", []))
    candidates.extend(str(row.get("path", "")) for row in issue_rows if row.get("path"))
    candidates = sorted(set(filter(None, candidates)))[:limits.max_plan_units]
    units = []
    for path in candidates:
        file = file_map.get(path)
        related = [row for row in issue_rows if row.get("path") == path]
        body = {
            "path": path,
            "operation": "modify-existing" if file else "investigate-only",
            "precondition_sha256": str(file.get("sha256", "")) if file else "",
            "intent": "Address only the observed issue(s), preserve public contracts, and avoid unrelated cleanup.",
            "issue_ids": sorted(str(row.get("id", "")) for row in related)[:32],
            "evidence_ids": sorted(set(str(ev) for row in related
                                       for ev in row.get("evidence_ids", [])))[:32],
            "patch_content_generated": False,
        }
        units.append(_record_with_id("eng40-unit-", body))
    gates = [
        {"order": 1, "name": "evidence-localization", "required": True,
         "satisfied": bool(issue_rows), "state": "observed" if issue_rows else "pending",
         "required_evidence": "parser evidence or deterministic reproducer identifies the behavior and location"},
        {"order": 2, "name": "failing-reproducer", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "isolated test fails before patch for the intended reason"},
        {"order": 3, "name": "impact-and-contract-review", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "reverse dependencies plus affected API/data contracts are reviewed"},
        {"order": 4, "name": "minimal-patch-review", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "patch is scoped, precondition hashes match, and unrelated changes are absent"},
        {"order": 5, "name": "static-rescan", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "before/after parser and detector findings show target reduction and no new findings"},
        {"order": 6, "name": "isolated-build-and-tests", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "authorized disposable build/test run passes without truncated output"},
        {"order": 7, "name": "performance-concurrency-contract", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "relevant benchmarks, schedule tests, and API/data compatibility checks pass"},
        {"order": 8, "name": "separate-apply-authorization", "required": True,
         "satisfied": False, "state": "pending",
         "required_evidence": "human approves the verified change set after stale-state checks"},
    ]
    return {
        "status": "PLAN", "issue": dict(issue_profile),
        "scope": {"explicit_changed_paths": list(impact.get("changed_paths", [])),
                  "static_affected_paths": list(impact.get("affected_paths", [])),
                  "api_contracts_observed": len(routes),
                  "data_contracts_observed": len(contracts)},
        "proposed_patch_units": units, "gates": gates,
        "target_code_executed": False, "patch_generated": False,
        "patch_applied": False, "writes_performed": False,
        "separate_execution_authorization_required": True,
        "separate_apply_authorization_required": True,
        "plan_is_proof": False,
    }


def _unavailable_report(root: str, gap: Mapping[str, Any], limits: Limits,
                        issue_profile: Mapping[str, Any]) -> dict[str, Any]:
    impact = {
        "status": "unavailable", "changed_paths": [], "affected_paths": [],
        "paths": [], "truncated": False, "basis": "analysis root was refused",
        "limitations": ["no repository evidence was read"],
    }
    workflow = _patch_workflow(issue_profile, [], impact, [], [], [], limits)
    report: dict[str, Any] = {
        "schema": SCHEMA, "version": VERSION, "root": root,
        "status": "unavailable",
        "analysis": {
            "level": ANALYSIS_LEVEL, "deterministic": True,
            "target_code_executed": False, "imports_executed": False,
            "processes_started": False, "network_accessed": False,
            "filesystem_writes": False, "compiler_invoked": False,
            "formal_proof_claimed": False,
        },
        "execution": {
            "target_code": False, "imports": False, "processes": False,
            "network": False, "filesystem_writes": False, "compilers": False,
            "tests": False, "patch_apply": False,
        },
        "summary": {"findings": 0, "severity": {name: 0 for name in _SEVERITY_ORDER},
                    "files": 0, "dependency_edges": 0, "test_cases_planned": 0,
                    "patch_units_planned": 0},
        "findings": [], "top_findings": [],
        "inventory": {"files": [], "languages": {}, "manifests": []},
        "evidence": [],
        "architecture": {
            "analysis_level": "unavailable", "modules": [], "components": [],
            "dependency_edges": [], "cycles": [], "hotspots": [],
            "unresolved_imports": [], "limitations": ["analysis root was refused"],
        },
        "impact": impact,
        "engineering_checks": {"issues": [], "summary": {"total": 0,
                                                            "severity": {},
                                                            "categories": {}}},
        "contracts": {"api_routes": [], "data_contracts": [],
                      "duplicate_routes": [], "migrations": []},
        "test_plan": {"status": "unavailable", "cases": [],
                      "tests_executed": False, "test_results_claimed": False},
        "refactor_plan": {"status": "unavailable", "steps": [],
                          "changes_applied": False, "compatibility_proven": False},
        "debug_plan": {"status": "unavailable", "steps": [],
                       "debugging_performed": False, "reproducer_executed": False},
        "patch_workflow": workflow,
        "coverage": {
            "state": "unavailable", "semantic_complete": False,
            "gaps": [dict(gap)], "limits": limits.__dict__,
            "compiler_style_evidence": [],
        },
        "limitations": [
            "No analysis ran because the selected root failed path and file-type validation.",
            "A PLAN does not prove correctness and cannot authorize execution or patch application.",
        ],
        "assurance": [
            "Analysis is static, deterministic, read-only, and starts no target process.",
            "No compiler, test, benchmark, database, migration, or network service was invoked.",
            "No finding or PLAN is presented as formal proof or an applied fix.",
        ],
    }
    report["report_sha256"] = _sha(report)
    return report


def analyze(root: str | os.PathLike[str], *, issue: str = "",
            ir: Mapping[str, Any] | None = None,
            changed_paths: Sequence[str | os.PathLike[str]] = (),
            limits: Limits | None = None) -> dict[str, Any]:
    """Analyze a repository/file and return a deterministic Attestor 4.0 report.

    ``ir`` may be an Attestor 3.5 polyglot IR for exactly ``root``.  Supplied IR is
    bounded and schema-checked but is still labeled caller-supplied; the engine
    never pretends to have independently parsed its source.  ``changed_paths``
    must be root-relative and is the only input used to seed impact traversal.
    """
    limits = limits or Limits()
    if not isinstance(limits, Limits):
        raise EngineeringError("limits must be an engineering_engine40.Limits instance")
    profile = _issue_profile(issue, limits.max_issue_chars)
    try:
        raw_root = os.fspath(root)
    except TypeError:
        return _unavailable_report(
            "<invalid>", {"kind": "invalid-root", "path": "<invalid>",
                           "message": "root is not text or path-like"}, limits, profile)
    if (not isinstance(raw_root, str) or not raw_root or len(raw_root) > 32_768 or
            _CONTROL_RE.search(raw_root)):
        return _unavailable_report(
            "<invalid>", {"kind": "invalid-root", "path": "<invalid>",
                           "message": "root contains invalid path text"}, limits, profile)
    try:
        supplied_root = Path(raw_root).expanduser()
        if supplied_root.is_symlink():
            return _unavailable_report(
                str(supplied_root), {"kind": "root-symlink-refused", "path": ".",
                                     "message": "analysis root may not be a symbolic link"},
                limits, profile)
        requested = supplied_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        return _unavailable_report(
            _bounded_text(raw_root, 4_096),
            {"kind": "invalid-root", "path": ".", "message": type(exc).__name__},
            limits, profile)
    if not (requested.is_file() or requested.is_dir()):
        return _unavailable_report(
            str(requested), {"kind": "invalid-root-type", "path": ".",
                             "message": "root is not a regular file or directory"},
            limits, profile)
    base = requested.parent if requested.is_file() else requested
    gaps: list[dict[str, Any]] = []
    evidence = _EvidenceStore(limits.max_evidence)
    issues = _IssueStore(limits.max_issues)
    direct_inputs, direct_discovered, direct_bytes = _discover_direct(
        requested, base, limits, gaps)
    try:
        polyglot_report = _polyglot_report(requested, base, limits, ir, gaps)
    except EngineeringError as exc:
        gaps.append({"kind": "supplied-ir-refused", "path": ".",
                     "message": _bounded_text(exc, 300)})
        polyglot_report = _empty_polyglot(
            str(requested), limits, "caller-supplied IR was refused")
    if ir is not None:
        gaps.append({
            "kind": "supplied-ir-not-independently-reparsed", "path": ".",
            "message": "caller-supplied IR was schema/boundary checked but its source hashes were not independently re-read",
        })
    for raw_gap in polyglot_report.get("parse_gaps", [])[:limits.max_evidence]:
        if not isinstance(raw_gap, dict):
            continue
        gaps.append({
            "kind": "polyglot/" + _bounded_text(raw_gap.get("kind", "gap"), 100),
            "path": _bounded_text(raw_gap.get("path", "."), 4_096),
            "line": raw_gap.get("line", 1) if isinstance(raw_gap.get("line"), int) else 1,
            "message": _bounded_text(raw_gap.get("message", "polyglot coverage gap"), 300),
        })
    converted = _convert_polyglot(polyglot_report, evidence, issues, limits)
    files: list[dict[str, Any]] = list(converted["files"])
    functions: list[dict[str, Any]] = list(converted["functions"])
    types: list[dict[str, Any]] = list(converted["types"])
    imports: list[dict[str, Any]] = list(converted["imports"])
    routes: list[dict[str, Any]] = list(converted["routes"])
    contracts: list[dict[str, Any]] = []
    migrations: list[dict[str, Any]] = []
    python_files: list[dict[str, Any]] = []
    for item in direct_inputs:
        if item.kind == "python":
            try:
                parsed = _analyze_python(item, evidence, issues, gaps)
            except (MemoryError, RecursionError, RuntimeError) as exc:
                gaps.append({"kind": "python-analysis-boundary", "path": item.path,
                             "message": type(exc).__name__})
                parsed = None
            if parsed is None:
                files.append({
                    "path": item.path, "module": _module_name(item.path),
                    "language": "python", "sha256": item.sha256, "bytes": item.size,
                    "parser": "python-ast/parse-failed", "parse_evidence_id": "",
                })
                continue
            python_files.append(parsed)
            files.append({key: parsed[key] for key in (
                "path", "module", "language", "sha256", "bytes", "parser",
                "parse_evidence_id")})
            functions.extend(parsed["functions"])
            types.extend(parsed["types"])
            imports.extend({**row, "language": "python"} for row in parsed["imports"])
            routes.extend(parsed["routes"])
            contracts.extend(parsed["data_contracts"])
        elif item.kind == "json-contract":
            files.append({
                "path": item.path, "module": PurePosixPath(item.path).stem,
                "language": "json-contract", "sha256": item.sha256, "bytes": item.size,
                "parser": "json", "parse_evidence_id": "",
            })
            json_routes, json_contracts = _analyze_json_contract(
                item, evidence, issues, gaps)
            routes.extend(json_routes)
            contracts.extend(json_contracts)
        elif item.kind == "sql":
            ev = evidence.add(
                "lexical-index", item.path, 1, "sql-lexical",
                "bounded SQL DDL/migration lexical pass completed", precision="lexical")
            files.append({
                "path": item.path, "module": PurePosixPath(item.path).stem,
                "language": "sql", "sha256": item.sha256, "bytes": item.size,
                "parser": "sql-lexical", "parse_evidence_id": ev,
            })
            sql_contracts, sql_migrations = _analyze_sql(item, evidence, issues)
            contracts.extend(sql_contracts)
            migrations.extend(sql_migrations)
    file_values = sorted({str(row["path"]): row for row in files}.values(),
                         key=lambda row: str(row["path"]))
    if len(file_values) > limits.max_files:
        gaps.append({"kind": "combined-file-boundary", "path": ".",
                     "message": "combined parser inventory exceeded the file boundary"})
    files = file_values[:limits.max_files]
    allowed_paths = {str(row["path"]) for row in files}
    python_files = [row for row in python_files if str(row.get("path", "")) in allowed_paths]

    def bounded_records(name: str, rows: Sequence[dict[str, Any]],
                        maximum: int) -> list[dict[str, Any]]:
        scoped = [row for row in rows if str(row.get("path", "")) in allowed_paths]
        scoped = sorted(scoped, key=lambda row: _canonical(row))
        if len(scoped) > maximum:
            gaps.append({"kind": name + "-boundary", "path": ".",
                         "message": name + " records exceeded their configured boundary"})
        return scoped[:maximum]

    functions = bounded_records("function", functions, limits.max_evidence)
    types = bounded_records("type", types, limits.max_evidence)
    imports = bounded_records("import", imports, limits.max_graph_edges * 2)
    routes = bounded_records("route", routes, limits.max_evidence)
    contracts = bounded_records("contract", contracts, limits.max_evidence)
    migrations = bounded_records("migration", migrations, limits.max_evidence)
    if requested.is_file() and not files:
        gaps.append({"kind": "unsupported-target-file", "path": requested.name,
                     "message": "selected file is not supported by the current parsers"})
    edges, unresolved = _resolve_dependencies(files, imports, limits, gaps)
    architecture = _architecture(files, edges, unresolved, evidence, issues)
    _lock_order_checks(python_files, issues)
    duplicate_routes = _route_contract_checks(routes, issues)
    impact = _impact(changed_paths, files, edges, unresolved, limits, gaps)
    if evidence.truncated:
        gaps.append({"kind": "evidence-boundary", "path": ".",
                     "message": "evidence catalog reached its configured boundary"})
    if issues.truncated:
        gaps.append({"kind": "issue-boundary", "path": ".",
                     "message": "engineering issue catalog reached its configured boundary"})
    gap_map = {_sha({
        "kind": _bounded_text(row.get("kind", "gap"), 120),
        "path": _bounded_text(row.get("path", "."), 4_096),
        "line": row.get("line", 1) if isinstance(row.get("line"), int) else 1,
        "message": _bounded_text(row.get("message", ""), 300),
    }): {
        "kind": _bounded_text(row.get("kind", "gap"), 120),
        "path": _bounded_text(row.get("path", "."), 4_096),
        "line": row.get("line", 1) if isinstance(row.get("line"), int) else 1,
        "message": _bounded_text(row.get("message", ""), 300),
    } for row in gaps}
    gap_rows = sorted(gap_map.values(), key=lambda row: (
        row["path"], row["line"], row["kind"], row["message"]))[:2_000]
    issue_rows = issues.rows()
    test_plan = _test_plan(
        functions, routes, contracts, issue_rows, impact, converted["manifests"],
        files, profile, limits)
    refactor_plan = _refactor_plan(architecture, issue_rows, migrations, profile)
    debug_plan = _debug_plan(profile, issue_rows, impact)
    workflow = _patch_workflow(
        profile, issue_rows, impact, files, routes, contracts, limits)
    languages = Counter(str(row.get("language", "unknown")) for row in files)
    severity = Counter(str(row["severity"]) for row in issue_rows)
    categories = Counter(str(row["category"]) for row in issue_rows)
    poly_coverage = polyglot_report.get("coverage", {}) \
        if isinstance(polyglot_report.get("coverage"), dict) else {}
    state = "bounded-input-complete" if not gap_rows else "partial"
    status = ("issues-observed" if issue_rows else
              "no-static-issues-with-gaps" if gap_rows else
              "no-static-issues-from-bounded-checks")
    report: dict[str, Any] = {
        "schema": SCHEMA, "version": VERSION, "root": str(requested),
        "status": status,
        "analysis": {
            "level": ANALYSIS_LEVEL, "deterministic": True,
            "target_code_executed": False, "imports_executed": False,
            "processes_started": False, "network_accessed": False,
            "filesystem_writes": False, "compiler_invoked": False,
            "formal_proof_claimed": False,
            "ir_source": "supplied-bounded-document" if ir is not None else "locally-produced-bounded-lexical-ir",
            "ir_sha256": _sha(polyglot_report),
        },
        "execution": {
            "target_code": False, "imports": False, "processes": False,
            "network": False, "filesystem_writes": False, "compilers": False,
            "tests": False, "benchmarks": False, "database": False,
            "migrations": False, "patch_apply": False,
        },
        "summary": {
            "findings": len(issue_rows),
            "severity": {key: severity[key] for key in _SEVERITY_ORDER},
            "files": len(files), "dependency_edges": len(edges),
            "test_cases_planned": len(test_plan.get("cases", [])),
            "patch_units_planned": len(workflow.get("proposed_patch_units", [])),
        },
        "findings": issue_rows, "top_findings": issue_rows[:100],
        "inventory": {
            "files": files, "languages": {key: languages[key] for key in sorted(languages)},
            "manifests": converted["manifests"],
            "functions": functions, "types": types,
        },
        "evidence": evidence.rows(), "architecture": architecture,
        "impact": impact,
        "engineering_checks": {
            "issues": issue_rows,
            "summary": {
                "total": len(issue_rows),
                "severity": {key: severity[key] for key in _SEVERITY_ORDER},
                "categories": {key: categories[key] for key in sorted(categories)},
            },
            "absence_proven": False,
        },
        "contracts": {
            "api_routes": routes, "data_contracts": contracts,
            "duplicate_routes": duplicate_routes, "migrations": migrations,
            "runtime_compatibility_proven": False,
        },
        "test_plan": test_plan, "refactor_plan": refactor_plan,
        "debug_plan": debug_plan, "patch_workflow": workflow,
        "coverage": {
            "state": state, "semantic_complete": False,
            "direct_files_discovered": direct_discovered,
            "direct_files_parsed": len(direct_inputs), "direct_bytes_read": direct_bytes,
            "polyglot_files_discovered": poly_coverage.get("supported_files_discovered", 0),
            "polyglot_files_parsed": poly_coverage.get("source_files_parsed", 0),
            "polyglot_bytes_read": poly_coverage.get("bytes_read", 0),
            "gaps": gap_rows, "limits": limits.__dict__,
            "compiler_style_evidence": [
                {"parser": "python-ast", "claim":
                 "CPython AST syntax acceptance and parser-derived declarations/control-flow shapes",
                 "not_claimed": "type checking, compiler diagnostics, runtime behavior, or formal proof"},
                {"parser": "json", "claim": "standard JSON grammar and duplicate-key checks",
                 "not_claimed": "full OpenAPI/JSON Schema semantic validation"},
                {"parser": "polyglot-ir35", "claim": "bounded lexical declarations/imports/calls/routes",
                 "not_claimed": "compiler-grade parsing, binding, type resolution, macros, or dispatch"},
                {"parser": "sql-lexical", "claim": "bounded DDL/migration token shapes",
                 "not_claimed": "dialect validation, transactional safety, or production compatibility"},
            ],
        },
        "limitations": [
            "No target code, build, compiler, test, benchmark, database, package hook, network service, or migration was executed.",
            "Static findings and invented plans are review candidates, not proof of defects, fixes, performance, exploitability, or compatibility.",
            "Only CPython AST and standard JSON are grammar parsers here; polyglot source and SQL evidence is bounded lexical evidence.",
            "Missing findings never prove absence of errors; coverage gaps and unresolved dependencies can hide behavior.",
            "Filesystem checks reduce link/path risk but cannot eliminate every concurrent filesystem race on every operating system.",
            "Patch workflow output is PLAN-only and requires separate execution and apply authorization.",
        ],
        "assurance": [
            "All conclusions are derived from bounded parser or explicitly labeled lexical evidence.",
            "No target import, target process, compiler, build, test, benchmark, database, migration, package hook, or network request was run.",
            "Cross-file impact contains only explicit changed paths and exactly resolved static reverse edges.",
            "Invented tests, refactors, migrations, debug steps, and patch units remain PLAN-only until their gates independently pass.",
            "Missing findings never establish the absence of defects, performance problems, races, or compatibility breaks.",
        ],
    }
    report["report_sha256"] = _sha(report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--issue", default="")
    parser.add_argument("--changed-path", action="append", default=[])
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = analyze(args.root, issue=args.issue, changed_paths=args.changed_path)
    except EngineeringError as exc:
        parser.error(str(exc))
    print(deterministic_json(report, pretty=not args.compact), end="" if not args.compact else "\n")
    if report["status"] == "unavailable":
        return 2
    return 1 if report["engineering_checks"]["summary"]["total"] else 0


__all__ = [
    "SCHEMA", "VERSION", "ANALYSIS_LEVEL", "EngineeringError", "Limits",
    "analyze", "deterministic_json", "verify_report", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
