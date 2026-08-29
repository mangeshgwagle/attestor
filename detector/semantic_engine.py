#!/usr/bin/env python3
"""Attestor 3.0 whole-program semantic analysis.

The engine uses Python's compiler-grade ``ast`` front end to build a repository
model without importing or executing target code.  It resolves imports and
calls, summarizes control/data flow, and computes interprocedural taint to a
fixed point.  Optional multi-language front-end checks use parser-only or
no-output compiler modes and always invoke tools with ``shell=False``.

Public API:

``analyze_repository(root, compiler_checks=False)``
    Return a deterministic, JSON-serializable repository report.

``run_frontend_checks(paths)``
    Safely syntax-check supported non-Python files with installed tools.

``build_frontend_command(path, language, executable=None, output_dir=None)``
    Build (but do not run) the hardened command for a language adapter.
"""
from __future__ import annotations

import argparse
import ast
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence


VERSION = "3.0.0"
SCHEMA = "attestor.semantic-analysis/3.0"
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 5_000
DEFAULT_FRONTEND_TIMEOUT = 8.0
MAX_EVIDENCE_CALLS = 16
MAX_TOOL_OUTPUT = 8_192

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", ".stack-work", ".terraform", ".gradle",
    ".next", "coverage", "bin", "obj",
}

LANGUAGE_EXTENSIONS = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
    ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".java": "java", ".cs": "csharp", ".go": "go", ".rs": "rust",
    ".rb": "ruby", ".php": "php", ".swift": "swift",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell", ".json": "json",
}

ROUTE_DECORATORS = {
    "route", "get", "post", "put", "patch", "delete", "options",
    "head", "websocket", "api_route", "api_view", "action",
}
ENTRYPOINT_NAMES = {
    "main", "handler", "lambda_handler", "application", "wsgi_app",
    "asgi_app", "handle", "do_get", "do_post",
}
CALLBACK_DECORATORS = {"task", "shared_task", "command", "listener", "receiver"}

# The value is (security context, CWE, severity, remediation, tainted positions).
SINK_SPECS: dict[str, tuple[str, str, str, str, tuple[int, ...]]] = {
    "eval": ("code", "CWE-95", "CRITICAL", "Remove eval or parse a strict data format.", (0,)),
    "builtins.eval": ("code", "CWE-95", "CRITICAL", "Remove eval or parse a strict data format.", (0,)),
    "exec": ("code", "CWE-95", "CRITICAL", "Remove exec and use an allowlisted operation.", (0,)),
    "builtins.exec": ("code", "CWE-95", "CRITICAL", "Remove exec and use an allowlisted operation.", (0,)),
    "os.system": ("command", "CWE-78", "CRITICAL", "Use an argument-vector API with an allowlisted executable.", (0,)),
    "os.popen": ("command", "CWE-78", "CRITICAL", "Use subprocess with shell=False and fixed executable names.", (0,)),
    "subprocess.Popen": ("command", "CWE-78", "CRITICAL", "Use a fixed executable and validated argument vector.", (0,)),
    "subprocess.run": ("command", "CWE-78", "HIGH", "Use a fixed executable and validated argument vector.", (0,)),
    "subprocess.call": ("command", "CWE-78", "HIGH", "Use a fixed executable and validated argument vector.", (0,)),
    "subprocess.check_call": ("command", "CWE-78", "HIGH", "Use a fixed executable and validated argument vector.", (0,)),
    "subprocess.check_output": ("command", "CWE-78", "HIGH", "Use a fixed executable and validated argument vector.", (0,)),
    "subprocess.getoutput": ("command", "CWE-78", "CRITICAL", "Avoid shell command strings; use a fixed argument vector.", (0,)),
    "pickle.loads": ("deserialize", "CWE-502", "CRITICAL", "Use JSON or another non-executable data format.", (0,)),
    "pickle.load": ("deserialize", "CWE-502", "CRITICAL", "Use JSON or another non-executable data format.", (0,)),
    "marshal.loads": ("deserialize", "CWE-502", "HIGH", "Do not deserialize untrusted marshal data.", (0,)),
    "yaml.load": ("deserialize", "CWE-502", "HIGH", "Use yaml.safe_load for untrusted YAML.", (0,)),
    "flask.render_template_string": ("template", "CWE-1336", "HIGH", "Render a fixed template and pass data as values.", (0,)),
    "render_template_string": ("template", "CWE-1336", "HIGH", "Render a fixed template and pass data as values.", (0,)),
    "markupsafe.Markup": ("html", "CWE-79", "HIGH", "Escape untrusted HTML and avoid marking it safe.", (0,)),
    "Markup": ("html", "CWE-79", "HIGH", "Escape untrusted HTML and avoid marking it safe.", (0,)),
    "flask.redirect": ("url", "CWE-601", "MEDIUM", "Allowlist redirect destinations.", (0,)),
    "django.shortcuts.redirect": ("url", "CWE-601", "MEDIUM", "Allowlist redirect destinations.", (0,)),
    "requests.get": ("url", "CWE-918", "HIGH", "Allowlist schemes, hosts, ports, and resolved IP ranges.", (0,)),
    "requests.post": ("url", "CWE-918", "HIGH", "Allowlist schemes, hosts, ports, and resolved IP ranges.", (0,)),
    "urllib.request.urlopen": ("url", "CWE-918", "HIGH", "Allowlist schemes, hosts, ports, and resolved IP ranges.", (0,)),
    "open": ("path", "CWE-22", "HIGH", "Resolve beneath an approved root and reject traversal.", (0,)),
    "builtins.open": ("path", "CWE-22", "HIGH", "Resolve beneath an approved root and reject traversal.", (0,)),
    "send_file": ("path", "CWE-22", "HIGH", "Map identifiers to server-owned paths instead of accepting paths.", (0,)),
    "flask.send_file": ("path", "CWE-22", "HIGH", "Map identifiers to server-owned paths instead of accepting paths.", (0,)),
}

SOURCE_CALLS = {
    "input": "console.input", "builtins.input": "console.input",
    "request.get_json": "http.json", "flask.request.get_json": "http.json",
    "request.args.get": "http.query", "flask.request.args.get": "http.query",
    "request.form.get": "http.form", "flask.request.form.get": "http.form",
    "request.values.get": "http.value", "request.headers.get": "http.header",
    "request.cookies.get": "http.cookie", "request.files.get": "http.file",
    "sys.stdin.read": "stdin", "sys.stdin.readline": "stdin",
    "socket.recv": "network.socket", "os.getenv": "environment",
    "os.environ.get": "environment", "cgi.FieldStorage.getvalue": "http.form",
}
SOURCE_PREFIXES = {
    "request.args": "http.query", "flask.request.args": "http.query",
    "request.form": "http.form", "flask.request.form": "http.form",
    "request.values": "http.value", "request.json": "http.json",
    "request.headers": "http.header", "request.cookies": "http.cookie",
    "request.files": "http.file", "request.data": "http.body",
    "request.body": "http.body", "request.GET": "http.query",
    "request.POST": "http.form", "request.META": "http.header",
    "sys.argv": "command-line", "os.environ": "environment",
}

SANITIZER_CONTEXTS = {
    "int": {"all"}, "builtins.int": {"all"},
    "float": {"all"}, "builtins.float": {"all"},
    "uuid.UUID": {"all"},
    "shlex.quote": {"command"},
    "html.escape": {"html"}, "markupsafe.escape": {"html"},
    "bleach.clean": {"html"},
    "werkzeug.utils.secure_filename": {"path"},
    "os.path.basename": {"path"},
    "yaml.safe_load": {"deserialize"},
}

PROPAGATING_CALLS = {
    "str", "bytes", "repr", "json.dumps", "json.loads",
    "urllib.parse.unquote", "urllib.parse.unquote_plus",
    "base64.b64decode", "base64.b64encode", "copy.copy", "copy.deepcopy",
}
PROPAGATING_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "replace",
    "format", "join", "encode", "decode", "split", "rsplit",
}


def _dotted(node: ast.AST | None) -> str:
    """Return a conservative dotted name without evaluating an expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _string_constant(node: ast.AST | None) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _language(path: Path) -> str:
    return LANGUAGE_EXTENSIONS.get(path.suffix.lower(), "unknown")


def _stable_hash(*parts: object) -> str:
    raw = "\x1f".join(str(part) for part in parts).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()


def _module_name(root: Path, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    # When the supplied root is itself a package, preserve that package prefix
    # so ``from .worker import work`` resolves to the sibling module.
    if (root / "__init__.py").is_file():
        parts.insert(0, root.name)
    parts = [part.replace("-", "_").replace(" ", "_") for part in parts]
    if not parts:
        return root.name.replace("-", "_").replace(" ", "_")
    return ".".join(parts)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True, order=True)
class CallTrace:
    caller: str
    callee: str
    path: str
    line: int


@dataclass(frozen=True, order=True)
class FlowAtom:
    origin: str
    sanitizers: tuple[str, ...] = ()
    calls: tuple[CallTrace, ...] = ()

    def sanitized_for(self, context: str) -> bool:
        return "all" in self.sanitizers or context in self.sanitizers


Flow = frozenset[FlowAtom]
EMPTY_FLOW: Flow = frozenset()


@dataclass(frozen=True, order=True)
class SinkTemplate:
    sink: str
    context: str
    cwe: str
    severity: str
    remediation: str
    function: str
    path: str
    line: int
    column: int
    atoms: Flow


@dataclass(frozen=True)
class FunctionSummary:
    returns: Flow = EMPTY_FLOW
    sinks: tuple[SinkTemplate, ...] = ()
    assignments: int = 0
    aliases: int = 0
    reassignments: int = 0
    sanitized_assignments: int = 0


@dataclass
class ModuleModel:
    name: str
    path: Path
    display_path: str
    tree: ast.Module
    imports: list[dict] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    module_aliases: dict[str, str] = field(default_factory=dict)


@dataclass
class FunctionModel:
    qname: str
    module: ModuleModel
    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualname: str
    class_qname: str
    parameters: tuple[str, ...]
    parameter_types: dict[str, str]
    decorators: tuple[str, ...]
    routes: tuple[dict, ...]
    entrypoint: bool
    control_flow: dict


@dataclass
class ClassModel:
    qname: str
    module: ModuleModel
    node: ast.ClassDef
    bases: tuple[str, ...]
    decorators: tuple[str, ...]


def _flow_union(*flows: Flow) -> Flow:
    atoms: set[FlowAtom] = set()
    for flow in flows:
        atoms.update(flow)
    # Keep state bounded under exotic recursive code.  Shorter evidence wins.
    if len(atoms) > 256:
        atoms = set(sorted(atoms, key=lambda item: (len(item.calls), item))[:256])
    return frozenset(atoms)


def _sanitize(flow: Flow, contexts: Iterable[str]) -> Flow:
    added = set(contexts)
    return frozenset(
        FlowAtom(atom.origin, tuple(sorted(set(atom.sanitizers) | added)), atom.calls)
        for atom in flow
    )


def _append_trace(atom: FlowAtom, trace: CallTrace) -> FlowAtom:
    if trace in atom.calls or len(atom.calls) >= MAX_EVIDENCE_CALLS:
        return atom
    return FlowAtom(atom.origin, atom.sanitizers, atom.calls + (trace,))


def _parameter_index(origin: str) -> int | None:
    if not origin.startswith("param:"):
        return None
    try:
        return int(origin.split(":", 1)[1])
    except ValueError:
        return None


def _source_id(qname: str, path: str, line: int, kind: str, symbol: str) -> str:
    return "source:" + _stable_hash(qname, path, line, kind, symbol)[:24]


class _ControlFlowVisitor(ast.NodeVisitor):
    """Compiler-AST control-flow metrics, excluding nested scopes."""

    def __init__(self) -> None:
        self.statements = 0
        self.decisions = 0
        self.loops = 0
        self.returns = 0
        self.raises = 0
        self.awaits = 0
        self.yields = 0
        self.breaks = 0
        self.continues = 0
        self.unreachable_lines: list[int] = []

    def visit_FunctionDef(self, node):  # nested scope
        return

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def generic_visit(self, node):
        if isinstance(node, ast.stmt):
            self.statements += 1
        super().generic_visit(node)

    def visit_If(self, node):
        self.decisions += 1
        self.generic_visit(node)

    def visit_IfExp(self, node):
        self.decisions += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.decisions += 1; self.loops += 1
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.decisions += 1; self.loops += 1
        self.generic_visit(node)

    def visit_Try(self, node):
        self.decisions += len(node.handlers)
        self.generic_visit(node)

    def visit_Match(self, node):
        self.decisions += max(0, len(node.cases) - 1)
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self.decisions += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_comprehension(self, node):
        self.decisions += 1 + len(node.ifs)
        self.generic_visit(node)

    def visit_Return(self, node):
        self.returns += 1
        self.generic_visit(node)

    def visit_Raise(self, node):
        self.raises += 1
        self.generic_visit(node)

    def visit_Await(self, node):
        self.awaits += 1
        self.generic_visit(node)

    def visit_Yield(self, node):
        self.yields += 1
        self.generic_visit(node)

    visit_YieldFrom = visit_Yield

    def visit_Break(self, node):
        self.breaks += 1
        self.generic_visit(node)

    def visit_Continue(self, node):
        self.continues += 1
        self.generic_visit(node)


def _always_terminates(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    if isinstance(statement, ast.If):
        return bool(statement.body and statement.orelse
                    and _always_terminates(statement.body[-1])
                    and _always_terminates(statement.orelse[-1]))
    if isinstance(statement, ast.Match) and statement.cases:
        last = statement.cases[-1]
        wildcard = (isinstance(last.pattern, ast.MatchAs) and last.pattern.pattern is None
                    and last.guard is None)
        return wildcard and all(case.body and _always_terminates(case.body[-1])
                                for case in statement.cases)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        return bool(statement.body and _always_terminates(statement.body[-1]))
    if isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
        if statement.finalbody and _always_terminates(statement.finalbody[-1]):
            return True
        body_terminates = bool(statement.body and _always_terminates(statement.body[-1]))
        handlers_terminate = all(handler.body and _always_terminates(handler.body[-1])
                                 for handler in statement.handlers)
        return body_terminates and handlers_terminate
    return False


def _unreachable_lines(statements: Sequence[ast.stmt]) -> list[int]:
    out: list[int] = []
    terminated = False
    for statement in statements:
        if terminated:
            out.append(getattr(statement, "lineno", 1))
            continue
        if _always_terminates(statement):
            terminated = True
        for nested in _statement_blocks(statement):
            out.extend(_unreachable_lines(nested))
    return sorted(set(out))


def _statement_blocks(statement: ast.stmt) -> list[list[ast.stmt]]:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return []
    blocks: list[list[ast.stmt]] = []
    for field_name in ("body", "orelse", "finalbody"):
        value = getattr(statement, field_name, None)
        if isinstance(value, list):
            blocks.append(value)
    if isinstance(statement, ast.Try):
        blocks.extend(handler.body for handler in statement.handlers)
    if isinstance(statement, ast.Match):
        blocks.extend(case.body for case in statement.cases)
    return blocks


def _control_flow(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    visitor = _ControlFlowVisitor()
    for statement in node.body:
        visitor.visit(statement)
    blocks = 1 + visitor.decisions + visitor.loops
    edges = max(0, blocks - 1) + (2 * visitor.decisions) + visitor.loops
    return {
        "statement_count": visitor.statements,
        "basic_blocks_estimate": blocks,
        "edges_estimate": edges,
        "decision_points": visitor.decisions,
        "loops": visitor.loops,
        "returns": visitor.returns,
        "raises": visitor.raises,
        "awaits": visitor.awaits,
        "yields": visitor.yields,
        "breaks": visitor.breaks,
        "continues": visitor.continues,
        "cyclomatic_complexity": 1 + visitor.decisions,
        "unreachable_lines": _unreachable_lines(node.body),
    }


def _arguments(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[tuple[str, ...], dict[str, str]]:
    args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    if node.args.vararg:
        args.append(node.args.vararg)
    if node.args.kwarg:
        args.append(node.args.kwarg)
    types = {arg.arg: _dotted(arg.annotation) for arg in args if arg.annotation is not None}
    return tuple(arg.arg for arg in args), types


def _decorator_name(node: ast.AST) -> str:
    return _dotted(node.func if isinstance(node, ast.Call) else node)


def _route_info(decorator: ast.AST) -> dict | None:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = _dotted(target)
    short = name.rsplit(".", 1)[-1].lower()
    if short not in ROUTE_DECORATORS:
        return None
    route = ""
    methods: list[str] = []
    if isinstance(decorator, ast.Call):
        if decorator.args:
            route = _string_constant(decorator.args[0])
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                methods.extend(_string_constant(item).upper() for item in keyword.value.elts)
    if short not in {"route", "api_view", "action"}:
        methods.append(short.upper())
    return {"decorator": name, "path": route, "methods": sorted(set(filter(None, methods))) or ["ANY"]}


def _resolve_relative_import(module: str, is_package: bool, level: int, imported: str) -> str:
    if level <= 0:
        return imported
    package = module if is_package else module.rpartition(".")[0]
    parts = [part for part in package.split(".") if part]
    remove = max(0, level - 1)
    if remove:
        parts = parts[:-remove] if remove <= len(parts) else []
    if imported:
        parts.extend(imported.split("."))
    return ".".join(parts)


def _collect_imports(model: ModuleModel) -> None:
    is_package = model.path.name == "__init__.py"
    for statement in model.tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                target = alias.name
                model.aliases[local] = target
                model.module_aliases[local] = target
                model.imports.append({"module": target, "level": 0, "line": statement.lineno})
        elif isinstance(statement, ast.ImportFrom):
            base = _resolve_relative_import(model.name, is_package, statement.level, statement.module or "")
            model.imports.append({"module": base, "level": statement.level, "line": statement.lineno})
            for alias in statement.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                target = ".".join(filter(None, (base, alias.name)))
                model.aliases[local] = target


def _collect_models(modules: Mapping[str, ModuleModel]) -> tuple[dict[str, FunctionModel], dict[str, ClassModel]]:
    functions: dict[str, FunctionModel] = {}
    classes: dict[str, ClassModel] = {}

    def visit_body(module: ModuleModel, body: Sequence[ast.stmt], parents: list[str], class_qname: str = "") -> None:
        for statement in body:
            if isinstance(statement, ast.ClassDef):
                qual = ".".join(parents + [statement.name])
                qname = module.name + "." + qual
                classes[qname] = ClassModel(
                    qname, module, statement, tuple(_dotted(base) for base in statement.bases),
                    tuple(_decorator_name(item) for item in statement.decorator_list),
                )
                visit_body(module, statement.body, parents + [statement.name], qname)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = ".".join(parents + [statement.name])
                qname = module.name + "." + qual
                parameters, types = _arguments(statement)
                decorators = tuple(_decorator_name(item) for item in statement.decorator_list)
                routes = tuple(filter(None, (_route_info(item) for item in statement.decorator_list)))
                short_decorators = {item.rsplit(".", 1)[-1].lower() for item in decorators}
                entry = bool(routes) or statement.name.lower() in ENTRYPOINT_NAMES or bool(
                    short_decorators & CALLBACK_DECORATORS)
                functions[qname] = FunctionModel(
                    qname, module, statement, qual, class_qname, parameters, types,
                    decorators, routes, entry, _control_flow(statement),
                )
                # Nested functions are real symbols and can participate in local calls.
                visit_body(module, statement.body, parents + [statement.name], class_qname)

    for module in modules.values():
        visit_body(module, module.tree.body, [])
    return functions, classes


def _resolve_module_target(imported: str, module_names: set[str]) -> str:
    if imported in module_names:
        return imported
    candidates = [name for name in module_names if name.startswith(imported + ".")]
    return min(candidates, key=lambda item: (item.count("."), item)) if candidates else ""


def _strongly_connected(graph: Mapping[str, Sequence[str]]) -> list[list[str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    found: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = low[node] = index
        index += 1
        stack.append(node); on_stack.add(node)
        for target in sorted(graph.get(node, ())):
            if target not in graph:
                continue
            if target not in indices:
                visit(target); low[node] = min(low[node], low[target])
            elif target in on_stack:
                low[node] = min(low[node], indices[target])
        if low[node] == indices[node]:
            component: list[str] = []
            while stack:
                item = stack.pop(); on_stack.remove(item); component.append(item)
                if item == node:
                    break
            component.sort()
            if len(component) > 1 or node in graph.get(node, ()):
                found.append(component)

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(found)


class SemanticRepository:
    """Internal immutable-source repository model and fixed-point solver."""

    def __init__(self, root: Path, modules: dict[str, ModuleModel], functions: dict[str, FunctionModel],
                 classes: dict[str, ClassModel]) -> None:
        self.root = root
        self.modules = modules
        self.functions = functions
        self.classes = classes
        functions_by_short: dict[str, list[str]] = collections.defaultdict(list)
        for qname in functions:
            functions_by_short[qname.rsplit(".", 1)[-1]].append(qname)
        self.functions_by_short = {
            name: tuple(sorted(values)) for name, values in functions_by_short.items()
        }
        classes_by_short: dict[str, list[str]] = collections.defaultdict(list)
        for qname in classes:
            classes_by_short[qname.rsplit(".", 1)[-1]].append(qname)
        self.classes_by_short = {
            name: tuple(sorted(values)) for name, values in classes_by_short.items()
        }
        self.summaries: dict[str, FunctionSummary] = {name: FunctionSummary() for name in functions}
        self.sources: dict[str, dict] = {}
        self.call_sites: dict[str, dict[tuple, dict]] = {name: {} for name in functions}
        self.function_evaluations = 0

    def source_atom(self, function: FunctionModel, line: int, column: int,
                    kind: str, symbol: str) -> FlowAtom:
        relative = self.relative_path(function.module.path)
        origin = _source_id(function.qname, relative, line, kind, symbol)
        self.sources.setdefault(origin, {
            "id": origin, "kind": kind, "symbol": symbol,
            "function": function.qname, "path": function.module.display_path,
            "line": line, "column": column,
        })
        return FlowAtom(origin)

    def relative_path(self, path: str | os.PathLike[str]) -> str:
        try:
            return Path(path).resolve().relative_to(self.root.resolve()).as_posix()
        except (OSError, ValueError):
            return Path(path).name

    def canonical_external(self, function: FunctionModel, raw: str, local_aliases: Mapping[str, str]) -> str:
        if raw in local_aliases:
            raw = local_aliases[raw]
        head, dot, tail = raw.partition(".")
        target = function.module.aliases.get(head)
        if target:
            return target + (("." + tail) if dot else "")
        return raw

    def resolve_call(self, function: FunctionModel, raw: str,
                     local_aliases: Mapping[str, str], object_types: Mapping[str, str]) -> str:
        if not raw:
            return ""
        if raw in local_aliases:
            raw = local_aliases[raw]
        head, dot, tail = raw.partition(".")

        # self.method / cls.method and locally constructed/annotated objects.
        if head in {"self", "cls"} and function.class_qname and tail:
            candidate = function.class_qname + "." + tail
            if candidate in self.functions:
                return candidate
        if head in object_types and tail:
            class_name = object_types[head]
            if class_name in self.classes and class_name + "." + tail in self.functions:
                return class_name + "." + tail

        imported = function.module.aliases.get(head)
        if imported:
            candidate = imported + (("." + tail) if dot else "")
            if candidate in self.functions:
                return candidate
            # ``from package import module`` can map to package.module.fn.
            suffix_matches = [name for name in self.functions_by_short.get(
                candidate.rsplit(".", 1)[-1], ())
                              if name == candidate or name.endswith("." + candidate)]
            if len(suffix_matches) == 1:
                return suffix_matches[0]

        # Current lexical scope, current class, then current module.
        parents = function.qualname.split(".")[:-1]
        for length in range(len(parents), -1, -1):
            prefix = ".".join([function.module.name] + parents[:length])
            candidate = prefix + "." + raw
            if candidate in self.functions:
                return candidate
        candidate = function.module.name + "." + raw
        if candidate in self.functions:
            return candidate

        # ``Class.method`` in this module.
        candidate = function.module.name + "." + raw
        if candidate in self.functions:
            return candidate

        # Cross-module calls require an import.  Resolving a unique global short
        # name without one would not match Python's actual name lookup rules.
        return ""

    def record_call(self, caller: FunctionModel, raw: str, canonical: str, target: str,
                    node: ast.Call) -> None:
        key = (caller.module.display_path, node.lineno,
               getattr(node, "col_offset", 0), raw, target)
        self.call_sites.setdefault(caller.qname, {})[key] = {
            "caller": caller.qname, "callee": raw, "canonical_callee": canonical,
            "target": target, "resolved": bool(target),
            "path": caller.module.display_path, "line": node.lineno,
            "column": getattr(node, "col_offset", 0),
        }

    def solve(self) -> tuple[int, bool]:
        """Solve summaries with a deterministic dependency worklist.

        A caller is revisited only when one of its resolved callees changes.
        This preserves fixed-point behavior while avoiding whole-repository
        rescans for every layer of an interprocedural chain.
        """
        queue = collections.deque(sorted(self.functions))
        queued = set(queue)
        dependencies: dict[str, set[str]] = {name: set() for name in self.functions}
        reverse: dict[str, set[str]] = collections.defaultdict(set)
        maximum = max(1_000, len(self.functions) * (MAX_EVIDENCE_CALLS + 4))
        operations = 0

        while queue and operations < maximum:
            qname = queue.popleft(); queued.remove(qname)
            operations += 1
            self.call_sites[qname] = {}
            analyzer = _FunctionAnalyzer(self, self.functions[qname], self.summaries)
            summary = analyzer.run()

            new_dependencies = {
                row["target"] for row in self.call_sites[qname].values() if row["target"]
            }
            for target in dependencies[qname] - new_dependencies:
                reverse[target].discard(qname)
            for target in new_dependencies - dependencies[qname]:
                reverse[target].add(qname)
            dependencies[qname] = new_dependencies

            if summary != self.summaries[qname]:
                self.summaries[qname] = summary
                for caller in sorted(reverse.get(qname, ())):
                    if caller not in queued:
                        queue.append(caller); queued.add(caller)

        self.function_evaluations = operations
        equivalent_rounds = (operations + max(1, len(self.functions)) - 1) // max(1, len(self.functions))
        return equivalent_rounds, not bool(queue)


class _FunctionAnalyzer:
    def __init__(self, repository: SemanticRepository, model: FunctionModel,
                 summaries: Mapping[str, FunctionSummary]) -> None:
        self.repository = repository
        self.model = model
        self.summaries = summaries
        self.returns: Flow = EMPTY_FLOW
        self.sinks: set[SinkTemplate] = set()
        self.assignments = 0
        self.aliases_count = 0
        self.reassignments = 0
        self.sanitized_assignments = 0
        self.local_call_aliases: dict[str, str] = {}
        self.object_types: dict[str, str] = {}

    def _route_parameter_is_source(self, name: str) -> bool:
        if not self.model.routes:
            return False
        if name in {"self", "cls", "request", "session", "db", "context", "current_user"}:
            return False
        paths = " ".join(route.get("path", "") for route in self.model.routes)
        explicit = re.findall(r"(?:<[^:>]*:)?([A-Za-z_]\w*)>|\{([A-Za-z_]\w*)\}", paths)
        path_names = {left or right for left, right in explicit}
        if name in path_names:
            return True
        default_name = self._parameter_default_name(name).rsplit(".", 1)[-1].lower()
        if default_name in {"depends", "security"}:
            return False
        annotation = self.model.parameter_types.get(name, "").rsplit(".", 1)[-1].lower()
        if annotation in {
            "request", "session", "connection", "database", "repository",
            "service", "client", "user", "principal",
        }:
            return False
        # FastAPI-style parameters are request-controlled even when the route
        # string has no placeholder (query/body parameters).
        decorator = " ".join(route.get("decorator", "") for route in self.model.routes).lower()
        framework_parameter = any(token in decorator for token in ("get", "post", "put", "patch", "delete", "route"))
        return framework_parameter

    def _parameter_default_name(self, name: str) -> str:
        arguments = self.model.node.args
        positional = list(arguments.posonlyargs) + list(arguments.args)
        first_default = len(positional) - len(arguments.defaults)
        for index, argument in enumerate(positional):
            if argument.arg == name and index >= first_default:
                value = arguments.defaults[index - first_default]
                return _dotted(value.func if isinstance(value, ast.Call) else value)
        for argument, value in zip(arguments.kwonlyargs, arguments.kw_defaults):
            if argument.arg == name and value is not None:
                return _dotted(value.func if isinstance(value, ast.Call) else value)
        return ""

    def initial_state(self) -> dict[str, Flow]:
        state: dict[str, Flow] = {}
        for index, parameter in enumerate(self.model.parameters):
            if self._route_parameter_is_source(parameter) or (
                    self.model.node.name == "lambda_handler" and parameter not in {"context"}):
                kind = "route.parameter" if self.model.routes else "event.parameter"
                state[parameter] = frozenset({self.repository.source_atom(
                    self.model, self.model.node.lineno, self.model.node.col_offset,
                    kind, parameter)})
            else:
                state[parameter] = frozenset({FlowAtom("param:%d" % index)})
            annotation = self.model.parameter_types.get(parameter, "")
            if annotation:
                resolved = self._resolve_class_name(annotation)
                if resolved:
                    self.object_types[parameter] = resolved
        return state

    def _resolve_class_name(self, name: str) -> str:
        if not name:
            return ""
        head, dot, tail = name.partition(".")
        imported = self.model.module.aliases.get(head)
        candidate = imported + (("." + tail) if imported and dot else "") if imported else ""
        possibilities = [candidate, self.model.module.name + "." + name, name]
        for item in possibilities:
            if item in self.repository.classes:
                return item
        matches = self.repository.classes_by_short.get(name.rsplit(".", 1)[-1], ())
        return matches[0] if len(matches) == 1 else ""

    def run(self) -> FunctionSummary:
        state = self.initial_state()
        self._process_block(self.model.node.body, state)
        return FunctionSummary(
            returns=self.returns,
            sinks=tuple(sorted(self.sinks)),
            assignments=self.assignments,
            aliases=self.aliases_count,
            reassignments=self.reassignments,
            sanitized_assignments=self.sanitized_assignments,
        )

    def _join_states(self, *states: Mapping[str, Flow]) -> dict[str, Flow]:
        keys = set().union(*(state.keys() for state in states)) if states else set()
        return {key: _flow_union(*(state.get(key, EMPTY_FLOW) for state in states)) for key in sorted(keys)}

    @staticmethod
    def _common_mapping(*mappings: Mapping[str, str]) -> dict[str, str]:
        if not mappings:
            return {}
        common = dict(mappings[0])
        for key in list(common):
            if any(mapping.get(key) != common[key] for mapping in mappings[1:]):
                common.pop(key, None)
        return common

    def _assign_name(self, name: str, flow: Flow, state: dict[str, Flow], value: ast.AST | None = None) -> None:
        self.assignments += 1
        if name in state:
            self.reassignments += 1
        state[name] = flow
        if isinstance(value, (ast.Name, ast.Attribute)):
            if flow:
                self.aliases_count += 1
            raw = _dotted(value)
            self.local_call_aliases[name] = raw
            if raw in self.object_types:
                self.object_types[name] = self.object_types[raw]
        elif isinstance(value, ast.Call):
            raw_type = _dotted(value.func)
            resolved_type = self._resolve_class_name(self.repository.canonical_external(
                self.model, raw_type, self.local_call_aliases))
            if resolved_type:
                self.object_types[name] = resolved_type
            else:
                self.object_types.pop(name, None)
            if self._sanitizer_contexts(value):
                self.sanitized_assignments += 1
            self.local_call_aliases.pop(name, None)
        else:
            self.local_call_aliases.pop(name, None)
            self.object_types.pop(name, None)

    def _assign_target(self, target: ast.AST, flow: Flow, state: dict[str, Flow], value: ast.AST | None = None) -> None:
        if isinstance(target, ast.Name):
            self._assign_name(target.id, flow, state, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, flow, state, value)
        elif isinstance(target, ast.Attribute):
            name = _dotted(target)
            if name:
                self._assign_name(name, flow, state, value)

    def _process_block(self, statements: Sequence[ast.stmt], state: dict[str, Flow]) -> dict[str, Flow]:
        for statement in statements:
            state = self._process_statement(statement, state)
            if _always_terminates(statement):
                break
        return state

    def _process_statement(self, node: ast.stmt, state: dict[str, Flow]) -> dict[str, Flow]:
        if isinstance(node, ast.Assign):
            flow = self._expr(node.value, state)
            for target in node.targets:
                self._assign_target(target, flow, state, node.value)
            return state
        if isinstance(node, ast.AnnAssign):
            flow = self._expr(node.value, state) if node.value is not None else EMPTY_FLOW
            self._assign_target(node.target, flow, state, node.value)
            return state
        if isinstance(node, ast.AugAssign):
            prior = self._expr(node.target, state)
            value = self._expr(node.value, state)
            self._assign_target(node.target, _flow_union(prior, value), state, node.value)
            return state
        if isinstance(node, ast.Expr):
            self._expr(node.value, state)
            return state
        if isinstance(node, ast.Return):
            if node.value is not None:
                self.returns = _flow_union(self.returns, self._expr(node.value, state))
            return state
        if isinstance(node, ast.Raise):
            if node.exc:
                self._expr(node.exc, state)
            return state
        if isinstance(node, ast.Delete):
            for target in node.targets:
                name = _dotted(target)
                if name:
                    state.pop(name, None)
            return state
        if isinstance(node, ast.If):
            self._expr(node.test, state)
            initial_aliases = dict(self.local_call_aliases)
            initial_types = dict(self.object_types)
            yes = self._process_block(node.body, dict(state))
            yes_aliases = dict(self.local_call_aliases)
            yes_types = dict(self.object_types)
            self.local_call_aliases = dict(initial_aliases)
            self.object_types = dict(initial_types)
            no = self._process_block(node.orelse, dict(state)) if node.orelse else dict(state)
            no_aliases = dict(self.local_call_aliases)
            no_types = dict(self.object_types)
            self.local_call_aliases = self._common_mapping(yes_aliases, no_aliases)
            self.object_types = self._common_mapping(yes_types, no_types)
            return self._join_states(yes, no)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            iterator = self._expr(node.iter, state)
            initial_aliases = dict(self.local_call_aliases)
            initial_types = dict(self.object_types)
            body_state = dict(state)
            self._assign_target(node.target, iterator, body_state, node.iter)
            body_state = self._process_block(node.body, body_state)
            self.local_call_aliases = self._common_mapping(initial_aliases, self.local_call_aliases)
            self.object_types = self._common_mapping(initial_types, self.object_types)
            joined = self._join_states(state, body_state)
            if node.orelse:
                joined = self._join_states(joined, self._process_block(node.orelse, dict(joined)))
            return joined
        if isinstance(node, ast.While):
            self._expr(node.test, state)
            initial_aliases = dict(self.local_call_aliases)
            initial_types = dict(self.object_types)
            body_state = self._process_block(node.body, dict(state))
            self.local_call_aliases = self._common_mapping(initial_aliases, self.local_call_aliases)
            self.object_types = self._common_mapping(initial_types, self.object_types)
            joined = self._join_states(state, body_state)
            if node.orelse:
                joined = self._join_states(joined, self._process_block(node.orelse, dict(joined)))
            return joined
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                flow = self._expr(item.context_expr, state)
                if item.optional_vars:
                    self._assign_target(item.optional_vars, flow, state, item.context_expr)
            return self._process_block(node.body, state)
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            paths = [self._process_block(node.body, dict(state))]
            for handler in node.handlers:
                handler_state = dict(state)
                if handler.name:
                    handler_state[handler.name] = EMPTY_FLOW
                paths.append(self._process_block(handler.body, handler_state))
            joined = self._join_states(*paths)
            if node.orelse:
                joined = self._process_block(node.orelse, joined)
            if node.finalbody:
                joined = self._process_block(node.finalbody, joined)
            return joined
        if isinstance(node, ast.Match):
            self._expr(node.subject, state)
            initial_aliases = dict(self.local_call_aliases)
            initial_types = dict(self.object_types)
            paths = []
            alias_paths = []
            type_paths = []
            for case in node.cases:
                self.local_call_aliases = dict(initial_aliases)
                self.object_types = dict(initial_types)
                paths.append(self._process_block(case.body, dict(state)))
                alias_paths.append(dict(self.local_call_aliases))
                type_paths.append(dict(self.object_types))
            self.local_call_aliases = self._common_mapping(initial_aliases, *alias_paths)
            self.object_types = self._common_mapping(initial_types, *type_paths)
            return self._join_states(state, *paths)
        if isinstance(node, ast.Assert):
            self._expr(node.test, state)
            if node.msg:
                self._expr(node.msg, state)
            return state
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom,
                             ast.Global, ast.Nonlocal, ast.Pass, ast.Break, ast.Continue)):
            return state
        # Future Python syntax degrades conservatively: inspect contained expressions.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._expr(child, state)
        return state

    def _lookup(self, name: str, state: Mapping[str, Flow]) -> Flow:
        if name in state:
            return state[name]
        head = name.split(".", 1)[0]
        return state.get(head, EMPTY_FLOW)

    def _source_kind(self, canonical: str) -> str:
        if canonical in SOURCE_CALLS:
            return SOURCE_CALLS[canonical]
        for prefix, kind in SOURCE_PREFIXES.items():
            if canonical == prefix or canonical.startswith(prefix + "."):
                return kind
        return ""

    def _sanitizer_contexts(self, node: ast.Call) -> set[str]:
        raw = _dotted(node.func)
        canonical = self.repository.canonical_external(self.model, raw, self.local_call_aliases)
        return set(SANITIZER_CONTEXTS.get(canonical, SANITIZER_CONTEXTS.get(raw, set())))

    def _sink_spec(self, canonical: str, raw: str) -> tuple[str, str, str, str, tuple[int, ...]] | None:
        spec = SINK_SPECS.get(canonical) or SINK_SPECS.get(raw)
        if spec:
            return spec
        candidate = canonical or raw
        parts = candidate.lower().split(".")
        method = parts[-1] if parts else ""
        receiver = parts[-2] if len(parts) > 1 else ""
        sql_receiver = receiver in {
            "cursor", "cur", "db", "database", "connection", "conn", "engine",
            "session", "queryset",
        } or any(token in candidate.lower() for token in (
            "sqlite", "sqlalchemy", "psycopg", "mysql", "django.db"))
        if method in {"execute", "executemany", "executescript", "raw"} and sql_receiver:
            return ("sql", "CWE-89", "CRITICAL", "Use a constant query with bound parameters.", (0,))
        return None

    def _actual_arguments(self, node: ast.Call, target: FunctionModel,
                          positional: Sequence[Flow], keywords: Mapping[str, Flow]) -> dict[int, Flow]:
        offset = 0
        if (target.class_qname and target.parameters and target.parameters[0] in {"self", "cls"}
                and isinstance(node.func, ast.Attribute)):
            receiver = _dotted(node.func.value)
            class_short = target.class_qname.rsplit(".", 1)[-1]
            # Calls through an instance bind self/cls implicitly.  Calls through
            # the class (Runner.method(instance, ...)) keep explicit position 0.
            is_classmethod = any(item.rsplit(".", 1)[-1] == "classmethod" for item in target.decorators)
            if (isinstance(node.func.value, ast.Call) or is_classmethod
                    or receiver.rsplit(".", 1)[-1] != class_short):
                offset = 1
        actual: dict[int, Flow] = {index + offset: flow for index, flow in enumerate(positional)}
        parameter_index = {name: index for index, name in enumerate(target.parameters)}
        for name, flow in keywords.items():
            if name in parameter_index:
                actual[parameter_index[name]] = flow
        return actual

    def _map_callee_atom(self, atom: FlowAtom, actual: Mapping[int, Flow], trace: CallTrace) -> Flow:
        parameter = _parameter_index(atom.origin)
        if parameter is None:
            return frozenset({_append_trace(atom, trace)})
        mapped: set[FlowAtom] = set()
        for source in actual.get(parameter, EMPTY_FLOW):
            combined = FlowAtom(
                source.origin,
                tuple(sorted(set(source.sanitizers) | set(atom.sanitizers))),
                source.calls,
            )
            combined = _append_trace(combined, trace)
            for nested in atom.calls:
                combined = _append_trace(combined, nested)
            mapped.add(combined)
        return frozenset(mapped)

    def _record_direct_sink(self, node: ast.Call, canonical: str, raw: str,
                            positional: Sequence[Flow], keywords: Mapping[str, Flow]) -> None:
        spec = self._sink_spec(canonical, raw)
        if not spec:
            return
        context, cwe, severity, remediation, positions = spec
        selected = [positional[index] for index in positions if index < len(positional)]
        # Some APIs accept the dangerous value by keyword.
        if not selected:
            for key in ("command", "args", "query", "url", "filename", "path", "source", "object"):
                if key in keywords:
                    selected.append(keywords[key])
        atoms = _flow_union(*selected)
        atoms = frozenset(atom for atom in atoms if not atom.sanitized_for(context))
        if not atoms:
            return
        self.sinks.add(SinkTemplate(
            sink=canonical or raw, context=context, cwe=cwe, severity=severity,
            remediation=remediation, function=self.model.qname,
            path=self.model.module.display_path, line=node.lineno,
            column=getattr(node, "col_offset", 0), atoms=atoms,
        ))

    def _propagate_callee_sinks(self, node: ast.Call, target: FunctionModel,
                                actual: Mapping[int, Flow], trace: CallTrace) -> None:
        for sink in self.summaries.get(target.qname, FunctionSummary()).sinks:
            mapped: set[FlowAtom] = set()
            for atom in sink.atoms:
                parameter = _parameter_index(atom.origin)
                # A source-to-sink flow entirely inside the callee is reported
                # once at the callee, not cloned into every caller.
                if parameter is None:
                    continue
                mapped.update(self._map_callee_atom(atom, actual, trace))
            safe_filtered = frozenset(atom for atom in mapped if not atom.sanitized_for(sink.context))
            if safe_filtered:
                self.sinks.add(SinkTemplate(
                    sink.sink, sink.context, sink.cwe, sink.severity, sink.remediation,
                    sink.function, sink.path, sink.line, sink.column, safe_filtered,
                ))

    def _expr(self, node: ast.AST | None, state: dict[str, Flow]) -> Flow:
        if node is None or isinstance(node, ast.Constant):
            return EMPTY_FLOW
        if isinstance(node, ast.Name):
            return self._lookup(node.id, state)
        if isinstance(node, ast.Attribute):
            raw = _dotted(node)
            canonical = self.repository.canonical_external(self.model, raw, self.local_call_aliases)
            kind = self._source_kind(canonical) or self._source_kind(raw)
            if kind:
                return frozenset({self.repository.source_atom(
                    self.model, node.lineno, node.col_offset, kind, raw)})
            return _flow_union(self._lookup(raw, state), self._expr(node.value, state))
        if isinstance(node, ast.Subscript):
            raw = _dotted(node.value)
            canonical = self.repository.canonical_external(self.model, raw, self.local_call_aliases)
            kind = self._source_kind(canonical) or self._source_kind(raw)
            if kind:
                return frozenset({self.repository.source_atom(
                    self.model, node.lineno, node.col_offset, kind, raw)})
            return self._expr(node.value, state)
        if isinstance(node, ast.NamedExpr):
            flow = self._expr(node.value, state)
            self._assign_target(node.target, flow, state, node.value)
            return flow
        if isinstance(node, (ast.BinOp, ast.BoolOp)):
            children = [node.left, node.right] if isinstance(node, ast.BinOp) else node.values
            return _flow_union(*(self._expr(child, state) for child in children))
        if isinstance(node, ast.UnaryOp):
            return self._expr(node.operand, state)
        if isinstance(node, ast.IfExp):
            self._expr(node.test, state)
            return _flow_union(self._expr(node.body, state), self._expr(node.orelse, state))
        if isinstance(node, ast.JoinedStr):
            return _flow_union(*(self._expr(value, state) for value in node.values))
        if isinstance(node, ast.FormattedValue):
            return self._expr(node.value, state)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return _flow_union(*(self._expr(item, state) for item in node.elts))
        if isinstance(node, ast.Dict):
            return _flow_union(
                *(self._expr(item, state) for item in list(node.keys) + list(node.values) if item is not None))
        if isinstance(node, ast.Starred):
            return self._expr(node.value, state)
        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
            return self._expr(node.value, state)
        if isinstance(node, ast.Compare):
            # Comparison results are booleans; inspect operands for nested calls
            # but do not label the resulting boolean as injectable text.
            self._expr(node.left, state)
            for comparator in node.comparators:
                self._expr(comparator, state)
            return EMPTY_FLOW
        if isinstance(node, ast.Lambda):
            return EMPTY_FLOW
        if isinstance(node, ast.Call):
            return self._call(node, state)
        if isinstance(node, ast.Slice):
            return _flow_union(self._expr(node.lower, state), self._expr(node.upper, state),
                               self._expr(node.step, state))
        # Conservatively combine unknown expression children, but nested scopes
        # are never traversed or executed.
        return _flow_union(*(self._expr(child, state) for child in ast.iter_child_nodes(node)
                             if isinstance(child, ast.expr)))

    def _call(self, node: ast.Call, state: dict[str, Flow]) -> Flow:
        raw = _dotted(node.func)
        canonical = self.repository.canonical_external(self.model, raw, self.local_call_aliases)
        target_name = self.repository.resolve_call(
            self.model, raw, self.local_call_aliases, self.object_types)
        target = self.repository.functions.get(target_name)
        self.repository.record_call(self.model, raw, canonical, target_name, node)

        positional = [self._expr(argument, state) for argument in node.args]
        keywords = {keyword.arg: self._expr(keyword.value, state)
                    for keyword in node.keywords if keyword.arg is not None}

        source_kind = self._source_kind(canonical) or self._source_kind(raw)
        if source_kind:
            return frozenset({self.repository.source_atom(
                self.model, node.lineno, node.col_offset, source_kind, raw)})

        contexts = SANITIZER_CONTEXTS.get(canonical) or SANITIZER_CONTEXTS.get(raw)
        if contexts:
            return _sanitize(_flow_union(*positional, *keywords.values()), contexts)

        if target:
            actual = self._actual_arguments(node, target, positional, keywords)
            trace = CallTrace(self.model.qname, target.qname, self.model.module.display_path, node.lineno)
            self._propagate_callee_sinks(node, target, actual, trace)
            returned: set[FlowAtom] = set()
            for atom in self.summaries.get(target.qname, FunctionSummary()).returns:
                returned.update(self._map_callee_atom(atom, actual, trace))
            return frozenset(returned)

        # A resolved repository function owns its own sink summary.  Only an
        # unresolved external call is classified directly as a dangerous API.
        self._record_direct_sink(node, canonical, raw, positional, keywords)

        short = canonical.rsplit(".", 1)[-1]
        receiver = EMPTY_FLOW
        if isinstance(node.func, ast.Attribute):
            receiver = self._expr(node.func.value, state)
        if short == "get" and isinstance(node.func, ast.Attribute):
            # Mapping.get(key, default) returns mapping content or the default;
            # the key chooses a value but does not itself become that value.
            default = positional[1] if len(positional) > 1 else keywords.get("default", EMPTY_FLOW)
            return _flow_union(receiver, default)
        if canonical in PROPAGATING_CALLS or raw in PROPAGATING_CALLS or short in PROPAGATING_METHODS:
            return _flow_union(receiver, *positional, *keywords.values())
        return EMPTY_FLOW


def _discover(root: Path, max_files: int, max_bytes: int) -> tuple[list[Path], list[dict], list[dict]]:
    files: list[Path] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    candidates: Iterable[Path]
    if root.is_file():
        candidates = [root]
        base = root.parent
    elif root.is_dir():
        candidates = root.rglob("*")
        base = root
    else:
        return [], [], [{"path": str(root), "message": "path does not exist"}]
    for path in sorted(candidates, key=lambda item: str(item).casefold()):
        if len(files) >= max_files:
            skipped.append({"path": str(base), "reason": "file limit reached", "limit": max_files})
            break
        try:
            if path.is_symlink():
                skipped.append({"path": str(path), "reason": "symbolic link not followed"})
                continue
            if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
                continue
            language = _language(path)
            if language == "unknown":
                continue
            resolved = path.resolve()
            if not _is_within(resolved, base.resolve()):
                skipped.append({"path": str(path), "reason": "outside analysis root"})
                continue
            size = path.stat().st_size
            if size > max_bytes:
                skipped.append({"path": str(path), "reason": "file too large", "bytes": size})
                continue
            files.append(resolved)
        except OSError as exc:
            errors.append({"path": str(path), "message": str(exc)})
    return files, skipped, errors


def _read_source(path: Path) -> tuple[str, bytes]:
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig"), data
    except UnicodeDecodeError:
        return data.decode("utf-8", "replace"), data


def _report_flow(atom: FlowAtom, repository: SemanticRepository) -> tuple[list[int], list[str]]:
    parameter = _parameter_index(atom.origin)
    if parameter is not None:
        return [parameter], []
    source = repository.sources.get(atom.origin)
    return [], [source["kind"]] if source else []


def _summary_to_json(summary: FunctionSummary, repository: SemanticRepository) -> dict:
    return_params: set[int] = set()
    return_sources: set[str] = set()
    for atom in summary.returns:
        params, sources = _report_flow(atom, repository)
        return_params.update(params); return_sources.update(sources)
    sink_rows = []
    for sink in summary.sinks:
        params: set[int] = set()
        sources: set[str] = set()
        for atom in sink.atoms:
            p, s = _report_flow(atom, repository)
            params.update(p); sources.update(s)
        sink_rows.append({
            "sink": sink.sink, "context": sink.context, "cwe": sink.cwe,
            "path": sink.path, "line": sink.line,
            "parameter_indexes": sorted(params), "source_kinds": sorted(sources),
            "interprocedural": any(atom.calls for atom in sink.atoms),
        })
    unique_sinks = {json.dumps(item, sort_keys=True): item for item in sink_rows}
    return {
        "return_parameter_indexes": sorted(return_params),
        "return_source_kinds": sorted(return_sources),
        "sink_dependencies": [unique_sinks[key] for key in sorted(unique_sinks)],
        "assignments": summary.assignments,
        "aliases": summary.aliases,
        "reassignments": summary.reassignments,
        "sanitized_assignments": summary.sanitized_assignments,
    }


def _finding_rows(repository: SemanticRepository) -> list[dict]:
    findings: dict[str, dict] = {}
    for owner in sorted(repository.summaries):
        for sink in repository.summaries[owner].sinks:
            for atom in sorted(sink.atoms):
                source = repository.sources.get(atom.origin)
                if not source or atom.sanitized_for(sink.context):
                    continue
                calls = []
                seen_calls = set()
                for trace in atom.calls:
                    key = (trace.caller, trace.callee, trace.path, trace.line)
                    if key not in seen_calls:
                        seen_calls.add(key); calls.append(trace)
                evidence = [{
                    "kind": "source", "path": source["path"], "line": source["line"],
                    "column": source["column"], "function": source["function"],
                    "symbol": source["symbol"], "detail": source["kind"],
                }]
                evidence.extend({
                    "kind": "call", "path": trace.path, "line": trace.line, "column": 0,
                    "caller": trace.caller, "callee": trace.callee,
                    "detail": "tainted value crosses function boundary",
                } for trace in calls)
                evidence.append({
                    "kind": "sink", "path": sink.path, "line": sink.line,
                    "column": sink.column, "function": sink.function,
                    "symbol": sink.sink, "detail": sink.context,
                })
                fingerprint = _stable_hash(source["id"], sink.function,
                                           repository.relative_path(sink.path), sink.line,
                                           sink.sink, sink.context)
                finding = {
                    "id": "ATTESTOR3-SEM-" + fingerprint[:12].upper(),
                    "fingerprint": fingerprint,
                    "rule": "semantic-taint/" + sink.context,
                    "severity": sink.severity,
                    "confidence": 0.99 if not calls else max(0.90, 0.98 - (0.01 * len(calls))),
                    "cwe": sink.cwe,
                    "message": "%s data reaches %s%s" % (
                        source["kind"], sink.sink,
                        " through %d resolved call%s" % (len(calls), "" if len(calls) == 1 else "s")
                        if calls else ""),
                    "path": sink.path, "line": sink.line, "column": sink.column,
                    "function": sink.function, "source": source,
                    "sink": {"name": sink.sink, "context": sink.context,
                             "path": sink.path, "line": sink.line},
                    "call_depth": len(calls), "sanitizers": list(atom.sanitizers),
                    "evidence": evidence, "remediation": sink.remediation,
                }
                findings[fingerprint] = finding
    return [findings[key] for key in sorted(findings)]


def _reachable(entrypoints: Sequence[str], edges: Sequence[dict]) -> list[str]:
    adjacency: dict[str, list[str]] = collections.defaultdict(list)
    for edge in edges:
        if edge["target"]:
            adjacency[edge["caller"]].append(edge["target"])
    reached = set(entrypoints)
    todo = collections.deque(sorted(entrypoints))
    while todo:
        current = todo.popleft()
        for target in sorted(set(adjacency.get(current, []))):
            if target not in reached:
                reached.add(target); todo.append(target)
    return sorted(reached)


# ---------------------------------------------------------------------------
# Safe multi-language compiler/parser front ends
# ---------------------------------------------------------------------------

FRONTEND_TOOLS: dict[str, tuple[str, ...]] = {
    "javascript": ("node",), "typescript": ("tsc",),
    "c": ("clang", "gcc"), "cpp": ("clang++", "g++"),
    "java": ("javac",), "csharp": ("csc",), "go": ("gofmt",),
    "rust": ("rustfmt",), "ruby": ("ruby",), "php": ("php",),
    "swift": ("swiftc",), "shell": ("bash",),
    "powershell": ("pwsh", "powershell"),
}


def build_frontend_command(path: str | os.PathLike[str], language: str,
                           executable: str | None = None,
                           output_dir: str | os.PathLike[str] | None = None) -> list[str] | None:
    """Return a parser/no-execution command as an argv list.

    No command is returned for languages where the engine cannot guarantee a
    parser-only mode.  Callers must still use ``shell=False`` and a timeout.
    """
    source = str(Path(path).resolve())
    tool = executable or (FRONTEND_TOOLS.get(language, (None,))[0])
    if not tool:
        return None
    out = str(Path(output_dir).resolve()) if output_dir else str(Path(tempfile.gettempdir()).resolve())
    if language == "javascript":
        return [tool, "--check", "--", source]
    if language == "typescript":
        return [tool, "--pretty", "false", "--noEmit", "--noResolve", "--skipLibCheck", source]
    if language == "c":
        return [tool, "-fsyntax-only", "-fno-diagnostics-color", "-x", "c", source]
    if language == "cpp":
        return [tool, "-fsyntax-only", "-fno-diagnostics-color", "-x", "c++", source]
    if language == "java":
        return [tool, "-proc:none", "-implicit:none", "-d", out, source]
    if language == "csharp":
        return [tool, "/noconfig", "/nologo", "/target:library", "/out:" + str(Path(out) / "check.dll"), source]
    if language == "go":
        return [tool, "-e", "-d", source]
    if language == "rust":
        return [tool, "--check", "--edition", "2021", source]
    if language == "ruby":
        return [tool, "--disable-gems", "-c", source]
    if language == "php":
        return [tool, "-n", "-l", source]
    if language == "swift":
        return [tool, "-parse", source]
    if language == "shell":
        return [tool, "--noprofile", "--norc", "-n", source]
    if language == "powershell":
        parser = ("$tokens=$null;$errors=$null;"
                  "[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)>$null;"
                  "if($errors.Count){$errors|ForEach-Object{$_.Message};exit 1}")
        return [tool, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser, source]
    return None


def available_frontends() -> list[dict]:
    rows = []
    for language in sorted(FRONTEND_TOOLS):
        executable = next((shutil.which(name) for name in FRONTEND_TOOLS[language] if shutil.which(name)), None)
        rows.append({"language": language, "available": bool(executable),
                     "tool": Path(executable).name if executable else ""})
    rows.append({"language": "json", "available": True, "tool": "python-json"})
    rows.append({"language": "python", "available": True, "tool": "python-ast"})
    return rows


def _clean_environment(home: str) -> dict[str, str]:
    keep = ("PATH", "SystemRoot", "WINDIR", "PATHEXT", "COMSPEC", "TEMP", "TMP", "LANG", "LC_ALL")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    env.update({
        "HOME": home, "USERPROFILE": home, "PYTHONNOUSERSITE": "1",
        "NO_COLOR": "1", "TERM": "dumb",
    })
    # Deliberately omit compiler/runtime injection variables such as
    # NODE_OPTIONS, RUBYOPT, PYTHONPATH, BASH_ENV, ENV, and DOTNET_STARTUP_HOOKS.
    return env


def _bounded_output(stdout: str, stderr: str, root: Path, temporary: Path) -> str:
    value = (stderr.strip() or stdout.strip()).replace(str(temporary), "<temporary>")
    value = value.replace(str(root), "<root>")
    if len(value) > MAX_TOOL_OUTPUT:
        value = value[:MAX_TOOL_OUTPUT] + "\n<output truncated>"
    return value


def run_frontend_checks(paths: Iterable[str | os.PathLike[str]], root: str | os.PathLike[str] | None = None,
                        timeout: float = DEFAULT_FRONTEND_TIMEOUT) -> list[dict]:
    """Run installed safe front ends without importing/executing target code."""
    source_paths = sorted({Path(path).resolve() for path in paths}, key=lambda item: str(item).casefold())
    report_root = Path(root).resolve() if root else (source_paths[0].parent if source_paths else Path.cwd())
    rows: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="attestor3-frontend-") as temporary_text:
        temporary = Path(temporary_text)
        env = _clean_environment(temporary_text)
        for path in source_paths:
            language = _language(path)
            if language == "python":
                try:
                    source = path.read_text(encoding="utf-8-sig")
                    ast.parse(source, filename=str(path), type_comments=True)
                    status, detail = "passed", ""
                except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
                    status, detail = "failed", getattr(exc, "msg", str(exc))
                rows.append({"path": str(path), "language": language, "tool": "python-ast",
                             "status": status, "command": ["python-ast"], "detail": detail})
                continue
            if language == "json":
                try:
                    json.loads(path.read_text(encoding="utf-8-sig"))
                    status, detail = "passed", ""
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    status, detail = "failed", str(exc)
                rows.append({"path": str(path), "language": language, "tool": "python-json",
                             "status": status, "command": ["python-json"], "detail": detail})
                continue
            candidates = FRONTEND_TOOLS.get(language, ())
            executable = next((shutil.which(name) for name in candidates if shutil.which(name)), None)
            if not executable:
                rows.append({"path": str(path), "language": language, "tool": "",
                             "status": "unavailable", "command": [],
                             "detail": "no safe parser/compiler front end installed"})
                continue
            command = build_frontend_command(path, language, executable, temporary)
            if not command:
                rows.append({"path": str(path), "language": language, "tool": Path(executable).name,
                             "status": "unsupported", "command": [],
                             "detail": "no no-execution mode is defined"})
                continue
            display = [Path(command[0]).name] + [
                item.replace(str(temporary), "<temporary>").replace(str(report_root), "<root>")
                for item in command[1:]
            ]
            try:
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                completed = subprocess.run(
                    command, shell=False, cwd=temporary, env=env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    encoding="utf-8", errors="replace", timeout=max(0.1, timeout),
                    creationflags=creationflags, check=False,
                )
                status = "passed" if completed.returncode == 0 else "failed"
                detail = _bounded_output(completed.stdout, completed.stderr, report_root, temporary)
            except subprocess.TimeoutExpired:
                status, detail = "timeout", "front end exceeded %.1f seconds" % timeout
            except OSError as exc:
                status, detail = "error", str(exc)
            rows.append({
                "path": str(path), "language": language, "tool": Path(executable).name,
                "status": status, "command": display, "detail": detail,
            })
    return rows


def analyze_repository(root: str | os.PathLike[str], *, compiler_checks: bool = False,
                       max_files: int = DEFAULT_MAX_FILES,
                       max_bytes: int = DEFAULT_MAX_BYTES,
                       frontend_timeout: float = DEFAULT_FRONTEND_TIMEOUT) -> dict:
    """Analyze a repository without importing or executing its code."""
    requested = Path(root).expanduser()
    base = requested.resolve()
    discovery_root = base.parent if base.is_file() else base
    files, skipped, operational_errors = _discover(base, max(1, max_files), max(1, max_bytes))
    modules: dict[str, ModuleModel] = {}
    file_rows: list[dict] = []
    parse_errors: list[dict] = []

    for path in files:
        language = _language(path)
        try:
            source, raw = _read_source(path)
        except OSError as exc:
            operational_errors.append({"path": str(path), "message": str(exc)})
            continue
        row = {
            "path": str(path), "relative_path": str(path.relative_to(discovery_root)),
            "language": language, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "status": "indexed",
        }
        if language == "python":
            module_name = _module_name(discovery_root, path)
            row["module"] = module_name
            try:
                tree = ast.parse(source, filename=str(path), type_comments=True)
            except (SyntaxError, ValueError) as exc:
                row["status"] = "parse-error"
                parse_errors.append({
                    "path": str(path), "line": getattr(exc, "lineno", 1) or 1,
                    "column": getattr(exc, "offset", 0) or 0,
                    "message": getattr(exc, "msg", str(exc)), "frontend": "python-ast",
                })
            else:
                model = ModuleModel(module_name, path, str(path), tree)
                _collect_imports(model)
                # Duplicate module names are explicit coverage failures rather
                # than silently replacing one file's semantics.
                if module_name in modules:
                    row["status"] = "duplicate-module"
                    parse_errors.append({
                        "path": str(path), "line": 1, "column": 0,
                        "message": "duplicate module name: " + module_name,
                        "frontend": "python-ast",
                    })
                else:
                    modules[module_name] = model
        file_rows.append(row)

    functions, classes = _collect_models(modules)
    repository = SemanticRepository(discovery_root, modules, functions, classes)
    rounds, converged = repository.solve()

    module_names = set(modules)
    import_edges: list[dict] = []
    import_graph: dict[str, list[str]] = {}
    for name in sorted(modules):
        targets: set[str] = set()
        for item in modules[name].imports:
            target = _resolve_module_target(item["module"], module_names)
            import_edges.append({
                "source": name, "imported": item["module"], "target": target,
                "resolved": bool(target), "path": modules[name].display_path,
                "line": item["line"],
            })
            if target:
                targets.add(target)
        import_graph[name] = sorted(targets)
    import_edges.sort(key=lambda item: (item["source"], item["line"], item["imported"]))

    calls = sorted(
        (row for per_caller in repository.call_sites.values() for row in per_caller.values()),
        key=lambda item: (
        item["caller"], item["path"], item["line"], item["column"], item["callee"]))
    entrypoints = sorted(name for name, model in functions.items() if model.entrypoint)
    reachable = _reachable(entrypoints, calls)
    frontend_rows = run_frontend_checks(files, discovery_root, frontend_timeout) if compiler_checks else []
    findings = _finding_rows(repository)

    function_rows = []
    control_flow = {}
    data_flow = {}
    for qname in sorted(functions):
        model = functions[qname]
        function_rows.append({
            "name": qname, "module": model.module.name, "qualname": model.qualname,
            "path": model.module.display_path, "line": model.node.lineno,
            "end_line": getattr(model.node, "end_lineno", model.node.lineno),
            "kind": "async-function" if isinstance(model.node, ast.AsyncFunctionDef) else
                    ("method" if model.class_qname else "function"),
            "parameters": list(model.parameters), "parameter_types": dict(sorted(model.parameter_types.items())),
            "decorators": list(model.decorators), "routes": list(model.routes),
            "entrypoint": model.entrypoint,
        })
        control_flow[qname] = model.control_flow
        data_flow[qname] = _summary_to_json(repository.summaries[qname], repository)

    class_rows = [{
        "name": name, "module": model.module.name, "path": model.module.display_path,
        "line": model.node.lineno, "bases": list(model.bases),
        "decorators": list(model.decorators),
    } for name, model in sorted(classes.items())]

    statuses = {"failed", "timeout", "error"}
    partial = bool(parse_errors or operational_errors or skipped or not converged or
                   any(row["status"] in statuses for row in frontend_rows))
    status = "error" if not files and operational_errors else ("partial" if partial else "complete")
    return {
        "schema": SCHEMA, "version": VERSION, "root": str(base), "status": status,
        "analysis": {
            "python_frontend": "stdlib-ast", "target_code_executed": False,
            "fixed_point_solver": "dependency-worklist",
            "fixed_point_rounds": rounds, "fixed_point_converged": converged,
            "function_evaluations": repository.function_evaluations,
            "compiler_checks_requested": compiler_checks,
        },
        "metrics": {
            "files_discovered": len(files), "python_modules": len(modules),
            "classes": len(classes), "functions": len(functions),
            "imports": len(import_edges), "calls": len(calls),
            "resolved_calls": sum(1 for call in calls if call["resolved"]),
            "entrypoints": len(entrypoints), "reachable_functions": len(reachable),
            "semantic_findings": len(findings), "parse_errors": len(parse_errors),
            "frontend_checks": len(frontend_rows),
        },
        "files": sorted(file_rows, key=lambda item: item["path"].casefold()),
        "module_graph": {
            "nodes": sorted(modules), "edges": import_edges,
            "cycles": _strongly_connected(import_graph),
        },
        "symbols": {"classes": class_rows, "functions": function_rows},
        "call_graph": {"nodes": sorted(functions), "edges": calls},
        "entrypoints": entrypoints, "reachable_functions": reachable,
        "control_flow": control_flow, "data_flow": data_flow,
        "sources": [repository.sources[key] for key in sorted(repository.sources)],
        "findings": findings, "frontend_checks": frontend_rows,
        "parse_errors": sorted(parse_errors, key=lambda item: (item["path"], item["line"])),
        "operational_errors": sorted(operational_errors, key=lambda item: item["path"]),
        "skipped": sorted(skipped, key=lambda item: (item["path"], item["reason"])),
    }


# Compact aliases for integration surfaces.
analyze = analyze_repository
scan = analyze_repository


def render(report: Mapping[str, object]) -> str:
    metrics = report.get("metrics", {})
    if not isinstance(metrics, Mapping):
        metrics = {}
    lines = [
        "Attestor %s Semantic Analysis" % report.get("version", VERSION),
        "=" * 72,
        "root: %s" % report.get("root", ""),
        "status: %s" % report.get("status", "unknown"),
        "files / Python modules: %s / %s" % (
            metrics.get("files_discovered", 0), metrics.get("python_modules", 0)),
        "functions / resolved calls: %s / %s" % (
            metrics.get("functions", 0), metrics.get("resolved_calls", 0)),
        "entrypoints / reachable: %s / %s" % (
            metrics.get("entrypoints", 0), metrics.get("reachable_functions", 0)),
        "confirmed semantic findings: %s" % metrics.get("semantic_findings", 0),
    ]
    findings = report.get("findings", [])
    if isinstance(findings, list) and findings:
        lines += ["", "source-to-sink evidence:"]
        for finding in findings[:20]:
            if isinstance(finding, Mapping):
                lines.append("  %s:%s %s %s" % (
                    finding.get("path", ""), finding.get("line", 1),
                    finding.get("severity", ""), finding.get("message", "")))
    parse_errors = report.get("parse_errors", [])
    if isinstance(parse_errors, list) and parse_errors:
        lines += ["", "parse errors:"]
        for error in parse_errors[:20]:
            if isinstance(error, Mapping):
                lines.append("  %s:%s %s" % (
                    error.get("path", ""), error.get("line", 1), error.get("message", "")))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", help="repository directory or source file")
    parser.add_argument("--json", action="store_true", help="emit the stable JSON report")
    parser.add_argument("--compiler-checks", action="store_true",
                        help="run installed parser-only multi-language front ends")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--frontend-timeout", type=float, default=DEFAULT_FRONTEND_TIMEOUT)
    args = parser.parse_args(argv)
    report = analyze_repository(
        args.root, compiler_checks=args.compiler_checks, max_files=args.max_files,
        max_bytes=args.max_bytes, frontend_timeout=args.frontend_timeout)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    return 2 if report["status"] == "error" else (1 if report["status"] == "partial" else 0)


if __name__ == "__main__":
    raise SystemExit(main())
