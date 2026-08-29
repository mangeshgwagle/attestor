#!/usr/bin/env python3
"""Deterministic repository semantic graph for Attestor 4.1.3.

Python uses CPython's parser to derive symbols, imports, calls, control-flow-ish
edges, data dependencies, and bounded interprocedural taint witnesses.  The
JavaScript/TypeScript adapter deliberately provides structural lexical evidence
only; it is never described as compiler-grade.  Every adapter and unsupported
language is reported explicitly.  Target code is never imported or executed.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

import analysis_snapshot41 as snapshot41


SCHEMA = "attestor.semantic-graph/4.1"
VERSION = "4.1.3"
MAX_AST_NODES = 250_000
MAX_ITEMS = 50_000
_JS_FUNCTION = re.compile(
    r"(?m)^\s*(?:export\s+)?(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)")
_JS_IMPORT = re.compile(
    r"(?m)^\s*import\s+(?:(.*?)\s+from\s+)?[\"']([^\"']+)[\"']|"
    r"require\s*\(\s*[\"']([^\"']+)[\"']\s*\)")
_JS_CALL = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
_SOURCE_CALLS = frozenset({
    "input", "builtins.input", "request.args.get", "request.form.get",
    "request.get_json", "os.getenv", "os.environ.get", "sys.stdin.read",
    "sys.stdin.readline", "socket.recv",
})
_SINKS = {
    "eval": ("CWE-95", "code"), "builtins.eval": ("CWE-95", "code"),
    "exec": ("CWE-95", "code"), "builtins.exec": ("CWE-95", "code"),
    "os.system": ("CWE-78", "command"), "os.popen": ("CWE-78", "command"),
    "subprocess.run": ("CWE-78", "command"),
    "subprocess.call": ("CWE-78", "command"),
    "subprocess.Popen": ("CWE-78", "command"),
    "pickle.loads": ("CWE-502", "deserialize"),
    "yaml.load": ("CWE-502", "deserialize"),
    "open": ("CWE-22", "path"), "builtins.open": ("CWE-22", "path"),
    "requests.get": ("CWE-918", "url"), "urllib.request.urlopen": ("CWE-918", "url"),
}
# Only transformations that make values unusable as every modeled string sink
# are treated as context-independent.  Shell/HTML/path escaping is deliberately
# not global: applying the wrong escaping discipline must not erase taint.
_SANITIZERS = frozenset({"int", "float", "uuid.UUID"})
_SINK_SANITIZERS = {"path": frozenset({"os.path.basename"})}


class SemanticGraphError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SemanticGraphError("semantic evidence must be JSON data") from exc


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _id(prefix: str, body: Mapping[str, Any]) -> str:
    return prefix + _sha(body)[:24]


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _module_for(path: str) -> str:
    pure = PurePosixPath(path)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _names(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    names = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
    names.update(name for item in ast.walk(node) if isinstance(item, ast.Attribute)
                 for name in [_dotted(item)] if name)
    return sorted(names)


def _calls(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    return sorted({name for item in ast.walk(node) if isinstance(item, ast.Call)
                   for name in [_dotted(item.func)] if name})


def _sources(node: ast.AST | None) -> list[dict[str, Any]]:
    if node is None:
        return []
    rows = []
    for item in ast.walk(node):
        if isinstance(item, ast.Call) and _dotted(item.func) in _SOURCE_CALLS:
            rows.append({"callee": _dotted(item.func), "line": getattr(item, "lineno", 1)})
    return sorted(rows, key=lambda row: (row["line"], row["callee"]))


def _call_sites(node: ast.AST | None) -> list[dict[str, Any]]:
    if node is None:
        return []
    rows = [{"callee": _dotted(item.func), "line": getattr(item, "lineno", 1)}
            for item in ast.walk(node) if isinstance(item, ast.Call) and _dotted(item.func)]
    return sorted(rows, key=lambda row: (row["line"], row["callee"]))


def _outer_call(node: ast.AST | None) -> str:
    return _dotted(node.func) if isinstance(node, ast.Call) else ""


def _absolute_import(module: str, current_module: str, path: str) -> str:
    """Resolve Python's leading-dot import spelling without importing code."""
    if not module.startswith("."):
        return module
    level = len(module) - len(module.lstrip("."))
    suffix = module[level:]
    package = current_module if PurePosixPath(path).name == "__init__.py" \
        else current_module.rpartition(".")[0]
    parts = [part for part in package.split(".") if part]
    if level - 1 > len(parts):
        return ""
    prefix = parts[:len(parts) - (level - 1)] if level > 1 else parts
    return ".".join([*prefix, *([suffix] if suffix else [])])


def _binding_for(facts: Mapping[str, Any], owner: str, name: str) -> str:
    scopes = facts.get("bindings_by_owner", {})
    if isinstance(scopes, Mapping):
        current = owner
        module = str(facts.get("module", ""))
        while current:
            row = scopes.get(current, {})
            if isinstance(row, Mapping) and isinstance(row.get(name), str):
                return str(row[name])
            if current == module or "." not in current:
                break
            current = current.rpartition(".")[0]
    binding = facts.get("bindings", {}).get(name)
    return str(binding) if isinstance(binding, str) else ""


def _bound_callee(callee: str, owner: str, facts: Mapping[str, Any]) -> str:
    first, dot, rest = callee.partition(".")
    binding = _binding_for(facts, owner, first)
    return (binding + (dot + rest if dot else "")) if binding else callee


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.Tuple, ast.List)):
        return sorted({name for part in node.elts for name in _targets(part)})
    name = _dotted(node)
    return [name] if name else []


class _PythonExtractor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.module = _module_for(path)
        self.scope: list[str] = []
        self.symbols: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.assignments: list[dict[str, Any]] = []
        self.returns: list[dict[str, Any]] = []
        self.sinks: list[dict[str, Any]] = []
        self.flow: list[dict[str, Any]] = []
        self.bindings: dict[str, str] = {}
        self.bindings_by_owner: dict[str, dict[str, str]] = {}
        self.call_details: list[dict[str, Any]] = []

    def owner(self) -> str:
        return ".".join([self.module, *self.scope]).strip(".")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            binding = alias.asname or alias.name.split(".")[0]
            resolved_binding = alias.name if alias.asname else alias.name.split(".")[0]
            owner = self.owner()
            self.bindings_by_owner.setdefault(owner, {})[binding] = resolved_binding
            if owner == self.module:
                self.bindings[binding] = resolved_binding
            self.imports.append({"module": alias.name, "resolved_module": alias.name,
                                 "binding": binding, "symbol": "", "owner": owner,
                                 "line": node.lineno})

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = ("." * node.level) + (node.module or "")
        resolved_module = _absolute_import(module, self.module, self.path)
        for alias in node.names:
            binding = alias.asname or alias.name
            resolved_symbol = ".".join(filter(None, (resolved_module, alias.name)))
            owner = self.owner()
            self.bindings_by_owner.setdefault(owner, {})[binding] = resolved_symbol
            if owner == self.module:
                self.bindings[binding] = resolved_symbol
            self.imports.append({"module": module, "resolved_module": resolved_module,
                                 "binding": binding, "symbol": alias.name,
                                 "owner": owner, "line": node.lineno})

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent = self.owner()
        qualified = ".".join([parent, node.name]).strip(".")
        self.symbols.append({"kind": "async-function" if isinstance(node, ast.AsyncFunctionDef)
                             else "function", "name": node.name, "qualified": qualified,
                             "parent": parent, "line": node.lineno,
                             "parameters": [arg.arg for arg in (*node.args.posonlyargs,
                                                                  *node.args.args,
                                                                  *node.args.kwonlyargs)]})
        self._statement_flow(qualified, node.body)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        parent = self.owner()
        qualified = ".".join([parent, node.name]).strip(".")
        self.symbols.append({"kind": "class", "name": node.name,
                             "qualified": qualified, "parent": parent,
                             "line": node.lineno, "parameters": []})
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        callee = _dotted(node.func)
        row = {"owner": self.owner(), "callee": callee, "line": node.lineno}
        self.calls.append(row)
        argument = node.args[0] if node.args else next(
            (keyword.value for keyword in node.keywords if keyword.arg is not None), None)
        self.call_details.append({**row, "argument_names": _names(argument),
                                  "argument_calls": _calls(argument),
                                  "argument_call_sites": _call_sites(argument),
                                  "argument_sources": _sources(argument),
                                  "argument_outer_call": _outer_call(argument)})
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = sorted({name for target in node.targets for name in _targets(target)})
        self._assignment(node, targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._assignment(node, _targets(node.target), node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._assignment(node, _targets(node.target), node.value)
        self.generic_visit(node)

    def _assignment(self, node: ast.AST, targets: list[str], value: ast.AST | None) -> None:
        if targets:
            self.assignments.append({"owner": self.owner(), "line": getattr(node, "lineno", 1),
                                     "targets": targets, "names": _names(value),
                                     "calls": _calls(value), "call_sites": _call_sites(value),
                                     "sources": _sources(value),
                                     "outer_call": _outer_call(value)})

    def visit_Return(self, node: ast.Return) -> None:
        self.returns.append({"owner": self.owner(), "line": node.lineno,
                             "names": _names(node.value), "calls": _calls(node.value),
                             "call_sites": _call_sites(node.value),
                             "sources": _sources(node.value),
                             "outer_call": _outer_call(node.value)})
        self.generic_visit(node)

    def _statement_flow(self, owner: str, body: list[ast.stmt]) -> None:
        for left, right in zip(body, body[1:]):
            self.flow.append({"owner": owner, "from_line": left.lineno,
                              "to_line": right.lineno, "kind": "next"})
        for statement in body:
            branches: list[tuple[str, list[ast.stmt]]] = []
            if isinstance(statement, ast.If):
                branches = [("true", statement.body), ("false", statement.orelse)]
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                branches = [("loop-body", statement.body), ("loop-exit", statement.orelse)]
            elif isinstance(statement, ast.Try):
                branches = [("try", statement.body), ("finally", statement.finalbody)]
            for kind, branch in branches:
                if branch:
                    self.flow.append({"owner": owner, "from_line": statement.lineno,
                                      "to_line": branch[0].lineno, "kind": kind})


def _extract_python(item: snapshot41.SnapshotFile) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    text, replaced = item.text()
    gaps: list[dict[str, Any]] = []
    if replaced:
        gaps.append({"path": item.path, "reason": "invalid-utf8-replaced",
                     "adapter": "python-ast"})
    try:
        tree = ast.parse(text, filename=item.path, type_comments=True)
    except (SyntaxError, ValueError) as exc:
        return {"path": item.path, "language": "python", "module": _module_for(item.path),
                "symbols": [], "imports": [], "calls": [], "assignments": [],
                "returns": [], "sinks": [], "flow": [], "bindings": {},
                "bindings_by_owner": {}}, [
                    {"path": item.path, "reason": "python-parse-error",
                     "line": getattr(exc, "lineno", 1) or 1, "adapter": "python-ast"}]
    count = sum(1 for _ in ast.walk(tree))
    if count > MAX_AST_NODES:
        return {"path": item.path, "language": "python", "module": _module_for(item.path),
                "symbols": [], "imports": [], "calls": [], "assignments": [],
                "returns": [], "sinks": [], "flow": [], "bindings": {},
                "bindings_by_owner": {}}, [
                    {"path": item.path, "reason": "ast-node-budget", "adapter": "python-ast"}]
    visitor = _PythonExtractor(item.path)
    visitor.symbols.append({"kind": "module", "name": visitor.module,
                            "qualified": visitor.module, "parent": "", "line": 1,
                            "parameters": []})
    visitor._statement_flow(visitor.module, tree.body)
    visitor.visit(tree)
    binding_facts = {"module": visitor.module, "bindings": visitor.bindings,
                     "bindings_by_owner": visitor.bindings_by_owner}

    def normalize_expression(row: dict[str, Any], prefix: str = "") -> None:
        owner = row["owner"]
        sites_key = prefix + "call_sites"
        sources_key = prefix + "sources"
        outer_key = prefix + "outer_call"
        sites = row.get(sites_key, [])
        resolved_sites = [{**site, "callee": _bound_callee(site["callee"], owner,
                                                            binding_facts)}
                          for site in sites]
        row[sources_key] = [site for site in resolved_sites
                            if site["callee"] in _SOURCE_CALLS]
        outer = _bound_callee(str(row.get(outer_key, "")), owner, binding_facts)
        row[prefix + "sanitized"] = outer in _SANITIZERS

    for record in [*visitor.assignments, *visitor.returns]:
        normalize_expression(record)
    for detail in visitor.call_details:
        resolved = _bound_callee(detail["callee"], detail["owner"], binding_facts)
        if resolved not in _SINKS:
            continue
        detail["raw_callee"] = detail["callee"]
        detail["callee"] = resolved
        normalize_expression(detail, "argument_")
        visitor.sinks.append(detail)
    result = {name: getattr(visitor, name) for name in
              ("symbols", "imports", "calls", "assignments", "returns", "sinks", "flow")}
    result.update({"path": item.path, "language": "python", "module": visitor.module,
                   "bindings": dict(sorted(visitor.bindings.items())),
                   "bindings_by_owner": {owner: dict(sorted(bindings.items()))
                                         for owner, bindings in
                                         sorted(visitor.bindings_by_owner.items())}})
    return result, gaps


def _extract_js(item: snapshot41.SnapshotFile) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    text, replaced = item.text()
    module = _module_for(item.path)
    symbols = [{"kind": "module", "name": module, "qualified": module,
                "parent": "", "line": 1, "parameters": []}]
    for match in _JS_FUNCTION.finditer(text):
        name = match.group(1) or match.group(2)
        symbols.append({"kind": "function", "name": name,
                        "qualified": module + "." + name, "parent": module,
                        "line": text.count("\n", 0, match.start()) + 1, "parameters": []})
    imports = []
    for match in _JS_IMPORT.finditer(text):
        target = match.group(2) or match.group(3) or ""
        imports.append({"module": target, "binding": "", "symbol": "",
                        "line": text.count("\n", 0, match.start()) + 1})
    calls = [{"owner": module, "callee": match.group(1),
              "line": text.count("\n", 0, match.start()) + 1}
             for match in _JS_CALL.finditer(text)
             if match.group(1) not in {"if", "for", "while", "switch", "function"}]
    result = {"path": item.path, "language": item.language, "module": module,
              "symbols": symbols[:MAX_ITEMS], "imports": imports[:MAX_ITEMS],
              "calls": calls[:MAX_ITEMS], "assignments": [], "returns": [],
              "sinks": [], "flow": [], "bindings": {}, "bindings_by_owner": {}}
    gaps = [{"path": item.path, "reason": "bounded-structural-not-compiler",
             "adapter": "javascript-typescript-structural"}]
    if replaced:
        gaps.append({"path": item.path, "reason": "invalid-utf8-replaced",
                     "adapter": "javascript-typescript-structural"})
    return result, gaps


@dataclass(frozen=True)
class Adapter:
    name: str
    languages: tuple[str, ...]
    level: str
    available: bool
    extractor: Callable[[snapshot41.SnapshotFile], tuple[dict[str, Any], list[dict[str, Any]]]] | None
    cache_token: str = VERSION
    compiler_evidence: Mapping[str, Any] | None = field(default=None, compare=True)
    invokes_compiler: bool = False
    starts_process: bool = False

    @property
    def cache_key(self) -> str:
        return _sha({"name": self.name, "level": self.level,
                     "cache_token": self.cache_token,
                     "compiler_evidence": self.compiler_evidence})


class AdapterRegistry:
    """Closed parser registry; registration is explicit and duplicate-safe."""
    def __init__(self) -> None:
        self._by_language: dict[str, Adapter] = {}

    def register(self, adapter: Adapter) -> None:
        if not adapter.name or not adapter.languages:
            raise SemanticGraphError("adapter name and languages are required")
        if adapter.available and not callable(adapter.extractor):
            raise SemanticGraphError("available adapter requires a callable extractor")
        if (not isinstance(adapter.cache_token, str) or not adapter.cache_token or
                len(adapter.cache_token) > 256):
            raise SemanticGraphError("adapter cache token is invalid")
        if adapter.starts_process and not adapter.invokes_compiler:
            raise SemanticGraphError("process-starting adapter must declare compiler invocation")
        if adapter.level.startswith("compiler-derived") and not adapter.compiler_evidence:
            raise SemanticGraphError("compiler-derived adapters require compiler evidence")
        if adapter.compiler_evidence is not None:
            _canonical(adapter.compiler_evidence)
        for language in adapter.languages:
            if language in self._by_language:
                raise SemanticGraphError(f"adapter already registered for {language}")
            self._by_language[language] = adapter

    def get(self, language: str) -> Adapter | None:
        return self._by_language.get(language)

    def report(self) -> list[dict[str, Any]]:
        unique = {adapter.name: adapter for adapter in self._by_language.values()}
        rows = []
        for item in sorted(unique.values(), key=lambda value: value.name):
            row = {"name": item.name, "languages": list(item.languages),
                   "analysis_level": item.level, "available": item.available,
                   "cache_token_sha256": _sha(item.cache_token),
                   "compiler_invoked": item.invokes_compiler,
                   "process_started": item.starts_process}
            if item.compiler_evidence is not None:
                row["compiler_evidence"] = json.loads(
                    _canonical(item.compiler_evidence).decode("utf-8"))
            rows.append(row)
        return rows


def compiler_js_ts_adapter(
        extractor: Callable[[snapshot41.SnapshotFile],
                            tuple[dict[str, Any], list[dict[str, Any]]]], *,
        compiler: str, compiler_version: str, compiler_sha256: str,
        cache_token: str, invokes_compiler: bool = False,
        starts_process: bool = False) -> Adapter:
    """Describe an explicitly supplied compiler adapter with auditable evidence.

    Attestor does not discover or execute a compiler automatically.  A caller may
    provide compiler-derived facts or an explicitly authorized extractor; its
    invocation/process claims are then reflected in the report contract.
    """
    if (not compiler or not compiler_version or
            not re.fullmatch(r"[0-9a-f]{64}", compiler_sha256)):
        raise SemanticGraphError("compiler name, version, and SHA-256 are required")
    return Adapter(
        "javascript-typescript-compiler", ("javascript", "typescript"),
        "compiler-derived-semantic-facts", True, extractor,
        cache_token=cache_token,
        compiler_evidence={"name": compiler, "version": compiler_version,
                           "binary_sha256": compiler_sha256},
        invokes_compiler=invokes_compiler, starts_process=starts_process)


def default_registry(js_ts_adapter: Adapter | None = None) -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(Adapter("python-ast", ("python",), "compiler-parser-ast", True,
                              _extract_python))
    registry.register(js_ts_adapter or Adapter(
        "javascript-typescript-structural", ("javascript", "typescript"),
        "bounded-structural-lexical", True, _extract_js))
    for language in ("json", "graphql", "protobuf", "sql"):
        registry.register(Adapter(language + "-semantic-unavailable", (language,),
                                  "unavailable-in-semantic-graph", False, None))
    return registry


class SemanticCache:
    """In-memory content cache.  It stores JSON facts, never AST objects or source."""
    def __init__(self) -> None:
        self._entries: dict[str, tuple[str, str, dict[str, Any], list[dict[str, Any]]]] = {}

    def synchronize(self, paths: set[str]) -> list[str]:
        removed = sorted(set(self._entries) - paths)
        for path in removed:
            del self._entries[path]
        return removed

    def lookup(self, path: str, sha256: str, adapter_key: str) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        row = self._entries.get(path)
        if row and row[0] == sha256 and row[1] == adapter_key:
            return json.loads(json.dumps(row[2])), json.loads(json.dumps(row[3]))
        return None

    def store(self, path: str, sha256: str, adapter_key: str, facts: dict[str, Any],
              gaps: list[dict[str, Any]]) -> bool:
        invalidated = (path in self._entries and
                       self._entries[path][:2] != (sha256, adapter_key))
        self._entries[path] = (sha256, adapter_key, json.loads(json.dumps(facts)),
                               json.loads(json.dumps(gaps)))
        return invalidated


def _resolve(callee: str, facts: Mapping[str, Any], known: set[str],
             owner: str = "") -> str:
    if not callee:
        return ""
    candidate = _bound_callee(callee, owner, facts)
    local = str(facts.get("module", "")) + "." + callee
    if candidate in known:
        return candidate
    scoped = (owner + "." + callee) if owner else ""
    if scoped in known:
        return scoped
    if local in known:
        return local
    return candidate


def _validated_facts(value: Any, item: snapshot41.SnapshotFile) -> dict[str, Any]:
    if type(value) is not dict:
        raise SemanticGraphError("adapter facts must be an object")
    encoded = _canonical(value)
    if len(encoded) > 32 * 1024 * 1024:
        raise SemanticGraphError("adapter facts exceed their byte budget")
    facts = json.loads(encoded.decode("utf-8"))
    if facts.get("path") != item.path or facts.get("language") != item.language:
        raise SemanticGraphError("adapter facts do not match the snapshot file")
    if not isinstance(facts.get("module"), str):
        raise SemanticGraphError("adapter module is invalid")
    for key in ("symbols", "imports", "calls", "assignments", "returns", "sinks", "flow"):
        rows = facts.get(key)
        if (not isinstance(rows, list) or len(rows) > MAX_ITEMS or
                any(type(row) is not dict for row in rows)):
            raise SemanticGraphError(f"adapter {key} facts are invalid or oversized")

    def text_field(row: Mapping[str, Any], key: str, *, optional: bool = False) -> None:
        value = row.get(key)
        if optional and value is None:
            return
        if not isinstance(value, str) or len(value) > 4_096 or "\x00" in value:
            raise SemanticGraphError(f"adapter field {key} is invalid")

    def line_field(row: Mapping[str, Any], key: str) -> None:
        value = row.get(key)
        if type(value) is not int or not 1 <= value <= 2_147_483_647:
            raise SemanticGraphError(f"adapter field {key} is invalid")

    def string_list(row: Mapping[str, Any], key: str) -> None:
        value = row.get(key)
        if (not isinstance(value, list) or len(value) > MAX_ITEMS or
                any(not isinstance(part, str) or len(part) > 4_096 for part in value)):
            raise SemanticGraphError(f"adapter field {key} is invalid")

    for row in facts["symbols"]:
        for key in ("kind", "name", "qualified", "parent"):
            text_field(row, key)
        line_field(row, "line")
        string_list(row, "parameters")
    for row in facts["imports"]:
        text_field(row, "module")
        line_field(row, "line")
    for row in facts["calls"]:
        text_field(row, "owner")
        text_field(row, "callee")
        line_field(row, "line")
    for collection in (facts["assignments"], facts["returns"]):
        for row in collection:
            text_field(row, "owner")
            line_field(row, "line")
            string_list(row, "names")
            string_list(row, "calls")
            sources = row.get("sources")
            if (not isinstance(sources, list) or len(sources) > MAX_ITEMS or
                    any(type(source) is not dict or
                        not isinstance(source.get("callee"), str) or
                        type(source.get("line")) is not int for source in sources)):
                raise SemanticGraphError("adapter source facts are invalid")
    for row in facts["assignments"]:
        string_list(row, "targets")
    for row in facts["sinks"]:
        text_field(row, "owner")
        text_field(row, "callee")
        line_field(row, "line")
        for key in ("argument_names", "argument_calls"):
            string_list(row, key)
        sources = row.get("argument_sources")
        if (not isinstance(sources, list) or len(sources) > MAX_ITEMS or
                any(type(source) is not dict or
                    not isinstance(source.get("callee"), str) or
                    type(source.get("line")) is not int for source in sources)):
            raise SemanticGraphError("adapter sink source facts are invalid")
    for row in facts["flow"]:
        text_field(row, "owner")
        text_field(row, "kind")
        line_field(row, "from_line")
        line_field(row, "to_line")
    bindings = facts.get("bindings")
    if (not isinstance(bindings, dict) or len(bindings) > MAX_ITEMS or
            any(not isinstance(key, str) or not isinstance(bound, str)
                for key, bound in bindings.items())):
        raise SemanticGraphError("adapter bindings are invalid or oversized")
    scoped = facts.get("bindings_by_owner")
    if (not isinstance(scoped, dict) or len(scoped) > MAX_ITEMS or
            any(not isinstance(owner, str) or not isinstance(bound, dict) or
                len(bound) > MAX_ITEMS or
                any(not isinstance(key, str) or not isinstance(target, str)
                    for key, target in bound.items())
                for owner, bound in scoped.items())):
        raise SemanticGraphError("adapter scoped bindings are invalid or oversized")
    return facts


def _public_row(prefix: str, row: dict[str, Any]) -> dict[str, Any]:
    body = dict(row)
    return {"id": _id(prefix, body), **body}


def build(snapshot: snapshot41.SourceSnapshot | str | Path, *,
          cache: SemanticCache | None = None,
          registry: AdapterRegistry | None = None,
          max_nodes: int | None = None) -> dict[str, Any]:
    """Build a deterministic graph over an immutable snapshot.

    ``max_nodes`` is an optional global ceiling over the public graph
    collections.  The ceiling is enforced before a row is constructed or
    appended, so a selected profile cannot first materialize an oversized graph
    and only reject it afterwards.  Omissions are retained as an explicit
    coverage gap.  ``None`` preserves the historical per-collection behavior.
    """
    if (max_nodes is not None and
            (type(max_nodes) is not int or
             not 1 <= max_nodes <= MAX_AST_NODES)):
        raise SemanticGraphError(
            f"max_nodes must be an integer between 1 and {MAX_AST_NODES}")
    if not isinstance(snapshot, snapshot41.SourceSnapshot):
        snapshot = snapshot41.capture(snapshot)
    registry = registry or default_registry()
    cache = cache or SemanticCache()
    extracted: list[dict[str, Any]] = []
    gaps = [dict(row) for row in snapshot.gaps]
    hits: list[str] = []
    misses: list[str] = []
    invalidated: list[str] = []
    removed = cache.synchronize({item.path for item in snapshot.files})
    used_adapters: dict[str, Adapter] = {}
    for item in snapshot.files:
        adapter = registry.get(item.language)
        if adapter is None:
            gaps.append({"path": item.path, "reason": "semantic-language-unsupported",
                         "language": item.language})
            continue
        used_adapters[adapter.name] = adapter
        if not adapter.available or adapter.extractor is None:
            gaps.append({"path": item.path, "reason": "semantic-adapter-unavailable",
                         "language": item.language, "adapter": adapter.name})
            continue
        cached = cache.lookup(item.path, item.sha256, adapter.cache_key)
        if cached is not None:
            facts, local_gaps = cached
            hits.append(item.path)
        else:
            try:
                raw_facts, local_gaps = adapter.extractor(item)
                facts = _validated_facts(raw_facts, item)
                facts["_adapter_level"] = adapter.level
                facts["_adapter_name"] = adapter.name
                if (not isinstance(local_gaps, list) or len(local_gaps) > MAX_ITEMS or
                        any(type(row) is not dict for row in local_gaps)):
                    raise SemanticGraphError("adapter gaps are invalid or oversized")
                local_gaps = json.loads(_canonical(local_gaps).decode("utf-8"))
                if any(not isinstance(row.get("reason"), str) or
                       not isinstance(row.get("path", ""), str) or
                       ("line" in row and type(row["line"]) is not int)
                       for row in local_gaps):
                    raise SemanticGraphError("adapter gap fields are invalid")
            except Exception as exc:
                gaps.append({"path": item.path, "reason": "semantic-adapter-failed-closed",
                             "adapter": adapter.name, "error_type": type(exc).__name__})
                misses.append(item.path)
                continue
            if cache.store(item.path, item.sha256, adapter.cache_key, facts, local_gaps):
                invalidated.append(item.path)
            misses.append(item.path)
        extracted.append(facts)
        gaps.extend(local_gaps)

    known = {row["qualified"] for facts in extracted for row in facts["symbols"]
             if row["kind"] in {"function", "async-function"}}
    by_module = {facts["module"]: facts for facts in extracted}
    symbols: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    flow: list[dict[str, Any]] = []
    data: list[dict[str, Any]] = []
    graph_node_count = 0
    graph_node_budget_reached = False

    def append_graph_row(
            collection: list[dict[str, Any]], prefix: str,
            row: dict[str, Any]) -> bool:
        nonlocal graph_node_count, graph_node_budget_reached
        if max_nodes is not None and graph_node_count >= max_nodes:
            graph_node_budget_reached = True
            return False
        collection.append(_public_row(prefix, row))
        graph_node_count += 1
        return True

    data_budget_reached = False
    for facts in extracted:
        if graph_node_budget_reached:
            break
        path = facts["path"]
        parser_level = str(facts.get("_adapter_level", "unknown"))
        semantic_precision = ("parser-derived" if facts["language"] == "python" else
                              "compiler-derived" if "compiler" in parser_level else
                              "bounded-structural")
        for row in facts["symbols"]:
            if not append_graph_row(
                    symbols, "sg41-sym-",
                    {"path": path, **row,
                     "analysis_level": semantic_precision}):
                break
        if graph_node_budget_reached:
            break
        for row in facts["imports"]:
            target = row["module"]
            resolved_module = row.get("resolved_module", target.lstrip("."))
            resolved_path = by_module.get(resolved_module, {}).get("path", "")
            if not append_graph_row(
                    imports, "sg41-imp-",
                    {"path": path, **row,
                     "resolved_path": resolved_path,
                     "precision": semantic_precision}):
                break
        if graph_node_budget_reached:
            break
        for row in facts["calls"]:
            resolved = _resolve(row["callee"], facts, known, row.get("owner", ""))
            if not append_graph_row(
                    calls, "sg41-call-",
                    {"path": path, **row, "resolved": resolved,
                     "precision": semantic_precision}):
                break
        if graph_node_budget_reached:
            break
        for row in facts["flow"]:
            if not append_graph_row(
                    flow, "sg41-cfg-",
                    {"path": path, **row,
                     "precision": "cfg-ish-conservative"}):
                break
        if graph_node_budget_reached:
            break
        if data_budget_reached:
            continue
        for row in facts["assignments"]:
            for target in row["targets"]:
                for source in row["names"]:
                    if len(data) >= MAX_ITEMS:
                        data_budget_reached = True
                        break
                    if not append_graph_row(
                            data, "sg41-data-",
                            {"path": path, "owner": row["owner"],
                             "line": row["line"], "target": target,
                             "depends_on": source,
                             "precision": "ast-name-dependency"}):
                        break
                if data_budget_reached or graph_node_budget_reached:
                    break
            if data_budget_reached or graph_node_budget_reached:
                break

    if data_budget_reached:
        gaps.append({"path": "", "reason": "graph-item-budget"})

    # Build summaries and witnesses in lexical statement order.  The analysis
    # remains path-insensitive (reported below), but a later reassignment can no
    # longer erase or invent taint at an earlier sink.
    origins: dict[str, dict[str, Any]] = {}

    def expression_origin(facts: Mapping[str, Any], row: Mapping[str, Any],
                          env: Mapping[str, dict[str, Any]], *,
                          prefix: str = "") -> dict[str, Any] | None:
        owner = str(row.get("owner", ""))
        if row.get(prefix + "sanitized"):
            return None
        sources = row.get(prefix + "sources", [])
        if sources:
            source = sources[0]
            return {"path": facts["path"], "line": source["line"],
                    "callee": source["callee"], "function": owner}
        for callee in row.get(prefix + "calls", []):
            resolved = _resolve(str(callee), facts, known, owner)
            if resolved in origins and resolved not in _SANITIZERS:
                result = dict(origins[resolved])
                result["propagation_call"] = {
                    "path": facts["path"], "line": int(row.get("line", 1)),
                    "callee": resolved}
                return result
        for name in row.get(prefix + "names", []):
            if name in env:
                return dict(env[name])
        return None

    def environment_before(facts: Mapping[str, Any], owner: str, line: int) -> dict[str, dict[str, Any]]:
        env: dict[str, dict[str, Any]] = {}
        assignments = sorted((row for row in facts["assignments"]
                              if row["owner"] == owner and row["line"] < line),
                             key=lambda row: row["line"])
        for assignment in assignments:
            origin = expression_origin(facts, assignment, env)
            for target in assignment["targets"]:
                if origin is None:
                    env.pop(target, None)
                else:
                    env[target] = dict(origin)
        return env

    returns_by_owner: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for facts in extracted:
        for row in facts["returns"]:
            returns_by_owner.setdefault(row["owner"], []).append((facts, row))
    # At most one new function summary is added per pass; the hard bound avoids
    # malformed adapter facts creating an unbounded fixed point.
    for _ in range(len(returns_by_owner) + 1):
        changed = False
        for owner in sorted(returns_by_owner):
            if owner in origins:
                continue
            for facts, row in sorted(returns_by_owner[owner],
                                     key=lambda pair: (pair[0]["path"], pair[1]["line"])):
                env = environment_before(facts, owner, row["line"])
                origin = expression_origin(facts, row, env)
                if origin is not None:
                    origin["via_function"] = owner
                    origins[owner] = origin
                    changed = True
                    break
        if not changed:
            break

    taint: list[dict[str, Any]] = []
    for facts in extracted:
        if graph_node_budget_reached:
            break
        owners = sorted({row["owner"] for row in [*facts["assignments"], *facts["sinks"]]})
        for owner in owners:
            if graph_node_budget_reached:
                break
            env: dict[str, dict[str, Any]] = {}
            events = [(row["line"], 0, row) for row in facts["assignments"]
                      if row["owner"] == owner]
            events += [(row["line"], 1, row) for row in facts["sinks"]
                       if row["owner"] == owner]
            for _line_no, kind, row in sorted(events, key=lambda event: (event[0], event[1])):
                if kind == 0:
                    origin = expression_origin(facts, row, env)
                    for target in row["targets"]:
                        if origin is None:
                            env.pop(target, None)
                        else:
                            env[target] = dict(origin)
                    continue
                cwe, context = _SINKS[row["callee"]]
                outer = _bound_callee(str(row.get("argument_outer_call", "")), owner, facts)
                if row.get("argument_sanitized") or outer in _SINK_SANITIZERS.get(context, ()):
                    continue
                origin = expression_origin(facts, row, env, prefix="argument_")
                if origin is None:
                    continue
                witness = {"source": origin, "sink": {"path": facts["path"],
                           "line": row["line"], "callee": row["callee"]},
                           "context": context, "cwe": cwe,
                           "cross_file": origin["path"] != facts["path"],
                           "precision": "bounded-parser-derived-source-to-sink"}
                if not append_graph_row(taint, "sg41-taint-", witness):
                    break

    if graph_node_budget_reached:
        gaps.append({
            "path": "",
            "reason": "selected-graph-node-budget",
            "limit": max_nodes,
            "constructed_nodes": graph_node_count,
        })

    for facts in extracted:
        if facts["language"] == "python" and any(row.get("parameters") for row in facts["symbols"]):
            gaps.append({"path": facts["path"], "reason": "parameter-taint-not-fully-interprocedural",
                         "adapter": "python-ast"})
        if facts["language"] == "python" and any(row.get("kind") != "next"
                                                   for row in facts["flow"]):
            gaps.append({"path": facts["path"],
                         "reason": "control-flow-path-merge-is-conservative",
                         "adapter": "python-ast"})
    sort_key = lambda row: (row.get("path", ""), row.get("line", row.get("from_line", 0)), row["id"])
    for collection in (symbols, imports, calls, flow, data, taint):
        collection.sort(key=sort_key)
        if len(collection) > MAX_ITEMS:
            del collection[MAX_ITEMS:]
            gaps.append({"path": "", "reason": "graph-item-budget"})
    gaps = sorted({json.dumps(row, sort_keys=True): row for row in gaps}.values(),
                  key=lambda row: (row.get("path", ""), row.get("reason", ""),
                                   row.get("line", 0)))
    body = {
        "schema": SCHEMA, "version": VERSION,
        "analysis_level": "mixed-parser-semantic-and-explicit-bounded-structural",
        "snapshot_sha256": snapshot.snapshot_sha256,
        "adapters": registry.report(),
        "graph": {"symbols": symbols, "imports": imports, "calls": calls,
                  "control_flow": flow, "data_flow": data,
                  "taint_witnesses": taint},
        "cache": {"identity_basis": "path+content-sha256+adapter-evidence-digest",
                  "hits": sorted(hits), "misses": sorted(misses),
                  "invalidated": sorted(invalidated), "removed": removed},
        "coverage": {"complete": not gaps, "gaps": gaps},
        "static_contract": {"target_code_executed": False,
                            "target_modules_imported": False,
                            "compiler_invoked": any(item.invokes_compiler
                                                    for item in used_adapters.values()),
                            "processes_started": any(item.starts_process
                                                     for item in used_adapters.values()),
                            "network_accessed": False, "filesystem_writes": False},
    }
    body["graph_sha256"] = _sha(body["graph"])
    body["report_sha256"] = _sha(body)
    return body


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["report is not a JSON object"]
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        errors.append("unsupported semantic graph schema or version")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        if report.get("report_sha256") != _sha(body):
            errors.append("report digest mismatch")
        if report.get("graph_sha256") != _sha(report.get("graph")):
            errors.append("graph digest mismatch")
    except SemanticGraphError:
        errors.append("report is not canonical JSON")
    return not errors, errors


analyze = build
build_semantic_graph = build
