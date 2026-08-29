#!/usr/bin/env python3
"""Bounded, evidence-producing Python symbolic analysis for Attestor 3.5.

This module deliberately does *not* import or execute target programs.  It uses
Python's ``ast`` parser and a small abstract interpreter whose states are
immutable.  The interpreter is path-sensitive, tracks fields/subscripts through
abstract heap identities, propagates taint through unresolved calls, and marks
every resource or precision limit in its public report.

Public API:

``analyze_source(source, filename="memory.py", **limits)``
    Analyze an in-memory Python source string.

``analyze_repository(root, **limits)``
    Read and analyze Python source files beneath ``root`` without following
    symbolic links or writing any files.

The returned dictionaries contain only JSON-shaped values and are stable for
the same source and options.
"""
from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Sequence


VERSION = "3.5.0"
SCHEMA = "attestor.symbolic-analysis/3.5"
DEFAULT_MAX_FILES = 2_000
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_STATES = 128
DEFAULT_0 = 50_000
DEFAULT_MAX_LOOP_ITERATIONS = 4
DEFAULT_MAX_CALL_DEPTH = 6
DEFAULT_MAX_CALL_CONTEXTS = 32
DEFAULT_MAX_ATOMS = 64
DEFAULT_MAX_OBJECT_FIELDS = 128
DEFAULT_MAX_EVIDENCE_STEPS = 24
DEFAULT_MAX_FINDINGS = 1_000

SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "node_modules", "vendor",
    "dist", "build", "target", ".next", "coverage", "bin", "obj",
}

# context, CWE, severity, tainted positional arguments, remediation
SINKS: dict[str, tuple[str, str, str, tuple[int, ...], str]] = {
    "eval": ("code", "CWE-95", "CRITICAL", (0,), "Remove eval; parse a strict data format."),
    "builtins.eval": ("code", "CWE-95", "CRITICAL", (0,), "Remove eval; parse a strict data format."),
    "exec": ("code", "CWE-95", "CRITICAL", (0,), "Replace dynamic code with allowlisted operations."),
    "builtins.exec": ("code", "CWE-95", "CRITICAL", (0,), "Replace dynamic code with allowlisted operations."),
    "os.system": ("command", "CWE-78", "CRITICAL", (0,), "Use a fixed executable and shell=False."),
    "os.popen": ("command", "CWE-78", "CRITICAL", (0,), "Use an argument vector and shell=False."),
    "subprocess.run": ("command", "CWE-78", "HIGH", (0,), "Use a fixed executable and shell=False."),
    "subprocess.call": ("command", "CWE-78", "HIGH", (0,), "Use a fixed executable and shell=False."),
    "subprocess.Popen": ("command", "CWE-78", "CRITICAL", (0,), "Use a fixed executable and shell=False."),
    "subprocess.check_call": ("command", "CWE-78", "HIGH", (0,), "Use a fixed executable and shell=False."),
    "subprocess.check_output": ("command", "CWE-78", "HIGH", (0,), "Use a fixed executable and shell=False."),
    "pickle.loads": ("deserialize", "CWE-502", "CRITICAL", (0,), "Use a non-executable data format."),
    "pickle.load": ("deserialize", "CWE-502", "CRITICAL", (0,), "Use a non-executable data format."),
    "marshal.loads": ("deserialize", "CWE-502", "HIGH", (0,), "Do not deserialize untrusted marshal data."),
    "yaml.load": ("deserialize", "CWE-502", "HIGH", (0,), "Use yaml.safe_load."),
    "render_template_string": ("template", "CWE-1336", "HIGH", (0,), "Render a fixed template."),
    "flask.render_template_string": ("template", "CWE-1336", "HIGH", (0,), "Render a fixed template."),
    "requests.get": ("url", "CWE-918", "HIGH", (0,), "Allowlist destination schemes and hosts."),
    "requests.post": ("url", "CWE-918", "HIGH", (0,), "Allowlist destination schemes and hosts."),
    "urllib.request.urlopen": ("url", "CWE-918", "HIGH", (0,), "Allowlist destination schemes and hosts."),
    "open": ("path", "CWE-22", "HIGH", (0,), "Resolve beneath an approved root."),
    "builtins.open": ("path", "CWE-22", "HIGH", (0,), "Resolve beneath an approved root."),
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
    "os.environ.get": "environment",
}
SOURCE_PREFIXES = {
    "request.args": "http.query", "flask.request.args": "http.query",
    "request.form": "http.form", "flask.request.form": "http.form",
    "request.values": "http.value", "request.json": "http.json",
    "request.headers": "http.header", "request.cookies": "http.cookie",
    "request.files": "http.file", "request.data": "http.body",
    "request.body": "http.body", "request.GET": "http.query",
    "request.POST": "http.form", "sys.argv": "command-line",
    "os.environ": "environment",
}
SANITIZERS = {
    "int": {"all"}, "builtins.int": {"all"},
    "float": {"all"}, "builtins.float": {"all"},
    "uuid.UUID": {"all"}, "shlex.quote": {"command"},
    "html.escape": {"html"}, "markupsafe.escape": {"html"},
    "bleach.clean": {"html"}, "werkzeug.utils.secure_filename": {"path"},
    "os.path.basename": {"path"}, "yaml.safe_load": {"deserialize"},
}
SAFE_PROPAGATORS = {
    "str", "bytes", "repr", "json.dumps", "json.loads", "copy.copy",
    "copy.deepcopy", "urllib.parse.unquote", "urllib.parse.unquote_plus",
}
SAFE_METHOD_PROPAGATORS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "replace",
    "format", "join", "encode", "decode", "split", "rsplit",
}
ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_route"}


def _hash(*parts: object) -> str:
    raw = "\x1f".join(str(part) for part in parts).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _literal(value: object) -> str:
    """Typed, sortable encoding for bounded scalar constants."""
    if value is None:
        return "none:"
    if isinstance(value, bool):
        return "bool:" + ("true" if value else "false")
    if isinstance(value, str):
        return "str:" + value
    if isinstance(value, int):
        return "int:" + str(value)
    if isinstance(value, float):
        return "float:" + repr(value)
    if isinstance(value, bytes):
        return "bytes:" + value.hex()
    return ""


def _literal_node(node: ast.AST | None) -> str:
    return _literal(node.value) if isinstance(node, ast.Constant) else ""


def _display_literal(encoded: str) -> str:
    kind, _, value = encoded.partition(":")
    if kind == "str":
        return repr(value)
    return value or kind


@dataclass(frozen=True, order=True)
class EvidenceStep:
    kind: str
    path: str
    line: int
    column: int
    detail: str
    symbol: str = ""

    def public(self) -> dict:
        row = {
            "kind": self.kind, "path": self.path, "line": self.line,
            "column": self.column, "detail": self.detail,
        }
        if self.symbol:
            row["symbol"] = self.symbol
        return row


@dataclass(frozen=True, order=True)
class Atom:
    source_id: str
    source_kind: str
    path: str
    line: int
    column: int
    symbol: str
    sanitizers: tuple[str, ...] = ()
    trace: tuple[EvidenceStep, ...] = ()

    def safe_for(self, context: str) -> bool:
        return "all" in self.sanitizers or context in self.sanitizers


@dataclass(frozen=True, order=True)
class Value:
    atoms: tuple[Atom, ...] = ()
    objects: tuple[str, ...] = ()
    constants: tuple[str, ...] = ()
    unknown: bool = False


EMPTY = Value()


@dataclass(frozen=True, order=True)
class AbstractObject:
    fields: tuple[tuple[str, Value], ...] = ()
    unknown_field: Value = EMPTY
    open: bool = False


@dataclass(frozen=True)
class SymbolicState:
    """An immutable CFG state; ``versions`` are SSA-like assignment indices."""

    env: tuple[tuple[str, Value], ...] = ()
    heap: tuple[tuple[str, AbstractObject], ...] = ()
    versions: tuple[tuple[str, int], ...] = ()
    predicates: tuple[str, ...] = ()
    control: str = "normal"
    return_value: Value = EMPTY


@dataclass(frozen=True)
class Limits:
    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_states: int = DEFAULT_MAX_STATES
    max_steps: int = DEFAULT_0
    max_loop_iterations: int = DEFAULT_MAX_LOOP_ITERATIONS
    max_call_depth: int = DEFAULT_MAX_CALL_DEPTH
    max_call_contexts: int = DEFAULT_MAX_CALL_CONTEXTS
    max_atoms: int = DEFAULT_MAX_ATOMS
    max_object_fields: int = DEFAULT_MAX_OBJECT_FIELDS
    max_evidence_steps: int = DEFAULT_MAX_EVIDENCE_STEPS
    max_findings: int = DEFAULT_MAX_FINDINGS

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if not isinstance(value, int) or value < 1:
                raise ValueError("%s must be a positive integer" % name)

    def public(self) -> dict:
        return dict(sorted(self.__dict__.items()))


@dataclass
class Module:
    name: str
    path: str
    tree: ast.Module
    aliases: dict[str, str] = field(default_factory=dict)
    functions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Function:
    qname: str
    module: str
    path: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    parameters: tuple[str, ...]
    route: bool


def _map(items: tuple[tuple[str, object], ...]) -> dict:
    return dict(items)


class SymbolicRepository:
    def __init__(self, modules: Sequence[Module], limits: Limits) -> None:
        self.modules = {module.name: module for module in modules}
        self.limits = limits
        self.functions: dict[str, Function] = {}
        self.short_functions: dict[str, list[str]] = {}
        self.module_globals: dict[str, dict[str, Value]] = {}
        self.module_heaps: dict[str, tuple[tuple[str, AbstractObject], ...]] = {}
        self.findings: dict[str, dict] = {}
        self.limit_hits: set[str] = set()
        self.coverage_gaps: set[str] = set()
        self.steps = 0
        self.states_created = 0
        self.peak_states = 0
        self.loop_widenings = 0
        self.unknown_calls = 0
        self.contexts: dict[str, set[str]] = {}
        self.functions_analyzed: set[str] = set()
        self._index()

    def _index(self) -> None:
        for module in sorted(self.modules.values(), key=lambda item: item.name):
            self._index_imports(module)
            self._index_globals(module)
            for node in module.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qname = module.name + "." + node.name
                    decorators = {_dotted(item.func if isinstance(item, ast.Call) else item)
                                  for item in node.decorator_list}
                    route = any(name.rsplit(".", 1)[-1] in ROUTE_DECORATORS
                                for name in decorators)
                    parameters = tuple(
                        arg.arg for arg in (
                            list(node.args.posonlyargs) + list(node.args.args) +
                            list(node.args.kwonlyargs)
                        )
                    )
                    self.functions[qname] = Function(
                        qname, module.name, module.path, node, parameters, route)
                    self.short_functions.setdefault(node.name, []).append(qname)
                    module.functions.append(qname)
        for names in self.short_functions.values():
            names.sort()

    def _static_value(self, module: Module, node: ast.AST,
                      env: Mapping[str, Value], heap: dict[str, AbstractObject]) -> tuple[Value, bool]:
        """Extract literal global data without evaluating target expressions."""
        if isinstance(node, ast.Constant):
            literal = _literal(node.value)
            return self.value(constants=(literal,) if literal else ()), bool(literal)
        if isinstance(node, ast.Name) and node.id in env:
            return env[node.id], True
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values: list[Value] = []
            fields: list[tuple[str, Value]] = []
            for index, child in enumerate(node.elts):
                value, supported = self._static_value(module, child, env, heap)
                if not supported:
                    return EMPTY, False
                values.append(value)
                fields.append(("index:%d" % index, value))
            if len(fields) > self.limits.max_object_fields:
                self.limit_hits.add("max_object_fields")
                fields = fields[:self.limits.max_object_fields]
            obj_id = "global:%s:%d:%d" % (
                module.path, getattr(node, "lineno", 1), getattr(node, "col_offset", 0))
            heap[obj_id] = AbstractObject(tuple(fields))
            constants = [constant for value in values for constant in value.constants]
            return self.value(objects=(obj_id,), constants=constants), True
        if isinstance(node, ast.Dict):
            fields: list[tuple[str, Value]] = []
            for key_node, value_node in zip(node.keys, node.values):
                literal = _literal_node(key_node)
                if not literal:
                    return EMPTY, False
                value, supported = self._static_value(module, value_node, env, heap)
                if not supported:
                    return EMPTY, False
                fields.append(("key:" + literal, value))
            if len(fields) > self.limits.max_object_fields:
                self.limit_hits.add("max_object_fields")
                fields = fields[:self.limits.max_object_fields]
            obj_id = "global:%s:%d:%d" % (
                module.path, getattr(node, "lineno", 1), getattr(node, "col_offset", 0))
            heap[obj_id] = AbstractObject(tuple(sorted(fields)))
            return self.value(objects=(obj_id,),
                              constants=(key[len("key:"):] for key, _ in fields)), True
        return EMPTY, False

    def _index_globals(self, module: Module) -> None:
        env: dict[str, Value] = {}
        heap: dict[str, AbstractObject] = {}
        for node in module.tree.body:
            target: ast.AST | None = None
            value_node: ast.AST | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value_node = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value_node = node.target, node.value
            if target is not None and value_node is not None:
                value, supported = self._static_value(module, value_node, env, heap)
                if supported and isinstance(target, ast.Name):
                    env[target.id] = value
                else:
                    self.coverage_gaps.add("dynamic module-level assignment not modeled")
            elif isinstance(node, ast.ClassDef):
                self.coverage_gaps.add("class and method bodies not indexed")
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                continue  # module docstring or inert literal
            elif not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                       ast.Import, ast.ImportFrom)):
                self.coverage_gaps.add("module-level executable flow not modeled")
        self.module_globals[module.name] = env
        self.module_heaps[module.name] = tuple(sorted(heap.items()))

    @staticmethod
    def _index_imports(module: Module) -> None:
        for node in module.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module.aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    if module.name == "__root__":
                        parts = []
                    elif Path(module.path).name == "__init__.py":
                        parts = module.name.split(".")
                    else:
                        parts = module.name.split(".")[:-1]
                    keep = max(0, len(parts) - node.level + 1)
                    prefix = ".".join(parts[:keep])
                    base = ".".join(item for item in (prefix, base) if item)
                for alias in node.names:
                    if alias.name != "*":
                        target = ".".join(item for item in (base, alias.name) if item)
                        module.aliases[alias.asname or alias.name] = target

    def tick(self) -> bool:
        self.steps += 1
        if self.steps > self.limits.max_steps:
            self.limit_hits.add("max_steps")
            return False
        return True

    def append_step(self, atom: Atom, step: EvidenceStep) -> Atom:
        trace = atom.trace
        if not trace or trace[-1] != step:
            trace = trace + (step,)
        if len(trace) > self.limits.max_evidence_steps:
            self.limit_hits.add("max_evidence_steps")
            trace = trace[:self.limits.max_evidence_steps - 1] + (
                EvidenceStep("limit", step.path, step.line, step.column,
                             "witness truncated at evidence-step limit"),)
        return Atom(atom.source_id, atom.source_kind, atom.path, atom.line,
                    atom.column, atom.symbol, atom.sanitizers, trace)

    def value(self, *, atoms: Iterable[Atom] = (), objects: Iterable[str] = (),
              constants: Iterable[str] = (), unknown: bool = False) -> Value:
        unique_atoms = sorted(set(atoms), key=lambda item: (len(item.trace), item))
        if len(unique_atoms) > self.limits.max_atoms:
            self.limit_hits.add("max_atoms")
            unique_atoms = unique_atoms[:self.limits.max_atoms]
        return Value(tuple(unique_atoms), tuple(sorted(set(objects))),
                     tuple(sorted(set(constants))), bool(unknown))

    def join_values(self, *values: Value) -> Value:
        return self.value(
            atoms=(atom for value in values for atom in value.atoms),
            objects=(obj for value in values for obj in value.objects),
            constants=(constant for value in values for constant in value.constants),
            unknown=any(value.unknown for value in values),
        )

    def transform(self, value: Value, step: EvidenceStep) -> Value:
        return self.value(atoms=(self.append_step(atom, step) for atom in value.atoms),
                          objects=value.objects, constants=value.constants,
                          unknown=value.unknown)

    def sanitize(self, value: Value, contexts: Iterable[str], step: EvidenceStep) -> Value:
        added = set(contexts)
        atoms = []
        for atom in value.atoms:
            changed = Atom(atom.source_id, atom.source_kind, atom.path, atom.line,
                           atom.column, atom.symbol,
                           tuple(sorted(set(atom.sanitizers) | added)), atom.trace)
            atoms.append(self.append_step(changed, step))
        return self.value(atoms=atoms, objects=value.objects,
                          constants=value.constants, unknown=value.unknown)

    def source(self, function: Function, node: ast.AST, kind: str, symbol: str) -> Value:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0)
        source_id = "source:" + _hash(function.path, line, column, kind, symbol)[:24]
        step = EvidenceStep("source", function.path, line, column,
                            "untrusted input enters the symbolic state", symbol)
        atom = Atom(source_id, kind, function.path, line, column, symbol, (), (step,))
        return self.value(atoms=(atom,), unknown=True)

    def canonical(self, module_name: str, raw: str) -> str:
        if not raw:
            return ""
        head, dot, tail = raw.partition(".")
        alias = self.modules[module_name].aliases.get(head)
        return alias + (("." + tail) if dot else "") if alias else raw

    def resolve_function(self, module_name: str, raw: str) -> str:
        canonical = self.canonical(module_name, raw)
        for candidate in (canonical, module_name + "." + raw):
            if candidate in self.functions:
                return candidate
        if "." not in raw and len(self.short_functions.get(raw, ())) == 1:
            return self.short_functions[raw][0]
        return ""

    def cap_states(self, states: Iterable[SymbolicState]) -> list[SymbolicState]:
        rows = sorted(set(states), key=self.state_key)
        self.states_created += len(rows)
        self.peak_states = max(self.peak_states, len(rows))
        if len(rows) <= self.limits.max_states:
            return rows
        self.limit_hits.add("max_states")
        return [self.join_states(rows)]

    @staticmethod
    def state_key(state: SymbolicState) -> str:
        return repr(state)

    def join_states(self, states: Sequence[SymbolicState]) -> SymbolicState:
        if not states:
            return SymbolicState()
        envs = [_map(state.env) for state in states]
        heaps = [_map(state.heap) for state in states]
        versions = [_map(state.versions) for state in states]
        env = []
        for name in sorted(set().union(*(row.keys() for row in envs))):
            env.append((name, self.join_values(*(row.get(name, EMPTY) for row in envs))))
        heap = []
        for obj_id in sorted(set().union(*(row.keys() for row in heaps))):
            objects = [row[obj_id] for row in heaps if obj_id in row]
            field_maps = [_map(obj.fields) for obj in objects]
            fields = []
            for key in sorted(set().union(*(row.keys() for row in field_maps))):
                fields.append((key, self.join_values(
                    *(row.get(key, EMPTY) for row in field_maps))))
            heap.append((obj_id, AbstractObject(
                tuple(fields),
                self.join_values(*(obj.unknown_field for obj in objects)),
                any(obj.open for obj in objects),
            )))
        common_predicates = set(states[0].predicates)
        for state in states[1:]:
            common_predicates.intersection_update(state.predicates)
        control = states[0].control if all(s.control == states[0].control for s in states) else "normal"
        returns = self.join_values(*(state.return_value for state in states))
        version_rows = tuple((name, max(row.get(name, 0) for row in versions))
                             for name in sorted(set().union(*(row.keys() for row in versions))))
        return SymbolicState(tuple(env), tuple(heap), version_rows,
                             tuple(sorted(common_predicates)), control, returns)

    def record_sink(self, function: Function, state: SymbolicState, node: ast.Call,
                    sink: str, spec: tuple[str, str, str, tuple[int, ...], str],
                    value: Value) -> None:
        context, cwe, severity, _positions, remediation = spec
        for atom in value.atoms:
            if atom.safe_for(context):
                continue
            if len(self.findings) >= self.limits.max_findings:
                self.limit_hits.add("max_findings")
                return
            line = getattr(node, "lineno", 1)
            column = getattr(node, "col_offset", 0)
            sink_step = EvidenceStep("sink", function.path, line, column,
                                     "untrusted value reaches %s" % sink, sink)
            witness = atom.trace + (sink_step,)
            fingerprint = _hash("symbolic35", atom.source_id, function.path,
                                line, column, sink, context, state.predicates)
            finding = {
                "rule": "symbolic-taint/" + context,
                "severity": severity,
                "cwe": cwe,
                "message": "%s input can reach %s" % (atom.source_kind, sink),
                "path": function.path,
                "line": line,
                "column": column,
                "function": function.qname,
                "source": {
                    "id": atom.source_id, "kind": atom.source_kind,
                    "path": atom.path, "line": atom.line,
                    "column": atom.column, "symbol": atom.symbol,
                },
                "sink": {"name": sink, "context": context, "path": function.path,
                         "line": line, "column": column},
                "path_predicates": list(state.predicates),
                "witness": [step.public() for step in witness],
                "evidence_level": "bounded-symbolic-witness",
                "remediation": remediation,
                "fingerprint": fingerprint,
            }
            self.findings[fingerprint] = finding

    def analyze(self) -> None:
        for qname in sorted(self.functions):
            function = self.functions[qname]
            analyzer = FunctionAnalyzer(self, function, call_depth=0, call_stack=())
            state = analyzer.initial_state(())
            analyzer.run(state)
            self.functions_analyzed.add(qname)


class FunctionAnalyzer:
    def __init__(self, repository: SymbolicRepository, function: Function,
                 call_depth: int, call_stack: tuple[str, ...]) -> None:
        self.repo = repository
        self.function = function
        self.call_depth = call_depth
        self.call_stack = call_stack

    def initial_state(self, actual: Sequence[Value], heap: tuple[tuple[str, AbstractObject], ...] = (),
                      predicates: tuple[str, ...] = ()) -> SymbolicState:
        env: dict[str, Value] = dict(self.repo.module_globals.get(self.function.module, {}))
        for index, name in enumerate(self.function.parameters):
            value = actual[index] if index < len(actual) else EMPTY
            if self.function.route and name not in {"self", "cls", "request", "session", "db"}:
                value = self.repo.join_values(value, self.repo.source(
                    self.function, self.function.node, "route.parameter", name))
            env[name] = value
        combined_heap = _map(self.repo.module_heaps.get(self.function.module, ()))
        combined_heap.update(_map(heap))
        return SymbolicState(tuple(sorted(env.items())), tuple(sorted(combined_heap.items())),
                             predicates=predicates)

    def run(self, state: SymbolicState) -> tuple[Value, tuple[tuple[str, AbstractObject], ...]]:
        states = self.block(self.function.node.body, [state])
        returns = [row.return_value for row in states if row.control == "return"]
        heaps = [row.heap for row in states]
        return self.repo.join_values(*returns), self.repo.join_states([
            SymbolicState(heap=heap) for heap in heaps]).heap if heaps else state.heap

    def block(self, statements: Sequence[ast.stmt], states: Sequence[SymbolicState]) -> list[SymbolicState]:
        current = self.repo.cap_states(states)
        for statement in statements:
            if not any(row.control == "normal" for row in current):
                break
            next_states: list[SymbolicState] = []
            for state in current:
                if state.control != "normal":
                    next_states.append(state)
                elif self.repo.tick():
                    next_states.extend(self.statement(statement, state))
                else:
                    next_states.append(state)
            current = self.repo.cap_states(next_states)
        return current

    def set_env(self, state: SymbolicState, name: str, value: Value,
                node: ast.AST | None = None) -> SymbolicState:
        env = _map(state.env)
        versions = _map(state.versions)
        versions[name] = versions.get(name, 0) + 1
        if node is not None and value.atoms:
            step = EvidenceStep("assignment", self.function.path,
                                getattr(node, "lineno", 1), getattr(node, "col_offset", 0),
                                "%s assigned as SSA version %d" % (name, versions[name]), name)
            value = self.repo.transform(value, step)
        env[name] = value
        return SymbolicState(tuple(sorted(env.items())), state.heap,
                             tuple(sorted(versions.items())), state.predicates,
                             state.control, state.return_value)

    def set_heap(self, state: SymbolicState, obj_id: str, obj: AbstractObject) -> SymbolicState:
        heap = _map(state.heap)
        heap[obj_id] = obj
        return SymbolicState(state.env, tuple(sorted(heap.items())), state.versions,
                             state.predicates, state.control, state.return_value)

    def allocate(self, state: SymbolicState, node: ast.AST, kind: str,
                 fields: Mapping[str, Value] | None = None, open_object: bool = False,
                 unknown: Value = EMPTY) -> tuple[Value, SymbolicState]:
        obj_id = "%s:%s:%d:%d" % (
            kind, self.function.path, getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0))
        items = sorted((fields or {}).items())
        if len(items) > self.repo.limits.max_object_fields:
            self.repo.limit_hits.add("max_object_fields")
            kept = items[:self.repo.limits.max_object_fields]
            unknown = self.repo.join_values(unknown, *(value for _, value in items[self.repo.limits.max_object_fields:]))
            items = kept
            open_object = True
        state = self.set_heap(state, obj_id, AbstractObject(tuple(items), unknown, open_object))
        constants: list[str] = []
        for key, item in items:
            if key.startswith("key:"):
                constants.append(key[len("key:"):])
            elif key.startswith("index:"):
                constants.extend(item.constants)
        return self.repo.value(objects=(obj_id,), constants=constants), state

    def lookup(self, state: SymbolicState, name: str) -> Value:
        return _map(state.env).get(name, EMPTY)

    def object_read(self, state: SymbolicState, base: Value, key: str,
                    node: ast.AST) -> Value:
        heap = _map(state.heap)
        results: list[Value] = []
        for obj_id in base.objects:
            obj = heap.get(obj_id, AbstractObject(open=True))
            fields = _map(obj.fields)
            if key:
                results.append(fields.get(key, obj.unknown_field if obj.open else EMPTY))
            else:
                results.extend(fields.values())
                results.append(obj.unknown_field)
        # A source object is open: any of its fields can contain source data.
        results.append(self.repo.value(atoms=base.atoms, unknown=base.unknown))
        value = self.repo.join_values(*results)
        if value.atoms:
            step = EvidenceStep("field-read", self.function.path,
                                getattr(node, "lineno", 1), getattr(node, "col_offset", 0),
                                "read %s field" % (key or "an unknown"), key)
            value = self.repo.transform(value, step)
        return value

    def object_write(self, state: SymbolicState, base: Value, key: str,
                     value: Value) -> SymbolicState:
        for obj_id in base.objects:
            heap = _map(state.heap)
            obj = heap.get(obj_id, AbstractObject(open=True))
            fields = _map(obj.fields)
            if key:
                fields[key] = value
                state = self.set_heap(state, obj_id, AbstractObject(
                    tuple(sorted(fields.items())), obj.unknown_field, obj.open))
            else:
                state = self.set_heap(state, obj_id, AbstractObject(
                    obj.fields, self.repo.join_values(obj.unknown_field, value), True))
        return state

    def assign(self, target: ast.AST, value: Value, state: SymbolicState,
               value_node: ast.AST | None = None) -> SymbolicState:
        if isinstance(target, ast.Name):
            return self.set_env(state, target.id, value, target)
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                state = self.assign(item, value, state, value_node)
            return state
        if isinstance(target, ast.Starred):
            return self.assign(target.value, value, state, value_node)
        if isinstance(target, ast.Subscript):
            base, state = self.expr(target.value, state)
            key = "key:" + _literal_node(target.slice) if _literal_node(target.slice) else ""
            return self.object_write(state, base, key, value)
        if isinstance(target, ast.Attribute):
            base, state = self.expr(target.value, state)
            return self.object_write(state, base, "attr:" + target.attr, value)
        self.repo.coverage_gaps.add("unsupported assignment target: " + type(target).__name__)
        return state

    def statement(self, node: ast.stmt, state: SymbolicState) -> list[SymbolicState]:
        if isinstance(node, ast.Assign):
            value, state = self.expr(node.value, state)
            for target in node.targets:
                state = self.assign(target, value, state, node.value)
            return [state]
        if isinstance(node, ast.AnnAssign):
            value, state = self.expr(node.value, state)
            return [self.assign(node.target, value, state, node.value)]
        if isinstance(node, ast.AugAssign):
            old, state = self.expr(node.target, state)
            new, state = self.expr(node.value, state)
            return [self.assign(node.target, self.repo.join_values(old, new), state, node.value)]
        if isinstance(node, ast.Expr):
            _value, state = self.expr(node.value, state)
            return [state]
        if isinstance(node, ast.Return):
            value, state = self.expr(node.value, state)
            return [SymbolicState(state.env, state.heap, state.versions,
                                  state.predicates, "return", value)]
        if isinstance(node, ast.Raise):
            _value, state = self.expr(node.exc, state)
            return [SymbolicState(state.env, state.heap, state.versions,
                                  state.predicates, "raise", EMPTY)]
        if isinstance(node, ast.If):
            _test_value, state = self.expr(node.test, state)
            truth = self.static_truth(node.test, state)
            outputs: list[SymbolicState] = []
            if truth is not False:
                yes = self.refine(state, node.test, True)
                outputs.extend(self.block(node.body, [yes]))
            if truth is not True:
                no = self.refine(state, node.test, False)
                outputs.extend(self.block(node.orelse, [no]) if node.orelse else [no])
            return self.repo.cap_states(outputs)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            iterator, state = self.expr(node.iter, state)
            item = self.object_read(state, iterator, "", node.iter)
            return self.loop(node, state, lambda row: self.assign(node.target, item, row, node.iter),
                             node.body, node.orelse, may_skip=True)
        if isinstance(node, ast.While):
            def prepare(row: SymbolicState) -> SymbolicState:
                _value, evaluated = self.expr(node.test, row)
                return self.refine(evaluated, node.test, True)
            truth = self.static_truth(node.test, state)
            return self.loop(node, state, prepare, node.body, node.orelse,
                             may_skip=truth is not True)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value, state = self.expr(item.context_expr, state)
                if item.optional_vars:
                    state = self.assign(item.optional_vars, value, state, item.context_expr)
            return self.block(node.body, [state])
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            paths = self.block(node.body, [state])
            for handler in node.handlers:
                handler_state = state
                if handler.name:
                    handler_state = self.set_env(handler_state, handler.name, EMPTY, handler)
                paths.extend(self.block(handler.body, [handler_state]))
            paths = self.repo.cap_states(paths)
            if node.orelse:
                paths = self.block(node.orelse, paths)
            if node.finalbody:
                final_paths: list[SymbolicState] = []
                for original in paths:
                    normalized = SymbolicState(original.env, original.heap,
                                               original.versions, original.predicates)
                    for final in self.block(node.finalbody, [normalized]):
                        if final.control == "normal":
                            final = SymbolicState(final.env, final.heap, final.versions,
                                                  final.predicates, original.control,
                                                  original.return_value)
                        final_paths.append(final)
                paths = self.repo.cap_states(final_paths)
            return paths
        if isinstance(node, ast.Match):
            _subject, state = self.expr(node.subject, state)
            paths = []
            for index, case in enumerate(node.cases):
                predicate = "match-case[%d]" % index
                case_state = SymbolicState(state.env, state.heap, state.versions,
                                           state.predicates + (predicate,))
                if case.guard:
                    _guard, case_state = self.expr(case.guard, case_state)
                    case_state = self.refine(case_state, case.guard, True)
                paths.extend(self.block(case.body, [case_state]))
            return self.repo.cap_states(paths or [state])
        if isinstance(node, ast.Delete):
            env = _map(state.env)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
            return [SymbolicState(tuple(sorted(env.items())), state.heap, state.versions,
                                  state.predicates, state.control, state.return_value)]
        if isinstance(node, ast.Break):
            return [SymbolicState(state.env, state.heap, state.versions,
                                  state.predicates, "break", EMPTY)]
        if isinstance(node, ast.Continue):
            return [SymbolicState(state.env, state.heap, state.versions,
                                  state.predicates, "continue", EMPTY)]
        if isinstance(node, ast.Assert):
            # Assertions may be removed with ``python -O``; never trust them as sanitizers.
            _value, state = self.expr(node.test, state)
            return [state]
        if isinstance(node, (ast.Pass, ast.Import, ast.ImportFrom, ast.Global,
                             ast.Nonlocal)):
            return [state]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.repo.coverage_gaps.add("nested scope body not independently analyzed")
            return [state]
        self.repo.coverage_gaps.add("unsupported statement: " + type(node).__name__)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                _value, state = self.expr(child, state)
        return [state]

    def loop(self, node: ast.stmt, state: SymbolicState, prepare,
             body: Sequence[ast.stmt], orelse: Sequence[ast.stmt],
             may_skip: bool) -> list[SymbolicState]:
        exits: list[SymbolicState] = [state] if may_skip else []
        active = [prepare(state)]
        previous = {self.repo.state_key(row) for row in active}
        converged = False
        for _iteration in range(self.repo.limits.max_loop_iterations):
            results = self.block(body, active)
            next_active: list[SymbolicState] = []
            for row in results:
                if row.control == "break":
                    exits.append(SymbolicState(row.env, row.heap, row.versions, row.predicates))
                elif row.control in {"normal", "continue"}:
                    normal = SymbolicState(row.env, row.heap, row.versions, row.predicates)
                    next_active.append(prepare(normal))
                else:
                    exits.append(row)
            active = self.repo.cap_states(next_active)
            signature = {self.repo.state_key(row) for row in active}
            if not active:
                converged = True
                break
            if signature == previous:
                converged = True
                exits.extend(active)
                break
            previous = signature
        if active and not converged:
            self.repo.limit_hits.add("max_loop_iterations")
            self.repo.loop_widenings += 1
            exits.append(self.repo.join_states([state] + active))
        normal_exits = [row for row in exits if row.control == "normal"]
        other = [row for row in exits if row.control != "normal"]
        if orelse and normal_exits:
            normal_exits = self.block(orelse, normal_exits)
        return self.repo.cap_states(other + normal_exits)

    def static_truth(self, node: ast.AST, state: SymbolicState) -> bool | None:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.static_truth(node.operand, state)
            return None if value is None else not value
        if isinstance(node, ast.Name):
            constants = self.lookup(state, node.id).constants
            if len(constants) == 1:
                if constants[0] == "bool:true":
                    return True
                if constants[0] in {"bool:false", "none:", "int:0", "str:"}:
                    return False
        return None

    @staticmethod
    def predicate(node: ast.AST, truth: bool) -> str:
        expression = FunctionAnalyzer._predicate_expression(node)
        return expression if truth else "not (%s)" % expression

    @staticmethod
    def _predicate_expression(node: ast.AST) -> str:
        """Render useful branch structure without copying source literals."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return _dotted(node) or "attribute"
        if isinstance(node, ast.Constant):
            return "<%s-literal>" % type(node.value).__name__.lower()
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return "not (%s)" % FunctionAnalyzer._predicate_expression(node.operand)
        if isinstance(node, ast.BoolOp):
            operator = " and " if isinstance(node.op, ast.And) else " or "
            return operator.join(FunctionAnalyzer._predicate_expression(item)
                                 for item in node.values)
        if isinstance(node, ast.Compare):
            operators = {
                ast.Eq: "==", ast.NotEq: "!=", ast.In: "in", ast.NotIn: "not in",
                ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
                ast.Is: "is", ast.IsNot: "is not",
            }
            parts = [FunctionAnalyzer._predicate_expression(node.left)]
            for operator, comparator in zip(node.ops, node.comparators):
                parts.append(operators.get(type(operator), type(operator).__name__))
                if isinstance(comparator, (ast.Set, ast.List, ast.Tuple)):
                    parts.append("<literal-allowlist:%d>" % len(comparator.elts))
                else:
                    parts.append(FunctionAnalyzer._predicate_expression(comparator))
            return " ".join(parts)
        if isinstance(node, ast.Call):
            return (_dotted(node.func) or "dynamic-call") + "(...)"
        return "<%s-predicate>" % type(node).__name__

    def finite_allowlist(self, node: ast.AST, state: SymbolicState) -> bool:
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            return bool(node.elts) and all(bool(_literal_node(item)) for item in node.elts)
        if isinstance(node, ast.Name):
            value = self.lookup(state, node.id)
            return bool(value.constants) and not value.atoms and not value.unknown
        return False

    def validation_target(self, test: ast.AST, truth: bool,
                          state: SymbolicState) -> str:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.validation_target(test.operand, not truth, state)
        if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
            return ""
        left, right, op = test.left, test.comparators[0], test.ops[0]
        if isinstance(left, ast.Name) and isinstance(op, (ast.Eq, ast.NotEq)) and _literal_node(right):
            safe_branch = truth if isinstance(op, ast.Eq) else not truth
            return left.id if safe_branch else ""
        if isinstance(right, ast.Name) and isinstance(op, (ast.Eq, ast.NotEq)) and _literal_node(left):
            safe_branch = truth if isinstance(op, ast.Eq) else not truth
            return right.id if safe_branch else ""
        if isinstance(left, ast.Name) and isinstance(op, (ast.In, ast.NotIn)) \
                and self.finite_allowlist(right, state):
            safe_branch = truth if isinstance(op, ast.In) else not truth
            return left.id if safe_branch else ""
        return ""

    def refine(self, state: SymbolicState, test: ast.AST, truth: bool) -> SymbolicState:
        predicate = self.predicate(test, truth)
        predicates = state.predicates + ((predicate,) if predicate not in state.predicates else ())
        state = SymbolicState(state.env, state.heap, state.versions, predicates,
                              state.control, state.return_value)
        name = self.validation_target(test, truth, state)
        if name:
            value = self.lookup(state, name)
            step = EvidenceStep("branch-validation", self.function.path,
                                getattr(test, "lineno", 1), getattr(test, "col_offset", 0),
                                "finite literal allowlist constrains %s" % name, name)
            state = self.set_env(state, name, self.repo.sanitize(value, {"all"}, step))
        return state

    def expr(self, node: ast.AST | None, state: SymbolicState) -> tuple[Value, SymbolicState]:
        if node is None:
            return EMPTY, state
        if not self.repo.tick():
            return EMPTY, state
        if isinstance(node, ast.Constant):
            literal = _literal(node.value)
            return self.repo.value(constants=(literal,) if literal else ()), state
        if isinstance(node, ast.Name):
            return self.lookup(state, node.id), state
        if isinstance(node, ast.Attribute):
            raw = _dotted(node)
            canonical = self.repo.canonical(self.function.module, raw)
            source_kind = self.source_kind(canonical) or self.source_kind(raw)
            if source_kind:
                return self.repo.source(self.function, node, source_kind, raw), state
            base, state = self.expr(node.value, state)
            return self.object_read(state, base, "attr:" + node.attr, node), state
        if isinstance(node, ast.Subscript):
            raw = _dotted(node.value)
            canonical = self.repo.canonical(self.function.module, raw)
            source_kind = self.source_kind(canonical) or self.source_kind(raw)
            if source_kind:
                return self.repo.source(self.function, node, source_kind, raw), state
            base, state = self.expr(node.value, state)
            _index, state = self.expr(node.slice, state)
            literal = _literal_node(node.slice)
            key = "key:" + literal if literal else ""
            return self.object_read(state, base, key, node), state
        if isinstance(node, ast.NamedExpr):
            value, state = self.expr(node.value, state)
            state = self.assign(node.target, value, state, node.value)
            return value, state
        if isinstance(node, (ast.BinOp, ast.BoolOp)):
            children = [node.left, node.right] if isinstance(node, ast.BinOp) else node.values
            values = []
            for child in children:
                value, state = self.expr(child, state)
                values.append(value)
            return self.repo.join_values(*values), state
        if isinstance(node, ast.UnaryOp):
            value, state = self.expr(node.operand, state)
            if isinstance(node.op, ast.Not):
                return self.repo.value(constants=("bool:true", "bool:false")), state
            return value, state
        if isinstance(node, ast.IfExp):
            _test, state = self.expr(node.test, state)
            yes_value, yes_state = self.expr(node.body, self.refine(state, node.test, True))
            no_value, no_state = self.expr(node.orelse, self.refine(state, node.test, False))
            joined = self.repo.join_states([yes_state, no_state])
            return self.repo.join_values(yes_value, no_value), joined
        if isinstance(node, ast.JoinedStr):
            values = []
            for item in node.values:
                value, state = self.expr(item, state)
                values.append(value)
            return self.repo.join_values(*values), state
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value, state)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            fields: dict[str, Value] = {}
            values = []
            for index, item in enumerate(node.elts):
                value, state = self.expr(item, state)
                fields["index:%d" % index] = value
                values.append(value)
            container, state = self.allocate(state, node, type(node).__name__.lower(), fields)
            constants = [constant for value in values for constant in value.constants]
            return self.repo.value(objects=container.objects, constants=constants), state
        if isinstance(node, ast.Dict):
            fields: dict[str, Value] = {}
            unknown = EMPTY
            for key_node, value_node in zip(node.keys, node.values):
                value, state = self.expr(value_node, state)
                if key_node is None:
                    unknown = self.repo.join_values(unknown, value)
                    continue
                _key_value, state = self.expr(key_node, state)
                literal = _literal_node(key_node)
                if literal:
                    fields["key:" + literal] = value
                else:
                    unknown = self.repo.join_values(unknown, value)
            return self.allocate(state, node, "dict", fields,
                                 open_object=bool(unknown.atoms or unknown.unknown), unknown=unknown)
        if isinstance(node, ast.Compare):
            _left, state = self.expr(node.left, state)
            for comparator in node.comparators:
                _right, state = self.expr(comparator, state)
            return self.repo.value(constants=("bool:true", "bool:false")), state
        if isinstance(node, ast.Call):
            return self.call(node, state)
        if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom, ast.Starred)):
            return self.expr(node.value, state)
        if isinstance(node, ast.Lambda):
            self.repo.coverage_gaps.add("lambda body not invoked symbolically")
            return EMPTY, state
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self.repo.coverage_gaps.add("comprehension widened to child-expression union")
        values = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                value, state = self.expr(child, state)
                values.append(value)
        return self.repo.join_values(*values), state

    @staticmethod
    def source_kind(canonical: str) -> str:
        if canonical in SOURCE_CALLS:
            return SOURCE_CALLS[canonical]
        for prefix, kind in SOURCE_PREFIXES.items():
            if canonical == prefix or canonical.startswith(prefix + "."):
                return kind
        return ""

    @staticmethod
    def sink_spec(canonical: str, raw: str) -> tuple[str, str, str, tuple[int, ...], str] | None:
        spec = SINKS.get(canonical) or SINKS.get(raw)
        if spec:
            return spec
        candidate = canonical or raw
        parts = candidate.lower().split(".")
        method = parts[-1] if parts else ""
        receiver = parts[-2] if len(parts) > 1 else ""
        sql_receiver = receiver in {
            "cursor", "cur", "db", "database", "connection", "conn",
            "engine", "session", "queryset",
        } or any(token in candidate.lower() for token in (
            "sqlite", "sqlalchemy", "psycopg", "mysql", "django.db"))
        if method in {"execute", "executemany", "executescript", "raw"} and sql_receiver:
            return ("sql", "CWE-89", "CRITICAL", (0,),
                    "Use a constant query with bound parameters.")
        return None

    def call(self, node: ast.Call, state: SymbolicState) -> tuple[Value, SymbolicState]:
        raw = _dotted(node.func)
        canonical = self.repo.canonical(self.function.module, raw)
        positional: list[Value] = []
        for argument in node.args:
            value, state = self.expr(argument, state)
            if isinstance(argument, ast.Starred):
                self.repo.coverage_gaps.add("starred call argument widened")
            positional.append(value)
        keywords: dict[str, Value] = {}
        for keyword in node.keywords:
            value, state = self.expr(keyword.value, state)
            if keyword.arg:
                keywords[keyword.arg] = value
            else:
                self.repo.coverage_gaps.add("double-star call argument widened")
                positional.append(value)
        source_kind = self.source_kind(canonical) or self.source_kind(raw)
        if source_kind:
            return self.repo.source(self.function, node, source_kind, raw), state
        contexts = SANITIZERS.get(canonical) or SANITIZERS.get(raw)
        if contexts:
            combined = self.repo.join_values(*positional, *keywords.values())
            step = EvidenceStep("sanitizer", self.function.path, node.lineno,
                                node.col_offset, "%s sanitizes %s" %
                                (canonical or raw, ", ".join(sorted(contexts))), canonical or raw)
            return self.repo.sanitize(combined, contexts, step), state
        target_name = self.repo.resolve_function(self.function.module, raw)
        if target_name:
            return self.call_function(target_name, node, positional, keywords, state)
        spec = self.sink_spec(canonical, raw)
        if spec:
            selected = [positional[index] for index in spec[3] if index < len(positional)]
            if not selected:
                for key in ("command", "args", "query", "url", "filename", "path", "source", "object"):
                    if key in keywords:
                        selected.append(keywords[key])
            dangerous = self.repo.join_values(*selected)
            self.repo.record_sink(self.function, state, node, canonical or raw, spec, dangerous)
            # The dangerous operation is modeled as a sink, not mislabeled as
            # an unresolved helper.  Conservatively preserve its data result.
            return dangerous, state
        receiver = EMPTY
        if isinstance(node.func, ast.Attribute):
            receiver, state = self.expr(node.func.value, state)
        short = (canonical or raw).rsplit(".", 1)[-1]
        if short == "get" and isinstance(node.func, ast.Attribute):
            key_node = node.args[0] if node.args else None
            literal = _literal_node(key_node)
            result = self.object_read(state, receiver, "key:" + literal if literal else "", node)
            default = positional[1] if len(positional) > 1 else keywords.get("default", EMPTY)
            return self.repo.join_values(result, default), state
        if canonical in SAFE_PROPAGATORS or raw in SAFE_PROPAGATORS or short in SAFE_METHOD_PROPAGATORS:
            return self.repo.join_values(receiver, *positional, *keywords.values()), state
        # Unknown calls are a trust boundary, not a taint eraser.  Return all
        # receiver/argument flows and explicitly label the witness.
        self.repo.unknown_calls += 1
        combined = self.repo.join_values(receiver, *positional, *keywords.values())
        if combined.atoms:
            step = EvidenceStep("unknown-call", self.function.path, node.lineno,
                                node.col_offset,
                                "unresolved call conservatively propagates inputs",
                                canonical or raw or "<dynamic-call>")
            combined = self.repo.transform(combined, step)
        return self.repo.value(atoms=combined.atoms, objects=combined.objects,
                               constants=combined.constants, unknown=True), state

    def call_function(self, target_name: str, node: ast.Call, positional: Sequence[Value],
                      keywords: Mapping[str, Value], state: SymbolicState) -> tuple[Value, SymbolicState]:
        target = self.repo.functions[target_name]
        actual = list(positional)
        parameter_index = {name: index for index, name in enumerate(target.parameters)}
        for name, value in keywords.items():
            index = parameter_index.get(name)
            if index is not None:
                while len(actual) <= index:
                    actual.append(EMPTY)
                actual[index] = value
        signature = _hash(target_name, tuple(
            (tuple(atom.source_id for atom in value.atoms), value.constants, bool(value.objects), value.unknown)
            for value in actual), state.heap)[:24]
        contexts = self.repo.contexts.setdefault(target_name, set())
        if signature not in contexts and len(contexts) >= self.repo.limits.max_call_contexts:
            self.repo.limit_hits.add("max_call_contexts")
            return self.unknown_call_result(node, actual, state, target_name)
        contexts.add(signature)
        if self.call_depth >= self.repo.limits.max_call_depth or target_name in self.call_stack:
            self.repo.limit_hits.add("max_call_depth" if self.call_depth >= self.repo.limits.max_call_depth
                                     else "recursive_call_widening")
            return self.unknown_call_result(node, actual, state, target_name)
        enter = EvidenceStep("call", self.function.path, node.lineno, node.col_offset,
                             "value enters bounded call context", target_name)
        actual = [self.repo.transform(value, enter) if value.atoms else value for value in actual]
        nested = FunctionAnalyzer(self.repo, target, self.call_depth + 1,
                                  self.call_stack + (self.function.qname,))
        nested_state = nested.initial_state(actual, state.heap, state.predicates)
        returned, heap = nested.run(nested_state)
        if returned.atoms:
            step = EvidenceStep("call", self.function.path, node.lineno, node.col_offset,
                                "value returned from bounded call context", target_name)
            returned = self.repo.transform(returned, step)
        state = SymbolicState(state.env, heap, state.versions, state.predicates,
                              state.control, state.return_value)
        self.repo.functions_analyzed.add(target_name)
        return returned, state

    def unknown_call_result(self, node: ast.Call, actual: Sequence[Value],
                            state: SymbolicState, target_name: str) -> tuple[Value, SymbolicState]:
        combined = self.repo.join_values(*actual)
        step = EvidenceStep("call-widening", self.function.path, node.lineno,
                            node.col_offset, "call result widened at analysis bound", target_name)
        return self.repo.transform(combined, step), state


def _module_name(relative: str) -> str:
    parts = list(Path(relative).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(part.replace("-", "_").replace(" ", "_") for part in parts) or "__root__"


def _parse_modules(sources: Sequence[tuple[str, str]]) -> tuple[list[Module], list[dict]]:
    modules: list[Module] = []
    errors: list[dict] = []
    for path, source in sorted(sources):
        try:
            tree = ast.parse(source, filename=path, type_comments=True)
            modules.append(Module(_module_name(path), path.replace("\\", "/"), tree))
        except (SyntaxError, ValueError, TypeError) as exc:
            errors.append({
                "path": path.replace("\\", "/"),
                "line": int(getattr(exc, "lineno", 1) or 1),
                "column": int(getattr(exc, "offset", 0) or 0),
                "message": str(getattr(exc, "msg", exc)),
            })
    return modules, errors


def _report(repository: SymbolicRepository, *, root: str, files_discovered: int,
            files_considered: int, input_bytes: int,
            parse_errors: Sequence[dict], skipped: Sequence[dict],
            filesystem_read: bool) -> dict:
    gaps = sorted(repository.coverage_gaps)
    hits = sorted(repository.limit_hits)
    partial_reasons = []
    if parse_errors:
        partial_reasons.append("parse-errors")
    if skipped:
        partial_reasons.append("skipped-files")
    if hits:
        partial_reasons.append("analysis-limits")
    if gaps:
        partial_reasons.append("coverage-gaps")
    status = "partial" if partial_reasons else "complete"
    findings = sorted(repository.findings.values(),
                      key=lambda row: (row["path"], row["line"], row["column"],
                                       row["rule"], row["fingerprint"]))
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "engine": "bounded-path-field-symbolic",
        "root": root,
        "status": status,
        "partial_reasons": partial_reasons,
        "analysis": {
            "target_code_executed": False,
            "network_accessed": False,
            "filesystem_read": filesystem_read,
            "filesystem_written": False,
            "processes_spawned": False,
            "method": "Python AST abstract interpretation",
        },
        "coverage": {
            "path_sensitive": True,
            "field_sensitive": True,
            "alias_aware_heap": True,
            "branch_predicates": True,
            "unknown_calls": "conservative input/receiver propagation",
            "call_contexts": "bounded",
            "loop_policy": "bounded unrolling followed by deterministic widening",
            "coverage_gaps": gaps,
        },
        "limits": {
            "configured": repository.limits.public(),
            "hit": hits,
            "input": {
                "files_considered": files_considered,
                "files_loaded": files_discovered,
                "bytes_loaded": input_bytes,
                "hit": [name for name in ("max_files", "max_bytes", "max_total_bytes")
                        if name in repository.limit_hits],
                "truncated": any(name in repository.limit_hits for name in (
                    "max_files", "max_bytes", "max_total_bytes")),
            },
        },
        "metrics": {
            "files_discovered": files_discovered,
            "files_considered": files_considered,
            "input_bytes": input_bytes,
            "python_modules_parsed": len(repository.modules),
            "functions_indexed": len(repository.functions),
            "functions_analyzed": len(repository.functions_analyzed),
            "symbolic_steps": repository.steps,
            "states_created": repository.states_created,
            "peak_live_states": repository.peak_states,
            "call_contexts": sum(len(rows) for rows in repository.contexts.values()),
            "unknown_calls": repository.unknown_calls,
            "loop_widenings": repository.loop_widenings,
            "findings": len(findings),
            "parse_errors": len(parse_errors),
            "skipped": len(skipped),
        },
        "findings": findings,
        "parse_errors": sorted(parse_errors, key=lambda row: (row["path"], row["line"])),
        "skipped": sorted(skipped, key=lambda row: (row.get("path", ""), row.get("reason", ""))),
    }
    # A digest over the semantic payload makes evidence transport tampering visible.
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    report["report_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return report


def _limits(options: Mapping[str, object]) -> Limits:
    names = set(Limits.__dataclass_fields__)
    unknown = sorted(set(options) - names)
    if unknown:
        raise TypeError("unexpected analysis options: %s" % ", ".join(unknown))
    return Limits(**options)


def analyze_source(source: str, filename: str = "memory.py", **options: int) -> dict:
    """Analyze source text without filesystem, network, process, or target execution."""
    if not isinstance(source, str):
        raise TypeError("source must be text")
    limits = _limits(options)
    display = Path(filename).name or "memory.py"
    source_bytes = len(source.encode("utf-8", "surrogatepass"))
    if source_bytes > limits.max_total_bytes:
        repository = SymbolicRepository((), limits)
        repository.limit_hits.add("max_total_bytes")
        repository.coverage_gaps.add(
            "input source omitted because max_total_bytes was exceeded")
        skipped = ({
            "path": display,
            "reason": "max_total_bytes reached",
            "bytes_loaded": 0,
            "candidate_bytes_at_least": source_bytes,
            "limit": limits.max_total_bytes,
        },)
        return _report(
            repository, root=display, files_discovered=0, files_considered=1,
            input_bytes=0, parse_errors=(), skipped=skipped,
            filesystem_read=False)
    modules, errors = _parse_modules([(display, source)])
    repository = SymbolicRepository(modules, limits)
    repository.analyze()
    return _report(repository, root=display, files_discovered=1,
                   files_considered=1, input_bytes=source_bytes,
                   parse_errors=errors, skipped=(), filesystem_read=False)


def _discover(root: Path, limits: Limits) -> tuple[
        list[tuple[str, str]], list[dict], list[dict], str, int, int]:
    skipped: list[dict] = []
    errors: list[dict] = []
    sources: list[tuple[str, str]] = []
    files_considered = 0
    input_bytes = 0
    resolved_root = root.resolve()
    base = resolved_root.parent if resolved_root.is_file() else resolved_root
    if not resolved_root.exists():
        return [], [], [{"path": str(root), "reason": "path does not exist"}], str(root), 0, 0
    candidates: Iterable[Path] = [resolved_root] if resolved_root.is_file() else resolved_root.rglob("*.py")
    for path in sorted(candidates, key=lambda item: str(item).casefold()):
        if files_considered >= limits.max_files:
            skipped.append({"path": ".", "reason": "max_files reached", "limit": limits.max_files})
            break
        files_considered += 1
        try:
            if path.is_symlink():
                skipped.append({"path": str(path), "reason": "symbolic link not followed"})
                continue
            if not path.is_file() or path.suffix.lower() not in {".py", ".pyw"}:
                if resolved_root.is_file():
                    skipped.append({"path": str(path), "reason": "not a Python source file"})
                continue
            if any(part in SKIP_DIRS for part in path.relative_to(base).parts):
                continue
            resolved = path.resolve()
            try:
                resolved.relative_to(base)
            except ValueError:
                skipped.append({"path": str(path), "reason": "outside analysis root"})
                continue
            size = resolved.stat().st_size
            relative = resolved.name if resolved_root.is_file() else resolved.relative_to(base).as_posix()
            if size > limits.max_bytes:
                skipped.append({"path": relative, "reason": "max_bytes exceeded", "bytes": size,
                                "limit": limits.max_bytes})
                continue
            remaining = limits.max_total_bytes - input_bytes
            if size > remaining:
                skipped.append({
                    "path": relative,
                    "reason": "max_total_bytes reached",
                    "bytes_loaded": input_bytes,
                    "candidate_bytes_at_least": size,
                    "limit": limits.max_total_bytes,
                })
                break
            # Do not trust stat() as a read bound: a concurrently replaced or
            # growing file must still be unable to cross either byte budget.
            read_budget = min(limits.max_bytes, remaining)
            with resolved.open("rb") as stream:
                raw = stream.read(read_budget + 1)
            if len(raw) > remaining:
                skipped.append({
                    "path": relative,
                    "reason": "max_total_bytes reached",
                    "bytes_loaded": input_bytes,
                    "candidate_bytes_at_least": len(raw),
                    "limit": limits.max_total_bytes,
                })
                break
            if len(raw) > limits.max_bytes:
                # The file changed after stat(). Count bytes already consumed
                # against the aggregate budget even though the source is not
                # retained for parsing.
                input_bytes += len(raw)
                skipped.append({
                    "path": relative, "reason": "max_bytes exceeded",
                    "bytes": len(raw), "limit": limits.max_bytes,
                })
                continue
            # Consume the aggregate budget before decoding so invalid UTF-8
            # cannot bypass it by repeatedly failing after a bounded read.
            input_bytes += len(raw)
            source = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            sources.append((relative, source))
        except (OSError, UnicodeError) as exc:
            errors.append({"path": str(path), "line": 1, "column": 0,
                           "message": "%s: %s" % (type(exc).__name__, exc)})
    return sources, errors, skipped, str(resolved_root), files_considered, input_bytes


def analyze_repository(root: str | Path, **options: int) -> dict:
    """Analyze Python files beneath ``root`` with bounded read-only discovery."""
    limits = _limits(options)
    sources, read_errors, skipped, display_root, files_considered, input_bytes = _discover(
        Path(root), limits)
    modules, parse_errors = _parse_modules(sources)
    repository = SymbolicRepository(modules, limits)
    for row in skipped:
        if row.get("reason") == "max_files reached":
            repository.limit_hits.add("max_files")
            repository.coverage_gaps.add("repository input truncated at max_files")
        elif row.get("reason") == "max_bytes exceeded":
            repository.limit_hits.add("max_bytes")
            repository.coverage_gaps.add("one or more input files omitted at max_bytes")
        elif row.get("reason") == "max_total_bytes reached":
            repository.limit_hits.add("max_total_bytes")
            repository.coverage_gaps.add(
                "repository input truncated at max_total_bytes")
    repository.analyze()
    return _report(repository, root=display_root, files_discovered=len(sources),
                   files_considered=files_considered, input_bytes=input_bytes,
                   parse_errors=list(read_errors) + parse_errors, skipped=skipped,
                   filesystem_read=True)


# Compact integration aliases.
analyze = analyze_source
scan = analyze_repository


__all__ = [
    "VERSION", "SCHEMA", "Limits", "analyze", "analyze_source",
    "analyze_repository", "scan",
]
