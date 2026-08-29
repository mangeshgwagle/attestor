#!/usr/bin/env python3
"""Bounded deep-correctness and compatibility analysis for Attestor 4.1.3.

Python concurrency and resource facts come from CPython's parser.  OpenAPI,
JSON Schema, and Avro JSON use the standard JSON parser.  GraphQL, Protobuf,
and SQL use explicitly labelled bounded lexical adapters.  No target module,
compiler, database, migration, service, or generated code is executed.

All deadlock, race, resource, and breaking-change results are static candidates:
the report records the exact evidence level and never promotes them to runtime
proof.  Compatibility findings require an explicit immutable baseline.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

import analysis_snapshot41 as snapshot41


SCHEMA = "attestor.deep-correctness/4.1"
VERSION = "4.1.3"
_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})
_RESOURCE_FACTORIES = {
    "open": "file", "builtins.open": "file", "io.open": "file",
    "socket.socket": "socket", "sqlite3.connect": "database-connection",
    "subprocess.Popen": "process", "tempfile.NamedTemporaryFile": "file",
    "requests.Session": "http-session", "aiohttp.ClientSession": "http-session",
}
_CLOSERS = {
    "file": frozenset({"close"}), "socket": frozenset({"close"}),
    "database-connection": frozenset({"close"}),
    # terminate/kill requests exit but do not reap a child process; wait or
    # communicate is still required for this bounded lifecycle model.
    "process": frozenset({"wait", "communicate"}),
    "http-session": frozenset({"close", "aclose"}),
}
_CREATE_TASK = frozenset({"asyncio.create_task", "create_task", "loop.create_task"})
_CONCURRENCY_IMPORTS = frozenset({"threading", "concurrent", "multiprocessing", "asyncio"})
_GRAPHQL_BLOCK = re.compile(
    r"\b(type|input|interface|enum)\s+([_A-Za-z][_0-9A-Za-z]*)[^{}]{0,4096}\{([^{}]{0,262144})\}",
    re.DOTALL)
_PROTO_BLOCK = re.compile(
    r"\b(message|service|enum)\s+([A-Za-z_]\w*)\s*\{([^{}]{0,262144})\}", re.DOTALL)
_DESTRUCTIVE_SQL = (
    ("drop-table", re.compile(r"\bDROP\s+TABLE\b", re.I)),
    ("drop-column", re.compile(r"\bDROP\s+COLUMN\b", re.I)),
    ("alter-column-type", re.compile(
        r"\bALTER\s+(?:COLUMN\s+)?[A-Za-z_]\w*\s+(?:TYPE|SET\s+DATA\s+TYPE)\b", re.I)),
    ("rename-schema-object", re.compile(r"\bRENAME\s+(?:COLUMN|TABLE|TO)\b", re.I)),
    ("set-not-null", re.compile(r"\b(?:SET\s+NOT\s+NULL|ADD\s+(?:COLUMN\s+)?"
                                r"[A-Za-z_]\w*[^;\n]{0,512}\bNOT\s+NULL\b"
                                r"(?![^;\n]*\bDEFAULT\b))", re.I)),
)


class DeepCorrectnessError(ValueError):
    """Input, budget, or evidence validation failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise DeepCorrectnessError("deep-correctness evidence must be bounded JSON") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _targets(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _targets(item)]
    return [node.id] if isinstance(node, ast.Name) else []


@dataclass(frozen=True)
class CorrectnessLimits:
    max_ast_nodes_per_file: int = 250_000
    max_contracts: int = 20_000
    max_evidence: int = 40_000
    max_findings: int = 20_000
    max_gaps: int = 20_000
    max_contract_fields: int = 5_000
    max_json_depth: int = 128

    def __post_init__(self) -> None:
        ranges = {
            "max_ast_nodes_per_file": (100, 2_000_000),
            "max_contracts": (1, 200_000), "max_evidence": (1, 400_000),
            "max_findings": (1, 200_000), "max_gaps": (1, 200_000),
            "max_contract_fields": (1, 50_000), "max_json_depth": (8, 512),
        }
        for name, (low, high) in ranges.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise DeepCorrectnessError(f"{name} must be an integer between {low} and {high}")


class _ReportStore:
    def __init__(self, limits: CorrectnessLimits):
        self.limits = limits
        self.evidence: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.gaps: list[dict[str, Any]] = []
        self._evidence_overflow = False
        self._finding_overflow = False
        self._gap_overflow = False

    def gap(self, reason: str, path: str = "", *, line: int = 1,
            adapter: str = "", detail: str = "") -> None:
        row: dict[str, Any] = {"reason": reason, "path": path, "line": max(1, int(line))}
        if adapter:
            row["adapter"] = adapter
        if detail:
            row["detail"] = detail[:512]
        if len(self.gaps) < self.limits.max_gaps:
            self.gaps.append(row)
        else:
            self._gap_overflow = True

    def add_evidence(self, kind: str, path: str, line: int, level: str,
                     detail: str, **extra: Any) -> str:
        body = {"kind": kind, "path": path, "line": max(1, int(line)),
                "analysis_level": level, "detail": detail[:1_000], **extra}
        identifier = "dc41-ev-" + _sha(body)[:24]
        if len(self.evidence) < self.limits.max_evidence:
            self.evidence.append({"id": identifier, **body})
        else:
            self._evidence_overflow = True
            return ""
        return identifier

    def add_finding(self, rule: str, severity: str, category: str, message: str,
                    path: str, line: int, evidence_ids: Iterable[str], *,
                    confidence: str, limitation: str) -> None:
        body = {"rule": rule, "severity": severity, "category": category,
                "message": message[:2_000], "path": path, "line": max(1, int(line)),
                "evidence_ids": sorted(set(filter(None, evidence_ids))),
                "confidence": confidence,
                "runtime_proven": False, "limitation": limitation[:2_000]}
        if len(self.findings) < self.limits.max_findings:
            self.findings.append({"id": "dc41-find-" + _sha(body)[:24], **body})
        else:
            self._finding_overflow = True

    def finish_gaps(self) -> None:
        if self._evidence_overflow:
            self.gap("evidence-budget-reached")
        if self._finding_overflow:
            self.gap("finding-budget-reached")
        if self._gap_overflow:
            marker = {"reason": "gap-budget-reached", "path": "", "line": 1}
            if self.gaps:
                self.gaps[-1] = marker
            else:
                self.gaps.append(marker)


def _bounded_public_rows(rows: Iterable[Any], maximum: int, store: _ReportStore,
                         reason: str, *, key: Callable[[Any], Any]) -> list[Any]:
    """Select a deterministic, bounded public prefix and record any omission."""
    selected: list[Any] = []
    for row in rows:
        if len(selected) >= maximum:
            store.gap(
                reason,
                detail=f"public collection limited to {maximum} rows; additional rows omitted")
            break
        selected.append(row)
    selected.sort(key=key)
    return selected


class _ScopeNodes(ast.NodeVisitor):
    def __init__(self, root: ast.AST):
        self.root = root
        self.nodes: list[ast.AST] = []

    def generic_visit(self, node: ast.AST) -> None:
        self.nodes.append(node)
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.nodes.append(node)
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.nodes.append(node)
        if node is self.root:
            self.visit(node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.nodes.append(node)


def _scope_nodes(root: ast.AST) -> list[ast.AST]:
    visitor = _ScopeNodes(root)
    if isinstance(root, ast.Module):
        visitor.nodes.append(root)
        for statement in root.body:
            visitor.visit(statement)
    else:
        visitor.visit(root)
    return visitor.nodes


def _scope_name(module: str, node: ast.AST) -> str:
    return module if isinstance(node, ast.Module) else module + "." + getattr(node, "name", "<scope>")


def _call(node: ast.AST | None) -> str:
    return _dotted(node.func) if isinstance(node, ast.Call) else ""


def _lock_base(call: ast.Call) -> tuple[str, str]:
    if not isinstance(call.func, ast.Attribute):
        return "", ""
    return _dotted(call.func.value), call.func.attr


def _context_lock_orders(statements: list[ast.stmt], held: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for statement in statements:
        current = held
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            acquired = tuple(filter(None, (_dotted(item.context_expr) for item in statement.items)))
            for right in acquired:
                for left in current:
                    if left != right:
                        result.append({"left": left, "right": right,
                                       "line": statement.lineno,
                                       "precision": "python-ast-nested-context"})
                current += (right,)
            result.extend(_context_lock_orders(statement.body, current))
            result.extend(_context_lock_orders(statement.orelse, held) if hasattr(statement, "orelse") else [])
            continue
        for field in ("body", "orelse", "finalbody"):
            body = getattr(statement, field, None)
            if isinstance(body, list) and not isinstance(
                    statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                result.extend(_context_lock_orders(body, held))
        if isinstance(statement, ast.Try):
            for handler in statement.handlers:
                result.extend(_context_lock_orders(handler.body, held))
    return result


def _resource_analysis(path: str, owner: str, nodes: list[ast.AST],
                       store: _ReportStore) -> list[dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    transactions: dict[str, dict[str, Any]] = {}
    escaped: set[str] = set()
    result: list[dict[str, Any]] = []
    ordered = sorted((node for node in nodes if hasattr(node, "lineno")),
                     key=lambda node: (getattr(node, "lineno", 1), type(node).__name__))
    for node in ordered:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = (node.targets if isinstance(node, ast.Assign) else [node.target])
            names = [name for target in targets for name in _targets(target)]
            factory = _call(value)
            kind = _RESOURCE_FACTORIES.get(factory)
            for name in names:
                if name in states:
                    previous = states[name]
                    ev = store.add_evidence(
                        "resource-overwrite", path, node.lineno, "python-ast-lexical-typestate",
                        "resource variable is overwritten before an observed closer",
                        owner=owner, resource=name, resource_kind=previous["kind"])
                    store.add_finding(
                        "resource/overwrite-before-close", "HIGH", "resource-typestate",
                        f"{previous['kind']} resource '{name}' is overwritten without an observed close.",
                        path, node.lineno, [previous["evidence_id"], ev],
                        confidence="strong-static-candidate",
                        limitation="Lexical typestate does not resolve aliases, exceptions, or framework ownership.")
                    del states[name]
                if kind:
                    ev = store.add_evidence(
                        "resource-open", path, node.lineno, "python-ast-lexical-typestate",
                        "resource-producing call assigned to a local name", owner=owner,
                        resource=name, resource_kind=kind, factory=factory)
                    states[name] = {"kind": kind, "line": node.lineno, "evidence_id": ev}
                    result.append({"owner": owner, "resource": name, "kind": kind,
                                   "open_line": node.lineno, "state": "open", "evidence_id": ev})
        if isinstance(node, ast.Return) and node.value is not None:
            escaped.update(part.id for part in ast.walk(node.value) if isinstance(part, ast.Name))
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        base, method = _lock_base(node)
        if base in states and method in _CLOSERS[states[base]["kind"]]:
            states.pop(base, None)
            for row in result:
                if row["resource"] == base and row["state"] == "open":
                    row["state"] = "closed"
                    row["close_line"] = node.lineno
        literal = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) \
            and isinstance(node.args[0].value, str) else ""
        known_database = (base in states and
                          states[base]["kind"] == "database-connection")
        if known_database and (method in {"begin", "begin_nested"} or
                               (method == "execute" and
                                re.match(r"\s*BEGIN\b", literal, re.I))):
            ev = store.add_evidence(
                "transaction-begin", path, node.lineno, "python-ast-literal-call",
                "explicit transaction begin was observed", owner=owner, resource=base)
            transactions[base] = {"line": node.lineno, "evidence_id": ev}
        elif method in {"commit", "rollback"}:
            transactions.pop(base, None)
    for name, state in sorted(states.items()):
        if name in escaped:
            for row in result:
                if row["resource"] == name and row["state"] == "open":
                    row["state"] = "escaped"
            continue
        ev = store.add_evidence(
            "resource-open-at-scope-exit", path, state["line"],
            "python-ast-lexical-typestate", "no recognized closer was observed in this scope",
            owner=owner, resource=name, resource_kind=state["kind"])
        store.add_finding(
            "resource/may-leak", "HIGH" if state["kind"] in {"socket", "process"} else "MEDIUM",
            "resource-typestate", f"{state['kind']} resource '{name}' may leave the scope open.",
            path, state["line"], [state["evidence_id"], ev],
            confidence="bounded-lexical-typestate-candidate",
            limitation="Aliases, implicit framework cleanup, exceptional paths, and runtime ownership are unresolved.")
    for name, state in sorted(transactions.items()):
        store.add_finding(
            "transaction/begin-without-terminal", "HIGH", "resource-typestate",
            f"Explicit transaction '{name}' has no observed commit or rollback in the same scope.",
            path, state["line"], [state["evidence_id"]],
            confidence="strong-static-candidate",
            limitation="Interprocedural transaction helpers and framework-managed completion are unresolved.")
    return result


def _python_analysis(item: snapshot41.SnapshotFile, limits: CorrectnessLimits,
                     store: _ReportStore) -> dict[str, Any]:
    text, replaced = item.text()
    if replaced:
        store.gap("invalid-utf8-replaced", item.path, adapter="python-ast")
    try:
        tree = ast.parse(text, filename=item.path, type_comments=True)
    except (SyntaxError, ValueError) as exc:
        store.gap("python-parse-error", item.path,
                  line=getattr(exc, "lineno", 1) or 1, adapter="python-ast")
        return {"path": item.path, "lock_orders": [], "resources": [],
                "global_writes": [], "async_checks": []}
    if sum(1 for _ in ast.walk(tree)) > limits.max_ast_nodes_per_file:
        store.gap("ast-node-budget", item.path, adapter="python-ast")
        return {"path": item.path, "lock_orders": [], "resources": [],
                "global_writes": [], "async_checks": []}
    module = ".".join(PurePosixPath(item.path).with_suffix("").parts)
    imports = {_dotted(alias) for alias in []}
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    scopes: list[ast.AST] = [tree]
    scopes.extend(node for node in ast.walk(tree)
                  if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
    lock_orders: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    global_writes: list[dict[str, Any]] = []
    async_checks: list[dict[str, Any]] = []
    for scope in scopes:
        owner = _scope_name(module, scope)
        nodes = _scope_nodes(scope)
        resources.extend(_resource_analysis(item.path, owner, nodes, store))
        body = getattr(scope, "body", [])
        if isinstance(body, list):
            for order in _context_lock_orders(body):
                ev = store.add_evidence(
                    "lock-order", item.path, order["line"], order["precision"],
                    "nested lock contexts establish a syntactic acquisition order",
                    owner=owner, left=order["left"], right=order["right"])
                lock_orders.append({"path": item.path, "owner": owner, **order,
                                    "evidence_id": ev})
        held: list[str] = []
        for node in sorted((node for node in nodes if isinstance(node, ast.Call)),
                           key=lambda row: (row.lineno, row.col_offset)):
            base, method = _lock_base(node)
            if not base or method not in {"acquire", "release"}:
                continue
            if method == "acquire":
                if base in held:
                    ev = store.add_evidence(
                        "lock-reacquire", item.path, node.lineno,
                        "python-ast-path-insensitive-call-order",
                        "the same syntactic lock expression is acquired while already held",
                        owner=owner, lock=base)
                    store.add_finding(
                        "concurrency/lock-reacquire-candidate", "HIGH", "concurrency",
                        f"Lock '{base}' is acquired again before an observed release.",
                        item.path, node.lineno, [ev], confidence="review-required",
                        limitation="The runtime object may be reentrant or control-flow may make the calls exclusive.")
                for left in held:
                    if left != base:
                        ev = store.add_evidence(
                            "lock-order", item.path, node.lineno,
                            "python-ast-path-insensitive-call-order",
                            "explicit acquire calls establish a lexical candidate order",
                            owner=owner, left=left, right=base)
                        lock_orders.append({"path": item.path, "owner": owner,
                                            "left": left, "right": base, "line": node.lineno,
                                            "precision": "python-ast-path-insensitive-call-order",
                                            "evidence_id": ev})
                held.append(base)
            elif base in held:
                held.remove(base)
            else:
                ev = store.add_evidence(
                    "lock-release-without-acquire", item.path, node.lineno,
                    "python-ast-path-insensitive-call-order",
                    "release call has no preceding acquire in this lexical scope",
                    owner=owner, lock=base)
                store.add_finding(
                    "concurrency/release-without-acquire", "MEDIUM", "concurrency",
                    f"Lock '{base}' is released without a preceding lexical acquire.",
                    item.path, node.lineno, [ev], confidence="review-required",
                    limitation="Branching, helper calls, and aliases can change runtime lock state.")
        for base in sorted(set(held)):
            first = next((node for node in nodes if isinstance(node, ast.Call)
                          and _lock_base(node) == (base, "acquire")), None)
            line_no = getattr(first, "lineno", 1)
            ev = store.add_evidence(
                "lock-held-at-scope-exit", item.path, line_no,
                "python-ast-path-insensitive-call-order",
                "no matching lexical release was observed", owner=owner, lock=base)
            store.add_finding(
                "concurrency/lock-may-remain-held", "HIGH", "concurrency",
                f"Lock '{base}' may remain held when the scope exits.", item.path, line_no,
                [ev], confidence="bounded-lexical-candidate",
                limitation="Control-flow feasibility, context managers, aliases, and helper releases are unresolved.")
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            declared = {name for node in nodes if isinstance(node, ast.Global) for name in node.names}
            for node in nodes:
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in declared:
                    ev = store.add_evidence(
                        "global-write", item.path, node.lineno, "python-ast-name-binding",
                        "function writes a name declared global", owner=owner, symbol=node.id)
                    global_writes.append({"symbol": node.id, "owner": owner,
                                          "path": item.path, "line": node.lineno,
                                          "evidence_id": ev})
        if isinstance(scope, ast.AsyncFunctionDef):
            assigned_tasks: dict[str, tuple[int, str]] = {}
            handled: set[str] = set()
            for node in nodes:
                if isinstance(node, ast.Expr) and _call(node.value) in _CREATE_TASK:
                    ev = store.add_evidence(
                        "discarded-task", item.path, node.lineno, "python-ast",
                        "create_task result is discarded", owner=owner)
                    store.add_finding(
                        "async/discarded-task-handle", "MEDIUM", "async-cancellation",
                        "Created task handle is discarded; cancellation and exceptions need ownership.",
                        item.path, node.lineno, [ev], confidence="parser-observed",
                        limitation="A framework task factory may deliberately retain the task.")
                    async_checks.append({"owner": owner, "kind": "discarded-task",
                                         "line": node.lineno, "evidence_id": ev})
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and _call(node.value) in _CREATE_TASK:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for name in _targets(target):
                            ev = store.add_evidence(
                                "task-created", item.path, node.lineno, "python-ast",
                                "create_task result assigned to a local name", owner=owner, task=name)
                            assigned_tasks[name] = (node.lineno, ev)
                if isinstance(node, ast.Await):
                    handled.update(part.id for part in ast.walk(node.value) if isinstance(part, ast.Name))
                if isinstance(node, ast.Call):
                    base, method = _lock_base(node)
                    if method in {"cancel", "result", "exception"}:
                        handled.add(base)
                    if _dotted(node.func) in {"asyncio.gather", "gather", "asyncio.wait", "wait"}:
                        handled.update(part.id for arg in node.args for part in ast.walk(arg)
                                       if isinstance(part, ast.Name))
                if isinstance(node, ast.ExceptHandler):
                    caught = _dotted(node.type)
                    if caught.endswith("CancelledError") and not any(
                            isinstance(part, ast.Raise) for statement in node.body
                            for part in ast.walk(statement)):
                        ev = store.add_evidence(
                            "cancellation-swallowed", item.path, node.lineno, "python-ast",
                            "CancelledError handler has no raise statement", owner=owner)
                        store.add_finding(
                            "async/cancellation-swallowed", "HIGH", "async-cancellation",
                            "Cancellation is caught without an observed re-raise.", item.path,
                            node.lineno, [ev], confidence="strong-static-candidate",
                            limitation="The handler may translate cancellation through an unresolved helper.")
            for name, (line_no, ev) in sorted(assigned_tasks.items()):
                if name not in handled:
                    store.add_finding(
                        "async/task-lifecycle-unobserved", "MEDIUM", "async-cancellation",
                        f"Task '{name}' is not awaited, cancelled, gathered, or inspected in this scope.",
                        item.path, line_no, [ev], confidence="bounded-parser-candidate",
                        limitation="Task ownership may escape through aliases, containers, or helper calls.")
    concurrency_possible = bool(imports & _CONCURRENCY_IMPORTS or
                                any(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(tree)))
    if concurrency_possible:
        by_symbol: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in global_writes:
            by_symbol[row["symbol"]].append(row)
        for symbol, rows in sorted(by_symbol.items()):
            owners = {row["owner"] for row in rows}
            if len(owners) < 2:
                continue
            first = sorted(rows, key=lambda row: (row["path"], row["line"]))[0]
            store.add_finding(
                "concurrency/shared-global-write-race-candidate", "HIGH", "concurrency",
                f"Global '{symbol}' is written by multiple concurrency-capable functions.",
                item.path, first["line"], [row["evidence_id"] for row in rows],
                confidence="review-required-race-candidate",
                limitation="Static syntax does not prove simultaneous execution or absence of synchronization.")
    return {"path": item.path, "lock_orders": lock_orders, "resources": resources,
            "global_writes": global_writes, "async_checks": async_checks}


def _json_depth(value: Any, maximum: int) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise DeepCorrectnessError("JSON nesting depth budget exceeded")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _json_load(text: str, maximum_depth: int) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DeepCorrectnessError("duplicate JSON object key")
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=unique)
    _json_depth(value, maximum_depth)
    return value


def _schema_signature(document: Mapping[str, Any], maximum: int) -> dict[str, Any]:
    properties = document.get("properties", {})
    fields: dict[str, Any] = {}
    if isinstance(properties, Mapping):
        for name, value in sorted(properties.items(), key=lambda pair: str(pair[0]))[:maximum]:
            if isinstance(name, str) and isinstance(value, Mapping):
                fields[name] = {"type": value.get("type", "unspecified"),
                                "enum": value.get("enum", []) if isinstance(value.get("enum"), list) else []}
    required = document.get("required", [])
    return {"fields": fields,
            "required": sorted(item for item in required if isinstance(item, str))[:maximum]
            if isinstance(required, list) else [],
            "type": document.get("type", "unspecified")}


def _add_contract(contracts: dict[str, dict[str, Any]], store: _ReportStore,
                  limits: CorrectnessLimits, *, key: str, kind: str, path: str,
                  name: str, line: int, level: str, signature: Mapping[str, Any]) -> None:
    if len(contracts) >= limits.max_contracts:
        store.gap("contract-budget-reached", path, line=line)
        return
    if key in contracts:
        store.gap("duplicate-contract-identity", path, line=line, adapter=level,
                  detail=key)
        return
    signature_copy = json.loads(_canonical(signature).decode("utf-8"))
    signature_sha256 = _sha(signature_copy)
    ev = store.add_evidence("contract", path, line, level,
                            "bounded contract signature extracted", contract_kind=kind, name=name,
                            signature_sha256=signature_sha256)
    contracts[key] = {"key": key, "kind": kind, "path": path, "name": name,
                      "line": line, "analysis_level": level,
                      "signature": signature_copy, "signature_sha256": signature_sha256,
                      "evidence_id": ev}


def _json_contracts(item: snapshot41.SnapshotFile, limits: CorrectnessLimits,
                    store: _ReportStore, contracts: dict[str, dict[str, Any]]) -> None:
    text, replaced = item.text()
    if replaced:
        store.gap("invalid-utf8-replaced", item.path, adapter="json-parser")
    try:
        value = _json_load(text, limits.max_json_depth)
    except (json.JSONDecodeError, DeepCorrectnessError) as exc:
        store.gap("json-contract-parse-error", item.path,
                  line=getattr(exc, "lineno", 1) or 1, adapter="json-parser",
                  detail=type(exc).__name__)
        return
    if not isinstance(value, Mapping):
        return
    if isinstance(value.get("openapi"), str) or isinstance(value.get("swagger"), str):
        paths = value.get("paths", {})
        if isinstance(paths, Mapping):
            for route, path_item in sorted(paths.items(), key=lambda pair: str(pair[0])):
                if not isinstance(route, str) or not isinstance(path_item, Mapping):
                    continue
                inherited = path_item.get("parameters", [])
                for method, operation in sorted(path_item.items(), key=lambda pair: str(pair[0])):
                    if str(method).casefold() not in _HTTP_METHODS or not isinstance(operation, Mapping):
                        continue
                    parameters = []
                    raw_parameters = [*(inherited if isinstance(inherited, list) else []),
                                      *(operation.get("parameters", [])
                                        if isinstance(operation.get("parameters"), list) else [])]
                    for parameter in raw_parameters[:limits.max_contract_fields]:
                        if not isinstance(parameter, Mapping):
                            continue
                        schema = parameter.get("schema", {})
                        parameters.append({"name": parameter.get("name", ""),
                                           "in": parameter.get("in", ""),
                                           "required": parameter.get("required") is True,
                                           "type": schema.get("type", "unspecified")
                                           if isinstance(schema, Mapping) else "unspecified"})
                    responses = operation.get("responses", {})
                    signature = {
                        "parameters": sorted(parameters, key=lambda row: (str(row["in"]), str(row["name"]))),
                        "request_required": isinstance(operation.get("requestBody"), Mapping)
                        and operation["requestBody"].get("required") is True,
                        "responses": sorted(str(code) for code in responses)
                        if isinstance(responses, Mapping) else [],
                    }
                    name = str(method).upper() + " " + route
                    _add_contract(contracts, store, limits, key="openapi-operation:" + name,
                                  kind="openapi-operation", path=item.path, name=name,
                                  line=1, level="json-parser-structural", signature=signature)
        components = value.get("components", {})
        schemas = components.get("schemas", {}) if isinstance(components, Mapping) else {}
        if isinstance(schemas, Mapping):
            for name, document in sorted(schemas.items(), key=lambda pair: str(pair[0])):
                if isinstance(name, str) and isinstance(document, Mapping):
                    _add_contract(contracts, store, limits,
                                  key="openapi-schema:" + name, kind="openapi-schema",
                                  path=item.path, name=name, line=1,
                                  level="json-parser-structural",
                                  signature=_schema_signature(document, limits.max_contract_fields))
        if "$ref" in text:
            store.gap("openapi-ref-resolution-not-performed", item.path,
                      adapter="json-parser-structural")
        return
    if value.get("type") == "record" and isinstance(value.get("name"), str):
        fields: dict[str, Any] = {}
        for field in value.get("fields", [])[:limits.max_contract_fields] \
                if isinstance(value.get("fields"), list) else []:
            if isinstance(field, Mapping) and isinstance(field.get("name"), str):
                fields[field["name"]] = {"type": field.get("type"),
                                         "has_default": "default" in field}
        _add_contract(contracts, store, limits, key="avro-record:" + value["name"],
                      kind="avro-record", path=item.path, name=value["name"], line=1,
                      level="json-parser-structural", signature={"fields": fields})
    elif ("$schema" in value or value.get("type") == "object" or
          isinstance(value.get("properties"), Mapping)):
        name = str(value.get("title") or PurePosixPath(item.path).stem)
        _add_contract(contracts, store, limits, key="json-schema:" + name,
                      kind="json-schema", path=item.path, name=name, line=1,
                      level="json-parser-structural",
                      signature=_schema_signature(value, limits.max_contract_fields))


def _strip_lexical_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"(?m)(?://|#).*?$", "", text)


def _graphql_contracts(item: snapshot41.SnapshotFile, limits: CorrectnessLimits,
                       store: _ReportStore, contracts: dict[str, dict[str, Any]]) -> None:
    text, replaced = item.text()
    if replaced:
        store.gap("invalid-utf8-replaced", item.path, adapter="graphql-lexical")
    clean = _strip_lexical_comments(text)
    matched = False
    for match in _GRAPHQL_BLOCK.finditer(clean):
        matched = True
        kind, name, body = match.groups()
        if kind == "enum":
            values = sorted(set(re.findall(r"(?m)^\s*([_A-Za-z][_0-9A-Za-z]*)\b", body)))
            signature: dict[str, Any] = {"values": values[:limits.max_contract_fields]}
        else:
            fields: dict[str, Any] = {}
            for raw in body.splitlines()[:limits.max_contract_fields]:
                field = re.match(r"\s*([_A-Za-z]\w*)\s*(?:\((.*?)\))?\s*:\s*([^#]+)", raw)
                if not field:
                    continue
                field_name, arguments, type_name = field.groups()
                args: dict[str, Any] = {}
                for fragment in (arguments or "").split(",")[:limits.max_contract_fields]:
                    argument = re.match(r"\s*([_A-Za-z]\w*)\s*:\s*([^=]+?)(?:\s*=.*)?$", fragment)
                    if argument:
                        arg_name, arg_type = argument.groups()
                        args[arg_name] = {"type": " ".join(arg_type.split()),
                                          "required": "!" in arg_type and "=" not in fragment}
                fields[field_name] = {"type": " ".join(type_name.split()), "args": args}
            signature = {"fields": fields}
        _add_contract(contracts, store, limits, key=f"graphql-{kind}:{name}",
                      kind=f"graphql-{kind}", path=item.path, name=name,
                      line=_line(clean, match.start()), level="bounded-graphql-lexical-signature",
                      signature=signature)
    if not matched and clean.strip():
        store.gap("graphql-signature-unparsed", item.path, adapter="graphql-lexical")


def _proto_contracts(item: snapshot41.SnapshotFile, limits: CorrectnessLimits,
                     store: _ReportStore, contracts: dict[str, dict[str, Any]]) -> None:
    text, replaced = item.text()
    if replaced:
        store.gap("invalid-utf8-replaced", item.path, adapter="protobuf-lexical")
    clean = _strip_lexical_comments(text)
    matched = False
    for match in _PROTO_BLOCK.finditer(clean):
        matched = True
        kind, name, body = match.groups()
        if kind == "message":
            fields: dict[str, Any] = {}
            pattern = re.compile(r"\b(optional|required|repeated)?\s*([.A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)"
                                 r"\s+([A-Za-z_]\w*)\s*=\s*(\d+)\b")
            for field in list(pattern.finditer(body))[:limits.max_contract_fields]:
                label, type_name, field_name, number = field.groups()
                fields[number] = {"name": field_name, "type": type_name,
                                  "label": label or "implicit"}
            signature: dict[str, Any] = {"fields": fields}
        elif kind == "service":
            rpcs = {rpc.group(1): {"request": rpc.group(2), "response": rpc.group(3)}
                    for rpc in re.finditer(
                        r"\brpc\s+([A-Za-z_]\w*)\s*\(\s*([^)]*?)\s*\)\s*returns\s*"
                        r"\(\s*([^)]*?)\s*\)", body)}
            signature = {"rpcs": dict(sorted(rpcs.items()))}
        else:
            values = {row.group(1): int(row.group(2)) for row in re.finditer(
                r"\b([A-Za-z_]\w*)\s*=\s*(-?\d+)\b", body)}
            signature = {"values": dict(sorted(values.items()))}
        _add_contract(contracts, store, limits, key=f"protobuf-{kind}:{name}",
                      kind=f"protobuf-{kind}", path=item.path, name=name,
                      line=_line(clean, match.start()), level="bounded-protobuf-lexical-signature",
                      signature=signature)
    if not matched and clean.strip():
        store.gap("protobuf-signature-unparsed", item.path, adapter="protobuf-lexical")


def _contracts(snapshot: snapshot41.SourceSnapshot, limits: CorrectnessLimits,
               store: _ReportStore) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in snapshot.files:
        if item.language == "json" or item.language == "avro":
            _json_contracts(item, limits, store, result)
        elif item.language == "graphql":
            _graphql_contracts(item, limits, store, result)
        elif item.language == "protobuf":
            _proto_contracts(item, limits, store, result)
    return result


def _compat_finding(store: _ReportStore, rule: str, message: str,
                    old: Mapping[str, Any], new: Mapping[str, Any] | None = None,
                    *, severity: str = "HIGH") -> dict[str, Any]:
    evidence = [str(old.get("evidence_id", ""))]
    if new:
        evidence.append(str(new.get("evidence_id", "")))
    path = str((new or old).get("path", ""))
    line = int((new or old).get("line", 1))
    store.add_finding(
        rule, severity, "compatibility", message, path, line, evidence,
        confidence="parser-or-bounded-signature-change-observed",
        limitation="Consumer usage, negotiated versions, deployment order, and runtime behavior were not observed.")
    return {"rule": rule, "path": path, "line": line, "message": message,
            "breaking_proven": False, "evidence_ids": sorted(set(filter(None, evidence)))}


def _compare_contracts(old: Mapping[str, dict[str, Any]], new: Mapping[str, dict[str, Any]],
                       store: _ReportStore) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for key in sorted(set(old) - set(new)):
        row = old[key]
        changes.append(_compat_finding(
            store, "compatibility/contract-removed",
            f"{row['kind']} contract '{row['name']}' is absent from the current snapshot.", row))
    for key in sorted(set(old) & set(new)):
        before, after = old[key], new[key]
        a = before["signature"]
        b = after["signature"]
        kind = before["kind"]
        if kind == "openapi-operation":
            old_params = {(str(row.get("in")), str(row.get("name"))): row
                          for row in a.get("parameters", []) if isinstance(row, Mapping)}
            new_params = {(str(row.get("in")), str(row.get("name"))): row
                          for row in b.get("parameters", []) if isinstance(row, Mapping)}
            for parameter in sorted(set(new_params) - set(old_params)):
                if new_params[parameter].get("required"):
                    changes.append(_compat_finding(
                        store, "compatibility/openapi-required-parameter-added",
                        f"Required OpenAPI parameter '{parameter[1]}' was added to {before['name']}.",
                        before, after))
            if not a.get("request_required") and b.get("request_required"):
                changes.append(_compat_finding(
                    store, "compatibility/openapi-request-body-became-required",
                    f"Request body became required for {before['name']}.", before, after))
            removed_success = {code for code in a.get("responses", []) if str(code).startswith("2")} - \
                {code for code in b.get("responses", []) if str(code).startswith("2")}
            if removed_success:
                changes.append(_compat_finding(
                    store, "compatibility/openapi-success-response-removed",
                    f"Successful response codes were removed from {before['name']}: "
                    f"{', '.join(sorted(removed_success))}.", before, after))
        if kind in {"openapi-schema", "json-schema"}:
            old_fields, new_fields = a.get("fields", {}), b.get("fields", {})
            for field in sorted(set(old_fields) - set(new_fields)):
                changes.append(_compat_finding(
                    store, "compatibility/schema-property-removed",
                    f"Schema property '{field}' was removed from {before['name']}.", before, after))
            for field in sorted(set(old_fields) & set(new_fields)):
                if old_fields[field].get("type") != new_fields[field].get("type"):
                    changes.append(_compat_finding(
                        store, "compatibility/schema-property-type-changed",
                        f"Schema property '{field}' changed type in {before['name']}.", before, after))
                old_enum = {_canonical(value) for value in old_fields[field].get("enum", [])}
                new_enum = {_canonical(value) for value in new_fields[field].get("enum", [])}
                removed_enum = old_enum - new_enum
                if removed_enum:
                    changes.append(_compat_finding(
                        store, "compatibility/schema-enum-narrowed",
                        f"Schema property '{field}' removed accepted enum values.", before, after))
            for field in sorted(set(b.get("required", [])) - set(a.get("required", []))):
                changes.append(_compat_finding(
                    store, "compatibility/schema-required-property-added",
                    f"Property '{field}' became required in {before['name']}.", before, after))
        if kind == "avro-record":
            old_fields, new_fields = a.get("fields", {}), b.get("fields", {})
            for field in sorted(set(old_fields) - set(new_fields)):
                changes.append(_compat_finding(
                    store, "compatibility/avro-field-removed",
                    f"Avro field '{field}' was removed from {before['name']}.", before, after))
            for field in sorted(set(new_fields) - set(old_fields)):
                if not new_fields[field].get("has_default"):
                    changes.append(_compat_finding(
                        store, "compatibility/avro-field-added-without-default",
                        f"Avro field '{field}' was added without a default.", before, after))
            for field in sorted(set(old_fields) & set(new_fields)):
                if old_fields[field].get("type") != new_fields[field].get("type"):
                    changes.append(_compat_finding(
                        store, "compatibility/avro-field-type-changed",
                        f"Avro field '{field}' changed type.", before, after))
        if kind.startswith("graphql-"):
            if kind == "graphql-enum":
                removed = set(a.get("values", [])) - set(b.get("values", []))
                if removed:
                    changes.append(_compat_finding(
                        store, "compatibility/graphql-enum-value-removed",
                        f"GraphQL enum {before['name']} removed: {', '.join(sorted(removed))}.",
                        before, after))
            else:
                old_fields, new_fields = a.get("fields", {}), b.get("fields", {})
                for field in sorted(set(old_fields) - set(new_fields)):
                    changes.append(_compat_finding(
                        store, "compatibility/graphql-field-removed",
                        f"GraphQL field '{field}' was removed from {before['name']}.", before, after))
                if kind == "graphql-input":
                    for field in sorted(set(new_fields) - set(old_fields)):
                        if "!" in str(new_fields[field].get("type", "")):
                            changes.append(_compat_finding(
                                store, "compatibility/graphql-required-input-added",
                                f"Required GraphQL input field '{field}' was added.", before, after))
                for field in sorted(set(old_fields) & set(new_fields)):
                    if old_fields[field].get("type") != new_fields[field].get("type"):
                        changes.append(_compat_finding(
                            store, "compatibility/graphql-field-type-changed",
                            f"GraphQL field '{field}' changed type.", before, after))
                    old_args = old_fields[field].get("args", {})
                    new_args = new_fields[field].get("args", {})
                    for argument in sorted(set(new_args) - set(old_args)):
                        if new_args[argument].get("required"):
                            changes.append(_compat_finding(
                                store, "compatibility/graphql-required-argument-added",
                                f"Required argument '{argument}' was added to field '{field}'.",
                                before, after))
                    for argument in sorted(set(old_args) & set(new_args)):
                        if (not old_args[argument].get("required") and
                                new_args[argument].get("required")):
                            changes.append(_compat_finding(
                                store, "compatibility/graphql-argument-became-required",
                                f"Argument '{argument}' became required on field '{field}'.",
                                before, after))
                        if old_args[argument].get("type") != new_args[argument].get("type"):
                            changes.append(_compat_finding(
                                store, "compatibility/graphql-argument-type-changed",
                                f"Argument '{argument}' changed type on field '{field}'.",
                                before, after))
        if kind == "protobuf-message":
            old_fields, new_fields = a.get("fields", {}), b.get("fields", {})
            for number in sorted(set(old_fields) - set(new_fields), key=lambda value: int(value)):
                changes.append(_compat_finding(
                    store, "compatibility/protobuf-field-number-removed",
                    f"Protobuf field number {number} ({old_fields[number]['name']}) was removed.",
                    before, after))
            for number in sorted(set(old_fields) & set(new_fields), key=lambda value: int(value)):
                if (old_fields[number].get("name"), old_fields[number].get("type")) != \
                        (new_fields[number].get("name"), new_fields[number].get("type")):
                    changes.append(_compat_finding(
                        store, "compatibility/protobuf-field-number-reused",
                        f"Protobuf field number {number} changed name or type.", before, after))
            for number in sorted(set(new_fields) - set(old_fields), key=lambda value: int(value)):
                if new_fields[number].get("label") == "required":
                    changes.append(_compat_finding(
                        store, "compatibility/protobuf-required-field-added",
                        f"Required Protobuf field {number} was added.", before, after))
        if kind == "protobuf-service":
            for rpc in sorted(set(a.get("rpcs", {})) - set(b.get("rpcs", {}))):
                changes.append(_compat_finding(
                    store, "compatibility/protobuf-rpc-removed",
                    f"Protobuf RPC '{rpc}' was removed from {before['name']}.", before, after))
    return changes


def _migration_analysis(snapshot: snapshot41.SourceSnapshot,
                        baseline: snapshot41.SourceSnapshot | None,
                        store: _ReportStore) -> list[dict[str, Any]]:
    current_paths = {item.path for item in snapshot.files}
    old_signatures: set[tuple[str, str, int]] = set()
    if baseline:
        for item in baseline.files:
            if item.language != "sql":
                continue
            text, _ = item.text()
            forward = re.split(r"(?mi)^\s*--\s*(?:down|rollback)\b", text, maxsplit=1)[0]
            for kind, pattern in _DESTRUCTIVE_SQL:
                old_signatures.update((item.path, kind, _line(forward, match.start()))
                                      for match in pattern.finditer(forward))
    rows: list[dict[str, Any]] = []
    for item in snapshot.files:
        if item.language != "sql" or item.path.casefold().endswith(".down.sql"):
            continue
        text, replaced = item.text()
        if replaced:
            store.gap("invalid-utf8-replaced", item.path, adapter="sql-lexical")
        down_section = re.search(r"(?mi)^\s*--\s*(?:down|rollback)\b", text)
        forward = text[:down_section.start()] if down_section else text
        rollback = (down_section is not None or
                    (item.path.casefold().endswith(".up.sql") and
                     item.path[:-7] + ".down.sql" in current_paths))
        transaction = bool(re.search(r"\b(?:BEGIN|START\s+TRANSACTION)\b", forward, re.I))
        for kind, pattern in _DESTRUCTIVE_SQL:
            for match in pattern.finditer(forward):
                line_no = _line(forward, match.start())
                if baseline and (item.path, kind, line_no) in old_signatures:
                    continue
                ev = store.add_evidence(
                    "migration-operation", item.path, line_no, "bounded-sql-lexical",
                    "destructive or compatibility-sensitive SQL token shape observed",
                    operation=kind, rollback_observed=rollback,
                    transaction_observed=transaction)
                row = {"path": item.path, "line": line_no, "operation": kind,
                       "analysis_level": "bounded-sql-lexical",
                       "rollback_observed": rollback,
                       "transaction_observed": transaction, "evidence_id": ev,
                       "execution_performed": False}
                rows.append(row)
                store.add_finding(
                    "migration/" + kind, "HIGH", "migration",
                    f"New or unbaselined migration contains {kind.replace('-', ' ')}; "
                    "expand/contract compatibility requires review.", item.path, line_no, [ev],
                    confidence="bounded-lexical-candidate",
                    limitation="SQL dialect, data distribution, lock duration, and deployment ordering are unresolved.")
                if not rollback:
                    store.add_finding(
                        "migration/rollback-evidence-missing", "MEDIUM", "migration",
                        "No paired .down.sql file or explicit rollback section was observed.",
                        item.path, line_no, [ev], confidence="bounded-file-evidence",
                        limitation="Rollback may be implemented by an external migration framework.")
    return rows


def analyze(snapshot: snapshot41.SourceSnapshot | str | Path, *,
            baseline: snapshot41.SourceSnapshot | str | Path | None = None,
            limits: CorrectnessLimits | None = None) -> dict[str, Any]:
    """Analyze one immutable snapshot, optionally against an immutable baseline."""
    limits = limits or CorrectnessLimits()
    if not isinstance(snapshot, snapshot41.SourceSnapshot):
        snapshot = snapshot41.capture(snapshot)
    if baseline is not None and not isinstance(baseline, snapshot41.SourceSnapshot):
        baseline = snapshot41.capture(baseline)
    store = _ReportStore(limits)
    for gap in snapshot.gaps:
        store.gap("snapshot-" + str(gap.get("reason", "coverage-gap")),
                  str(gap.get("path", "")), detail=str(gap.get("detail", "")))
    if baseline:
        for gap in baseline.gaps:
            store.gap("baseline-snapshot-" + str(gap.get("reason", "coverage-gap")),
                      str(gap.get("path", "")), detail=str(gap.get("detail", "")))
    python_rows = [_python_analysis(item, limits, store) for item in snapshot.files
                   if item.language == "python"]
    lock_orders = _bounded_public_rows(
        (row for file in python_rows for row in file["lock_orders"]),
        limits.max_evidence, store, "concurrency-lock-order-budget-reached",
        key=lambda row: (row["path"], row["line"], row["owner"],
                         row["left"], row["right"]))
    by_pair: dict[tuple[tuple[str, str], tuple[str, str]],
                  list[dict[str, Any]]] = defaultdict(list)
    for row in lock_orders:
        by_pair[((row["path"], row["left"]),
                 (row["path"], row["right"]))].append(row)
    emitted: set[tuple[tuple[str, str], tuple[str, str]]] = set()
    deadlocks: list[dict[str, Any]] = []
    for (left_id, right_id), rows in sorted(by_pair.items()):
        pair = tuple(sorted((left_id, right_id)))
        reverse = by_pair.get((right_id, left_id), [])
        if not reverse or pair in emitted:
            continue
        emitted.add(pair)
        left, right = left_id[1], right_id[1]
        evidence = sorted(set(row["evidence_id"] for row in [*rows, *reverse]
                              if row.get("evidence_id")))
        first = sorted([*rows, *reverse], key=lambda row: (row["path"], row["line"]))[0]
        store.add_finding(
            "concurrency/inconsistent-lock-order", "HIGH", "concurrency",
            f"Locks '{left}' and '{right}' have reverse syntactic acquisition orders.",
            first["path"], first["line"], evidence,
            confidence="strong-static-deadlock-candidate",
            limitation="Name identity, path concurrency, reentrancy, and runtime scheduling are not proven.")
        deadlocks.append({"locks": sorted((left, right)), "locations": [
            {"path": row["path"], "line": row["line"], "owner": row["owner"],
             "precision": row["precision"]} for row in sorted(
                 [*rows, *reverse], key=lambda row: (row["path"], row["line"], row["owner"]))],
                           "evidence_ids": evidence, "deadlock_proven": False})
    deadlocks_public = _bounded_public_rows(
        deadlocks, limits.max_findings, store,
        "concurrency-deadlock-candidate-budget-reached",
        key=lambda row: tuple(row["locks"]))
    for index, candidate in enumerate(deadlocks_public):
        public_candidate = dict(candidate)
        public_candidate["locations"] = _bounded_public_rows(
            candidate["locations"], limits.max_evidence, store,
            "concurrency-deadlock-location-budget-reached",
            key=lambda row: (row["path"], row["line"], row["owner"]))
        public_candidate["evidence_ids"] = _bounded_public_rows(
            candidate["evidence_ids"], limits.max_evidence, store,
            "concurrency-deadlock-evidence-budget-reached", key=str)
        deadlocks_public[index] = public_candidate
    current_contracts = _contracts(snapshot, limits, store)
    baseline_contracts: dict[str, dict[str, Any]] = {}
    if baseline:
        baseline_contracts = _contracts(baseline, limits, store)
        compatibility_changes = _compare_contracts(baseline_contracts, current_contracts, store)
    else:
        compatibility_changes = []
        store.gap("compatibility-baseline-not-supplied")
    migrations = _migration_analysis(snapshot, baseline, store)
    global_writes_public = _bounded_public_rows(
        (row for file in python_rows for row in file["global_writes"]),
        limits.max_evidence, store, "concurrency-global-write-budget-reached",
        key=lambda row: (row["path"], row["line"], row["owner"], row["symbol"]))
    resource_states_public = _bounded_public_rows(
        (row for file in python_rows for row in file["resources"]),
        limits.max_evidence, store, "resource-state-budget-reached",
        key=lambda row: (row.get("path", ""), row.get("line", row.get("open_line", 1)),
                         row["owner"], row["resource"]))
    contracts_public = _bounded_public_rows(
        ({key: value for key, value in row.items() if key != "signature"}
         for row in current_contracts.values()),
        min(limits.max_contracts, limits.max_evidence), store,
        "compatibility-contract-budget-reached",
        key=lambda row: (row["kind"], row["name"], row["path"]))
    compatibility_changes_public = _bounded_public_rows(
        compatibility_changes, limits.max_findings, store,
        "compatibility-change-budget-reached",
        key=lambda row: (row["path"], row["line"], row["rule"], row["message"]))
    for index, change in enumerate(compatibility_changes_public):
        public_change = dict(change)
        public_change["evidence_ids"] = _bounded_public_rows(
            change.get("evidence_ids", []), limits.max_evidence, store,
            "compatibility-change-evidence-budget-reached", key=str)
        compatibility_changes_public[index] = public_change
    migrations_public = _bounded_public_rows(
        migrations, limits.max_evidence, store, "migration-operation-budget-reached",
        key=lambda row: (row["path"], row["line"], row["operation"]))
    store.finish_gaps()
    evidence = sorted({row["id"]: row for row in store.evidence}.values(),
                      key=lambda row: (row["path"], row["line"], row["kind"], row["id"]))
    findings = sorted({row["id"]: row for row in store.findings}.values(),
                      key=lambda row: (row["path"], row["line"], row["rule"], row["id"]))
    gaps = sorted({_canonical(row): row for row in store.gaps}.values(),
                  key=lambda row: (row["path"], row["line"], row["reason"]))
    body = {
        "schema": SCHEMA, "version": VERSION,
        "analysis_level": "mixed-parser-derived-and-explicit-bounded-lexical",
        "snapshot_sha256": snapshot.snapshot_sha256,
        "baseline_snapshot_sha256": baseline.snapshot_sha256 if baseline else "",
        "summary": {"findings": len(findings), "evidence": len(evidence),
                    "deadlock_candidates": len(deadlocks_public),
                    "resource_states": len(resource_states_public),
                    "contracts": len(contracts_public),
                    "compatibility_changes": len(compatibility_changes_public),
                    "migration_candidates": len(migrations_public)},
        "concurrency": {
            "analysis_level": "python-ast-syntactic-and-path-insensitive-typestate",
            "lock_orders": lock_orders,
            "deadlock_candidates": deadlocks_public,
            "global_writes": global_writes_public,
            "runtime_deadlocks_or_races_proven": False,
        },
        "resources": {
            "analysis_level": "python-ast-lexical-typestate",
            "states": resource_states_public,
            "runtime_leaks_proven": False,
        },
        "compatibility": {
            "comparison_performed": baseline is not None,
            "analysis_levels": ["json-parser-structural",
                                "bounded-graphql-lexical-signature",
                                "bounded-protobuf-lexical-signature"],
            "contracts": contracts_public, "changes": compatibility_changes_public,
            "breaking_changes_proven": False,
        },
        "migrations": {"analysis_level": "bounded-sql-lexical",
                       "operations": migrations_public,
                       "database_or_migration_executed": False},
        "findings": findings, "evidence": evidence,
        "coverage": {
            "complete_within_declared_static_adapters": not gaps,
            "semantic_complete": False, "gaps": gaps,
            "limitations": [
                "Static name identity does not prove runtime object identity or scheduling.",
                "Python resource typestate is lexical, path-insensitive, and bounded to one scope.",
                "GraphQL, Protobuf, and SQL adapters do not invoke reference compilers or databases.",
                "Compatibility candidates do not observe consumers, negotiated versions, or deployment order.",
            ],
        },
        "limits": {name: getattr(limits, name) for name in limits.__dataclass_fields__},
        "static_contract": {"target_code_executed": False,
                            "target_modules_imported": False,
                            "compiler_invoked": False, "database_accessed": False,
                            "migration_executed": False, "processes_started": False,
                            "network_accessed": False, "filesystem_writes": False},
    }
    body["report_sha256"] = _sha(body)
    return body


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    if type(report) is not dict:
        return False, ["report is not a JSON object"]
    errors: list[str] = []
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        errors.append("unsupported deep-correctness schema or version")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        if report.get("report_sha256") != _sha(body):
            errors.append("report digest mismatch")
    except DeepCorrectnessError:
        errors.append("report is not canonical JSON")
    return not errors, errors


scan = analyze
