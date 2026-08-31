#!/usr/bin/env python3
"""Inter-procedural dataflow -- cross-function taint propagation.

Builds a call graph across an entire project, computes per-function taint
summaries, and propagates taint through call boundaries to find source-to-sink
flows that span multiple functions.

    index = build_index(["src/"])
    graph = build_call_graph(index)
    findings = analyze(index, graph)
"""
from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".tox", ".mypy_cache"}

_SOURCE_PATTERNS = {
    "request.args",     "request.form",     "request.data",
    "request.json",     "request.values",   "request.files",
    "request.headers",  "request.cookies",
    "input(",           "sys.stdin",        "os.environ",
    "raw_input(",       "argv",
}

_SOURCE_CALLS = re.compile(
    r"\b(request\.\w+\.get|request\.get_json|input|raw_input)\s*\(")

_SINK_MAP = {
    "os.system":             ("CWE-78",  "command_injection",   "CRITICAL"),
    "os.popen":              ("CWE-78",  "command_injection",   "CRITICAL"),
    "subprocess.call":       ("CWE-78",  "command_injection",   "HIGH"),
    "subprocess.run":        ("CWE-78",  "command_injection",   "HIGH"),
    "subprocess.Popen":      ("CWE-78",  "command_injection",   "HIGH"),
    "subprocess.check_output": ("CWE-78", "command_injection",  "HIGH"),
    "eval":                  ("CWE-95",  "code_injection",      "CRITICAL"),
    "exec":                  ("CWE-95",  "code_injection",      "CRITICAL"),
    "cursor.execute":        ("CWE-89",  "sql_injection",       "CRITICAL"),
    "db.execute":            ("CWE-89",  "sql_injection",       "CRITICAL"),
    "conn.execute":          ("CWE-89",  "sql_injection",       "CRITICAL"),
    "session.execute":       ("CWE-89",  "sql_injection",       "CRITICAL"),
    "pickle.loads":          ("CWE-502", "deserialization",     "HIGH"),
    "pickle.load":           ("CWE-502", "deserialization",     "HIGH"),
    "yaml.load":             ("CWE-502", "deserialization",     "HIGH"),
    "open":                  ("CWE-22",  "path_traversal",      "MEDIUM"),
    "send_file":             ("CWE-22",  "path_traversal",      "MEDIUM"),
    "redirect":              ("CWE-601", "open_redirect",       "MEDIUM"),
    "render_template_string": ("CWE-79", "template_injection",  "HIGH"),
    "Markup":                ("CWE-79",  "xss",                 "MEDIUM"),
    "innerHTML":             ("CWE-79",  "xss",                 "MEDIUM"),
    "requests.get":          ("CWE-918", "ssrf",                "HIGH"),
    "requests.post":         ("CWE-918", "ssrf",                "HIGH"),
    "urllib.request.urlopen": ("CWE-918", "ssrf",               "HIGH"),
    "httpx.get":             ("CWE-918", "ssrf",                "HIGH"),
    "httpx.post":            ("CWE-918", "ssrf",                "HIGH"),
}


@dataclass
class ParamInfo:
    name: str
    index: int
    has_default: bool = False


@dataclass
class FuncDef:
    name: str
    qualname: str
    module: str
    file: str
    line: int
    end_line: int
    params: list[ParamInfo] = field(default_factory=list)
    source_params: set[int] = field(default_factory=set)
    return_taints_from: set[int] = field(default_factory=set)
    sink_params: dict[int, list[tuple[str, str, str, int]]] = field(default_factory=dict)
    is_entry_point: bool = False
    decorators: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    caller: str
    callee: str
    file: str
    line: int
    arg_map: dict[int, str] = field(default_factory=dict)


@dataclass
class ProjectIndex:
    functions: dict[str, FuncDef] = field(default_factory=dict)
    calls: list[CallSite] = field(default_factory=list)
    modules: dict[str, str] = field(default_factory=dict)
    imports: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass
class CallGraphEdge:
    caller: str
    callee: str
    site: CallSite


@dataclass
class CallGraph:
    edges: list[CallGraphEdge] = field(default_factory=list)
    callers_of: dict[str, list[CallGraphEdge]] = field(default_factory=dict)
    callees_of: dict[str, list[CallGraphEdge]] = field(default_factory=dict)


@dataclass
class InterFinding:
    category: str
    severity: str
    cwe: str
    source_func: str
    source_file: str
    source_line: int
    source_param: str
    sink_func: str
    sink_file: str
    sink_line: int
    sink_call: str
    call_chain: list[str] = field(default_factory=list)
    chain_length: int = 0


def _module_name(filepath: str, root: str) -> str:
    rel = os.path.relpath(filepath, root).replace(os.sep, "/")
    if rel.endswith("/__init__.py"):
        return rel[:-12].replace("/", ".")
    if rel.endswith(".py"):
        return rel[:-3].replace("/", ".")
    return rel.replace("/", ".")


def _decorator_name(dec: ast.expr) -> str:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _decorator_name(dec.func)
    return ""


_ENTRY_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch",
    "api_route", "websocket", "app_route",
    "cli.command", "command",
}


class _FuncVisitor(ast.NodeVisitor):
    def __init__(self, module: str, filepath: str, source_lines: list[str]):
        self.module = module
        self.filepath = filepath
        self.source_lines = source_lines
        self.functions: list[FuncDef] = []
        self.calls: list[CallSite] = []
        self._scope_stack: list[str] = []

    def _qualname(self, name: str) -> str:
        parts = [self.module] + self._scope_stack + [name]
        return ".".join(parts)

    def _current_scope(self) -> str:
        if self._scope_stack:
            return ".".join([self.module] + self._scope_stack)
        return self.module

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_func(node)

    def _process_func(self, node):
        qualname = self._qualname(node.name)
        params = []
        for i, arg in enumerate(node.args.args):
            if arg.arg == "self":
                continue
            has_default = i >= len(node.args.args) - len(node.args.defaults)
            params.append(ParamInfo(
                name=arg.arg, index=len(params), has_default=has_default))

        decorators = [_decorator_name(d) for d in node.decorator_list]
        is_entry = bool(set(decorators) & _ENTRY_DECORATORS)

        func = FuncDef(
            name=node.name, qualname=qualname, module=self.module,
            file=self.filepath, line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno + 20),
            params=params, is_entry_point=is_entry,
            decorators=decorators,
        )

        self._analyze_body(func, node)
        self.functions.append(func)

        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def _analyze_body(self, func: FuncDef, node):
        param_names = {p.name: p.index for p in func.params}
        tainted: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                self._check_source_assign(child, func, param_names, tainted)

            if isinstance(child, ast.Call):
                self._check_sink_call(child, func, param_names, tainted)
                self._record_call(child, func, param_names, tainted)

            if isinstance(child, ast.Return) and child.value:
                ret_names = self._names_in(child.value)
                for n in ret_names:
                    if n in param_names:
                        func.return_taints_from.add(param_names[n])
                    elif n in tainted:
                        for pn, pi in param_names.items():
                            if pn in tainted:
                                func.return_taints_from.add(pi)

    def _check_source_assign(self, node: ast.Assign, func: FuncDef,
                             param_names: dict, tainted: set):
        if not node.targets:
            return
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            return
        val_src = ast.dump(node.value) if node.value else ""
        line = self.source_lines[node.lineno - 1] if node.lineno <= len(self.source_lines) else ""
        is_source = (_SOURCE_CALLS.search(line) or
                     any(s in line for s in _SOURCE_PATTERNS))
        if is_source:
            tainted.add(target.id)
            if target.id in param_names:
                func.source_params.add(param_names[target.id])

    def _check_sink_call(self, node: ast.Call, func: FuncDef,
                         param_names: dict, tainted: set):
        call_name = self._call_name(node)
        if not call_name:
            return
        sink_info = None
        for sink_pattern, info in _SINK_MAP.items():
            if call_name.endswith(sink_pattern) or call_name == sink_pattern:
                sink_info = info
                break
        if not sink_info:
            return

        cwe, category, severity = sink_info
        for i, arg in enumerate(node.args):
            arg_names = self._names_in(arg)
            for name in arg_names:
                if name in param_names:
                    pi = param_names[name]
                    func.sink_params.setdefault(pi, []).append(
                        (cwe, category, severity, node.lineno))
                elif name in tainted:
                    for pn, pi in param_names.items():
                        func.sink_params.setdefault(pi, []).append(
                            (cwe, category, severity, node.lineno))
                        break

        for kw in node.keywords:
            if kw.value:
                kw_names = self._names_in(kw.value)
                for name in kw_names:
                    if name in param_names:
                        pi = param_names[name]
                        func.sink_params.setdefault(pi, []).append(
                            (cwe, category, severity, node.lineno))

    def _record_call(self, node: ast.Call, func: FuncDef,
                     param_names: dict, tainted: set):
        call_name = self._call_name(node)
        if not call_name:
            return
        arg_map = {}
        for i, arg in enumerate(node.args):
            names = self._names_in(arg)
            for n in names:
                if n in param_names or n in tainted:
                    arg_map[i] = n
                    break
        if arg_map:
            self.calls.append(CallSite(
                caller=func.qualname, callee=call_name,
                file=self.filepath, line=node.lineno,
                arg_map=arg_map,
            ))

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            obj = node.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            return ".".join(reversed(parts))
        return ""

    def _names_in(self, node) -> set[str]:
        names = set()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.BinOp, ast.BoolOp)):
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    names.add(child.id)
        elif isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    names |= self._names_in(val.value)
        elif isinstance(node, ast.Call):
            for arg in node.args:
                names |= self._names_in(arg)
        elif isinstance(node, ast.Subscript):
            names |= self._names_in(node.value)
        return names


def _parse_imports(tree: ast.Module, module: str) -> dict[str, str]:
    mapping = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                mapping[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                mapping[local] = f"{mod}.{alias.name}" if mod else alias.name
    return mapping


def index_file(filepath: str, root: str) -> tuple[list[FuncDef], list[CallSite], dict[str, str]]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return [], [], {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], [], {}

    module = _module_name(filepath, root)
    lines = source.splitlines()
    visitor = _FuncVisitor(module, filepath, lines)
    visitor.visit(tree)
    imports = _parse_imports(tree, module)
    return visitor.functions, visitor.calls, imports


def build_index(paths: list[str]) -> ProjectIndex:
    index = ProjectIndex()
    roots = []
    for p in paths:
        if os.path.isdir(p):
            roots.append(os.path.abspath(p))
        elif os.path.isfile(p):
            roots.append(os.path.dirname(os.path.abspath(p)))

    root = roots[0] if roots else "."

    files = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".py"):
            files.append(os.path.abspath(p))
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                for n in fn:
                    if n.endswith(".py"):
                        files.append(os.path.abspath(os.path.join(dp, n)))

    for filepath in files:
        funcs, calls, imports = index_file(filepath, root)
        module = _module_name(filepath, root)
        index.modules[module] = filepath
        index.imports[module] = imports
        for func in funcs:
            index.functions[func.qualname] = func
        index.calls.extend(calls)

    return index


def _resolve_callee(call_name: str, caller_module: str,
                    index: ProjectIndex) -> str | None:
    if call_name in index.functions:
        return call_name

    caller_imports = index.imports.get(caller_module, {})

    parts = call_name.split(".")
    first = parts[0]
    if first in caller_imports:
        resolved = caller_imports[first]
        if len(parts) > 1:
            resolved = resolved + "." + ".".join(parts[1:])
        if resolved in index.functions:
            return resolved

    full = f"{caller_module}.{call_name}"
    if full in index.functions:
        return full

    for qn in index.functions:
        if qn.endswith(f".{call_name}"):
            return qn

    return None


def build_call_graph(index: ProjectIndex) -> CallGraph:
    graph = CallGraph()
    for site in index.calls:
        caller_func = index.functions.get(site.caller)
        if not caller_func:
            continue
        resolved = _resolve_callee(
            site.callee, caller_func.module, index)
        if resolved and resolved in index.functions:
            edge = CallGraphEdge(
                caller=site.caller, callee=resolved, site=site)
            graph.edges.append(edge)
            graph.callers_of.setdefault(resolved, []).append(edge)
            graph.callees_of.setdefault(site.caller, []).append(edge)
    return graph


def _propagate_taint(index: ProjectIndex, graph: CallGraph,
                     max_depth: int = 10) -> dict[str, FuncDef]:
    changed = True
    iteration = 0
    while changed and iteration < max_depth:
        changed = False
        iteration += 1
        for edge in graph.edges:
            caller = index.functions.get(edge.caller)
            callee = index.functions.get(edge.callee)
            if not caller or not callee:
                continue

            caller_param_names = {p.name: p.index for p in caller.params}

            for arg_idx, arg_name in edge.site.arg_map.items():
                caller_param_idx = caller_param_names.get(arg_name)
                if caller_param_idx is None:
                    continue

                if arg_idx in callee.sink_params:
                    for sink_info in callee.sink_params[arg_idx]:
                        existing = caller.sink_params.get(caller_param_idx, [])
                        if sink_info not in existing:
                            caller.sink_params.setdefault(
                                caller_param_idx, []).append(sink_info)
                            changed = True

                if arg_idx in callee.return_taints_from:
                    pass

    return index.functions


def _find_entry_sources(index: ProjectIndex) -> list[tuple[FuncDef, int, str]]:
    sources = []
    for func in index.functions.values():
        if not func.is_entry_point:
            continue
        for param in func.params:
            sources.append((func, param.index, param.name))

        for filepath_key, file_imports in index.imports.items():
            if func.module != filepath_key:
                continue

    return sources


def analyze(index: ProjectIndex, graph: CallGraph,
            max_depth: int = 8) -> list[InterFinding]:
    _propagate_taint(index, graph, max_depth)

    findings = []
    seen = set()

    for func in index.functions.values():
        if not func.sink_params:
            continue

        for param_idx, sinks in func.sink_params.items():
            if param_idx >= len(func.params):
                continue
            param = func.params[param_idx]

            for cwe, category, severity, sink_line in sinks:
                chain = _trace_chain(func.qualname, param_idx,
                                     index, graph, max_depth)
                key = (func.qualname, param_idx, cwe, sink_line)
                if key in seen:
                    continue
                seen.add(key)

                source_func = chain[0] if chain else func.qualname
                source_def = index.functions.get(source_func, func)

                finding = InterFinding(
                    category=category, severity=severity, cwe=cwe,
                    source_func=source_def.qualname,
                    source_file=source_def.file,
                    source_line=source_def.line,
                    source_param=param.name,
                    sink_func=func.qualname,
                    sink_file=func.file,
                    sink_line=sink_line,
                    sink_call=category,
                    call_chain=chain,
                    chain_length=len(chain),
                )
                findings.append(finding)

    findings.sort(key=lambda f: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 9),
        -f.chain_length))
    return findings


def _trace_chain(func_name: str, param_idx: int,
                 index: ProjectIndex, graph: CallGraph,
                 max_depth: int) -> list[str]:
    chain = [func_name]
    visited = {func_name}
    current = func_name
    current_param = param_idx

    for _ in range(max_depth):
        callers = graph.callers_of.get(current, [])
        found = False
        for edge in callers:
            if edge.caller in visited:
                continue
            for arg_idx, arg_name in edge.site.arg_map.items():
                if arg_idx == current_param:
                    caller_func = index.functions.get(edge.caller)
                    if caller_func:
                        caller_params = {p.name: p.index for p in caller_func.params}
                        if arg_name in caller_params:
                            chain.insert(0, edge.caller)
                            visited.add(edge.caller)
                            current = edge.caller
                            current_param = caller_params[arg_name]
                            found = True
                            break
            if found:
                break
        if not found:
            break

    return chain


def scan_paths(paths: list[str], max_depth: int = 8) -> list[InterFinding]:
    index = build_index(paths)
    graph = build_call_graph(index)
    return analyze(index, graph, max_depth)


def to_dict(findings: list[InterFinding]) -> list[dict]:
    return [
        {
            "category": f.category, "severity": f.severity, "cwe": f.cwe,
            "source_func": f.source_func, "source_file": f.source_file,
            "source_line": f.source_line, "source_param": f.source_param,
            "sink_func": f.sink_func, "sink_file": f.sink_file,
            "sink_line": f.sink_line, "sink_call": f.sink_call,
            "call_chain": f.call_chain, "chain_length": f.chain_length,
            "file": f.sink_file, "path": f.sink_file,
            "line": f.sink_line,
            "sink_type": f.category,
        }
        for f in findings
    ]


def render(findings: list[InterFinding], index: ProjectIndex | None = None) -> str:
    if not findings:
        if index and index.functions:
            return (f"  analyzed {len(index.functions)} function(s) across "
                    f"{len(index.modules)} module(s). no cross-function taint flows found.")
        return "  nothing indexed. point it at a directory with python files."

    cross = [f for f in findings if f.chain_length > 1]
    local = [f for f in findings if f.chain_length <= 1]
    crits = sum(1 for f in findings if f.severity == "CRITICAL")

    lines = [
        f"\n  Inter-procedural Analysis",
        "  " + "=" * 62,
    ]
    if index:
        lines.append(
            f"  {len(index.functions)} function(s) | {len(index.modules)} module(s) | "
            f"{len(findings)} finding(s)")
    if cross:
        lines.append(
            f"  {len(cross)} cross-function flow(s) -- "
            f"these are the ones single-file scanners miss.")
    if crits:
        lines.append(f"  {crits} critical. attackers see what you don't.")

    for f in findings:
        tag = "CROSS" if f.chain_length > 1 else "LOCAL"
        lines.append(
            f"\n  [{f.severity}] [{tag}] {f.category}")
        if f.call_chain:
            chain_str = " -> ".join(
                qn.rsplit(".", 1)[-1] for qn in f.call_chain)
            lines.append(f"    chain: {chain_str}")
        lines.append(
            f"    source: {f.source_param} in "
            f"{os.path.basename(f.source_file)}:{f.source_line} "
            f"({f.source_func.rsplit('.', 1)[-1]})")
        lines.append(
            f"    sink: {f.sink_call} at "
            f"{os.path.basename(f.sink_file)}:{f.sink_line} "
            f"({f.sink_func.rsplit('.', 1)[-1]})")
        lines.append(f"    {f.cwe}")

    return "\n".join(lines)
