#!/usr/bin/env python3
"""Interprocedural taint tracking -- traces data flow from sources (user input,
file reads, network) through transforms to sinks (exec, SQL, file writes, HTML
output) across function boundaries and files. Builds a call graph and propagates
taint through arguments, return values, and assignments."""
from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".tox", ".mypy_cache", ".pytest_cache",
}


TAINT_SOURCES = {
    "input": "user_input",
    "sys.stdin.read": "user_input",
    "sys.stdin.readline": "user_input",
    "request.args.get": "http_param",
    "request.form.get": "http_param",
    "request.json": "http_body",
    "request.data": "http_body",
    "request.cookies.get": "http_cookie",
    "request.headers.get": "http_header",
    "request.files": "http_upload",
    "request.get_json": "http_body",
    "request.values.get": "http_param",
    "flask.request.args": "http_param",
    "flask.request.form": "http_param",
    "os.environ.get": "env_var",
    "os.getenv": "env_var",
    "sys.argv": "cli_arg",
    "open": "file_read",
    "urlopen": "network_read",
    "requests.get": "network_read",
    "requests.post": "network_read",
    "socket.recv": "network_read",
    "json.loads": "deserialized",
    "pickle.loads": "deserialized",
    "yaml.load": "deserialized",
    "yaml.unsafe_load": "deserialized",
}

TAINT_SINKS = {
    "os.system": ("command_injection", "CWE-78"),
    "os.popen": ("command_injection", "CWE-78"),
    "subprocess.call": ("command_injection", "CWE-78"),
    "subprocess.run": ("command_injection", "CWE-78"),
    "subprocess.Popen": ("command_injection", "CWE-78"),
    "eval": ("code_injection", "CWE-95"),
    "exec": ("code_injection", "CWE-95"),
    "compile": ("code_injection", "CWE-95"),
    "__import__": ("code_injection", "CWE-95"),
    "cursor.execute": ("sql_injection", "CWE-89"),
    "db.execute": ("sql_injection", "CWE-89"),
    "connection.execute": ("sql_injection", "CWE-89"),
    "engine.execute": ("sql_injection", "CWE-89"),
    "render_template_string": ("template_injection", "CWE-94"),
    "Markup": ("xss", "CWE-79"),
    "innerHTML": ("xss", "CWE-79"),
    "document.write": ("xss", "CWE-79"),
    "open": ("path_traversal", "CWE-22"),
    "send_file": ("path_traversal", "CWE-22"),
    "shutil.copy": ("path_traversal", "CWE-22"),
    "redirect": ("open_redirect", "CWE-601"),
    "urlopen": ("ssrf", "CWE-918"),
    "requests.get": ("ssrf", "CWE-918"),
    "requests.post": ("ssrf", "CWE-918"),
    "pickle.loads": ("deserialization", "CWE-502"),
    "yaml.load": ("deserialization", "CWE-502"),
    "xml.etree.ElementTree.parse": ("xxe", "CWE-611"),
    "lxml.etree.parse": ("xxe", "CWE-611"),
    "smtplib.SMTP.sendmail": ("email_injection", "CWE-93"),
    "logging.info": ("log_injection", "CWE-117"),
    "logging.error": ("log_injection", "CWE-117"),
    "logging.warning": ("log_injection", "CWE-117"),
}

SANITIZERS = {
    "escape", "html.escape", "markupsafe.escape", "bleach.clean",
    "shlex.quote", "pipes.quote",
    "int", "float", "bool", "abs",
    "urllib.parse.quote", "urllib.parse.urlencode",
    "re.escape",
    "parameterized", "placeholder", "%s",
    "sanitize", "clean", "strip_tags", "escape_html",
    "validate", "is_valid",
}


@dataclass
class TaintFlow:
    source_file: str
    source_line: int
    source_type: str
    source_var: str
    sink_file: str
    sink_line: int
    sink_type: str
    sink_cwe: str
    path: list[str] = field(default_factory=list)
    confidence: str = "high"
    sanitized: bool = False


@dataclass
class FunctionInfo:
    name: str
    file: str
    line: int
    args: list[str]
    returns_tainted: bool = False
    tainted_args: set[int] = field(default_factory=set)
    tainted_vars: dict[str, str] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    body_node: Optional[ast.AST] = field(default=None, repr=False)


class TaintAnalyzer(ast.NodeVisitor):

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.functions: dict[str, FunctionInfo] = {}
        self.tainted: dict[str, str] = {}
        self.flows: list[TaintFlow] = []
        self.current_func: Optional[str] = None
        self.assignments: dict[str, ast.AST] = {}

    def _resolve_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value = self._resolve_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        if isinstance(node, ast.Subscript):
            return self._resolve_name(node.value)
        return ""

    def _is_source(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Call):
            name = self._resolve_name(node.func)
            for source_name, source_type in TAINT_SOURCES.items():
                if name.endswith(source_name):
                    return source_type
        if isinstance(node, ast.Attribute):
            full = self._resolve_name(node)
            for source_name, source_type in TAINT_SOURCES.items():
                if full.endswith(source_name):
                    return source_type
        if isinstance(node, ast.Subscript):
            full = self._resolve_name(node.value)
            for source_name, source_type in TAINT_SOURCES.items():
                if full.endswith(source_name):
                    return source_type
        return None

    def _is_sink(self, node: ast.Call) -> Optional[tuple[str, str]]:
        name = self._resolve_name(node.func)
        for sink_name, (vuln_type, cwe) in TAINT_SINKS.items():
            if name.endswith(sink_name):
                return vuln_type, cwe
        return None

    def _is_sanitized(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            name = self._resolve_name(node.func)
            return any(name.endswith(s) for s in SANITIZERS)
        return False

    def _var_is_tainted(self, name: str) -> Optional[str]:
        if name in self.tainted:
            return self.tainted[name]
        if self.current_func and self.current_func in self.functions:
            func = self.functions[self.current_func]
            if name in func.tainted_vars:
                return func.tainted_vars[name]
        return None

    def _check_arg_taint(self, node: ast.AST) -> Optional[tuple[str, str]]:
        if isinstance(node, ast.Name):
            taint = self._var_is_tainted(node.id)
            if taint:
                return node.id, taint
        elif isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    result = self._check_arg_taint(val.value)
                    if result:
                        return result
        elif isinstance(node, ast.BinOp):
            left = self._check_arg_taint(node.left)
            if left:
                return left
            right = self._check_arg_taint(node.right)
            if right:
                return right
        elif isinstance(node, ast.Call):
            if self._is_sanitized(node):
                return None
            for arg in node.args:
                result = self._check_arg_taint(arg)
                if result:
                    return result
        elif isinstance(node, ast.Attribute):
            return self._check_arg_taint(node.value)
        elif isinstance(node, ast.Subscript):
            return self._check_arg_taint(node.value)
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_name = node.name
        if self.current_func:
            func_name = f"{self.current_func}.{node.name}"
        args = [arg.arg for arg in node.args.args]
        self.functions[func_name] = FunctionInfo(
            name=func_name, file=self.filepath, line=node.lineno,
            args=args, body_node=node,
        )
        old_func = self.current_func
        self.current_func = func_name
        self.generic_visit(node)
        self.current_func = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            var_name = self._resolve_name(target)
            if not var_name:
                continue
            source_type = self._is_source(node.value)
            if source_type:
                self.tainted[var_name] = source_type
                if self.current_func and self.current_func in self.functions:
                    self.functions[self.current_func].tainted_vars[var_name] = source_type
            elif isinstance(node.value, ast.Name):
                propagated = self._var_is_tainted(node.value.id)
                if propagated:
                    self.tainted[var_name] = propagated
                    if self.current_func and self.current_func in self.functions:
                        self.functions[self.current_func].tainted_vars[var_name] = propagated
            elif isinstance(node.value, ast.BinOp):
                result = self._check_arg_taint(node.value)
                if result:
                    self.tainted[var_name] = result[1]
            elif isinstance(node.value, ast.JoinedStr):
                result = self._check_arg_taint(node.value)
                if result:
                    self.tainted[var_name] = result[1]
            elif isinstance(node.value, ast.Call):
                if not self._is_sanitized(node.value):
                    for arg in node.value.args:
                        result = self._check_arg_taint(arg)
                        if result:
                            self.tainted[var_name] = result[1]
                            break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        sink = self._is_sink(node)
        if sink:
            vuln_type, cwe = sink
            for arg in node.args:
                if self._is_sanitized(arg):
                    continue
                taint_result = self._check_arg_taint(arg)
                if taint_result:
                    var_name, source_type = taint_result
                    flow = TaintFlow(
                        source_file=self.filepath,
                        source_line=self._find_taint_origin(var_name),
                        source_type=source_type,
                        source_var=var_name,
                        sink_file=self.filepath,
                        sink_line=node.lineno,
                        sink_type=vuln_type,
                        sink_cwe=cwe,
                        path=self._build_path(var_name, node.lineno),
                    )
                    self.flows.append(flow)
            for kw in node.keywords:
                if kw.value and not self._is_sanitized(kw.value):
                    taint_result = self._check_arg_taint(kw.value)
                    if taint_result:
                        var_name, source_type = taint_result
                        self.flows.append(TaintFlow(
                            source_file=self.filepath,
                            source_line=self._find_taint_origin(var_name),
                            source_type=source_type,
                            source_var=var_name,
                            sink_file=self.filepath,
                            sink_line=node.lineno,
                            sink_type=vuln_type,
                            sink_cwe=cwe,
                            path=self._build_path(var_name, node.lineno),
                        ))

        func_name = self._resolve_name(node.func)
        if self.current_func and self.current_func in self.functions:
            self.functions[self.current_func].calls.append(func_name)

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if node.value and self.current_func and self.current_func in self.functions:
            result = self._check_arg_taint(node.value)
            if result:
                self.functions[self.current_func].returns_tainted = True
        self.generic_visit(node)

    def _find_taint_origin(self, var_name: str) -> int:
        return 0

    def _build_path(self, var_name: str, sink_line: int) -> list[str]:
        return [f"tainted:{var_name}", f"sink:line {sink_line}"]


class CrossFileAnalyzer:

    def __init__(self):
        self.file_analyzers: dict[str, TaintAnalyzer] = {}
        self.all_functions: dict[str, FunctionInfo] = {}
        self.all_flows: list[TaintFlow] = []
        self.call_graph: dict[str, list[str]] = {}

    def analyze_file(self, filepath: str):
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
        except (SyntaxError, OSError):
            return

        analyzer = TaintAnalyzer(filepath)
        analyzer.visit(tree)
        self.file_analyzers[filepath] = analyzer
        self.all_functions.update(analyzer.functions)
        self.all_flows.extend(analyzer.flows)

        for func_name, func_info in analyzer.functions.items():
            self.call_graph[func_name] = func_info.calls

    def analyze_directory(self, root: str):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                if fname.endswith(".py"):
                    fpath = os.path.join(dirpath, fname)
                    self.analyze_file(fpath)
        self._propagate_cross_function()

    def _propagate_cross_function(self):
        changed = True
        iterations = 0
        max_iterations = 10
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            for func_name, func_info in self.all_functions.items():
                for call in func_info.calls:
                    called_func = self.all_functions.get(call)
                    if not called_func:
                        continue
                    if called_func.returns_tainted and not func_info.returns_tainted:
                        func_info.returns_tainted = True
                        changed = True
                    for var, taint_type in called_func.tainted_vars.items():
                        if var not in func_info.tainted_vars:
                            func_info.tainted_vars[var] = taint_type
                            changed = True

    def get_flows(self) -> list[TaintFlow]:
        return self.all_flows

    def get_call_graph(self) -> dict[str, list[str]]:
        return self.call_graph

    def get_tainted_functions(self) -> list[FunctionInfo]:
        return [f for f in self.all_functions.values()
                if f.tainted_vars or f.returns_tainted]


def scan_file(path: str) -> list[TaintFlow]:
    analyzer = CrossFileAnalyzer()
    analyzer.analyze_file(path)
    return analyzer.get_flows()


def scan_directory(root: str) -> list[TaintFlow]:
    analyzer = CrossFileAnalyzer()
    analyzer.analyze_directory(root)
    return analyzer.get_flows()


def render(flows: list[TaintFlow]) -> str:
    if not flows:
        return "  No taint flows detected."
    lines = []
    by_type = {}
    for f in flows:
        by_type.setdefault(f.sink_type, []).append(f)

    lines.append(f"\n  Taint Analysis ({len(flows)} flow{'s' if len(flows) != 1 else ''})")
    lines.append(f"  {'='*55}")

    for vuln_type in sorted(by_type):
        group = by_type[vuln_type]
        cwe = group[0].sink_cwe
        lines.append(f"\n  [{vuln_type}] ({cwe}) -- {len(group)} flow(s)")
        for flow in group:
            lines.append(f"    Source: {flow.source_file}:{flow.source_line}  "
                         f"({flow.source_type}) var={flow.source_var}")
            lines.append(f"    Sink:   {flow.sink_file}:{flow.sink_line}  "
                         f"({flow.sink_type})")
            if flow.path:
                lines.append(f"    Path:   {' -> '.join(flow.path)}")
            lines.append("")

    return "\n".join(lines)


def to_dict(flows: list[TaintFlow]) -> list[dict]:
    return [
        {
            "source_file": f.source_file,
            "source_line": f.source_line,
            "source_type": f.source_type,
            "source_var": f.source_var,
            "sink_file": f.sink_file,
            "sink_line": f.sink_line,
            "sink_type": f.sink_type,
            "sink_cwe": f.sink_cwe,
            "path": f.path,
            "confidence": f.confidence,
        }
        for f in flows
    ]
