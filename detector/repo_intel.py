#!/usr/bin/env python3
"""Repository-level graph, reachability, configuration, and taint intelligence.

This module keeps Project Brain's structural model separate from presentation so
other Attestor surfaces can consume a stable JSON-compatible graph.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
             "vendor", "dist", "build", "target", "generated_service"}
ROUTE_NAMES = {"route", "get", "post", "put", "patch", "delete", "options", "websocket"}
SINKS = {"eval", "exec", "os.system", "subprocess.run", "subprocess.call",
         "subprocess.Popen", "yaml.load", "pickle.loads", "cursor.execute", "db.execute"}
CONFIG_RX = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*[:=]", re.M)


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _name(node.value)
        return (left + "." if left else "") + node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _module(root: Path, path: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = [part for part in rel.parts if part != "__init__"]
    return ".".join(parts) or root.name.replace("-", "_")


def _route(decorator) -> str:
    if not isinstance(decorator, ast.Call):
        return ""
    name = _name(decorator.func).rsplit(".", 1)[-1].lower()
    if name not in ROUTE_NAMES or not decorator.args:
        return ""
    value = decorator.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else ""


def _expr_has_source(node, tainted: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tainted:
            return True
        if isinstance(child, ast.Attribute):
            text = _name(child)
            if text.startswith(("request.", "sys.argv", "flask.request.", "ctx.request.")):
                return True
        if isinstance(child, ast.Call) and _name(child.func) in {"input", "request.get_json"}:
            return True
    return False


class FunctionFlow(ast.NodeVisitor):
    def __init__(self, qname: str, parameters: list[str], route: bool):
        self.qname = qname
        self.tainted = set(parameters if route else [])
        self.flows = []
        self.tainted_calls = []
        self.returns_tainted = False

    def visit_FunctionDef(self, node):
        return  # nested scope belongs to a different function

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_Assign(self, node):
        if _expr_has_source(node.value, self.tainted):
            for target in node.targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name):
                        self.tainted.add(child.id)
        self.visit(node.value)

    def visit_AnnAssign(self, node):
        if node.value is not None and _expr_has_source(node.value, self.tainted) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        if node.value is not None:
            self.visit(node.value)

    def visit_Call(self, node):
        callee = _name(node.func)
        tainted_positions = [index for index, arg in enumerate(node.args)
                             if _expr_has_source(arg, self.tainted)]
        if tainted_positions:
            self.tainted_calls.append({"caller": self.qname, "callee": callee,
                                       "positions": tainted_positions, "line": node.lineno})
        sink = callee in SINKS or callee.endswith((".execute", ".executemany", ".raw", ".send_file"))
        if sink and tainted_positions:
            parameterized_sql = callee.endswith((".execute", ".executemany")) and len(node.args) > 1
            if not parameterized_sql:
                self.flows.append({"scope": self.qname, "sink": callee, "line": node.lineno,
                                   "message": "request-derived data reaches %s" % callee,
                                   "confidence": 0.94})
        self.generic_visit(node)

    def visit_Return(self, node):
        if node.value is not None and _expr_has_source(node.value, self.tainted):
            self.returns_tainted = True
        if node.value is not None:
            self.visit(node.value)


class ModuleVisitor(ast.NodeVisitor):
    def __init__(self, module: str, path: str):
        self.module = module
        self.path = path
        self.imports = []
        self.aliases = {}
        self.definitions = {}
        self.calls = []
        self.inheritance = []
        self.config_uses = []
        self.flows = []
        self.tainted_calls = []
        self._classes = []
        self._functions = []

    def _scope(self) -> str:
        return ".".join([self.module] + self._classes + self._functions)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)
            self.aliases[alias.asname or alias.name.split(".", 1)[0]] = alias.name

    def visit_ImportFrom(self, node):
        base = ("." * node.level) + (node.module or "")
        self.imports.append(base)
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = (base + "." + alias.name).strip(".")

    def visit_ClassDef(self, node):
        qname = ".".join([self.module] + self._classes + [node.name])
        self.definitions[qname] = {"path": self.path, "line": node.lineno, "kind": "class",
                                   "decorators": [_name(item) for item in node.decorator_list]}
        for base in node.bases:
            self.inheritance.append({"class": qname, "base": _name(base), "path": self.path,
                                     "line": node.lineno})
        self._classes.append(node.name)
        for child in node.body:
            self.visit(child)
        self._classes.pop()

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node)

    def _visit_function(self, node):
        qname = ".".join([self.module] + self._classes + self._functions + [node.name])
        routes = [route for route in (_route(item) for item in node.decorator_list) if route]
        decorators = [_name(item.func if isinstance(item, ast.Call) else item) for item in node.decorator_list]
        parameters = [arg.arg for arg in (list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs))]
        self.definitions[qname] = {
            "path": self.path, "line": node.lineno, "kind": "method" if self._classes else "function",
            "decorators": decorators, "routes": routes, "parameters": parameters,
        }
        flow = FunctionFlow(qname, parameters, bool(routes))
        for statement in node.body:
            flow.visit(statement)
        for item in flow.flows:
            self.flows.append({**item, "path": self.path})
        self.tainted_calls.extend({**item, "path": self.path} for item in flow.tainted_calls)
        self._functions.append(node.name)
        for child in node.body:
            self.visit(child)
        self._functions.pop()

    def visit_Call(self, node):
        callee = _name(node.func)
        caller = self._scope()
        self.calls.append({"caller": caller, "callee": callee, "path": self.path,
                           "line": getattr(node, "lineno", 1)})
        if callee in {"os.getenv", "os.environ.get", "getenv"} and node.args:
            arg = node.args[0]
            key = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else "<dynamic>"
            self.config_uses.append({"key": key, "scope": caller, "path": self.path,
                                     "line": getattr(node, "lineno", 1)})
        self.generic_visit(node)


def _resolve_call(call: dict, modules: dict, definitions: dict) -> str:
    caller_module = call["caller"].split(".", 1)[0]
    info = modules.get(caller_module, {})
    callee = call["callee"]
    if not callee:
        return ""
    same_module = caller_module + "." + callee
    if same_module in definitions:
        return same_module
    short = callee.rsplit(".", 1)[-1]
    same_candidates = [name for name in definitions if name.startswith(caller_module + ".")
                       and name.rsplit(".", 1)[-1] == short]
    if len(same_candidates) == 1:
        return same_candidates[0]
    head, _, tail = callee.partition(".")
    alias = info.get("aliases", {}).get(head)
    if alias:
        candidate = alias + (("." + tail) if tail else "")
        if candidate in definitions:
            return candidate
        matches = [name for name in definitions if name.endswith("." + candidate.rsplit(".", 1)[-1])
                   and name.startswith(alias.split(".", 1)[0] + ".")]
        if len(matches) == 1:
            return matches[0]
    global_matches = [name for name in definitions if name.rsplit(".", 1)[-1] == short]
    return global_matches[0] if len(global_matches) == 1 else ""


def _cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    index = 0
    stack = []
    on_stack = set()
    indices = {}
    low = {}
    found = []

    def strong(node):
        nonlocal index
        indices[node] = low[node] = index; index += 1
        stack.append(node); on_stack.add(node)
        for target in graph.get(node, []):
            if target not in graph:
                continue
            if target not in indices:
                strong(target); low[node] = min(low[node], low[target])
            elif target in on_stack:
                low[node] = min(low[node], indices[target])
        if low[node] == indices[node]:
            component = []
            while stack:
                item = stack.pop(); on_stack.remove(item); component.append(item)
                if item == node:
                    break
            if len(component) > 1 or node in graph.get(node, []):
                found.append(sorted(component))

    for node in sorted(graph):
        if node not in indices:
            strong(node)
    return sorted(found)


def analyze(root: str) -> dict:
    base = Path(root).expanduser().resolve()
    report = {"root": str(base), "modules": {}, "definitions": {}, "calls": [],
              "resolved_calls": [], "import_graph": {}, "import_cycles": [],
              "inheritance": [], "entrypoints": [], "reachable": [], "unreferenced": [],
              "config_defined": [], "config_used": [], "config_undeclared": [],
              "unsafe_flows": [], "parse_errors": []}
    if not base.is_dir():
        report["parse_errors"].append({"path": str(base), "line": 1, "message": "not a directory"})
        return report
    python_files = [path for path in base.rglob("*.py")
                    if not any(part in SKIP_DIRS for part in path.parts)]
    for path in sorted(python_files):
        module = _module(base, path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError) as exc:
            report["parse_errors"].append({"path": str(path), "line": getattr(exc, "lineno", 1) or 1,
                                           "message": str(exc)})
            continue
        visitor = ModuleVisitor(module, str(path)); visitor.visit(tree)
        report["modules"][module] = {"path": str(path), "imports": visitor.imports,
                                     "aliases": visitor.aliases}
        report["definitions"].update(visitor.definitions)
        report["calls"].extend(visitor.calls)
        report["inheritance"].extend(visitor.inheritance)
        report["config_used"].extend(visitor.config_uses)
        report["unsafe_flows"].extend(visitor.flows)
    module_names = set(report["modules"])
    for module, info in report["modules"].items():
        targets = []
        for imported in info["imports"]:
            cleaned = imported.lstrip(".")
            candidates = [name for name in module_names if name == cleaned or name.startswith(cleaned + ".")]
            if candidates:
                targets.append(sorted(candidates, key=len)[0])
        report["import_graph"][module] = sorted(set(targets))
    report["import_cycles"] = _cycles(report["import_graph"])
    for call in report["calls"]:
        target = _resolve_call(call, report["modules"], report["definitions"])
        report["resolved_calls"].append({**call, "target": target})
    incoming = {name: 0 for name in report["definitions"]}
    adjacency = {name: [] for name in report["definitions"]}
    for call in report["resolved_calls"]:
        if call["target"] in incoming:
            incoming[call["target"]] += 1
            if call["caller"] in adjacency:
                adjacency[call["caller"]].append(call["target"])
    entries = []
    for name, meta in report["definitions"].items():
        short = name.rsplit(".", 1)[-1]
        if meta.get("routes") or short in {"main", "handler", "application", "lambda_handler"}:
            entries.append(name)
    report["entrypoints"] = sorted(entries)
    reachable = set(entries)
    todo = list(entries)
    while todo:
        node = todo.pop()
        for target in adjacency.get(node, []):
            if target not in reachable:
                reachable.add(target); todo.append(target)
    report["reachable"] = sorted(reachable)
    callback_prefixes = ("visit_", "do_", "on_", "handle_", "test_", "setUp", "tearDown")
    for name, meta in report["definitions"].items():
        if meta["kind"] == "class" or name in reachable or incoming[name] or meta.get("decorators"):
            continue
        short = name.rsplit(".", 1)[-1]
        if short.startswith("__") or short.startswith(callback_prefixes):
            continue
        report["unreferenced"].append({"function": name, "path": meta["path"], "line": meta["line"],
                                       "confidence": 0.78 if short.startswith("_") else 0.48,
                                       "reason": "no static callers or framework entrypoint found"})
    config_files = [path for path in base.rglob("*") if path.is_file() and (
        path.name.lower().startswith(".env") or path.suffix.lower() in {
            ".env", ".ini", ".cfg", ".conf", ".toml", ".yaml", ".yml", ".properties"})
                    and not any(part in SKIP_DIRS for part in path.parts)]
    defined = set()
    for path in config_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in CONFIG_RX.finditer(text):
            defined.add(match.group(1))
            report["config_defined"].append({"key": match.group(1), "path": str(path),
                                             "line": text.count("\n", 0, match.start()) + 1})
    used = {item["key"] for item in report["config_used"] if item["key"] != "<dynamic>"}
    report["config_undeclared"] = sorted(used - defined)
    return report


def render(report: dict) -> str:
    out = ["Repository Intelligence for " + report["root"], "=" * 72,
           "modules: %d" % len(report["modules"]),
           "definitions: %d" % len(report["definitions"]),
           "resolved call edges: %d/%d" % (
               sum(bool(call["target"]) for call in report["resolved_calls"]), len(report["resolved_calls"])),
           "entrypoints: %d" % len(report["entrypoints"]),
           "reachable definitions: %d" % len(report["reachable"]),
           "import cycles: %d" % len(report["import_cycles"]),
           "unreferenced candidates: %d" % len(report["unreferenced"]),
           "unsafe taint flows: %d" % len(report["unsafe_flows"])]
    if report["import_cycles"]:
        out += ["", "import cycles:"] + ["  " + " -> ".join(cycle + [cycle[0]])
                                          for cycle in report["import_cycles"][:12]]
    if report["unsafe_flows"]:
        out += ["", "confirmed source-to-sink flows:"] + [
            "  %s:%d %s -> %s (%.0f%%)" % (
                flow["path"], flow["line"], flow["scope"], flow["sink"], flow["confidence"] * 100)
            for flow in report["unsafe_flows"][:20]]
    if report["unreferenced"]:
        out += ["", "unreferenced candidates:"] + [
            "  %s:%d %s (confidence %.0f%%)" % (
                item["path"], item["line"], item["function"], item["confidence"] * 100)
            for item in report["unreferenced"][:20]]
    if report["config_undeclared"]:
        out += ["", "configuration used but not declared in repository templates:",
                "  " + ", ".join(report["config_undeclared"])]
    return "\n".join(out)
