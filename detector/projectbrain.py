#!/usr/bin/env python3
"""
projectbrain.py -- multi-file structural analysis for Attestor.

This is the project-scale read: imports, call graph, config/env usage, API
routes, database queries, dead code candidates, and suspicious source-to-sink
flows across a tree. It is intentionally conservative and deterministic.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re

import detect
import repo_intel

ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch", "options"}
DB_WORDS = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", re.I)
ENV_RX = re.compile(r"\b(?:os\.environ(?:\.get)?|os\.getenv|getenv)\s*\(")
CONFIG_KEY_RX = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*[:=]")


def _module_name(root: str, path: str) -> str:
    rel = os.path.relpath(path, root)
    stem = os.path.splitext(rel)[0]
    parts = [p for p in re.split(r"[\\/]+", stem) if p != "__init__"]
    return ".".join(parts)


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _name(node.value)
        return (left + "." if left else "") + node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _string_arg(node) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _decorator_route(dec) -> tuple[str, str] | None:
    if not isinstance(dec, ast.Call):
        return None
    name = _name(dec.func)
    method = name.rsplit(".", 1)[-1].lower()
    if method not in ROUTE_METHODS:
        return None
    if not dec.args:
        return None
    route = _string_arg(dec.args[0])
    if not route.startswith("/"):
        return None
    if method == "route":
        method = "ANY"
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                vals = [_string_arg(v).upper() for v in kw.value.elts]
                method = ",".join(v for v in vals if v) or "ANY"
    else:
        method = method.upper()
    return method, route


class FileVisitor(ast.NodeVisitor):
    def __init__(self, module: str, path: str):
        self.module = module
        self.path = path
        self.imports = []
        self.functions = {}
        self.calls = []
        self.routes = []
        self.env = []
        self.db = []
        self.flows = []
        self._stack = []

    def _scope(self) -> str:
        return ".".join(self._stack) if self._stack else "<module>"

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append(alias.name)

    def visit_ImportFrom(self, node):
        mod = ("." * node.level) + (node.module or "")
        self.imports.append(mod)

    def visit_FunctionDef(self, node):
        self._function(node)

    def visit_AsyncFunctionDef(self, node):
        self._function(node)

    def _function(self, node):
        qname = self.module + "." + ".".join(self._stack + [node.name])
        self.functions[qname] = {"line": node.lineno, "path": self.path}
        for dec in node.decorator_list:
            route = _decorator_route(dec)
            if route:
                method, url = route
                self.routes.append({"method": method, "route": url, "handler": qname,
                                    "path": self.path, "line": node.lineno})
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    def visit_Call(self, node):
        callee = _name(node.func)
        caller = self.module + "." + self._scope()
        if callee:
            self.calls.append({"caller": caller, "callee": callee,
                               "path": self.path, "line": getattr(node, "lineno", 1)})
        if callee in ("os.getenv", "os.environ.get", "getenv"):
            key = _string_arg(node.args[0]) if node.args else ""
            self.env.append({"key": key or "<dynamic>", "path": self.path,
                             "line": getattr(node, "lineno", 1), "scope": caller})
        if callee.endswith(".execute") or callee.endswith(".executemany") or callee.endswith(".query"):
            query = _string_arg(node.args[0]) if node.args else ""
            self.db.append({"query": query or "<dynamic>", "path": self.path,
                            "line": getattr(node, "lineno", 1), "scope": caller,
                            "dynamic": not bool(query)})
        self.generic_visit(node)

    def visit_Attribute(self, node):
        text = _name(node)
        if text.startswith(("request.args", "request.form", "request.json", "request.values")):
            self.flows.append({"kind": "source", "name": text, "scope": self.module + "." + self._scope(),
                               "path": self.path, "line": getattr(node, "lineno", 1)})
        self.generic_visit(node)


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _config_keys(path: str, text: str) -> list[dict]:
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        if ENV_RX.search(line):
            out.append({"key": "<dynamic>", "path": path, "line": no, "scope": "<text>"})
        m = CONFIG_KEY_RX.match(line)
        if m:
            out.append({"key": m.group(1), "path": path, "line": no, "scope": "<config>"})
    return out


def analyze(root: str) -> dict:
    files = detect.collect_paths([root])
    py_files = [p for p in files if os.path.splitext(p)[1].lower() in (".py", ".pyw")]
    report = {
        "root": root,
        "files": files,
        "imports": {},
        "functions": {},
        "calls": [],
        "routes": [],
        "env": [],
        "db": [],
        "dead_code": [],
        "unsafe_flows": [],
        "parse_errors": [],
    }
    source_scopes = set()
    sink_scopes = {}

    for path in files:
        text = _read(path)
        if path not in py_files:
            report["env"].extend(_config_keys(path, text))
            continue
        module = _module_name(root, path)
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            report["parse_errors"].append({"path": path, "line": exc.lineno or 1,
                                           "message": exc.msg})
            continue
        visitor = FileVisitor(module, path)
        visitor.visit(tree)
        report["imports"][module] = visitor.imports
        report["functions"].update(visitor.functions)
        report["calls"].extend(visitor.calls)
        report["routes"].extend(visitor.routes)
        report["env"].extend(visitor.env)
        report["db"].extend(visitor.db)
        for flow in visitor.flows:
            source_scopes.add(flow["scope"])
        for call in visitor.calls:
            callee = call["callee"]
            if callee.endswith((".execute", ".executemany")) or callee in ("eval", "exec", "yaml.load"):
                sink_scopes.setdefault(call["caller"], []).append(call)
            if callee.startswith("subprocess.") or callee in ("os.system", "popen"):
                sink_scopes.setdefault(call["caller"], []).append(call)

    called_names = {c["callee"].rsplit(".", 1)[-1] for c in report["calls"]}
    route_handlers = {r["handler"] for r in report["routes"]}
    for qname, meta in sorted(report["functions"].items()):
        short = qname.rsplit(".", 1)[-1]
        if short.startswith("_") or qname in route_handlers or short in ("main", "handler"):
            continue
        if short not in called_names:
            report["dead_code"].append({"function": qname, **meta})

    for scope in sorted(source_scopes & set(sink_scopes)):
        for sink in sink_scopes[scope]:
            report["unsafe_flows"].append({
                "scope": scope,
                "sink": sink["callee"],
                "path": sink["path"],
                "line": sink["line"],
                "message": "request-derived data and an unsafe sink appear in the same handler",
            })

    # Attestor 3.0 repository intelligence resolves cross-file edges, import cycles,
    # framework entrypoints, configuration contracts, and expression-level taint.
    graph = repo_intel.analyze(root)
    report["repo_graph"] = graph
    report["import_cycles"] = graph["import_cycles"]
    report["inheritance"] = graph["inheritance"]
    report["entrypoints"] = graph["entrypoints"]
    report["reachable"] = graph["reachable"]
    report["config_undeclared"] = graph["config_undeclared"]
    report["dead_code"] = [dict(item) for item in graph["unreferenced"]]
    if graph["unsafe_flows"]:
        report["unsafe_flows"] = [dict(item) for item in graph["unsafe_flows"]]
    report["parse_errors"].extend(
        item for item in graph["parse_errors"]
        if item not in report["parse_errors"])

    return report


def render(report: dict) -> str:
    root = report["root"]
    out = ["Project Brain for %s" % root, "=" * (18 + len(root))]
    out.append("files scanned: %d" % len(report["files"]))
    out.append("python modules: %d" % len(report["imports"]))
    out.append("functions: %d" % len(report["functions"]))
    out.append("calls: %d" % len(report["calls"]))
    out.append("routes: %d" % len(report["routes"]))
    out.append("env/config touches: %d" % len(report["env"]))
    out.append("database query sites: %d" % len(report["db"]))
    out.append("dead-code candidates: %d" % len(report["dead_code"]))
    out.append("unsafe flow candidates: %d" % len(report["unsafe_flows"]))
    out.append("resolved entrypoints/reachable: %d/%d" % (
        len(report.get("entrypoints", [])), len(report.get("reachable", []))))
    out.append("import cycles: %d" % len(report.get("import_cycles", [])))
    if report["routes"]:
        out += ["", "routes:"]
        for route in report["routes"][:12]:
            out.append("  %s %s -> %s" % (route["method"], route["route"], route["handler"]))
    if report["db"]:
        out += ["", "database:"]
        for db in report["db"][:12]:
            dyn = "dynamic" if db["dynamic"] else "literal"
            out.append("  %s:%d %s query in %s" % (db["path"], db["line"], dyn, db["scope"]))
    if report["unsafe_flows"]:
        out += ["", "unsafe flows:"]
        for flow in report["unsafe_flows"][:12]:
            out.append("  %s:%d %s -> %s" % (
                flow["path"], flow["line"], flow["scope"], flow["sink"]))
    if report["dead_code"]:
        out += ["", "dead-code candidates:"]
        for dead in report["dead_code"][:12]:
            out.append("  %s:%d %s" % (dead["path"], dead["line"], dead["function"]))
    if report.get("import_cycles"):
        out += ["", "import cycles:"]
        for cycle in report["import_cycles"][:12]:
            out.append("  " + " -> ".join(cycle + [cycle[0]]))
    if report.get("config_undeclared"):
        out += ["", "configuration used but not declared in repository templates:",
                "  " + ", ".join(report["config_undeclared"])]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="project directory to analyze")
    ap.add_argument("--json", action="store_true", help="machine-readable repository graph")
    args = ap.parse_args(argv)
    report = analyze(args.root)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 2 if report["parse_errors"] and not report["files"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
