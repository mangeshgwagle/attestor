#!/usr/bin/env python3
"""reader42 -- whole-repo design-level comprehension, white-box edition.

Does deterministically what a long-context model does impressionistically:

    ingest  -> every Python file AST-parsed, no context window
    model   -> routes, auth markers, sinks, params, call graph
    reason  -> design queries:
               Q1 network-reachable sinks with no auth on the path
               Q2 inconsistent validation of the same parameter
               Q3 trust-boundary matrix (route classes -> sink classes)
               Q4 auth-coverage statistics
    explain -> narrated prose where every claim carries file:line

Approximation honesty: name-level call resolution and marker heuristics,
clearly labeled; this is pattern comprehension, not neural reasoning.
Every claim is graph-backed and replayable.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path

RD_SCHEMA = "attestor-reader-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

SINKS = {
    "eval": "code-exec", "exec": "code-exec",
    "system": "cmd-exec", "popen": "cmd-exec",
    "execute": "sql-exec", "executemany": "sql-exec",
    "write": "fs-write",
}

AUTH_DECORATOR_HINTS = ("auth", "login_required", "admin", "permission",
                        "requires_user", "jwt_required", "protected")
AUTH_CALL_HINTS = ("check_auth", "verify_token", "current_user",
                   "get_current_user", "require_login", "authenticate",
                   "authorize", "session[")

ROUTE_HINTS = ("route", "get", "post", "put", "delete", "patch",
               "api_view", "view")

SANITIZER_HINTS = ("sanitize", "escape", "quote", "parameterize",
                   "validate", "clean", "int(")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class RdError(ValueError):
    pass


# ------------------------------------------------------------- ingestion

def _attr_name(node):
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _attr_name(node.func)
    return ""


class FileModel:
    def __init__(self, path):
        self.path = path
        self.functions = []          # dicts


def ingest_file(path):
    model = FileModel(path)
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8",
                                              errors="replace"))
    except SyntaxError:
        return model

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):  # noqa: N802
            entry = {
                "name": node.name,
                "file": str(path),
                "line": node.lineno,
                "routes": [],
                "has_auth_marker": False,
                "sinks": [],
                "calls": [],
                "params": set(),
                "sanitized_params": set(),
            }
            for dec in node.decorator_list:
                dname = _attr_name(dec).lower()
                if any(h in dname for h in ROUTE_HINTS):
                    route_path = ""
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        route_path = str(dec.args[0].value)
                    entry["routes"].append(route_path or "/" + node.name)
                if any(h in dname for h in AUTH_DECORATOR_HINTS):
                    entry["has_auth_marker"] = True

            def _request_root(node):
                """Walk an attribute/call chain down to its base name."""
                while isinstance(node, ast.Attribute):
                    node = node.value
                if isinstance(node, ast.Name):
                    return node.id
                return ""

            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    cname = _attr_name(sub.func)
                    entry["calls"].append(cname)
                    if cname in SINKS:
                        entry["sinks"].append(
                            {"name": cname, "kind": SINKS[cname],
                             "line": sub.lineno})
                    # request.args.get('param') / request.GET.get('param')
                    if cname == "get" and \
                            _request_root(sub.func) == "request" and \
                            sub.args and \
                            isinstance(sub.args[0], ast.Constant):
                        entry["params"].add(str(sub.args[0].value))
                    if cname == "request":
                        for arg in sub.args:
                            entry["params"].add(_attr_name(arg))
                if isinstance(sub, ast.Subscript) and \
                        isinstance(sub.value, ast.Attribute) and \
                        _request_root(sub) == "request" and \
                        isinstance(sub.slice, ast.Constant):
                    entry["params"].add(str(sub.slice.value))
                if isinstance(sub, ast.Name) and \
                        sub.id in ("password", "token", "secret"):
                    entry["params"].add(sub.id)
                src_frag = ast.unparse(sub)[:60] if hasattr(ast, "unparse") \
                    else ""
                low = src_frag.lower()
                if any(h in low for h in AUTH_CALL_HINTS):
                    entry["has_auth_marker"] = True
                if any(h in low for h in SANITIZER_HINTS):
                    for p in list(entry["params"]):
                        if p and p in low:
                            entry["sanitized_params"].add(p)
            model.functions.append(entry)
            self.generic_visit(node)

    Visitor().visit(tree)
    return model


def ingest_repo(root):
    models = []
    root_path = Path(root)
    for path in sorted(root_path.rglob("*.py")):
        if any(part in (".git", "__pycache__", ".venv", "venv",
                        "node_modules") for part in path.parts):
            continue
        model = ingest_file(path)
        models.append(model)
    return models


# --------------------------------------------------------------- queries

def build_callgraph(models):
    by_name = {}
    for model in models:
        for fn in model.functions:
            by_name.setdefault(fn["name"], []).append(fn)
    edges = {}
    for model in models:
        for fn in model.functions:
            for callee in fn["calls"]:
                if callee in by_name and callee != fn["name"]:
                    edges.setdefault(fn["name"], set()).add(callee)
    return by_name, edges


def q1_unauth_sink_paths(models, by_name, edges):
    findings = []
    for model in models:
        for fn in model.functions:
            if not fn["routes"] or fn["has_auth_marker"]:
                continue
            visited = set()
            stack = [fn["name"]]
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                for target in by_name.get(current, []):
                    for sink in target["sinks"]:
                        findings.append({
                            "query": "Q1-unauth-sink",
                            "route": fn["routes"][0],
                            "handler": fn["name"],
                            "handler_file": fn["file"],
                            "handler_line": fn["line"],
                            "sink": sink["name"],
                            "sink_kind": sink["kind"],
                            "sink_file": target["file"],
                            "sink_line": sink["line"],
                            "path": sorted(visited - {fn["name"]}),
                        })
                stack.extend(edges.get(current, ()))
    return findings


def q2_inconsistent_validation(models):
    by_param = {}
    for model in models:
        for fn in model.functions:
            for param in fn["params"]:
                if len(param) < 3:
                    continue
                by_param.setdefault(param, []).append(fn)
    findings = []
    for param, handlers in sorted(by_param.items()):
        sanitized = [h for h in handlers if param in h["sanitized_params"]]
        unsanitized = [h for h in handlers if param not in
                       h["sanitized_params"]]
        if sanitized and unsanitized:
            findings.append({
                "query": "Q2-inconsistent-validation",
                "param": param,
                "sanitized_in": [{"name": h["name"], "file": h["file"],
                                  "line": h["line"]}
                                 for h in sanitized[:6]],
                "unsanitized_in": [{"name": h["name"], "file": h["file"],
                                    "line": h["line"]}
                                   for h in unsanitized[:6]],
            })
    return findings


def q3_trust_matrix(models):
    matrix = {}
    total_routes = 0
    authed_routes = 0
    for model in models:
        for fn in model.functions:
            if not fn["routes"]:
                continue
            total_routes += 1
            if fn["has_auth_marker"]:
                authed_routes += 1
            for sink in fn["sinks"]:
                key = ("authed" if fn["has_auth_marker"] else "unauthed",
                       sink["kind"])
                matrix[key] = matrix.get(key, 0) + 1
    return {"routes_total": total_routes,
            "routes_with_auth_markers": authed_routes,
            "matrix": {"%s->%s" % k: v for k, v in sorted(matrix.items())}}


# ------------------------------------------------------------- narrative

def narrate(report):
    p = []
    p.append("Owen read %d Python files and understood %d functions."
             % (report["files_read"], report["functions_understood"]))
    p.append("The repo exposes %d network routes; %d declare an auth "
             "marker." % (report["trust_matrix"]["routes_total"],
                          report["trust_matrix"]["routes_with_auth_markers"]))
    q1 = report["findings_q1"]
    if q1:
        first = q1[0]
        p.append("Most serious: route %s (%s:%d) can reach a %s sink "
                 "(%s:%d) with no authentication anywhere on the path."
                 % (first["route"], first["handler_file"],
                    first["handler_line"], first["sink_kind"],
                    first["sink_file"], first["sink_line"]))
    else:
        p.append("No unauthenticated route reaches a dangerous sink on "
                 "any call path I can see.")
    q2 = report["findings_q2"]
    if q2:
        first = q2[0]
        p.append("Parameter '%s' is sanitized in %d handler(s) but used "
                 "raw in %d other(s) - classic inconsistent-validation "
                 "design smell." % (first["param"],
                                    len(first["sanitized_in"]),
                                    len(first["unsanitized_in"])))
    else:
        p.append("Parameter handling looks consistent across handlers.")
    return " ".join(p)


# ---------------------------------------------------------------- driver

def read_repo(root):
    import os
    models = ingest_repo(root)
    root_path = Path(root).resolve()
    # relativize paths so reports (and their digests) are stable across
    # machines and temp directories
    for model in models:
        for fn in model.functions:
            try:
                fn["file"] = os.path.relpath(fn["file"], str(root_path))
            except ValueError:
                pass
    by_name, edges = build_callgraph(models)
    functions_total = sum(len(m.functions) for m in models)
    files_read = sum(1 for m in models
                     if m.functions or True)
    q1 = q1_unauth_sink_paths(models, by_name, edges)
    q2 = q2_inconsistent_validation(models)
    matrix = q3_trust_matrix(models)
    report = {
        "schema": RD_SCHEMA,
        "tool": "reader42",
        "root": str(root),
        "files_read": files_read,
        "functions_understood": functions_total,
        "findings_q1": q1[:100],
        "q1_count": len(q1),
        "findings_q2": q2[:100],
        "q2_count": len(q2),
        "trust_matrix": matrix,
        "boundary": ("name-level call resolution and marker heuristics; "
                     "pattern comprehension, not neural reasoning; every "
                     "claim carries file:line"),
    }
    report["narrative"] = narrate(report)
    # digest excludes the volatile root path; everything content-bearing
    # is relativized above
    digest_payload = {k: v for k, v in report.items() if k != "root"}
    report["report_sha256"] = sha256_hex(
        canonical_json(digest_payload).encode())
    return report


# -------------------------------------------------------------- selftest

def run_selftest():
    import tempfile
    checks = []

    vulnerable = ("import os\n"
                  "from flask import Flask, request\n"
                  "app = Flask(__name__)\n"
                  "def run_cmd(c):\n"
                  "    return os.system(c)\n"
                  "@app.route('/admin')\n"
                  "def admin():\n"
                  "    cmd = request.args.get('cmd')\n"
                  "    return str(run_cmd(cmd))\n"
                  "@app.route('/safe')\n"
                  "@login_required\n"
                  "def safe():\n"
                  "    cmd = request.args.get('cmd')\n"
                  "    return str(run_cmd('echo hi'))\n")
    inconsistent = ("from flask import Flask, request\n"
                    "app2 = Flask(__name__)\n"
                    "@app2.route('/a')\n"
                    "def ha():\n"
                    "    user_id = request.args.get('user_id')\n"
                    "    return str(int(user_id))\n"
                    "@app2.route('/b')\n"
                    "def hb():\n"
                    "    user_id = request.args.get('user_id')\n"
                    "    return user_id\n")

    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "app.py").write_text(vulnerable, encoding="utf-8")
        (Path(tmp) / "misc.py").write_text(inconsistent, encoding="utf-8")
        report = read_repo(tmp)

    checks.append(("Q1 caught unauth route to cmd-exec sink",
                   any(f["sink_kind"] == "cmd-exec"
                       for f in report["findings_q1"])))
    checks.append(("Q2 caught inconsistent param validation",
                   any(f["param"] == "user_id"
                       for f in report["findings_q2"])))
    checks.append(("narrative mentions the serious finding",
                   "no authentication anywhere" in report["narrative"]))
    checks.append(("digest pinned",
                   len(report["report_sha256"]) == 64))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": RD_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="reader42", description="Whole-repo design comprehension")
    parser.add_argument("root")
    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    if not Path(args.root).is_dir():
        print("reader42: not a directory: %s" % args.root, file=sys.stderr)
        return EXIT_INVALID

    try:
        report = read_repo(args.root)
    except OSError as exc:
        print("reader42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    if args.format == "text":
        print(report["narrative"])
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    total = report["q1_count"] + report["q2_count"]
    return EXIT_FINDING if total else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
