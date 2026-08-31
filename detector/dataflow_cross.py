#!/usr/bin/env python3
"""Cross-service dataflow -- trace taint across JS frontend → Python backend.

Connects the JS/TS and Python dataflow engines by matching HTTP call sites
in JavaScript (fetch, axios, XMLHttpRequest) to Flask/Express/FastAPI route
handlers in Python. When tainted data flows from a JS source into a fetch()
call body/URL, and the receiving Python endpoint passes that data to a sink,
this engine chains them into a cross-service finding.

Example:
  JS:   const name = document.location.hash;
        fetch('/api/search', {method: 'POST', body: JSON.stringify({q: name})})
  Py:   @app.route('/api/search', methods=['POST'])
        def search():
            q = request.json['q']
            cursor.execute("SELECT * FROM items WHERE name = '%s'" % q)

  → Cross-service finding: dom_url → fetch('/api/search') → request.json → SQLi

Neither the JS engine nor the Python engine catches this alone because the
taint crosses an HTTP boundary.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".next", ".nuxt", "coverage", ".cache"}
PY_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


@dataclass
class Step:
    file: str
    line: int
    code: str
    note: str


@dataclass
class Finding:
    cwe: str
    sink_type: str
    sink_file: str
    sink_line: int
    sink_code: str
    source_type: str
    severity: str
    trace: list[Step]
    interprocedural: bool = True
    confidence: str = "medium"
    language: str = "cross-service"
    client_file: str = ""
    server_file: str = ""
    endpoint: str = ""


@dataclass
class HTTPCallSite:
    file: str
    line: int
    code: str
    method: str  # GET, POST, etc.
    url: str     # the URL pattern (e.g., /api/search)
    tainted_fields: list[str] = field(default_factory=list)
    source_type: str = ""
    source_trace: list[Step] = field(default_factory=list)


@dataclass
class RouteHandler:
    file: str
    line: int
    code: str
    method: str
    path: str
    func_name: str
    framework: str  # flask, fastapi, express


_FETCH_RE = re.compile(
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]"""
)
_AXIOS_RE = re.compile(
    r"""axios\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"""
)
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]+)['"`]"""
)

_FLASK_ROUTE_RE = re.compile(
    r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?"""
)
_FASTAPI_ROUTE_RE = re.compile(
    r"""@\w+\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]"""
)
_EXPRESS_ROUTE_RE = re.compile(
    r"""(?:app|router)\.(get|post|put|delete|patch|all|use)\s*\(\s*['"]([^'"]+)['"]"""
)


_CLIENT_SOURCES: dict[str, str] = {
    "document.location": "dom_url",
    "window.location": "dom_url",
    "location.href": "dom_url",
    "location.search": "dom_url",
    "location.hash": "dom_url",
    "document.cookie": "dom_cookie",
    "document.referrer": "dom_referrer",
    "document.URL": "dom_url",
    "getElementById": "dom_input",
    "querySelector": "dom_input",
    "getElementsByName": "dom_input",
    ".value": "dom_input",
    "localStorage.getItem": "dom_storage",
    "sessionStorage.getItem": "dom_storage",
    "URLSearchParams": "dom_url",
    "FormData": "form_data",
    "event.data": "postmessage",
    "e.data": "postmessage",
    "postMessage": "postmessage",
    "req.body": "http_body",
    "req.query": "http_param",
    "req.params": "http_param",
    "request.body": "http_body",
    "request.query": "http_param",
    "process.env": "env_var",
}


def _collect_all_sources() -> dict[str, str]:
    merged = dict(_CLIENT_SOURCES)
    try:
        from dataflow_js import JS_SOURCES
        merged.update(JS_SOURCES)
    except ImportError:
        pass
    return merged


_ALL_SOURCES: dict[str, str] | None = None

def _source_in_js(code: str) -> str | None:
    global _ALL_SOURCES
    if _ALL_SOURCES is None:
        _ALL_SOURCES = _collect_all_sources()
    for pattern, stype in _ALL_SOURCES.items():
        if pattern in code:
            return stype
    return None


def extract_http_calls(filepath: str, lines: list[str],
                       taint_env: dict[str, str] | None = None) -> list[HTTPCallSite]:
    calls = []
    env = taint_env or {}

    for i, line in enumerate(lines):
        lineno = i + 1
        stripped = line.strip()

        src = _source_in_js(stripped)
        assign_m = re.search(r"(?:let|const|var)\s+(\w+)\s*=\s*(.+?)(?:;|$)", stripped)
        if assign_m and src:
            env[assign_m.group(1)] = src

        m = _FETCH_RE.search(stripped)
        if m:
            url = m.group(1)
            method = "POST" if "method" in stripped and ("POST" in stripped or "post" in stripped) else "GET"
            tainted = _find_tainted_in_call(stripped, env, lines, i)
            if tainted:
                calls.append(HTTPCallSite(
                    file=filepath, line=lineno, code=stripped[:100],
                    method=method, url=url,
                    tainted_fields=list(tainted.keys()),
                    source_type=list(tainted.values())[0],
                    source_trace=[Step(filepath, lineno, stripped[:100],
                                       f"tainted data sent to {method} {url}")],
                ))

        m = _AXIOS_RE.search(stripped)
        if m:
            method = m.group(1).upper()
            url = m.group(2)
            tainted = _find_tainted_in_call(stripped, env, lines, i)
            if tainted:
                calls.append(HTTPCallSite(
                    file=filepath, line=lineno, code=stripped[:100],
                    method=method, url=url,
                    tainted_fields=list(tainted.keys()),
                    source_type=list(tainted.values())[0],
                    source_trace=[Step(filepath, lineno, stripped[:100],
                                       f"tainted data sent to {method} {url}")],
                ))

        m = _XHR_OPEN_RE.search(stripped)
        if m:
            method, url = m.group(1), m.group(2)
            tainted = _find_tainted_in_call(stripped, env, lines, i)
            if tainted:
                calls.append(HTTPCallSite(
                    file=filepath, line=lineno, code=stripped[:100],
                    method=method, url=url,
                    tainted_fields=list(tainted.keys()),
                    source_type=list(tainted.values())[0],
                ))
    return calls


def _find_tainted_in_call(line: str, env: dict[str, str],
                          all_lines: list[str], idx: int) -> dict[str, str]:
    tainted = {}
    for var, stype in env.items():
        if var in line:
            tainted[var] = stype
    context = " ".join(all_lines[max(0, idx-2):idx+3])
    for var, stype in env.items():
        if var in context and var not in tainted:
            tainted[var] = stype
    return tainted


def extract_routes(filepath: str, lines: list[str]) -> list[RouteHandler]:
    routes = []
    for i, line in enumerate(lines):
        lineno = i + 1
        stripped = line.strip()

        m = _FLASK_ROUTE_RE.search(stripped)
        if m:
            path = m.group(1)
            methods_str = m.group(2) or "'GET'"
            methods = re.findall(r"['\"](\w+)['\"]", methods_str)
            func_name = ""
            if i + 1 < len(lines):
                fm = re.search(r"def\s+(\w+)", lines[i + 1])
                if fm:
                    func_name = fm.group(1)
            for method in (methods or ["GET"]):
                routes.append(RouteHandler(
                    file=filepath, line=lineno, code=stripped[:100],
                    method=method.upper(), path=path,
                    func_name=func_name, framework="flask"))
            continue

        m = _FASTAPI_ROUTE_RE.search(stripped)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            func_name = ""
            for j in range(i + 1, min(i + 5, len(lines))):
                fm = re.search(r"(?:async\s+)?def\s+(\w+)", lines[j])
                if fm:
                    func_name = fm.group(1)
                    break
            routes.append(RouteHandler(
                file=filepath, line=lineno, code=stripped[:100],
                method=method, path=path,
                func_name=func_name, framework="fastapi"))
            continue

        m = _EXPRESS_ROUTE_RE.search(stripped)
        if m:
            method, path = m.group(1).upper(), m.group(2)
            func_name = ""
            fm = re.search(r"(?:function\s+)?(\w+)\s*\(", stripped[m.end():])
            if fm:
                func_name = fm.group(1)
            routes.append(RouteHandler(
                file=filepath, line=lineno, code=stripped[:100],
                method=method, path=path,
                func_name=func_name, framework="express"))
    return routes


def _paths_match(call_url: str, route_path: str) -> bool:
    call_parts = [p for p in call_url.strip("/").split("/") if p]
    route_parts = [p for p in route_path.strip("/").split("/") if p]
    if len(call_parts) != len(route_parts):
        return False
    for cp, rp in zip(call_parts, route_parts):
        if rp.startswith("<") or rp.startswith("{") or rp.startswith(":"):
            continue
        if cp != rp:
            return False
    return True


def _methods_match(call_method: str, route_method: str) -> bool:
    if route_method in ("ALL", "USE"):
        return True
    return call_method == route_method


def chain(calls: list[HTTPCallSite], routes: list[RouteHandler],
          py_findings: list[dict]) -> list[Finding]:
    findings = []
    for call in calls:
        for route in routes:
            if not _paths_match(call.url, route.path):
                continue
            if not _methods_match(call.method, route.method):
                continue

            for pf in py_findings:
                pf_file = pf.get("sink_file") or pf.get("file") or ""
                if not _same_module(pf_file, route.file):
                    continue

                trace = list(call.source_trace) + [
                    Step(call.file, call.line, call.code[:100],
                         f"HTTP {call.method} {call.url} → server"),
                    Step(route.file, route.line, route.code[:100],
                         f"received by {route.framework} handler {route.func_name}()"),
                ]
                pf_trace = pf.get("trace") or []
                for step in pf_trace:
                    trace.append(Step(
                        step.get("file", ""), step.get("line", 0),
                        step.get("code", ""), step.get("note", "")))

                findings.append(Finding(
                    cwe=pf.get("cwe", ""),
                    sink_type=pf.get("sink_type", "unknown"),
                    sink_file=pf.get("sink_file", ""),
                    sink_line=int(pf.get("sink_line", 0)),
                    sink_code=pf.get("sink_code", ""),
                    source_type=call.source_type,
                    severity=pf.get("severity", "HIGH"),
                    trace=trace,
                    client_file=call.file,
                    server_file=route.file,
                    endpoint=f"{call.method} {call.url}",
                ))
    return findings


def _same_module(finding_file: str, route_file: str) -> bool:
    return (os.path.abspath(finding_file) == os.path.abspath(route_file)
            or os.path.basename(finding_file) == os.path.basename(route_file))


def scan_paths(paths: list[str]) -> list[Finding]:
    js_files, py_files = [], []
    for p in paths:
        if os.path.isfile(p):
            ext = os.path.splitext(p)[1]
            if ext in JS_EXTENSIONS:
                js_files.append(p)
            elif ext in PY_EXTENSIONS:
                py_files.append(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                for n in fn:
                    ext = os.path.splitext(n)[1]
                    fp = os.path.join(dp, n)
                    if ext in JS_EXTENSIONS:
                        js_files.append(fp)
                    elif ext in PY_EXTENSIONS:
                        py_files.append(fp)

    all_calls = []
    for jf in js_files:
        try:
            with open(jf, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
            all_calls += extract_http_calls(jf, lines)
        except OSError:
            pass

    all_routes = []
    for pf in py_files:
        try:
            with open(pf, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
            all_routes += extract_routes(pf, lines)
        except OSError:
            pass
    for jf in js_files:
        try:
            with open(jf, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
            all_routes += extract_routes(jf, lines)
        except OSError:
            pass

    py_findings = []
    if py_files:
        try:
            import dataflow
            py_findings += dataflow.to_dict(dataflow.scan_paths(py_files))
        except Exception:
            pass

    return chain(all_calls, all_routes, py_findings)


def render(findings: list[Finding]) -> str:
    if not findings:
        return "  No cross-service taint flows detected."
    lines = [
        f"\n  Cross-Service Dataflow -- {len(findings)} flow(s)",
        "  " + "=" * 62,
    ]
    for f in findings:
        lines.append(f"\n  [{f.severity}] {f.sink_type} ({f.cwe}) -- cross-service")
        lines.append(f"    client: {os.path.basename(f.client_file)}")
        lines.append(f"    endpoint: {f.endpoint}")
        lines.append(f"    server sink: {os.path.basename(f.sink_file)}:{f.sink_line}")
        lines.append(f"    source: {f.source_type}")
        if f.trace:
            lines.append(f"    trace: {len(f.trace)} steps")
    return "\n".join(lines)


def to_dict(findings: list[Finding]) -> list[dict]:
    return [
        {
            "cwe": f.cwe, "sink_type": f.sink_type, "sink_file": f.sink_file,
            "sink_line": f.sink_line, "sink_code": f.sink_code,
            "source_type": f.source_type, "severity": f.severity,
            "interprocedural": True, "confidence": f.confidence,
            "language": "cross-service",
            "client_file": f.client_file, "server_file": f.server_file,
            "endpoint": f.endpoint,
            "trace": [{"file": s.file, "line": s.line, "code": s.code, "note": s.note}
                      for s in f.trace],
        }
        for f in findings
    ]
