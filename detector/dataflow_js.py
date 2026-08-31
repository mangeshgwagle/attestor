#!/usr/bin/env python3
"""Interprocedural taint analysis for JavaScript / TypeScript.

Same architecture as dataflow.py (summary-based interprocedural taint with
evidence traces) but parses JS/TS via regex-based extraction instead of Python
ast. Produces the same Finding / Step / trace format so confirm, adjudicate,
and reachability consume JS findings identically to Python ones.

Sources: DOM inputs (document.location, URL params, req.body, req.query,
         req.params, window.location, document.cookie, postMessage data,
         URLSearchParams, FormData, localStorage, sessionStorage).
Sinks:   innerHTML, eval, exec, child_process, document.write, Function(),
         setTimeout(string), setInterval(string), $.html(), sql query methods,
         fs path methods, redirect, open, fetch/XHR with tainted URLs.
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
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_MAX_SUMMARY_ITERS = 6
_MAX_TRACE = 24


@dataclass
class Step:
    file: str
    line: int
    code: str
    note: str


@dataclass
class Taint:
    source_type: str
    trace: list[Step] = field(default_factory=list)

    def hop(self, file: str, line: int, code: str, note: str) -> "Taint":
        return Taint(self.source_type,
                     (self.trace + [Step(file, line, code.strip()[:100], note)])[:_MAX_TRACE])


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
    interprocedural: bool = False
    confidence: str = "high"
    language: str = "javascript"


@dataclass
class FuncSummary:
    name: str
    file: str
    params: list[str]
    start_line: int
    end_line: int
    body_lines: list[str] = field(default_factory=list)
    param_sinks: dict[int, list[tuple]] = field(default_factory=dict)
    return_tainted_params: set[int] = field(default_factory=set)
    returns_source: str = ""


JS_SOURCES: dict[str, str] = {
    "req.body": "http_body",
    "req.query": "http_param",
    "req.params": "http_param",
    "req.headers": "http_header",
    "req.cookies": "http_cookie",
    "req.files": "http_upload",
    "request.body": "http_body",
    "request.query": "http_param",
    "request.params": "http_param",
    "request.headers": "http_header",
    "ctx.request.body": "http_body",
    "ctx.query": "http_param",
    "ctx.params": "http_param",
    "document.location": "dom_url",
    "window.location": "dom_url",
    "location.href": "dom_url",
    "location.search": "dom_url",
    "location.hash": "dom_url",
    "document.cookie": "dom_cookie",
    "document.referrer": "dom_referrer",
    "document.URL": "dom_url",
    "localStorage.getItem": "dom_storage",
    "sessionStorage.getItem": "dom_storage",
    "event.data": "postmessage",
    "e.data": "postmessage",
    "process.env": "env_var",
    "process.argv": "cli_arg",
}
_SOURCE_PATTERN = re.compile(
    r"(?:" + "|".join(re.escape(s) for s in sorted(JS_SOURCES, key=len, reverse=True)) + r")"
)
_URL_SEARCH_PARAMS = re.compile(r"new\s+URLSearchParams\s*\(")
_FORM_DATA = re.compile(r"new\s+FormData\s*\(")
_READLINE = re.compile(r"readline\s*\(|createInterface\s*\(")

JS_SINKS: dict[str, tuple[str, str]] = {
    "innerHTML": ("xss", "CWE-79"),
    "outerHTML": ("xss", "CWE-79"),
    "document.write": ("xss", "CWE-79"),
    "document.writeln": ("xss", "CWE-79"),
    "insertAdjacentHTML": ("xss", "CWE-79"),
    ".html(": ("xss", "CWE-79"),
    "dangerouslySetInnerHTML": ("xss", "CWE-79"),
    "eval(": ("code_injection", "CWE-95"),
    "Function(": ("code_injection", "CWE-95"),
    "exec(": ("command_injection", "CWE-78"),
    "execSync(": ("command_injection", "CWE-78"),
    "spawn(": ("command_injection", "CWE-78"),
    "spawnSync(": ("command_injection", "CWE-78"),
    "execFile(": ("command_injection", "CWE-78"),
    "child_process.exec": ("command_injection", "CWE-78"),
    "child_process.execSync": ("command_injection", "CWE-78"),
    ".execute(": ("sql_injection", "CWE-89"),
    ".query(": ("sql_injection", "CWE-89"),
    ".raw(": ("sql_injection", "CWE-89"),
    "knex.raw": ("sql_injection", "CWE-89"),
    "sequelize.query": ("sql_injection", "CWE-89"),
    "fs.readFile": ("path_traversal", "CWE-22"),
    "fs.readFileSync": ("path_traversal", "CWE-22"),
    "fs.writeFile": ("path_traversal", "CWE-22"),
    "fs.writeFileSync": ("path_traversal", "CWE-22"),
    "fs.unlink": ("path_traversal", "CWE-22"),
    "fs.unlinkSync": ("path_traversal", "CWE-22"),
    "res.redirect": ("open_redirect", "CWE-601"),
    "window.open": ("open_redirect", "CWE-601"),
    "fetch(": ("ssrf", "CWE-918"),
    "axios.get": ("ssrf", "CWE-918"),
    "axios.post": ("ssrf", "CWE-918"),
    "http.get": ("ssrf", "CWE-918"),
    "http.request": ("ssrf", "CWE-918"),
    "XMLHttpRequest": ("ssrf", "CWE-918"),
}

JS_SANITIZERS = {
    "encodeURIComponent", "encodeURI", "escape",
    "DOMPurify.sanitize", "sanitize", "escapeHtml", "escape_html",
    "validator.escape", "xss", "sanitizeHtml",
    "parseInt", "parseFloat", "Number",
    "path.basename", "path.normalize", "path.resolve",
    "JSON.stringify",
}

_SEV = {"CWE-78": "CRITICAL", "CWE-95": "CRITICAL", "CWE-89": "HIGH",
        "CWE-79": "HIGH", "CWE-22": "HIGH", "CWE-918": "HIGH",
        "CWE-601": "MEDIUM", "CWE-502": "HIGH"}

_FUNC_RE = re.compile(
    r"(?:(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)"  # function foo(a,b)
    r"|(\w+)\s*[=:]\s*(?:async\s+)?\(([^)]*)\)\s*=>"                 # const foo = (a,b) =>
    r"|(\w+)\s*[=:]\s*(?:async\s+)?function\s*\(([^)]*)\)"           # const foo = function(a,b)
    r"|(\w+)\s*\(([^)]*)\)\s*\{)"                                    # method foo(a,b) { (class method)
)

_ASSIGN_RE = re.compile(
    r"(?:(?:let|const|var)\s+)?(\w+)(?:\s*:\s*[\w<>\[\]|&, ]+)?\s*=\s*(.+?)(?:;|$)"
)

_RETURN_RE = re.compile(r"\breturn\s+(.+?)(?:;|$)")

_TEMPLATE_INTERP = re.compile(r"\$\{([^}]+)\}")


def _extract_functions(lines: list[str], filepath: str) -> list[FuncSummary]:
    funcs = []
    i = 0
    while i < len(lines):
        m = _FUNC_RE.search(lines[i])
        if m:
            name = m.group(1) or m.group(3) or m.group(5) or m.group(7) or ""
            param_str = m.group(2) or m.group(4) or m.group(6) or m.group(8) or ""
            if not name or name in ("if", "for", "while", "switch", "catch"):
                i += 1
                continue
            params = [p.strip().split(":")[0].split("=")[0].strip()
                      for p in param_str.split(",") if p.strip()]
            params = [p for p in params if p and p != "..."]
            start = i
            brace = lines[i].count("{") - lines[i].count("}")
            j = i + 1
            while j < len(lines) and brace > 0:
                brace += lines[j].count("{") - lines[j].count("}")
                j += 1
            end = min(j, len(lines))
            funcs.append(FuncSummary(
                name=name, file=filepath, params=params,
                start_line=start + 1, end_line=end,
                body_lines=lines[start:end],
            ))
            i = end
        else:
            i += 1
    return funcs


def _source_in(code: str) -> str | None:
    m = _SOURCE_PATTERN.search(code)
    if m:
        return JS_SOURCES[m.group(0)]
    if _URL_SEARCH_PARAMS.search(code):
        return "dom_url"
    if _FORM_DATA.search(code):
        return "http_body"
    if _READLINE.search(code):
        return "user_input"
    return None


def _sink_in(code: str) -> tuple[str, str] | None:
    for pattern, (vuln, cwe) in JS_SINKS.items():
        if pattern in code:
            return vuln, cwe
    st_re = re.search(r"setTimeout\s*\(\s*['\"`]", code)
    if st_re:
        return "code_injection", "CWE-95"
    si_re = re.search(r"setInterval\s*\(\s*['\"`]", code)
    if si_re:
        return "code_injection", "CWE-95"
    return None


def _is_sanitized(code: str) -> bool:
    for s in JS_SANITIZERS:
        if s in code:
            return True
    return False


class Analyzer:
    def __init__(self):
        self.funcs: dict[str, FuncSummary] = {}
        self.findings: list[Finding] = []
        self._src_lines: dict[str, list[str]] = {}
        self._file_lines: list[tuple[str, list[str]]] = []

    def add_file(self, filepath: str):
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError:
            return
        if not src.strip():
            return
        lines = src.splitlines()
        self._src_lines[filepath] = lines
        self._file_lines.append((filepath, lines))
        for func in _extract_functions(lines, filepath):
            self.funcs[func.name] = func

    def _code_at(self, filepath: str, line: int) -> str:
        lines = self._src_lines.get(filepath, [])
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def _build_summaries(self):
        for _ in range(_MAX_SUMMARY_ITERS):
            changed = False
            for name, func in self.funcs.items():
                before = (len(func.param_sinks),
                          sum(len(v) for v in func.param_sinks.values()),
                          len(func.return_tainted_params), func.returns_source)
                self._analyze_func_summary(func)
                after = (len(func.param_sinks),
                         sum(len(v) for v in func.param_sinks.values()),
                         len(func.return_tainted_params), func.returns_source)
                if after != before:
                    changed = True
            if not changed:
                break

    def _analyze_func_summary(self, func: FuncSummary):
        env: dict[str, Taint] = {}
        for i, p in enumerate(func.params):
            env[p] = Taint(f"param:{i}", [Step(func.file, func.start_line, "",
                                               f"parameter '{p}' (tainted by caller)")])
        func.param_sinks.clear()
        func.return_tainted_params.clear()
        func.returns_source = ""

        for offset, line in enumerate(func.body_lines):
            lineno = func.start_line + offset
            self._process_line(line, lineno, func.file, env,
                               emit=False, summary=func)

    def _process_line(self, line: str, lineno: int, filepath: str,
                      env: dict[str, Taint], emit: bool,
                      summary: FuncSummary | None):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return

        am = _ASSIGN_RE.search(stripped)
        rhs_sanitized = False
        if am:
            varname = am.group(1)
            rhs = am.group(2)
            if _is_sanitized(rhs):
                rhs_sanitized = True
            else:
                t = self._taint_of_expr(rhs, env, filepath, lineno)
                if t:
                    env[varname] = t.hop(filepath, lineno, stripped[:100],
                                         f"flows into '{varname}'")

        interps = _TEMPLATE_INTERP.findall(stripped)
        for expr in interps:
            t = self._taint_of_expr(expr, env, filepath, lineno)
            if t and not _is_sanitized(stripped):
                sink = _sink_in(stripped)
                if sink:
                    self._emit_or_record(t, sink, stripped, lineno, filepath,
                                         env, emit, summary)

        sink = _sink_in(stripped)
        if sink:
            for varname, taint in env.items():
                if varname in stripped and not _is_sanitized(stripped):
                    self._emit_or_record(taint, sink, stripped, lineno, filepath,
                                         env, emit, summary)
                    break
            direct_src = _source_in(stripped)
            if direct_src and not _is_sanitized(stripped):
                t = Taint(direct_src, [Step(filepath, lineno, stripped[:100],
                                            f"source: {direct_src}")])
                self._emit_or_record(t, sink, stripped, lineno, filepath,
                                     env, emit, summary)

        src = _source_in(stripped)
        if src and not sink and not rhs_sanitized:
            if am:
                varname = am.group(1)
                if varname not in env:
                    env[varname] = Taint(src, [Step(filepath, lineno, stripped[:100],
                                                    f"source: {src}")])

        rm = _RETURN_RE.search(stripped)
        if rm and summary is not None:
            ret_expr = rm.group(1)
            t = self._taint_of_expr(ret_expr, env, filepath, lineno)
            if t:
                if t.source_type.startswith("param:"):
                    summary.return_tainted_params.add(int(t.source_type.split(":")[1]))
                else:
                    summary.returns_source = t.source_type

        for fname, callee in self.funcs.items():
            call_pat = fname + "("
            if call_pat in stripped and emit:
                self._instantiate_call(fname, stripped, lineno, filepath, env)

    def _taint_of_expr(self, expr: str, env: dict[str, Taint],
                       filepath: str, lineno: int) -> Taint | None:
        if _is_sanitized(expr):
            return None
        src = _source_in(expr)
        if src:
            return Taint(src, [Step(filepath, lineno,
                                    self._code_at(filepath, lineno).strip()[:100],
                                    f"source: {src}")])
        for varname, taint in env.items():
            if re.search(r'\b' + re.escape(varname) + r'\b', expr):
                return taint
        for fname, callee in self.funcs.items():
            if fname + "(" in expr:
                if callee.returns_source:
                    return Taint(callee.returns_source, [
                        Step(filepath, lineno,
                             self._code_at(filepath, lineno).strip()[:100],
                             f"returned from {fname}() (source: {callee.returns_source})")])
                for pi in callee.return_tainted_params:
                    pass
        return None

    def _emit_or_record(self, taint: Taint, sink: tuple[str, str],
                        code: str, lineno: int, filepath: str,
                        env: dict[str, Taint], emit: bool,
                        summary: FuncSummary | None):
        vuln, cwe = sink
        trace = taint.hop(filepath, lineno, code[:100],
                          f"reaches sink: {vuln}").trace
        if summary is not None:
            if taint.source_type.startswith("param:"):
                pidx = int(taint.source_type.split(":")[1])
                summary.param_sinks.setdefault(pidx, []).append(
                    (vuln, cwe, lineno, code[:100], trace))
        elif emit and not taint.source_type.startswith("param:"):
            self.findings.append(Finding(
                cwe=cwe, sink_type=vuln, sink_file=filepath,
                sink_line=lineno, sink_code=code.strip()[:120],
                source_type=taint.source_type,
                severity=_SEV.get(cwe, "HIGH"), trace=trace))

    def _instantiate_call(self, fname: str, line: str, lineno: int,
                          filepath: str, env: dict[str, Taint]):
        callee = self.funcs.get(fname)
        if not callee:
            return
        arg_match = re.search(re.escape(fname) + r"\(([^)]*)\)", line)
        if not arg_match:
            return
        args = [a.strip() for a in arg_match.group(1).split(",") if a.strip()]
        for i, arg in enumerate(args):
            at = self._taint_of_expr(arg, env, filepath, lineno)
            if not at or at.source_type.startswith("param:"):
                continue
            for (vuln, cwe, sline, scode, ftrace) in callee.param_sinks.get(i, []):
                combined = (at.hop(filepath, lineno, line.strip()[:100],
                                   f"passed to {fname}() as arg {i}").trace + ftrace)
                self.findings.append(Finding(
                    cwe=cwe, sink_type=vuln,
                    sink_file=callee.file, sink_line=sline, sink_code=scode,
                    source_type=at.source_type,
                    severity=_SEV.get(cwe, "HIGH"),
                    trace=combined[:_MAX_TRACE], interprocedural=True))

    def analyze(self) -> list[Finding]:
        self._build_summaries()
        for filepath, lines in self._file_lines:
            env: dict[str, Taint] = {}
            for lineno_0, line in enumerate(lines):
                self._process_line(line, lineno_0 + 1, filepath, env,
                                   emit=True, summary=None)
        uniq, out = set(), []
        for f in self.findings:
            k = (f.sink_file, f.sink_line, f.sink_type, f.source_type, f.interprocedural)
            if k not in uniq:
                uniq.add(k)
                out.append(f)
        self.findings = out
        return self.findings


def scan_paths(paths: list[str]) -> list[Finding]:
    az = Analyzer()
    files = []
    for p in paths:
        if os.path.isfile(p) and os.path.splitext(p)[1] in JS_EXTENSIONS:
            files.append(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                files += [os.path.join(dp, n) for n in fn
                          if os.path.splitext(n)[1] in JS_EXTENSIONS]
    for f in files:
        az.add_file(f)
    return az.analyze()


def render(findings: list[Finding]) -> str:
    if not findings:
        return "  No taint flows detected (JS/TS dataflow engine)."
    lines = [f"\n  JS/TS Dataflow Analysis -- {len(findings)} flow(s) with evidence traces",
             "  " + "=" * 62]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        kind = "interprocedural" if f.interprocedural else "intraprocedural"
        lines.append(f"\n  [{f.severity}] {f.sink_type} ({f.cwe})  -- {kind}")
        lines.append(f"    sink: {f.sink_file}:{f.sink_line}")
        lines.append(f"    evidence trace:")
        for i, s in enumerate(f.trace):
            arrow = "  " if i == 0 else "->"
            base = s.file.replace("\\", "/").split("/")[-1]
            code = f"   {s.code.strip()}" if s.code else ""
            lines.append(f"     {arrow} {base}:{s.line}  {s.note}{code}")
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    inter = sum(1 for f in findings if f.interprocedural)
    lines.append(f"\n  {len(findings)} flow(s): {crit} critical, {inter} cross-function")
    return "\n".join(lines)


def to_dict(findings: list[Finding]) -> list[dict]:
    return [
        {
            "cwe": f.cwe, "sink_type": f.sink_type, "sink_file": f.sink_file,
            "sink_line": f.sink_line, "sink_code": f.sink_code,
            "source_type": f.source_type, "severity": f.severity,
            "interprocedural": f.interprocedural, "confidence": f.confidence,
            "language": f.language,
            "trace": [{"file": s.file, "line": s.line, "note": s.note, "code": s.code}
                      for s in f.trace],
        }
        for f in findings
    ]
