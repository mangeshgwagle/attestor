#!/usr/bin/env python3
"""Interprocedural, summary-based taint analysis with EVIDENCE TRACES.

This is the SOTA core. Unlike `taint_tracker` (single-pass AST pattern matching),
this builds function summaries and instantiates them at call sites, so taint
follows data ACROSS function and file boundaries -- and every finding carries the
full provenance trace: source -> each propagation hop -> sink. That trace is the
evidence that makes a finding trustworthy (and the grounding Owen Coder reasons
over in the adjudication layer).

Technique: classic function-summary interprocedural dataflow.
  1. Compute a summary per function by analysing it with each parameter treated
     as a symbolic taint source: which params reach a sink (param->sink), and
     whether the return value is tainted by a param (param->return). Iterated to
     a fixpoint so summaries can depend on other summaries (multi-hop).
  2. Analyse each function from REAL sources; at every call site, instantiate the
     callee's summary to (a) emit interprocedural sink findings with a combined
     trace and (b) propagate tainted return values for further hops.

Python only (richest AST); covers the injection CWE families.
"""
from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Reuse the vocabulary from taint_tracker (DRY), extend where useful.
from taint_tracker import TAINT_SOURCES, TAINT_SINKS, SANITIZERS  # noqa: E402

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
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


@dataclass
class FuncSummary:
    qualname: str
    file: str
    params: list[str]
    # param index -> list of (sink_type, cwe, sink_line, sink_code, trace-within-fn)
    param_sinks: dict[int, list[tuple]] = field(default_factory=dict)
    return_tainted_params: set[int] = field(default_factory=set)
    returns_source: str = ""          # set when the fn returns a value from an in-fn SOURCE
    node: ast.AST = field(default=None, repr=False)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return ""


def _is_source(node: ast.AST) -> str | None:
    # Match on exact name or attribute suffix ONLY -- never a bare substring, or
    # a function like `get_input` falsely matches the `input` source.
    full = _name(node)
    if not full:
        return None
    for src, stype in TAINT_SOURCES.items():
        if full == src or full.endswith("." + src):
            return stype
    return None


def _is_sanitizer(node: ast.Call) -> bool:
    n = _name(node.func)
    return any(n == s or n.endswith("." + s) for s in SANITIZERS)


def _sink_of(call: ast.Call) -> tuple[str, str] | None:
    n = _name(call.func)
    last = n.split(".")[-1] if n else ""
    for sink, (vuln, cwe) in TAINT_SINKS.items():
        if n == sink or n.endswith("." + sink):
            return vuln, cwe
    # any `.execute(` is a SQL sink regardless of the receiver variable name
    if last == "execute":
        return "sql_injection", "CWE-89"
    # subprocess.* with shell=True is a command-injection sink
    if n.startswith("subprocess.") or n in ("Popen", "call", "run", "check_output"):
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return "command_injection", "CWE-78"
    return None


class _FuncCollector(ast.NodeVisitor):
    """Index every function definition by a qualified name."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.funcs: dict[str, ast.AST] = {}
        self._stack: list[str] = []

    def visit_FunctionDef(self, node):
        qual = ".".join(self._stack + [node.name])
        self.funcs[qual] = node
        # also index by bare name for cross-file resolution
        self.funcs.setdefault(node.name, node)
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef


class Analyzer:
    def __init__(self):
        self.func_node: dict[str, ast.AST] = {}
        self.func_file: dict[str, str] = {}
        self.summaries: dict[str, FuncSummary] = {}
        self.findings: list[Finding] = []
        self._src_lines: dict[str, list[str]] = {}
        self._module_trees: list = []

    # --- indexing -------------------------------------------------------
    def add_file(self, filepath: str):
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                src = f.read()
            tree = ast.parse(src, filename=filepath)
        except (OSError, SyntaxError):
            return
        self._src_lines[filepath] = src.splitlines()
        col = _FuncCollector(filepath)
        col.visit(tree)
        for qual, node in col.funcs.items():
            self.func_node[qual] = node
            self.func_file[qual] = filepath
        self._module_trees.append((filepath, tree))

    def _code_at(self, filepath: str, line: int) -> str:
        lines = self._src_lines.get(filepath, [])
        return lines[line - 1] if 0 < line <= len(lines) else ""

    # --- taint evaluation within a function -----------------------------
    def _taint_of(self, node: ast.AST, env: dict[str, Taint], filepath: str,
                  call_out: list | None = None) -> Taint | None:
        """Return the Taint of an expression, or None. If call_out is provided,
        append (callee_qual, arg_index, arg_taint) for local calls with tainted
        args, so the caller can instantiate summaries."""
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.JoinedStr):  # f-string
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self._taint_of(v.value, env, filepath, call_out)
                    if t:
                        return t.hop(filepath, node.lineno,
                                     self._code_at(filepath, node.lineno),
                                     "interpolated into f-string")
            return None
        if isinstance(node, ast.BinOp):  # concatenation / %-format
            for side in (node.left, node.right):
                t = self._taint_of(side, env, filepath, call_out)
                if t:
                    return t.hop(filepath, node.lineno,
                                 self._code_at(filepath, node.lineno),
                                 "combined via operator")
            return None
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._taint_of(node.value, env, filepath, call_out)
        if isinstance(node, ast.Call):
            src = _is_source(node)
            if src:
                return Taint(src, [Step(filepath, node.lineno,
                                        self._code_at(filepath, node.lineno).strip()[:100],
                                        f"source: {src}")])
            if _is_sanitizer(node):
                return None  # sanitizer kills taint
            # .format() / .join() on a tainted string, or tainted args
            argtaint = None
            for a in node.args:
                t = self._taint_of(a, env, filepath, call_out)
                if t:
                    argtaint = t
                    break
            # tainted receiver, e.g. tainted.format(...) or "x".join(tainted)
            recv = self._taint_of(node.func, env, filepath, call_out) if isinstance(node.func, ast.Attribute) else None
            base_taint = argtaint or recv
            # interprocedural: local function returning taint-by-param
            callee = self._resolve_callee(node)
            if callee and callee in self.summaries:
                summ = self.summaries[callee]
                for i, a in enumerate(node.args):
                    at = self._taint_of(a, env, filepath, call_out)
                    if at and call_out is not None:
                        call_out.append((callee, i, at, node.lineno))
                    if at and i in summ.return_tainted_params:
                        return at.hop(filepath, node.lineno,
                                      self._code_at(filepath, node.lineno),
                                      f"returned from {callee}()")
                # function that returns an in-body SOURCE (e.g. `return request.args.get()`)
                if summ.returns_source:
                    return Taint(summ.returns_source,
                                 [Step(filepath, node.lineno,
                                       self._code_at(filepath, node.lineno).strip()[:100],
                                       f"returned from {callee}() (source: {summ.returns_source})")])
            return base_taint
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                t = self._taint_of(e, env, filepath, call_out)
                if t:
                    return t
        return None

    def _resolve_callee(self, call: ast.Call) -> str | None:
        n = _name(call.func)
        if not n:
            return None
        bare = n.split(".")[-1]
        if n in self.func_node:
            return n
        if bare in self.func_node:
            return bare
        return None

    # --- walk a function body -------------------------------------------
    def _walk(self, fn: ast.AST, filepath: str, env: dict[str, Taint],
              emit: bool, summary: FuncSummary | None):
        """Walk statements; propagate taint through env; emit sink findings.
        If summary is not None we are computing a summary (record param->sink,
        param->return) instead of/in addition to emitting real findings."""
        for node in ast.walk(fn):
            # assignment propagation
            if isinstance(node, ast.Assign):
                t = self._taint_of(node.value, env, filepath)
                if t:
                    for tgt in node.targets:
                        nm = _name(tgt)
                        if nm:
                            env[nm.split(".")[0]] = t.hop(
                                filepath, node.lineno, self._code_at(filepath, node.lineno),
                                f"flows into '{nm}'")
            elif isinstance(node, ast.AugAssign):
                t = self._taint_of(node.value, env, filepath) or self._taint_of(node.target, env, filepath)
                nm = _name(node.target)
                if t and nm:
                    env[nm.split(".")[0]] = t.hop(filepath, node.lineno,
                                                  self._code_at(filepath, node.lineno),
                                                  f"appended into '{nm}'")
            # sink checks + interprocedural arg passing
            elif isinstance(node, ast.Call):
                call_out: list = []
                sink = _sink_of(node)
                if sink:
                    vuln, cwe = sink
                    for a in list(node.args) + [k.value for k in node.keywords]:
                        t = self._taint_of(a, env, filepath, call_out)
                        if t:
                            trace = t.hop(filepath, node.lineno,
                                          self._code_at(filepath, node.lineno),
                                          f"reaches sink: {vuln}").trace
                            if summary is not None:
                                if t.source_type.startswith("param:"):
                                    pidx = int(t.source_type.split(":")[1])
                                    summary.param_sinks.setdefault(pidx, []).append(
                                        (vuln, cwe, node.lineno,
                                         self._code_at(filepath, node.lineno).strip()[:100], trace))
                            elif emit and not t.source_type.startswith("param:"):
                                self.findings.append(Finding(
                                    cwe=cwe, sink_type=vuln, sink_file=filepath,
                                    sink_line=node.lineno,
                                    sink_code=self._code_at(filepath, node.lineno).strip()[:120],
                                    source_type=t.source_type,
                                    severity=self._severity(cwe), trace=trace))
                            break
                # interprocedural: tainted arg into a local function's param->sink
                for a_i, a in enumerate(node.args):
                    at = self._taint_of(a, env, filepath)
                    callee = self._resolve_callee(node)
                    if at and callee and callee in self.summaries and not at.source_type.startswith("param:"):
                        summ = self.summaries[callee]
                        for (vuln, cwe, sline, scode, ftrace) in summ.param_sinks.get(a_i, []):
                            combined = (at.hop(filepath, node.lineno,
                                               self._code_at(filepath, node.lineno),
                                               f"passed to {callee}() as arg {a_i}").trace
                                        + ftrace)
                            if emit:
                                self.findings.append(Finding(
                                    cwe=cwe, sink_type=vuln,
                                    sink_file=summ.file, sink_line=sline, sink_code=scode,
                                    source_type=at.source_type,
                                    severity=self._severity(cwe),
                                    trace=combined[:_MAX_TRACE], interprocedural=True))
            elif isinstance(node, ast.Return) and summary is not None and node.value is not None:
                t = self._taint_of(node.value, env, filepath)
                if t and t.source_type.startswith("param:"):
                    summary.return_tainted_params.add(int(t.source_type.split(":")[1]))
                elif t:                                   # returns an in-body source
                    summary.returns_source = t.source_type

    def _severity(self, cwe: str) -> str:
        return {"CWE-78": "CRITICAL", "CWE-95": "CRITICAL", "CWE-89": "HIGH",
                "CWE-94": "CRITICAL", "CWE-502": "HIGH", "CWE-22": "HIGH",
                "CWE-918": "HIGH", "CWE-79": "MEDIUM", "CWE-611": "HIGH"}.get(cwe, "HIGH")

    # --- summary construction (fixpoint) --------------------------------
    def _build_summaries(self):
        for qual, node in self.func_node.items():
            params = [a.arg for a in getattr(node.args, "args", [])] if hasattr(node, "args") else []
            self.summaries[qual] = FuncSummary(qual, self.func_file[qual], params, node=node)
        for _ in range(_MAX_SUMMARY_ITERS):
            changed = False
            for qual, summ in self.summaries.items():
                before = (len(summ.param_sinks), len(summ.return_tainted_params),
                          sum(len(v) for v in summ.param_sinks.values()), summ.returns_source)
                env = {p: Taint(f"param:{i}", [Step(summ.file, getattr(summ.node, "lineno", 0),
                                                    "", f"parameter '{p}' (tainted by caller)")])
                       for i, p in enumerate(summ.params)}
                summ.param_sinks.clear()
                self._walk(summ.node, summ.file, env, emit=False, summary=summ)
                after = (len(summ.param_sinks), len(summ.return_tainted_params),
                         sum(len(v) for v in summ.param_sinks.values()), summ.returns_source)
                if after != before:
                    changed = True
            if not changed:
                break

    # --- top-level analysis ---------------------------------------------
    def analyze(self):
        self._build_summaries()
        seen = set()
        for qual, node in self.func_node.items():
            key = (self.func_file[qual], getattr(node, "lineno", 0))
            if key in seen:
                continue
            seen.add(key)
            env: dict[str, Taint] = {}
            self._walk(node, self.func_file[qual], env, emit=True, summary=None)
        # de-duplicate findings
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
        if os.path.isfile(p) and p.endswith(".py"):
            files.append(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                files += [os.path.join(dp, n) for n in fn if n.endswith(".py")]
    for f in files:
        az.add_file(f)
    return az.analyze()


def render(findings: list[Finding]) -> str:
    if not findings:
        return "  No taint flows detected (dataflow engine)."
    lines = [f"\n  Dataflow Analysis -- {len(findings)} flow(s) with evidence traces",
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
            "trace": [{"file": s.file, "line": s.line, "note": s.note, "code": s.code}
                      for s in f.trace],
        }
        for f in findings
    ]
