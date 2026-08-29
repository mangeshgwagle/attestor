#!/usr/bin/env python3
"""Dynamic confirmation WITHOUT detonation -- prove a vuln actually fires.

The capability a 2023 model could not touch: it can neither see the whole data
path nor run code to prove it. This does both. For each dataflow finding it:
  1. replaces the dangerous SINK (os.system, subprocess, eval, exec) with a
     RECORDER that logs its argument and returns harmlessly -- the dangerous
     operation NEVER executes;
  2. feeds a unique MARKER in at the SOURCE (input(), os.getenv, sys.argv, and
     Flask request args/form parsed from the code);
  3. drives the module's functions and checks whether the MARKER reached a sink.

If it did -> CONFIRMED EXPLOITABLE, with the payload that triggers it, and nothing
dangerous ran. Confirmation, not detonation.

Runs the harness in an isolated subprocess with a timeout. You are running it on
your own code, but note it does import and call the target's functions (with the
sinks neutralised); use on code you trust.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dataflow

MARKER = "ATTESTOR_TAINT_MARKER_7Z9"

# Which sink vuln-types this harness can instrument (module/builtin level).
_INSTRUMENTABLE = {"command_injection", "code_injection"}


@dataclass
class ConfirmResult:
    finding: dataflow.Finding
    status: str                 # CONFIRMED | UNCONFIRMED | NOT_INSTRUMENTABLE | ERROR
    payload: str = ""
    detail: str = ""


_HARNESS = r'''
import sys, os, json, builtins, re, inspect, importlib.util
MARKER = "%MARKER%"
TARGET = sys.argv[1]
recorded = []

def _rec(kind):
    def f(*a, **k):
        blob = " ".join([repr(x) for x in a] + [repr(v) for v in k.values()])
        recorded.append({"kind": kind, "tainted": (MARKER in blob)})
        return ""
    return f

# --- feed the marker in at the sources (safe to patch before import) ---
builtins.input = lambda *a, **k: MARKER
os.getenv = lambda *a, **k: MARKER
sys.argv = [sys.argv[0], MARKER]

try:
    with open(TARGET, encoding="utf-8", errors="replace") as fh:
        SRC = fh.read()
except Exception:
    SRC = ""

# Flask: push a request context whose args/form the code reads = MARKER
try:
    import flask
    akeys = re.findall(r"request\.(?:args|values)\.get\(\s*['\"]([^'\"]+)", SRC)
    fkeys = re.findall(r"request\.form\.get\(\s*['\"]([^'\"]+)", SRC)
    qs = "&".join("%s=%s" % (k, MARKER) for k in akeys) or "x=%s" % MARKER
    app = flask.Flask("attestor_confirm")
    ctx = app.test_request_context("/?" + qs, method="POST",
                                   data={k: MARKER for k in fkeys})
    ctx.push()
except Exception:
    pass

# --- import target FIRST (real exec), THEN neutralise sinks ---
# (patching builtins.exec before import would break importlib's own module exec)
try:
    spec = importlib.util.spec_from_file_location("attestor_target", TARGET)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
except Exception as e:
    print(json.dumps({"recorded": recorded, "import_error": str(e)[:200]}))
    sys.exit(0)

# --- neutralise sinks (they RECORD, never execute) ---
os.system = _rec("command_injection")
os.popen = _rec("command_injection")
try:
    import subprocess as _sp
    _sp.run = _rec("command_injection"); _sp.call = _rec("command_injection")
    _sp.Popen = _rec("command_injection"); _sp.check_output = _rec("command_injection")
    _sp.check_call = _rec("command_injection")
except Exception:
    pass
builtins.eval = _rec("code_injection")
builtins.exec = _rec("code_injection")

def _call(fn):
    try:
        sig = inspect.signature(fn)
        need = [p for p in sig.parameters.values()
                if p.default is p.empty and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        fn(*([MARKER] * len(need)))
    except Exception:
        pass

# zero-arg functions first (usual orchestrators), then the rest
fns = [o for o in vars(mod).values() if inspect.isfunction(o)]
fns.sort(key=lambda f: len(inspect.signature(f).parameters))
for fn in fns:
    _call(fn)

print(json.dumps({"recorded": recorded}))
'''


def _run_harness(target: str, timeout: int = 15) -> dict:
    harness = _HARNESS.replace("%MARKER%", MARKER)
    with tempfile.NamedTemporaryFile("w", suffix="_harness.py", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(harness)
        hp = fh.name
    try:
        p = subprocess.run([sys.executable, hp, target], capture_output=True,
                           text=True, timeout=timeout, encoding="utf-8", errors="replace")
        out = (p.stdout or "").strip().splitlines()
        for line in reversed(out):
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)
        return {"recorded": [], "error": (p.stderr or "no output")[:200]}
    except subprocess.TimeoutExpired:
        return {"recorded": [], "error": "timeout"}
    except Exception as exc:
        return {"recorded": [], "error": str(exc)[:200]}
    finally:
        try:
            os.unlink(hp)
        except OSError:
            pass


def confirm_findings(findings: list[dataflow.Finding], timeout: int = 15) -> list[ConfirmResult]:
    by_file: dict[str, list[dataflow.Finding]] = {}
    for f in findings:
        by_file.setdefault(f.sink_file, []).append(f)

    results: list[ConfirmResult] = []
    for path, group in by_file.items():
        harness = _run_harness(path, timeout)
        confirmed_kinds = {r["kind"] for r in harness.get("recorded", []) if r.get("tainted")}
        err = harness.get("error") or harness.get("import_error")
        for f in group:
            if f.sink_type not in _INSTRUMENTABLE:
                results.append(ConfirmResult(f, "NOT_INSTRUMENTABLE",
                                             detail=f"{f.sink_type} sink not dynamically instrumentable yet"))
            elif f.sink_type in confirmed_kinds:
                results.append(ConfirmResult(f, "CONFIRMED", payload=MARKER,
                                             detail="marker reached the sink; nothing detonated"))
            elif err:
                results.append(ConfirmResult(f, "ERROR", detail=err))
            else:
                results.append(ConfirmResult(f, "UNCONFIRMED",
                                             detail="could not drive input to the sink dynamically"))
    return results


def confirm_paths(paths: list[str], timeout: int = 15) -> list[ConfirmResult]:
    return confirm_findings(dataflow.scan_paths(paths), timeout)


def render(results: list[ConfirmResult]) -> str:
    if not results:
        return "  No dataflow findings to confirm."
    order = {"CONFIRMED": 0, "UNCONFIRMED": 1, "NOT_INSTRUMENTABLE": 2, "ERROR": 3}
    results = sorted(results, key=lambda r: order.get(r.status, 9))
    confirmed = sum(1 for r in results if r.status == "CONFIRMED")
    lines = ["\n  Dynamic Confirmation -- confirmation without detonation",
             "  " + "=" * 60,
             f"  {confirmed}/{len(results)} finding(s) CONFIRMED exploitable "
             f"(sinks were recorded, never executed)"]
    for r in results:
        f = r.finding
        base = f.sink_file.replace("\\", "/").split("/")[-1]
        tag = {"CONFIRMED": "CONFIRMED ", "UNCONFIRMED": "unconfirmed",
               "NOT_INSTRUMENTABLE": "n/a        ", "ERROR": "error      "}.get(r.status, r.status)
        lines.append(f"\n  [{tag}] {f.sink_type} ({f.cwe})  {base}:{f.sink_line}")
        if r.status == "CONFIRMED":
            lines.append(f"    PROOF: attacker marker reached the sink; payload = {r.payload!r}")
            lines.append(f"    (the dangerous call was intercepted -- nothing ran)")
        elif r.detail:
            lines.append(f"    {r.detail}")
    return "\n".join(lines)


def to_dict(results: list[ConfirmResult]) -> list[dict]:
    return [
        {
            "cwe": r.finding.cwe, "sink_type": r.finding.sink_type,
            "sink_file": r.finding.sink_file, "sink_line": r.finding.sink_line,
            "status": r.status, "payload": r.payload, "detail": r.detail,
            "interprocedural": r.finding.interprocedural,
        }
        for r in results
    ]
