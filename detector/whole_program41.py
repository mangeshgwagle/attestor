#!/usr/bin/env python3
"""Whole-program taint: follow a value across module boundaries.

``interprocedural41`` closed the argument direction but only inside one file.
The shape that actually matters in real software still slipped through:

    # views.py
    from helpers import handle
    def view(request):   handle(request.args.get("q"))

    # helpers.py
    def handle(value):   os.system("ls " + value)

Neither file contains a defect on its own.  A single-file analyser is not
merely imprecise here -- it is structurally blind, because the source and the
sink live in different translation units.  This module resolves imports, binds
call sites to functions in *other* modules, and runs one fixpoint over the
merged call graph.

Why this is the part that wants a big machine
---------------------------------------------
Whole-program analysis is where cost stops being linear.  The call graph must
be held entire, and the fixpoint re-walks it until nothing changes, so both
memory and iteration count grow with the program rather than with a file.  That
is a genuine reason to want many cores and a lot of RAM -- unlike sharding,
which only makes the same analysis finish sooner.

So the bounds are a *profile*, not a constant.  A laptop gets limits that keep
a scan interactive; a cluster gets limits that let the fixpoint actually run to
completion on a large codebase.  Every report states which profile produced it,
because a result from ``workstation`` and a result from ``cluster`` are not the
same claim about the same code.

Fail-closed, as everywhere else here: a run that exhausts its budget is
reported as incomplete with the gap named.  It is never reported as clean.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from typing import Any, Iterable

import interprocedural41 as single

SCHEMA = "attestor.whole-program-taint/1.0"
VERSION = "4.1.4"

# Bounds scale with the machine the analysis is actually running on.  The
# numbers are deliberately far apart: the point of the cluster profile is to
# let a fixpoint finish that a laptop would have to abandon.
PROFILES: dict[str, dict[str, int]] = {
    "workstation": {"max_modules": 400, "max_functions": 20_000,
                    "max_calls": 200_000, "max_iterations": 24,
                    "max_witnesses": 512},
    "server": {"max_modules": 4_000, "max_functions": 200_000,
               "max_calls": 2_000_000, "max_iterations": 96,
               "max_witnesses": 4_096},
    "cluster": {"max_modules": 60_000, "max_functions": 3_000_000,
                "max_calls": 30_000_000, "max_iterations": 512,
                "max_witnesses": 32_768},
}
DEFAULT_PROFILE = "workstation"
MAX_FILE_BYTES = 4 * 1024 * 1024

SOURCES = single.SOURCES
SINKS = single.SINKS
SANITIZERS = single.SANITIZERS


class WholeProgramError(ValueError):
    """The supplied inputs or profile are unusable."""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def _module_name(path: str, root: str) -> str:
    relative = os.path.relpath(path, root).replace("\\", "/")
    if relative.endswith(".py"):
        relative = relative[:-3]
    if relative.endswith("/__init__"):
        relative = relative[:-len("/__init__")]
    return relative.strip("./").replace("/", ".")


def _imports(tree: ast.AST) -> dict[str, str]:
    """local name -> fully qualified target it refers to."""
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                bindings[alias.asname or alias.name] = \
                    node.module + "." + alias.name
    return bindings


def _collect(source: str, module: str, limits: dict[str, int]):
    tree = ast.parse(source)
    collector = single._Collector()
    collector.visit(tree)
    functions = {}
    for name, row in collector.functions.items():
        qualified = module + "." + name if module else name
        functions[qualified] = dict(row, module=module, qualified=qualified)
    calls = []
    for call in collector.calls:
        owner = call["owner"]
        calls.append(dict(call,
                          module=module,
                          owner=(module + "." + owner) if owner else module))
    return functions, calls, _imports(tree)


def _tail_index(functions: dict[str, Any]) -> dict[str, list[str]]:
    """Bare name -> qualified names ending in it.

    Built once.  Scanning every function for every call site is O(functions x
    calls), which on a few hundred modules is billions of string comparisons --
    the difference between a whole-program run taking seconds and taking longer
    than anyone will wait.
    """
    index: dict[str, list[str]] = {}
    for name in functions:
        index.setdefault(name.rsplit(".", 1)[-1], []).append(name)
    return index


def _resolve(callee: str, owner_module: str, bindings: dict[str, str],
             functions: dict[str, Any], by_tail: dict[str, list[str]]) -> str:
    """Resolve a call to a function anywhere in the program."""
    head, _, rest = callee.partition(".")
    target = bindings.get(head)
    if target:
        candidate = target + ("." + rest if rest else "")
        if candidate in functions:
            return candidate
        # `import helpers` then `helpers.handle(...)`
        if rest and (target + "." + rest) in functions:
            return target + "." + rest
    local = owner_module + "." + callee if owner_module else callee
    if local in functions:
        return local
    if callee in functions:
        return callee
    matches = by_tail.get(callee.rsplit(".", 1)[-1], ())
    # Only bind a bare name when it is unambiguous across the program;
    # guessing between same-named functions invents call edges.
    return matches[0] if len(matches) == 1 else ""


def analyze_files(sources: Iterable[tuple[str, str]], *,
                  root: str = ".",
                  profile: str = DEFAULT_PROFILE) -> dict[str, Any]:
    """Analyse a whole program supplied as (path, source) pairs."""
    if profile not in PROFILES:
        raise WholeProgramError("unknown profile: %r (have %s)"
                                % (profile, ", ".join(sorted(PROFILES))))
    limits = PROFILES[profile]

    functions: dict[str, Any] = {}
    calls: list[dict[str, Any]] = []
    bindings: dict[str, dict[str, str]] = {}
    modules, unparsed = 0, []
    for path, source in sources:
        if modules >= limits["max_modules"]:
            unparsed.append((path, "module budget"))
            continue
        if type(source) is not str or len(source) > MAX_FILE_BYTES:
            unparsed.append((path, "oversized or non-text"))
            continue
        module = _module_name(path, root)
        try:
            found, made, imported = _collect(source, module, limits)
        except (SyntaxError, ValueError, RecursionError) as exc:
            unparsed.append((path, type(exc).__name__))
            continue
        modules += 1
        functions.update(found)
        calls.extend(made)
        bindings[module] = imported
        if len(functions) > limits["max_functions"] or \
                len(calls) > limits["max_calls"]:
            unparsed.append((path, "graph budget"))
            break

    by_tail = _tail_index(functions)
    resolved_calls = []
    for call in calls:
        target = _resolve(call["callee"], call["module"],
                          bindings.get(call["module"], {}), functions, by_tail)
        resolved_calls.append(dict(call, resolved=target))
    # The fixpoint only ever needs calls that land on a known function.
    resolved_calls = [call for call in resolved_calls if call["resolved"]] + \
                     [call for call in resolved_calls if not call["resolved"]]
    live_calls = [call for call in resolved_calls if call["resolved"]]

    tainted: dict[tuple[str, str], dict[str, Any]] = {}
    iterations, converged = 0, False
    for iterations in range(1, limits["max_iterations"] + 1):
        changed = False
        for call in live_calls:
            target = call["resolved"]
            parameters = functions[target]["parameters"]
            for argument in call["arguments"]:
                index = argument["index"]
                if index >= len(parameters) or argument["sanitised"]:
                    continue
                key = (target, parameters[index])
                if key in tainted:
                    continue
                reason = None
                if argument["source"]:
                    reason = {"kind": "source", "callee": argument["source"],
                              "module": call["module"], "line": call["line"],
                              "caller": call["owner"]}
                else:
                    for name in argument["names"]:
                        if (call["owner"], name) in tainted:
                            reason = {"kind": "forwarded",
                                      "from": "%s(%s)" % (call["owner"], name),
                                      "module": call["module"],
                                      "line": call["line"],
                                      "caller": call["owner"]}
                            break
                if reason is not None:
                    tainted[key] = reason
                    changed = True
        if not changed:
            converged = True
            break

    witnesses = []
    for call in resolved_calls:
        entry = SINKS.get(call["callee"])
        if entry is None:
            continue
        cwe, context = entry
        for argument in call["arguments"] + call["keywords"]:
            if argument["sanitised"]:
                continue
            hit = next((name for name in argument["names"]
                        if (call["owner"], name) in tainted), None)
            if hit is None:
                continue
            entered = tainted[(call["owner"], hit)]
            witnesses.append({
                "cwe": cwe, "context": context, "parameter": hit,
                "sink": {"callee": call["callee"], "line": call["line"],
                         "function": call["owner"], "module": call["module"]},
                "entered_via": entered,
                "cross_module": entered.get("module") != call["module"],
                "precision": "bounded-whole-program-argument-propagation",
            })
            break
        if len(witnesses) >= limits["max_witnesses"]:
            break

    witnesses.sort(key=lambda item: (item["sink"]["module"],
                                     item["sink"]["line"],
                                     item["sink"]["callee"]))
    report = {
        "schema": SCHEMA, "version": VERSION, "profile": profile,
        "limits": dict(limits),
        "modules": modules, "functions": len(functions),
        "calls": len(resolved_calls),
        "resolved_calls": sum(1 for c in resolved_calls if c["resolved"]),
        "cross_module_calls": sum(
            1 for c in resolved_calls
            if c["resolved"] and functions[c["resolved"]]["module"] != c["module"]),
        "tainted_parameters": len(tainted),
        "iterations": iterations, "converged": converged,
        "witnesses": witnesses,
        "cross_module_witnesses": sum(1 for w in witnesses if w["cross_module"]),
        "skipped": [{"path": p, "reason": r} for p, r in unparsed[:64]],
        "limitations": [
            "an empty result means no path was found under this profile's "
            "budget, never that the program is safe",
            "path-insensitive: a value tainted on any branch counts as tainted",
            "import resolution is static; dynamic dispatch and monkey-patching "
            "are not modelled",
            "a same-named function in several modules is only resolved when "
            "the name is unambiguous",
        ],
    }
    if not converged:
        report["coverage_gap"] = (
            "fixpoint hit the %s profile's %d-iteration bound; results are "
            "incomplete. A larger profile may find more."
            % (profile, limits["max_iterations"]))
    if unparsed:
        report.setdefault("coverage_gap", "")
        report["coverage_gap"] = (report["coverage_gap"] + " "
                                  if report["coverage_gap"] else "") + \
            "%d file(s) were not analysed." % len(unparsed)
    report["report_sha256"] = _sha(
        {k: v for k, v in report.items() if k != "report_sha256"})
    return report


def analyze_tree(root: str, *, profile: str = DEFAULT_PROFILE) -> dict[str, Any]:
    sources = []
    for current, directories, names in os.walk(root):
        directories[:] = [d for d in sorted(directories)
                          if d not in {".git", "__pycache__", "node_modules",
                                       ".venv", "venv"}]
        for name in sorted(names):
            if name.endswith(".py"):
                path = os.path.join(current, name)
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        sources.append((path, fh.read()))
                except OSError:
                    continue
    return analyze_files(sources, root=root, profile=profile)


def verify_report(report: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["report is not a mapping"]
    if report.get("schema") != SCHEMA:
        errors.append("unexpected schema")
    if report.get("profile") not in PROFILES:
        errors.append("unknown profile")
    if not report.get("converged") and not report.get("coverage_gap"):
        errors.append("a non-converged run must declare its coverage gap")
    if report.get("cross_module_witnesses", 0) > len(report.get("witnesses", [])):
        errors.append("cross-module count exceeds total witnesses")
    recomputed = _sha({k: v for k, v in report.items() if k != "report_sha256"})
    if report.get("report_sha256") != recomputed:
        errors.append("report digest does not match its content")
    return not errors, errors


def render(report: dict[str, Any]) -> str:
    lines = ["whole-program taint (profile: %s)" % report["profile"],
             "=" * 62,
             "modules=%d functions=%d calls=%d resolved=%d cross-module=%d"
             % (report["modules"], report["functions"], report["calls"],
                report["resolved_calls"], report["cross_module_calls"]),
             "iterations=%d converged=%s tainted parameters=%d"
             % (report["iterations"], report["converged"],
                report["tainted_parameters"])]
    if not report["witnesses"]:
        lines.append("no taint path found under this profile")
    for item in report["witnesses"][:40]:
        entered = item["entered_via"]
        lines.append("  %s %s at %s:%d  '%s' entered in %s:%d%s"
                     % (item["cwe"], item["sink"]["callee"],
                        item["sink"]["module"], item["sink"]["line"],
                        item["parameter"], entered.get("module", "?"),
                        entered["line"],
                        "  [CROSS-MODULE]" if item["cross_module"] else ""))
    if report.get("coverage_gap"):
        lines.append("gap: " + report["coverage_gap"])
    lines.extend("note: " + text for text in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root")
    parser.add_argument("--profile", default=DEFAULT_PROFILE,
                        choices=sorted(PROFILES))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.root):
        print("not a directory: %s" % args.root)
        return 2
    report = analyze_tree(args.root, profile=args.profile)
    print(json.dumps(report, indent=1, sort_keys=True) if args.json
          else render(report), end="" if args.json else "")
    return 1 if report["witnesses"] else 0


__all__ = ["SCHEMA", "VERSION", "PROFILES", "DEFAULT_PROFILE",
           "WholeProgramError", "analyze_files", "analyze_tree",
           "verify_report", "render"]


if __name__ == "__main__":
    raise SystemExit(main())
