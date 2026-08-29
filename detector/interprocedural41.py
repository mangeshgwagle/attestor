#!/usr/bin/env python3
"""Taint that flows *into* a function through its arguments.

``semantic_graph41`` already tracks taint across function boundaries, but only
in one direction.  It computes a summary for each function's **return value**,
so this is found:

    def read_name():  return input()
    def go():         os.system("ls " + read_name())     # detected

and this is not:

    def run(part):    os.system("ls " + part)
    def go():         run(input())                       # missed

The second shape is the common one in real code: a request handler takes user
input and passes it *down* into helpers.  This module closes that direction.

Method
------
A bounded fixpoint over per-function parameter summaries.

1.  Seed: a call argument whose expression reaches a taint source.
2.  Bind: argument i of a call becomes parameter i of the resolved callee.
3.  Propagate: if a tainted parameter reaches a sink, record a witness; if it
    is passed on to another call, taint that callee's parameter too.
4.  Repeat until nothing changes, or the iteration bound is hit.

The bound is not decoration.  Recursive and mutually recursive functions make
naive propagation non-terminating, so the loop is capped and the report says
plainly whether it converged.  A run that hits the cap is reported as
incomplete rather than as clean.

Scope, stated rather than implied: single-module only.  Calls are resolved
within one file, because cross-file resolution needs import binding that
belongs to the semantic graph, not here.  Analysis is path-insensitive -- a
value tainted on any branch is treated as tainted -- which over-approximates,
and over-approximation in a security scanner is the safe direction.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
from typing import Any

import semantic_graph41 as graph

SCHEMA = "attestor.interprocedural-taint/1.0"
VERSION = "4.1.4"

MAX_FUNCTIONS = 2_000
MAX_CALLS = 20_000
MAX_WITNESSES = 512
MAX_SOURCE_BYTES = 2 * 1024 * 1024

SOURCES = frozenset(graph._SOURCE_CALLS)
SINKS = dict(graph._SINKS)
SANITIZERS = frozenset(graph._SANITIZERS)


class InterproceduralError(ValueError):
    """The supplied source or budget is unusable."""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return (base + "." + node.attr) if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _calls_in(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    return [_dotted(item.func) for item in ast.walk(node)
            if isinstance(item, ast.Call)]


def _has_source(node: ast.AST | None) -> str:
    for callee in _calls_in(node):
        if callee in SOURCES:
            return callee
    return ""


def _sanitised(node: ast.AST | None) -> bool:
    return any(callee in SANITIZERS for callee in _calls_in(node))


class _Collector(ast.NodeVisitor):
    """Functions, their parameters, their calls, and each call's arguments."""

    def __init__(self) -> None:
        self.functions: dict[str, dict[str, Any]] = {}
        self.calls: list[dict[str, Any]] = []
        self.scope: list[str] = []

    def _owner(self) -> str:
        return ".".join(self.scope)

    def _function(self, node) -> None:
        name = ".".join(self.scope + [node.name])
        if len(self.functions) < MAX_FUNCTIONS:
            arguments = node.args
            positional = [item.arg for item in
                          list(getattr(arguments, "posonlyargs", []))
                          + list(arguments.args)]
            self.functions[name] = {
                "name": name, "line": node.lineno,
                "parameters": positional,
                "keyword_parameters": [item.arg for item in arguments.kwonlyargs],
            }
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if len(self.calls) < MAX_CALLS:
            self.calls.append({
                "owner": self._owner(),
                "callee": _dotted(node.func),
                "line": node.lineno,
                "arguments": [
                    {"index": index,
                     "names": sorted(_names(argument)),
                     "source": _has_source(argument),
                     "sanitised": _sanitised(argument)}
                    for index, argument in enumerate(node.args)],
                "keywords": [
                    {"name": keyword.arg,
                     "names": sorted(_names(keyword.value)),
                     "source": _has_source(keyword.value),
                     "sanitised": _sanitised(keyword.value)}
                    for keyword in node.keywords if keyword.arg],
            })
        self.generic_visit(node)


def _resolve(callee: str, owner: str, functions: dict[str, Any]) -> str:
    """Resolve a call to a function defined in this module, or "" if external."""
    if callee in functions:
        return callee
    parts = owner.split(".") if owner else []
    while parts:
        candidate = ".".join(parts + [callee])
        if candidate in functions:
            return candidate
        parts.pop()
    tail = callee.rsplit(".", 1)[-1]
    return tail if tail in functions else ""


def analyze(source: str, path: str = "<code>") -> dict[str, Any]:
    """Find taint that reaches a sink only by being passed as an argument."""
    if type(source) is not str:
        raise InterproceduralError("source must be text")
    if len(source) > MAX_SOURCE_BYTES:
        raise InterproceduralError("source exceeds the analysis boundary")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return {"schema": SCHEMA, "version": VERSION, "path": path,
                "status": "unparsed", "reason": type(exc).__name__,
                "witnesses": [], "converged": True, "iterations": 0,
                "functions": 0, "limitations": _limitations()}

    collector = _Collector()
    collector.visit(tree)
    functions, calls = collector.functions, collector.calls

    # tainted[(function, parameter)] -> how it became tainted
    tainted: dict[tuple[str, str], dict[str, Any]] = {}
    iterations = 0
    converged = False
    for iterations in range(1, 0 + 1):
        changed = False
        for call in calls:
            target = _resolve(call["callee"], call["owner"], functions)
            if not target:
                continue
            parameters = functions[target]["parameters"]
            bindings = [(argument["index"], argument) for argument in call["arguments"]]
            for index, argument in bindings:
                if index >= len(parameters) or argument["sanitised"]:
                    continue
                key = (target, parameters[index])
                if key in tainted:
                    continue
                reason = None
                if argument["source"]:
                    reason = {"kind": "source", "callee": argument["source"],
                              "line": call["line"], "caller": call["owner"]}
                else:
                    for name in argument["names"]:
                        if (call["owner"], name) in tainted:
                            reason = {"kind": "forwarded",
                                      "from": "%s(%s)" % (call["owner"], name),
                                      "line": call["line"],
                                      "caller": call["owner"]}
                            break
                if reason is not None:
                    tainted[key] = reason
                    changed = True
        if not changed:
            converged = True
            break

    witnesses: list[dict[str, Any]] = []
    for call in calls:
        entry = SINKS.get(call["callee"])
        if entry is None:
            continue
        cwe, context = entry
        for argument in call["arguments"] + call["keywords"]:
            if argument["sanitised"]:
                continue
            for name in argument["names"]:
                key = (call["owner"], name)
                if key not in tainted:
                    continue
                witnesses.append({
                    "path": path,
                    "cwe": cwe,
                    "context": context,
                    "sink": {"callee": call["callee"], "line": call["line"],
                             "function": call["owner"]},
                    "parameter": name,
                    "entered_via": tainted[key],
                    "precision": "bounded-argument-propagation",
                })
                break
            if len(witnesses) >= MAX_WITNESSES:
                break

    witnesses.sort(key=lambda item: (item["sink"]["line"],
                                     item["sink"]["callee"], item["parameter"]))
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "path": path,
        "status": "analyzed",
        "functions": len(functions),
        "calls": len(calls),
        "tainted_parameters": len(tainted),
        "iterations": iterations,
        "converged": converged,
        "witnesses": witnesses[:MAX_WITNESSES],
        "limitations": _limitations(),
    }
    if not converged:
        report["coverage_gap"] = (
            "argument propagation hit its %d-iteration bound; results are "
            "incomplete, not clean" % 0)
    report["report_sha256"] = _sha(
        {key: value for key, value in report.items() if key != "report_sha256"})
    return report


def _limitations() -> list[str]:
    return [
        "single module: calls are resolved within one file only",
        "path-insensitive: a value tainted on any branch counts as tainted",
        "an empty result means no argument-borne path was found, never that "
        "the file is safe",
        "complements semantic_graph41, which covers taint returned from a "
        "callee; this covers taint passed into one",
    ]


def verify_report(report: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["report is not a mapping"]
    if report.get("schema") != SCHEMA:
        errors.append("unexpected schema")
    if report.get("status") == "analyzed":
        if not report.get("converged") and "coverage_gap" not in report:
            errors.append("a non-converged run must declare its coverage gap")
        recomputed = _sha({key: value for key, value in report.items()
                           if key != "report_sha256"})
        if report.get("report_sha256") != recomputed:
            errors.append("report digest does not match its content")
    return not errors, errors


def analyze_path(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return analyze(handle.read(), path)


def render(report: dict[str, Any]) -> str:
    lines = ["interprocedural taint: %s" % report["path"], "=" * 60]
    if report["status"] != "analyzed":
        lines.append("not analyzed (%s)" % report.get("reason", "?"))
        return "\n".join(lines) + "\n"
    lines.append("functions=%d calls=%d tainted parameters=%d "
                 "iterations=%d converged=%s"
                 % (report["functions"], report["calls"],
                    report["tainted_parameters"], report["iterations"],
                    report["converged"]))
    if not report["witnesses"]:
        lines.append("no argument-borne taint path found")
    for item in report["witnesses"]:
        entered = item["entered_via"]
        lines.append("  %s at %s:%d  parameter '%s' entered at line %d (%s)"
                     % (item["cwe"], item["sink"]["callee"],
                        item["sink"]["line"], item["parameter"],
                        entered["line"],
                        entered.get("callee") or entered.get("from", "?")))
    lines.extend("note: " + text for text in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.path):
        print("no such file: %s" % args.path)
        return 2
    report = analyze_path(args.path)
    print(json.dumps(report, indent=1, sort_keys=True) if args.json
          else render(report), end="" if args.json else "")
    return 1 if report.get("witnesses") else 0


__all__ = ["SCHEMA", "VERSION", "0", "InterproceduralError",
           "analyze", "analyze_path", "verify_report", "render"]


if __name__ == "__main__":
    raise SystemExit(main())
