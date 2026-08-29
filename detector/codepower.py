#!/usr/bin/env python3
"""codepower.py -- Attestor 2's coding-agent upgrade layer.

Code Power is a project/file coding review that combines Attestor's existing engines
with extra engineering views:

  - Architect Mode
  - Test Smith
  - Spec-to-Code Engine
  - Refactor Planner
  - Type Maximizer
  - Bug Oracle
  - Performance Lens
  - API Designer
  - Doc Forge
  - Migration Assistant
  - Review Duel
  - Code Contract Mode
  - Dead Code Surgeon
  - Patch Ranker
  - Self-Evolution Log

For a path it analyzes the code. For a plain-English request it delegates to
Sieve, so generated code still goes through Attestor's write/review/improve loop.
"""
from __future__ import annotations

import argparse
import ast
import os
import re

import codemax
import deepscan
import fixmemory
import grade
import metrics
import sieve

MAX_FILES = 30
MAX_ITEMS = 14

_DEF = (ast.FunctionDef, ast.AsyncFunctionDef)


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _py_files(target: str) -> list[str]:
    if os.path.isdir(target):
        return metrics.collect_paths([target])[:MAX_FILES]
    if os.path.isfile(target) and target.endswith((".py", ".pyw")):
        return [target]
    return []


def _module_name(root: str, path: str) -> str:
    rel = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(path))
    stem = os.path.splitext(rel)[0]
    return ".".join(part for part in re.split(r"[\\/]+", stem) if part != "__init__")


def _parse(source: str):
    try:
        return ast.parse(source), None
    except SyntaxError as exc:
        return None, exc


def _call_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _call_name(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _top_defs(tree) -> list[ast.AST]:
    return [node for node in tree.body if isinstance(node, (ast.ClassDef,) + _DEF)]


def architect(files: list[str], root: str) -> list[str]:
    """Describe the project shape and likely layering pressure."""
    buckets = {"interface": 0, "domain": 0, "data": 0, "tests": 0, "tools": 0}
    imports = {}
    for path in files:
        rel = os.path.relpath(path, root if os.path.isdir(root) else os.path.dirname(path))
        low = rel.lower()
        if any(word in low for word in ("route", "view", "api", "controller")):
            buckets["interface"] += 1
        elif any(word in low for word in ("model", "schema", "db", "repo", "storage")):
            buckets["data"] += 1
        elif any(word in low for word in ("service", "core", "domain", "logic")):
            buckets["domain"] += 1
        elif "test" in low:
            buckets["tests"] += 1
        else:
            buckets["tools"] += 1
        tree, error = _parse(_read(path))
        if error is not None:
            continue
        imports[rel] = sum(1 for node in ast.walk(tree)
                           if isinstance(node, (ast.Import, ast.ImportFrom)))
    lines = ["files by layer: " + ", ".join("%s=%d" % item for item in buckets.items())]
    if buckets["tests"] == 0:
        lines.append("add a tests layer; no test-like Python files were found.")
    crowded = sorted(imports.items(), key=lambda item: item[1], reverse=True)[:5]
    if crowded:
        lines.append("highest import pressure: " + "; ".join("%s=%d" % item for item in crowded))
    return lines


def test_smith(files: list[str]) -> list[str]:
    """Generate compact unittest skeletons for the first importable modules."""
    lines = []
    for path in files[:3]:
        source = _read(path)
        lines.append("skeleton for %s:" % os.path.basename(path))
        skeleton = codemax.test_skeleton(path, source).splitlines()
        lines.extend("  " + line for line in skeleton[:18])
    return lines or ["no Python files available for test generation."]


def type_maximizer(files: list[str]) -> list[str]:
    """Find missing parameter and return annotations."""
    gaps = []
    for path in files:
        for item in codemax.api_surface(_read(path), path):
            if item["kind"] not in ("function", "method"):
                continue
            if item["args"] and item["typed_args"] < item["args"]:
                gaps.append("%s:%d type %d parameter(s) on %s" % (
                    path, item["line"], item["args"] - item["typed_args"], item["name"]))
            if not item["has_return"]:
                gaps.append("%s:%d add return annotation to %s" % (
                    path, item["line"], item["name"]))
    return gaps[:MAX_ITEMS] or ["all public callables inspected have complete annotations."]


def refactor_planner(files: list[str]) -> list[str]:
    """Rank complexity hotspots and suggest safe split points."""
    funcs = []
    for path in files:
        funcs.extend(metrics.analyze_source(_read(path), path))
    ranked = sorted(funcs, key=lambda item: (item.cognitive, item.complexity, item.length),
                    reverse=True)
    out = []
    for item in ranked[:MAX_ITEMS]:
        if item.exceeded(metrics.DEFAULT_LIMITS) or item.cognitive >= 8:
            out.append("%s:%d split %s; cog=%d cx=%d len=%d" % (
                item.path, item.line, item.qualname, item.cognitive,
                item.complexity, item.length))
    return out or ["no high-pressure refactor target found."]


class _PerfVisitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.loop_depth = 0
        self.items = []

    def _add(self, node, rule: str, detail: str):
        self.items.append("%s:%d %s - %s" % (
            self.path, getattr(node, "lineno", 1), rule, detail))

    def visit_For(self, node):
        self.loop_depth += 1
        if self.loop_depth >= 2:
            self._add(node, "nested-loop", "check data sizes or use indexing/maps")
        self.generic_visit(node)
        self.loop_depth -= 1

    visit_AsyncFor = visit_For
    visit_While = visit_For

    def visit_AugAssign(self, node):
        if self.loop_depth and isinstance(node.op, ast.Add):
            self._add(node, "loop-concat", "avoid repeated string/list concatenation in loops")
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _call_name(node.func)
        if self.loop_depth and name in ("sorted", "list", "sum"):
            self._add(node, "repeated-work", "consider hoisting or streaming repeated work")
        self.generic_visit(node)


def performance_lens(files: list[str]) -> list[str]:
    """Spot small performance traps that often grow into production pain."""
    out = []
    for path in files:
        tree, error = _parse(_read(path))
        if error is not None:
            continue
        visitor = _PerfVisitor(path)
        visitor.visit(tree)
        out.extend(visitor.items)
    return out[:MAX_ITEMS] or ["no obvious local performance traps found."]


def api_designer(files: list[str]) -> list[str]:
    """Review public functions/classes for ergonomics and compatibility risk."""
    out = []
    for path in files:
        for item in codemax.api_surface(_read(path), path):
            if item["kind"] not in ("function", "method", "class"):
                continue
            if item.get("args", 0) >= 5:
                out.append("%s:%d %s has many parameters; consider an options object." % (
                    path, item["line"], item["name"]))
            if not item.get("has_doc"):
                out.append("%s:%d document behavior and edge cases for %s." % (
                    path, item["line"], item["name"]))
    return out[:MAX_ITEMS] or ["public API shape looks compact from this pass."]


def migration_assistant(files: list[str]) -> list[str]:
    """Suggest modern Python cleanup opportunities."""
    out = []
    for path in files:
        for no, line in enumerate(_read(path).splitlines(), start=1):
            if re.search(r"typing\.(List|Dict|Tuple|Set)\b", line):
                out.append("%s:%d use built-in collection generics on Python 3.9+." % (path, no))
            if re.search(r"['\"][^'\"]*%[sdfr][^'\"]*['\"]\s*%", line):
                out.append("%s:%d consider f-strings or format for clearer interpolation." % (path, no))
            if "unittest.TestCase" not in line and re.search(r"\bsuper\([^)]*,\s*self\)", line):
                out.append("%s:%d use zero-argument super() on modern Python." % (path, no))
    return out[:MAX_ITEMS] or ["no obvious migration cleanup items found."]


def bug_oracle(files: list[str]) -> list[str]:
    """Combine semantic findings with risk-shape predictions."""
    out = []
    for path in files:
        source = _read(path)
        findings = deepscan.analyze(source, path)
        for finding in findings[:5]:
            out.append("%s:%d [%s] %s -> %s" % (
                path, finding.line, finding.severity, finding.rule, finding.fix))
        fg, _findings, funcs = grade.grade_source(source, path, metrics.DEFAULT_LIMITS)
        if fg.score < 90:
            out.append("%s code-health prediction: %s %d/100; review before extending." % (
                path, fg.grade, fg.score))
        if any(item.cognitive >= 10 for item in funcs):
            out.append("%s future-bug risk: high cognitive complexity concentrates defects." % path)
    return out[:MAX_ITEMS] or ["no semantic findings or strong risk-shapes found."]


def code_contracts(files: list[str]) -> list[str]:
    """Infer lightweight pre/postcondition ideas from function signatures."""
    out = []
    for path in files:
        tree, error = _parse(_read(path))
        if error is not None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, _DEF):
                continue
            args = [arg.arg for arg in node.args.args if arg.arg != "self"]
            hints = []
            for arg in args:
                low = arg.lower()
                if any(word in low for word in ("path", "file", "dir")):
                    hints.append("%s exists or is intentionally creatable" % arg)
                if any(word in low for word in ("items", "values", "nums", "rows")):
                    hints.append("%s is iterable and not mutated unexpectedly" % arg)
                if any(word in low for word in ("count", "limit", "size", "index")):
                    hints.append("%s is non-negative" % arg)
            if hints:
                out.append("%s:%d %s preconditions: %s" % (
                    path, node.lineno, node.name, "; ".join(hints)))
    return out[:MAX_ITEMS] or ["no obvious contract candidates inferred."]


def dead_code_surgeon(files: list[str]) -> list[str]:
    """Find conservative dead-code candidates inside each module."""
    out = []
    for path in files:
        tree, error = _parse(_read(path))
        if error is not None:
            continue
        defs = {node.name: node for node in ast.walk(tree) if isinstance(node, _DEF)}
        calls = {_call_name(node.func).rsplit(".", 1)[-1]
                 for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for name, node in sorted(defs.items()):
            if name.startswith("_") or name in ("main", "run") or name.startswith("test_"):
                continue
            if name not in calls:
                out.append("%s:%d %s is not called in its own module; verify external use." % (
                    path, node.lineno, name))
    return out[:MAX_ITEMS] or ["no conservative dead-code candidates found."]


def patch_ranker(files: list[str]) -> list[str]:
    """Rank fix opportunities by severity, safety, and maintainability payoff."""
    ranked = []
    for path in files:
        source = _read(path)
        _fg, findings, funcs = grade.grade_source(source, path, metrics.DEFAULT_LIMITS)
        for tip in grade.improvements(findings, funcs, metrics.DEFAULT_LIMITS, top=6):
            score = 50
            if "[HIGH]" in tip:
                score += 30
            if "split" in tip:
                score += 10
            ranked.append((score, tip))
    ranked.sort(reverse=True)
    return ["score %d: %s" % item for item in ranked[:MAX_ITEMS]] or \
        ["no ranked patch opportunities from current findings."]


def doc_forge(files: list[str], root: str) -> list[str]:
    """Create a README/docstring outline from inspected modules."""
    names = [os.path.basename(path) for path in files[:8]]
    return [
        "README outline: purpose, quick start, configuration, security notes, test command.",
        "documented modules to mention: " + ", ".join(names) if names else "no modules found.",
        "add examples for the most public entry points from API Designer.",
        "include generated smoke tests from Test Smith as usage examples.",
    ]


def self_evolution_log() -> list[str]:
    """Summarize repeated repair memory if Attestor has learned any local patterns."""
    memory = fixmemory.load()
    patterns = memory.get("patterns", {})
    if not patterns:
        return ["no repeated repair patterns recorded yet."]
    ranked = sorted(patterns.values(), key=lambda item: item.get("count", 0), reverse=True)
    return ["%s x%d promoted=%s" % (
        item.get("rule", "unknown"), item.get("count", 0), item.get("promoted", False))
        for item in ranked[:MAX_ITEMS]]


def review_duel(files: list[str]) -> list[str]:
    """Run multiple review lenses and summarize their verdicts."""
    sections = {
        "correctness": bug_oracle(files)[:3],
        "security": ["run Security Max for full defensive review"],
        "performance": performance_lens(files)[:3],
        "maintainability": refactor_planner(files)[:3],
        "tests": test_smith(files)[:5],
    }
    out = []
    for name, items in sections.items():
        out.append(name + ": " + (items[0] if items else "clear"))
    return out


def analyze(target: str) -> dict:
    files = _py_files(target)
    root = target if os.path.isdir(target) else (os.path.dirname(target) or ".")
    return {
        "target": target,
        "files": files,
        "architect": architect(files, root),
        "test_smith": test_smith(files),
        "refactor_planner": refactor_planner(files),
        "type_maximizer": type_maximizer(files),
        "bug_oracle": bug_oracle(files),
        "performance_lens": performance_lens(files),
        "api_designer": api_designer(files),
        "doc_forge": doc_forge(files, root),
        "migration_assistant": migration_assistant(files),
        "review_duel": review_duel(files),
        "code_contracts": code_contracts(files),
        "dead_code_surgeon": dead_code_surgeon(files),
        "patch_ranker": patch_ranker(files),
        "self_evolution_log": self_evolution_log(),
    }


def _section(title: str, items: list[str]) -> list[str]:
    lines = [title + ":"]
    lines.extend("  - " + item for item in (items or ["no items"]))
    return lines


def render(report: dict) -> str:
    lines = [
        "Attestor 2 Code Power",
        "=" * 72,
        "target: " + report["target"],
        "python files analyzed: %d" % len(report["files"]),
        "",
    ]
    order = [
        ("Architect Mode", "architect"),
        ("Test Smith", "test_smith"),
        ("Spec-to-Code Engine", "spec"),
        ("Refactor Planner", "refactor_planner"),
        ("Type Maximizer", "type_maximizer"),
        ("Bug Oracle", "bug_oracle"),
        ("Performance Lens", "performance_lens"),
        ("API Designer", "api_designer"),
        ("Doc Forge", "doc_forge"),
        ("Migration Assistant", "migration_assistant"),
        ("Review Duel", "review_duel"),
        ("Code Contract Mode", "code_contracts"),
        ("Dead Code Surgeon", "dead_code_surgeon"),
        ("Patch Ranker", "patch_ranker"),
        ("Self-Evolution Log", "self_evolution_log"),
    ]
    for title, key in order:
        if key == "spec":
            items = ["plain-English requests route through Sieve for write/review/improve verification."]
        else:
            items = report[key]
        lines.extend(_section(title, items))
        lines.append("")
    return "\n".join(lines).rstrip()


def run(target: str, bus: object | None = None, rounds: int = sieve.DEFAULT_PASSES) -> tuple[str, int]:
    target = (target or "").strip()
    if not target:
        return "Code Power needs a file, folder, or coding request.", 2
    if os.path.exists(target):
        report = analyze(target)
        code = 0 if report["files"] else 1
        return render(report), code
    text, code = sieve.run(target, bus=bus, rounds=rounds)
    header = [
        "Attestor 2 Code Power prompt pipeline",
        "=" * 72,
        "request: " + target,
        "route: Sieve write/review/improve loop",
        "",
    ]
    return "\n".join(header) + text, code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="+", help="file/folder or coding request")
    parser.add_argument("--passes", type=int, default=sieve.DEFAULT_PASSES)
    parser.add_argument("--model", default="")
    args = parser.parse_args(argv)
    bus = sieve.brain.from_env(model=args.model)
    text, code = run(" ".join(args.target), bus=bus, rounds=args.passes)
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
