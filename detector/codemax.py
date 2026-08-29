#!/usr/bin/env python3
"""
codemax.py -- Attestor's maximum coding console.

Code Max is the "use every coding muscle at once" path:

  - grade the file or folder with detect + deepscan + metrics,
  - map the public API and direct in-module calls,
  - point at complexity, typing, and documentation gaps,
  - safely refine what Attestor can prove improves,
  - generate a small unittest skeleton so the next human can pin behavior,
  - delegate plain-English generation requests to Sieve's write/review/improve loop.

It stays deterministic and local for file/folder review. If the target is not a
path, Code Max hands the request to sieve.py, which uses configured providers
when available and honest offline snippets when not.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import sys

import grade
import metrics
import refine
import sieve

DEFAULT_PASSES = 200
MAX_FILES = 20
MAX_SURFACE = 24
MAX_EDGES = 24
MAX_GAPS = 12
MAX_TEST_ITEMS = 12
MAX_REFINED_LINES = 260

_DEF = (ast.FunctionDef, ast.AsyncFunctionDef)


def _read(path: str) -> tuple[str | None, str]:
    """Read UTF-8-ish source and return either text or a compact error string."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(), ""
    except OSError as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)


def _parse(source: str) -> tuple[ast.Module | None, SyntaxError | None]:
    """Parse Python source without throwing; callers render syntax failures."""
    try:
        return ast.parse(source), None
    except SyntaxError as exc:
        return None, exc


def _unparse(node: ast.AST) -> str:
    """Best-effort AST rendering for bases and annotations."""
    try:
        return ast.unparse(node)
    except Exception:
        return "..."


def _arg_nodes(node: ast.AST) -> list:
    """Return every explicit parameter node for a function-like AST node."""
    args = node.args
    out = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    if args.vararg:
        out.append(args.vararg)
    if args.kwarg:
        out.append(args.kwarg)
    return out


def _surface_entry(kind: str, node: ast.AST, owner: str = "") -> dict:
    """Convert a function or method node into a compact public-surface row."""
    arg_nodes = _arg_nodes(node) if isinstance(node, _DEF) else []
    typed = sum(1 for item in arg_nodes if item.annotation is not None)
    name = (owner + "." if owner else "") + node.name
    return {
        "kind": kind,
        "name": name,
        "line": node.lineno,
        "args": len(arg_nodes),
        "typed_args": typed,
        "has_return": bool(getattr(node, "returns", None)),
        "has_doc": bool(ast.get_docstring(node)),
        "async": isinstance(node, ast.AsyncFunctionDef),
    }


def api_surface(source: str, path: str = "<code>") -> list[dict]:
    """List top-level classes/functions and first-level class methods."""
    tree, error = _parse(source)
    if error is not None:
        return [{"kind": "syntax", "name": "<parse error>", "line": error.lineno or 1,
                 "message": error.msg, "args": 0, "typed_args": 0,
                 "has_return": False, "has_doc": False, "async": False}]
    entries: list[dict] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods = [item for item in node.body if isinstance(item, _DEF)]
            entries.append({
                "kind": "class",
                "name": node.name,
                "line": node.lineno,
                "methods": len(methods),
                "bases": ", ".join(_unparse(base) for base in node.bases),
                "has_doc": bool(ast.get_docstring(node)),
            })
            for item in methods:
                entries.append(_surface_entry("method", item, node.name))
        elif isinstance(node, _DEF):
            entries.append(_surface_entry("function", node))
    return entries[:MAX_SURFACE]


def _function_nodes(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    """Return top-level functions and class methods for direct call mapping."""
    out = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, _DEF):
                    out.append(("%s.%s" % (node.name, item.name), item))
        elif isinstance(node, _DEF):
            out.append((node.name, node))
    return out


def call_graph(source: str) -> list[tuple[str, str]]:
    """Return direct calls between functions/methods defined in the same module."""
    tree, error = _parse(source)
    if error is not None:
        return []
    functions = _function_nodes(tree)
    known = {name.split(".")[-1] for name, _ in functions}
    edges = []
    seen = set()
    for caller, node in functions:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            callee = ""
            if isinstance(child.func, ast.Name):
                callee = child.func.id
            elif isinstance(child.func, ast.Attribute):
                callee = child.func.attr
            edge = (caller, callee)
            if callee in known and callee != caller.split(".")[-1] and edge not in seen:
                seen.add(edge)
                edges.append(edge)
    return edges[:MAX_EDGES]


def _module_name(path: str) -> str:
    """Return an importable module name for a file path, or blank if unsafe."""
    name = os.path.splitext(os.path.basename(path))[0]
    return name if name.isidentifier() else ""


def _test_name(name: str) -> str:
    """Make a public symbol safe for use inside a generated unittest method."""
    clean = re.sub(r"[^0-9A-Za-z_]+", "_", name).strip("_").lower()
    if not clean or clean[0].isdigit():
        clean = "symbol_" + clean
    return clean


def test_skeleton(path: str, source: str) -> str:
    """Build a small unittest import skeleton for public module symbols."""
    module = _module_name(path)
    if not module:
        return "# Cannot build an import skeleton: module filename is not importable."
    tree, error = _parse(source)
    if error is not None:
        return "# Cannot build tests until the syntax error on line %s is fixed." % (error.lineno or 1)
    names = []
    for node in tree.body:
        if isinstance(node, (ast.ClassDef,) + _DEF) and not node.name.startswith("_"):
            names.append(node.name)
    lines = ["import unittest", "import %s as target" % module, "",
             "class GeneratedSmokeTests(unittest.TestCase):"]
    if not names:
        lines += [
            "    def test_module_imports(self):",
            "        self.assertIsNotNone(target)",
            "",
        ]
    for name in names[:MAX_TEST_ITEMS]:
        lines += [
            "    def test_%s_exists(self):" % _test_name(name),
            "        self.assertTrue(callable(target.%s))" % name,
            "",
        ]
    lines += ['if __name__ == "__main__":', "    unittest.main()"]
    return "\n".join(lines)


def _format_class_entry(item: dict) -> str:
    """Render one class row for the public API section."""
    base = " bases: " + item["bases"] if item.get("bases") else ""
    doc = "doc" if item.get("has_doc") else "no-doc"
    return "  class %s line %d, %d method(s), %s%s" % (
        item["name"], item["line"], item.get("methods", 0), doc, base)


def _format_syntax_entry(item: dict) -> str:
    """Render a syntax-error row in the public API section."""
    return "  syntax error line %d: %s" % (item["line"], item.get("message", ""))


def _format_callable_entry(item: dict) -> str:
    """Render one function or method row for the public API section."""
    async_tag = "async " if item.get("async") else ""
    doc = "doc" if item.get("has_doc") else "no-doc"
    ret = "return-typed" if item.get("has_return") else "return-untyped"
    return "  %s%s %s line %d, args %d/%d typed, %s, %s" % (
        async_tag, item["kind"], item["name"], item["line"],
        item["typed_args"], item["args"], ret, doc)


def _render_surface(entries: list[dict]) -> list[str]:
    """Render API rows without burying presentation branching in the report body."""
    if not entries:
        return ["  no top-level functions/classes found."]
    renderers = {"class": _format_class_entry, "syntax": _format_syntax_entry}
    return [renderers.get(item["kind"], _format_callable_entry)(item) for item in entries]


def _render_calls(edges: list[tuple[str, str]]) -> list[str]:
    """Render direct call graph edges, including the empty graph case."""
    if not edges:
        return ["  no direct in-module calls between public functions/methods found."]
    return ["  %s -> %s" % (caller, callee) for caller, callee in edges]


def _hotspots(funcs: list) -> list[str]:
    """Render the gnarliest measured functions first."""
    ranked = sorted(funcs, key=lambda item: (item.cognitive, item.complexity, item.length),
                    reverse=True)
    lines = []
    for item in ranked[:8]:
        status = ", ".join(item.exceeded(metrics.DEFAULT_LIMITS)) or "within limits"
        lines.append("  %s:%d %s  cog=%d cx=%d len=%d nest=%d args=%d  [%s]" % (
            os.path.basename(item.path), item.line, item.qualname, item.cognitive,
            item.complexity, item.length, item.nesting, item.args, status))
    return lines or ["  no functions measured."]


def _entry_gaps(item: dict) -> list[str]:
    """Return docstring/type gaps for one API row."""
    if item["kind"] == "class":
        return [] if item.get("has_doc") else ["add a docstring to class %s" % item["name"]]
    if item["kind"] not in ("function", "method"):
        return []
    gaps = []
    if item["args"] and item["typed_args"] < item["args"]:
        gaps.append("type %s remaining parameter(s) on %s" % (
            item["args"] - item["typed_args"], item["name"]))
    if not item["has_return"]:
        gaps.append("add a return annotation to %s" % item["name"])
    if not item["has_doc"]:
        gaps.append("add a short behavior docstring to %s" % item["name"])
    return gaps


def _metric_gaps(funcs: list) -> list[str]:
    """Return complexity-driven split/simplify guidance."""
    ranked = sorted(funcs, key=lambda metric: metric.cognitive, reverse=True)
    return ["split or simplify %s around line %d" % (item.qualname, item.line)
            for item in ranked if item.exceeded(metrics.DEFAULT_LIMITS)]


def _quality_gaps(entries: list[dict], funcs: list) -> list[str]:
    """Prioritize the code-health improvements a reviewer would ask for next."""
    gaps = []
    for item in entries:
        gaps.extend(_entry_gaps(item))
    gaps.extend(_metric_gaps(funcs))
    return list(dict.fromkeys(gaps))[:MAX_GAPS]


def _grade_line(file_grade: grade.FileGrade) -> str:
    """Compress a FileGrade into one report line."""
    return "%s %d/100, %d high, %d medium, %d low, %d/%d over threshold" % (
        file_grade.grade, file_grade.score, file_grade.findings_high,
        file_grade.findings_medium, file_grade.findings_low,
        file_grade.over_threshold, file_grade.functions)


def _review_file(path: str, rounds: int, include_refined: bool) -> tuple[str, int]:
    """Run the complete Code Max pipeline for one Python file."""
    source, err = _read(path)
    if source is None:
        return "Code Max could not read %s: %s" % (path, err), 2

    before, findings, funcs = grade.grade_source(source, path, metrics.DEFAULT_LIMITS)
    refined, changes = refine.refine(source, path, rounds=rounds)
    after, after_findings, _after_funcs = grade.grade_source(
        refined, "<codemax-refined>", metrics.DEFAULT_LIMITS)
    surface = api_surface(source, path)
    edges = call_graph(source)
    gaps = _quality_gaps(surface, funcs)

    lines = [
        "Code Max file review",
        "=" * 72,
        "source: " + path,
        "before: " + _grade_line(before),
        "after safe refinement: " + _grade_line(after),
        "safe fixes applied: %d" % len(changes),
    ]
    if changes:
        lines += ["  - " + change for change in changes]
    if findings:
        lines += ["", "highest priority findings:"]
        for item in grade.improvements(findings, funcs, metrics.DEFAULT_LIMITS, top=8):
            lines.append("  - " + item)

    lines += ["", "API surface:"] + _render_surface(surface)
    lines += ["", "call graph:"] + _render_calls(edges)
    lines += ["", "complexity hotspots:"] + _hotspots(funcs)
    lines += ["", "quality targets:"]
    lines += ["  - " + gap for gap in gaps] if gaps else ["  no obvious doc/type/complexity gaps."]
    lines += [
        "",
        "Generated smoke-test skeleton:",
        "-" * 72,
        test_skeleton(path, refined),
    ]
    if include_refined:
        body = refined
        refined_lines = refined.splitlines()
        if len(refined_lines) > MAX_REFINED_LINES:
            body = "\n".join(refined_lines[:MAX_REFINED_LINES])
            body += "\n# ... refined code truncated in report ..."
        lines += ["", "Refined code:", "-" * 72, body]

    remaining = len(after_findings)
    return "\n".join(lines), min(remaining, 250)


def _review_directory(path: str, rounds: int) -> tuple[str, int]:
    """Run the project-level Code Max summary over a directory."""
    files = metrics.collect_paths([path])[:MAX_FILES]
    if not files:
        return "Code Max found no Python files under " + path, 1

    graded = grade.collect(files, top=4)
    lines = [
        "Code Max project review",
        "=" * 72,
        "root: " + path,
        "python files reviewed: %d%s" % (
            len(files), " (limited to first %d)" % MAX_FILES if len(files) == MAX_FILES else ""),
        "",
        "grade board:",
    ]
    for file_grade, tips in graded[:MAX_FILES]:
        lines.append("  %s  %s" % (_grade_line(file_grade), file_grade.path))
        for tip in tips[:3]:
            lines.append("    - " + tip)

    all_funcs = []
    all_edges = []
    for file_path in files:
        source, _err = _read(file_path)
        if source is None:
            continue
        all_funcs += metrics.analyze_source(source, file_path)
        for caller, callee in call_graph(source):
            all_edges.append(("%s:%s" % (os.path.basename(file_path), caller), callee))

    lines += ["", "project complexity hotspots:"] + _hotspots(all_funcs)
    lines += ["", "project call graph sample:"] + _render_calls(all_edges[:MAX_EDGES])
    lines += [
        "",
        "next power move:",
        "  run Code Max on the worst file above to get its safe-refined code and test skeleton.",
    ]
    return "\n".join(lines), min(len(grade.failures(graded, "C")), 250)


def run(target: str, bus: object | None = None, rounds: int = DEFAULT_PASSES) -> tuple[str, int]:
    """Dispatch a file, directory, or prompt through Code Max."""
    target = (target or "").strip()
    if not target:
        return "Code Max needs a Python file, folder, or coding request.", 2
    if os.path.isdir(target):
        return _review_directory(target, rounds=min(rounds, 50))
    if os.path.exists(target):
        return _review_file(target, rounds=min(rounds, DEFAULT_PASSES), include_refined=True)
    text, code = sieve.run(target, bus=bus, rounds=rounds)
    header = [
        "Code Max prompt pipeline",
        "=" * 72,
        "request: " + target,
        "route: Sieve write/review/improve loop",
        "",
    ]
    return "\n".join(header) + text, code


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="+", help="Python file/folder or coding request")
    parser.add_argument("--passes", type=int, default=DEFAULT_PASSES,
                        help="max safe-refine or sieve passes")
    parser.add_argument("--model", default="", help="pin the model for prompt generation")
    args = parser.parse_args(argv)

    bus = sieve.brain.from_env(model=args.model)
    text, code = run(" ".join(args.target), bus=bus, rounds=args.passes)
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
