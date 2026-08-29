#!/usr/bin/env python3
"""
comprehend.py -- Attestor reads a file in many passes, builds a clear picture of how
it works, and improves it.

The idea: take a file (from GitHub or disk), read it several times, each pass
adding to the picture -- size, syntax, dependencies, definitions, complexity, the
call graph, then the bug classes and the safe fixes -- until there's a clear image
of how it works, then make it better.

Here is the honest shape of that. Every "read" below is a REAL analysis pass. More
passes build a richer *structural* model -- genuine comprehension of how the code
is assembled. What they do NOT give, on their own, is understanding of *intent* or
the ability to invent non-mechanical improvements; that needs a real model. So
Attestor reports what he truly sees, applies the mechanical fixes he is sure of, and
-- if you have wired a brain (brain.py) -- asks it for the deeper ones.

    python3 comprehend.py detect.py
    python3 comprehend.py https://github.com/owner/repo/blob/main/app.py
    python3 comprehend.py messy.py --fix --out clean.py
    python3 comprehend.py messy.py --brain           # + real-LLM suggestions
"""
from __future__ import annotations

import argparse
import ast
import os
import sys
import tempfile

import brain
import deepscan
import detect
import harvest
import rarebugs


def _imports(tree) -> list:
    out = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            out += [a.asname or a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = ("." * (node.level or 0)) + (node.module or "")
            out += [module + "." + a.name for a in node.names]
    return out


def _detect_only(source: str, ext: str) -> list:
    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8") as fh:
        fh.write(source)
        tmp = fh.name
    try:
        found = detect.scan_file(tmp)
        for f in found:
            f.path = "file" + ext
        return found
    finally:
        os.unlink(tmp)


def comprehend(source: str, path: str) -> dict:
    """Read the file in a sequence of passes; return a structured report."""
    ext = (os.path.splitext(path)[1] or ".py").lower()
    is_py = ext in (".py", ".pyw")
    passes = []

    def read(name: str, summary: str) -> None:
        passes.append((len(passes) + 1, name, summary))

    lines = source.split("\n")
    code = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    read("skim the shape",
         "%d lines (%d code, %d blank/comment)" % (len(lines), len(code), len(lines) - len(code)))

    tree = None
    if is_py:
        try:
            tree = ast.parse(source)
            read("parse to a syntax tree", "parses cleanly")
        except SyntaxError as exc:
            read("parse to a syntax tree", "SYNTAX ERROR line %s: %s" % (exc.lineno, exc.msg))

    image = None
    if tree is not None:
        imports = _imports(tree)
        shown = ", ".join(imports[:8]) + (" ..." if len(imports) > 8 else "")
        read("trace dependencies", ("%d imports: %s" % (len(imports), shown)) if imports else "no imports")

        funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
        read("map the definitions", "%d top-level function(s), %d class(es)" % (len(funcs), len(classes)))

        ranked = sorted(((f.name, deepscan.complexity(f)) for f in funcs),
                        key=lambda pair: pair[1], reverse=True)
        read("measure complexity",
             ("hottest path: %s (cyclomatic %d)" % (ranked[0][0], ranked[0][1])) if ranked
             else "no functions to rank")

        documented = sum(1 for f in funcs if ast.get_docstring(f))
        read("check documentation",
             ("%d/%d functions documented" % (documented, len(funcs))) if funcs else "no functions")

        image = deepscan.explain(source, path)
        read("build the call graph", "cross-referenced who calls whom (see the picture below)")

    regex_findings = _detect_only(source, ext)
    read("scan for known bug patterns", "%d issue(s) from the pattern engine" % len(regex_findings))

    if is_py and tree is not None:
        ast_findings = deepscan.analyze(source, path)
        read("scan for semantic bugs", "%d issue(s) from the AST engine" % len(ast_findings))
        rare_findings = rarebugs.analyze(source, path)
        read("scan for rare Python traps", "%d issue(s) from the rare-error oracle" % len(rare_findings))

    improved, applied = harvest.improve(source)
    fixable = sum(count for _, count, _ in applied)
    read("look for safe improvements", "%d mechanical fix(es) available" % fixable)

    return {
        "path": path, "ext": ext, "is_py": is_py, "passes": passes, "image": image,
        "findings": harvest.scan_content(source, ext), "applied": applied,
        "improved": improved,
    }


def render(report: dict) -> str:
    out = ["Attestor read %s in %d passes:" % (os.path.basename(report["path"]), len(report["passes"]))]
    for number, name, summary in report["passes"]:
        out.append("  read %2d  %-26s %s" % (number, name, summary))

    if report["image"]:
        out += ["", "the picture he formed", "-" * 60, report["image"]]

    findings = sorted(report["findings"], key=detect.Finding.sort_key)
    out.append("")
    if findings:
        out.append("what needs work (%d):" % len(findings))
        for f in findings:
            out.append("  line %d [%s] %s: %s" % (f.line, f.severity, f.rule, f.fix))
    else:
        out.append("what needs work: nothing the engines can see. clean.")

    if report["applied"]:
        out.append("")
        out.append("what he improved automatically:")
        for _, count, note in report["applied"]:
            out.append("  %s x%d" % (note, count))

    out += [
        "",
        "honest note: this is a STRUCTURAL read -- how the code is assembled, plus",
        "the bug classes the engines know. It is not understanding of intent, and",
        "the auto-fixes are mechanical. Deeper, novel improvements need a real",
        "model -- run again with --brain once a key works.",
    ]
    return "\n".join(out)


def _load(target: str):
    parsed = harvest.parse_github_url(target)
    if parsed:
        repo, ref, path = parsed
        try:
            content, _repo, path, _url, _lic = harvest.fetch_url(repo, ref, path)
            return content, path
        except Exception as exc:                # noqa: BLE001 -- report and bail
            print("could not fetch %s: %s" % (target, exc), file=sys.stderr)
            return None, None
    if not os.path.exists(target):
        print("no such file: " + target, file=sys.stderr)
        return None, None
    with open(target, encoding="utf-8", errors="replace") as fh:
        return fh.read(), target


def _brain_suggest(source: str, report: dict) -> str:
    bus = brain.from_env()
    if not bus.available():
        return "--brain: no LLM configured (set GEMINI_API_KEY and/or OPENAI_API_KEY)."
    issues = "; ".join("%s at line %d" % (f.rule, f.line) for f in report["findings"][:10])
    prompt = ("Review this %s file and suggest concrete improvements beyond these "
              "known issues [%s]. Be specific and brief.\n\n%s"
              % (report["ext"], issues or "none", source))
    try:
        answer = bus.generate(prompt)
    except brain.ProviderError as exc:
        return "--brain failed: %s" % exc
    if isinstance(answer, dict):
        return "\n\n".join("----- %s -----\n%s" % (name, text) for name, text in answer.items())
    return "deeper suggestions (from the brain):\n" + answer


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="a file path or a GitHub file URL")
    ap.add_argument("--fix", action="store_true", help="write the improved copy")
    ap.add_argument("--out", help="where to write the improved file")
    ap.add_argument("--brain", action="store_true",
                    help="also ask a real LLM (if a key is set) for deeper suggestions")
    args = ap.parse_args(argv)

    source, path = _load(args.target)
    if source is None:
        return 2

    report = comprehend(source, path)
    print(render(report))

    if args.brain:
        print("\n" + _brain_suggest(source, report))

    if args.fix:
        out_path = args.out or os.path.join("attestor_harvest", "improved_" + os.path.basename(path))
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(report["improved"])
        print("\nwrote improved copy -> " + out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
