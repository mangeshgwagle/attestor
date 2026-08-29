#!/usr/bin/env python3
"""
metrics.py -- Attestor's third engine: maintainability, measured.

detect.py finds *bugs* by regex; deepscan.py finds *semantic* bugs by AST. Neither
tells you the thing every reviewer eyeballs first: "this function is too much." A
200-line function with a complexity of 40 may have zero detectable bugs today and
still be the place tomorrow's bug will hide. This engine measures that, per
function, deterministically -- no keys, no network, just the AST.

For every function/method (nested ones and async included) it reports:

  - cyclomatic complexity -- McCabe: 1 + each independent branch. Counted:
    if/elif, for, while, except, ternary (a if c else b), each `and`/`or` operand
    past the first, each `if` clause in a comprehension, and each match `case`.
    (assert and plain else are NOT counted -- they add no new path.)
  - cognitive complexity -- SonarSource model: how hard the code is to *follow*.
    Every control-flow break scores +1, and a break nested inside others costs
    +1 more per level of nesting -- so deep code hurts more than flat code with
    the same cyclomatic number. This is the sharper of the two: it is what makes
    a reviewer's eyes glaze over. elif/else and boolean chains score a flat +1.
  - nesting depth   -- how deep the deepest block sits (function body = 1;
    if/elif/else and try/except branches share their parent's level).
  - length          -- source lines the def spans.
  - args            -- declared parameters (incl. *args/**kwargs).

A function is FLAGGED when it exceeds any threshold. Exit code = number of flagged
functions (capped at 250), so CI can gate on it exactly like detect.py:

    python3 metrics.py app.py                       # human report
    python3 metrics.py src/ --max-complexity 8      # stricter gate, recurse a dir
    python3 metrics.py app.py --top 5               # 5 gnarliest, ignore thresholds
    python3 metrics.py app.py --json                # machine-readable
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import asdict, dataclass

DEFAULT_LIMITS = {"complexity": 10, "cognitive": 15, "length": 60, "nesting": 4, "args": 6}

# Statements that open a nested block (used for nesting depth).
_BLOCK = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith,
          ast.Try, ast.Match)
_DEF = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass
class FuncMetric:
    path: str
    qualname: str
    line: int          # 1-indexed, where the def starts
    complexity: int
    cognitive: int
    length: int
    nesting: int
    args: int

    def exceeded(self, limits: dict) -> list[str]:
        """Which limits this function blows past, worst-first-ish for reporting."""
        over = []
        if self.complexity > limits["complexity"]:
            over.append("complexity")
        if self.cognitive > limits["cognitive"]:
            over.append("cognitive")
        if self.length > limits["length"]:
            over.append("length")
        if self.nesting > limits["nesting"]:
            over.append("nesting")
        if self.args > limits["args"]:
            over.append("args")
        return over

    def value(self, name: str) -> int:
        return getattr(self, name)


# --------------------------------------------------------------------------- #
# The three measurements. Each stops at a nested def boundary: a nested function
# is its own scope and gets its own FuncMetric, so its internals never inflate
# the enclosing one.
# --------------------------------------------------------------------------- #
def _decisions(node) -> int:
    total = 0
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _DEF):
            continue                       # separate scope, measured on its own
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While,
                              ast.ExceptHandler, ast.IfExp)):
            total += 1
        elif isinstance(child, ast.BoolOp):
            total += len(child.values) - 1
        elif isinstance(child, ast.comprehension):
            total += len(child.ifs)
        elif isinstance(child, ast.match_case):
            total += 1
        total += _decisions(child)
    return total


def _if_blocks(stmt) -> list:
    """An if's nested blocks, flattening the elif chain so if/elif/else all sit
    at one level (Python nests each elif as an If inside the previous orelse)."""
    blocks = [stmt.body]
    orelse = stmt.orelse
    while len(orelse) == 1 and isinstance(orelse[0], ast.If):
        blocks.append(orelse[0].body)
        orelse = orelse[0].orelse
    if orelse:
        blocks.append(orelse)
    return blocks


def _child_blocks(stmt) -> list:
    """The nested statement-blocks a compound statement opens. if/elif/else and
    the arms of try/except/finally are returned flat -- they share one level."""
    if isinstance(stmt, ast.If):
        return _if_blocks(stmt)
    if isinstance(stmt, ast.Match):
        return [case.body for case in stmt.cases]
    blocks = [getattr(stmt, f, None) for f in ("body", "orelse", "finalbody")]
    blocks += [h.body for h in getattr(stmt, "handlers", [])]
    return [b for b in blocks if b]


def _block_depth(stmts, depth: int = 1) -> int:
    """Deepest block level in a list of statements; a nested compound statement
    adds one level. Nested defs/classes are their own scope and are skipped."""
    best = depth
    for stmt in stmts:
        if isinstance(stmt, _DEF + (ast.ClassDef,)):
            continue
        for block in _child_blocks(stmt):
            best = max(best, _block_depth(block, depth + 1))
    return best


class _Cognitive:
    """SonarSource cognitive-complexity walker (see _cognitive). Each control-flow
    break scores +1; one nested inside others also adds the current nesting level,
    so deep code costs more than flat code with the same branch count. elif/else,
    boolean chains, and loop-else score a flat +1. Nested defs are their own scope.
    A per-node-type dispatch table keeps each handler small."""

    def __init__(self):
        self.total = 0

    def run(self, fn) -> int:
        self._block(fn.body, 0)
        return self.total

    def _block(self, stmts, nesting) -> None:
        for stmt in stmts:
            self._visit(stmt, nesting)

    def _visit(self, node, nesting) -> None:
        handler = self._HANDLERS.get(type(node))
        if handler is not None:
            handler(self, node, nesting)
        else:
            for child in ast.iter_child_nodes(node):
                self._visit(child, nesting)

    def _if(self, node, nesting) -> None:
        self.total += 1 + nesting
        self._visit(node.test, nesting)
        self._block(node.body, nesting + 1)
        orelse = node.orelse
        while orelse:
            if len(orelse) == 1 and isinstance(orelse[0], ast.If):
                branch = orelse[0]                       # elif: +1 flat, same depth
                self.total += 1
                self._visit(branch.test, nesting)
                self._block(branch.body, nesting + 1)
                orelse = branch.orelse
            else:
                self.total += 1                          # else: +1 flat
                self._block(orelse, nesting + 1)
                orelse = []

    def _loop(self, node, nesting) -> None:
        self.total += 1 + nesting
        self._visit(node.test if isinstance(node, ast.While) else node.iter, nesting)
        self._block(node.body, nesting + 1)
        if node.orelse:
            self.total += 1                              # loop-else: +1 flat
            self._block(node.orelse, nesting + 1)

    def _try(self, node, nesting) -> None:
        self._block(node.body, nesting)                  # try itself does not break flow
        for handler in node.handlers:
            self.total += 1 + nesting
            self._block(handler.body, nesting + 1)
        self._block(node.orelse, nesting)
        self._block(node.finalbody, nesting)

    def _with(self, node, nesting) -> None:
        self._block(node.body, nesting)                  # with does not break flow

    def _match(self, node, nesting) -> None:
        self.total += 1 + nesting
        for case in node.cases:
            self._block(case.body, nesting + 1)

    def _ternary(self, node, nesting) -> None:           # a if cond else b
        self.total += 1 + nesting
        self._visit(node.test, nesting)
        self._visit(node.body, nesting + 1)
        self._visit(node.orelse, nesting + 1)

    def _boolop(self, node, nesting) -> None:            # and/or sequence: flat +1
        self.total += 1
        for value in node.values:
            self._visit(value, nesting)

    def _skip(self, node, nesting) -> None:
        return                                           # nested def/lambda: own scope

    _HANDLERS = {
        ast.If: _if,
        ast.For: _loop, ast.AsyncFor: _loop, ast.While: _loop,
        ast.Try: _try,
        ast.With: _with, ast.AsyncWith: _with,
        ast.Match: _match,
        ast.IfExp: _ternary,
        ast.BoolOp: _boolop,
        ast.FunctionDef: _skip, ast.AsyncFunctionDef: _skip, ast.Lambda: _skip,
    }


def _cognitive(fn) -> int:
    return _Cognitive().run(fn)


def _arg_count(node) -> int:
    a = node.args
    n = len(a.posonlyargs) + len(a.args) + len(a.kwonlyargs)
    n += 1 if a.vararg else 0
    n += 1 if a.kwarg else 0
    return n


def _measure(node, qualname: str, path: str) -> FuncMetric:
    end = getattr(node, "end_lineno", node.lineno) or node.lineno
    return FuncMetric(
        path=path,
        qualname=qualname,
        line=node.lineno,
        complexity=1 + _decisions(node),
        cognitive=_cognitive(node),
        length=end - node.lineno + 1,
        nesting=_block_depth(node.body) - 1,     # flat body -> 0
        args=_arg_count(node),
    )


def _collect(node, prefix: str, path: str, out: list) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.ClassDef):
            _collect(child, prefix + child.name + ".", path, out)
        elif isinstance(child, _DEF):
            qual = prefix + child.name
            out.append(_measure(child, qual, path))
            _collect(child, qual + ".", path, out)     # nested defs
        else:
            _collect(child, prefix, path, out)          # descend module/if/loop bodies


def analyze_source(src: str, path: str = "<string>") -> list[FuncMetric]:
    """Every function/method in `src`, each with its own metrics. Empty list on
    a syntax error (a file that won't parse has no functions to measure)."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out: list[FuncMetric] = []
    _collect(tree, "", path, out)
    return out


def analyze_file(path: str) -> list[FuncMetric]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return analyze_source(fh.read(), path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def collect_paths(paths) -> list:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".py")]
        elif p.endswith(".py") or os.path.isfile(p):
            out.append(p)
    return out


def _fmt(metrics: list, limits: dict, top: int = 0) -> str:
    if top:
        shown = sorted(metrics, key=lambda m: (m.cognitive, m.complexity),
                       reverse=True)[:top]
        title = "top %d by cognitive complexity" % top
    else:
        shown = [m for m in metrics if m.exceeded(limits)]
        shown.sort(key=lambda m: (m.cognitive, m.complexity, m.length), reverse=True)
        title = "functions over threshold"
    if not shown:
        return "no functions over threshold (%d measured)." % len(metrics)
    lines = [title, "=" * 68,
             "  %-30s %4s %4s %4s %4s %4s" % ("function", "cx", "cog", "len", "nst", "arg")]
    for m in shown:
        over = set(m.exceeded(limits))

        def mark(name, val, over=over):
            return ("%d*" % val) if name in over else str(val)

        where = "%s:%d %s" % (os.path.basename(m.path), m.line, m.qualname)
        if len(where) > 30:
            where = where[:29] + "…"
        lines.append("  %-30s %4s %4s %4s %4s %4s" % (
            where, mark("complexity", m.complexity), mark("cognitive", m.cognitive),
            mark("length", m.length), mark("nesting", m.nesting), mark("args", m.args)))
    lines.append("  (* = over limit; cx=cyclomatic cog=cognitive len=lines nst=nesting arg=params)")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Python files or directories")
    ap.add_argument("--max-complexity", type=int, default=DEFAULT_LIMITS["complexity"])
    ap.add_argument("--max-cognitive", type=int, default=DEFAULT_LIMITS["cognitive"])
    ap.add_argument("--max-length", type=int, default=DEFAULT_LIMITS["length"])
    ap.add_argument("--max-nesting", type=int, default=DEFAULT_LIMITS["nesting"])
    ap.add_argument("--max-args", type=int, default=DEFAULT_LIMITS["args"])
    ap.add_argument("--top", type=int, default=0,
                    help="show the N gnarliest functions and ignore thresholds")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    limits = {"complexity": args.max_complexity, "cognitive": args.max_cognitive,
              "length": args.max_length, "nesting": args.max_nesting, "args": args.max_args}
    metrics = []
    for path in collect_paths(args.paths):
        try:
            metrics += analyze_file(path)
        except OSError as exc:
            print("skip %s: %s" % (path, exc), file=sys.stderr)

    flagged = [m for m in metrics if m.exceeded(limits)]
    if args.json:
        print(json.dumps([{**asdict(m), "over": m.exceeded(limits)} for m in metrics],
                         indent=2))
    else:
        print(_fmt(metrics, limits, top=args.top))
        if not args.top:
            print("%d of %d function(s) over threshold." % (len(flagged), len(metrics)))
    return min(len(flagged), 250)


if __name__ == "__main__":
    sys.exit(main())
