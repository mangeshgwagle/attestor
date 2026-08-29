#!/usr/bin/env python3
"""
deadcode.py -- find module-level functions and classes nothing references.

Per-file tools miss code that is dead across the whole project: a function still
defined, still tested-adjacent, but never called from anywhere. This reads every
file, gathers every name that is USED anywhere (called, attribute-accessed, named
in a string for dynamic dispatch, or listed in __all__), and reports the top-level
defs whose name appears in none of them.

It is deliberately conservative -- Attestor would rather stay silent than delete
something that matters. It never flags: dunders, main, test*/setUp/tearDown,
decorated defs (they are often registered by the decorator), or anything a string
literal mentions. Private names (leading underscore) are the high-confidence
finds; public names are flagged too but noted, since a library's public API is
"unused" here only because its callers live outside the tree you scanned.

    deadcode.py src/                 # unreferenced defs across a project
    deadcode.py app.py --private     # only the high-confidence private ones
    deadcode.py src/ --json          # machine-readable
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import asdict, dataclass

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "build", "dist", "node_modules"}
_EXEMPT = {"main", "setUp", "tearDown", "setUpClass", "tearDownClass",
           "setUpModule", "tearDownModule"}


@dataclass
class Dead:
    path: str
    line: int
    name: str
    kind: str
    private: bool


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _parse(src: str):
    try:
        return ast.parse(src)
    except SyntaxError:
        return None


def _is_exempt(name: str) -> bool:
    return (name in _EXEMPT or name.startswith("test")
            or (name.startswith("__") and name.endswith("__")))


def _top_level_defs(tree) -> list:
    """(name, line, kind, decorated) for each module-level function/class."""
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, node.lineno, "function", bool(node.decorator_list)))
        elif isinstance(node, ast.ClassDef):
            out.append((node.name, node.lineno, "class", bool(node.decorator_list)))
    return out


def _dunder_all(tree) -> set:
    names = set()
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else []
        if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
            for element in getattr(node.value, "elts", []):
                if isinstance(element, ast.Constant) and isinstance(element.value, str):
                    names.add(element.value)
    return names


def _references(tree) -> tuple:
    """(used_names, exported_names): every name used anywhere, and __all__ entries."""
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            used.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node.value.isidentifier():
            used.add(node.value)
    return used, _dunder_all(tree)


def _load_trees(paths) -> dict:
    trees = {}
    for path in collect_paths(paths):
        tree = _parse(_read(path))
        if tree is not None:
            trees[path] = tree
    return trees


def _gather_references(trees: dict) -> tuple:
    used = set()
    exported = set()
    for tree in trees.values():
        file_used, file_exports = _references(tree)
        used |= file_used
        exported |= file_exports
    return used, exported


def _dead_in_file(path: str, tree, used: set, exported: set, private_only: bool) -> list:
    out = []
    for name, line, kind, decorated in _top_level_defs(tree):
        if decorated or _is_exempt(name) or name in exported or name in used:
            continue
        private = name.startswith("_")
        if not (private_only and not private):
            out.append(Dead(path, line, name, kind, private))
    return out


def find_dead(paths, private_only: bool = False) -> list:
    trees = _load_trees(paths)
    used, exported = _gather_references(trees)
    dead = []
    for path, tree in trees.items():
        dead += _dead_in_file(path, tree, used, exported, private_only)
    dead.sort(key=lambda d: (not d.private, d.path, d.line))
    return dead


def collect_paths(paths) -> list:
    out = []
    for raw in paths:
        if os.path.isdir(raw):
            for root, dirs, files in os.walk(raw):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".py")]
        elif raw.endswith(".py") or os.path.isfile(raw):
            out.append(raw)
    return out


def render(dead: list) -> str:
    if not dead:
        return "no unreferenced top-level defs found. clean."
    private = sum(1 for d in dead if d.private)
    lines = ["%d unreferenced def(s): %d private (high confidence), %d public "
             "(may be external API)" % (len(dead), private, len(dead) - private),
             "=" * 64]
    for d in dead:
        tag = "private" if d.private else "public"
        lines.append("%s:%d  %s %s  [%s]" % (d.path, d.line, d.kind, d.name, tag))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Python files or directories")
    ap.add_argument("--private", action="store_true",
                    help="report only leading-underscore names (the high-confidence dead code)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    dead = find_dead(args.paths, private_only=args.private)
    if args.json:
        print(json.dumps([asdict(d) for d in dead], indent=2))
    else:
        print(render(dead))
    return min(len(dead), 250)


if __name__ == "__main__":
    sys.exit(main())
