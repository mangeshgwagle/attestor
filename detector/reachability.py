#!/usr/bin/env python3
"""Whole-program reachability -- can an attacker actually TRIGGER this finding?

A taint flow is only exploitable if some ENTRY POINT (an HTTP route, main(), a
public API handler) can reach the sink through the call graph. This walks the
graph from every entry point across the whole repo and answers, per finding:
  - reachable?  (can any entry point reach the sink's function)
  - from where? (which route / entry)
  - by what path? (the exact call chain entry -> ... -> sink)

That's whole-program intelligence a language model can't reliably do -- it can't
hold the entire call graph across files in its head. This is deterministic,
reproducible, and grounds every finding in a concrete attacker path.
"""
from __future__ import annotations

import ast
import os
import re
from collections import deque
from dataclasses import dataclass, field

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

# decorator names that mark an HTTP entry point (Flask/FastAPI/Django-REST/etc.)
_ROUTE_DEC = re.compile(
    r"\b(route|get|post|put|delete|patch|options|head|websocket|api_route|"
    r"endpoint|command|task|handler|middleware|before_request)\b", re.I)


@dataclass
class Func:
    name: str
    file: str
    line: int
    end: int
    calls: set[str] = field(default_factory=set)
    is_entry: bool = False
    entry_reason: str = ""


@dataclass
class Reach:
    reachable: bool
    entry: str = ""          # "GET /search" style label or function name
    path: list[str] = field(default_factory=list)   # entry -> ... -> sink func


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _dec_label(fn: ast.AST) -> str | None:
    """Return an entry-point label if the function is decorated like a route."""
    for dec in getattr(fn, "decorator_list", []):
        name = _call_name(dec)
        if name and _ROUTE_DEC.search(name):
            verb = name.upper() if name.lower() in (
                "get", "post", "put", "delete", "patch") else "ROUTE"
            path = ""
            if isinstance(dec, ast.Call) and dec.args:
                a0 = dec.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    path = a0.value
            return f"{verb} {path}".strip()
    return None


class _Collector(ast.NodeVisitor):
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.funcs: list[Func] = []
        self._cur: Func | None = None

    def visit_FunctionDef(self, node):
        f = Func(name=node.name, file=self.filepath, line=node.lineno,
                 end=getattr(node, "end_lineno", node.lineno))
        label = _dec_label(node)
        if label is not None:
            f.is_entry, f.entry_reason = True, label
        elif node.name in ("main", "handler", "index"):
            f.is_entry, f.entry_reason = True, node.name + "()"
        elif node.args.args and node.args.args[0].arg in ("request", "req", "event"):
            f.is_entry, f.entry_reason = True, f"{node.name}(request)"
        self.funcs.append(f)
        prev, self._cur = self._cur, f
        self.generic_visit(node)
        self._cur = prev

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        if self._cur is not None:
            n = _call_name(node.func)
            if n:
                self._cur.calls.add(n)
        self.generic_visit(node)


def build(paths: list[str]) -> dict[str, list[Func]]:
    """Collect all functions across the tree, indexed by bare name."""
    files = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".py"):
            files.append(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                files += [os.path.join(dp, n) for n in fn if n.endswith(".py")]
    by_name: dict[str, list[Func]] = {}
    for fp in files:
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                tree = ast.parse(fh.read(), filename=fp)
        except (OSError, SyntaxError):
            continue
        c = _Collector(fp)
        c.visit(tree)
        for f in c.funcs:
            by_name.setdefault(f.name, []).append(f)
    return by_name


def _reachable_set(by_name: dict[str, list[Func]]) -> tuple[set[int], dict[int, Func]]:
    """BFS from all entry points; return (reachable func ids, id->Func)."""
    idmap: dict[int, Func] = {}
    for lst in by_name.values():
        for f in lst:
            idmap[id(f)] = f
    reachable: set[int] = set()
    q: deque[Func] = deque()
    for f in idmap.values():
        if f.is_entry:
            reachable.add(id(f))
            q.append(f)
    while q:
        cur = q.popleft()
        for callee_name in cur.calls:
            for target in by_name.get(callee_name, []):
                if id(target) not in reachable:
                    reachable.add(id(target))
                    q.append(target)
    return reachable, idmap


def _shortest_path(by_name: dict[str, list[Func]], target: Func) -> tuple[str, list[str]]:
    """BFS from entries to `target`; return (entry_label, [entry..target] names)."""
    prev: dict[int, Func | None] = {}
    q: deque[Func] = deque()
    for lst in by_name.values():
        for f in lst:
            if f.is_entry:
                prev[id(f)] = None
                q.append(f)
    while q:
        cur = q.popleft()
        if cur is target or (cur.name == target.name and cur.file == target.file
                             and cur.line == target.line):
            # reconstruct
            chain, node = [], cur
            while node is not None:
                chain.append(f"{node.name} ({os.path.basename(node.file)}:{node.line})")
                node = prev[id(node)]
            chain.reverse()
            entry = next((f.entry_reason for f in _all(by_name)
                          if f.name == chain[0].split(" ")[0] and f.is_entry), chain[0])
            return entry, chain
        for callee_name in cur.calls:
            for t in by_name.get(callee_name, []):
                if id(t) not in prev:
                    prev[id(t)] = cur
                    q.append(t)
    return "", []


def _all(by_name):
    for lst in by_name.values():
        for f in lst:
            yield f


def _enclosing(by_name: dict[str, list[Func]], file: str, line: int) -> Func | None:
    best = None
    for f in _all(by_name):
        if f.file == file and f.line <= line <= f.end:
            if best is None or f.line > best.line:  # innermost
                best = f
    return best


def annotate(findings: list[dict], paths: list[str]) -> list[tuple[dict, Reach]]:
    """For each finding (dict with sink_file/sink_line or file/line), compute
    reachability from entry points and the entry->sink call path."""
    by_name = build(paths)
    reachable, _ = _reachable_set(by_name)
    out = []
    for fdict in findings:
        sfile = fdict.get("sink_file") or fdict.get("file") or ""
        sline = fdict.get("sink_line") or fdict.get("line") or 0
        fn = _enclosing(by_name, sfile, int(sline) if sline else 0)
        if fn is None:
            out.append((fdict, Reach(reachable=False)))
            continue
        if id(fn) in reachable:
            entry, path = _shortest_path(by_name, fn)
            out.append((fdict, Reach(reachable=True, entry=entry or fn.entry_reason, path=path)))
        else:
            out.append((fdict, Reach(reachable=False)))
    return out


def scan(paths: list[str]) -> list[tuple[dict, Reach]]:
    """Run the dataflow engine, then annotate each flow with reachability."""
    import dataflow
    flows = dataflow.to_dict(dataflow.scan_paths(paths))
    return annotate(flows, paths)


def render(annotated: list[tuple[dict, Reach]]) -> str:
    if not annotated:
        return "  No findings to assess for reachability."
    reach = [(f, r) for f, r in annotated if r.reachable]
    unreach = [(f, r) for f, r in annotated if not r.reachable]
    lines = ["\n  Whole-Program Reachability",
             "  " + "=" * 58,
             f"  {len(reach)} reachable from an entry point  |  "
             f"{len(unreach)} not reachable (lower priority)"]
    for f, r in reach:
        base = (f.get("sink_file") or f.get("file", "?")).replace("\\", "/").split("/")[-1]
        lines.append(f"\n  [REACHABLE] {f.get('sink_type', f.get('rule_id','?'))} "
                     f"({f.get('cwe','')})  {base}:{f.get('sink_line', f.get('line','?'))}")
        lines.append(f"    attacker entry: {r.entry}")
        if r.path:
            lines.append(f"    call path: {' -> '.join(r.path)}")
    if unreach:
        lines.append(f"\n  Not reachable from any entry point ({len(unreach)}):")
        for f, r in unreach[:10]:
            base = (f.get("sink_file") or f.get("file", "?")).replace("\\", "/").split("/")[-1]
            lines.append(f"    - {f.get('sink_type', f.get('rule_id','?'))} "
                         f"{base}:{f.get('sink_line', f.get('line','?'))}")
    return "\n".join(lines)


def to_dict(annotated: list[tuple[dict, Reach]]) -> list[dict]:
    return [
        {**f, "reachable": r.reachable, "entry_point": r.entry, "call_path": r.path}
        for f, r in annotated
    ]
