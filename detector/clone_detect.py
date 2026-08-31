#!/usr/bin/env python3
"""Semantic clone detection -- find copy-paste vulnerability variants.

Normalizes AST structures to fingerprints, then groups functions with similar
structure. If one copy has a vulnerability, its clones likely do too.

Approach:
  1. Parse each file, extract function ASTs
  2. Normalize: rename variables to positional tokens, strip comments/docstrings
  3. Hash the normalized AST structure
  4. Group by hash — exact structural matches
  5. Also compute Jaccard similarity of AST node-type sequences for near-clones
"""
from __future__ import annotations

import ast
import hashlib
import os
import sys
from collections import Counter
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

MIN_NODES = 8


@dataclass
class FuncSig:
    name: str
    file: str
    line: int
    end_line: int
    fingerprint: str
    node_seq: tuple[str, ...]
    param_count: int
    node_count: int


@dataclass
class CloneGroup:
    fingerprint: str
    members: list[FuncSig] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)


@dataclass
class NearClone:
    func_a: FuncSig
    func_b: FuncSig
    similarity: float


def _normalize_ast(node: ast.FunctionDef) -> ast.FunctionDef:
    import copy
    tree = copy.deepcopy(node)
    var_map: dict[str, str] = {}
    counter = [0]

    class Normalizer(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id not in var_map:
                var_map[node.id] = f"v{counter[0]}"
                counter[0] += 1
            node.id = var_map[node.id]
            return node

        def visit_arg(self, node):
            if node.arg not in var_map:
                var_map[node.arg] = f"v{counter[0]}"
                counter[0] += 1
            node.arg = var_map[node.arg]
            node.annotation = None
            return node

        def visit_Constant(self, node):
            if isinstance(node.value, str) and len(node.value) > 1:
                node.value = "S"
            return node

        def visit_FunctionDef(self, node):
            node.name = "func"
            node.decorator_list = []
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body = node.body[1:]
            node.returns = None
            self.generic_visit(node)
            return node

        visit_AsyncFunctionDef = visit_FunctionDef

    Normalizer().visit(tree)
    return tree


def _node_sequence(node: ast.AST) -> tuple[str, ...]:
    seq = []
    for child in ast.walk(node):
        seq.append(type(child).__name__)
    return tuple(seq)


def _fingerprint(node: ast.AST) -> str:
    seq = _node_sequence(node)
    return hashlib.sha256("|".join(seq).encode()).hexdigest()[:16]


def _node_count(node: ast.AST) -> int:
    return sum(1 for _ in ast.walk(node))


def _jaccard(a: tuple[str, ...], b: tuple[str, ...]) -> float:
    ca, cb = Counter(a), Counter(b)
    intersection = sum((ca & cb).values())
    union = sum((ca | cb).values())
    return intersection / union if union else 0.0


def extract_functions(source: str, filepath: str) -> list[FuncSig]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    sigs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nc = _node_count(node)
            if nc < MIN_NODES:
                continue
            normalized = _normalize_ast(node)
            fp = _fingerprint(normalized)
            seq = _node_sequence(normalized)
            params = len(node.args.args)
            sigs.append(FuncSig(
                name=node.name, file=filepath, line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                fingerprint=fp, node_seq=seq, param_count=params,
                node_count=nc,
            ))
    return sigs


def find_clones(sigs: list[FuncSig]) -> list[CloneGroup]:
    by_fp: dict[str, list[FuncSig]] = {}
    for s in sigs:
        by_fp.setdefault(s.fingerprint, []).append(s)
    return [CloneGroup(fingerprint=fp, members=members)
            for fp, members in by_fp.items()
            if len(members) > 1]


def find_near_clones(sigs: list[FuncSig], threshold: float = 0.75) -> list[NearClone]:
    near = []
    for i, a in enumerate(sigs):
        for b in sigs[i + 1:]:
            if a.fingerprint == b.fingerprint:
                continue
            if abs(a.node_count - b.node_count) > max(a.node_count, b.node_count) * 0.5:
                continue
            sim = _jaccard(a.node_seq, b.node_seq)
            if sim >= threshold:
                near.append(NearClone(func_a=a, func_b=b, similarity=sim))
    return near


def scan_paths(paths: list[str], near_threshold: float = 0.75) -> tuple[list[CloneGroup], list[NearClone]]:
    all_sigs = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".py"):
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    all_sigs += extract_functions(f.read(), p)
            except OSError:
                pass
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules"}]
                for n in fn:
                    if n.endswith(".py"):
                        fp = os.path.join(dp, n)
                        try:
                            with open(fp, encoding="utf-8", errors="replace") as f:
                                all_sigs += extract_functions(f.read(), fp)
                        except OSError:
                            pass
    clones = find_clones(all_sigs)
    nears = find_near_clones(all_sigs, near_threshold)
    return clones, nears


def to_dict(clones: list[CloneGroup], nears: list[NearClone]) -> list[dict]:
    results = []
    for g in clones:
        for m in g.members:
            results.append({
                "category": "exact_clone", "severity": "MEDIUM",
                "file": m.file, "path": m.file,
                "sink_file": m.file, "sink_line": m.line,
                "line": m.line, "sink_type": "clone",
                "description": f"Exact structural clone of {g.size} functions "
                               f"(fingerprint {g.fingerprint})",
                "function": m.name, "fingerprint": g.fingerprint,
                "clone_count": g.size,
                "cwe": "CWE-1041",
            })
    for n in nears:
        results.append({
            "category": "near_clone", "severity": "LOW",
            "file": n.func_a.file, "path": n.func_a.file,
            "sink_file": n.func_a.file, "sink_line": n.func_a.line,
            "line": n.func_a.line, "sink_type": "near_clone",
            "description": f"Near-clone: {n.func_a.name} ({os.path.basename(n.func_a.file)}:"
                           f"{n.func_a.line}) ~ {n.func_b.name} ({os.path.basename(n.func_b.file)}:"
                           f"{n.func_b.line}), similarity={n.similarity:.0%}",
            "function_a": n.func_a.name, "function_b": n.func_b.name,
            "similarity": round(n.similarity, 3),
            "cwe": "CWE-1041",
        })
    return results


def render(clones: list[CloneGroup], nears: list[NearClone]) -> str:
    if not clones and not nears:
        return "  No code clones detected."
    lines = [
        f"\n  Semantic Clone Detection -- {len(clones)} exact group(s), "
        f"{len(nears)} near-clone(s)",
        "  " + "=" * 62,
    ]
    for g in clones:
        lines.append(f"\n  [EXACT CLONE] {g.size} copies, fingerprint {g.fingerprint}")
        for m in g.members:
            lines.append(f"    {m.name}() at {os.path.basename(m.file)}:{m.line} "
                         f"({m.node_count} nodes)")
    for n in nears:
        lines.append(f"\n  [NEAR CLONE] {n.similarity:.0%} similar")
        lines.append(f"    {n.func_a.name}() at {os.path.basename(n.func_a.file)}:{n.func_a.line}")
        lines.append(f"    {n.func_b.name}() at {os.path.basename(n.func_b.file)}:{n.func_b.line}")
    return "\n".join(lines)
