#!/usr/bin/env python3
"""Symbolic path feasibility -- prove whether a taint path is actually exploitable.

Lightweight constraint solver (no Z3 dependency). Walks the AST between a source
and sink, collects branch conditions along the path, and determines if the
conjunction of those conditions is satisfiable. Turns "maybe vulnerable" into
"definitely exploitable" or "guarded by impossible condition."

Example:
  def handler(request):
      cmd = request.args.get('cmd')
      if len(cmd) > 100:        # constraint: len(cmd) > 100
          return "too long"
      if cmd.startswith('/bin'):  # constraint: cmd.startswith('/bin')
          os.system(cmd)          # sink

  → Path feasible: cmd can satisfy len>100=False AND startswith('/bin')=True
  → Exploitable

  def safe(request):
      val = request.args.get('x')
      if val != val:             # always False (NaN edge case aside)
          eval(val)
  → Path infeasible: val != val is unsatisfiable
  → Pruned
"""
from __future__ import annotations

import ast
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


class Feasibility(Enum):
    FEASIBLE = "feasible"
    INFEASIBLE = "infeasible"
    UNKNOWN = "unknown"


@dataclass
class Constraint:
    variable: str
    operator: str
    value: str
    negated: bool = False
    line: int = 0
    code: str = ""

    def __repr__(self):
        neg = "NOT " if self.negated else ""
        return f"{neg}{self.variable} {self.operator} {self.value}"


@dataclass
class PathResult:
    finding: dict
    feasibility: Feasibility
    constraints: list[Constraint] = field(default_factory=list)
    reason: str = ""


_ALWAYS_TRUE = {
    ("==", "same"),
    ("is", "None_check"),
    (">=", "0_for_len"),
}

_TAUTOLOGIES = [
    re.compile(r"(\w+)\s*==\s*\1\b"),
    re.compile(r"(\w+)\s*is\s+\1\b"),
    re.compile(r"True\b"),
    re.compile(r"1\b"),
]

_CONTRADICTIONS = [
    re.compile(r"(\w+)\s*!=\s*\1\b"),
    re.compile(r"False\b"),
    re.compile(r"0\b"),
    re.compile(r"None\s+is\s+not\s+None"),
    re.compile(r"(\w+)\s*is\s+not\s+\1\b"),
]


def _is_tautology(code: str) -> bool:
    stripped = code.strip()
    return any(p.fullmatch(stripped) for p in _TAUTOLOGIES)


def _is_contradiction(code: str) -> bool:
    stripped = code.strip()
    return any(p.fullmatch(stripped) for p in _CONTRADICTIONS)


def _extract_constraint(node: ast.Compare, source: str) -> Constraint | None:
    if not node.ops or not node.comparators:
        return None
    left = ast.get_source_segment(source, node.left) if hasattr(ast, 'get_source_segment') else ""
    if not left:
        left = _name_of(node.left)
    op = node.ops[0]
    right = ast.get_source_segment(source, node.comparators[0]) if hasattr(ast, 'get_source_segment') else ""
    if not right:
        right = _name_of(node.comparators[0])
    op_str = {
        ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
        ast.Gt: ">", ast.GtE: ">=", ast.Is: "is", ast.IsNot: "is not",
        ast.In: "in", ast.NotIn: "not in",
    }.get(type(op), "?")
    return Constraint(variable=left, operator=op_str, value=right,
                      line=node.lineno,
                      code=f"{left} {op_str} {right}")


def _name_of(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return repr(node.value)
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func) + "()"
    if isinstance(node, ast.Subscript):
        return _name_of(node.value) + "[...]"
    return "?"


def _collect_path_constraints(tree: ast.Module, source: str,
                               sink_line: int) -> list[Constraint]:
    constraints = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.branch_stack: list[tuple[Constraint, bool]] = []

        def visit_If(self, node):
            cmp = self._extract_test(node.test, source)
            if cmp and node.lineno < sink_line:
                in_body = any(
                    getattr(n, 'lineno', 0) == sink_line
                    for child in node.body
                    for n in ast.walk(child)
                    if hasattr(n, 'lineno')
                )
                in_else = any(
                    getattr(n, 'lineno', 0) == sink_line
                    for child in node.orelse
                    for n in ast.walk(child)
                    if hasattr(n, 'lineno')
                )

                if in_body and not in_else:
                    constraints.append(cmp)
                elif in_else and not in_body:
                    cmp.negated = True
                    constraints.append(cmp)
            self.generic_visit(node)

        def _extract_test(self, node, source):
            if isinstance(node, ast.Compare):
                return _extract_constraint(node, source)
            if isinstance(node, ast.Call):
                name = _name_of(node.func)
                return Constraint(variable=name, operator="truthy",
                                  value="True", line=node.lineno,
                                  code=f"{name}()")
            if isinstance(node, ast.Name):
                return Constraint(variable=node.id, operator="truthy",
                                  value="True", line=node.lineno,
                                  code=node.id)
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                inner = self._extract_test(node.operand, source)
                if inner:
                    inner.negated = not inner.negated
                    return inner
            if isinstance(node, ast.BoolOp):
                if isinstance(node.op, ast.And) and node.values:
                    return self._extract_test(node.values[0], source)
            return None

    Visitor().visit(tree)
    return constraints


def _check_feasibility(constraints: list[Constraint]) -> tuple[Feasibility, str]:
    if not constraints:
        return Feasibility.FEASIBLE, "no branch conditions guard the sink"

    for c in constraints:
        cond_code = c.code
        is_taut = _is_tautology(cond_code)
        is_contra = _is_contradiction(cond_code)

        if c.negated:
            is_taut, is_contra = is_contra, is_taut

        if is_contra:
            return Feasibility.INFEASIBLE, f"condition '{c}' is always false"

    var_constraints: dict[str, list[Constraint]] = {}
    for c in constraints:
        var_constraints.setdefault(c.variable, []).append(c)

    for var, clist in var_constraints.items():
        if len(clist) >= 2:
            ops = {(c.operator, c.negated) for c in clist}
            if ("==", False) in ops and ("!=", False) in ops:
                eq_vals = {c.value for c in clist
                           if c.operator == "==" and not c.negated}
                neq_vals = {c.value for c in clist
                            if c.operator == "!=" and not c.negated}
                if eq_vals & neq_vals:
                    return (Feasibility.INFEASIBLE,
                            f"{var} must equal and not-equal "
                            f"{eq_vals & neq_vals}")

            if ("is", False) in ops and ("is not", False) in ops:
                is_vals = {c.value for c in clist
                           if c.operator == "is" and not c.negated}
                isnot_vals = {c.value for c in clist
                              if c.operator == "is not" and not c.negated}
                if is_vals & isnot_vals:
                    return (Feasibility.INFEASIBLE,
                            f"{var} must be and not-be {is_vals & isnot_vals}")

            has_lt = any(c.operator in ("<", "<=") and not c.negated for c in clist)
            has_gt = any(c.operator in (">", ">=") and not c.negated for c in clist)
            if has_lt and has_gt:
                lt_vals = []
                gt_vals = []
                for c in clist:
                    if c.negated:
                        continue
                    try:
                        v = float(c.value)
                    except (ValueError, TypeError):
                        continue
                    if c.operator in ("<", "<="):
                        lt_vals.append(v)
                    elif c.operator in (">", ">="):
                        gt_vals.append(v)
                if lt_vals and gt_vals:
                    if min(lt_vals) <= max(gt_vals):
                        return (Feasibility.INFEASIBLE,
                                f"{var} must be < {min(lt_vals)} "
                                f"and > {max(gt_vals)}")

    type_constraints = {}
    for c in constraints:
        if c.operator == "is" and c.value == "None" and not c.negated:
            type_constraints.setdefault(c.variable, set()).add("none")
        elif c.operator == "is not" and c.value == "None" and not c.negated:
            type_constraints.setdefault(c.variable, set()).add("not_none")
        elif c.operator in ("==", "!=", "<", ">") and not c.negated:
            type_constraints.setdefault(c.variable, set()).add("not_none")

    for var, types in type_constraints.items():
        if "none" in types and "not_none" in types:
            return Feasibility.INFEASIBLE, f"{var} must be None and not-None"

    return Feasibility.FEASIBLE, "all path constraints are satisfiable"


def analyze_finding(finding: dict, source_code: str) -> PathResult:
    sink_line = int(finding.get("sink_line") or finding.get("line") or 0)
    if not sink_line:
        return PathResult(finding=finding, feasibility=Feasibility.UNKNOWN,
                          reason="no sink line")
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return PathResult(finding=finding, feasibility=Feasibility.UNKNOWN,
                          reason="parse error")

    constraints = _collect_path_constraints(tree, source_code, sink_line)
    feasibility, reason = _check_feasibility(constraints)
    return PathResult(finding=finding, feasibility=feasibility,
                      constraints=constraints, reason=reason)


def analyze_findings(findings: list[dict], paths: list[str]) -> list[PathResult]:
    file_cache: dict[str, str] = {}
    for p in paths:
        if os.path.isfile(p) and p.endswith(".py"):
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    file_cache[os.path.abspath(p)] = f.read()
                file_cache[p] = file_cache[os.path.abspath(p)]
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
                                file_cache[os.path.abspath(fp)] = f.read()
                                file_cache[fp] = file_cache[os.path.abspath(fp)]
                        except OSError:
                            pass

    results = []
    for finding in findings:
        fpath = finding.get("sink_file") or finding.get("file") or ""
        source = (file_cache.get(fpath) or
                  file_cache.get(os.path.abspath(fpath)) or
                  file_cache.get(os.path.basename(fpath), ""))
        if not source:
            for cached_path, cached_source in file_cache.items():
                if os.path.basename(cached_path) == os.path.basename(fpath):
                    source = cached_source
                    break
        if source:
            results.append(analyze_finding(finding, source))
        else:
            results.append(PathResult(finding=finding,
                                      feasibility=Feasibility.UNKNOWN,
                                      reason="source file not found"))
    return results


def render(results: list[PathResult]) -> str:
    feasible = [r for r in results if r.feasibility == Feasibility.FEASIBLE]
    infeasible = [r for r in results if r.feasibility == Feasibility.INFEASIBLE]
    unknown = [r for r in results if r.feasibility == Feasibility.UNKNOWN]

    if not results:
        return "  nothing to check. quiet day."

    verdict = "all clear, nothing exploitable." if not feasible else (
        f"{len(feasible)} confirmed exploitable. patch these first.")

    lines = [
        f"\n  Symbolic Path Analysis",
        "  " + "=" * 62,
        f"  {len(feasible)} exploitable | {len(infeasible)} dead paths pruned "
        f"| {len(unknown)} unknown",
        f"  verdict: {verdict}",
    ]
    for r in infeasible:
        f = r.finding
        sink = f.get("sink_type") or f.get("category") or "unknown"
        loc = os.path.basename(f.get("sink_file") or f.get("file") or "?")
        lines.append(f"\n  [PRUNED] {sink} at {loc}:"
                     f"{f.get('sink_line', '?')} -- dead path, no attacker can reach this")
        lines.append(f"    why: {r.reason}")
        for c in r.constraints:
            lines.append(f"    guard L{c.line}: {c}")
    for r in feasible:
        f = r.finding
        sink = f.get("sink_type") or f.get("category") or "unknown"
        loc = os.path.basename(f.get("sink_file") or f.get("file") or "?")
        n = len(r.constraints)
        lines.append(f"\n  [EXPLOITABLE] {sink} at {loc}:"
                     f"{f.get('sink_line', '?')} -- all {n} guard(s) satisfiable")
    return "\n".join(lines)


def to_dict(results: list[PathResult]) -> list[dict]:
    return [
        {
            **r.finding,
            "feasibility": r.feasibility.value,
            "path_constraints": [
                {"variable": c.variable, "operator": c.operator,
                 "value": c.value, "negated": c.negated,
                 "line": c.line, "code": c.code}
                for c in r.constraints
            ],
            "feasibility_reason": r.reason,
        }
        for r in results
    ]
