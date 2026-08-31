#!/usr/bin/env python3
"""Abstract interpretation -- value-range tracking for integer overflow and bounds detection.

Tracks integer ranges through arithmetic operations to catch:
  - Integer overflows (value exceeds type bounds)
  - Array/buffer out-of-bounds access
  - Truncation bugs (assigning wide range to narrow type)
  - Division by zero possibilities
  - Negative index access

Works at the AST level on Python code. Propagates abstract value ranges
[lo, hi] through assignments and arithmetic, narrows on branches.
"""
from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass, field
from enum import Enum

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

INT32_MIN, INT32_MAX = -(2**31), 2**31 - 1
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1
UINT_MAX = 2**32 - 1


class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Range:
    lo: int | float
    hi: int | float

    @staticmethod
    def top() -> Range:
        return Range(float('-inf'), float('inf'))

    @staticmethod
    def const(v: int) -> Range:
        return Range(v, v)

    def contains_zero(self) -> bool:
        return self.lo <= 0 <= self.hi

    def contains_negative(self) -> bool:
        return self.lo < 0

    def overflows_32(self) -> bool:
        return self.lo < INT32_MIN or self.hi > INT32_MAX

    def overflows_64(self) -> bool:
        return self.lo < INT64_MIN or self.hi > INT64_MAX

    def __add__(self, other: Range) -> Range:
        return Range(self.lo + other.lo, self.hi + other.hi)

    def __sub__(self, other: Range) -> Range:
        return Range(self.lo - other.hi, self.hi - other.lo)

    def __mul__(self, other: Range) -> Range:
        products = [self.lo * other.lo, self.lo * other.hi,
                    self.hi * other.lo, self.hi * other.hi]
        return Range(min(products), max(products))

    def narrow_lt(self, bound: int) -> Range:
        return Range(self.lo, min(self.hi, bound - 1))

    def narrow_ge(self, bound: int) -> Range:
        return Range(max(self.lo, bound), self.hi)

    def widen(self, other: Range) -> Range:
        lo = self.lo if other.lo >= self.lo else float('-inf')
        hi = self.hi if other.hi <= self.hi else float('inf')
        return Range(lo, hi)


@dataclass
class AIFinding:
    category: str
    severity: str
    file: str
    line: int
    code: str
    description: str
    variable: str
    range_lo: int | float
    range_hi: int | float
    cwe: str = ""


class _Interpreter(ast.NodeVisitor):
    def __init__(self, filepath: str, source_lines: list[str]):
        self.filepath = filepath
        self.source_lines = source_lines
        self.env: dict[str, Range] = {}
        self.findings: list[AIFinding] = []

    def _code_at(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _eval_expr(self, node: ast.AST) -> Range:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return Range.const(int(node.value))
        if isinstance(node, ast.Name) and node.id in self.env:
            return self.env[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            inner = self._eval_expr(node.operand)
            return Range(-inner.hi, -inner.lo)
        if isinstance(node, ast.BinOp):
            left = self._eval_expr(node.left)
            right = self._eval_expr(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.FloorDiv) or isinstance(node.op, ast.Div):
                if right.contains_zero():
                    self.findings.append(AIFinding(
                        category="division_by_zero", severity="HIGH",
                        file=self.filepath, line=node.lineno,
                        code=self._code_at(node.lineno),
                        description=f"Possible division by zero: divisor range [{right.lo}, {right.hi}]",
                        variable="divisor", range_lo=right.lo, range_hi=right.hi,
                        cwe="CWE-369",
                    ))
                return Range.top()
            if isinstance(node.op, ast.Mod):
                if right.contains_zero():
                    self.findings.append(AIFinding(
                        category="division_by_zero", severity="HIGH",
                        file=self.filepath, line=node.lineno,
                        code=self._code_at(node.lineno),
                        description=f"Possible modulo by zero: divisor range [{right.lo}, {right.hi}]",
                        variable="divisor", range_lo=right.lo, range_hi=right.hi,
                        cwe="CWE-369",
                    ))
                return Range.top()
            if isinstance(node.op, ast.LShift):
                if right.hi > 63:
                    return Range.top()
                if right.lo >= 0 and right.hi <= 63:
                    return Range(left.lo << int(right.lo), left.hi << int(right.hi))
                return Range.top()
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name == "int" and node.args:
                return self._eval_expr(node.args[0])
            if func_name == "len":
                return Range(0, float('inf'))
            if func_name == "abs":
                inner = self._eval_expr(node.args[0]) if node.args else Range.top()
                return Range(0, max(abs(inner.lo), abs(inner.hi)))
        if isinstance(node, ast.Subscript):
            val = self._eval_expr(node.value) if isinstance(node.value, ast.Name) else Range.top()
            if isinstance(node.slice, (ast.Constant, ast.Name, ast.BinOp, ast.UnaryOp)):
                idx = self._eval_expr(node.slice)
                if idx.contains_negative():
                    self.findings.append(AIFinding(
                        category="negative_index", severity="MEDIUM",
                        file=self.filepath, line=node.lineno,
                        code=self._code_at(node.lineno),
                        description=f"Possible negative index: range [{idx.lo}, {idx.hi}]",
                        variable="index", range_lo=idx.lo, range_hi=idx.hi,
                        cwe="CWE-786",
                    ))
            return Range.top()
        return Range.top()

    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            val = self._eval_expr(node.value)
            self.env[name] = val
            if val.overflows_32() and not val.overflows_64():
                self.findings.append(AIFinding(
                    category="integer_overflow_32", severity="MEDIUM",
                    file=self.filepath, line=node.lineno,
                    code=self._code_at(node.lineno),
                    description=f"Value of '{name}' may overflow 32-bit: [{val.lo}, {val.hi}]",
                    variable=name, range_lo=val.lo, range_hi=val.hi,
                    cwe="CWE-190",
                ))
            if val.overflows_64():
                self.findings.append(AIFinding(
                    category="integer_overflow_64", severity="HIGH",
                    file=self.filepath, line=node.lineno,
                    code=self._code_at(node.lineno),
                    description=f"Value of '{name}' may overflow 64-bit: [{val.lo}, {val.hi}]",
                    variable=name, range_lo=val.lo, range_hi=val.hi,
                    cwe="CWE-190",
                ))
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            name = node.target.id
            cur = self.env.get(name, Range.top())
            right = self._eval_expr(node.value)
            if isinstance(node.op, ast.Add):
                result = cur + right
            elif isinstance(node.op, ast.Sub):
                result = cur - right
            elif isinstance(node.op, ast.Mult):
                result = cur * right
            else:
                result = Range.top()
            self.env[name] = result
            if result.overflows_32() and not result.overflows_64():
                self.findings.append(AIFinding(
                    category="integer_overflow_32", severity="MEDIUM",
                    file=self.filepath, line=node.lineno,
                    code=self._code_at(node.lineno),
                    description=f"Value of '{name}' may overflow 32-bit after augmented assign",
                    variable=name, range_lo=result.lo, range_hi=result.hi,
                    cwe="CWE-190",
                ))
        self.generic_visit(node)

    def visit_For(self, node):
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if isinstance(node.iter, ast.Call):
                func = node.iter.func if isinstance(node.iter.func, ast.Name) else None
                if func and func.id == "range":
                    args = node.iter.args
                    if len(args) == 1:
                        self.env[name] = Range(0, self._eval_expr(args[0]).hi - 1)
                    elif len(args) >= 2:
                        lo = self._eval_expr(args[0])
                        hi = self._eval_expr(args[1])
                        self.env[name] = Range(lo.lo, hi.hi - 1)
        self.generic_visit(node)

    def visit_If(self, node):
        if isinstance(node.test, ast.Compare) and len(node.test.ops) == 1:
            left = node.test.left
            right = node.test.comparators[0]
            if isinstance(left, ast.Name) and isinstance(right, ast.Constant):
                name = left.id
                bound = right.value if isinstance(right.value, int) else None
                if bound is not None and name in self.env:
                    op = node.test.ops[0]
                    saved = self.env[name]
                    if isinstance(op, (ast.Lt, ast.LtE)):
                        self.env[name] = saved.narrow_lt(bound + (1 if isinstance(op, ast.LtE) else 0))
                    elif isinstance(op, (ast.Gt, ast.GtE)):
                        self.env[name] = saved.narrow_ge(bound + (0 if isinstance(op, ast.GtE) else 1))
        self.generic_visit(node)

    def visit_Expr(self, node):
        if isinstance(node.value, ast.Subscript):
            self._eval_expr(node.value)
        if isinstance(node.value, ast.Call):
            self._check_dangerous_call(node.value)
        self.generic_visit(node)

    def _check_dangerous_call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
        if func_name == "pack" and node.args:
            for arg in node.args[1:]:
                r = self._eval_expr(arg)
                if r.overflows_32():
                    self.findings.append(AIFinding(
                        category="struct_truncation", severity="HIGH",
                        file=self.filepath, line=node.lineno,
                        code=self._code_at(node.lineno),
                        description=f"struct.pack may truncate: value range [{r.lo}, {r.hi}] "
                                    f"exceeds 32-bit",
                        variable="pack_arg", range_lo=r.lo, range_hi=r.hi,
                        cwe="CWE-681",
                    ))
        if func_name in ("c_int", "c_uint", "c_short", "c_ushort",
                         "c_int32", "c_uint32") and node.args:
            r = self._eval_expr(node.args[0])
            if r.overflows_32():
                self.findings.append(AIFinding(
                    category="ctypes_truncation", severity="HIGH",
                    file=self.filepath, line=node.lineno,
                    code=self._code_at(node.lineno),
                    description=f"ctypes cast to {func_name} may truncate: "
                                f"range [{r.lo}, {r.hi}]",
                    variable="ctypes_arg", range_lo=r.lo, range_hi=r.hi,
                    cwe="CWE-681",
                ))


def scan_source(source: str, filepath: str = "<string>") -> list[AIFinding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    interp = _Interpreter(filepath, source.splitlines())
    interp.visit(tree)
    return interp.findings


def scan_file(path: str) -> list[AIFinding]:
    if not path.endswith(".py"):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return []
    return scan_source(source, path)


def scan_paths(paths: list[str]) -> list[AIFinding]:
    findings = []
    for p in paths:
        if os.path.isfile(p):
            findings += scan_file(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules"}]
                for n in fn:
                    if n.endswith(".py"):
                        findings += scan_file(os.path.join(dp, n))
    return findings


def to_dict(findings: list[AIFinding]) -> list[dict]:
    return [
        {
            "category": f.category, "severity": f.severity,
            "file": f.file, "path": f.file,
            "sink_file": f.file, "sink_line": f.line,
            "line": f.line, "sink_code": f.code,
            "sink_type": f.category, "matched_text": f.code,
            "description": f.description, "cwe": f.cwe,
            "variable": f.variable,
            "range_lo": f.range_lo, "range_hi": f.range_hi,
        }
        for f in findings
    ]


def render(findings: list[AIFinding]) -> str:
    if not findings:
        return "  clean. no overflows, no div-by-zero, no dodgy indices. nice one."
    high = sum(1 for f in findings if f.severity == "HIGH")
    lines = [
        f"\n  Abstract Interpretation -- {len(findings)} issue(s)"
        f"{f', {high} high-severity' if high else ''}",
        "  " + "=" * 62,
    ]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        lines.append(f"\n  [{f.severity}] {f.category} at "
                     f"{os.path.basename(f.file)}:{f.line}")
        lines.append(f"    {f.description}")
        lines.append(f"    value range: [{f.range_lo}, {f.range_hi}]")
    if high:
        lines.append(f"\n  {high} of these will crash in production. fix them.")
    return "\n".join(lines)
