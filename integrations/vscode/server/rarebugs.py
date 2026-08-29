#!/usr/bin/env python3
"""rarebugs.py -- Attestor's rare-error oracle for Python.

These are the bugs that often survive ordinary review because the code looks
reasonable at a glance: context managers that swallow exceptions, regex strings
where ``\b`` became a backspace, dataclass factories accidentally called at class
definition time, mutating methods assigned as if they returned a value, NaN
comparisons, shared mutable values from ``dict.fromkeys``, and a few more.

The rules are intentionally narrow. Attestor should be uncanny, not noisy.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from dataclasses import asdict

from detect import Finding, SEVERITY_ORDER

# List mutators that return None. Safe to flag on a list literal or a bare Name
# (the classic `x = mylist.append(y)` bug), but NOT on an attribute receiver like
# self.items -- that's too often a custom object whose method really returns data.
LIST_MUTATORS = {"append", "extend", "insert", "clear", "sort", "reverse"}
# dict/set mutators whose names are also extremely common custom methods
# (repo.update, builder.add, cache.discard). Only flag these on a *provable*
# container literal, so custom methods are never mistaken for None-returners.
CONTAINER_LITERAL_MUTATORS = {"update", "add", "discard", "remove", "setdefault_update"}
MUTATING_RETURNS_NONE = LIST_MUTATORS | CONTAINER_LITERAL_MUTATORS
REGEX_CALLS = {
    "re.compile", "re.search", "re.match", "re.fullmatch", "re.findall",
    "re.finditer", "re.split", "re.sub", "re.subn",
}


def _snip(lines: list[str], line: int) -> str:
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _name(node.value)
        return (left + "." if left else "") + node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _is_mutable_literal(node) -> bool:
    return isinstance(node, (ast.List, ast.Dict, ast.Set)) or (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"})


def _is_nan(node) -> bool:
    if isinstance(node, ast.Attribute) and node.attr == "nan":
        return _name(node.value) in {"math", "np", "numpy"}
    if isinstance(node, ast.Call) and _name(node.func) == "float":
        return bool(node.args and isinstance(node.args[0], ast.Constant)
                    and str(node.args[0].value).lower() == "nan")
    return False


def _decorator_name(node) -> str:
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return _name(node)


def _is_container_literal(node) -> bool:
    """True when a receiver is provably a list/dict/set -- a literal, a
    comprehension, or a list()/dict()/set() call. Only then is a mutating method
    on it guaranteed to be the None-returning builtin, not a custom method."""
    if isinstance(node, (ast.List, ast.Dict, ast.Set,
                         ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"list", "dict", "set"})


def _assignment_targets(node) -> list:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, ast.AnnAssign):
        return [node.target]
    return []


def _same_expr(left, right) -> bool:
    return _name(left) == _name(right) and bool(_name(left))


def _add(out: list[Finding], lines: list[str], path: str, node, rule: str,
         severity: str, message: str, fix: str) -> None:
    line = getattr(node, "lineno", 1)
    out.append(Finding(path, line, rule, severity, message, fix, _snip(lines, line)))


class RareVisitor(ast.NodeVisitor):
    """AST visitor for rare Python correctness traps."""

    def __init__(self, source: str, path: str):
        self.path = path
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self.class_stack: list[str] = []
        self.async_depth = 0

    def add(self, node, rule: str, severity: str, message: str, fix: str) -> None:
        _add(self.findings, self.lines, self.path, node, rule, severity, message, fix)

    def visit_Assign(self, node):
        self._check_mutating_assignment(node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._check_mutating_assignment(node.value, node)
        self.generic_visit(node)

    def _check_mutating_assignment(self, value, node) -> None:
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)):
            return
        method = value.func.attr
        if method not in MUTATING_RETURNS_NONE:
            return                                  # only the known None-returners
        receiver = value.func.value
        literal = _is_container_literal(receiver)
        assigned_back = any(_same_expr(target, receiver) for target in _assignment_targets(node))
        if method in CONTAINER_LITERAL_MUTATORS and not literal:
            return                                  # ambiguous name on a non-literal: skip
        if method in LIST_MUTATORS and not (literal or isinstance(receiver, ast.Name) or assigned_back):
            return                                  # list mutator on self.x etc.: too risky
        self.add(
            node, "rare-mutating-method-assigned", "HIGH",
            "'%s()' mutates in place and returns None; the assignment loses the data." % method,
            "call the mutating method on its own line, or use a non-mutating expression.")

    def visit_Return(self, node):
        if isinstance(node.value, ast.Constant) and node.value.value is True:
            current = self._current_function_name()
            if current in {"__exit__", "__aexit__"}:
                self.add(
                    node, "rare-exit-swallows-exception", "HIGH",
                    "%s returns True, so exceptions inside the context manager are swallowed." % current,
                    "return False/None unless deliberate suppression is the documented behavior.")
        if self._current_property_setter() and node.value is not None:
            self.add(
                node, "rare-property-setter-return", "LOW",
                "a property setter return value is ignored, which often hides a mistaken API design.",
                "assign state on self and return None implicitly.")
        self.generic_visit(node)

    def visit_Call(self, node):
        name = _name(node.func)
        if name.endswith(".field") or name == "field" or name == "dataclasses.field":
            self._check_dataclass_field(node)
        if name in REGEX_CALLS:
            self._check_regex_boundary(node)
        if name == "dict.fromkeys":
            self._check_dict_fromkeys(node)
        if name in {"contextlib.suppress", "suppress"}:
            self._check_contextlib_suppress(node)
        if name in {"asyncio.create_task", "create_task"}:
            self._check_fire_and_forget_task(node)
        if name in {"decimal.Decimal", "Decimal"}:
            self._check_decimal_float(node)
        if self.async_depth and (name.startswith("requests.") or name in {"urllib.request.urlopen"}):
            self.add(
                node, "rare-blocking-http-in-async", "MEDIUM",
                "blocking HTTP client call appears inside async code.",
                "use an async HTTP client or move the blocking call to a worker thread.")
        self.generic_visit(node)

    def _check_dataclass_field(self, node) -> None:
        for keyword in node.keywords:
            if keyword.arg == "default_factory" and isinstance(keyword.value, ast.Call):
                self.add(
                    keyword.value, "rare-default-factory-called", "HIGH",
                    "default_factory is called at class definition time instead of passed as a callable.",
                    "use default_factory=list, not default_factory=list().")

    def _check_regex_boundary(self, node) -> None:
        if not node.args:
            return
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and "\b" in first.value:
            self.add(
                first, "rare-regex-backspace-boundary", "HIGH",
                "regex pattern contains a backspace character; a normal string likely used '\\b'.",
                "use a raw string such as r'\\bword\\b'.")

    def _check_dict_fromkeys(self, node) -> None:
        if len(node.args) >= 2 and _is_mutable_literal(node.args[1]):
            self.add(
                node, "rare-dict-fromkeys-shared-mutable", "MEDIUM",
                "dict.fromkeys with a mutable default shares the same object across every key.",
                "use a comprehension: {key: [] for key in keys}.")

    def _check_contextlib_suppress(self, node) -> None:
        broad = {"Exception", "BaseException"}
        names = {_name(arg) for arg in node.args}
        if names & broad:
            self.add(
                node, "rare-broad-contextlib-suppress", "MEDIUM",
                "contextlib.suppress is hiding a broad exception class.",
                "suppress only the exact exception that is expected and harmless.")

    def _check_fire_and_forget_task(self, node) -> None:
        parent = getattr(node, "_rare_parent", None)
        if isinstance(parent, ast.Expr):
            self.add(
                node, "rare-untracked-asyncio-task", "MEDIUM",
                "asyncio.create_task result is not stored or awaited; failures can disappear.",
                "store the task, await it, or attach explicit error handling.")

    def _check_decimal_float(self, node) -> None:
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, float):
            self.add(
                node, "rare-decimal-from-float", "MEDIUM",
                "Decimal constructed from a float preserves binary floating-point noise.",
                "construct Decimal from a string or integer instead.")

    def visit_Compare(self, node):
        operands = [node.left] + list(node.comparators)
        if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops) and any(_is_nan(x) for x in operands):
            self.add(
                node, "rare-nan-comparison", "MEDIUM",
                "NaN never compares equal to itself; ==/!= checks are almost always wrong.",
                "use math.isnan, numpy.isnan, or pandas.isna as appropriate.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        self.async_depth += 1
        self._visit_function(node)
        self.async_depth -= 1

    def _visit_function(self, node) -> None:
        prior = getattr(self, "_function_stack", [])
        self._function_stack = prior + [node]
        self._check_lru_cache_method(node)
        self.generic_visit(node)
        self._function_stack = prior

    def _check_lru_cache_method(self, node) -> None:
        if not self.class_stack or not node.args.args:
            return
        first = node.args.args[0].arg
        if first not in {"self", "cls"}:
            return
        decorators = {_decorator_name(dec) for dec in node.decorator_list}
        if decorators & {"lru_cache", "functools.lru_cache", "cache", "functools.cache"}:
            self.add(
                node, "rare-lru-cache-on-method", "MEDIUM",
                "cache decorator on an instance/class method includes self/cls in the cache key.",
                "cache a static function or a stable key, or clear the cache with lifecycle care.")

    def visit_ClassDef(self, node):
        self._check_enum_aliases(node)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def _check_enum_aliases(self, node) -> None:
        bases = {_name(base).rsplit(".", 1)[-1] for base in node.bases}
        if "Enum" not in bases and "IntEnum" not in bases and "StrEnum" not in bases:
            return
        values = {}
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.value, ast.Constant):
                value = (type(stmt.value.value).__name__, stmt.value.value)
                if value in values:
                    self.add(
                        stmt, "rare-enum-duplicate-value", "LOW",
                        "Enum member duplicates %s; Python treats it as an alias." % values[value],
                        "make the alias explicit or give the member a unique value.")
                else:
                    target = stmt.targets[0]
                    values[value] = getattr(target, "id", "<member>")

    def _current_function_name(self) -> str:
        stack = getattr(self, "_function_stack", [])
        return stack[-1].name if stack else ""

    def _current_property_setter(self) -> bool:
        stack = getattr(self, "_function_stack", [])
        if not stack:
            return False
        return any(_decorator_name(dec).endswith(".setter") for dec in stack[-1].decorator_list)


def _attach_parents(tree) -> None:
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            setattr(child, "_rare_parent", parent)


def analyze(source: str, path: str = "<code>") -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    _attach_parents(tree)
    visitor = RareVisitor(source, path)
    visitor.visit(tree)
    visitor.findings.sort(key=Finding.sort_key)
    return visitor.findings


def scan_path(path: str) -> list[Finding]:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return analyze(handle.read(), path)
    except OSError:
        return []


def _iter_py(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules"}]
                for name in sorted(files):
                    if name.endswith((".py", ".pyw")):
                        yield os.path.join(root, name)
        elif path.endswith((".py", ".pyw")):
            yield path


def collect(paths, min_severity: str = "LOW") -> list[Finding]:
    """Collect rare findings from Python files/folders."""
    threshold = SEVERITY_ORDER[min_severity]
    findings = []
    for path in _iter_py(paths):
        findings.extend(item for item in scan_path(path)
                        if SEVERITY_ORDER[item.severity] >= threshold)
    findings.sort(key=Finding.sort_key)
    return findings


def render(findings: list[Finding]) -> str:
    lines = ["Rare Error Oracle", "=" * 72]
    if not findings:
        lines.append("No rare Python errors found.")
        return "\n".join(lines)
    for item in findings:
        lines += [
            "%s:%d [%s] %s" % (item.path, item.line, item.severity, item.rule),
            "  " + item.message,
            "  > " + item.snippet if item.snippet else "  >",
            "  fix: " + item.fix,
            "",
        ]
    lines.append("%d rare finding(s)." % len(findings))
    return "\n".join(lines).rstrip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", help="Python files or folders")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    args = parser.parse_args(argv)
    findings = collect(args.paths, min_severity=args.min_severity)
    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    else:
        print(render(findings))
    return min(len(findings), 250)


if __name__ == "__main__":
    raise SystemExit(main())
