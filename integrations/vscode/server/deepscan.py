#!/usr/bin/env python3
"""
deepscan.py -- Attestor actually reads the code.

Where detect.py matches patterns line-by-line, this parses Python into an AST and
reasons about structure: scopes, control flow, the call graph, which names are
defined where. That lets it (a) explain how a file works, and (b) find bugs regex
cannot -- both common ones (NameErrors, dead code, mutable defaults) and the tiny,
rare ones (`assert (cond, "msg")` is always true; a `return` in a `finally`
swallows exceptions; a duplicate dict key silently dropped).

Pure standard library. No dependencies, no API key.

    python3 deepscan.py path/to/file.py            # findings
    python3 deepscan.py path/to/file.py --explain   # how the code works + findings
    python3 deepscan.py path/to/file.py --json
"""
from __future__ import annotations

import argparse
import ast
import builtins
import dataclasses
import json
import os
import sys

from detect import Finding, SEVERITY_ORDER

BUILTINS = set(dir(builtins)) | {
    "__name__", "__file__", "__doc__", "__all__", "__package__", "__spec__",
    "__loader__", "__builtins__", "__class__", "__dict__", "__module__", "__qualname__",
}

# a small slice of the builtin exception hierarchy (superclass -> subclasses)
EXC_SUB = {
    "ArithmeticError": {"ZeroDivisionError", "OverflowError", "FloatingPointError"},
    "LookupError": {"KeyError", "IndexError"},
    "OSError": {"FileNotFoundError", "PermissionError", "IsADirectoryError",
                "NotADirectoryError", "FileExistsError", "ConnectionError",
                "ConnectionResetError", "TimeoutError", "InterruptedError"},
    "ValueError": {"UnicodeError", "UnicodeDecodeError", "UnicodeEncodeError"},
    "RuntimeError": {"RecursionError", "NotImplementedError"},
    "Exception": {"ValueError", "KeyError", "IndexError", "TypeError", "RuntimeError",
                  "OSError", "IOError", "AttributeError", "ArithmeticError",
                  "LookupError", "FileNotFoundError", "ZeroDivisionError",
                  "StopIteration", "ImportError", "NameError", "AssertionError"},
}
SHADOWABLE = {"list", "dict", "set", "tuple", "str", "int", "float", "bool", "bytes",
              "id", "type", "sum", "min", "max", "input", "open", "hash", "filter",
              "map", "range", "object", "len", "format", "dir", "vars", "next",
              "iter", "sorted", "list", "all", "any", "print"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _snip(lines, lineno):
    return lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""


def _target_names(t):
    if isinstance(t, ast.Name):
        return [t.id]
    if isinstance(t, (ast.Tuple, ast.List)):
        return [n for e in t.elts for n in _target_names(e)]
    if isinstance(t, ast.Starred):
        return _target_names(t.value)
    return []


def _all_args(a: ast.arguments):
    out = list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
    if a.vararg:
        out.append(a.vararg)
    if a.kwarg:
        out.append(a.kwarg)
    return out


def _handler_names(h: ast.ExceptHandler):
    if h.type is None:
        return ["<bare>"]
    if isinstance(h.type, ast.Name):
        return [h.type.id]
    if isinstance(h.type, ast.Tuple):
        return [e.id for e in h.type.elts if isinstance(e, ast.Name)]
    return []


def _is_caught_by(name, prev):
    if prev == "<bare>":
        return True
    child = getattr(builtins, name, None)
    parent = getattr(builtins, prev, None)
    if not isinstance(child, type) or not isinstance(parent, type):
        return name in EXC_SUB.get(prev, set())
    try:
        return issubclass(child, parent) and issubclass(child, BaseException)
    except TypeError:
        return False


def complexity(node) -> int:
    c = 1
    for n in ast.walk(node):
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While,
                          ast.ExceptHandler, ast.IfExp, ast.With, ast.AsyncWith)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
    return c


_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _walk_scope(root):
    """Walk one executable scope without leaking into nested defs/classes."""
    stack = list(reversed(list(ast.iter_child_nodes(root))))
    while stack:
        node = stack.pop()
        if isinstance(node, _SCOPE_NODES):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #
def analyze(source: str, path: str = "<code>") -> list:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [Finding(path, e.lineno or 1, "syntax-error", "HIGH",
                        f"Python cannot parse this file: {e.msg}.",
                        "fix the syntax error before deeper analysis.", "")]
    lines = source.split("\n")
    out = []

    def add(line, rule, sev, msg, fix):
        out.append(Finding(path, line, rule, sev, msg, fix, _snip(lines, line)))

    _assert_tuple(tree, add)
    _return_in_finally(tree, add)
    _unreachable(tree, add)
    _dict_dupe_key(tree, add)
    _list_multiply_alias(tree, add)
    _dataclass_mutable_default(tree, add)
    _mutable_class_attribute(tree, add)
    _late_binding_closure(tree, add)
    _call_default(tree, add)
    _exception_var_leak(tree, add)
    _return_value_in_init(tree, add)
    _async_runtime_traps(tree, add)
    _redefined_func(tree, add)
    _self_comparison(tree, add)
    _is_literal(tree, add)
    _float_equality(tree, add)
    _mutable_default(tree, add)
    _except_handlers(tree, add)
    _shadow_builtin(tree, add)
    _unused_import(tree, add)
    _undefined_name(tree, add)
    _unsafe_value_flow(tree, add, source)

    out.sort(key=Finding.sort_key)
    return out


# --------------------------------------------------------------------------- #
# Value flow across statements
#
# The line rules in detect.py see `requests.get(url, verify=False)` and
# `db.execute("... " + name)`.  They cannot see the same defect once the value
# is parked in a local first, because by then no single line contains it:
#
#     opts = {"verify": False}          sql = "SELECT ... " + name
#     requests.get(url, **opts)         db.execute(sql)
#
# This is a deliberately small propagation: one function scope, names assigned
# exactly once, sink must come after the assignment.  Anything reassigned,
# conditional, or crossing a scope is left alone rather than guessed at.
# --------------------------------------------------------------------------- #
SQL_KEYWORDS = ("select ", "insert ", "update ", "delete ", "drop ",
                "create ", "alter ", "replace into")
SQL_SINKS = {"execute", "executemany", "executescript"}
HTTP_SINKS = {"get", "post", "put", "patch", "delete", "head", "options",
              "request", "send"}
PROCESS_SINKS = {"run", "call", "check_call", "check_output", "popen"}
SHELL_SINKS = {"system", "popen"}
WEAK_ALGOS = {"md5", "sha1"}
# (keyword, literal value that is unsafe) -> how to report it.
BOOL_KWARGS = {
    ("verify", False): ("tls-verify-disabled", "HIGH", "verify=False",
                        HTTP_SINKS),
    ("shell", True): ("py-subprocess-shell", "MEDIUM", "shell=True",
                      PROCESS_SINKS),
}


def _string_literals(node):
    """Every literal string fragment reachable in a string-building expression."""
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


def _is_interpolated_string(node) -> bool:
    """True when a string value is assembled from a non-literal part."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        sides = (node.left, node.right)
        literal = any(isinstance(side, ast.Constant)
                      and isinstance(side.value, str) for side in sides)
        dynamic = any(not isinstance(side, ast.Constant) for side in sides)
        return literal and dynamic
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)
            and isinstance(node.func.value.value, str)):
        return bool(node.args or node.keywords)
    return False


def _unsafe_option_dict(node):
    """A dict literal that turns off a protection, as (rule, severity, what)."""
    if not isinstance(node, ast.Dict):
        return None
    for key, value in zip(node.keys, node.values):
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)
                and isinstance(value, ast.Constant)):
            continue
        if key.value == "verify" and value.value is False:
            return ("tls-verify-disabled", "HIGH", "verify=False")
        if key.value == "shell" and value.value is True:
            return ("py-subprocess-shell", "MEDIUM", "shell=True")
    return None


def _sink_attr(call):
    return call.func.attr if isinstance(call.func, ast.Attribute) else None


def _scopes(tree):
    yield tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _scope_nodes(scope):
    """Nodes owned by this scope. Nested callables are their own scope, so a
    name assigned in one function must never be resolved against a sink in
    another -- ast.walk would happily do exactly that."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _bound_names(target):
    """Every name a binding target writes, including through tuple unpacking."""
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            yield node.id


def _single_assignments(scope):
    """name -> (value_node, lineno) for names this scope assigns exactly once.

    Every binding form has to be counted, not just `name = value`.  A name
    bound in one branch by `a, b = pair` and in another by `a = 'md5'` is not a
    constant, and treating it as one asserts a certainty the code does not
    have.  Anything bound more than once, or bound in a form whose value cannot
    be read off statically, is dropped.
    """
    counts, values = {}, {}

    def bump(name, amount=1):
        counts[name] = counts.get(name, 0) + amount

    for node in _scope_nodes(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and len(node.targets) == 1:
                    bump(target.id)
                    values[target.id] = (node.value, node.lineno)
                else:
                    # Unpacking or chained assignment: bound, but the value of
                    # any single name is not readable here.
                    for name in _bound_names(target):
                        bump(name, 2)
        elif isinstance(node, ast.AnnAssign) and node.value is not None \
                and isinstance(node.target, ast.Name):
            bump(node.target.id)
            values[node.target.id] = (node.value, node.lineno)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            for name in _bound_names(node.target):
                bump(name, 2)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for name in _bound_names(node.target):
                bump(name, 2)
        elif isinstance(node, ast.NamedExpr):
            for name in _bound_names(node.target):
                bump(name, 2)
        elif isinstance(node, ast.comprehension):
            for name in _bound_names(node.target):
                bump(name, 2)
        elif isinstance(node, (ast.withitem,)):
            if node.optional_vars is not None:
                for name in _bound_names(node.optional_vars):
                    bump(name, 2)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bump(node.name, 2)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bump(name, 2)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                               ast.ClassDef)):
            bump(node.name, 2)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bump((alias.asname or alias.name).split(".")[0], 2)
    return {name: values[name] for name, count in counts.items()
            if count == 1 and name in values}


def _class_constants(tree):
    """method node -> {attribute: literal} for its own class body constants.

    Covers `class C: VERIFY = False` reached later as `self.VERIFY`, which no
    line rule can see because neither statement contains the other's half.
    """
    owned = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        constants = {}
        for statement in node.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 \
                    and isinstance(statement.targets[0], ast.Name) \
                    and isinstance(statement.value, ast.Constant):
                constants[statement.targets[0].id] = statement.value.value
        if not constants:
            continue
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owned[statement] = constants
    return owned


def _literal_of(node, kinds):
    if isinstance(node, ast.Constant) and isinstance(node.value, kinds) \
            and not (kinds is str and isinstance(node.value, bool)):
        return node.value
    return None


# Nothing below can fire unless one of these appears somewhere in the source.
# Checking that first skips the per-scope walks entirely for the large majority
# of files, which is what keeps this affordable on a one-worker Pi profile.
FLOW_MARKERS = ("verify", "shell", "execute", "system", "popen", "md5", "sha1")


def _unsafe_value_flow(tree, add, source=""):
    if source and not any(marker in source for marker in FLOW_MARKERS):
        return
    class_constants = _class_constants(tree)
    for scope in _scopes(tree):
        assigned = _single_assignments(scope)
        constants = class_constants.get(scope, {})
        if not assigned and not constants:
            continue
        options, queries, commands, flags, algorithms = {}, {}, {}, {}, {}
        for name, (value, lineno) in assigned.items():
            unsafe = _unsafe_option_dict(value)
            if unsafe:
                options[name] = (unsafe, lineno)
                continue
            if _is_interpolated_string(value):
                text = " ".join(_string_literals(value)).lower()
                if any(word in text for word in SQL_KEYWORDS):
                    queries[name] = lineno
                # Any assembled string is a command-injection risk once it
                # reaches os.system/os.popen, which are always a shell.
                commands[name] = lineno
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, bool):
                flags[name] = (value.value, lineno)
            elif isinstance(value, ast.Constant) \
                    and isinstance(value.value, str) \
                    and value.value.lower() in WEAK_ALGOS:
                algorithms[name] = (value.value.lower(), lineno)
        if not (options or queries or commands or flags or algorithms
                or constants):
            continue
        for node in _scope_nodes(scope):
            if not isinstance(node, ast.Call):
                continue
            attr = _sink_attr(node)
            for keyword in node.keywords:
                if keyword.arg is not None or \
                        not isinstance(keyword.value, ast.Name):
                    continue
                entry = options.get(keyword.value.id)
                if not entry or node.lineno < entry[1]:
                    continue
                (rule, severity, what), _ = entry
                if rule == "tls-verify-disabled" and attr not in HTTP_SINKS:
                    continue
                if rule == "py-subprocess-shell" and attr not in PROCESS_SINKS:
                    continue
                add(node.lineno, rule, severity,
                    f"'{keyword.value.id}' carries {what} and is expanded into this "
                    f"call, which disables the same protection as writing it inline.",
                    "set the option at the call site, or do not disable it at all.")

            # A plain kwarg whose value is a name holding a literal bool, or a
            # class constant reached through self/cls.
            for keyword in node.keywords:
                if keyword.arg is None:
                    continue
                if isinstance(keyword.value, ast.Name):
                    held = flags.get(keyword.value.id)
                    if held is None or node.lineno < held[1]:
                        continue
                    value, source = held[0], keyword.value.id
                elif isinstance(keyword.value, ast.Attribute) and \
                        isinstance(keyword.value.value, ast.Name) and \
                        keyword.value.value.id in {"self", "cls"}:
                    if keyword.value.attr not in constants:
                        continue
                    value = constants[keyword.value.attr]
                    source = "%s.%s" % (keyword.value.value.id,
                                        keyword.value.attr)
                else:
                    continue
                reported = BOOL_KWARGS.get((keyword.arg, value))
                if not reported or attr not in reported[3]:
                    continue
                rule, severity, what, _ = reported
                add(node.lineno, rule, severity,
                    f"'{source}' holds {what}; passing it here disables the "
                    f"same protection as writing the literal inline.",
                    "set the option explicitly at the call site, or do not "
                    "disable it at all.")

            if attr in SQL_SINKS and node.args and \
                    isinstance(node.args[0], ast.Name):
                lineno = queries.get(node.args[0].id)
                if lineno is not None and node.lineno >= lineno:
                    add(node.lineno, "py-sql-injection", "HIGH",
                        f"the query in '{node.args[0].id}' was assembled with "
                        f"formatting or concatenation on line {lineno}; user input "
                        f"reaching it is a SQL-injection vector.",
                        "use parameterized queries: execute(sql, (params,)).")

            if attr in SHELL_SINKS and node.args and \
                    isinstance(node.args[0], ast.Name) and \
                    isinstance(node.func, ast.Attribute) and \
                    isinstance(node.func.value, ast.Name) and \
                    node.func.value.id == "os":
                lineno = commands.get(node.args[0].id)
                if lineno is not None and node.lineno >= lineno:
                    add(node.lineno, "py-os-command-injection", "HIGH",
                        f"the command in '{node.args[0].id}' was assembled with "
                        f"formatting or concatenation on line {lineno}; os.system "
                        f"and os.popen always run it through a shell.",
                        "use subprocess with an argv list and shell=False.")

            # hashlib.new(algo) / getattr(hashlib, algo) where algo is a name
            # holding "md5" or "sha1".
            candidate = None
            if attr == "new" and node.args:
                candidate = node.args[0]
            elif isinstance(node.func, ast.Name) and node.func.id == "getattr" \
                    and len(node.args) >= 2:
                candidate = node.args[1]
            if isinstance(candidate, ast.Name):
                held = algorithms.get(candidate.id)
                if held is not None and node.lineno >= held[1]:
                    add(node.lineno, "weak-hash", "MEDIUM",
                        f"'{candidate.id}' selects {held[0].upper()}, which is "
                        f"collision-broken; naming the algorithm indirectly does "
                        f"not make it safe.",
                        "use SHA-256+; for passwords use bcrypt/scrypt/argon2.")


def _assert_tuple(tree, add):
    for n in ast.walk(tree):
        if isinstance(n, ast.Assert) and isinstance(n.test, ast.Tuple) and n.test.elts:
            add(n.lineno, "assert-tuple", "HIGH",
                "assert on a non-empty tuple is ALWAYS true -- the assertion never fires.",
                'drop the parentheses: assert cond, "message"')


def _return_in_finally(tree, add):
    def scan(stmts):
        bad = []

        def rec(node, loopdepth):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return                             # new scope -- return is fine there
            if isinstance(node, ast.Return):
                bad.append((node.lineno, "return"))
            elif isinstance(node, (ast.Break, ast.Continue)) and loopdepth == 0:
                bad.append((node.lineno, type(node).__name__.lower()))
            inner = loopdepth + isinstance(node, (ast.For, ast.AsyncFor, ast.While))
            for child in ast.iter_child_nodes(node):
                rec(child, inner)
        for s in stmts:
            rec(s, 0)
        return bad

    for t in ast.walk(tree):
        if isinstance(t, ast.Try) and t.finalbody:
            for ln, kind in scan(t.finalbody):
                add(ln, "return-in-finally", "MEDIUM",
                    f"a '{kind}' inside 'finally' silently swallows any exception still in flight.",
                    "move it out of finally, or re-raise before returning.")


def _unreachable(tree, add):
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(node, field, None)
            if not isinstance(stmts, list):
                continue
            for i, s in enumerate(stmts[:-1]):
                if isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    add(stmts[i + 1].lineno, "unreachable-code", "MEDIUM",
                        "this statement can never run -- the line above always exits the block.",
                        "remove the dead code, or fix the control flow above it.")
                    break


def _dict_dupe_key(tree, add):
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            seen = set()
            for k in n.keys:
                if isinstance(k, ast.Constant) and isinstance(
                        k.value, (str, int, float, bytes, bool, type(None))):
                    key = (type(k.value).__name__, k.value)
                    if key in seen:
                        add(k.lineno, "dict-duplicate-key", "MEDIUM",
                            f"duplicate key {k.value!r} in this dict literal -- the earlier value is dropped.",
                            "remove or rename the duplicate key.")
                    seen.add(key)


def _is_mutable_node(node):
    return isinstance(node, (ast.List, ast.Dict, ast.Set)) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "dict", "set"})


def _list_multiply_alias(tree, add):
    def mutable_container_expr(node):
        if _is_mutable_node(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            return isinstance(node.left, ast.List) or isinstance(node.right, ast.List)
        return False

    def repeated_mutable(node):
        if isinstance(node, ast.List):
            return any(mutable_container_expr(e) for e in node.elts)
        return False

    for n in ast.walk(tree):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult):
            if repeated_mutable(n.left) or repeated_mutable(n.right):
                add(n.lineno, "list-multiply-alias", "MEDIUM",
                    "multiplying a list containing a mutable object aliases the same inner object many times.",
                    "use a comprehension, e.g. [[0 for _ in range(cols)] for _ in range(rows)].")


def _decorator_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _decorator_name(node.value)
        return (base + "." if base else "") + node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _dataclass_mutable_default(tree, add):
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        decorators = {_decorator_name(d) for d in cls.decorator_list}
        if "dataclass" not in decorators and "dataclasses.dataclass" not in decorators:
            continue
        for stmt in cls.body:
            value = None
            if isinstance(stmt, ast.Assign):
                value = stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                value = stmt.value
            if value is not None and _is_mutable_node(value):
                add(stmt.lineno, "dataclass-mutable-default", "MEDIUM",
                    "dataclass field uses a mutable default shared by every instance.",
                    "use field(default_factory=list/dict/set) instead of a literal default.")


def _mutable_class_attribute(tree, add):
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        dataclass_decorated = any(_decorator_name(d).endswith("dataclass") for d in cls.decorator_list)
        if dataclass_decorated:
            continue
        for stmt in cls.body:
            pairs = []
            if isinstance(stmt, ast.Assign):
                pairs = [(t, stmt.value) for t in stmt.targets]
            elif isinstance(stmt, ast.AnnAssign):
                pairs = [(stmt.target, stmt.value)] if stmt.value is not None else []
            for target, value in pairs:
                if isinstance(target, ast.Name) and not target.id.isupper() and _is_mutable_node(value):
                    add(stmt.lineno, "mutable-class-attribute", "LOW",
                        f"class attribute '{target.id}' is mutable and shared by all instances.",
                        "initialize it on self in __init__, or make the shared state explicit.")


def _names_loaded(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _body_names_loaded(fn):
    """Names loaded in a lambda/function BODY only. Default-argument and
    annotation expressions are evaluated eagerly in the enclosing scope, so a loop
    variable referenced there (e.g. `lambda x=x: ...` or `lambda m, g=good: ...`)
    is EARLY-bound -- the very fix for late binding -- and must not count as a late
    capture. Only free variables read when the closure later RUNS matter."""
    body = fn.body
    nodes = body if isinstance(body, list) else [body]
    loaded = set()
    for node in nodes:
        loaded |= _names_loaded(node)
    return loaded


def _param_names(fn):
    if isinstance(fn, ast.Lambda):
        return {a.arg for a in _all_args(fn.args)}
    if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {a.arg for a in _all_args(fn.args)}
    return set()


def _late_binding_closure(tree, add):
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.AsyncFor)):
            continue
        loop_names = set(_target_names(loop.target))
        if not loop_names:
            continue
        for stmt in loop.body:
            for child in ast.walk(stmt):
                if isinstance(child, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
                    captured = (_body_names_loaded(child) & loop_names) - _param_names(child)
                    if captured:
                        names = ", ".join(sorted(captured))
                        add(child.lineno, "late-binding-closure", "MEDIUM",
                            f"closure captures loop variable(s) {names}; every callback will see the final loop value.",
                            "bind the value now, e.g. lambda x=x: ... or functools.partial(...).")


def _call_default(tree, add):
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in list(fn.args.defaults) + [x for x in fn.args.kw_defaults if x is not None]:
                if isinstance(d, ast.Call) and not _is_mutable_node(d):
                    add(d.lineno, "call-default", "MEDIUM",
                        "function default is a call evaluated once at definition/import time, not once per call.",
                        "default to None and call the factory inside the function body.")


def _loads_name(node, name):
    """True if `name` is loaded as a free variable in `node`. A nested
    `except ... as name:` handler rebinds `name` locally, so uses inside it are
    that fresh binding, not a leak of the outer one -- those subtrees are skipped
    (otherwise two adjacent try/excepts that reuse the same name false-positive)."""
    if isinstance(node, ast.Name):
        return isinstance(node.ctx, ast.Load) and node.id == name
    if isinstance(node, ast.ExceptHandler) and node.name == name:
        return False
    return any(_loads_name(child, name) for child in ast.iter_child_nodes(node))


def _stores_name(node, name):
    return any(isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id == name
               for n in ast.walk(node))


def _exception_var_leak(tree, add):
    def scan_list(stmts):
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, ast.Try):
                names = list(dict.fromkeys(h.name for h in stmt.handlers if h.name))
                for name in names:
                    rebound = False
                    for later in stmts[i + 1:]:
                        if not rebound and _loads_name(later, name):
                            add(later.lineno, "exception-var-leak", "MEDIUM",
                                f"exception variable '{name}' is cleared after the except block in Python 3.",
                                "copy it to another name inside except if you need it later.")
                            break
                        if _stores_name(later, name):
                            rebound = True
            for field in ("body", "orelse", "finalbody"):
                child = getattr(stmt, field, None)
                if isinstance(child, list):
                    scan_list(child)
            if isinstance(stmt, ast.Try):
                for handler in stmt.handlers:
                    scan_list(handler.body)
    scan_list(tree.body)


def _return_value_in_init(tree, add):
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef) and fn.name == "__init__":
            for node in _walk_scope(fn):
                if isinstance(node, ast.Return) and node.value is not None:
                    add(node.lineno, "return-value-in-init", "HIGH",
                        "__init__ must return None; returning a value raises TypeError during construction.",
                        "assign state on self and let __init__ return implicitly.")


def _async_runtime_traps(tree, add):
    async_names = {n.name for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}

    def scan_async_body(fn):
        for node in _walk_scope(fn):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    base, attr = node.func.value.id, node.func.attr
                    if base == "asyncio" and attr == "run":
                        add(node.lineno, "asyncio-run-in-async", "HIGH",
                            "asyncio.run() cannot be called from a running event loop.",
                            "await the coroutine directly, or create a task in the existing loop.")
                    if base == "time" and attr == "sleep":
                        add(node.lineno, "blocking-sleep-in-async", "MEDIUM",
                            "time.sleep() blocks the entire event loop inside async code.",
                            "use await asyncio.sleep(...).")

        def scan_stmts(stmts):
            for stmt in stmts:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                    continue
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    func = stmt.value.func
                    if isinstance(func, ast.Name) and func.id in async_names:
                        add(stmt.lineno, "unawaited-coroutine", "HIGH",
                            f"async function '{func.id}' is called without await; the coroutine will never run.",
                            "use await, asyncio.create_task, or return the coroutine intentionally.")
                for field in ("body", "orelse", "finalbody"):
                    child = getattr(stmt, field, None)
                    if isinstance(child, list):
                        scan_stmts(child)
                if isinstance(stmt, ast.Try):
                    for handler in stmt.handlers:
                        scan_stmts(handler.body)
        scan_stmts(fn.body)

    for fn in ast.walk(tree):
        if isinstance(fn, ast.AsyncFunctionDef):
            scan_async_body(fn)


def _redefined_func(tree, add):
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        seen = set()
        for s in body:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and not s.decorator_list:
                if s.name in seen:
                    add(s.lineno, "redefined-function", "MEDIUM",
                        f"'{s.name}' is defined more than once in the same scope -- the later one wins.",
                        "rename or remove the duplicate definition.")
                seen.add(s.name)


def _self_comparison(tree, add):
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare) and len(n.ops) == 1 and \
                isinstance(n.ops[0], (ast.Eq, ast.Is)):        # skip != / is not (NaN idiom)
            l, r = n.left, n.comparators[0]
            if isinstance(l, ast.Name) and isinstance(r, ast.Name) and l.id == r.id:
                add(n.lineno, "self-comparison", "MEDIUM",
                    f"'{l.id}' is compared to itself -- this is always True.",
                    "almost certainly a typo for a different variable.")


def _is_literal(tree, add):
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            for op, comp in zip(n.ops, n.comparators):
                if isinstance(op, (ast.Is, ast.IsNot)):
                    for operand in (n.left, comp):
                        if isinstance(operand, ast.Constant) and \
                                isinstance(operand.value, (int, str, bytes, float)) and \
                                not isinstance(operand.value, bool):
                            add(n.lineno, "is-literal", "MEDIUM",
                                "'is'/'is not' with a literal tests identity, not value -- it works only by luck.",
                                "use == / != for value comparison.")
                            break


def _float_equality(tree, add):
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            for op, comp in zip(n.ops, n.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    for operand in (n.left, comp):
                        if isinstance(operand, ast.Constant) and isinstance(operand.value, float):
                            add(n.lineno, "float-equality", "MEDIUM",
                                "comparing to a float literal with == / != is unreliable (rounding).",
                                "compare within a tolerance: abs(a - b) < eps.")
                            break


def _mutable_default(tree, add):
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in list(fn.args.defaults) + list(fn.args.kw_defaults):
                if d is None:
                    continue
                if isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
                        isinstance(d, ast.Call) and isinstance(d.func, ast.Name)
                        and d.func.id in {"list", "dict", "set"}):
                    add(d.lineno, "mutable-default", "MEDIUM",
                        "a mutable default ([], {}, set()) is created once and shared across all calls.",
                        "default to None and build the container inside the function.")


def _except_handlers(tree, add):
    for t in ast.walk(tree):
        if not isinstance(t, ast.Try):
            continue
        caught = []
        for h in t.handlers:
            names = _handler_names(h)
            if h.type is None:
                add(h.lineno, "bare-except", "MEDIUM",
                    "bare 'except:' catches everything, including KeyboardInterrupt and SystemExit.",
                    "catch a specific exception, or 'except Exception:' at minimum.")
            for nm in names:
                for prev in caught:
                    if _is_caught_by(nm, prev):
                        add(h.lineno, "except-unordered", "MEDIUM",
                            f"'except {nm}' can never run -- a broader handler ('{prev}') was listed before it.",
                            f"put the more specific 'except {nm}' before '{prev}'.")
                        break
            # Exceptions inside one tuple are peers handled by the same clause;
            # their order cannot make another tuple member unreachable.
            caught.extend(names)


def _shadow_builtin(tree, add):
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                for nm in _target_names(t):
                    if nm in SHADOWABLE:
                        add(t.lineno, "shadow-builtin", "LOW",
                            f"'{nm}' shadows a builtin of the same name in this scope.",
                            "rename it to avoid surprising bugs later.")
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for a in _all_args(n.args):
                if a.arg in SHADOWABLE:
                    add(a.lineno, "shadow-builtin", "LOW",
                        f"parameter '{a.arg}' shadows a builtin.",
                        "rename it to avoid surprising bugs later.")


def _collect_dunder_all(tree):
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in n.targets):
            if isinstance(n.value, (ast.List, ast.Tuple)):
                for e in n.value.elts:
                    if isinstance(e, ast.Constant) and isinstance(e.value, str):
                        names.add(e.value)
    return names


def _unused_import(tree, add):
    if any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
           for n in ast.walk(tree)):
        return                                              # star import: give up, too dynamic
    imported = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                imported[(a.asname or a.name).split(".")[0]] = n.lineno
        elif isinstance(n, ast.ImportFrom):
            if n.module == "__future__":
                continue
            for a in n.names:
                imported[a.asname or a.name] = n.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    exported = _collect_dunder_all(tree)
    for name, ln in imported.items():
        if name not in used and name not in exported and not name.startswith("_"):
            add(ln, "unused-import", "LOW",
                f"'{name}' is imported but never used.",
                "remove the unused import.")


class _BindingCollector(ast.NodeVisitor):
    """Bindings for exactly one Python lexical scope (nested scopes are opaque)."""

    def __init__(self, parameters=()):
        self.bound = set(parameters)
        self.globals = set()
        self.nonlocals = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.bound.add(node.id)

    def visit_Import(self, node):
        for alias in node.names:
            self.bound.add(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == "*":
                continue
            self.bound.add(alias.asname or alias.name)

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.nonlocals.update(node.names)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node):
        if node.name:
            self.bound.add(node.name)

    def visit_FunctionDef(self, node):
        self.bound.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bound.add(node.name)

    def visit_Lambda(self, node):
        return

    def visit_ListComp(self, node):
        return

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


class _NameScope:
    def __init__(self, kind, parent, statements=(), parameters=(), extra=()):
        self.kind = kind
        self.parent = parent
        collector = _BindingCollector(parameters)
        for statement in statements:
            collector.visit(statement)
        self.assigned = set(collector.bound)
        self.bound = (collector.bound | set(extra)) - collector.globals - collector.nonlocals
        self.globals = collector.globals
        self.nonlocals = collector.nonlocals


def _module_scope(scope):
    while scope.parent is not None:
        scope = scope.parent
    return scope


def _name_resolves(scope, name):
    if name in BUILTINS:
        return True
    if name in scope.globals:
        return name in scope.assigned or name in _module_scope(scope).bound
    if name in scope.nonlocals:
        parent = scope.parent
        while parent is not None and parent.kind != "module":
            if parent.kind != "class" and name in parent.bound:
                return True
            parent = parent.parent
        return False
    if name in scope.bound:
        return True
    parent = scope.parent
    # A method does not close over its class namespace: `field` must be
    # `self.field`/`Cls.field`. It can still close over an enclosing function.
    if scope.kind in {"function", "lambda", "comprehension"}:
        while parent is not None and parent.kind == "class":
            parent = parent.parent
    return _name_resolves(parent, name) if parent is not None else False


class _UndefinedVisitor(ast.NodeVisitor):
    def __init__(self, tree, add):
        self.add = add
        self.scope = _NameScope("module", None, tree.body)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and not _name_resolves(self.scope, node.id):
            self.add(node.lineno, "undefined-name", "HIGH",
                     f"'{node.id}' is used but is not defined in this accessible scope.",
                     "check for a typo, a missing import, or a missing assignment.")

    def visit_AnnAssign(self, node):
        # Type annotations may be forward references or postponed; analyze the
        # runtime value only, matching the analyzer's long-standing policy.
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)

    def _visit_function(self, node, kind="function"):
        # Decorators and defaults execute in the enclosing scope. Annotations are
        # deliberately ignored: forward references and postponed evaluation are valid.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            self.visit(default)
        parameters = [arg.arg for arg in _all_args(node.args)]
        extra = {"__class__"} if self.scope.kind == "class" else set()
        child = _NameScope(kind, self.scope, node.body, parameters, extra)
        previous, self.scope = self.scope, child
        for statement in node.body:
            self.visit(statement)
        self.scope = previous

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d]:
            self.visit(default)
        parameters = [arg.arg for arg in _all_args(node.args)]
        child = _NameScope("lambda", self.scope, [node.body], parameters)
        previous, self.scope = self.scope, child
        self.visit(node.body)
        self.scope = previous

    def visit_ClassDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        child = _NameScope("class", self.scope, node.body)
        previous, self.scope = self.scope, child
        for statement in node.body:
            self.visit(statement)
        self.scope = previous

    def _visit_comprehension(self, node, result_nodes):
        if not node.generators:
            return
        self.visit(node.generators[0].iter)  # first iterable runs in the outer scope
        targets = set()
        for generator in node.generators:
            targets.update(_target_names(generator.target))
        child = _NameScope("comprehension", self.scope, extra=targets)
        previous, self.scope = self.scope, child
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for result in result_nodes:
            self.visit(result)
        self.scope = previous

    def visit_ListComp(self, node):
        self._visit_comprehension(node, [node.elt])

    visit_SetComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_DictComp(self, node):
        self._visit_comprehension(node, [node.key, node.value])


def _undefined_name(tree, add):
    # Dynamic namespace injection and star imports make precise name reasoning
    # impossible; stay quiet rather than invent false positives.
    dynamic = {"exec", "eval", "globals", "locals", "vars", "__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in dynamic:
            return
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            return
    visitor = _UndefinedVisitor(tree, add)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            collector = _BindingCollector(arg.arg for arg in _all_args(node.args))
            for statement in node.body:
                collector.visit(statement)
            visitor.scope.bound.update(collector.globals & collector.bound)
    visitor.visit(tree)


# --------------------------------------------------------------------------- #
# explain -- how the code works
# --------------------------------------------------------------------------- #
def _sig(fn: ast.AST) -> str:
    """Render a def's parameter list roughly the way it reads in source."""
    a = fn.args
    parts = []
    pos = list(a.posonlyargs) + list(a.args)
    ndef = len(a.defaults)
    first_def = len(pos) - ndef
    for i, arg in enumerate(pos):
        s = arg.arg
        if i >= first_def:
            s += "=" + _unparse(a.defaults[i - first_def])
        parts.append(s)
        if a.posonlyargs and i == len(a.posonlyargs) - 1:
            parts.append("/")
    if a.vararg:
        parts.append("*" + a.vararg.arg)
    elif a.kwonlyargs:
        parts.append("*")
    for arg, d in zip(a.kwonlyargs, a.kw_defaults):
        s = arg.arg
        if d is not None:
            s += "=" + _unparse(d)
        parts.append(s)
    if a.kwarg:
        parts.append("**" + a.kwarg.arg)
    return ", ".join(parts)


def _unparse(node) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "..."


def _defined_functions(tree):
    """Every function def in the module, keyed by name (for the call graph)."""
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(n.name)
    return names


def _calls_in(fn, known):
    """Direct calls this function makes to other module-level functions."""
    out = []
    seen = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            target = None
            if isinstance(n.func, ast.Name):
                target = n.func.id
            elif isinstance(n.func, ast.Attribute):
                target = n.func.attr
            if target and target in known and target != fn.name and target not in seen:
                seen.add(target)
                out.append(target)
    return out


def explain(source: str, path: str) -> str:
    """
    A plain-language structural summary: what this module contains and how the
    pieces call each other. Not a bug report -- the "read it and understand it"
    half of the request. Pairs with analyze() for the "find the errors" half.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return f"{path}: cannot parse ({e.msg} at line {e.lineno})."

    lines = source.split("\n")
    loc = sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    out = [f"how {os.path.basename(path)} works", "=" * 60]

    doc = ast.get_docstring(tree)
    if doc:
        first = doc.strip().split("\n", 1)[0]
        out.append(f"purpose : {first}")
    out.append(f"size    : {len(lines)} lines ({loc} of code)")

    imports = []
    for n in tree.body:
        if isinstance(n, ast.Import):
            imports += [a.asname or a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            mod = ("." * (n.level or 0)) + (n.module or "")
            imports += [f"{mod}.{a.name}" for a in n.names]
    if imports:
        shown = ", ".join(imports[:12]) + (" ..." if len(imports) > 12 else "")
        out.append(f"imports : {shown}")

    known = _defined_functions(tree)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    funcs = [n for n in tree.body
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    if classes:
        out.append("")
        out.append(f"classes ({len(classes)}):")
        for c in classes:
            bases = ", ".join(_unparse(b) for b in c.bases)
            methods = [m for m in c.body
                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            head = f"  class {c.name}" + (f"({bases})" if bases else "")
            out.append(f"{head}  -- {len(methods)} method(s)")
            for m in methods:
                out.append(f"      .{m.name}({_sig(m)})  [complexity {complexity(m)}]")

    if funcs:
        out.append("")
        out.append(f"top-level functions ({len(funcs)}):")
        for f in funcs:
            kw = "async def" if isinstance(f, ast.AsyncFunctionDef) else "def"
            out.append(f"  {kw} {f.name}({_sig(f)})  [complexity {complexity(f)}]")
            fdoc = ast.get_docstring(f)
            if fdoc:
                out.append(f"      \"{fdoc.strip().splitlines()[0]}\"")

    # intra-module call graph -- who calls whom
    edges = []
    for f in funcs:
        for callee in _calls_in(f, known):
            edges.append((f.name, callee))
    for c in classes:
        for m in c.body:
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for callee in _calls_in(m, known):
                    edges.append((f"{c.name}.{m.name}", callee))
    if edges:
        out.append("")
        out.append("call graph (who calls whom, within this module):")
        for caller, callee in edges:
            out.append(f"  {caller} -> {callee}")

    # the most complex function is where the risk concentrates
    ranked = sorted(
        [[f.name, complexity(f)] for f in funcs] +
        [[f"{c.name}.{m.name}", complexity(m)]
         for c in classes for m in c.body
         if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))],
        key=lambda x: x[1], reverse=True)
    if ranked:
        out.append("")
        top = ranked[0]
        out.append(f"hot spot : {top[0]} is the most complex path "
                   f"(cyclomatic complexity {top[1]}) -- read it first.")
    return "\n".join(out)


# rules detect.py's regex engine already covers for Python -- suppressed when
# deepscan runs *through* attestor, so the same line isn't reported twice.
DETECT_OVERLAP = {"mutable-default", "bare-except", "is-literal"}


def scan_path(path: str) -> list:
    """
    Read a .py file and return the AST findings detect.py can't produce.
    Used by attestor --deep to layer semantic analysis on top of the regex engine.
    Any read/parse trouble degrades to [] -- deep mode must never crash a scan.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return []
    return [f for f in analyze(source, path) if f.rule not in DETECT_OVERLAP]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _iter_py(paths, errors=None):
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                if "__pycache__" in root:
                    continue
                for fn in sorted(files):
                    if fn.endswith(".py"):
                        yield os.path.join(root, fn)
        elif os.path.isfile(p) and p.lower().endswith((".py", ".pyw")):
            yield p
        elif errors is not None:
            reason = "unsupported input type" if os.path.isfile(p) else "path does not exist"
            errors.append("%s: %s" % (p, reason))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Python files or directories")
    ap.add_argument("--explain", action="store_true",
                    help="print how each file works before its findings")
    ap.add_argument("--json", action="store_true", help="machine-readable findings")
    ap.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    args = ap.parse_args(argv)

    threshold = SEVERITY_ORDER[args.min_severity]
    all_findings = []
    scan_errors = []
    files = list(_iter_py(args.paths, scan_errors))
    if not files and not scan_errors:
        scan_errors.append("no Python source files were found")
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as e:
            scan_errors.append("cannot read %s: %s" % (path, e))
            continue
        findings = [f for f in analyze(source, path)
                    if SEVERITY_ORDER[f.severity] >= threshold]
        all_findings += findings
        if args.explain and not args.json:
            print(explain(source, path))
            print()

    all_findings.sort(key=Finding.sort_key)

    for message in scan_errors:
        print("scan error: " + message, file=sys.stderr)

    if args.json:
        print(json.dumps([dataclasses.asdict(f) for f in all_findings], indent=2))
        return 2 if scan_errors else min(len(all_findings), 250)

    for f in all_findings:
        print(f"{f.path}:{f.line}  [{f.severity}] {f.rule}")
        print(f"   {f.message}")
        if f.snippet:
            print(f"   > {f.snippet}")
        print(f"   fix: {f.fix}")
        print()
    n = len(all_findings)
    print(f"— {n} finding{'s' if n != 1 else ''} —")
    return 2 if scan_errors else min(n, 250)


if __name__ == "__main__":
    sys.exit(main())
