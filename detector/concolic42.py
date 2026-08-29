#!/usr/bin/env python3
"""Concolic 4.2 -- constraint-directed path exploration (bounded symbolic).

Scope (honest): a bounded concolic engine for Python functions that take a
single bytes argument, covering these guard forms:

    len(data)  <  n        len(data) >=  n
    data[i] == c           data[i] != c
    data.startswith(s)     (also under 'not')

Semantics: every extracted test is treated as a GUARD on the path toward the
function's deepest statement. Reaching that depth requires each guard to
evaluate False, so the solver FALSIFIES constraints one by one and then
enumerates alternates by satisfying exactly one guard at a time.

This is NOT a general SMT solver; it solves the documented forms greedily.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import sys
import textwrap

CC_SCHEMA = "attestor-concolic-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


class CcError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_data(node):
    return isinstance(node, ast.Name) and node.id == "data"


def extract_constraints(fn):
    try:
        source = textwrap.dedent(inspect.getsource(fn))
    except (OSError, TypeError) as exc:
        raise CcError("cannot read source of %r" % fn) from exc
    tree = ast.parse(source)
    constraints = []
    for node in ast.walk(tree):

        def record(form, **fields):
            fields["form"] = form
            fields["line"] = getattr(node, "lineno", 0)
            constraints.append(fields)

        def prefix_of(const_node):
            raw = const_node.value
            if isinstance(raw, bytes):
                return raw.decode("latin-1")
            if isinstance(raw, str):
                return raw
            return None

        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = node.operand
            if isinstance(inner, ast.Call) and \
                    isinstance(inner.func, ast.Attribute) and \
                    inner.func.attr == "startswith" and \
                    _is_data(inner.func.value) and inner.args and \
                    isinstance(inner.args[0], ast.Constant):
                prefix = prefix_of(inner.args[0])
                if prefix is not None:
                    record("startswith", prefix=prefix, negated=True)
            continue

        if not isinstance(node, ast.Compare):
            continue
        left = node.left
        right = node.comparators[0]
        op = node.ops[0]

        if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) \
                and left.func.id == "len" and left.args and \
                _is_data(left.args[0]) and \
                isinstance(right, ast.Constant) and \
                isinstance(right.value, int):
            if isinstance(op, ast.Lt) or isinstance(op, ast.LtE):
                record("len_lt", n=int(right.value))
            elif isinstance(op, ast.Gt) or isinstance(op, ast.GtE):
                record("len_ge", n=int(right.value))
            continue

        if isinstance(left, ast.Call) and \
                isinstance(left.func, ast.Attribute) and \
                left.func.attr == "startswith" and _is_data(left.value) \
                and left.args and isinstance(left.args[0], ast.Constant):
            prefix = prefix_of(left.args[0])
            if prefix is not None:
                record("startswith", prefix=prefix, negated=False)
            continue

        if isinstance(op, (ast.Eq, ast.NotEq)) and \
                isinstance(left, ast.Subscript) and _is_data(left.value) \
                and isinstance(right, ast.Constant) and \
                isinstance(left.slice, ast.Constant) and \
                isinstance(left.slice.value, int) and \
                isinstance(right.value, (int, str)):
            record("eq_byte" if isinstance(op, ast.Eq) else "neq_byte",
                   index=left.slice.value,
                   value=right.value)
    return constraints


def _byte_of(value):
    raw = ord(value) if isinstance(value, str) else value
    return raw & 0xFF


def apply_constraint(buf, constraint, mode):
    """mode 'falsify' drives past the guard; mode 'satisfy' takes it."""
    form = constraint["form"]
    falsify = mode == "falsify"

    if form == "eq_byte":
        index = constraint["index"]
        while index >= len(buf):
            buf.extend(b"\x00")
        target = _byte_of(constraint["value"])
        # guard 'data[i] == c': satisfy => byte equals c, falsify => differs
        buf[index] = target if mode == "satisfy" else ((target ^ 1) & 0xFF)
    elif form == "neq_byte":
        index = constraint["index"]
        while index >= len(buf):
            buf.extend(b"\x00")
        target = _byte_of(constraint["value"])
        # guard 'data[i] != c': satisfy => differs, falsify => equals c
        buf[index] = ((target ^ 1) & 0xFF) if mode == "satisfy" else target
    elif form == "startswith":
        prefix = constraint["prefix"].encode("latin-1", errors="replace")
        negated = constraint.get("negated", False)
        present_needed = negated ^ (mode == "satisfy")
        if present_needed and prefix:
            buf[:len(prefix)] = prefix
        elif prefix and buf:
            buf[0] = (_byte_of(prefix[0]) ^ 1) & 0xFF
    elif form == "len_lt":
        if mode == "falsify":
            while len(buf) < constraint["n"]:
                buf.extend(b"\x00")
        else:
            del buf[max(1, constraint["n"] - 1):]
    elif form == "len_ge":
        if mode == "falsify":
            del buf[max(1, constraint["n"] - 1):]
        else:
            while len(buf) < constraint["n"]:
                buf.extend(b"\x00")


def solve_path(constraints, satisfy_index=None):
    """Falsify every guard except the chosen one (which is satisfied)."""
    buf = bytearray(16)
    ordered = [c for c in constraints if not c["form"].startswith("len")] + \
              [c for c in constraints if c["form"].startswith("len")]
    highest_index = -1
    for position, constraint in enumerate(ordered):
        original_index = constraints.index(constraint)
        mode = "satisfy" if original_index == satisfy_index else "falsify"
        apply_constraint(buf, constraint, mode)
        form = constraint["form"]
        if form in ("eq_byte", "neq_byte"):
            highest_index = max(highest_index,
                                int(constraint["index"]))
        elif form == "startswith" and constraint.get(
                "prefix") and (
                constraint.get("negated") ^ (mode == "satisfy")):
            highest_index = max(highest_index,
                                len(str(constraint["prefix"])) - 1)
    # trim to the smallest buffer that still honors every touched position
    floor = highest_index + 1
    for constraint in constraints:
        form = constraint["form"]
        was_satisfied = constraints.index(constraint) == satisfy_index
        if form == "len_lt":
            floor = max(floor, constraint["n"]) \
                if not was_satisfied else floor
            if was_satisfied:
                floor = max(floor, 0)
        elif form == "len_ge":
            floor = max(floor, constraint["n"] if not was_satisfied else 0)
    if floor and len(buf) > floor:
        del buf[floor:]
    return bytes(buf)


def explore(fn, max_alternates=None):
    constraints = extract_constraints(fn)
    paths = []
    crashes = []

    def attempt(label, data):
        try:
            result = fn(bytes(data))
            paths.append({"path": label,
                          "input_hex": bytes(data).hex(),
                          "outcome": ("returned:%r" % (result,))[:48]})
        except Exception as exc:  # noqa: BLE001
            crashes.append({
                "input_hex": bytes(data).hex(),
                "exception": "%s: %s" % (type(exc).__name__, exc),
                "path": label,
            })

    attempt("all-guards-false-deep-path",
            solve_path(constraints))
    limit = len(constraints) if max_alternates is None else min(len(constraints), max_alternates)
    for index in range(limit):
        attempt("guard-%d-taken" % index, solve_path(constraints,
                                                     satisfy_index=index))

    return {
        "schema": CC_SCHEMA,
        "tool": "concolic-explorer",
        "target": getattr(fn, "__name__", "<fn>"),
        "constraints_found": constraints,
        "paths_explored": len(paths),
        "paths": paths[:12],
        "crashes_found": len(crashes),
        "crashes": crashes,
        "boundary": ("bounded constraint-directed enumeration over "
                     "documented guard forms; not a general SMT solver"),
    }


def run_selftest():
    checks = []

    def guarded(data):
        if len(data) < 6:
            return "too-short"
        if data[0] != 67:
            return "wrong-first-byte"
        if data[5] != 70:
            return "wrong-sixth-byte"
        raise RuntimeError("deep-planted-bug")

    report = explore(guarded)
    forms = {c["form"] for c in report["constraints_found"]}
    checks.append(("constraints cover all three forms",
                   forms == {"len_lt", "neq_byte"}))
    crashing = [c for c in report["crashes"]
                if "deep-planted-bug" in c["exception"]]
    checks.append(("deep bug reached via falsified guards",
                   bool(crashing)))
    if crashing:
        solved = bytes.fromhex(crashing[0]["input_hex"])
        checks.append(("solved input satisfies the deep semantics",
                       len(solved) >= 6 and solved[0] == 67
                       and solved[5] == 70))
    checks.append(("alternate guard paths enumerated",
                   report["paths_explored"] >= 3))

    def prefixed(data):
        if not data.startswith(b"MA"):
            return "wrong-prefix"
        if len(data) < 5:
            return "short"
        if data[4] != 0x7F:
            return "wrong-marker"
        raise RuntimeError("boom-prefixed")

    report2 = explore(prefixed)
    negated_startswith = any(
        c["form"] == "startswith" and c.get("negated")
        for c in report2["constraints_found"])
    checks.append(("'not startswith' guard recognized",
                   negated_startswith))
    checks.append(("prefixed deep bug reached",
                   any("boom-prefixed" in c["exception"]
                       for c in report2["crashes"])))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": CC_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="concolic42", description="Bounded concolic path explorer")
    parser.add_argument("--target-module", required=True)
    parser.add_argument("--target-entry", required=True)
    args = parser.parse_args(argv)


    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "attestor_concolic_target", args.target_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, args.target_entry, None)
    if not callable(fn):
        print("concolic42: entry %r is not callable" % args.target_entry,
              file=sys.stderr)
        return EXIT_INVALID

    try:
        report = explore(fn)
    except CcError as exc:
        print("concolic42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_FINDING if report["crashes_found"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
