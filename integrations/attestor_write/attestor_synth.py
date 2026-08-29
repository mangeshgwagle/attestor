"""Attestor writes a function nobody wrote a template for.

`codegen.py` expands templates: it emits the program it was built to emit.
This does not. Give it input/output examples and it *searches* for a program
that reproduces them, so the result is discovered rather than instantiated
-- there is no template for `sum(x for x in value if x % 2 == 0)` anywhere
in this file.

The method is bottom-up enumerative synthesis, the same shape as FlashFill
and the SyGuS solvers: build every program of size 1, then every program of
size 2 built from those, and so on, testing each against the examples.

Two things make that tractable rather than hopeless.

*Observational equivalence.* Two programs that agree on every example are
interchangeable for the rest of the search, so only the first is kept.
`x + 0` and `x` produce identical output columns, and keeping both would
double the next level and every level after it.

*No evaluation of text.* Candidates are trees of real Python callables,
applied directly against an environment. Nothing is `eval`ed or `exec`ed
during the search. Source is rendered only for the program that already
won, and that text is then put through Attestor's own analyzer.

Loops and recursion
-------------------
Both arrive through *higher-order* operators -- `map`, `filter`, `count`,
`fold`, `take_while` -- whose first argument is a small program rather than
a value. That inner program is synthesized too, over a grammar where the
loop's bound names (`item`, `acc`) are leaves.

Recursion is deliberately restricted to the structural kind. `fold` is a
catamorphism: it consumes one element per step and stops when the sequence
is exhausted, so a synthesized fold terminates by construction. General
self-recursion is *not* in the grammar, and that is a design decision, not
an omission -- an enumerative search over arbitrary recursive programs
spends almost all its time building things that never return, and a
synthesizer whose candidates can hang is not usable. Every loop Attestor writes
here is guaranteed to finish.
"""

from __future__ import annotations

import itertools
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

_HERE = Path(__file__).resolve()
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

import attestor_write  # noqa: E402

__all__ = [
    "Op", "Program", "synthesize", "render", "write_function",
    "INT_OPS", "STR_OPS", "LIST_OPS", "BODY_OPS", "PRED_OPS", "ALL_OPS",
    "MAX_SIZE", "MAX_BODY_SIZE", "operator_count",
]

MAX_SIZE = 4
#: Inner loop bodies are kept tiny: the pool multiplies the outer search, so
#: every extra unit of body size costs a level of the whole enumeration.
MAX_BODY_SIZE = 3
_REJECT = object()
_LIMIT = 4096
_HUGE = 10 ** 12


@dataclass(frozen=True)
class Op:
    """One operator: how to compute it, and how to write it down.

    `body` marks a higher-order operator whose first argument is a program
    to run per element rather than a value to consume. `binds` names the
    variables that program may read.
    """

    name: str
    arity: int
    fn: Callable[..., Any]
    template: str
    body: bool = False
    binds: tuple[str, ...] = ()


@dataclass(frozen=True)
class Program:
    op: Op
    args: tuple = ()

    @property
    def size(self) -> int:
        return 1 + sum(a.size for a in self.args)

    @property
    def uses_loop(self) -> bool:
        return self.op.body or any(a.uses_loop for a in self.args)

    def evaluate(self, env):
        """Run against an environment mapping names to values."""
        if self.op.body:
            inner, rest = self.args[0], self.args[1:]
            values = []
            for arg in rest:
                got = arg.evaluate(env)
                if got is _REJECT:
                    return _REJECT
                values.append(got)
            try:
                out = self.op.fn(env, inner, *values)
            except Exception:
                return _REJECT
            return _bounded(out)
        values = []
        for arg in self.args:
            got = arg.evaluate(env)
            if got is _REJECT:
                return _REJECT
            values.append(got)
        try:
            return _bounded(self.op.fn(env, *values))
        except Exception:
            return _REJECT

    def render(self, var: str = "value") -> str:
        if self.op.arity == 0:
            return self.op.template.format(var)
        parts = [a.render(var) for a in self.args]
        return self.op.template.format(*parts)


def _bounded(out):
    """Discard candidates that are building something absurd."""
    if out is _REJECT:
        return _REJECT
    if isinstance(out, (str, list, tuple)) and len(out) > _LIMIT:
        return _REJECT
    if isinstance(out, int) and not isinstance(out, bool) and abs(out) > _HUGE:
        return _REJECT
    return out


# --------------------------------------------------------------------------- #
# Leaves and first-order operators.
# --------------------------------------------------------------------------- #

def _leaf(name, fn, template):
    return Op(name, 0, lambda env: fn(env), template)


def _var(name, template=None):
    return Op(name, 0, lambda env, _n=name: env[_n], template or "{0}")


def _const(value):
    return Op("const%s" % value, 0, lambda env, _v=value: _v, repr(value))


def _un(name, fn, template):
    return Op(name, 1, lambda env, a: fn(a), template)


def _bin(name, fn, template):
    return Op(name, 2, lambda env, a, b: fn(a, b), template)


def _nonzero(fn):
    def guarded(a, b):
        if b == 0:
            raise ZeroDivisionError
        return fn(a, b)
    return guarded


VALUE = _var("value")
ITEM = Op("item", 0, lambda env: env["item"], "item")
ACC = Op("acc", 0, lambda env: env["acc"], "acc")

_NUMBERS = tuple(_const(n) for n in (0, 1, 2, 3, 10, -1))

INT_OPS: tuple[Op, ...] = (VALUE,) + _NUMBERS + (
    _bin("add", lambda a, b: a + b, "({0} + {1})"),
    _bin("sub", lambda a, b: a - b, "({0} - {1})"),
    _bin("mul", lambda a, b: a * b, "({0} * {1})"),
    _bin("floordiv", _nonzero(lambda a, b: a // b), "({0} // {1})"),
    _bin("mod", _nonzero(lambda a, b: a % b), "({0} % {1})"),
    _bin("pow", lambda a, b: a ** b if 0 <= b <= 8 else _bad(), "({0} ** {1})"),
    _bin("max", max, "max({0}, {1})"),
    _bin("min", min, "min({0}, {1})"),
    _un("neg", lambda a: -a, "(-{0})"),
    _un("abs", abs, "abs({0})"),
    _un("square", lambda a: a * a, "({0} * {0})"),
    _un("double", lambda a: a * 2, "({0} * 2)"),
    _un("half", lambda a: a // 2, "({0} // 2)"),
    _un("incr", lambda a: a + 1, "({0} + 1)"),
    _un("decr", lambda a: a - 1, "({0} - 1)"),
    _un("sign", lambda a: (a > 0) - (a < 0), "((({0}) > 0) - (({0}) < 0))"),
    _un("bit_not", lambda a: ~a, "(~{0})"),
    _bin("bit_and", lambda a, b: a & b, "({0} & {1})"),
    _bin("bit_or", lambda a, b: a | b, "({0} | {1})"),
    _bin("bit_xor", lambda a, b: a ^ b, "({0} ^ {1})"),
    _bin("shl", lambda a, b: a << b if 0 <= b <= 32 else _bad(), "({0} << {1})"),
    _bin("shr", lambda a, b: a >> b if 0 <= b <= 32 else _bad(), "({0} >> {1})"),
)

STR_OPS: tuple[Op, ...] = (VALUE,) + (
    _un("upper", lambda a: a.upper(), "{0}.upper()"),
    _un("lower", lambda a: a.lower(), "{0}.lower()"),
    _un("title", lambda a: a.title(), "{0}.title()"),
    _un("swapcase", lambda a: a.swapcase(), "{0}.swapcase()"),
    _un("capitalize", lambda a: a.capitalize(), "{0}.capitalize()"),
    _un("strip", lambda a: a.strip(), "{0}.strip()"),
    _un("lstrip", lambda a: a.lstrip(), "{0}.lstrip()"),
    _un("rstrip", lambda a: a.rstrip(), "{0}.rstrip()"),
    _un("reverse", lambda a: a[::-1], "{0}[::-1]"),
    _un("first", lambda a: a[0], "{0}[0]"),
    _un("last", lambda a: a[-1], "{0}[-1]"),
    _un("rest", lambda a: a[1:], "{0}[1:]"),
    _un("init", lambda a: a[:-1], "{0}[:-1]"),
    _un("length", len, "len({0})"),
    _un("split", lambda a: a.split(), "{0}.split()"),
    _un("words", lambda a: len(a.split()), "len({0}.split())"),
    _un("to_int", int, "int({0})"),
    _un("to_str", str, "str({0})"),
    _bin("concat", lambda a, b: a + b, "({0} + {1})"),
    _bin("repeat", lambda a, b: a * b if 0 <= b <= 64 else _bad(), "({0} * {1})"),
    _bin("join_on", lambda a, b: a.join(b), "{0}.join({1})"),
    _bin("take", lambda a, b: a[:b], "{0}[:{1}]"),
    _bin("drop", lambda a, b: a[b:], "{0}[{1}:]"),
    _bin("at", lambda a, b: a[b], "{0}[{1}]"),
    _const(""), _const(" "), _const("-"), _const(1), _const(2),
)

LIST_OPS: tuple[Op, ...] = (VALUE,) + (
    _un("sorted", lambda a: sorted(a), "sorted({0})"),
    _un("reverse", lambda a: a[::-1], "{0}[::-1]"),
    _un("total", sum, "sum({0})"),
    _un("length", len, "len({0})"),
    _un("largest", max, "max({0})"),
    _un("smallest", min, "min({0})"),
    _un("first", lambda a: a[0], "{0}[0]"),
    _un("last", lambda a: a[-1], "{0}[-1]"),
    _un("rest", lambda a: a[1:], "{0}[1:]"),
    _un("init", lambda a: a[:-1], "{0}[:-1]"),
    _un("unique", lambda a: sorted(set(a)), "sorted(set({0}))"),
    _un("flatten", lambda a: [x for row in a for x in row],
        "[x for row in {0} for x in row]"),
    _un("mean", lambda a: sum(a) // len(a) if a else _bad(),
        "(sum({0}) // len({0}))"),
    _bin("take", lambda a, b: a[:b], "{0}[:{1}]"),
    _bin("drop", lambda a, b: a[b:], "{0}[{1}:]"),
    _bin("at", lambda a, b: a[b], "{0}[{1}]"),
    _bin("concat", lambda a, b: a + b, "({0} + {1})"),
    _bin("count_of", lambda a, b: a.count(b), "{0}.count({1})"),
    _const(0), _const(1), _const(2),
)

#: Predicates over `item`, used as the condition of filter/count/take_while.
PRED_OPS: tuple[Op, ...] = (ITEM, ACC) + _NUMBERS + (
    _bin("gt", lambda a, b: a > b, "({0} > {1})"),
    _bin("ge", lambda a, b: a >= b, "({0} >= {1})"),
    _bin("lt", lambda a, b: a < b, "({0} < {1})"),
    _bin("le", lambda a, b: a <= b, "({0} <= {1})"),
    _bin("eq", lambda a, b: a == b, "({0} == {1})"),
    _bin("ne", lambda a, b: a != b, "({0} != {1})"),
    _bin("mod", _nonzero(lambda a, b: a % b), "({0} % {1})"),
    _un("not_", lambda a: not a, "(not {0})"),
    _un("is_even", lambda a: a % 2 == 0, "({0} % 2 == 0)"),
    _un("is_odd", lambda a: a % 2 == 1, "({0} % 2 == 1)"),
    _un("is_positive", lambda a: a > 0, "({0} > 0)"),
    _un("is_negative", lambda a: a < 0, "({0} < 0)"),
    _un("is_zero", lambda a: a == 0, "({0} == 0)"),
)

#: Bodies of a loop: expressions over `item` and `acc`.
BODY_OPS: tuple[Op, ...] = (ITEM, ACC) + _NUMBERS + (
    _bin("add", lambda a, b: a + b, "({0} + {1})"),
    _bin("sub", lambda a, b: a - b, "({0} - {1})"),
    _bin("mul", lambda a, b: a * b, "({0} * {1})"),
    _bin("max", max, "max({0}, {1})"),
    _bin("min", min, "min({0}, {1})"),
    _bin("mod", _nonzero(lambda a, b: a % b), "({0} % {1})"),
    _un("square", lambda a: a * a, "({0} * {0})"),
    _un("double", lambda a: a * 2, "({0} * 2)"),
    _un("incr", lambda a: a + 1, "({0} + 1)"),
    _un("abs", abs, "abs({0})"),
    _un("neg", lambda a: -a, "(-{0})"),
    _un("to_str", str, "str({0})"),
    _un("upper", lambda a: a.upper(), "{0}.upper()"),
    _un("length", len, "len({0})"),
)


def _bad():
    raise ValueError("out of range")


# --------------------------------------------------------------------------- #
# Loops. Each is a bounded, terminating traversal of one sequence.
# --------------------------------------------------------------------------- #

def _run_map(env, body, seq):
    return [_require(body.evaluate({**env, "item": x})) for x in seq]


def _run_filter(env, body, seq):
    return [x for x in seq if _require(body.evaluate({**env, "item": x}))]


def _run_count(env, body, seq):
    return sum(1 for x in seq if _require(body.evaluate({**env, "item": x})))


def _run_take_while(env, body, seq):
    out = []
    for x in seq:
        if not _require(body.evaluate({**env, "item": x})):
            break
        out.append(x)
    return out


def _run_fold(env, body, seq, start):
    """Structural recursion: one element per step, and it stops."""
    acc = start
    for x in seq:
        acc = _require(body.evaluate({**env, "item": x, "acc": acc}))
        acc = _bounded(acc)
        if acc is _REJECT:
            raise ValueError("fold ran away")
    return acc


def _require(value):
    if value is _REJECT:
        raise ValueError("inner program failed")
    return value


LOOP_OPS: tuple[Op, ...] = (
    Op("map", 2, _run_map, "[{0} for item in {1}]", body=True, binds=("item",)),
    Op("filter", 2, _run_filter, "[item for item in {1} if {0}]",
       body=True, binds=("item",)),
    Op("count", 2, _run_count, "sum(1 for item in {1} if {0})",
       body=True, binds=("item",)),
    Op("take_while", 2, _run_take_while,
       "list(itertools.takewhile(lambda item: {0}, {1}))",
       body=True, binds=("item",)),
    Op("fold", 3, _run_fold, "functools.reduce(lambda acc, item: {0}, {1}, {2})",
       body=True, binds=("item", "acc")),
)

ALL_OPS: tuple[Op, ...] = tuple(
    dict.fromkeys(INT_OPS + STR_OPS + LIST_OPS + PRED_OPS + BODY_OPS + LOOP_OPS))


def operator_count() -> dict[str, int]:
    """How many distinct operators each grammar offers."""
    return {
        "int": len(INT_OPS), "str": len(STR_OPS), "list": len(LIST_OPS),
        "predicate": len(PRED_OPS), "body": len(BODY_OPS), "loop": len(LOOP_OPS),
        "total_distinct": len(ALL_OPS),
    }


# --------------------------------------------------------------------------- #
# The search.
# --------------------------------------------------------------------------- #

def _key(value):
    """A hashable stand-in, so signatures can go in a set.

    Both the candidate's output *and* the expected output have to go through
    this. They did not at first: `wanted` kept raw lists while signatures
    held their `repr`, so a program returning exactly the right list never
    compared equal to the target and every list-valued task reported "not
    found" while quietly computing the right answer.
    """
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def _signature(program, envs):
    out = []
    for env in envs:
        got = program.evaluate(env)
        if got is _REJECT:
            return None
        out.append(_key(got))
    return tuple(out)


def _enumerate_bodies(ops, max_size, probes):
    """A pool of small programs over the loop's bound names.

    Enumerated once and reused by every higher-order operator, because the
    pool is the expensive part: it multiplies into the outer search at every
    level, which is why MAX_BODY_SIZE is small and deliberately so.
    """
    pool: dict[int, list[Program]] = {}
    seen: set = set()
    leaves = [op for op in ops if op.arity == 0]
    for op in leaves:
        candidate = Program(op)
        signature = _signature(candidate, probes)
        if signature is not None and signature not in seen:
            seen.add(signature)
            pool.setdefault(1, []).append(candidate)
    for size in range(2, max_size + 1):
        for op in ops:
            if op.arity == 0 or op.body:
                continue
            for split in _partitions(size - 1, op.arity):
                pools = [pool.get(part, ()) for part in split]
                if not all(pools):
                    continue
                for combo in itertools.product(*pools):
                    candidate = Program(op, tuple(combo))
                    signature = _signature(candidate, probes)
                    if signature is None or signature in seen:
                        continue
                    seen.add(signature)
                    pool.setdefault(size, []).append(candidate)
    return [p for size in sorted(pool) for p in pool[size]]


class _BudgetExceeded(Exception):
    """The search visited more programs than the caller allowed."""


def synthesize(examples, ops=INT_OPS, max_size: int = MAX_SIZE,
               loops: bool = False, body_ops=BODY_OPS, pred_ops=PRED_OPS,
               max_body_size: int = MAX_BODY_SIZE, node_budget: int = 0):
    """Find the smallest program in `ops` reproducing every example.

    `node_budget` caps how many distinct programs the search may weigh before
    giving up (0 = unlimited). A large operator set combined with loops and
    depth explodes combinatorially; without a cap a hopeless search runs for a
    minute before admitting defeat, and with one it fails in a fixed fraction
    of a second. That is what lets `auto` try a ladder of cheap tiers rather
    than betting everything on the most expensive search.

    `loops=True` adds map/filter/count/take_while/fold, whose bodies are
    drawn from a pool synthesized over `body_ops` and `pred_ops`. Returns
    None when the bounded space does not contain a solution -- a real
    answer, not a failure to try harder.
    """
    examples = list(examples)
    if not examples:
        raise ValueError("synthesis needs at least one example")
    envs = [{"value": value} for value, _ in examples]
    wanted = tuple(_key(expected) for _, expected in examples)

    grammar = list(ops)
    body_pool: list[Program] = []
    pred_pool: list[Program] = []
    if loops:
        # The pool dedupes by behaviour on these, so a thin probe set merges
        # operators that are genuinely different. With only {3, -1, 0},
        # `not item` and `item % 2 == 0` agree everywhere, so `is_even` was
        # dropped as a duplicate and every "sum the even ones" task came
        # back not-found. Even and odd, positive and negative, zero and one
        # all have to be represented or the search loses operators it was
        # given.
        probes = [{"item": item, "acc": acc} for item, acc in (
            (3, 2), (-1, 5), (0, 0), (2, 1), (4, -3),
            (7, 0), (1, 10), (-2, 2), (10, 1), (5, -1))]
        body_pool = _enumerate_bodies(body_ops, max_body_size, probes)
        pred_pool = _enumerate_bodies(pred_ops, max_body_size, probes)
        grammar += list(LOOP_OPS)

    by_size: dict[int, list[Program]] = {}
    seen: dict[tuple, Program] = {}

    def offer(program):
        signature = _signature(program, envs)
        if signature is None or signature in seen:
            return None
        if node_budget and len(seen) >= node_budget:
            raise _BudgetExceeded()
        seen[signature] = program
        by_size.setdefault(program.size, []).append(program)
        return signature

    try:
        return _search(examples, wanted, grammar, max_size, body_pool,
                       pred_pool, by_size, offer)
    except _BudgetExceeded:
        return None


def _search(examples, wanted, grammar, max_size, body_pool, pred_pool,
            by_size, offer):
    for op in grammar:
        if op.arity != 0:
            continue
        if op.name in {"item", "acc"}:
            continue        # bound names are only meaningful inside a loop
        candidate = Program(op)
        if offer(candidate) == wanted:
            return candidate

    for size in range(2, max_size + 1):
        for op in grammar:
            if op.arity == 0:
                continue
            if op.body:
                pool = pred_pool if op.name in {"filter", "count",
                                                "take_while"} else body_pool
                for body in pool:
                    remaining = size - 1 - body.size
                    if remaining < op.arity - 1:
                        continue
                    for split in _partitions(remaining, op.arity - 1):
                        pools = [by_size.get(part, ()) for part in split]
                        if not all(pools):
                            continue
                        for combo in itertools.product(*pools):
                            candidate = Program(op, (body,) + tuple(combo))
                            if offer(candidate) == wanted:
                                return candidate
                continue
            for split in _partitions(size - 1, op.arity):
                pools = [by_size.get(part, ()) for part in split]
                if not all(pools):
                    continue
                for combo in itertools.product(*pools):
                    candidate = Program(op, tuple(combo))
                    if offer(candidate) == wanted:
                        return candidate
    return None


def _partitions(total: int, parts: int):
    if parts <= 0:
        if total == 0:
            yield ()
        return
    if parts == 1:
        if total >= 1:
            yield (total,)
        return
    for first in range(1, total - parts + 2):
        for rest in _partitions(total - first, parts - 1):
            yield (first,) + rest


def render(program, name: str = "transform", var: str = "value") -> str:
    """The winning program as a Python function, imports included."""
    body = program.render(var)
    header = []
    if "functools." in body:
        header.append("import functools")
    if "itertools." in body:
        header.append("import itertools")
    prefix = ("\n".join(header) + "\n\n\n") if header else ""
    return "%sdef %s(%s):\n    return %s\n" % (prefix, name, var, body)


# The escalation ladder, cheapest first: (loops, max_size, node_budget).
#
# A flat search at depth four is nearly free and answers most arithmetic and
# list questions, so it goes first. Loops are added only when flat search has
# already failed, and depth and budget grow together so the expensive tiers are
# reached only for problems the cheap ones could not touch. Every budget is
# finite, so the whole ladder terminates: a genuinely out-of-reach spec returns
# None in about a second rather than hanging on the last tier.
_AUTO_TIERS = (
    (False, 4, 0),
    (False, 6, 60_000),
    (True, 4, 40_000),
    (True, 5, 150_000),
    (True, 6, 400_000),
)


def auto(examples, ops=INT_OPS, tiers=_AUTO_TIERS):
    """Synthesize without the caller having to tune loops or depth.

    Returns `(program, tier)` where `tier` is the ladder rung that solved it,
    or `(None, None)` when no rung did. The point is that the working power of
    the synthesizer -- map, filter, fold, and their compositions -- is reached
    by a plain call, instead of only by a caller who already knows to pass
    `loops=True, max_size=5`. Small problems still return in milliseconds
    because they are solved on the first, cheapest rung.
    """
    examples = list(examples)
    for loops, max_size, budget in tiers:
        program = synthesize(examples, ops=ops, max_size=max_size,
                             loops=loops, node_budget=budget)
        if program is not None:
            return program, {"loops": loops, "max_size": max_size}
    return None, None


def write_auto(examples, ops=INT_OPS, name: str = "transform", tiers=_AUTO_TIERS):
    """`auto`, then render and put the result through Attestor before returning.

    Returns `(source, tier)` or `(None, None)`. The generated function is
    scanned by Attestor's own rules before it is handed back, so a synthesized
    program that somehow tripped a finding would be withheld rather than
    shipped -- the writer is held to the same bar as any other code.
    """
    program, tier = auto(examples, ops=ops, tiers=tiers)
    if program is None:
        return None, None
    source = render(program, name=name)
    result = attestor_write.write({"%s.py" % name: source})
    if not result.clean:
        return None, None
    return result.files["%s.py" % name], tier


def write_function(examples, ops=INT_OPS, name: str = "transform",
                   max_size: int = MAX_SIZE, loops: bool = False,
                   max_body_size: int = MAX_BODY_SIZE):
    """Synthesize, render, and put the result through Attestor before returning."""
    program = synthesize(examples, ops=ops, max_size=max_size, loops=loops,
                         max_body_size=max_body_size)
    if program is None:
        return None, None
    source = render(program, name=name)
    result = attestor_write.write({"%s.py" % name: source})
    if not result.clean:
        return program, None
    return program, result.files["%s.py" % name]


def main(argv=None) -> int:      # pragma: no cover - demonstration entry
    counts = operator_count()
    print("grammar: %s" % ", ".join("%s=%d" % kv for kv in counts.items()))
    demos = [
        ("sum of even numbers",
         [([1, 2, 3, 4], 6), ([2, 2], 4), ([1, 3], 0), ([10, 5, 4], 14)],
         LIST_OPS, 4, True),
        ("count positives",
         [([1, -2, 3], 2), ([-1, -1], 0), ([5], 1)], LIST_OPS, 3, True),
        ("squares",
         [([1, 2, 3], [1, 4, 9]), ([4], [16])], LIST_OPS, 3, True),
    ]
    for label, examples, ops, size, loops in demos:
        program = synthesize(examples, ops=ops, max_size=size, loops=loops)
        found = render(program).strip().splitlines()[-1].strip() if program else "not found"
        print("  %-22s %s" % (label, found))
    return 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
