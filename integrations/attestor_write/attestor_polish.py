"""Make what Attestor writes read like something a person would keep.

The synthesizer emits correct code that nobody would enjoy inheriting:
every parameter is called `value`, every loop variable is `item`, there are
no type hints, `sum([...])` builds a throwaway list, and `(value * value)`
is spelled the long way round. All of it correct, none of it sharp.

Every rewrite here is *semantics-preserving by construction and by test*.
The pass is only ever applied by `polish`, which re-runs the original
examples through the rewritten source and throws the rewrite away if a
single one disagrees. A prettifier that changes behaviour is a bug factory,
so the check is not optional and not sampled.
"""

from __future__ import annotations

import re

__all__ = ["polish", "name_for", "hint_for", "REWRITES"]


def _kind(sample):
    if isinstance(sample, bool):
        return "flag"
    if isinstance(sample, int):
        return "number"
    if isinstance(sample, str):
        return "text"
    if isinstance(sample, (list, tuple)):
        inner = sample[0] if sample else None
        if isinstance(inner, str):
            return "words"
        return "numbers"
    return "value"


def name_for(examples) -> str:
    """A parameter name taken from what the examples actually contain."""
    return _kind(examples[0][0])


def hint_for(examples) -> tuple[str, str]:
    """(parameter hint, return hint), or empty strings when unclear."""
    def annotate(sample):
        if isinstance(sample, bool):
            return "bool"
        if isinstance(sample, int):
            return "int"
        if isinstance(sample, str):
            return "str"
        if isinstance(sample, (list, tuple)):
            inner = sample[0] if sample else None
            if isinstance(inner, int) and not isinstance(inner, bool):
                return "list[int]"
            if isinstance(inner, str):
                return "list[str]"
            return "list"
        return ""
    given = {annotate(value) for value, _ in examples}
    wanted = {annotate(expected) for _, expected in examples}
    return (given.pop() if len(given) == 1 else "",
            wanted.pop() if len(wanted) == 1 else "")


#: (pattern, replacement, why). Applied to the expression text only.
REWRITES: tuple = (
    (re.compile(r"sum\(\[(.+?) for (\w+) in (.+?)\]\)"),
     r"sum(\1 for \2 in \3)",
     "a list built only to be summed is a generator"),
    (re.compile(r"\((\w+) \* \1\)"), r"\1 ** 2", "x * x is x squared"),
    # A comparison is already the whole condition. The parentheses the
    # renderer adds so an expression stays safe inside a bigger one are just
    # noise once it stands alone after `if`.
    (re.compile(r"if \(([^()]+?)\)\)"), r"if \1)",
     "a bare condition needs no parentheses"),
    (re.compile(r"if \(([^()]+?)\)\]"), r"if \1]",
     "the same, at the end of a comprehension"),
)


def _rename(text: str, mapping: dict) -> str:
    for old, new in mapping.items():
        text = re.sub(r"\b%s\b" % re.escape(old), new, text)
    return text


def _strip_outer_parens(expression: str) -> str:
    """`(a + b)` as a whole return value does not need its parentheses."""
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        for index, char in enumerate(expression):
            depth += (char == "(") - (char == ")")
            if depth == 0 and index != len(expression) - 1:
                return expression
        expression = expression[1:-1].strip()
    return expression


def polish(source: str, examples, name: str = "transform",
           summary: str | None = None):
    """Rewrite for readability, then prove the meaning did not move.

    Returns the sharpened source, or the original when any rewrite would
    have changed an answer. Never raises on a bad rewrite -- it declines.
    """
    original = source
    head, _, tail = source.partition("def %s(" % name)
    if not tail:
        return original
    signature, _, body = tail.partition("\n")
    old_param = signature.split(")")[0].strip()
    expression = body.strip()
    if not expression.startswith("return "):
        return original
    expression = expression[len("return "):].strip()

    param = name_for(examples)
    loop_name = {"numbers": "number", "words": "word",
                 "text": "letter"}.get(param, "item")
    expression = _rename(expression, {old_param: param, "item": loop_name})
    for pattern, replacement, _why in REWRITES:
        expression = pattern.sub(replacement, expression)
    expression = _strip_outer_parens(expression)

    param_hint, return_hint = hint_for(examples)
    declared = "%s: %s" % (param, param_hint) if param_hint else param
    arrow = " -> %s" % return_hint if return_hint else ""
    doc = summary or "Derived from %d example(s)." % len(examples)
    sharpened = "%sdef %s(%s)%s:\n    \"\"\"%s\"\"\"\n    return %s\n" % (
        head, name, declared, arrow, doc, expression)

    if not _agrees(sharpened, original, examples, name):
        return original
    return sharpened


def _agrees(candidate: str, original: str, examples, name: str) -> bool:
    """Run both and require identical answers on every example."""
    try:
        new_ns: dict = {}
        old_ns: dict = {}
        exec(compile(candidate, "polished.py", "exec"), new_ns)  # noqa: S102
        exec(compile(original, "original.py", "exec"), old_ns)   # noqa: S102
    except Exception:
        return False
    for value, expected in examples:
        try:
            got_new = new_ns[name](value)
            got_old = old_ns[name](value)
        except Exception:
            return False
        if got_new != got_old or got_new != expected:
            return False
    return True
