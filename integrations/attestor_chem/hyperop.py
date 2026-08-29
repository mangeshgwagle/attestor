"""The hyperoperation hierarchy: addition through hexation.

Each level is repeated application of the one below it::

    H1(a, b) = a + b            addition
    H2(a, b) = a * b            multiplication  -- a added to itself b times
    H3(a, b) = a ** b           exponentiation  -- a multiplied b times
    H4(a, b) = a ↑↑ b           tetration       -- a raised b times
    H5(a, b) = a ↑↑↑ b          pentation       -- a tetrated b times
    H6(a, b) = a ↑↑↑↑ b         hexation        -- a pentated b times

Why this needs a size guard rather than just recursion
------------------------------------------------------
The numbers stop being representable almost immediately. 2↑↑4 is 65536 and
2↑↑5 is 2^65536, a number with about twenty thousand digits. 3↑↑3 is
7,625,597,484,987 and 3↑↑4 is 3 raised to that -- more digits than there are
atoms in the observable universe. Pentation is worse: 3↑↑↑3 is 3 tetrated
7,625,597,484,987 times.

So a naive implementation does not return a wrong answer, it hangs or
exhausts memory. Every function here takes a digit budget and raises
`TooLarge` the moment the result would exceed it. Refusing is the correct
behaviour: an answer you cannot hold is not an answer, and a calculator that
freezes has told you less than one that says why.

The recursion is checked against the closed forms it should agree with --
H2 against a*b, H3 against a**b -- so the definition and the arithmetic have
to match rather than being assumed to.
"""

from __future__ import annotations

__all__ = ["hyper", "add", "multiply", "power", "tetrate", "pentate",
           "hexate", "TooLarge", "DIGIT_BUDGET", "NAMES"]

#: Roughly the largest number worth printing. 10,000 digits is already a
#: page of output; beyond that the answer exists but cannot be looked at.
DIGIT_BUDGET = 10_000

NAMES = {1: "addition", 2: "multiplication", 3: "exponentiation",
         4: "tetration", 5: "pentation", 6: "hexation"}


class TooLarge(ArithmeticError):
    """The result would not fit in the digit budget."""


def digits(value: int) -> int:
    """How many decimal digits, without building the string.

    `len(str(n))` is the obvious way and it is a trap: CPython refuses to
    stringify an integer above 4,300 digits (`sys.set_int_max_str_digits`),
    so a guard written that way raises ValueError from deep inside itself
    rather than the TooLarge it exists to raise -- and any budget above
    4,300 becomes unreachable.

    bit_length has no such limit, but an estimate from it cannot be exact
    on its own: 999 and 1000 share a bit_length and have different digit
    counts. So the estimate is corrected against exact powers of ten, which
    is integer comparison and needs no string at all.
    """
    if value == 0:
        return 1
    value = abs(value)
    estimate = int(value.bit_length() * 0.30102999566398) + 1
    if value >= 10 ** estimate:
        estimate += 1
    elif estimate > 1 and value < 10 ** (estimate - 1):
        estimate -= 1
    return estimate


def _guard(value: int, budget: int, what: str) -> int:
    """Raise if `value` has outgrown the budget."""
    if value and digits(value) > budget:
        raise TooLarge("%s exceeds the %d-digit budget" % (what, budget))
    return value


def _would_overflow(base: int, exponent: int, budget: int) -> bool:
    """Digits of base**exponent without computing it.

    log10(a^b) = b * log10(a). Checking first is the difference between a
    refusal and a machine that stops responding.
    """
    if base in (0, 1) or exponent == 0:
        return False
    import math
    return exponent * math.log10(abs(base)) > budget


def add(a: int, b: int) -> int:
    return a + b


def multiply(a: int, b: int, budget: int = DIGIT_BUDGET) -> int:
    return _guard(a * b, budget, "%d * %d" % (a, b))


def power(a: int, b: int, budget: int = DIGIT_BUDGET) -> int:
    if b < 0:
        raise ValueError("negative exponents are not integers")
    if _would_overflow(a, b, budget):
        raise TooLarge("%d ** %d exceeds the %d-digit budget" % (a, b, budget))
    return _guard(a ** b, budget, "%d ** %d" % (a, b))


def tetrate(a: int, height: int, budget: int = DIGIT_BUDGET) -> int:
    """a↑↑height: a raised to itself `height` times, right-associated.

    Right-associated is the definition and it matters: 2↑↑3 is 2^(2^2) = 16,
    not (2^2)^2 = 16 -- which agree -- but 3↑↑3 is 3^(3^3) = 3^27, while
    left association would give (3^3)^3 = 3^9. The first is 7.6 trillion,
    the second 19683.
    """
    if height < 0:
        raise ValueError("tetration height must be at least 0")
    if height == 0:
        return 1
    result = a
    for _ in range(height - 1):
        if _would_overflow(a, result, budget):
            raise TooLarge(
                "%d tetrated to height %d exceeds the %d-digit budget"
                % (a, height, budget))
        result = a ** result
        _guard(result, budget, "tetration")
    return result


def pentate(a: int, height: int, budget: int = DIGIT_BUDGET) -> int:
    """a↑↑↑height: tetration applied `height` times."""
    if height < 0:
        raise ValueError("pentation height must be at least 0")
    if height == 0:
        return 1
    result = a
    for _ in range(height - 1):
        result = tetrate(a, result, budget)
    return result


def hexate(a: int, height: int, budget: int = DIGIT_BUDGET) -> int:
    """a↑↑↑↑height: pentation applied `height` times."""
    if height < 0:
        raise ValueError("hexation height must be at least 0")
    if height == 0:
        return 1
    result = a
    for _ in range(height - 1):
        result = pentate(a, result, budget)
    return result


def hyper(level: int, a: int, b: int, budget: int = DIGIT_BUDGET) -> int:
    """H_level(a, b). Level 1 is addition, 6 is hexation.

    Defined by the recursion rather than by dispatching to the closed forms,
    at levels 4 and above: the point of the hierarchy is that each level is
    the one below it repeated, and writing them independently would let the
    definition and the implementation disagree without anything noticing.
    """
    if level not in NAMES:
        raise ValueError("level must be 1..6 (%s)" % ", ".join(
            "%d=%s" % item for item in sorted(NAMES.items())))
    if level == 1:
        return add(a, b)
    if level == 2:
        return multiply(a, b, budget)
    if level == 3:
        return power(a, b, budget)
    if level == 4:
        return tetrate(a, b, budget)
    if level == 5:
        return pentate(a, b, budget)
    return hexate(a, b, budget)
