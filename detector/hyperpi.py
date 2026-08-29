#!/usr/bin/env python3
"""
hyperpi.py -- Attestor answers the 6am incantation, honestly.

The brief: "demonstrate circumferential properties of pi tetrated to 7 and
pentated to 5 ... 12*3 turgidity ... c^5 ... dinosaurs return with the IQ of
Stephen Dihhkawking."

Most of that is beautiful nonsense and Attestor will say so. But two pieces are real
mathematics, and they're the hard part: pi TETRATED to 7 and PENTATED to 5 are
so large that no float, no bignum, no amount of RAM can hold them. The only way
to "demonstrate" them is to stop trying to store the number and instead reason
about its *tower* -- its super-logarithm. That's what this does.

    tetration   a↑↑b  = a^a^...^a          (b copies)      -- a power tower
    pentation   a↑↑↑b = a↑↑(a↑↑(...a))     (b copies)      -- a tower of towers

Pure standard library. No API key. No dinosaurs.

    python3 hyperpi.py
"""
from __future__ import annotations

import math

PI = math.pi
LOG10_PI = math.log10(PI)
FLOAT_LOG10_MAX = 308.0          # ~ the largest exponent a float64 can hold


# --------------------------------------------------------------------------- #
# integer hyperoperations -- the WELL-DEFINED cases (these actually compute)
# --------------------------------------------------------------------------- #
def hyperop(n: int, a: int, b: int, _guard: int = 10 ** 6) -> int:
    """
    The nth hyperoperation on non-negative integers:
        n=1 add, n=2 multiply, n=3 power, n=4 tetration, n=5 pentation.
    Only sane for tiny inputs -- anything past a toy example is astronomically
    large, so we cap the magnitude and refuse rather than eat all your memory.
    """
    if n == 1:
        return a + b
    if n == 2:
        return a * b
    if n == 3:
        result = a ** b
        if result > _guard:
            raise OverflowError(f"{a}^{b} = {result} exceeds the demo guard")
        return result
    if b == 0:
        return 1
    # n >= 4: fold the (n-1)th operation b times
    acc = a
    for _ in range(b - 1):
        acc = hyperop(n - 1, a, acc, _guard)
    return acc


# --------------------------------------------------------------------------- #
# pi tetrated to 7 -- too big to store, so describe the TOWER
# --------------------------------------------------------------------------- #
def tetration_profile(base: float, height: int):
    """
    Walk a power tower base^base^...^base (given height) from the bottom up,
    keeping each level as a real float for as long as it fits. When the next
    level would overflow, switch to tracking log10 (the digit count). Returns:

        exact   : the tower levels we could hold exactly, e.g. [pi, 36.46, 1.35e18]
        log10   : log10 of the first level that overflowed (its digit count),
                  or None if the whole tower fit
        blew_at : the 1-based level where it overflowed (None if it never did)
        superlog: the super-logarithm base `base` -- for an exact tower this is
                  simply the height. It is the one clean, finite invariant.
    """
    exact = [base]
    log10_of_next = None
    blew_at = None
    for level in range(2, height + 1):
        prev = exact[-1]
        # log10(base^prev) = prev * log10(base)
        next_log10 = prev * math.log10(base)
        if next_log10 < FLOAT_LOG10_MAX:
            exact.append(base ** prev)
        else:
            log10_of_next = next_log10
            blew_at = level
            break
    return {
        "exact": exact,
        "log10": log10_of_next,
        "blew_at": blew_at,
        "superlog": height,
    }


# --------------------------------------------------------------------------- #
# the "circumferential property" -- honest scale reasoning
# --------------------------------------------------------------------------- #
def circumference_note(base: float, height: int) -> str:
    """
    C = 2*pi*r. For a circle of radius r = pi↑↑height, the circumference is
    2*pi larger than the radius. Against a power tower of that size, a factor of
    2*pi vanishes without a trace: it changes the number's digit count by
    log10(2*pi) ~ 0.80 -- utterly lost in a digit count of ~6.7e17.
    """
    factor_digits = math.log10(2 * base)
    return (f"C = 2*pi*r. Multiplying a height-{height} tower by 2*pi adds only "
            f"~{factor_digits:.2f} to its digit count -- so the 'circumference' of "
            f"a circle with radius pi↑↑{height} is, to any resolution a human or "
            f"machine can express, the exact same unfathomable tower.")


# --------------------------------------------------------------------------- #
# the joke physics -- evaluated deterministically, units disclaimed
# --------------------------------------------------------------------------- #
def turgid_physics():
    """Chain the literal operations the incantation asked for. The unit algebra
    is meaningless; the arithmetic is real and reproducible."""
    turgidity = 12 * 3                                   # the decreed 12*3 = 36
    c = 299_792_458.0                                    # speed of light, m/s
    c5 = c ** 5                                           # "c to the power of 5"
    G = 6.674e-11
    M_earth = 5.972e24                                   # kg
    R_earth = 6.371e6                                     # m
    area = 4 * math.pi * R_earth ** 2                     # "the earth's ... area"
    # "gravitational potential energy of the earth's square area,
    #  square rooted, and multiplied by 4"
    U = 3 * G * M_earth ** 2 / (5 * R_earth)              # self-gravitation energy, J
    gpe_of_square_area = U * area ** 2
    concoction = math.sqrt(gpe_of_square_area) * 4
    return {
        "turgidity": turgidity,
        "c^5": c5,
        "c^5 gate open?": c5 > 0,                         # the "if c^5 then" branch
        "earth surface area (m^2)": area,
        "earth self-gravity U (J)": U,
        "sqrt(U * area^2) * 4": concoction,
    }


# --------------------------------------------------------------------------- #
# the dinosaur clause
# --------------------------------------------------------------------------- #
def dinosaurs_return() -> bool:
    """The clause is gated on a physically impossible antecedent. It is False."""
    return False


def _fmt(x: float) -> str:
    return f"{x:.6g}"


def main() -> int:
    print("AttestorVonLuneberg parses the 6am incantation")
    print("=" * 66)
    print("half of this is word salad. i'll do the two bits that are real maths,")
    print("and i'll be honest about the rest. sit down.\n")

    # --- pi tetrated to 7 ---
    prof = tetration_profile(PI, 7)
    print("pi TETRATED to 7   ->  pi↑↑7 = pi^pi^pi^pi^pi^pi^pi  (a tower of 7 pis)")
    holds = prof["exact"]
    print(f"   level 1 (pi)          = {_fmt(holds[0])}")
    print(f"   level 2 (pi^pi)       = {_fmt(holds[1])}")
    print(f"   level 3 (pi^pi^pi)    = {_fmt(holds[2])}   (~1.3 quintillion)")
    print(f"   level 4               = a number with ~{_fmt(prof['log10'])} digits"
          f"   <- overflows every float here")
    print("   levels 5, 6, 7        = towers stacked on THAT. no float, no bignum,")
    print("                           no computer that will ever exist can store it.")
    print(f"   the one finite truth  : super-log base pi (pi↑↑7) = {prof['superlog']}"
          "  (its height, exactly).")
    print("   " + circumference_note(PI, 7))
    print()

    # --- pi pentated to 5 ---
    print("pi PENTATED to 5   ->  pi↑↑↑5 = pi↑↑(pi↑↑(pi↑↑(pi↑↑pi)))")
    print("   this one is worse than 'too big': it isn't even well-DEFINED.")
    print("   pentation needs tetration at the heights pi, then pi↑↑pi, then ...")
    print("   -- i.e. tetration to NON-INTEGER, then astronomical, heights. Plain")
    print("   tetration is only defined for whole-number heights, so pi↑↑↑5 has no")
    print("   elementary value at all without first inventing an extension of")
    print("   tetration to the reals. it's not a big number; it's an open question.")
    print("   what IS well-defined is integer pentation. proof the code computes it:")
    for a, b in ((2, 2), (2, 3), (3, 2)):
        try:
            val = hyperop(5, a, b)
            print(f"      {a}↑↑↑{b} = {val}")
        except OverflowError:
            print(f"      {a}↑↑↑{b} = (astronomically large; past the demo guard)")
    print(f"      2↑↑↑4  = (undecidably huge: it's 2↑↑65536 -- a tower 65,536 tall)")
    print()

    # --- the pseudo-physics ---
    print("the '12*3 turgidity / c^5 / earth' physics (arithmetic real, units void):")
    for k, v in turgid_physics().items():
        val = v if isinstance(v, bool) else _fmt(v)
        print(f"   {k:<28} = {val}")
    print()

    # --- the verdict ---
    back = dinosaurs_return()
    print(f"dinosaurs return?     {back}  (the antecedent is impossible; the clause")
    print("                      never fires. they remain extinct. i'm sorry.)")
    print('IQ of "Stephen Dihhkawking": undefined -- not a real person, and IQ is a')
    print("                      poor metric anyway. Hawking himself declined to quote his.")
    print()
    print("verdict: two real, correctly-handled transfinite computations; one honest")
    print("'not even defined'; a pile of arithmetic; and zero resurrected reptiles.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
