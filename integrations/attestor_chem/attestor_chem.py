"""Attestor does chemistry, and checks it.

Chemistry suits this project better than most subjects, because it has
*invariants*. Atoms are conserved. Charge is conserved. A balanced equation
is not a matter of opinion or of having memorised the answer -- it is a
claim that can be verified by counting, and a wrong one can be caught the
same way Attestor catches a wrong rule.

So nothing here looks anything up and reports it. The balancer solves for
coefficients and then **counts every atom on both sides**, and refuses to
return an equation that does not balance. A chemistry helper that returns a
plausible-looking equation it has not checked is worse than no helper: it is
wrong in exactly the way a student cannot detect.

What it does
------------
    formula("Ca(OH)2")        -> {"Ca": 1, "O": 2, "H": 2}
    molar_mass("H2SO4")       -> 98.08 g/mol
    balance("H2 + O2 -> H2O") -> "2H2 + O2 -> 2H2O"

Balancing is a nullspace problem: build a matrix of element counts with
reactants positive and products negative, find the integer vector it sends
to zero. Exact rational arithmetic throughout, because a floating-point
coefficient is a coefficient you cannot trust to be a whole number.

What it is not
--------------
Not a substitute for understanding the reaction. It will happily balance
something that does not occur -- balancing is arithmetic, and whether two
substances actually react is chemistry. It says so rather than implying
otherwise.
"""

from __future__ import annotations

import re
from fractions import Fraction

__all__ = ["formula", "molar_mass", "balance", "conserves", "plausible",
           "implausible_species", "MASSES", "VALENCIES", "ChemError"]


class ChemError(ValueError):
    """A formula could not be read, or an equation could not be balanced."""


# Standard atomic weights (IUPAC, 4 s.f.). The ICSE/ISC syllabus works to
# 1-2 decimal places, so this is more precision than the schoolwork needs
# and less than a research calculation would want -- stated so nobody
# mistakes it for either.
MASSES = {
    "H": 1.008, "He": 4.003, "Li": 6.941, "Be": 9.012, "B": 10.81,
    "C": 12.011, "N": 14.007, "O": 15.999, "F": 18.998, "Ne": 20.180,
    "Na": 22.990, "Mg": 24.305, "Al": 26.982, "Si": 28.086, "P": 30.974,
    "S": 32.06, "Cl": 35.45, "Ar": 39.948, "K": 39.098, "Ca": 40.078,
    "Sc": 44.956, "Ti": 47.867, "V": 50.942, "Cr": 51.996, "Mn": 54.938,
    "Fe": 55.845, "Co": 58.933, "Ni": 58.693, "Cu": 63.546, "Zn": 65.38,
    "Ga": 69.723, "Ge": 72.630, "As": 74.922, "Se": 78.971, "Br": 79.904,
    "Kr": 83.798, "Rb": 85.468, "Sr": 87.62, "Y": 88.906, "Zr": 91.224,
    "Nb": 92.906, "Mo": 95.95, "Ag": 107.868, "Cd": 112.414, "Sn": 118.710,
    "Sb": 121.760, "I": 126.904, "Xe": 131.293, "Ba": 137.327,
    "Pt": 195.084, "Au": 196.967, "Hg": 200.592, "Pb": 207.2,
    "Bi": 208.980, "U": 238.029,
}

_TOKEN = re.compile(r"([A-Z][a-z]?)(\d*)|(\()|(\)(\d*))|(·|\.)(\d*)")


def formula(text: str) -> dict:
    """Atom counts for a formula, including brackets and hydrates.

    `Ca(OH)2` and `CuSO4·5H2O` both parse. The dot form matters for the
    school syllabus -- hydrated salts are most of the mole-concept
    questions -- and treating it as a full stop would silently halve the
    mass of every one of them.
    """
    if not text or not text.strip():
        raise ChemError("an empty formula has no atoms")
    text = text.strip().replace(" ", "")
    counts: dict = {}
    stack: list = [{}]
    index = 0
    while index < len(text):
        char = text[index]
        if char == "(":
            stack.append({})
            index += 1
        elif char == ")":
            index += 1
            digits = ""
            while index < len(text) and text[index].isdigit():
                digits += text[index]
                index += 1
            multiplier = int(digits) if digits else 1
            if len(stack) == 1:
                raise ChemError("%r closes a bracket that was never opened"
                                % text)
            group = stack.pop()
            for element, number in group.items():
                stack[-1][element] = stack[-1].get(element, 0) + number * multiplier
        elif char in "·.*":
            # A hydrate: everything after the dot is multiplied by its own
            # leading coefficient, so `CuSO4·5H2O` is CuSO4 plus 5 waters.
            index += 1
            digits = ""
            while index < len(text) and text[index].isdigit():
                digits += text[index]
                index += 1
            multiplier = int(digits) if digits else 1
            rest = formula(text[index:])
            for element, number in rest.items():
                stack[-1][element] = stack[-1].get(element, 0) + number * multiplier
            index = len(text)
        elif char.isupper():
            symbol = char
            index += 1
            if index < len(text) and text[index].islower():
                symbol += text[index]
                index += 1
            digits = ""
            while index < len(text) and text[index].isdigit():
                digits += text[index]
                index += 1
            stack[-1][symbol] = stack[-1].get(symbol, 0) + (
                int(digits) if digits else 1)
        else:
            raise ChemError("%r is not something a formula can contain"
                            % text[index])
    if len(stack) != 1:
        raise ChemError("%r has an unclosed bracket" % text)
    counts = stack[0]
    unknown = sorted(set(counts) - set(MASSES))
    if unknown:
        raise ChemError("unknown element(s): %s" % ", ".join(unknown))
    return counts


def molar_mass(text: str) -> float:
    """Grams per mole, from the atom counts."""
    return round(sum(MASSES[element] * number
                     for element, number in formula(text).items()), 3)


def _split(equation: str):
    for arrow in ("->", "→", "=", "-->"):
        if arrow in equation:
            left, right = equation.split(arrow, 1)
            break
    else:
        raise ChemError("an equation needs an arrow: use '->'")
    reactants = [part.strip() for part in left.split("+") if part.strip()]
    products = [part.strip() for part in right.split("+") if part.strip()]
    if not reactants or not products:
        raise ChemError("an equation needs something on both sides")
    return reactants, products


def conserves(coefficients, reactants, products) -> bool:
    """Does every element appear equally on both sides?

    This is the check the whole module exists for, and it is deliberately
    separate from the solver so it can be run against an equation the
    solver did not produce -- including one a person wrote by hand.
    """
    # Sign comes from *position*, not membership. Deciding it with
    # `species in reactants` counts a substance that appears on both sides
    # as a reactant twice -- and water on both sides is extremely ordinary
    # chemistry, so the check would have passed equations that do not
    # balance.
    tally: dict = {}
    everything = list(reactants) + list(products)
    for index, (coefficient, species) in enumerate(
            zip(coefficients, everything)):
        sign = 1 if index < len(reactants) else -1
        for element, number in formula(species).items():
            tally[element] = tally.get(element, 0) + sign * coefficient * number
    return all(total == 0 for total in tally.values())


def balance(equation: str, check_valency: bool = True) -> str:
    """Balance an equation, or refuse.

    Solves the nullspace of the element-count matrix in exact rationals,
    scales to the smallest whole numbers, then *verifies by counting atoms*
    before returning anything. A solver bug therefore surfaces as a refusal
    rather than as a wrong equation, which is the only failure mode a
    student could not catch themselves.
    """
    reactants, products = _split(equation)
    species = reactants + products

    # Arithmetic before chemistry would balance FeCl9 quite happily. The
    # valency check runs first so an impossible compound is reported as
    # itself rather than as a balanced equation nobody can use.
    if check_valency:
        broken = implausible_species(equation)
        if broken:
            raise ChemError(
                "%s contains a compound that cannot exist: %s"
                % (equation, "; ".join("%s -- %s" % pair for pair in broken)))
    if len(species) < 2:
        raise ChemError("nothing to balance")
    elements = sorted({e for s in species for e in formula(s)})

    # Reactants positive, products negative: a balanced equation is a vector
    # this matrix sends to zero.
    matrix = [[Fraction(formula(s).get(element, 0)
                        * (1 if index < len(reactants) else -1))
               for index, s in enumerate(species)]
              for element in elements]

    solution = _nullspace(matrix, len(species))
    if solution is None:
        raise ChemError(
            "%s cannot be balanced: no set of whole-number coefficients "
            "conserves every element. Check the formulae -- this usually "
            "means one of them is wrong rather than that the reaction is "
            "impossible." % equation)

    if any(value <= 0 for value in solution):
        raise ChemError(
            "%s balances only with a non-positive coefficient, which means "
            "a species is on the wrong side of the arrow" % equation)

    if not conserves(solution, reactants, products):
        raise ChemError(
            "internal check failed: the solver returned coefficients that "
            "do not conserve atoms, so nothing is returned")

    def render(names, values):
        parts = []
        for name, value in zip(names, values):
            parts.append(name if value == 1 else "%d%s" % (value, name))
        return " + ".join(parts)

    split = len(reactants)
    return "%s -> %s" % (render(reactants, solution[:split]),
                         render(products, solution[split:]))


def _nullspace(matrix, width):
    """Smallest positive integer vector in the nullspace, or None."""
    rows = [row[:] for row in matrix]
    pivot_of: dict = {}
    row_index = 0
    for column in range(width):
        pivot = None
        for candidate in range(row_index, len(rows)):
            if rows[candidate][column] != 0:
                pivot = candidate
                break
        if pivot is None:
            continue
        rows[row_index], rows[pivot] = rows[pivot], rows[row_index]
        lead = rows[row_index][column]
        rows[row_index] = [value / lead for value in rows[row_index]]
        for other in range(len(rows)):
            if other != row_index and rows[other][column] != 0:
                factor = rows[other][column]
                rows[other] = [a - factor * b
                               for a, b in zip(rows[other], rows[row_index])]
        pivot_of[column] = row_index
        row_index += 1

    free = [c for c in range(width) if c not in pivot_of]
    if len(free) != 1:
        # No free column means only the trivial solution; more than one
        # means the equation is under-determined and picking an answer
        # would be inventing chemistry.
        return None
    free_column = free[0]
    values = [Fraction(0)] * width
    values[free_column] = Fraction(1)
    for column, row in pivot_of.items():
        values[column] = -rows[row][free_column]

    denominators = [value.denominator for value in values]
    multiplier = 1
    for denominator in denominators:
        multiplier = multiplier * denominator // _gcd(multiplier, denominator)
    scaled = [int(value * multiplier) for value in values]
    common = 0
    for value in scaled:
        common = _gcd(common, abs(value))
    if common == 0:
        return None
    scaled = [value // common for value in scaled]
    if all(value < 0 for value in scaled):
        scaled = [-value for value in scaled]
    return scaled


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


# --------------------------------------------------------------------------- #
# Plausibility: is this a compound that could exist?
# --------------------------------------------------------------------------- #
#
# Balancing is arithmetic. `2Fe + 18HCl -> 2FeCl9 + 9H2` conserves every
# atom perfectly and FeCl9 does not exist, because iron has no valency of
# nine. Arithmetic cannot see that; valency can.
#
# The hard part is not catching FeCl9. It is catching FeCl9 *without*
# rejecting KMnO4, H2SO4 and every other polyatomic compound whose apparent
# valencies look absurd until you know the structure. A check that refuses
# real chemistry is worse than no check, because the student stops believing
# it and then ignores it when it is right.
#
# So the scope is deliberately narrow: **binary compounds only**, one metal
# or hydrogen with one non-metal. Anything with three or more elements is
# reported as *unchecked* rather than as valid, which is the honest answer
# and keeps KMnO4 out of the way.

#: Common valencies. Not every oxidation state an element can be coerced
#: into -- the ones a compound is actually built from.
VALENCIES = {
    "H": {1}, "Li": {1}, "Na": {1}, "K": {1}, "Rb": {1}, "Cs": {1},
    "Ag": {1}, "Be": {2}, "Mg": {2}, "Ca": {2}, "Sr": {2}, "Ba": {2},
    "Zn": {2}, "Cd": {2}, "Al": {3}, "B": {3},
    "Fe": {2, 3}, "Cu": {1, 2}, "Hg": {1, 2}, "Sn": {2, 4}, "Pb": {2, 4},
    "Cr": {2, 3, 6}, "Mn": {2, 3, 4, 6, 7}, "Co": {2, 3}, "Ni": {2, 3},
    "Au": {1, 3}, "Pt": {2, 4}, "Ti": {3, 4}, "V": {2, 3, 4, 5},
    "F": {1}, "Cl": {1, 3, 5, 7}, "Br": {1, 3, 5, 7}, "I": {1, 3, 5, 7},
    "O": {2}, "S": {2, 4, 6}, "Se": {2, 4, 6}, "N": {3, 5},
    "P": {3, 5}, "C": {2, 4}, "Si": {4}, "As": {3, 5}, "Sb": {3, 5},
    "He": {0}, "Ne": {0}, "Ar": {0}, "Kr": {0}, "Xe": {0},
}

#: In a binary compound the second element is the more electronegative one
#: and takes its lowest (anionic) valency: chlorine is 1 in FeCl3, not 7.
_ANIONIC = {"F": 1, "Cl": 1, "Br": 1, "I": 1, "O": 2, "S": 2,
            "N": 3, "P": 3, "C": 4, "Si": 4, "Se": 2, "As": 3}

#: The cation has to be a metal for the arithmetic to mean anything.
METALS = {
    "Li", "Na", "K", "Rb", "Cs", "Be", "Mg", "Ca", "Sr", "Ba", "Al",
    "Fe", "Cu", "Zn", "Ag", "Au", "Hg", "Sn", "Pb", "Cr", "Mn", "Co",
    "Ni", "Pt", "Ti", "V", "Cd",
}


def plausible(text: str):
    """(verdict, reason) for a formula. Verdict is True, False or None.

    None means *not checked* -- three or more elements, an element with no
    valency recorded, or a plain element. Returning None rather than True
    matters: a check that reports "fine" for everything it did not examine
    is a check that will one day be believed about something it never looked
    at.
    """
    counts = formula(text)
    if len(counts) == 1:
        return None, "a single element; nothing to check"
    if len(counts) > 2:
        return None, ("%d elements: only binary compounds are checked, "
                      "because polyatomic ions make apparent valencies "
                      "misleading" % len(counts))

    (first, first_n), (second, second_n) = list(counts.items())
    if second not in _ANIONIC:
        if first in _ANIONIC:
            first, second = second, first
            first_n, second_n = second_n, first_n
        else:
            return None, "neither element is one this checks as an anion"
    if first not in VALENCIES:
        return None, "no valency recorded for %s" % first
    # Only *ionic* binaries. Simple valency arithmetic is a fact about ions
    # and not about covalent bonding, so applying it to C3H8 rejects
    # propane -- which this did, along with NO. CO2, CH4 and NH3 were
    # passing by luck rather than by the rule being right about them.
    #
    # A check that refuses real chemistry is worse than no check, so
    # covalent compounds are reported unchecked. That gives up H2O and HCl
    # as well, which is a real loss and the correct trade: FeCl9 is the
    # mistake a student actually makes, and propane is not.
    if first not in METALS:
        return None, ("%s-%s is covalent; simple valency arithmetic does not "
                      "decide whether a covalent compound exists" % (first, second))

    anion_valency = _ANIONIC[second]
    needed = second_n * anion_valency
    if needed % first_n:
        return False, ("%s would need a valency of %s, which is not a whole "
                       "number" % (first, needed / first_n))
    valency = needed // first_n
    if valency in VALENCIES[first]:
        return True, "%s(%d) with %s(%d) balances" % (
            first, valency, second, anion_valency)
    return False, ("%s would need a valency of %d; it has %s"
                   % (first, valency,
                      " or ".join(str(v) for v in sorted(VALENCIES[first]))))


def implausible_species(equation: str):
    """Every species in an equation that fails the valency check."""
    reactants, products = _split(equation)
    bad = []
    for species in reactants + products:
        verdict, reason = plausible(species)
        if verdict is False:
            bad.append((species, reason))
    return bad
