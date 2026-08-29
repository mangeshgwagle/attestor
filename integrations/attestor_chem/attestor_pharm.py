"""Pharmaceutical calculations, each one checked rather than asserted.

Every calculation here conserves something, and that is what makes it
checkable in the way the equation balancer is. A dilution conserves the mass
of solute; an alligation conserves both mass and volume. So each function
computes an answer and then **verifies the conservation law it rests on**,
raising rather than returning if the two disagree.

Exact arithmetic throughout. `Fraction`, not float: 1/3 of a 30 mL bottle is
10 mL, and a helper that says 9.999999999999998 has taught the student to
distrust it. Answers are rounded only at the point of display.

A word on what this is for
--------------------------
This is exam and study support. It does the arithmetic and shows the law it
used, so the working can be followed and marked. It is not a clinical
dosing tool and does not know anything about a patient, a drug's therapeutic
range, or whether a prescription makes sense -- it will compute a dose that
would be dangerous just as readily as one that would not, because arithmetic
cannot tell the difference. For anything reaching a person, the answer needs
checking against a current reference and a pharmacist, not against this.
"""

from __future__ import annotations

from fractions import Fraction

__all__ = ["PharmError", "percent_strength", "ratio_strength", "ppm",
           "dilute", "alligation", "molarity", "dose_by_weight",
           "millieq", "solve_c1v1"]


class PharmError(ValueError):
    """The numbers given cannot describe a real preparation."""


def _positive(name: str, value):
    number = Fraction(str(value))
    if number <= 0:
        raise PharmError("%s must be greater than zero, got %s" % (name, value))
    return number


def _nonneg(name: str, value):
    number = Fraction(str(value))
    if number < 0:
        raise PharmError("%s cannot be negative, got %s" % (name, value))
    return number


def percent_strength(amount, total, kind: str = "w/v") -> float:
    """Percentage strength.

    w/v is grams per 100 mL, w/w grams per 100 g, v/v mL per 100 mL. The
    kind is required rather than defaulted silently, because "5%" means
    three different quantities and mixing them up is the classic error.
    """
    if kind not in ("w/v", "w/w", "v/v"):
        raise PharmError("kind must be w/v, w/w or v/v, not %r" % kind)
    return float(_nonneg("amount", amount) / _positive("total", total) * 100)


def ratio_strength(part: int, whole: int, total, kind: str = "w/v") -> float:
    """A 1:5000 strength expressed as the amount in a given total.

    Ratio strength is 1 part in `whole` parts: 1:1000 w/v is 1 g in 1000 mL.
    """
    if _positive("part", part) != 1:
        raise PharmError("ratio strength is written 1:n, so the first part "
                         "is 1, not %s" % part)
    return float(_positive("total", total) / _positive("whole", whole))


def ppm(amount, total) -> float:
    """Parts per million."""
    return float(_nonneg("amount", amount) / _positive("total", total) * 10 ** 6)


def dilute(strength_before, volume_before, strength_after=None,
           volume_after=None) -> dict:
    """Dilution by C1V1 = C2V2, with the conservation checked.

    Give three of the four and it returns the fourth, the diluent to add,
    and the law it used. The solute is conserved -- diluting changes the
    volume, never the amount of drug -- so the result is verified against
    that before it is returned.
    """
    c1 = _positive("strength before", strength_before)
    v1 = _positive("volume before", volume_before)
    if (strength_after is None) == (volume_after is None):
        raise PharmError("give exactly one of the final strength or the "
                         "final volume; the other is what this works out")
    if strength_after is None:
        v2 = _positive("volume after", volume_after)
        c2 = c1 * v1 / v2
    else:
        c2 = _positive("strength after", strength_after)
        v2 = c1 * v1 / c2

    if c2 > c1:
        raise PharmError(
            "this concentrates rather than dilutes: %s%% cannot be reached "
            "from %s%% by adding diluent" % (float(c2), float(c1)))
    if c1 * v1 != c2 * v2:
        raise PharmError("internal check failed: solute is not conserved")

    return {
        "strength_before": float(c1), "volume_before": float(v1),
        "strength_after": float(c2), "volume_after": float(v2),
        "diluent_to_add": float(v2 - v1),
        "solute": float(c1 * v1 / 100),
        "law": "C1V1 = C2V2  (%s x %s = %s x %s)" % (
            float(c1), float(v1), float(c2), float(v2)),
    }


def solve_c1v1(c1=None, v1=None, c2=None, v2=None) -> Fraction:
    """The missing one of C1, V1, C2, V2. Exactly one may be None."""
    given = [c1, v1, c2, v2]
    if sum(1 for value in given if value is None) != 1:
        raise PharmError("exactly one of C1, V1, C2, V2 must be unknown")
    if c1 is None:
        return _positive("C2", c2) * _positive("V2", v2) / _positive("V1", v1)
    if v1 is None:
        return _positive("C2", c2) * _positive("V2", v2) / _positive("C1", c1)
    if c2 is None:
        return _positive("C1", c1) * _positive("V1", v1) / _positive("V2", v2)
    return _positive("C1", c1) * _positive("V1", v1) / _positive("C2", c2)


def alligation(strong, weak, wanted, total=None) -> dict:
    """Mixing two strengths to reach a third, by alligation.

    The parts come from the differences: strong gets (wanted - weak) parts,
    weak gets (strong - wanted). Both the mass of drug and the total volume
    are checked against the answer before it is returned, because getting
    the two subtractions the wrong way round is the mistake this method
    invites and it produces a plausible-looking wrong ratio.
    """
    high = _positive("strong", strong)
    low = _nonneg("weak", weak)
    target = _positive("wanted", wanted)
    if not low < target < high:
        raise PharmError(
            "the wanted strength (%s) must lie between the two you are "
            "mixing (%s and %s)" % (float(target), float(low), float(high)))

    parts_strong = target - low
    parts_weak = high - target
    result = {
        "parts_strong": float(parts_strong),
        "parts_weak": float(parts_weak),
        "ratio": "%s : %s" % (float(parts_strong), float(parts_weak)),
    }
    if total is not None:
        whole = _positive("total", total)
        share = parts_strong + parts_weak
        volume_strong = whole * parts_strong / share
        volume_weak = whole * parts_weak / share
        # Two conservation checks, not one: volume and drug.
        if volume_strong + volume_weak != whole:
            raise PharmError("internal check failed: volumes do not sum")
        drug = volume_strong * high + volume_weak * low
        if drug != whole * target:
            raise PharmError("internal check failed: drug mass does not match")
        result.update({"volume_strong": float(volume_strong),
                       "volume_weak": float(volume_weak),
                       "total": float(whole)})
    return result


def molarity(grams, molar_mass_value, litres) -> float:
    """mol/L from a mass, a molar mass and a volume."""
    moles = _nonneg("grams", grams) / _positive("molar mass", molar_mass_value)
    return float(moles / _positive("litres", litres))


def millieq(grams, equivalent_weight) -> float:
    """Milliequivalents, which the syllabus asks for in electrolyte sums."""
    return float(_nonneg("grams", grams) * 1000
                 / _positive("equivalent weight", equivalent_weight))


def dose_by_weight(dose_per_kg, kilograms, doses_per_day: int = 1) -> dict:
    """A weight-based dose, per administration and per day.

    Returns both, because conflating "5 mg/kg/day in 3 divided doses" with
    "5 mg/kg per dose" is a three-fold error and the wording that causes it
    is everywhere.
    """
    per_dose = _positive("dose per kg", dose_per_kg) * _positive(
        "kilograms", kilograms)
    if doses_per_day < 1:
        raise PharmError("doses per day must be at least 1")
    return {"per_dose": float(per_dose),
            "per_day": float(per_dose * doses_per_day),
            "doses_per_day": doses_per_day,
            "note": "per_dose assumes the rate given is per administration; "
                    "if it is a daily total, divide by doses_per_day instead"}
