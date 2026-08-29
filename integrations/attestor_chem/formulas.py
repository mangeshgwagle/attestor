"""Pharmacy formulas, each one checked against its own worked example.

A formula sheet with a typo is worse than no formula sheet, because you
memorise the typo and it survives the exam. So every entry here carries a
worked example with a known answer, and `test_formulas.py` runs all of them:
if a formula is mistyped, the example stops coming out right and the suite
fails. The reference cannot silently rot.

Each entry has:
    key       a short handle
    topic     for grouping and searching
    name      what it is called
    formula   written the way it appears in a textbook
    variables what each symbol means, with units
    example   inputs, the expected answer, and where it comes from
    compute   the function, so the example can actually be run

Use it as:
    formulas.find("clearance")        -> matching entries
    formulas.show("cockcroft_gault")  -> the formula, laid out
    formulas.compute("bsa_mosteller", height_cm=170, weight_kg=70)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

__all__ = ["Formula", "FORMULAS", "find", "show", "compute", "topics"]


@dataclass(frozen=True)
class Formula:
    key: str
    topic: str
    name: str
    formula: str
    variables: dict
    compute: object
    example: dict = field(default_factory=dict)
    note: str = ""

    def run_example(self):
        inputs = {k: v for k, v in self.example.items()
                  if k not in ("answer", "source", "tolerance")}
        return self.compute(**inputs)


def _f(key, topic, name, formula, variables, compute, example, note=""):
    return Formula(key, topic, name, formula, variables, compute, example, note)


# --------------------------------------------------------------------------- #
# Concentration and strength
# --------------------------------------------------------------------------- #

_ENTRIES = [
    _f("percent_wv", "concentration", "Percentage strength w/v",
       "% w/v = (grams of solute / mL of solution) x 100",
       {"grams": "g of solute", "millilitres": "mL of final solution"},
       lambda grams, millilitres: grams / millilitres * 100,
       {"grams": 9, "millilitres": 1000, "answer": 0.9,
        "source": "normal saline is 0.9% w/v"},
       "w/v is grams per 100 mL. w/w and v/v are different quantities."),

    _f("percent_ww", "concentration", "Percentage strength w/w",
       "% w/w = (grams of solute / grams of preparation) x 100",
       {"grams": "g of solute", "total_grams": "g of final preparation"},
       lambda grams, total_grams: grams / total_grams * 100,
       {"grams": 5, "total_grams": 100, "answer": 5.0,
        "source": "5 g in 100 g of ointment"}),

    _f("percent_vv", "concentration", "Percentage strength v/v",
       "% v/v = (mL of solute / mL of solution) x 100",
       {"millilitres": "mL of solute", "total_ml": "mL of solution"},
       lambda millilitres, total_ml: millilitres / total_ml * 100,
       {"millilitres": 70, "total_ml": 100, "answer": 70.0,
        "source": "70% v/v alcohol"}),

    _f("ratio_strength", "concentration", "Ratio strength to amount",
       "amount = total / n     for a strength written 1:n",
       {"total": "mL or g of preparation", "n": "the n in 1:n"},
       lambda total, n: total / n,
       {"total": 250, "n": 5000, "answer": 0.05,
        "source": "1:5000 in 250 mL gives 0.05 g"}),

    _f("ppm", "concentration", "Parts per million",
       "ppm = (amount / total) x 10^6",
       {"amount": "same unit as total", "total": "same unit as amount"},
       lambda amount, total: amount / total * 10 ** 6,
       {"amount": 0.001, "total": 1000, "answer": 1.0,
        "source": "1 mg in 1 L is 1 ppm"}),

    _f("mg_percent", "concentration", "Milligram percent",
       "mg% = mg of solute per 100 mL",
       {"mg": "mg of solute", "millilitres": "mL of solution"},
       lambda mg, millilitres: mg / millilitres * 100,
       {"mg": 100, "millilitres": 1000, "answer": 10.0,
        "source": "100 mg/L is 10 mg%"}),

    # ----------------------------------------------------------------- #
    # Dilution
    # ----------------------------------------------------------------- #
    _f("c1v1", "dilution", "Dilution equation",
       "C1 x V1 = C2 x V2",
       {"c1": "strength before", "v1": "volume before",
        "c2": "strength after"},
       lambda c1, v1, c2: c1 * v1 / c2,
       {"c1": 70, "v1": 100, "c2": 20, "answer": 350.0,
        "source": "70% 100 mL diluted to 20% gives 350 mL"},
       "The solute is conserved; only the volume changes."),

    _f("alligation_parts", "dilution", "Alligation parts",
       "parts of strong = wanted - weak;  parts of weak = strong - wanted",
       {"strong": "higher strength", "weak": "lower strength",
        "wanted": "target strength"},
       lambda strong, weak, wanted: (wanted - weak) / (strong - wanted),
       {"strong": 70, "weak": 20, "wanted": 40, "answer": 0.6667,
        "tolerance": 0.001,
        "source": "70/20 to 40% is 20:30 parts, i.e. strong:weak = 2:3, "
                  "which agrees with attestor_pharm giving 200 mL + 300 mL "
                  "for a 500 mL batch"},
       "Returns the ratio strong:weak. Getting the subtractions the wrong "
       "way round gives a plausible but wrong ratio."),

    # ----------------------------------------------------------------- #
    # Moles and equivalents
    # ----------------------------------------------------------------- #
    _f("moles", "moles", "Number of moles",
       "moles = mass (g) / molar mass (g/mol)",
       {"grams": "g", "molar_mass": "g/mol"},
       lambda grams, molar_mass: grams / molar_mass,
       {"grams": 9.8, "molar_mass": 98.0, "answer": 0.1,
        "source": "9.8 g of H2SO4 is 0.1 mol"}),

    _f("molarity", "moles", "Molarity",
       "M = moles of solute / litres of solution",
       {"moles": "mol", "litres": "L"},
       lambda moles, litres: moles / litres,
       {"moles": 0.1, "litres": 0.5, "answer": 0.2,
        "source": "0.1 mol in 500 mL is 0.2 M"}),

    _f("molality", "moles", "Molality",
       "m = moles of solute / kg of solvent",
       {"moles": "mol", "kg_solvent": "kg"},
       lambda moles, kg_solvent: moles / kg_solvent,
       {"moles": 0.5, "kg_solvent": 2, "answer": 0.25,
        "source": "0.5 mol in 2 kg of solvent"},
       "Molality uses the mass of *solvent*, molarity the volume of "
       "*solution*. Mixing them up is a standard trap."),

    _f("normality", "moles", "Normality",
       "N = M x n     where n is the number of equivalents per mole",
       {"molarity": "mol/L", "equivalents": "per mole"},
       lambda molarity, equivalents: molarity * equivalents,
       {"molarity": 0.5, "equivalents": 2, "answer": 1.0,
        "source": "0.5 M H2SO4 is 1 N"}),

    _f("milliequivalents", "moles", "Milliequivalents",
       "mEq = (mg of substance x valency) / molar mass",
       {"mg": "mg", "valency": "charge number", "molar_mass": "g/mol"},
       lambda mg, valency, molar_mass: mg * valency / molar_mass,
       {"mg": 585, "valency": 1, "molar_mass": 58.5, "answer": 10.0,
        "source": "585 mg NaCl is 10 mEq of Na+"}),

    _f("osmolarity", "moles", "Osmolarity",
       "mOsmol/L = (g/L / molar mass) x number of species x 1000",
       {"grams_per_litre": "g/L", "molar_mass": "g/mol",
        "species": "ions per formula unit"},
       lambda grams_per_litre, molar_mass, species:
           grams_per_litre / molar_mass * species * 1000,
       {"grams_per_litre": 9, "molar_mass": 58.5, "species": 2,
        "answer": 307.69, "tolerance": 0.01,
        "source": "0.9% NaCl is about 308 mOsmol/L"}),

    # ----------------------------------------------------------------- #
    # Dosage
    # ----------------------------------------------------------------- #
    _f("dose_per_kg", "dosage", "Dose by body weight",
       "dose = mg/kg x weight (kg)",
       {"mg_per_kg": "mg/kg", "kg": "kg"},
       lambda mg_per_kg, kg: mg_per_kg * kg,
       {"mg_per_kg": 12, "kg": 70, "answer": 840.0,
        "source": "12 mg/kg for a 70 kg adult"}),

    _f("bsa_mosteller", "dosage", "Body surface area (Mosteller)",
       "BSA (m^2) = sqrt(height_cm x weight_kg / 3600)",
       {"height_cm": "cm", "weight_kg": "kg"},
       lambda height_cm, weight_kg: math.sqrt(height_cm * weight_kg / 3600),
       {"height_cm": 170, "weight_kg": 70, "answer": 1.8181,
        "tolerance": 0.001, "source": "170 cm, 70 kg"},
       "The one to memorise -- it is the simplest and the most examined."),

    _f("bsa_dubois", "dosage", "Body surface area (Du Bois)",
       "BSA = 0.007184 x height_cm^0.725 x weight_kg^0.425",
       {"height_cm": "cm", "weight_kg": "kg"},
       lambda height_cm, weight_kg:
           0.007184 * height_cm ** 0.725 * weight_kg ** 0.425,
       {"height_cm": 170, "weight_kg": 70, "answer": 1.8097,
        "tolerance": 0.001,
        "source": "170 cm, 70 kg -- Du Bois runs slightly below Mosteller "
                  "(1.8181) for the same person, which is expected"}),

    _f("dose_by_bsa", "dosage", "Dose by body surface area",
       "dose = mg/m^2 x BSA",
       {"mg_per_m2": "mg/m^2", "bsa": "m^2"},
       lambda mg_per_m2, bsa: mg_per_m2 * bsa,
       {"mg_per_m2": 100, "bsa": 1.8, "answer": 180.0,
        "source": "cytotoxics are dosed this way"}),

    _f("clarks_rule", "dosage", "Clark's rule (paediatric)",
       "child dose = adult dose x (weight in lb / 150)",
       {"adult_dose": "mg", "weight_lb": "lb"},
       lambda adult_dose, weight_lb: adult_dose * weight_lb / 150,
       {"adult_dose": 500, "weight_lb": 75, "answer": 250.0,
        "source": "half the adult dose at 75 lb"}),

    _f("youngs_rule", "dosage", "Young's rule (paediatric)",
       "child dose = adult dose x age / (age + 12)",
       {"adult_dose": "mg", "age_years": "years"},
       lambda adult_dose, age_years: adult_dose * age_years / (age_years + 12),
       {"adult_dose": 500, "age_years": 12, "answer": 250.0,
        "source": "at 12 years, exactly half"}),

    _f("frieds_rule", "dosage", "Fried's rule (infants)",
       "infant dose = adult dose x age in months / 150",
       {"adult_dose": "mg", "age_months": "months"},
       lambda adult_dose, age_months: adult_dose * age_months / 150,
       {"adult_dose": 500, "age_months": 15, "answer": 50.0,
        "source": "15-month-old"}),

    # ----------------------------------------------------------------- #
    # Pharmacokinetics
    # ----------------------------------------------------------------- #
    _f("elimination_rate", "pharmacokinetics", "Elimination rate constant",
       "k = 0.693 / t½",
       {"half_life": "h"},
       lambda half_life: 0.693 / half_life,
       {"half_life": 6, "answer": 0.1155, "tolerance": 0.0001,
        "source": "a 6-hour half-life"}),

    _f("half_life", "pharmacokinetics", "Half-life",
       "t½ = 0.693 / k = 0.693 x Vd / CL",
       {"k": "per hour"},
       lambda k: 0.693 / k,
       {"k": 0.1155, "answer": 6.0, "tolerance": 0.01,
        "source": "inverse of the above"}),

    _f("volume_distribution", "pharmacokinetics", "Volume of distribution",
       "Vd = dose / plasma concentration",
       {"dose_mg": "mg", "concentration": "mg/L"},
       lambda dose_mg, concentration: dose_mg / concentration,
       {"dose_mg": 500, "concentration": 10, "answer": 50.0,
        "source": "500 mg giving 10 mg/L"}),

    _f("clearance", "pharmacokinetics", "Clearance",
       "CL = k x Vd",
       {"k": "per hour", "vd": "L"},
       lambda k, vd: k * vd,
       {"k": 0.1155, "vd": 50, "answer": 5.775, "tolerance": 0.001,
        "source": "k 0.1155/h, Vd 50 L"}),

    _f("loading_dose", "pharmacokinetics", "Loading dose",
       "LD = (Vd x target concentration) / F",
       {"vd": "L", "target": "mg/L", "bioavailability": "fraction 0-1"},
       lambda vd, target, bioavailability: vd * target / bioavailability,
       {"vd": 50, "target": 10, "bioavailability": 1.0, "answer": 500.0,
        "source": "IV, so F = 1"}),

    _f("maintenance_dose", "pharmacokinetics", "Maintenance dose",
       "MD = (CL x target concentration x interval) / F",
       {"clearance": "L/h", "target": "mg/L", "interval": "h",
        "bioavailability": "fraction 0-1"},
       lambda clearance, target, interval, bioavailability:
           clearance * target * interval / bioavailability,
       {"clearance": 5.775, "target": 10, "interval": 12,
        "bioavailability": 1.0, "answer": 693.0, "tolerance": 0.1,
        "source": "CL 5.775 L/h, 12-hourly"}),

    _f("bioavailability", "pharmacokinetics", "Absolute bioavailability",
       "F = (AUC_oral x dose_IV) / (AUC_IV x dose_oral)",
       {"auc_oral": "mg·h/L", "dose_iv": "mg", "auc_iv": "mg·h/L",
        "dose_oral": "mg"},
       lambda auc_oral, dose_iv, auc_iv, dose_oral:
           auc_oral * dose_iv / (auc_iv * dose_oral),
       {"auc_oral": 40, "dose_iv": 100, "auc_iv": 100, "dose_oral": 100,
        "answer": 0.4, "source": "40% orally bioavailable"}),

    _f("cockcroft_gault", "pharmacokinetics", "Creatinine clearance",
       "CrCl = ((140 - age) x weight) / (72 x serum creatinine)  "
       "[x 0.85 if female]",
       {"age": "years", "weight_kg": "kg", "creatinine": "mg/dL",
        "female": "True or False"},
       lambda age, weight_kg, creatinine, female=False:
           (140 - age) * weight_kg / (72 * creatinine) * (0.85 if female else 1),
       {"age": 60, "weight_kg": 70, "creatinine": 1.0, "answer": 77.78,
        "tolerance": 0.01, "source": "60-year-old, 70 kg, creatinine 1.0"},
       "The 0.85 female correction is the part most often forgotten."),

    # ----------------------------------------------------------------- #
    # Infusion
    # ----------------------------------------------------------------- #
    _f("drops_per_min", "infusion", "Drop rate",
       "drops/min = (volume mL x drop factor) / time in minutes",
       {"volume_ml": "mL", "drop_factor": "drops/mL", "minutes": "min"},
       lambda volume_ml, drop_factor, minutes:
           volume_ml * drop_factor / minutes,
       {"volume_ml": 1000, "drop_factor": 20, "minutes": 480,
        "answer": 41.67, "tolerance": 0.01,
        "source": "1 L over 8 h with a 20 drops/mL set"}),

    _f("infusion_rate", "infusion", "Infusion rate mL/h",
       "mL/h = total volume / hours",
       {"volume_ml": "mL", "hours": "h"},
       lambda volume_ml, hours: volume_ml / hours,
       {"volume_ml": 1000, "hours": 8, "answer": 125.0,
        "source": "1 L over 8 hours"}),

    _f("dose_rate_infusion", "infusion", "Weight-based infusion rate",
       "mL/h = (dose mcg/kg/min x kg x 60) / concentration mcg/mL",
       {"mcg_kg_min": "mcg/kg/min", "kg": "kg",
        "concentration_mcg_ml": "mcg/mL"},
       lambda mcg_kg_min, kg, concentration_mcg_ml:
           mcg_kg_min * kg * 60 / concentration_mcg_ml,
       {"mcg_kg_min": 5, "kg": 70, "concentration_mcg_ml": 1000,
        "answer": 21.0, "source": "5 mcg/kg/min, 70 kg, 1 mg/mL"}),

    # ----------------------------------------------------------------- #
    # Isotonicity and physical pharmacy
    # ----------------------------------------------------------------- #
    _f("sodium_chloride_equivalent", "isotonicity", "NaCl equivalent",
       "NaCl needed = 0.009 x volume mL - (E x grams of drug)",
       {"volume_ml": "mL", "e_value": "NaCl equivalent",
        "drug_grams": "g"},
       lambda volume_ml, e_value, drug_grams:
           0.009 * volume_ml - e_value * drug_grams,
       {"volume_ml": 100, "e_value": 0.18, "drug_grams": 1,
        "answer": 0.72, "tolerance": 0.001,
        "source": "1 g of a drug with E 0.18 in 100 mL"},
       "0.009 g/mL is the NaCl needed for isotonicity."),

    _f("freezing_point", "isotonicity", "Freezing point depression",
       "NaCl needed (g/100 mL) = (0.52 - depression by drug) / 0.576",
       {"drug_depression": "degrees C"},
       lambda drug_depression: (0.52 - drug_depression) / 0.576,
       {"drug_depression": 0.2, "answer": 0.5556, "tolerance": 0.0001,
        "source": "blood freezes at -0.52 C; 1% NaCl depresses 0.576"}),

    _f("specific_gravity", "physical", "Specific gravity",
       "SG = mass of substance / mass of equal volume of water",
       {"grams": "g", "millilitres": "mL"},
       lambda grams, millilitres: grams / millilitres,
       {"grams": 125, "millilitres": 100, "answer": 1.25,
        "source": "125 g occupying 100 mL"}),

    _f("displacement_value", "physical", "Displacement value",
       "DV = drug weight / weight of base displaced",
       {"drug_grams": "g", "base_displaced": "g"},
       lambda drug_grams, base_displaced: drug_grams / base_displaced,
       {"drug_grams": 6, "base_displaced": 1, "answer": 6.0,
        "source": "suppository calculations"}),

    _f("hlb_blend", "physical", "HLB of a blend",
       "HLB = (fraction_A x HLB_A) + (fraction_B x HLB_B)",
       {"fraction_a": "0-1", "hlb_a": "", "fraction_b": "0-1", "hlb_b": ""},
       lambda fraction_a, hlb_a, fraction_b, hlb_b:
           fraction_a * hlb_a + fraction_b * hlb_b,
       {"fraction_a": 0.6, "hlb_a": 15, "fraction_b": 0.4, "hlb_b": 4.3,
        "answer": 10.72, "tolerance": 0.01,
        "source": "60:40 Tween 80 / Span 80"}),

    _f("henderson_hasselbalch", "physical", "Henderson-Hasselbalch",
       "pH = pKa + log10([salt] / [acid])",
       {"pka": "", "salt": "concentration", "acid": "concentration"},
       lambda pka, salt, acid: pka + math.log10(salt / acid),
       {"pka": 4.76, "salt": 1, "acid": 1, "answer": 4.76,
        "tolerance": 0.001, "source": "equal parts: pH = pKa"},
       "For a base: pH = pKa + log([base]/[salt])."),

    _f("dilution_factor", "physical", "Dilution factor",
       "DF = final volume / initial volume",
       {"final_ml": "mL", "initial_ml": "mL"},
       lambda final_ml, initial_ml: final_ml / initial_ml,
       {"final_ml": 100, "initial_ml": 10, "answer": 10.0,
        "source": "1 in 10 dilution"}),
]

FORMULAS = {entry.key: entry for entry in _ENTRIES}


def topics() -> list:
    return sorted({entry.topic for entry in _ENTRIES})


def find(text: str) -> list:
    """Every formula whose name, topic, key or expression mentions `text`."""
    needle = text.lower().strip()
    return [entry for entry in _ENTRIES
            if needle in entry.key.lower()
            or needle in entry.name.lower()
            or needle in entry.topic.lower()
            or needle in entry.formula.lower()]


def show(key: str) -> str:
    """One formula, laid out with its worked example."""
    if key not in FORMULAS:
        matches = find(key)
        if len(matches) == 1:
            key = matches[0].key
        else:
            raise KeyError("no formula %r; try find(%r)" % (key, key))
    entry = FORMULAS[key]
    lines = ["%s  [%s]" % (entry.name, entry.topic), "",
             "    %s" % entry.formula, ""]
    for symbol, meaning in entry.variables.items():
        lines.append("    %-22s %s" % (symbol, meaning))
    if entry.example:
        given = ", ".join("%s=%s" % (k, v) for k, v in entry.example.items()
                          if k not in ("answer", "source", "tolerance"))
        lines += ["", "    worked: %s" % given,
                  "            -> %s   (%s)" % (entry.example["answer"],
                                                entry.example.get("source", ""))]
    if entry.note:
        lines += ["", "    %s" % entry.note]
    return "\n".join(lines)


def compute(key: str, **inputs):
    """Run a formula. Raises KeyError if the name is not recognised."""
    if key not in FORMULAS:
        raise KeyError("no formula %r; try find(%r)" % (key, key))
    return FORMULAS[key].compute(**inputs)
