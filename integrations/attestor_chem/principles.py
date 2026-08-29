"""The reasoning behind preparations, so an unseen one can be derived.

`preparations` holds worked answers. This file holds the small number of
ideas those answers are made of. There are not sixty unrelated methods --
there are about a dozen patterns, reused. Someone who knows the patterns can
construct a defensible answer for a substance they have never revised, and
that is the difference between a question being frightening and being work.

How to use it
-------------
Read a pattern, then read the preparations listed under it and watch the
same move happen in each. Once you can see the pattern in three different
substances, you own it -- and you will recognise it in a fourth you have
never seen.

`derive()` at the bottom turns the patterns into an ordered set of questions
to ask about any target substance. Answering those questions in order *is*
the exam answer. It will not always produce the official industrial route,
and it says so, but it produces chemistry that works and reasoning that
earns marks -- which is a far better position than a blank page.

Every cross-reference here is checked against `preparations`, so a pattern
cannot cite an example that does not exist or has been renamed.
"""

from __future__ import annotations

from dataclasses import dataclass

import preparations

__all__ = ["Pattern", "PATTERNS", "DERIVATION", "derive", "find", "show",
           "check_examples", "CrossReferenceError"]


class CrossReferenceError(ValueError):
    """A pattern cites a preparation that does not exist."""


@dataclass(frozen=True)
class Pattern:
    key: str
    name: str
    idea: str
    recognise: str        # when this pattern is the one you want
    moves: tuple          # what it makes you do, and why
    examples: tuple       # keys in preparations
    trap: str = ""        # how it is got wrong


_PATTERNS = [
    Pattern(
        key="neutralisation",
        name="Neutralisation: acid plus base, carbonate or oxide",
        idea=(
            "The commonest route to a salt. An acid is neutralised by the "
            "metal's oxide, hydroxide or carbonate, and the salt is "
            "crystallised from the solution."),
        recognise=(
            "The target is a simple salt of a common acid -- a sulphate, "
            "chloride, or the salt of an organic acid -- and the metal has "
            "an available oxide or carbonate."),
        moves=(
            ("Use the metal compound in slight excess, not the acid.",
             "Excess acid stays in the product, attacks the container and "
             "irritates on use. Excess oxide or carbonate is insoluble and "
             "filters off -- so the excess reagent is chosen to be the one "
             "you can remove."),
            ("Take the excess as the endpoint.",
             "Effervescence ceasing (carbonate) or solid remaining "
             "undissolved (oxide) tells you the acid is consumed. You do not "
             "need a titration to know when to stop."),
            ("Filter hot, then crystallise on cooling.",
             "Hot filtration removes the excess and any insoluble impurity "
             "before crystallisation traps it in the crystals."),
            ("Let the excess scavenge heavy metals.",
             "A slight excess of carbonate raises the pH just enough to "
             "precipitate iron and heavy metals as basic salts, which the "
             "same filtration then removes. One step, two purposes."),
        ),
        examples=("magnesium_sulphate", "copper_sulphate",
                  "calcium_gluconate", "boric_acid"),
        trap="Using excess acid 'to make sure it all reacts'. It guarantees "
             "free acid in the product, which is a specification failure."),

    Pattern(
        key="double_decomposition",
        name="Double decomposition: two solubles give one insoluble",
        idea=(
            "Two soluble salts are mixed and the desired product "
            "precipitates because it is the least soluble combination "
            "present. The chemistry is trivial; the craft is entirely in "
            "controlling the precipitate and washing it."),
        recognise=(
            "The target is insoluble in water -- a hydroxide, carbonate, or "
            "an insoluble sulphate."),
        moves=(
            ("Use dilute solutions, and usually hot.",
             "Dilute and hot gives a denser, more crystalline, filterable "
             "precipitate. Concentrated cold solutions give a gelatinous "
             "mass that occludes impurities and will not wash."),
            ("Add slowly with constant stirring.",
             "Slow addition avoids local excess, which is what makes "
             "precipitates slimy and traps the mother liquor inside them."),
            ("Choose which reagent is in excess on safety grounds.",
             "The excess reagent is the one that will contaminate the "
             "product, so it must be the harmless one. In barium sulphate "
             "this decides the whole method."),
            ("Wash to an endpoint defined by a test, not by a number of "
             "washes.",
             "Wash until the washings give no precipitate with barium "
             "chloride (sulphate gone) or with silver nitrate (chloride "
             "gone). 'Wash three times' is not an answer."),
            ("Wash gelatinous precipitates by decantation, not on the "
             "filter.",
             "They blind the filter paper. Settle, pour off, refill -- "
             "repeatedly."),
        ),
        examples=("barium_sulphate", "magnesium_hydroxide",
                  "aluminium_hydroxide_gel", "calcium_carbonate"),
        trap="Stating a washing step without stating how you know when to "
             "stop. The test is the mark."),

    Pattern(
        key="solubility_difference",
        name="Separation by a solubility difference",
        idea=(
            "Both product and by-product are in the same solution. The one "
            "whose solubility changes most with temperature crystallises out "
            "on cooling; the other stays behind in the mother liquor."),
        recognise=(
            "The reaction produces the wanted substance together with a very "
            "soluble by-product such as sodium chloride, and no precipitate "
            "forms during the reaction itself."),
        moves=(
            ("Work hot and concentrated, then cool.",
             "The separation is driven by the gap between hot and cold "
             "solubility. Boric acid is roughly ten times more soluble in "
             "boiling water than in cold; sodium chloride is nearly as "
             "soluble cold as hot, so it does not come out."),
            ("Cool slowly and undisturbed for purity, quickly for fine "
             "crystals.",
             "Slow cooling grows large clean crystals that exclude "
             "impurities. Fast cooling is chosen only when something else -- "
             "oxidation, as in ferrous sulphate -- matters more."),
            ("Wash the crystals with a *little cold* solvent.",
             "Cold so the crop is not redissolved; the wash removes the film "
             "of mother liquor, which is where the impurity is."),
            ("Recrystallise if purity demands it.",
             "Each recrystallisation repeats the same separation and costs "
             "yield -- a trade-off worth naming in an answer."),
        ),
        examples=("boric_acid", "ferrous_sulphate", "magnesium_sulphate",
                  "potassium_iodide"),
        trap="Cooling fast for convenience when the monograph wants pure "
             "crystals, or washing with water that is not cold."),

    Pattern(
        key="thermal_stability_difference",
        name="Separation by a difference in thermal stability",
        idea=(
            "Two salts in the same mixture decompose at different "
            "temperatures. Heat to a point between them: the impurity "
            "decomposes to something insoluble, the product does not."),
        recognise=(
            "The impurity is chemically similar to the product -- a "
            "neighbouring metal, so solubility will not separate them -- but "
            "its salt is less stable to heat."),
        moves=(
            ("Evaporate to dryness and fuse gently.",
             "Gently: the window between the two decomposition temperatures "
             "is what you are exploiting, and overshooting decomposes the "
             "product too."),
            ("Extract with water and filter.",
             "The decomposed impurity is now an insoluble oxide; the product "
             "is still a soluble salt. The separation has become trivial."),
        ),
        examples=("silver_nitrate",),
        trap="Overheating, which decomposes the product as well and turns "
             "the whole batch into oxide."),

    Pattern(
        key="protecting_an_oxidation_state",
        name="Protecting a labile oxidation state",
        idea=(
            "The wanted species is stable enough to make but not stable "
            "enough to leave alone. Every step of the method is then shaped "
            "by keeping it in the right oxidation state, and so is the "
            "storage condition."),
        recognise=(
            "The target is a lower oxidation state that air oxidises -- "
            "Fe(II) above all -- or a substance that decomposes on standing."),
        moves=(
            ("Keep the reducing agent in excess throughout.",
             "Excess metallic iron reduces any Fe(III) formed straight back "
             "to Fe(II). The protection is chemical and continuous, not a "
             "one-off correction."),
            ("Keep the solution acidic.",
             "Suppresses hydrolysis to basic salts, which is the brown "
             "discolouration."),
            ("Minimise time, temperature and air contact.",
             "Filter hot but quickly; cool rapidly; dry at low temperature; "
             "displace water with alcohol so drying is fast."),
            ("Carry the protection into the container.",
             "'Well-filled, tightly closed' is not generic advice -- "
             "well-filled means little enclosed air, which is the whole "
             "point for an oxidisable salt."),
            ("Name the visible sign of failure.",
             "Pale bluish-green is good; brown or yellow is Fe(III). A "
             "colour is an in-process control."),
        ),
        examples=("ferrous_sulphate", "hydrogen_peroxide",
                  "sodium_thiosulphate", "potassium_iodide"),
        trap="Treating storage as an afterthought. For these substances the "
             "storage condition is part of the method and carries marks."),

    Pattern(
        key="amphoterism",
        name="Amphoterism as a constraint on the method",
        idea=(
            "An amphoteric hydroxide dissolves in excess alkali as well as "
            "in acid. So the precipitation has a pH window, and overshooting "
            "destroys the product you have just made."),
        recognise=(
            "The metal is aluminium, zinc, lead, tin or chromium -- the "
            "amphoteric ones."),
        moves=(
            ("Add the alkali to the metal salt, never the reverse.",
             "This direction keeps the alkali always in local deficit. The "
             "reverse direction passes through a large excess of alkali and "
             "redissolves the product as the aluminate or zincate."),
            ("Control and state the pH.",
             "An answer for an amphoteric hydroxide that does not mention pH "
             "control has missed the only difficult part."),
            ("Use the amphoterism as the identification test.",
             "Soluble in both dilute acid and sodium hydroxide -- the same "
             "property that made the preparation awkward proves the "
             "product's identity."),
        ),
        examples=("aluminium_hydroxide_gel",),
        trap="Adding the aluminium salt into the alkali, which is the "
             "reverse of what works."),

    Pattern(
        key="by_product_removes_itself",
        name="Choosing the reagent so the by-product removes itself",
        idea=(
            "When several acids would work, choose the one whose salt with "
            "the counter-ion is insoluble. The by-product then filters off "
            "and no separation step is needed at all."),
        recognise=(
            "You have a choice of mineral acid, and one of them forms an "
            "insoluble salt with the metal present."),
        moves=(
            ("Pick the acid by the solubility of its by-product.",
             "Barium peroxide with sulphuric acid gives barium sulphate, "
             "which is insoluble and filters out, leaving pure hydrogen "
             "peroxide solution. Hydrochloric acid would leave soluble "
             "barium chloride in the product -- and soluble barium is "
             "poisonous."),
            ("Say why the alternative was rejected.",
             "That sentence is often worth more than the procedure, because "
             "it shows the choice was reasoned rather than recalled."),
        ),
        examples=("hydrogen_peroxide", "barium_sulphate"),
        trap="Naming the acid without justifying it. The justification is "
             "the chemistry."),

    Pattern(
        key="redox_and_disproportionation",
        name="Oxidation, reduction and disproportionation",
        idea=(
            "The element must be moved to a different oxidation state. "
            "Sometimes one reaction does it; sometimes an intermediate forms "
            "and must then be pushed further, and sometimes a species "
            "disproportionates -- part oxidised, part reduced."),
        recognise=(
            "The target is a high-oxidation-state anion (permanganate, "
            "iodate, chlorate) or the element is being extracted from an ore "
            "in the wrong state."),
        moves=(
            ("Identify the intermediate and its visible sign.",
             "Manganese dioxide fuses to green manganate before it becomes "
             "purple permanganate. The colour is the in-process check on the "
             "first stage."),
            ("Account for the atoms that go the wrong way.",
             "In disproportionation only part of the element ends up as "
             "product -- two thirds for manganate to permanganate, five "
             "sixths for the iodide from iodine and alkali. Stating the "
             "fraction shows you understand the equation rather than having "
             "copied it."),
            ("Recover or reduce the by-product.",
             "The MnO2 is recycled to the fusion; the KIO3 is reduced with "
             "charcoal. Skipping this loses most of the yield and leaves the "
             "by-product as an impurity."),
            ("Prefer the electrolytic route where it exists.",
             "Electrolytic oxidation avoids the disproportionation loss "
             "entirely, which is why industry uses it -- a good "
             "'advantages' paragraph."),
        ),
        examples=("potassium_permanganate", "potassium_iodide",
                  "bleaching_powder", "sodium_thiosulphate"),
        trap="Writing the first equation and stopping. The iodate step and "
             "the manganate step are where the marks are."),

    Pattern(
        key="temperature_ceiling",
        name="A temperature ceiling set by the product, not the reaction",
        idea=(
            "Many products have a maximum temperature above which they stop "
            "being the substance you are making -- by losing water of "
            "crystallisation, by decomposing, or by inverting."),
        recognise=(
            "The product is a hydrate, a bicarbonate, a peroxide, or a "
            "sugar."),
        moves=(
            ("State the ceiling and what happens above it.",
             "Boric acid above 55 degrees C becomes metaboric acid. Sodium "
             "bicarbonate above 50 becomes the carbonate. A hydrate heated "
             "becomes a lower hydrate with a different assay per gram. "
             "Naming the consequence is what earns the mark."),
            ("Dry by displacement rather than by heat where possible.",
             "Washing with alcohol displaces water, so drying is fast and "
             "cool."),
            ("Air-dry hydrates at room temperature, never in an oven.",
             "The water of crystallisation is part of the formula. Drive it "
             "off and you have a lower hydrate: a different molecular "
             "weight, so a different quantity of drug per gram, and the "
             "product fails its assay while looking perfectly normal."),
        ),
        examples=("boric_acid", "sodium_bicarbonate", "ferrous_sulphate",
                  "magnesium_sulphate", "copper_sulphate"),
        trap="Writing 'dry the product' with no temperature. For these "
             "substances the temperature is the step."),

    Pattern(
        key="physical_form_is_a_specification",
        name="Physical form is part of the specification",
        idea=(
            "Two products can be the same compound and different medicines. "
            "Particle size, bulk density and crystal form are controlled "
            "deliberately, by concentration, temperature and rate."),
        recognise=(
            "The monograph name contains 'light', 'heavy', 'precipitated', "
            "'gel' or 'impalpable', or the product is a suspension or "
            "contrast medium."),
        moves=(
            ("Control concentration, temperature and rate of addition.",
             "These three set particle size and crystal habit. Light and "
             "heavy magnesium carbonate are the same chemistry made under "
             "different conditions."),
            ("Say what the form is for.",
             "Fine particles suspend well and do not sediment -- which is "
             "why barium sulphate for radiography is made from dilute "
             "solutions. A gel has surface area and so has antacid "
             "activity. Impalpable powder does not abrade skin."),
        ),
        examples=("barium_sulphate", "calcium_carbonate",
                  "aluminium_hydroxide_gel"),
        trap="Treating the physical description as decoration rather than "
             "as something the method was designed to achieve."),

    Pattern(
        key="assay_follows_chemistry",
        name="The assay follows from the substance's own chemistry",
        idea=(
            "You do not have to memorise which assay goes with which "
            "substance. Ask what the substance does chemically, and the "
            "assay is the reaction that does it quantitatively."),
        recognise="Always -- this is how to answer an assay you have not "
                  "revised.",
        moves=(
            ("If it is oxidisable, titrate with an oxidant.",
             "Fe(II) with permanganate or cerium(IV). Hydrogen peroxide and "
             "oxalate with permanganate -- self-indicating, so no indicator "
             "is needed."),
            ("If it is an oxidant, liberate iodine and titrate with "
             "thiosulphate.",
             "Iodometry: copper(II), bleaching powder, hypochlorite. Starch "
             "as indicator, added near the endpoint."),
            ("If it is a divalent metal, titrate complexometrically with "
             "disodium edetate.",
             "Magnesium, calcium, aluminium, zinc. Buffered to pH 10 with "
             "mordant black for Mg and Ca."),
            ("If it is insoluble or reacts slowly, use excess acid and back-"
             "titrate.",
             "Magnesium hydroxide, calcium carbonate -- a direct titration "
             "would have no usable endpoint."),
            ("If it is a halide, titrate with silver nitrate.",
             "Argentometry -- Mohr, Volhard or Fajans depending on the "
             "conditions."),
            ("If it is too weak an acid to titrate, make it stronger.",
             "Boric acid with mannitol or glycerol. This is the classic "
             "'trick' assay and it is asked often."),
        ),
        examples=("ferrous_sulphate", "copper_sulphate", "boric_acid",
                  "magnesium_hydroxide", "potassium_permanganate",
                  "bleaching_powder"),
        trap="Trying to memorise a table of assays. Derive it from what the "
             "substance is."),

    Pattern(
        key="impurity_comes_from_the_method",
        name="The limit tests follow from the method",
        idea=(
            "The impurities a monograph tests for are not arbitrary. They "
            "are the reagents, the container, and the failure modes of the "
            "process that made it. Read your own procedure back and the "
            "limit tests fall out."),
        recognise="Always -- this is how to answer a limit test you have not "
                  "revised.",
        moves=(
            ("List your reagents; those are your first limit tests.",
             "Boric acid is made with hydrochloric acid, so chloride is "
             "tested. Magnesium hydroxide is made from the sulphate, so "
             "sulphate is tested."),
            ("Add the characteristic decomposition product.",
             "Ferrous sulphate is tested for ferric iron; potassium iodide "
             "for iodate and free iodine; bleaching powder for chlorate. "
             "Each is what the substance turns into when the method or the "
             "storage fails."),
            ("Add heavy metals and arsenic as general tests.",
             "These come from the raw materials and the plant, not from the "
             "chemistry, and appear in almost every monograph."),
            ("Ask what would be dangerous, and test for that specifically.",
             "Soluble barium in barium sulphate. The test exists because "
             "people have died of its absence."),
        ),
        examples=("boric_acid", "ferrous_sulphate", "barium_sulphate",
                  "potassium_iodide"),
        trap="Reciting 'chloride, sulphate, heavy metals, arsenic' for every "
             "substance. Say which one matters here, and why."),
]

PATTERNS = {pattern.key: pattern for pattern in _PATTERNS}


#: The questions to ask about a substance you have never revised, in order.
#: Answering these in sequence produces the shape of a full answer.
DERIVATION = (
    ("What is it, chemically?",
     "Salt, oxide, hydroxide, element, organic salt? The class decides the "
     "route before anything else does."),
    ("Is it soluble or insoluble in water?",
     "Insoluble means precipitation by double decomposition, and the whole "
     "difficulty will be washing. Soluble means neutralisation or "
     "dissolution, and the difficulty will be crystallising it cleanly."),
    ("What cheap starting material contains the metal or the anion?",
     "An ore, a carbonate, an oxide, the metal itself. You are not expected "
     "to invent an exotic starting material."),
    ("Which reaction converts that to the target?",
     "Usually neutralisation, double decomposition, or a redox step. Write "
     "the equation and balance it before writing any procedure."),
    ("Which reagent should be in excess, and why?",
     "The one you can remove, or the one that is harmless. Never the acid, "
     "unless you can boil it off."),
    ("How does the product separate from the by-product?",
     "By precipitating, by crystallising on cooling, or because the "
     "by-product is insoluble and filters off. If you cannot answer this, "
     "you have not got a method yet."),
    ("What limits the temperature?",
     "Water of crystallisation, decomposition, oxidation, inversion. State "
     "the ceiling and the consequence of exceeding it."),
    ("How is it washed, and how do you know when to stop?",
     "Name the test on the washings -- barium chloride for sulphate, silver "
     "nitrate for chloride."),
    ("How is it dried, and at what temperature?",
     "Air, low oven, alcohol displacement. Never 'dry the product' alone."),
    ("What impurity does this method leave, and what tests for it?",
     "Your own reagents, plus the substance's characteristic decomposition "
     "product."),
    ("What chemistry does it do, and therefore how is it assayed?",
     "Oxidisable, oxidising, divalent metal, halide, weak acid -- each "
     "implies its titration."),
    ("What makes it deteriorate, and therefore how is it stored?",
     "Light, air, moisture, carbon dioxide, heat. The storage condition is "
     "the last line of the answer and it is never generic."),
)


def check_examples() -> bool:
    """Every cited example exists in `preparations`.

    A reference that points at a renamed or deleted entry is worse than one
    that points nowhere, because it looks correct.
    """
    known = set(preparations.PREPARATIONS)
    for pattern in _PATTERNS:
        missing = [key for key in pattern.examples if key not in known]
        if missing:
            raise CrossReferenceError(
                "pattern %r cites unknown preparation(s): %s"
                % (pattern.key, ", ".join(missing)))
    return True


def patterns_for(preparation_key: str) -> list:
    """Which patterns this preparation demonstrates."""
    return [pattern for pattern in _PATTERNS
            if preparation_key in pattern.examples]


def find(text: str) -> list:
    needle = text.lower().strip()
    return [pattern for pattern in _PATTERNS
            if needle in pattern.key.lower()
            or needle in pattern.name.lower()
            or needle in pattern.idea.lower()
            or needle in pattern.recognise.lower()]


def derive(target: str = "") -> str:
    """The checklist for a substance you have not revised."""
    lines = ["DERIVING A PREPARATION" + (" -- %s" % target if target else ""),
             "",
             "Answer these in order. The answers are the paragraphs of your",
             "answer. Balance the equation before you write any procedure.",
             ""]
    matches = preparations.find(target) if target else []
    if len(matches) == 1:
        match = matches[0]
        matched_patterns = patterns_for(match.key)
        lines += ["KNOWN REFERENCE MATCH",
                  "  %s (%s)" % (match.name, match.key),
                  "  Relevant patterns: %s" % (
                      ", ".join(pattern.key for pattern in matched_patterns)
                      or "none recorded"),
                  "  Read the checked entry with: pharma show %s" % match.key,
                  ""]
    elif target:
        lines += ["NO UNIQUE CHECKED MATCH",
                  "  Attestor is not inferring a substance-specific route.",
                  "  Use this only to structure questions for your prescribed",
                  "  text or pharmacopoeia.", ""]
    for index, (question, guidance) in enumerate(DERIVATION, start=1):
        lines.append("%2d. %s" % (index, question))
        lines.append("    %s" % guidance)
    lines += ["",
              "This will not always reproduce the official industrial route.",
              "The checklist does not prove a reaction route; it structures",
              "an exam hypothesis that must be checked against the prescribed",
              "source."]
    return "\n".join(lines)


def show(key: str) -> str:
    if key not in PATTERNS:
        matches = find(key)
        if len(matches) == 1:
            key = matches[0].key
        else:
            raise KeyError("no pattern %r; try find(%r)" % (key, key))
    p = PATTERNS[key]
    lines = [p.name, "", "THE IDEA", "  %s" % p.idea,
             "", "WHEN THIS IS THE PATTERN", "  %s" % p.recognise,
             "", "WHAT IT MAKES YOU DO"]
    for move, why in p.moves:
        lines.append("  - %s" % move)
        lines.append("    %s" % why)
    lines += ["", "SEEN IN"]
    for example in p.examples:
        prep = preparations.PREPARATIONS[example]
        lines.append("  - %s (%s)" % (prep.name, example))
    if p.trap:
        lines += ["", "HOW IT IS GOT WRONG", "  %s" % p.trap]
    return "\n".join(lines)
