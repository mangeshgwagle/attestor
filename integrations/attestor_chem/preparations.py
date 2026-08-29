"""Preparation of pharmaceutical substances: the chemistry, not the formula.

A dosage form is compounded (see `methods`). A *substance* is manufactured,
and the examinable answer has a fixed shape:

    principle -> reaction -> procedure -> purification -> identification
    -> limit tests -> assay -> uses -> storage

Everything here follows that shape, so the answer you write has the same
skeleton every time and you are only filling in the chemistry.

Why the equations are checked and not just typed
------------------------------------------------
A preparation answer stands on its balanced equation. An unbalanced one is
the fastest way to lose the marks for a question you otherwise knew, and a
wrong coefficient is invisible on rereading -- it looks like chemistry.

So every reaction here is run through `attestor_chem.conserves`, the same atom
conservation check the balancer is verified against. A mistyped coefficient
stops conserving and the test suite fails. The equations in this file are
therefore checked arithmetic rather than remembered arithmetic.

What this file is not
---------------------
It is not a substitute for your pharmacopoeia. Assay limits, percentage
purity requirements and the exact quantities in an official monograph are
IP/BP/USP text and vary by edition -- where a number is monograph-specific
it says so instead of inventing one. The chemistry, the procedure and the
reasoning are what is here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import attestor_chem

__all__ = ["Preparation", "PREPARATIONS", "check_reactions", "find", "show",
           "categories", "ReactionError", "split_equation"]


class ReactionError(ValueError):
    """A stated equation does not conserve atoms."""


@dataclass(frozen=True)
class Preparation:
    key: str
    name: str
    formula: str
    category: str
    principle: str
    reactions: tuple          # balanced equations, as written in an answer
    procedure: tuple          # (step, why)
    purification: str = ""
    identification: tuple = ()
    limit_tests: tuple = ()
    assay: str = ""
    uses: tuple = ()
    storage: str = ""
    note: str = ""


_COEFFICIENT = re.compile(r"^(\d+)\s*(.+)$")


def split_equation(equation: str):
    """"2H2 + O2 -> 2H2O" -> ([2,1,2], ['H2','O2'], ['H2O']).

    Separating the coefficient from the species is the whole trick: the
    conservation check needs them apart, and writing them together is how a
    coefficient error hides.
    """
    if "->" not in equation:
        raise ReactionError("no -> in %r" % equation)
    left, right = equation.split("->", 1)

    def parse(side):
        coefficients, species = [], []
        for term in side.split("+"):
            term = term.strip()
            if not term:
                continue
            match = _COEFFICIENT.match(term)
            if match:
                coefficients.append(int(match.group(1)))
                species.append(match.group(2).strip())
            else:
                coefficients.append(1)
                species.append(term)
        return coefficients, species

    left_coefficients, reactants = parse(left)
    right_coefficients, products = parse(right)
    return left_coefficients + right_coefficients, reactants, products


def check_reactions(prep: "Preparation") -> bool:
    """Every equation in this preparation conserves atoms."""
    for equation in prep.reactions:
        if "->" not in equation:          # a prose note, not an equation
            continue
        coefficients, reactants, products = split_equation(equation)
        if not attestor_chem.conserves(coefficients, reactants, products):
            raise ReactionError("%s: %s does not balance" % (prep.key, equation))
    return True


def _p(step, why):
    return (step, why)


# --------------------------------------------------------------------------- #

_PREPARATIONS = [
    Preparation(
        key="boric_acid",
        name="Boric acid",
        formula="H3BO3",
        category="Acids and bases",
        principle=(
            "Borax is decomposed by a strong mineral acid. Boric acid is far "
            "less soluble in cold water than in hot, so it crystallises out "
            "on cooling while the sodium chloride formed stays in solution -- "
            "that solubility difference is the separation."),
        reactions=("Na2B4O7 + 2HCl + 5H2O -> 4H3BO3 + 2NaCl",),
        procedure=(
            _p("Dissolve borax in the minimum quantity of boiling water.",
               "Hot water because boric acid must stay dissolved until the "
               "reaction is complete; a cold saturated solution would "
               "precipitate product mid-reaction."),
            _p("Add concentrated hydrochloric acid slowly with stirring until "
               "the solution is acidic to litmus.",
               "Slowly and with stirring so the reaction does not boil over; "
               "acid to litmus is the endpoint indicating all the borax has "
               "been decomposed."),
            _p("Allow to cool slowly, undisturbed.",
               "Boric acid is about ten times less soluble cold than hot, so "
               "cooling crystallises it while NaCl remains in the mother "
               "liquor. Slow cooling gives larger, purer crystals."),
            _p("Filter the crystals, wash with a little cold water, and "
               "recrystallise from hot water.",
               "Cold water for washing so the product is not redissolved; "
               "the wash removes adhering mother liquor carrying chloride."),
            _p("Dry the crystals at a temperature below 55 degrees C.",
               "Above this boric acid loses water and passes to metaboric "
               "acid (HBO2) and then to boric anhydride, so the product "
               "would no longer be H3BO3."),
        ),
        purification="Recrystallisation from hot water.",
        identification=(
            "Warm with ethanol and concentrated sulphuric acid and ignite -- "
            "burns with a characteristic green-edged flame (ethyl borate).",
            "Turns turmeric paper red-brown; the colour turns greenish-black "
            "on adding alkali.",
        ),
        limit_tests=("Chloride, sulphate, and heavy metals -- chloride is the "
                     "one that matters here because HCl is a reagent.",),
        assay="Titration with standard NaOH in the presence of mannitol or "
              "glycerol, using phenolphthalein. Boric acid is too weak to "
              "titrate directly; the polyol forms a stronger complex acid "
              "that gives a sharp endpoint. That trick is examinable.",
        uses=("Mild antiseptic", "Eye lotion (as boric acid solution)",
              "Buffer component", "Dusting powder"),
        storage="Well-closed container."),

    Preparation(
        key="ferrous_sulphate",
        name="Ferrous sulphate",
        formula="FeSO4.7H2O",
        category="Haematinics",
        principle=(
            "Iron is dissolved in dilute sulphuric acid. The whole difficulty "
            "is that Fe(II) oxidises readily to Fe(III), so every step is "
            "arranged to exclude air and keep the solution acidic."),
        reactions=("Fe + H2SO4 -> FeSO4 + H2",),
        procedure=(
            _p("Add iron filings (in slight excess) to dilute sulphuric acid "
               "and warm gently.",
               "Excess iron is deliberate: any Fe(III) formed is reduced back "
               "to Fe(II) by metallic iron, and it guarantees no free acid is "
               "left to attack the product."),
            _p("Filter the hot solution quickly to remove undissolved iron "
               "and insoluble impurities.",
               "Hot, so ferrous sulphate does not crystallise in the filter; "
               "quickly, because a hot solution in contact with air oxidises "
               "fastest."),
            _p("Add a little dilute sulphuric acid to the filtrate.",
               "A slightly acid solution suppresses hydrolysis to basic "
               "ferric salts, which is what makes the product turn brown."),
            _p("Cool rapidly, protected from air, and collect the pale "
               "bluish-green crystals.",
               "Rapid cooling gives small crystals with less time exposed to "
               "oxygen. The colour is itself the purity check -- brown or "
               "yellow means Fe(III)."),
            _p("Wash with a little cold water, then with alcohol, and dry "
               "between filter papers at low temperature.",
               "Alcohol displaces water so drying is fast and cool; heat "
               "drives off water of crystallisation and promotes oxidation."),
        ),
        purification="Recrystallisation from water acidified with sulphuric "
                     "acid, in the presence of a little iron.",
        identification=(
            "Gives the reactions of ferrous salts: with potassium "
            "ferricyanide, a dark blue precipitate (Turnbull's blue).",
            "Gives the reactions of sulphate: with barium chloride, a white "
            "precipitate insoluble in dilute hydrochloric acid.",
        ),
        limit_tests=("Ferric iron -- the characteristic impurity, arising "
                     "from oxidation during preparation or storage.",),
        assay="Titration with standard cerium(IV) sulphate or potassium "
              "permanganate, which oxidises Fe(II) to Fe(III). Permanganate "
              "is self-indicating.",
        uses=("Haematinic in iron-deficiency anaemia",),
        storage="Well-filled, tightly closed containers -- well-filled so "
                "little air is enclosed, since oxidation is the failure mode.",
        note="Efflorescent and readily oxidised; the storage condition is "
             "part of the answer, not an afterthought."),

    Preparation(
        key="magnesium_sulphate",
        name="Magnesium sulphate (Epsom salt)",
        formula="MgSO4.7H2O",
        category="Saline cathartics",
        principle=(
            "Magnesium carbonate or magnesite is neutralised with dilute "
            "sulphuric acid; carbon dioxide is evolved and the soluble "
            "sulphate crystallises out."),
        reactions=("MgCO3 + H2SO4 -> MgSO4 + H2O + CO2",),
        procedure=(
            _p("Add magnesium carbonate in small portions to dilute "
               "sulphuric acid.",
               "In portions because the reaction effervesces vigorously; "
               "adding it all at once causes the vessel to froth over."),
            _p("Continue until effervescence ceases and a slight excess of "
               "carbonate remains.",
               "Excess carbonate ensures no free sulphuric acid is left, and "
               "the excess precipitates iron and other heavy metals as "
               "insoluble basic salts."),
            _p("Boil, then filter to remove the excess and the precipitated "
               "impurities.",
               "Boiling coagulates the precipitate so it filters cleanly "
               "rather than passing through."),
            _p("Concentrate the filtrate and allow to crystallise.",
               "Concentration to the point of saturation; the heptahydrate "
               "separates on cooling."),
            _p("Drain, wash with a little cold water, and dry in air at "
               "room temperature.",
               "Air drying only -- heat drives off water of crystallisation "
               "and gives a lower hydrate of different strength per gram."),
        ),
        purification="Recrystallisation from water.",
        identification=(
            "Gives the reactions of magnesium: with ammonium chloride, "
            "ammonia solution and disodium hydrogen phosphate, a white "
            "crystalline precipitate of magnesium ammonium phosphate.",
            "Gives the reactions of sulphate with barium chloride.",
        ),
        limit_tests=("Chloride, iron, heavy metals, arsenic.",),
        assay="Complexometric titration with disodium edetate using "
              "mordant black / eriochrome black T indicator at pH 10.",
        uses=("Saline purgative", "In eclampsia and as an anticonvulsant, "
              "parenterally", "Externally as a paste for boils"),
        storage="Well-closed container; it effloresces in dry air."),

    Preparation(
        key="magnesium_hydroxide",
        name="Magnesium hydroxide (milk of magnesia when a suspension)",
        formula="Mg(OH)2",
        category="Antacids",
        principle=(
            "A soluble magnesium salt is precipitated by an alkali. The "
            "product is a bulky gelatinous precipitate that is very hard to "
            "wash free of the sodium sulphate formed with it -- washing is "
            "the whole practical problem."),
        reactions=("MgSO4 + 2NaOH -> Mg(OH)2 + Na2SO4",),
        procedure=(
            _p("Prepare hot dilute solutions of magnesium sulphate and "
               "sodium hydroxide separately.",
               "Dilute and hot gives a denser, more granular precipitate; "
               "concentrated cold solutions give a slimy one that will not "
               "wash or filter."),
            _p("Add the alkali to the magnesium salt solution slowly with "
               "constant stirring.",
               "Slow addition with stirring keeps local excess of alkali "
               "low, which is what causes the precipitate to become "
               "gelatinous and occlude sulphate."),
            _p("Allow the precipitate to settle, then decant and wash "
               "repeatedly with hot distilled water.",
               "Washing by decantation rather than on the filter -- the "
               "gelatinous mass blocks the filter, and hot water washes "
               "sulphate out far faster than cold."),
            _p("Continue washing until the washings give no precipitate "
               "with barium chloride.",
               "That is the endpoint and the reason for the barium chloride: "
               "no white precipitate means no sulphate remains."),
            _p("Collect and either dry at a low temperature, or suspend in "
               "purified water to the required strength.",
               "Dried for the powder; suspended for milk of magnesia, which "
               "is officially about 7-8 percent w/v -- confirm the figure "
               "against your monograph."),
        ),
        purification="Repeated washing by decantation until free of sulphate.",
        identification=(
            "Dissolves in dilute acids with no effervescence -- distinguishing "
            "it from the carbonate, which fizzes.",
            "Gives the reactions of magnesium.",
        ),
        limit_tests=("Soluble alkalis, sulphate, chloride, calcium, heavy "
                     "metals.",),
        assay="Dissolve in excess standard acid and back-titrate the unused "
              "acid with standard alkali. Back-titration is used because the "
              "solid is insoluble and reacts too slowly for a direct one.",
        uses=("Antacid", "Mild laxative"),
        storage="Well-closed container; it absorbs carbon dioxide from the "
                "air and slowly converts to carbonate.",
        note="The distinction between the dried powder and the aqueous "
             "suspension is a common exam point -- name which you are making."),

    Preparation(
        key="aluminium_hydroxide_gel",
        name="Aluminium hydroxide gel",
        formula="Al(OH)3",
        category="Antacids",
        principle=(
            "Aluminium sulphate is precipitated by alkali under conditions "
            "controlled to give a hydrated gel rather than a crystalline "
            "solid -- the gel state is what gives it antacid activity and a "
            "usable texture."),
        reactions=("Al2(SO4)3 + 6NaOH -> 2Al(OH)3 + 3Na2SO4",),
        procedure=(
            _p("Prepare dilute solutions of aluminium sulphate and sodium "
               "carbonate or hydroxide.",
               "Dilute solutions are essential; concentrated ones give a "
               "dense precipitate with no gel character and little activity."),
            _p("Add the alkali slowly to the aluminium salt with vigorous "
               "stirring, keeping the pH controlled.",
               "Aluminium hydroxide is amphoteric -- it dissolves in excess "
               "alkali as the aluminate. Overshooting the pH destroys the "
               "product, which is why the alkali goes into the salt and not "
               "the reverse."),
            _p("Wash the gel thoroughly by decantation with purified water.",
               "To remove sodium sulphate. As with magnesium hydroxide, "
               "decantation rather than filtration, because the gel clogs."),
            _p("Adjust to the required concentration and add a preservative.",
               "The gel is an aqueous system and supports microbial growth."),
        ),
        purification="Washing by decantation until free of sulphate.",
        identification=("Gives the reactions of aluminium salts; dissolves in "
                        "both dilute acids and in sodium hydroxide solution, "
                        "demonstrating its amphoteric nature.",),
        limit_tests=("Sulphate, chloride, heavy metals, arsenic.",),
        assay="Complexometric, by adding excess disodium edetate and back-"
              "titrating with standard zinc sulphate.",
        uses=("Antacid, non-systemic and long-acting",
              "Phosphate binder in renal failure",
              "Adsorbent and adjuvant in vaccines"),
        storage="Well-closed container; do not allow to freeze, which breaks "
                "the gel structure irreversibly.",
        note="Aluminium hydroxide is amphoteric -- if an answer does not "
             "mention pH control, it has missed the point of the method."),

    Preparation(
        key="potassium_permanganate",
        name="Potassium permanganate",
        formula="KMnO4",
        category="Oxidising agents / antiseptics",
        principle=(
            "Manganese dioxide is fused with alkali in air to the green "
            "manganate, which is then oxidised further to the purple "
            "permanganate -- classically by carbon dioxide "
            "(disproportionation) or, industrially, electrolytically."),
        reactions=(
            "2MnO2 + 4KOH + O2 -> 2K2MnO4 + 2H2O",
            "3K2MnO4 + 2CO2 -> 2KMnO4 + MnO2 + 2K2CO3",
        ),
        procedure=(
            _p("Fuse finely powdered manganese dioxide with potassium "
               "hydroxide in an iron pan, with free access to air.",
               "Air supplies the oxygen for the first oxidation; an iron pan "
               "because the melt attacks porcelain and silica."),
            _p("Continue until the mass is green, then extract with water.",
               "Green is potassium manganate, the intermediate. Its colour "
               "is the in-process check on the first stage."),
            _p("Pass carbon dioxide through the solution, or oxidise "
               "electrolytically.",
               "The manganate disproportionates -- two thirds of the "
               "manganese is oxidised to permanganate and one third reduced "
               "back to MnO2. The electrolytic route avoids that loss, which "
               "is why industry uses it."),
            _p("Filter off the manganese dioxide and concentrate the purple "
               "filtrate.",
               "The MnO2 is a by-product of the disproportionation and is "
               "recycled to the fusion stage."),
            _p("Crystallise, collect the dark purple crystals, and dry at a "
               "low temperature away from organic matter.",
               "It is a powerful oxidiser -- contact with organic material "
               "during drying risks ignition, which is a safety point worth "
               "stating in an answer."),
        ),
        purification="Recrystallisation from water.",
        identification=(
            "Intense purple solution, decolourised by reducing agents such "
            "as ferrous salts, oxalic acid or hydrogen peroxide in acid.",
            "Gives the reactions of potassium.",
        ),
        limit_tests=("Chloride, sulphate, and matter insoluble in water.",),
        assay="Titration against standard oxalic acid or sodium oxalate in "
              "warm dilute sulphuric acid; self-indicating, the endpoint "
              "being the first permanent pink.",
        uses=("Antiseptic and disinfectant, in dilute solution",
              "Deodorant and oxidising agent",
              "Antidote by oxidation in certain poisonings",
              "Volumetric analytical reagent"),
        storage="Well-closed container, away from organic and readily "
                "oxidisable matter.",
        note="Never triturate with organic substances such as glycerol or "
             "sulphur -- it can ignite. This is examinable as an "
             "incompatibility."),

    Preparation(
        key="sodium_thiosulphate",
        name="Sodium thiosulphate",
        formula="Na2S2O3.5H2O",
        category="Antidotes / pharmaceutical aids",
        principle=(
            "Sulphur is boiled with a solution of sodium sulphite; the "
            "sulphite takes up one atom of sulphur to become thiosulphate."),
        reactions=("Na2SO3 + S -> Na2S2O3",),
        procedure=(
            _p("Boil finely divided (flowers of) sulphur with a solution of "
               "sodium sulphite under reflux.",
               "Finely divided sulphur for surface area -- the reaction is "
               "heterogeneous and slow. Reflux prevents loss of water and "
               "keeps the temperature at the boil for hours."),
            _p("Continue until most of the sulphur has dissolved, then filter "
               "off the excess.",
               "Excess sulphur is used to drive the reaction to completion; "
               "unreacted sulphur must be removed or it appears as an "
               "insoluble impurity."),
            _p("Concentrate the filtrate and allow to crystallise.",
               "The pentahydrate separates as large colourless prisms."),
            _p("Drain and dry in air at room temperature.",
               "It effloresces above about 33 degrees C and melts in its own "
               "water of crystallisation, so heat is not used."),
        ),
        purification="Recrystallisation from water.",
        identification=(
            "With dilute hydrochloric acid, sulphur dioxide is evolved and "
            "sulphur is slowly precipitated, turning the solution milky.",
            "Decolourises iodine solution.",
            "Gives the reactions of sodium.",
        ),
        limit_tests=("Sulphate, sulphide, chloride.",),
        assay="Titration with standard iodine solution using starch "
              "indicator; thiosulphate is oxidised to tetrathionate.",
        uses=("Antidote in cyanide poisoning, with sodium nitrite",
              "In the treatment of tinea versicolor, topically",
              "Antichlor and analytical reagent in iodometry"),
        storage="Well-closed container in a cool place."),

    Preparation(
        key="calcium_gluconate",
        name="Calcium gluconate",
        formula="Ca(C6H11O7)2",
        category="Calcium supplements",
        principle=(
            "Gluconic acid, obtained by the controlled oxidation or "
            "fermentation of glucose, is neutralised with calcium carbonate "
            "or calcium hydroxide."),
        reactions=("2C6H12O7 + CaCO3 -> Ca(C6H11O7)2 + H2O + CO2",),
        procedure=(
            _p("Obtain gluconic acid by fermenting glucose with Aspergillus "
               "niger, or by controlled oxidation of glucose.",
               "The fermentation route is the industrial one and gives a "
               "cleaner product than chemical oxidation, which over-oxidises "
               "to saccharic acid."),
            _p("Neutralise the gluconic acid solution with calcium carbonate, "
               "warming, until effervescence ceases.",
               "Effervescence ceasing is the endpoint -- carbon dioxide stops "
               "when all the acid is neutralised. A slight excess of "
               "carbonate ensures no free acid remains."),
            _p("Filter hot to remove excess carbonate and any insoluble "
               "matter.",
               "Hot, because calcium gluconate is markedly more soluble in "
               "hot water and would otherwise crystallise in the filter."),
            _p("Concentrate the filtrate and allow to crystallise.",
               "The salt separates as a white crystalline or granular "
               "powder."),
            _p("Wash, and dry at a moderate temperature.",
               "It is stable to gentle heat, unlike the hydrated inorganic "
               "salts."),
        ),
        purification="Recrystallisation from water; decolourise with "
                     "activated charcoal if the fermentation liquor is "
                     "coloured.",
        identification=(
            "Gives the reactions of calcium: with ammonium oxalate, a white "
            "precipitate insoluble in acetic acid but soluble in "
            "hydrochloric acid.",
            "Gives a characteristic reaction for gluconate on warming with "
            "acetyl chloride, and forms a phenylhydrazide derivative of "
            "defined melting point.",
        ),
        limit_tests=("Chloride, sulphate, reducing sugars, heavy metals.",),
        assay="Complexometric titration with disodium edetate.",
        uses=("Calcium supplement in deficiency, tetany and rickets",
              "Intravenously in acute hypocalcaemia and as an antidote in "
              "hydrofluoric acid burns and magnesium overdose"),
        storage="Well-closed container.",
        note="Its low irritancy compared with calcium chloride is why it is "
             "the salt chosen for injection -- a likely 'why this salt' mark."),

    Preparation(
        key="sodium_bicarbonate",
        name="Sodium bicarbonate",
        formula="NaHCO3",
        category="Antacids / electrolytes",
        principle=(
            "The Solvay (ammonia-soda) process. Carbon dioxide is passed "
            "into brine saturated with ammonia; sodium bicarbonate is the "
            "least soluble species present and precipitates out."),
        reactions=("NaCl + NH3 + CO2 + H2O -> NaHCO3 + NH4Cl",),
        procedure=(
            _p("Saturate a strong brine solution with ammonia.",
               "Ammonia first, then carbon dioxide: ammoniated brine absorbs "
               "far more CO2 than plain brine, because the ammonia keeps the "
               "solution alkaline and drives the equilibrium."),
            _p("Pass carbon dioxide through the ammoniated brine in a "
               "carbonating tower, cooled.",
               "Cooling because the reaction is exothermic and because "
               "sodium bicarbonate is less soluble cold, which is what makes "
               "it precipitate."),
            _p("Filter off the precipitated sodium bicarbonate and wash with "
               "a little cold water.",
               "Cold water, and only a little -- the product is appreciably "
               "soluble and washing loses yield."),
            _p("Dry at a temperature below 50 degrees C.",
               "Above this it decomposes to sodium carbonate, carbon dioxide "
               "and water, so the product would assay as the wrong "
               "substance."),
        ),
        purification="Redissolve in water, filter, and reprecipitate by "
                     "passing carbon dioxide; or recrystallise carefully "
                     "below 50 degrees C.",
        identification=(
            "Effervesces with dilute acids, evolving carbon dioxide which "
            "turns limewater milky.",
            "Aqueous solution is alkaline to litmus but does not give a red "
            "colour with phenolphthalein in the cold -- distinguishing "
            "bicarbonate from carbonate.",
            "Gives the reactions of sodium; yellow flame.",
        ),
        limit_tests=("Chloride, sulphate, carbonate, heavy metals, arsenic.",),
        assay="Titration with standard hydrochloric acid using methyl orange "
              "as indicator.",
        uses=("Antacid, systemic and rapid-acting",
              "In the treatment of metabolic acidosis",
              "Component of effervescent preparations",
              "Alkalinising agent to make urine alkaline"),
        storage="Well-closed container in a cool dry place.",
        note="The phenolphthalein test distinguishing bicarbonate from "
             "carbonate is asked often; carbonate gives a pink colour cold, "
             "bicarbonate does not."),

    Preparation(
        key="potassium_iodide",
        name="Potassium iodide",
        formula="KI",
        category="Expectorants / antithyroid",
        principle=(
            "Iodine is dissolved in potassium hydroxide, which gives a "
            "mixture of iodide and iodate. The iodate is then reduced to "
            "iodide -- otherwise five sixths of the potassium is wasted."),
        reactions=(
            "6KOH + 3I2 -> 5KI + KIO3 + 3H2O",
            "KIO3 + 3C -> KI + 3CO",
        ),
        procedure=(
            _p("Dissolve iodine in a solution of potassium hydroxide until "
               "the colour is discharged.",
               "The disappearance of the iodine colour is the endpoint; "
               "excess iodine would remain free in the product."),
            _p("Evaporate to dryness.",
               "Leaves the mixed iodide and iodate as a dry solid ready for "
               "reduction."),
            _p("Mix the residue with charcoal (or wood charcoal) and heat to "
               "dull redness.",
               "Carbon reduces the iodate to iodide. Without this step the "
               "yield is only five sixths and the product is contaminated "
               "with iodate."),
            _p("Extract with water, filter, concentrate, and crystallise.",
               "Water dissolves the potassium iodide away from the excess "
               "charcoal, which is filtered off."),
            _p("Dry the colourless cubical crystals.",
               "Colourless is the check -- a yellow tinge means free iodine "
               "from decomposition."),
        ),
        purification="Recrystallisation from water; a trace of alkali "
                     "prevents liberation of free iodine.",
        identification=(
            "With chlorine water, free iodine is liberated, giving a blue "
            "colour with starch mucilage.",
            "With silver nitrate, a yellow precipitate insoluble in ammonia "
            "-- distinguishing iodide from chloride and bromide.",
            "Gives the reactions of potassium; violet flame.",
        ),
        limit_tests=("Iodate, cyanide, thiosulphate, chloride and bromide.",),
        assay="Titration with standard silver nitrate, or iodometrically "
              "after oxidation.",
        uses=("Expectorant", "In hyperthyroidism, before thyroidectomy",
              "In the prophylaxis of iodine deficiency",
              "Source of iodide in Lugol's solution and as a solubiliser "
              "for iodine"),
        storage="Well-closed container, protected from light -- light and "
                "air liberate free iodine, and the product turns yellow.",
        note="Free iodine is the characteristic impurity on storage; the "
             "yellow colour is the visible sign."),

    Preparation(
        key="barium_sulphate",
        name="Barium sulphate",
        formula="BaSO4",
        category="Diagnostic agents",
        principle=(
            "A soluble barium salt is precipitated by a soluble sulphate. "
            "The point of the preparation is not the chemistry, which is "
            "trivial, but the complete removal of every soluble barium "
            "compound -- soluble barium is highly toxic."),
        reactions=("BaCl2 + Na2SO4 -> BaSO4 + 2NaCl",),
        procedure=(
            _p("Prepare dilute solutions of barium chloride and sodium "
               "sulphate.",
               "Dilute solutions give a fine, uniform precipitate that "
               "suspends well -- essential for a radiographic contrast "
               "medium, which must not sediment in the gut."),
            _p("Add the sulphate solution to the barium solution with "
               "constant stirring, keeping the sulphate in slight excess.",
               "Excess sulphate, never excess barium: the excess reagent "
               "must be the harmless one. This is the safety-critical "
               "direction of addition."),
            _p("Wash the precipitate repeatedly with hot water until the "
               "washings are free of chloride.",
               "Tested with silver nitrate. Any soluble barium remaining is "
               "a poisoning risk when the product is swallowed in bulk."),
            _p("Dry and, if required, sterilise; then test for soluble "
               "barium salts.",
               "The test for acid-soluble barium is a pharmacopoeial "
               "requirement, not an optional check -- deaths have followed "
               "contaminated batches."),
        ),
        purification="Exhaustive washing until free of chloride and of "
                     "acid-soluble barium.",
        identification=(
            "Insoluble in water and in dilute acids -- the property that "
            "makes it safe to swallow.",
            "After fusion with sodium carbonate and extraction, gives the "
            "reactions of barium and of sulphate.",
        ),
        limit_tests=("Soluble barium salts, acid-soluble substances, sulphide, "
                     "heavy metals. Soluble barium is the critical one.",),
        assay="Gravimetric, or by the pharmacopoeial method for the "
              "monograph.",
        uses=("X-ray contrast medium for the gastrointestinal tract",),
        storage="Well-closed container.",
        note="Its complete insolubility is the whole basis of its safety. "
             "The contrast comes from the high atomic number of barium "
             "absorbing X-rays."),

    Preparation(
        key="hydrogen_peroxide",
        name="Hydrogen peroxide solution",
        formula="H2O2",
        category="Antiseptics / oxidising agents",
        principle=(
            "Barium peroxide is decomposed by an acid. Sulphuric acid is "
            "chosen because the barium sulphate formed is insoluble and "
            "filters off, leaving the peroxide in solution with no "
            "by-product to remove."),
        reactions=("BaO2 + H2SO4 -> BaSO4 + H2O2",),
        procedure=(
            _p("Make a thin paste of hydrated barium peroxide with ice-cold "
               "water.",
               "Ice-cold throughout: hydrogen peroxide decomposes readily, "
               "and the reaction is exothermic. The hydrate is used because "
               "anhydrous BaO2 reacts sluggishly and coats itself."),
            _p("Add dilute sulphuric acid slowly with stirring, keeping the "
               "mixture cold.",
               "Slow addition keeps the temperature down. Local excess of "
               "acid and any rise in temperature destroy the product as it "
               "forms."),
            _p("Filter off the barium sulphate.",
               "The insolubility of BaSO4 is why sulphuric acid was chosen "
               "-- the by-product removes itself."),
            _p("Add a trace of a stabiliser such as acetanilide or "
               "phosphoric acid, and adjust the strength.",
               "Traces of metals and alkali catalyse decomposition; the "
               "stabiliser and a slightly acid pH suppress it."),
        ),
        purification="Filtration from barium sulphate; the solution is not "
                     "distilled at atmospheric pressure, which is dangerous.",
        identification=(
            "With acidified potassium dichromate and ether, a blue colour "
            "(perchromic acid) in the ether layer.",
            "Liberates iodine from acidified potassium iodide.",
            "Decolourises acidified potassium permanganate, with oxygen "
            "evolved.",
        ),
        limit_tests=("Free acid, barium, heavy metals, and non-volatile "
                     "matter.",),
        assay="Titration with standard potassium permanganate in dilute "
              "sulphuric acid; self-indicating.",
        uses=("Antiseptic and deodorant, especially for wounds -- the "
              "effervescence mechanically dislodges debris",
              "Mouthwash and ear drops, diluted",
              "Bleaching agent"),
        storage="In a cool place, in containers with a vent, protected from "
                "light. Oxygen is evolved on decomposition and a sealed "
                "container can burst.",
        note="Strength is expressed in volumes -- '20 volume' means one "
             "volume liberates twenty volumes of oxygen. Converting between "
             "volume strength and percentage is a standard calculation: "
             "percentage w/v is approximately volume strength divided by "
             "3.38."),

    Preparation(
        key="calcium_carbonate",
        name="Precipitated calcium carbonate",
        formula="CaCO3",
        category="Antacids",
        principle=(
            "Limestone is calcined to quicklime, slaked to calcium "
            "hydroxide, and reprecipitated with carbon dioxide -- the round "
            "trip exists to purify the calcium and control particle size."),
        reactions=(
            "CaCO3 -> CaO + CO2",
            "CaO + H2O -> Ca(OH)2",
            "Ca(OH)2 + CO2 -> CaCO3 + H2O",
        ),
        procedure=(
            _p("Calcine limestone at high temperature to give quicklime, "
               "collecting the carbon dioxide.",
               "The CO2 evolved is used again in the last stage -- the "
               "process is self-supplying, which is worth stating."),
            _p("Slake the quicklime with water to give milk of lime, and "
               "filter.",
               "Slaking is vigorously exothermic. Filtration removes silica, "
               "iron and unburnt material -- this is where the purification "
               "actually happens."),
            _p("Pass carbon dioxide through the filtered milk of lime with "
               "stirring, controlling temperature and concentration.",
               "Temperature and concentration determine crystal form and "
               "particle size, which set the bulk density -- light against "
               "heavy calcium carbonate are the same chemistry and different "
               "products."),
            _p("Filter, wash, and dry the precipitate.",
               "Washing removes any remaining soluble alkali."),
        ),
        purification="The calcination-slaking-recarbonation cycle is itself "
                     "the purification.",
        identification=(
            "Effervesces with dilute acids, evolving CO2 that turns limewater "
            "milky.",
            "Gives the reactions of calcium; brick-red flame.",
        ),
        limit_tests=("Chloride, sulphate, iron, heavy metals, arsenic, "
                     "matter insoluble in acid.",),
        assay="Complexometric titration with disodium edetate, or by "
              "dissolving in excess standard acid and back-titrating.",
        uses=("Antacid", "Calcium supplement", "Tablet diluent",
              "Mild abrasive in dentifrices"),
        storage="Well-closed container."),

    Preparation(
        key="silver_nitrate",
        name="Silver nitrate",
        formula="AgNO3",
        category="Astringents / caustics",
        principle=(
            "Silver is dissolved in nitric acid. Copper is the impurity that "
            "matters, and it is removed by taking advantage of the different "
            "thermal stability of the two nitrates."),
        reactions=("Ag + 2HNO3 -> AgNO3 + NO2 + H2O",),
        procedure=(
            _p("Dissolve silver in dilute nitric acid, warming, in a fume "
               "cupboard.",
               "Oxides of nitrogen are evolved and are toxic -- the fume "
               "cupboard is part of the method, not a general precaution."),
            _p("Evaporate to dryness and gently fuse the residue.",
               "Copper nitrate decomposes to the black insoluble oxide at a "
               "temperature at which silver nitrate is still stable. That "
               "difference is the separation."),
            _p("Dissolve the fused mass in water and filter off the copper "
               "oxide.",
               "Silver nitrate dissolves; cupric oxide does not."),
            _p("Concentrate and crystallise; dry and store away from light.",
               "Colourless transparent plates. Light reduces it to metallic "
               "silver, which is why it darkens."),
        ),
        purification="Fusion to decompose copper nitrate, followed by "
                     "recrystallisation from water.",
        identification=(
            "With hydrochloric acid, a curdy white precipitate soluble in "
            "ammonia.",
            "Gives the reactions of nitrate: brown ring test with ferrous "
            "sulphate and concentrated sulphuric acid.",
        ),
        limit_tests=("Copper, lead, bismuth, and foreign salts.",),
        assay="Titration with standard ammonium or potassium thiocyanate "
              "using ferric ammonium sulphate as indicator (Volhard).",
        uses=("Caustic and astringent, for warts and granulation tissue",
              "Formerly in ophthalmia neonatorum prophylaxis",
              "Analytical reagent"),
        storage="Well-closed, light-resistant container -- it is darkened by "
                "light and stains skin and fabric black.",
        note="Handle with care: it is corrosive and stains indelibly. The "
            "stain is metallic silver, which is why it will not wash out."),

    Preparation(
        key="bleaching_powder",
        name="Bleaching powder (chlorinated lime)",
        formula="CaOCl2",
        category="Disinfectants",
        principle=(
            "Slaked lime absorbs chlorine to give a mixed calcium "
            "chloride-hypochlorite. Its activity is measured as 'available "
            "chlorine', not as a percentage of the compound."),
        reactions=("Ca(OH)2 + Cl2 -> CaOCl2 + H2O",),
        procedure=(
            _p("Spread dry slaked lime in thin layers in a chlorinating "
               "chamber.",
               "Thin layers and dry lime: the reaction is a gas-solid one, "
               "so surface area governs it, and moisture causes the product "
               "to decompose as it forms."),
            _p("Pass chlorine gas over the lime, counter-current, at a "
               "controlled low temperature.",
               "Counter-current gives the most complete absorption. The "
               "reaction is exothermic and heat decomposes hypochlorite to "
               "chlorate, which has no disinfectant value."),
            _p("Continue until the required available chlorine content is "
               "reached, then pack immediately.",
               "The product loses chlorine continuously on exposure to air, "
               "moisture and light, so it is packed as made."),
        ),
        purification="Not purified; controlled by available chlorine assay.",
        identification=(
            "Smells of chlorine; liberates chlorine on treatment with dilute "
            "acids.",
            "Bleaches litmus and indigo solution.",
            "Liberates iodine from potassium iodide.",
        ),
        limit_tests=("Chlorate and calcium chlorate content.",),
        assay="Iodometric: liberate iodine from potassium iodide with a "
              "known weight and titrate with standard sodium thiosulphate. "
              "Reported as percentage available chlorine, which must be not "
              "less than the monograph figure.",
        uses=("Disinfectant for water and sanitation",
              "Deodorant", "Bleaching agent"),
        storage="Well-closed, light-resistant containers in a cool place. "
                "It deteriorates rapidly, losing available chlorine.",
        note="'Available chlorine' is the examinable concept -- the "
             "substance is a variable mixture, so it is specified by what it "
             "can do rather than by what it is."),

    Preparation(
        key="copper_sulphate",
        name="Copper sulphate",
        formula="CuSO4.5H2O",
        category="Astringents / antidotes",
        principle=(
            "Copper oxide, or copper scrap oxidised in air, is dissolved in "
            "dilute sulphuric acid and the blue pentahydrate crystallised."),
        reactions=("CuO + H2SO4 -> CuSO4 + H2O",),
        procedure=(
            _p("Add copper oxide to hot dilute sulphuric acid until a slight "
               "excess remains undissolved.",
               "Excess oxide guarantees no free acid in the product, which "
               "would otherwise attack the container and irritate on use."),
            _p("Filter the hot solution.",
               "Removes the excess oxide and insoluble impurities before "
               "crystallisation locks them into the crystals."),
            _p("Concentrate and allow to crystallise slowly.",
               "Slow crystallisation gives the large blue triclinic crystals "
               "characteristic of the pentahydrate."),
            _p("Drain and dry in air at room temperature.",
               "Heat drives off water of crystallisation, turning the "
               "crystals white -- the anhydrous salt is a different "
               "substance with a different assay per gram."),
        ),
        purification="Recrystallisation from water acidified with a little "
                     "sulphuric acid.",
        identification=(
            "Blue solution; with ammonia, a pale blue precipitate dissolving "
            "in excess to a deep blue solution.",
            "With potassium ferrocyanide, a reddish-brown precipitate.",
            "Gives the reactions of sulphate.",
        ),
        limit_tests=("Iron, chloride, and alkali metals.",),
        assay="Iodometric: copper(II) liberates iodine from potassium "
              "iodide, titrated with standard sodium thiosulphate.",
        uses=("Astringent and fungicide, externally",
              "Emetic, historically -- now largely abandoned as unsafe",
              "Antidote in phosphorus poisoning",
              "Analytical reagent, including Fehling's solution"),
        storage="Well-closed container; it effloresces in dry air.",
        note="Blue for the pentahydrate, white for the anhydrous salt -- "
             "the colour change on heating is a standard identification."),
]

PREPARATIONS = {prep.key: prep for prep in _PREPARATIONS}


def categories() -> list:
    return sorted({prep.category for prep in _PREPARATIONS})


def find(text: str) -> list:
    needle = text.lower().strip()
    return [prep for prep in _PREPARATIONS
            if needle in prep.key.lower()
            or needle in prep.name.lower()
            or needle in prep.formula.lower()
            or needle in prep.category.lower()
            or any(needle in use.lower() for use in prep.uses)]


def show(key: str) -> str:
    """One substance, laid out in the order an answer is marked in."""
    if key not in PREPARATIONS:
        matches = find(key)
        if len(matches) == 1:
            key = matches[0].key
        else:
            raise KeyError("no preparation %r; try find(%r)" % (key, key))
    p = PREPARATIONS[key]
    out = [
           "EXAM THEORY - LEGACY ENTRY; VERIFY AGAINST THE PRESCRIBED TEXT",
           "NOT A LABORATORY OR MANUFACTURING PROTOCOL.", "",
           "%s   %s   [%s]" % (p.name, p.formula, p.category), "",
           "PRINCIPLE", "  %s" % p.principle, "", "REACTION"]
    out += ["  %s" % reaction for reaction in p.reactions]
    out += ["", "PROCEDURE"]
    for index, (step, why) in enumerate(p.procedure, start=1):
        out.append("  %d. %s" % (index, step))
        out.append("     why: %s" % why)
    if p.purification:
        out += ["", "PURIFICATION", "  %s" % p.purification]
    if p.identification:
        out += ["", "IDENTIFICATION"]
        out += ["  - %s" % test for test in p.identification]
    if p.limit_tests:
        out += ["", "LIMIT TESTS"]
        out += ["  - %s" % test for test in p.limit_tests]
    if p.assay:
        out += ["", "ASSAY", "  %s" % p.assay]
    if p.uses:
        out += ["", "USES"]
        out += ["  - %s" % use for use in p.uses]
    if p.storage:
        out += ["", "STORAGE", "  %s" % p.storage]
    if p.note:
        out += ["", "NOTE", "  %s" % p.note]
    return "\n".join(out)
