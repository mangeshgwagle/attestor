"""Methods of preparation: how a dosage form is actually made.

The calculation is the easy half. The method -- what you do, in what order,
and why that order -- is what carries the marks, and it is the part that
tends not to be written down anywhere convenient.

Each method here is a sequence of steps. Every step carries a `why`, because
in a written answer the reason is what separates a pass from a good mark:
"levigate the powder" is a step, "levigate the powder with a small quantity
of the vehicle to break down aggregates before the bulk is added" is an
answer.

What makes this checkable
-------------------------
Order is not decoration in compounding. Several steps have hard
prerequisites -- you cannot levigate after adding the bulk vehicle, you
cannot add the oil phase before both phases are at the same temperature --
and getting them the wrong way round is the single most common way to lose
marks and to ruin a preparation. So each step can declare what must already
have happened, and `check_order` verifies the sequence satisfies every one.
A method with its steps transposed fails that check rather than reading
plausibly.

Scope, stated honestly
----------------------
These are the *general methods*, which is what a written exam asks for and
what is common across pharmacopoeias. Specific quantities, official
formulae, and the monograph for any named preparation come from your
pharmacopoeia -- IP, BP or USP as your course uses -- and not from here.
Where a step depends on a particular monograph, it says so rather than
inventing a number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Step", "Method", "METHODS", "check_order", "find", "show",
           "topics", "OrderError"]


class OrderError(ValueError):
    """A method's steps are in an order that would not work."""


@dataclass(frozen=True)
class Step:
    """One operation, why it is done, and what must precede it."""

    action: str
    why: str
    after: tuple = ()          # tags of steps that must already have happened
    tag: str = ""              # this step's own tag, if others depend on it


@dataclass(frozen=True)
class Method:
    key: str
    form: str
    name: str
    principle: str
    apparatus: tuple
    steps: tuple
    critical: tuple = ()
    errors: tuple = ()
    note: str = ""


def _s(action, why, after=(), tag=""):
    return Step(action, why, tuple(after), tag)


# --------------------------------------------------------------------------- #

_METHODS = [
    Method(
        key="solution_simple",
        form="Solutions",
        name="Simple solution by dissolution",
        principle=(
            "The solute is dissolved in a portion of the vehicle and the "
            "volume adjusted afterwards -- never dissolved in the full "
            "volume, because a solid occupies volume once dissolved."),
        apparatus=("beaker", "stirring rod", "measuring cylinder",
                   "volumetric flask or graduated bottle", "filter paper"),
        steps=(
            _s("Weigh the solute accurately on a calibrated balance.",
               "The strength of the whole preparation follows from this one "
               "weighing; an error here cannot be corrected later.",
               tag="weighed"),
            _s("Dissolve the solute in about two-thirds to three-quarters of "
               "the vehicle in a beaker, stirring.",
               "Dissolving in part of the vehicle leaves room to make up to "
               "the final volume. Dissolving in the whole volume overshoots, "
               "because the dissolved solid contributes volume.",
               after=("weighed",), tag="dissolved"),
            _s("Add any adjuvants -- preservative, colour, flavour -- and "
               "stir until dissolved.",
               "Added after the principal solute so its dissolution is not "
               "hindered, and so the solution can be seen to be clear.",
               after=("dissolved",), tag="adjuvants"),
            _s("Transfer to a measuring cylinder or volumetric flask and "
               "make up to the final volume with the vehicle, rinsing the "
               "beaker into it.",
               "Rinsing carries over solute left on the glass; skipping it "
               "under-doses the preparation.",
               after=("adjuvants",), tag="volume_adjusted"),
            _s("Filter if required, into a clean dry bottle.",
               "Solutions must be clear; filtration removes undissolved "
               "particles and fibres.",
               after=("volume_adjusted",), tag="filtered"),
            _s("Label: name, strength, quantity, directions, storage, "
               "date and 'Shake well' only if appropriate.",
               "Labelling is examinable and is part of the preparation, not "
               "an afterthought. A solution does not carry 'Shake well'.",
               after=("filtered",)),
        ),
        critical=(
            "Make to volume at the end, never dissolve in the final volume.",
            "Rinse the beaker into the measure so no solute is lost.",
            "Check for clarity before labelling.",
        ),
        errors=(
            "Dissolving in the full volume, which gives a weak preparation.",
            "Labelling a solution 'Shake well' -- that belongs on a "
            "suspension and its presence suggests you do not know which you "
            "have made.",
        )),

    Method(
        key="suspension",
        form="Suspensions",
        name="Suspension by trituration and levigation",
        principle=(
            "An insoluble solid is reduced in particle size and wetted with "
            "a levigating agent before the vehicle is added, so it disperses "
            "instead of floating or caking."),
        apparatus=("mortar and pestle", "measuring cylinder", "beaker",
                   "graduated bottle"),
        steps=(
            _s("Weigh the insoluble solid and transfer to a dry mortar.",
               "A dry mortar first -- water added early turns the powder to "
               "a paste that cannot be triturated.",
               tag="in_mortar"),
            _s("Triturate to reduce particle size.",
               "Smaller particles settle more slowly (Stokes' law: rate of "
               "sedimentation is proportional to the square of the particle "
               "radius) and redisperse more readily.",
               after=("in_mortar",), tag="triturated"),
            _s("Add the levigating or wetting agent and levigate to a smooth "
               "paste.",
               "Wetting the powder displaces adsorbed air, which is what "
               "otherwise makes a hydrophobic powder float on the vehicle.",
               after=("triturated",), tag="levigated"),
            _s("Add the suspending agent, previously dispersed, and mix.",
               "The suspending agent raises the viscosity of the continuous "
               "phase, which slows sedimentation -- again by Stokes' law.",
               after=("levigated",), tag="suspending_added"),
            _s("Add the vehicle in small portions with continuous "
               "trituration, transferring to a measure.",
               "Small portions keep the paste smooth; adding the bulk at "
               "once leaves lumps that never disperse.",
               after=("suspending_added",), tag="vehicle_added"),
            _s("Rinse the mortar with vehicle into the measure and make up "
               "to volume.",
               "The mortar retains a significant quantity of the solid.",
               after=("vehicle_added",), tag="volume_adjusted"),
            _s("Label, including 'Shake well before use'.",
               "A suspension is a disperse system; the dose is only uniform "
               "after shaking, so the direction is part of the preparation.",
               after=("volume_adjusted",)),
        ),
        critical=(
            "Triturate dry, then levigate, then add vehicle -- in that order.",
            "Add the vehicle in portions, not all at once.",
            "'Shake well before use' is compulsory.",
        ),
        errors=(
            "Adding the vehicle before levigating, which gives a lumpy "
            "product that cannot be rescued.",
            "Omitting 'Shake well', which costs marks every time.",
        )),

    Method(
        key="emulsion_dry_gum",
        form="Emulsions",
        name="Dry gum method (continental, 4:2:1)",
        principle=(
            "The emulsifying agent is mixed with the oil first, then all the "
            "water for the primary emulsion is added in one portion and "
            "triturated in one direction until it cracks -- forming a "
            "primary emulsion which is then diluted."),
        apparatus=("dry porcelain mortar and pestle", "measuring cylinder",
                   "graduated bottle"),
        steps=(
            _s("Use a completely dry mortar and pestle.",
               "Any water present starts the emulsion prematurely and the "
               "primary emulsion will not form.",
               tag="dry_mortar"),
            _s("Triturate the gum (acacia) with the oil until evenly mixed.",
               "This is what makes it the *dry* gum method: the gum meets "
               "the oil before it meets any water.",
               after=("dry_mortar",), tag="gum_in_oil"),
            _s("Add the calculated water for the primary emulsion all at "
               "once -- 4 parts oil : 2 parts water : 1 part gum for a "
               "fixed oil.",
               "All at once, not in portions: a partial addition will not "
               "form the primary emulsion. The 4:2:1 ratio changes for "
               "mineral (3:2:1) and volatile (2:2:1) oils.",
               after=("gum_in_oil",), tag="water_added"),
            _s("Triturate rapidly and continuously in one direction until a "
               "characteristic clicking sound is heard and the mixture is "
               "white and creamy.",
               "The click and the colour change are the endpoint -- they "
               "indicate the primary emulsion has formed. Reversing "
               "direction breaks it.",
               after=("water_added",), tag="primary_formed"),
            _s("Add the remaining water in small portions with continuous "
               "trituration.",
               "Dilution only after the primary emulsion is made; adding "
               "bulk water earlier cracks it.",
               after=("primary_formed",), tag="diluted"),
            _s("Incorporate any other soluble ingredients dissolved in a "
               "little water, transfer, and make up to volume.",
               "Added to the external phase so the emulsion is not stressed.",
               after=("diluted",), tag="volume_adjusted"),
            _s("Label, including 'Shake well before use'.",
               "An emulsion is a disperse system and may cream on standing.",
               after=("volume_adjusted",)),
        ),
        critical=(
            "The mortar must be dry.",
            "Primary emulsion water goes in all at once.",
            "Triturate in one direction only until the click.",
            "4:2:1 fixed oil, 3:2:1 mineral oil, 2:2:1 volatile oil.",
        ),
        errors=(
            "Adding the primary water in portions -- the emulsion never "
            "forms and the whole preparation is wasted.",
            "Using a damp mortar.",
            "Quoting one ratio for every oil type.",
        )),

    Method(
        key="emulsion_wet_gum",
        form="Emulsions",
        name="Wet gum method (English)",
        principle=(
            "A mucilage of the gum is made first, and the oil is added to it "
            "in small portions -- the reverse order to the dry gum method."),
        apparatus=("mortar and pestle", "measuring cylinder"),
        steps=(
            _s("Triturate the gum with the primary emulsion water to form a "
               "mucilage.",
               "The gum is hydrated before it meets any oil, which is what "
               "makes this the *wet* gum method.",
               tag="mucilage"),
            _s("Add the oil in small portions with continuous trituration.",
               "Small portions let each addition be emulsified before the "
               "next arrives; a bulk addition cannot be dispersed.",
               after=("mucilage",), tag="oil_added"),
            _s("Triturate until the primary emulsion is formed.",
               "Same endpoint as the dry gum method -- white, creamy, and a "
               "characteristic sound.",
               after=("oil_added",), tag="primary_formed"),
            _s("Dilute with the remaining water and make up to volume.",
               "Dilution comes only after the primary emulsion exists; bulk "
               "water added to an unformed emulsion cracks it, exactly as in "
               "the dry gum method.",
               after=("primary_formed",), tag="volume_adjusted"),
            _s("Label, including 'Shake well before use'.",
               "An emulsion is a thermodynamically unstable disperse system "
               "and may cream on standing, so the dose is only uniform after "
               "shaking.",
               after=("volume_adjusted",)),
        ),
        critical=(
            "Mucilage first, then oil in portions -- the opposite of dry gum.",
            "Slower than the dry gum method, which is why dry gum is "
            "preferred when a mortar can be kept dry.",
        ),
        errors=("Confusing the two orders in a written answer -- name the "
                "method and then be consistent with it.",)),

    Method(
        key="ointment_fusion",
        form="Semisolids",
        name="Ointment by fusion",
        principle=(
            "The bases are melted together, the medicament incorporated, and "
            "the mixture stirred until cold -- used when the bases have "
            "different melting points or the drug is soluble in the base."),
        apparatus=("porcelain dish or water bath", "spatula", "ointment slab",
                   "thermometer"),
        steps=(
            _s("Melt the base with the highest melting point first, on a "
               "water bath.",
               "Melting the highest first means the others melt on contact "
               "without the mixture being overheated.",
               tag="highest_melted"),
            _s("Add the remaining bases in descending order of melting "
               "point, stirring.",
               "Each is added to a melt already hot enough to take it.",
               after=("highest_melted",), tag="bases_melted"),
            _s("Remove from the heat before adding volatile or thermolabile "
               "ingredients.",
               "Volatile substances are lost and thermolabile ones decompose "
               "if added to a hot melt -- this is a marked point.",
               after=("bases_melted",), tag="off_heat"),
            _s("Incorporate the medicament, dissolved or finely dispersed.",
               "A soluble drug is dissolved in the melt; an insoluble one is "
               "levigated first so it does not give a gritty product.",
               after=("off_heat",), tag="drug_added"),
            _s("Stir continuously until cold and congealed.",
               "Continuous stirring prevents the separate bases from "
               "crystallising out in layers as they cool.",
               after=("drug_added",), tag="stirred_cold"),
            _s("Transfer to a wide-mouthed ointment jar and label.",
               "For external use; the label must say so.",
               after=("stirred_cold",)),
        ),
        critical=(
            "Highest melting point first.",
            "Off the heat before volatiles.",
            "Stir until cold, not just until mixed.",
        ),
        errors=(
            "Adding volatile ingredients to a hot melt.",
            "Stopping stirring while still warm, giving a grainy ointment.",
        )),

    Method(
        key="ointment_trituration",
        form="Semisolids",
        name="Ointment by trituration (levigation)",
        principle=(
            "An insoluble solid is levigated with a small quantity of base "
            "or a levigating agent, then incorporated into the remaining "
            "base on a slab -- used when heat is not wanted."),
        apparatus=("ointment slab or tile", "spatula", "mortar and pestle"),
        steps=(
            _s("Reduce the medicament to a fine powder and pass through a "
               "sieve if the monograph requires it.",
               "Particle size determines whether the finished ointment feels "
               "smooth or gritty.",
               tag="powdered"),
            _s("Levigate the powder on the slab with a small quantity of the "
               "base or a levigating agent.",
               "Levigation wets the particles and breaks aggregates before "
               "the bulk base is added; afterwards it is too stiff to do so.",
               after=("powdered",), tag="levigated"),
            _s("Incorporate the remaining base by geometric dilution, "
               "working with the spatula.",
               "Doubling the quantity each time is what makes the "
               "distribution uniform; adding the bulk at once does not mix.",
               after=("levigated",), tag="geometric"),
            _s("Work the mass until homogeneous, with no streaks or "
               "grittiness.",
               "Uniformity is the specification for a semisolid.",
               after=("geometric",), tag="uniform"),
            _s("Pack into a jar and label 'For external use only'.",
               "Required on topical preparations.",
               after=("uniform",)),
        ),
        critical=("Levigate before adding bulk base.",
                  "Geometric dilution, not bulk addition."),
        errors=("Adding all the base at once, giving streaks.",)),

    Method(
        key="suppository_fusion",
        form="Suppositories",
        name="Suppositories by fusion moulding",
        principle=(
            "The base is melted, the drug incorporated, and the mixture "
            "poured into a lubricated mould -- with the quantity corrected "
            "by the displacement value of the drug."),
        apparatus=("suppository mould", "water bath", "porcelain dish",
                   "spatula"),
        steps=(
            _s("Calibrate the mould and calculate the quantity of base using "
               "the displacement value of the drug.",
               "The drug displaces its own volume of base; ignoring the "
               "displacement value gives suppositories of the wrong weight "
               "and dose. This is the calculation most often examined.",
               tag="calculated"),
            _s("Lubricate the mould with a suitable agent and let it drain.",
               "The lubricant must be one the base does not dissolve in -- "
               "soft soap or glycerin for a fatty base, liquid paraffin for "
               "a water-soluble one.",
               after=("calculated",), tag="mould_ready"),
            _s("Melt about two-thirds of the base on a water bath, gently.",
               "Only part, and gently: an overheated fatty base develops "
               "unstable polymorphs and the suppositories will not set.",
               after=("mould_ready",), tag="base_melted"),
            _s("Incorporate the finely powdered drug, then add the remaining "
               "base.",
               "The reserved base cools the melt towards its setting point, "
               "which keeps the drug suspended rather than sedimenting.",
               after=("base_melted",), tag="drug_incorporated"),
            _s("Pour into the mould slightly overfilled, while still just "
               "molten.",
               "Overfilling allows for contraction on cooling; pouring too "
               "cool gives layered or cavitated suppositories.",
               after=("drug_incorporated",), tag="poured"),
            _s("Allow to cool, then trim the excess with a warm blade.",
               "Trimming after setting gives a flat, uniform end.",
               after=("poured",), tag="trimmed"),
            _s("Remove from the mould, wrap, and label with route and "
               "storage.",
               "Suppositories are stored in a cool place; the route must be "
               "on the label.",
               after=("trimmed",)),
        ),
        critical=(
            "Displacement value is the whole calculation -- do not skip it.",
            "Do not overheat the base.",
            "Overfill to allow for contraction.",
        ),
        errors=(
            "Ignoring displacement value, which gives an under-dosed or "
            "oversized suppository.",
            "Choosing a lubricant the base dissolves in.",
        )),

    Method(
        key="powder_divided",
        form="Powders",
        name="Divided powders by geometric dilution",
        principle=(
            "Potent ingredients present in small quantity are mixed with "
            "diluent by doubling the quantity at each stage, so the small "
            "quantity is distributed uniformly."),
        apparatus=("mortar and pestle", "sieve", "powder papers", "balance"),
        steps=(
            _s("Weigh each ingredient accurately.",
               "Content uniformity begins at the balance.",
               tag="weighed"),
            _s("Place the ingredient of smallest bulk in the mortar.",
               "The smallest quantity starts in the mortar; putting the bulk "
               "in first makes uniform mixing impossible.",
               after=("weighed",), tag="smallest_first"),
            _s("Add an approximately equal volume of the diluent and mix.",
               "Equal volumes -- not equal weights -- because mixing is a "
               "volumetric process.",
               after=("smallest_first",), tag="first_dilution"),
            _s("Continue doubling the quantity added at each stage until all "
               "the diluent is incorporated.",
               "Geometric dilution: each stage mixes two similar volumes, "
               "which is the only way to distribute a small quantity "
               "uniformly through a large one.",
               after=("first_dilution",), tag="geometric_complete"),
            _s("Pass the mixed powder through a sieve and remix.",
               "Sieving breaks any remaining aggregates and confirms "
               "uniformity of particle size.",
               after=("geometric_complete",), tag="sieved"),
            _s("Weigh into individual doses on powder papers, fold, and "
               "label.",
               "Divided powders are dispensed as individual doses.",
               after=("sieved",)),
        ),
        critical=("Smallest quantity into the mortar first.",
                  "Double the quantity at each stage, by volume."),
        errors=("Adding the bulk diluent first, which gives non-uniform "
                "content and is the classic mistake.",)),

    Method(
        key="tablet_wet_granulation",
        form="Tablets",
        name="Tablets by wet granulation",
        principle=(
            "The powder blend is agglomerated with a binder solution into "
            "granules, dried, sized and compressed -- improving flow and "
            "compressibility."),
        apparatus=("mixer", "granulator", "sieves", "tray or fluid-bed "
                   "dryer", "tablet press"),
        steps=(
            _s("Weigh and sift the drug, diluent and disintegrant; mix dry.",
               "Sifting removes lumps and the dry mix distributes the "
               "components before liquid is introduced.",
               tag="dry_mixed"),
            _s("Prepare the binder solution and add it to the dry blend to "
               "form a damp, cohesive mass.",
               "The endpoint is a mass that coheres when squeezed and "
               "crumbles when pressed -- too wet gives hard granules, too "
               "dry gives fines.",
               after=("dry_mixed",), tag="massed"),
            _s("Pass the wet mass through a coarse sieve to form granules.",
               "Wet screening sets the granule size before drying fixes it.",
               after=("massed",), tag="wet_screened"),
            _s("Dry the granules at a controlled temperature.",
               "Residual moisture causes sticking and chemical instability; "
               "over-drying makes granules brittle.",
               after=("wet_screened",), tag="dried"),
            _s("Pass the dried granules through a finer sieve.",
               "Dry screening breaks agglomerates formed during drying and "
               "gives the final size distribution.",
               after=("dried",), tag="dry_screened"),
            _s("Add the lubricant and glidant, and blend briefly.",
               "Added *after* drying and only briefly: lubricant is "
               "hydrophobic and over-blending coats the granules, slowing "
               "disintegration and weakening the tablet.",
               after=("dry_screened",), tag="lubricated"),
            _s("Compress on a tablet press to the required weight and "
               "hardness.",
               "Weight, hardness, thickness, friability and disintegration "
               "are the in-process checks.",
               after=("lubricated",), tag="compressed"),
            _s("Evaluate: weight variation, hardness, friability, "
               "disintegration, dissolution, content uniformity.",
               "The pharmacopoeial tests -- name them, they carry marks.",
               after=("compressed",)),
        ),
        critical=(
            "Lubricant goes in last and is blended only briefly.",
            "Both a wet screen and a dry screen, before and after drying.",
        ),
        errors=(
            "Adding the lubricant before drying.",
            "Over-blending after lubrication, which retards disintegration.",
        )),

    Method(
        key="tablet_dry_granulation",
        form="Tablets",
        name="Tablets by dry granulation (slugging / roller compaction)",
        principle=(
            "The blend is compacted into large slugs or a ribbon, then broken "
            "down into granules -- used when the drug is moisture-sensitive "
            "or heat-labile and wet granulation is therefore impossible."),
        apparatus=("heavy-duty tablet press or roller compactor", "sieves",
                   "blender", "tablet press"),
        steps=(
            _s("Weigh, sift and blend the drug with the diluent and part of "
               "the disintegrant, plus a lubricant for the slugging stage.",
               "A lubricant is needed even for slugging, or the compacted "
               "material sticks to the punches.",
               tag="blended"),
            _s("Compress the blend into large slugs, or pass it through a "
               "roller compactor to form a ribbon.",
               "Compaction supplies the particle bonding that a binder "
               "solution would otherwise provide -- with no liquid and no "
               "drying, which is the entire reason for the method.",
               after=("blended",), tag="slugged"),
            _s("Break the slugs or ribbon down and pass through a sieve to "
               "the required granule size.",
               "Sizing gives the flow and packing properties that make "
               "compression reproducible.",
               after=("slugged",), tag="sized"),
            _s("Add the remaining disintegrant, the glidant and the "
               "lubricant, and blend briefly.",
               "Disintegrant split between the two stages -- part inside the "
               "granule and part outside -- so the tablet breaks into "
               "granules and the granules then break apart.",
               after=("sized",), tag="lubricated"),
            _s("Compress into tablets and evaluate.",
               "Same in-process controls as wet granulation.",
               after=("lubricated",)),
        ),
        critical=(
            "No water and no heat -- that is the whole point of the method.",
            "Disintegrant is usually split intragranular / extragranular.",
        ),
        errors=("Offering this method without saying why wet granulation "
                "was ruled out; the justification is the answer.",)),

    Method(
        key="tablet_direct_compression",
        form="Tablets",
        name="Tablets by direct compression",
        principle=(
            "The drug and directly compressible excipients are blended and "
            "compressed with no granulation at all -- the fewest steps, but "
            "only possible when the blend already flows and compacts."),
        apparatus=("sifter", "blender", "tablet press"),
        steps=(
            _s("Sift the drug and the directly compressible diluent "
               "together.",
               "Sifting through a common screen is the first mixing step and "
               "removes agglomerates that would cause content variation.",
               tag="sifted"),
            _s("Blend with the disintegrant and glidant.",
               "Directly compressible grades -- spray-dried lactose, "
               "microcrystalline cellulose -- are engineered for flow and "
               "compactibility, which is what replaces granulation.",
               after=("sifted",), tag="blended"),
            _s("Add the lubricant and blend only briefly.",
               "Over-lubrication is a worse problem here than in granulation, "
               "because there is no granule to protect the surfaces.",
               after=("blended",), tag="lubricated"),
            _s("Compress and evaluate, watching weight variation "
               "particularly closely.",
               "Segregation of an ungranulated blend is the characteristic "
               "failure, and it shows up as weight and content variation.",
               after=("lubricated",)),
        ),
        critical=("Only suitable for drugs with good flow and "
                  "compressibility, or a low dose in a compressible carrier.",
                  "Segregation is the risk that replaces the drying step."),
        errors=("Proposing it for a high-dose, poorly compressible drug.",)),

    Method(
        key="tincture_maceration",
        form="Galenicals",
        name="Tincture by maceration",
        principle=(
            "The drug is soaked in the whole of the menstruum in a closed "
            "vessel for a set period, then strained and pressed -- a batch "
            "extraction that reaches equilibrium rather than exhaustion."),
        apparatus=("closed macerator or wide-mouthed bottle", "muslin/press",
                   "measure"),
        steps=(
            _s("Reduce the drug to the degree of coarseness the monograph "
               "specifies.",
               "Too coarse and extraction is incomplete; too fine and the "
               "product will not strain and clogs the press.",
               tag="comminuted"),
            _s("Place the drug in a closed vessel with the whole of the "
               "specified menstruum.",
               "Closed, because the menstruum is usually alcoholic and "
               "would evaporate, changing both the strength and the "
               "solvent power.",
               after=("comminuted",), tag="steeping"),
            _s("Allow to stand for seven days with occasional shaking.",
               "Shaking renews the solvent at the drug surface; the period "
               "is what allows equilibrium to be approached.",
               after=("steeping",), tag="macerated"),
            _s("Strain, then press the marc and mix the two liquids.",
               "The marc retains a large volume of saturated liquid; "
               "pressing recovers it, and omitting this loses a substantial "
               "part of the yield.",
               after=("macerated",), tag="pressed"),
            _s("Add sufficient menstruum to produce the required volume, "
               "then clarify by filtration.",
               "Adjusting to volume is what makes the strength defined.",
               after=("pressed",), tag="adjusted"),
            _s("Label, protect from light, and store in a cool place.",
               "Tinctures are alcoholic and their constituents are usually "
               "light-sensitive.",
               after=("adjusted",)),
        ),
        critical=(
            "Maceration reaches equilibrium; it does not exhaust the drug.",
            "Press the marc -- the retained liquid is the richest fraction.",
        ),
        errors=("Confusing this with percolation. Maceration uses the whole "
                "menstruum at once and is used for drugs that swell a lot or "
                "whose active is readily soluble.",)),

    Method(
        key="tincture_percolation",
        form="Galenicals",
        name="Tincture by percolation",
        principle=(
            "Fresh menstruum flows continuously through a packed column of "
            "drug, so the drug always meets unsaturated solvent -- which is "
            "why percolation can exhaust the drug and maceration cannot."),
        apparatus=("percolator (conical)", "measure", "receiver"),
        steps=(
            _s("Reduce the drug to the specified degree of coarseness.",
               "Uniform particle size is essential or the menstruum "
               "channels through the easy paths and leaves the rest "
               "unextracted.",
               tag="comminuted"),
            _s("Moisten the drug with a portion of the menstruum and allow "
               "it to stand for about four hours (imbibition).",
               "The drug swells now, outside the percolator. Packing it dry "
               "means it swells inside, jams the column and stops the flow.",
               after=("comminuted",), tag="imbibed"),
            _s("Pack the moistened drug evenly into the percolator.",
               "Even packing without air pockets; too tight stops flow, too "
               "loose lets the menstruum channel.",
               after=("imbibed",), tag="packed"),
            _s("Add menstruum until it runs from the outlet, close the "
               "outlet, cover, and macerate for 24 hours.",
               "Running it through first expels air. The maceration period "
               "lets the solvent penetrate the cells before flow begins.",
               after=("packed",), tag="soaked"),
            _s("Open the outlet and allow percolation at the specified rate, "
               "adding menstruum to keep the drug covered.",
               "The rate matters: too fast and the solvent leaves before it "
               "is saturated, too slow and the batch takes days.",
               after=("soaked",), tag="percolated"),
            _s("Reserve the first portion (typically three-quarters of the "
               "final volume) if the monograph so directs.",
               "For potent drugs the first runnings are reserved unheated, "
               "and only the weak later percolate is concentrated -- so the "
               "actives are not exposed to heat.",
               after=("percolated",), tag="reserved"),
            _s("Press the marc, combine, adjust to volume, and clarify.",
               "The marc holds a large volume of the richest liquid, and "
               "adjusting to volume is what fixes the declared strength -- "
               "the same two reasons as in maceration.",
               after=("reserved",), tag="adjusted"),
            _s("Label and store protected from light in a cool place.",
               "The menstruum is alcoholic and evaporates, and most of the "
               "extracted constituents are degraded by light, so both the "
               "strength and the activity depend on the storage.",
               after=("adjusted",)),
        ),
        critical=(
            "Imbibition before packing -- swelling inside the percolator "
            "blocks it.",
            "Percolation can exhaust the drug; maceration cannot.",
            "Reserved percolate protects thermolabile actives from heat.",
        ),
        errors=("Packing dry drug, which is the classic practical failure.",)),

    Method(
        key="syrup",
        form="Galenicals",
        name="Syrup",
        principle=(
            "A near-saturated solution of sucrose in water -- about 66.7 "
            "percent w/w -- which is self-preserving because so little free "
            "water remains available to micro-organisms."),
        apparatus=("beaker", "water bath", "stirrer", "muslin/filter"),
        steps=(
            _s("Heat the purified water and dissolve the sucrose with "
               "stirring, avoiding prolonged boiling.",
               "Heat speeds dissolution, but prolonged heating inverts "
               "sucrose to invert sugar, which darkens the syrup and "
               "destroys its self-preserving property.",
               tag="dissolved"),
            _s("Remove from the heat as soon as dissolution is complete.",
               "Same reason -- every extra minute of heat is inversion.",
               after=("dissolved",), tag="off_heat"),
            _s("Add any medicament, dissolved separately, and adjust to the "
               "final weight or volume.",
               "Added off the heat so thermolabile actives are not lost.",
               after=("off_heat",), tag="adjusted"),
            _s("Strain through muslin while still warm.",
               "Warm syrup is far less viscous and will actually pass "
               "through; cold syrup will not strain.",
               after=("adjusted",), tag="strained"),
            _s("Transfer to a dry bottle and label.",
               "A dry bottle: water condensing on the surface dilutes the "
               "top layer, and that layer then supports mould growth.",
               after=("strained",)),
        ),
        critical=(
            "66.7 percent w/w is what makes it self-preserving.",
            "Do not boil -- inversion darkens the syrup and spoils it.",
            "Strain warm.",
        ),
        errors=("Prolonged heating; a diluted syrup needs an added "
                "preservative because it is no longer self-preserving.",)),

    Method(
        key="aromatic_water",
        form="Galenicals",
        name="Aromatic water by solution / distillation",
        principle=(
            "A saturated or near-saturated aqueous solution of a volatile "
            "oil. Because the oil is only sparingly soluble, the practical "
            "problem is dispersing it enough for the water to take up its "
            "share."),
        apparatus=("bottle", "talc or filter paper", "filter funnel"),
        steps=(
            _s("Triturate the volatile oil with about ten times its weight "
               "of purified talc (or use filter paper).",
               "Talc is an inert distributing agent: it spreads the oil over "
               "a large surface so the water can dissolve it, and then "
               "filters out. It is not an ingredient of the product.",
               tag="triturated"),
            _s("Add the purified water gradually with trituration, then "
               "shake well and allow to stand.",
               "Standing allows the water to become saturated with the oil.",
               after=("triturated",), tag="shaken"),
            _s("Filter until a clear solution is obtained, returning the "
               "first cloudy runnings to the filter.",
               "The first runnings carry suspended oil and talc; returning "
               "them is what finally gives a clear product.",
               after=("shaken",), tag="filtered"),
            _s("Label and store in a cool place in a well-filled, "
               "well-closed container.",
               "Volatile and readily spoiled; well-filled to limit the air "
               "above the liquid.",
               after=("filtered",)),
        ),
        critical=("Talc is a distributing agent and is removed by filtration.",
                  "Return the first cloudy filtrate."),
        errors=("Calling the talc an ingredient of the finished water.",)),

    Method(
        key="cream",
        form="Semisolids",
        name="Cream by emulsification of the two phases",
        principle=(
            "A semisolid emulsion. Oil-soluble components are melted "
            "together as the oily phase, water-soluble ones dissolved as the "
            "aqueous phase, and the two combined at the same temperature "
            "with stirring until cold."),
        apparatus=("two beakers", "water bath", "thermometer", "stirrer",
                   "ointment slab"),
        steps=(
            _s("Melt the oil-soluble ingredients together on a water bath at "
               "about 70 degrees C -- the oily phase.",
               "All the oil-soluble components including the oil-soluble "
               "emulsifier go here.",
               tag="oil_phase"),
            _s("Dissolve the water-soluble ingredients in the water and heat "
               "to the same temperature -- the aqueous phase.",
               "Preservative, humectant and water-soluble emulsifier go "
               "here.",
               after=("oil_phase",), tag="water_phase"),
            _s("Check that both phases are at the same temperature before "
               "mixing.",
               "A temperature difference solidifies the fatty components on "
               "contact and gives a lumpy, unstable cream. This is the step "
               "most often omitted and it is the one that matters.",
               after=("water_phase",), tag="matched"),
            _s("Add the internal phase to the external phase slowly with "
               "continuous stirring.",
               "Which phase is internal follows from the emulsifier and the "
               "type of cream: aqueous into oily for w/o, oily into aqueous "
               "for o/w.",
               after=("matched",), tag="combined"),
            _s("Continue stirring until the cream is cold and set.",
               "Stirring through the cooling range is what fixes the droplet "
               "size; stopping early lets the emulsion coalesce.",
               after=("combined",), tag="stirred_cold"),
            _s("Add any volatile or thermolabile ingredient near room "
               "temperature, then pack and label.",
               "Perfumes and volatile actives are lost if added hot.",
               after=("stirred_cold",)),
        ),
        critical=(
            "Both phases at the same temperature, around 70 degrees C.",
            "Stir until cold, not just until combined.",
            "Direction of addition follows the emulsion type.",
        ),
        errors=("Combining phases at different temperatures.",
                "Adding perfume to a hot cream.")),

    Method(
        key="capsules_hard",
        form="Capsules",
        name="Filling hard gelatin capsules",
        principle=(
            "A measured quantity of powder blend is enclosed in a two-piece "
            "gelatin shell; the capsule size is chosen from the bulk volume "
            "of the fill, not from its weight."),
        apparatus=("capsule filling machine or hand-filling plate",
                   "sieve", "blender", "balance"),
        steps=(
            _s("Determine the bulk density of the blend and select the "
               "capsule size accordingly.",
               "Capsule sizes are volumetric -- size 0, 1, 2 and so on "
               "describe a volume. Choosing by weight is the standard error.",
               tag="size_chosen"),
            _s("Sift and blend the drug with the diluent, glidant and "
               "lubricant.",
               "A capsule blend still needs flow: it must fill every pocket "
               "reproducibly at speed.",
               after=("size_chosen",), tag="blended"),
            _s("Separate the caps from the bodies and load the bodies into "
               "the filling plate.",
               "Filling is into the body; the cap is replaced afterwards.",
               after=("blended",), tag="loaded"),
            _s("Fill the bodies with the blend, level off, and replace the "
               "caps.",
               "Levelling is what makes fill weight uniform -- it is a "
               "volumetric measure, so the powder bed must be level and "
               "consistently packed.",
               after=("loaded",), tag="filled"),
            _s("Lock, clean the outside of the capsules, and check weight "
               "variation.",
               "Cleaning removes adhering powder, which otherwise both "
               "falsifies the weight check and tastes of the drug.",
               after=("filled",), tag="checked"),
            _s("Pack in a well-closed container and label.",
               "Gelatin is hygroscopic; capsules soften in damp air and "
               "become brittle in very dry air.",
               after=("checked",)),
        ),
        critical=("Size is chosen by volume, not by weight.",
                  "Level the fill; weight variation is the control."),
        errors=("Selecting the capsule size from the dose in milligrams "
                "without considering bulk density.",)),

    Method(
        key="dusting_powder",
        form="Powders",
        name="Dusting powder",
        principle=(
            "A finely divided powder for external application, which must "
            "be impalpable so it does not irritate, and which is sterile "
            "when intended for wounds or for use on the umbilical cord."),
        apparatus=("mortar and pestle", "fine sieve (usually 120 mesh or "
                   "finer)", "sifter-top container"),
        steps=(
            _s("Reduce each ingredient to a very fine powder.",
               "Impalpability is the specification. A gritty dusting powder "
               "abrades the skin it is meant to protect.",
               tag="powdered"),
            _s("Mix by geometric dilution and pass through a fine sieve.",
               "Sieving both mixes and guarantees the particle size, which "
               "is what 'impalpable' means in practice.",
               after=("powdered",), tag="sieved"),
            _s("If intended for open wounds, broken skin or the umbilical "
               "cord, sterilise -- usually by dry heat.",
               "This is a compulsory point: surgical and umbilical dusting "
               "powders must be sterile, because the site has no intact skin "
               "barrier and spores of Clostridium are the specific concern.",
               after=("sieved",), tag="sterilised"),
            _s("Pack in a sifter-top container and label 'For external use "
               "only'.",
               "The container form is part of the design -- it delivers a "
               "fine, even dusting.",
               after=("sterilised",)),
        ),
        critical=("Impalpable fineness.",
                  "Sterile if for wounds, broken skin, or the umbilicus."),
        errors=("Omitting sterilisation for a surgical dusting powder.",)),

    Method(
        key="effervescent_granules",
        form="Powders",
        name="Effervescent granules",
        principle=(
            "Sodium bicarbonate and an organic acid are granulated so that "
            "they react only on contact with water. The reaction generates "
            "carbon dioxide, which masks taste and aids dissolution -- and "
            "which is why every trace of moisture must be excluded."),
        apparatus=("oven or hot plate", "sieves", "porcelain dish",
                   "airtight container"),
        steps=(
            _s("Dry every ingredient thoroughly and work in a low-humidity "
               "environment.",
               "Any moisture starts the reaction in the mixture; once "
               "started it is self-accelerating, because the reaction "
               "itself produces water.",
               tag="dried"),
            _s("Mix the sodium bicarbonate with the citric and tartaric "
               "acids and any other ingredients.",
               "The two acids together are conventional: citric acid alone "
               "gives a sticky mass, tartaric acid alone gives a granule "
               "that crumbles.",
               after=("dried",), tag="mixed"),
            _s("Warm the mixture gently in a dish at about 93-104 degrees C "
               "until the water of crystallisation of the citric acid is "
               "released and the mass becomes coherent.",
               "The citric acid monohydrate supplies its own granulating "
               "liquid -- no water is added from outside. This is the "
               "elegant part of the method and it earns marks.",
               after=("mixed",), tag="massed"),
            _s("Pass the warm mass promptly through a sieve to form "
               "granules.",
               "Promptly, because the mass sets hard as it cools and cannot "
               "then be granulated.",
               after=("massed",), tag="granulated"),
            _s("Dry the granules at a low temperature and pass through a "
               "sieve to size.",
               "Drying stops the reaction by removing the released water.",
               after=("granulated",), tag="dried_granules"),
            _s("Pack immediately in airtight containers, with a desiccant.",
               "Immediately and airtight -- atmospheric moisture will start "
               "the reaction in storage.",
               after=("dried_granules",)),
        ),
        critical=(
            "No added water; the citric acid's water of crystallisation "
            "is the granulating liquid.",
            "Sieve while warm.",
            "Airtight packing is part of the product, not the packaging.",
        ),
        errors=("Adding water as a granulating fluid, which sets the whole "
                "batch effervescing.",)),

    Method(
        key="injection",
        form="Parenterals",
        name="Small-volume injection (terminally sterilised)",
        principle=(
            "A sterile, pyrogen-free, particle-free solution prepared under "
            "controlled conditions, sealed in its final container, and "
            "sterilised in that container wherever the product will tolerate "
            "it."),
        apparatus=("clean room / LAF unit", "borosilicate glassware",
                   "sintered glass or membrane filter (0.22 micron)",
                   "ampoule filling and sealing unit", "autoclave"),
        steps=(
            _s("Prepare the vehicle -- water for injection, freshly "
               "distilled and pyrogen-free.",
               "Sterility and freedom from pyrogens are separate "
               "requirements: pyrogens are bacterial endotoxins that survive "
               "autoclaving, so they must be excluded, not killed.",
               tag="vehicle"),
            _s("Dissolve the drug and adjuncts -- tonicity adjuster, buffer, "
               "antioxidant, preservative if permitted.",
               "No preservative is permitted in large-volume parenterals or "
               "in intrathecal, intracardiac and ophthalmic-intraocular "
               "injections; that exclusion is examinable.",
               after=("vehicle",), tag="dissolved"),
            _s("Adjust the volume, then filter through a 0.22 micron "
               "membrane until clear and particle-free.",
               "Clarity is a pharmacopoeial requirement -- a particle "
               "injected intravenously is an embolus.",
               after=("dissolved",), tag="filtered"),
            _s("Fill into ampoules or vials under aseptic conditions, "
               "allowing the specified overage.",
               "Overage compensates for what cannot be withdrawn from the "
               "container, so the labelled dose can actually be given.",
               after=("filtered",), tag="filled"),
            _s("Seal the ampoules and test the seals.",
               "A faulty seal makes the whole sterilisation meaningless. "
               "Leak testing by dye bath or vacuum follows.",
               after=("filled",), tag="sealed"),
            _s("Sterilise terminally -- autoclave at 121 degrees C for 15 "
               "minutes where the product allows.",
               "Terminal sterilisation in the final sealed container is "
               "always preferred to aseptic processing, because it "
               "sterilises the product as it will be used.",
               after=("sealed",), tag="sterilised"),
            _s("Inspect every container against black and white backgrounds "
               "for particles and cracks.",
               "One hundred percent visual inspection; this is not a "
               "sampling test.",
               after=("sterilised",), tag="inspected"),
            _s("Test for sterility, pyrogens, and clarity; then label.",
               "The three tests that define a parenteral.",
               after=("inspected",)),
        ),
        critical=(
            "Sterile, pyrogen-free, particle-free, and isotonic where "
            "required -- name all four.",
            "Terminal sterilisation is preferred over aseptic filling.",
            "No preservative in LVPs or intrathecal injections.",
        ),
        errors=(
            "Treating 'sterile' and 'pyrogen-free' as the same requirement.",
            "Forgetting the overage.",
        )),

    Method(
        key="eye_drops",
        form="Parenterals",
        name="Eye drops",
        principle=(
            "A sterile aqueous or oily solution, isotonic and suitably "
            "buffered, containing a preservative for multi-dose containers "
            "-- prepared to the same standard as an injection because the "
            "cornea is easily damaged and readily infected."),
        apparatus=("LAF unit", "membrane filter", "autoclave",
                   "sterile dropper containers"),
        steps=(
            _s("Dissolve the drug in the vehicle with the buffer and "
               "tonicity adjuster.",
               "Isotonic and near-neutral pH minimise stinging and reflex "
               "lacrimation, which would otherwise wash the dose straight "
               "out.",
               tag="dissolved"),
            _s("Add the preservative -- for multi-dose containers only.",
               "Single-dose and intraocular-surgery preparations must be "
               "preservative-free, because the preservative is toxic to "
               "corneal endothelium.",
               after=("dissolved",), tag="preserved"),
            _s("Clarify by filtration through a membrane filter.",
               "A particle in an eye drop abrades the cornea.",
               after=("preserved",), tag="filtered"),
            _s("Fill into containers and sterilise -- autoclave where the "
               "drug allows, otherwise filter-sterilise and fill "
               "aseptically.",
               "The decision follows the thermostability of the drug, and "
               "saying which and why is the mark.",
               after=("filtered",), tag="sterilised"),
            _s("Label with the strength, the storage condition, and a "
               "discard date after opening.",
               "Multi-dose eye drops are conventionally discarded four weeks "
               "after opening -- confirm the period your course specifies.",
               after=("sterilised",)),
        ),
        critical=(
            "Sterile, isotonic, buffered, preserved (multi-dose only).",
            "No preservative for intraocular or single-dose use.",
        ),
        errors=("Preserving a preparation intended for use during eye "
                "surgery.",)),
]

METHODS = {method.key: method for method in _METHODS}


def check_order(method: "Method") -> bool:
    """Do the steps satisfy every prerequisite they declare?

    The point of the module: in compounding, order is correctness. A method
    whose steps are transposed reads perfectly well and would ruin the
    preparation, so the sequence is verified rather than trusted.
    """
    seen: set = set()
    for index, step in enumerate(method.steps, start=1):
        missing = [tag for tag in step.after if tag not in seen]
        if missing:
            raise OrderError(
                "%s step %d (%s) requires %s, which has not happened yet"
                % (method.key, index, step.action[:40],
                   ", ".join(missing)))
        if step.tag:
            seen.add(step.tag)
    return True


def topics() -> list:
    return sorted({method.form for method in _METHODS})


def find(text: str) -> list:
    needle = text.lower().strip()
    return [method for method in _METHODS
            if needle in method.key.lower()
            or needle in method.name.lower()
            or needle in method.form.lower()
            or needle in method.principle.lower()]


def show(key: str) -> str:
    """One method, written out the way an answer would be."""
    if key not in METHODS:
        matches = find(key)
        if len(matches) == 1:
            key = matches[0].key
        else:
            raise KeyError("no method %r; try find(%r)" % (key, key))
    m = METHODS[key]
    lines = ["%s  [%s]" % (m.name, m.form), "",
             "PRINCIPLE", "  %s" % m.principle, "",
             "APPARATUS", "  %s" % ", ".join(m.apparatus), "",
             "METHOD"]
    for index, step in enumerate(m.steps, start=1):
        lines.append("  %d. %s" % (index, step.action))
        lines.append("     why: %s" % step.why)
    if m.critical:
        lines += ["", "CRITICAL POINTS"]
        lines += ["  - %s" % point for point in m.critical]
    if m.errors:
        lines += ["", "COMMON ERRORS"]
        lines += ["  - %s" % error for error in m.errors]
    if m.note:
        lines += ["", m.note]
    return "\n".join(lines)
