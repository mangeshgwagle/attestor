"""One place to look things up while revising.

Three kinds of thing live in this package and they answer different
questions:

    formulas      "what is the equation and how do I use it"
    methods       "how is this dosage form compounded"
    preparations  "how is this substance manufactured"
    principles    "why is it made that way, and how do I work out one I
                   have never seen"

Under exam pressure you do not want to remember which module holds what, so
`find` searches all of them and says which kind each hit is.

    python exam.py find emulsion          search everything
    python exam.py show boric_acid        the full worked answer
    python exam.py teach boric_acid       answer + reasons + recall prompt
    python exam.py why boric_acid         which patterns it demonstrates
    python exam.py patterns               the dozen reusable ideas
    python exam.py derive "zinc oxide"    checklist for an unseen substance
    python exam.py recall 5               questions with the answers hidden
    python exam.py list                   everything, by topic
    python exam.py coverage               what is covered, and what is not
    python exam.py check                  verify the reference is still sound

`derive` is the one that matters most. There are not sixty unrelated
methods to memorise; there are about a dozen patterns, reused. Knowing them
means an unseen substance is work rather than a wall.
"""

from __future__ import annotations

from pathlib import Path
import random
import sys

# Isolated mode deliberately omits the script directory from ``sys.path``.
# Add only this fixed, release-owned module directory so the unified CLI can
# invoke the study tool without trusting the caller's working directory or
# PYTHONPATH.
if not __package__:
    _HERE = Path(__file__).resolve(strict=True).parent
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))

import formulas
import methods
import preparations
import principles


def _all_sources():
    return (
        ("formula", formulas.find, formulas.show,
         lambda entry: entry.key),
        ("method", methods.find, methods.show,
         lambda entry: entry.key),
        ("preparation", preparations.find, preparations.show,
         lambda entry: entry.key),
        ("principle", principles.find, principles.show,
         lambda entry: entry.key),
    )


def why(preparation_key: str) -> str:
    """Which reasoning patterns a given preparation demonstrates.

    The bridge from a memorised answer to a transferable one: seeing that
    boric acid and ferrous sulphate are the same separation trick is worth
    more than knowing both procedures.
    """
    if preparation_key not in preparations.PREPARATIONS:
        matches = preparations.find(preparation_key)
        if len(matches) != 1:
            raise KeyError("no preparation %r" % preparation_key)
        preparation_key = matches[0].key
    prep = preparations.PREPARATIONS[preparation_key]
    found = principles.patterns_for(preparation_key)
    lines = ["%s is an example of %d pattern(s):" % (prep.name, len(found)), ""]
    for pattern in found:
        lines.append("  %-34s %s" % (pattern.key, pattern.name))
        lines.append("    %s" % pattern.idea)
        others = [k for k in pattern.examples if k != preparation_key]
        if others:
            lines.append("    same move in: %s" % ", ".join(others))
        lines.append("")
    lines.append("Read those together and the pattern becomes portable.")
    return "\n".join(lines)


def recall(count: int = 5, seed: int = None) -> str:
    """Questions with the answers withheld, for self-testing.

    Reading an answer feels like learning and mostly is not. Being asked
    the question cold, failing, and then reading is what makes it stick --
    so this prints only the prompts and tells you where to check.
    """
    rng = random.Random(seed)
    pool = []
    for key, prep in preparations.PREPARATIONS.items():
        pool.append(("Give the principle, balanced equation and procedure "
                     "for the preparation of %s." % prep.name,
                     "show %s" % key))
        pool.append(("How is %s assayed, and why that method?" % prep.name,
                     "show %s" % key))
        pool.append(("What impurity does the preparation of %s leave, and "
                     "why?" % prep.name, "show %s" % key))
    for key, method in methods.METHODS.items():
        pool.append(("Describe the method of preparation of a %s, with "
                     "reasons for the order of the steps."
                     % method.name.lower(), "show %s" % key))
    chosen = rng.sample(pool, min(count, len(pool)))
    lines = ["ANSWER THESE BEFORE LOOKING. Write them out -- reading is not "
             "recall.", ""]
    for index, (question, where) in enumerate(chosen, start=1):
        lines.append("%d. %s" % (index, question))
        lines.append("   check with:  python exam.py %s" % where)
        lines.append("")
    return "\n".join(lines)


def find(term: str) -> list:
    """Every hit across all three, as (kind, key, label)."""
    hits = []
    for kind, search, _show, key_of in _all_sources():
        for entry in search(term):
            hits.append((kind, key_of(entry), getattr(entry, "name", "")))
    return hits


def show(key: str) -> str:
    """Whichever of the three holds this key."""
    for kind, _search, render, _key_of in _all_sources():
        try:
            return render(key)
        except KeyError:
            continue
    raise KeyError("nothing called %r -- try: python exam.py find %s"
                   % (key, key))


def teach(preparation_key: str) -> str:
    """A worked preparation, its reusable patterns, then active recall."""
    answer = preparations.show(preparation_key)
    reasoning = why(preparation_key)
    matches = preparations.find(preparation_key)
    if preparation_key in preparations.PREPARATIONS:
        key = preparation_key
        prep = preparations.PREPARATIONS[key]
    elif len(matches) == 1:
        prep = matches[0]
        key = prep.key
    else:
        raise KeyError("no preparation %r" % preparation_key)
    return "\n\n".join((
        "WORKED EXAM ANSWER\n\n" + answer,
        "TRANSFERABLE REASONING\n\n" + reasoning,
        "CLOSE THE ANSWER AND WRITE THIS FROM MEMORY\n\n"
        "Give the principle, balanced equation, ordered procedure with a "
        "reason for every step, purification, identification, limit tests, "
        "assay, uses and storage for %s.\n\nCheck with: pharma teach %s"
        % (prep.name, key),
    ))


def check() -> int:
    """Run the invariants that keep this reference honest.

    Worth being able to run by hand: it is the difference between a
    reference you trust and one you hope about.
    """
    failures = 0

    for key, entry in formulas.FORMULAS.items():
        try:
            got = entry.run_example()
            want = entry.example["answer"]
            tolerance = entry.example.get("tolerance", 0.01)
            if abs(got - want) > tolerance:
                print("FORMULA  %s: computes %s, example says %s"
                      % (key, got, want))
                failures += 1
        except Exception as exc:                      # noqa: BLE001
            print("FORMULA  %s raised %s" % (key, exc))
            failures += 1

    for key, method in methods.METHODS.items():
        try:
            methods.check_order(method)
        except methods.OrderError as exc:
            print("METHOD   %s" % exc)
            failures += 1

    for key, prep in preparations.PREPARATIONS.items():
        try:
            preparations.check_reactions(prep)
        except preparations.ReactionError as exc:
            print("REACTION %s" % exc)
            failures += 1

    try:
        principles.check_examples()
    except principles.CrossReferenceError as exc:
        print("PATTERN  %s" % exc)
        failures += 1
    orphans = [key for key in preparations.PREPARATIONS
               if not principles.patterns_for(key)]
    if orphans:
        print("PATTERN  no reasoning pattern covers: %s" % ", ".join(orphans))
        failures += 1

    total = (len(formulas.FORMULAS) + len(methods.METHODS)
             + len(preparations.PREPARATIONS))
    if failures:
        print("\n%d problem(s) in %d entries." % (failures, total))
    else:
        equation_count = sum(
            1 for prep in preparations.PREPARATIONS.values()
            for equation in prep.reactions if "->" in equation)
        print("%d formulas computed their own examples, "
              "%d methods are in a workable order, "
              "%d preparation entries passed (%d equations conserve atoms)."
              % (len(formulas.FORMULAS), len(methods.METHODS),
                 len(preparations.PREPARATIONS), equation_count))
    return failures


def _list(kind: str = "") -> None:
    if kind in ("", "formulas", "formula"):
        print("FORMULAS (%d)" % len(formulas.FORMULAS))
        for topic in formulas.topics():
            keys = [k for k, e in sorted(formulas.FORMULAS.items())
                    if e.topic == topic]
            print("  %-28s %s" % (topic, ", ".join(keys)))
    if kind in ("", "methods", "method"):
        print("\nMETHODS OF PREPARATION -- dosage forms (%d)"
              % len(methods.METHODS))
        for form in methods.topics():
            keys = [k for k, m in sorted(methods.METHODS.items())
                    if m.form == form]
            print("  %-28s %s" % (form, ", ".join(keys)))
    if kind in ("", "preparations", "preparation", "substances"):
        print("\nPHARMACEUTICAL SUBSTANCES (%d)"
              % len(preparations.PREPARATIONS))
        for category in preparations.categories():
            keys = [k for k, p in sorted(preparations.PREPARATIONS.items())
                    if p.category == category]
            print("  %-28s %s" % (category, ", ".join(keys)))


def coverage() -> str:
    """State the current evidence boundary instead of implying completeness."""
    return "\n".join((
        "CURRENT PHARMACY REFERENCE COVERAGE",
        "",
        "  %d worked pharmaceutical substances" % len(preparations.PREPARATIONS),
        "  %d reusable formation patterns" % len(principles.PATTERNS),
        "  %d dosage-form methods" % len(methods.METHODS),
        "  %d calculation formulas" % len(formulas.FORMULAS),
        "",
        "BOARD BINDING",
        "  Not yet bound to a named board, syllabus, textbook, or edition.",
        "  This reference must not be described as complete until every",
        "  syllabus substance is mapped to a checked worked answer.",
        "",
        "CONTENT BOUNDARY",
        "  Exam-level chemistry and reasons are included. Exact official",
        "  quantities, purity limits, and monograph values must come from",
        "  the applicable IP/BP/USP edition and the board-prescribed text.",
    ))


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    command, rest = argv[0], argv[1:]

    if command == "find":
        if not rest:
            print("find what?")
            return 2
        hits = find(" ".join(rest))
        if not hits:
            print("nothing matches %r" % " ".join(rest))
            return 1
        for kind, key, name in hits:
            print("%-12s %-28s %s" % (kind, key, name))
        return 0

    if command == "show":
        if not rest:
            print("show what?")
            return 2
        try:
            print(show(" ".join(rest)))
        except KeyError as exc:
            print(exc)
            return 1
        return 0

    if command == "teach":
        if not rest:
            print("teach what?")
            return 2
        try:
            print(teach(" ".join(rest)))
        except KeyError as exc:
            print(exc)
            return 1
        return 0

    if command == "list":
        _list(rest[0] if rest else "")
        return 0

    if command == "why":
        if not rest:
            print("why what?")
            return 2
        try:
            print(why(" ".join(rest)))
        except KeyError as exc:
            print(exc)
            return 1
        return 0

    if command == "derive":
        print(principles.derive(" ".join(rest)))
        return 0

    if command == "recall":
        try:
            count = int(rest[0]) if rest else 5
        except ValueError:
            count = 5
        print(recall(count))
        return 0

    if command == "patterns":
        for key, pattern in principles.PATTERNS.items():
            print("%-34s %s" % (key, pattern.name))
        return 0

    if command == "coverage":
        print(coverage())
        return 0

    if command == "check":
        return 1 if check() else 0

    print("unknown command %r -- try find, show, teach, why, derive, recall, "
          "patterns, list, coverage, check" % command)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
