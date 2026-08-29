#!/usr/bin/env python3
"""Three named analysis tiers: Allegro, Belladonna, Cioccolata.

Potency increases in alphabetical order, and it is a measured property rather
than a label. Attestor is a deterministic rule engine, so "more potent" can only
honestly mean one of two things -- it examines more, or it examines deeper --
and both are countable. Nothing here is a neural model, and calling these
three the same word used for one would be the sort of claim this codebase
spends its effort avoiding.

    Allegro     the rules that stayed silent on 112,753 lines of working
                code. Quiet enough to run on every save.
    Belladonna  the full detector catalogue with the taint engines on.
    Cioccolata  everything Belladonna has, plus deep rules, plus three
                further catalogues the detector does not load by itself:
                nativescan, multilang and advanced_rules. NOT
                precision_catalog -- see UNWIRED_CATALOGUES.

An earlier draft of this file said "all five catalogues" and measured
identically to Belladonna, because three of the four it named exposed no scan
function and the loader quietly returned nothing for each. The count in a
docstring is not evidence; the table printed by `--inventory` is.

Where the tier membership comes from
------------------------------------
Not from taste. `scratchpad/precision.py` scans Attestor's own production source
-- excluding tests and the `realworld/` directory, whose files announce in
their own headers that they are deliberately insecure detector input -- and
counts what each rule reports on code written to be correct. Five rules
accounted for 35 of the 40 findings:

    py-except-pass      18   often deliberate in defensive code
    insecure-http-url    9   mostly matches its own rule definition
    todo-fixme           4   matches Attestor's TODO-detecting rule text
    hardcoded-secret     2   `token = "is not" if negated else "is"`
    unsigned-underflow   2   function-span gap, see detect._unsigned_here

Those five are what Allegro drops. Every other rule produced nothing on that
corpus while still firing correctly on the planted fixtures, which is the
strongest evidence available that it discriminates.

The number that is NOT claimed here
-----------------------------------
Recall per tier. Allegro's exclusions cost detection, and by how much is
unmeasured for those five rules against Juliet. Until that is run, Allegro is
"quieter", not "as good and quieter".
"""
from __future__ import annotations

import pathlib
import re
import sys

DETECTOR = pathlib.Path(__file__).resolve().parent.parent.parent / "detector"
if str(DETECTOR) not in sys.path:
    sys.path.insert(0, str(DETECTOR))

import detect  # noqa: E402


class ModelError(Exception):
    """An unknown tier was asked for, or a catalogue failed to load."""


# Rules that cannot be right, as opposed to rules that are merely noisy.
# These are dropped by every tier including Cioccolata, because carrying a
# check that is wrong by construction is not extra reach, it is just volume.
#
#   adv-py-return-finally   pattern is `^\s*return\b`, which matches every
#                           return statement in Python and never mentions
#                           `finally`. It produced 1,211 of Cioccolata's
#                           1,223 findings on Attestor's own source -- 99% of the
#                           tier's entire output, all wrong. The defect it
#                           describes is real, so it is reimplemented as
#                           detect.py's `py-return-in-finally`, which tracks
#                           block indentation and can actually tell.
STRUCTURALLY_BROKEN = frozenset({"adv-py-return-finally"})

# Measured on Attestor's own production source; see the module docstring.
NOISY_ON_REAL_CODE = frozenset({
    "py-except-pass",
    "insecure-http-url",
    "todo-fixme",
    "hardcoded-secret",
    "unsigned-underflow",
})

# Loaded only by Cioccolata. These are separate modules rather than entries in
# detect.RULES, so nothing else in this program consults them.
EXTRA_CATALOGUES = ("nativescan", "multilang", "advanced_rules",
                    "precision_catalog")
# Anything Cioccolata cannot actually run belongs here, and `_run_catalogue`
# raises on it rather than returning nothing. Empty is the correct state; a
# name appearing here is a gap being declared, not hidden.
UNWIRED_CATALOGUES = ()


class Model:
    def __init__(self, name, deep, drop, catalogues, note):
        self.name = name
        self.deep = deep
        self.drop = frozenset(drop)
        self.catalogues = tuple(catalogues)
        self.note = note

    def rules(self):
        """The detector rules this tier will run."""
        return [r for r in detect.RULES
                if r.rid not in self.drop and (self.deep or not r.deep)]

    def scan(self, text, path="<code>", lang="text"):
        blocked = self.drop | STRUCTURALLY_BROKEN
        found = [f for f in detect.scan_source(text, path, lang, deep=self.deep)
                 if f.rule not in blocked]
        for name in self.catalogues:
            found.extend(f for f in _run_catalogue(name, text, path, lang)
                         if f.rule not in blocked)
        return found

    def __repr__(self):
        return "<Model %s>" % self.name


def _finding(path, index, rid, severity, message, raw):
    return detect.Finding(
        path=path, line=index + 1, rule=rid, severity=severity,
        message=message, fix="",
        snippet=raw[index].strip()[:120] if index < len(raw) else "")


def _run_catalogue(name, text, path, lang):
    """Run one extra catalogue, or say plainly that it was not run.

    The first version of this looked for a `scan`-shaped function, found none
    on three of the four catalogues, and returned an empty list. Cioccolata
    therefore claimed four extra catalogues and ran one -- and measured
    identically to Belladonna while looking like the most powerful tier.

    `advanced_rules` and `multilang` are not scanners at all; they are tables
    of (id, severity, regex, message), so they are interpreted here. Patterns
    are applied to blanked code so a rule cannot match its own description in
    a comment, which is how `todo-fixme` and `insecure-http-url` came to
    report Attestor's own rule definitions.
    """
    try:
        module = __import__(name)
    except ImportError as error:
        raise ModelError("%s could not be loaded: %s" % (name, error))

    raw = text.split("\n")
    code = detect.blank(text, lang)
    out = []

    if name == "nativescan":
        fn = getattr(module, "scan_text", None) or getattr(module, "scan", None)
        if not callable(fn):
            raise ModelError("nativescan exposes no scan function")
        try:
            return list(fn(text, path, lang))
        except TypeError:
            return list(fn(text))

    if name == "advanced_rules":
        for rule in module.RULES:
            if getattr(rule, "language", None) not in (lang, "*", None):
                continue
            pattern = re.compile(rule.pattern)
            for index, line in enumerate(code):
                if pattern.search(line):
                    out.append(_finding(path, index, rule.rid, rule.severity,
                                        rule.message, raw))
        return out

    if name == "multilang":
        # Entries are (rid, severity, pattern, message, fix). The first
        # version unpacked four, having read a truncated sample print, and
        # raised ValueError on the first language that actually had rules.
        # It never showed up in testing because the corpus was Python and
        # multilang has no Python entries, so `.get` returned empty and
        # nothing was unpacked at all -- the catalogue had never once run.
        for entry in module.RULES.get(lang, ()):
            if len(entry) < 4:
                raise ModelError(
                    "multilang entry for %s has %d fields, expected at least "
                    "4" % (lang, len(entry)))
            rid, severity, pattern, message = entry[:4]
            compiled = re.compile(pattern)
            for index, line in enumerate(code):
                if compiled.search(line):
                    out.append(_finding(path, index, rid, severity,
                                        message, raw))
        return out

    if name == "precision_catalog":
        # It does have an engine after all: `analyze(text, path)`, which
        # scanengine.py already uses. Two rounds of this function missed it
        # because both looked only for names containing "scan". Worth
        # recording as a lesson about probing an interface by guessing at
        # its vocabulary -- `dir()` would have answered it immediately, and
        # the wrong guess made 15,000 rules look like they had no runner.
        return list(module.analyze(text, path))

    raise ModelError("%s has no interpreter here and will not be faked" % name)


ALLEGRO = Model(
    "Attestor Allegro", deep=False, drop=NOISY_ON_REAL_CODE, catalogues=(),
    note="quietest; the rules that said nothing on 112,753 lines of "
         "working code. For every save and every commit.")

BELLADONNA = Model(
    "Attestor Belladonna", deep=False, drop=frozenset(), catalogues=(),
    note="the full detector catalogue, taint engines on. For review and CI.")

CIOCCOLATA = Model(
    "Attestor Cioccolata", deep=True, drop=frozenset(),
    catalogues=EXTRA_CATALOGUES,
    note="deep rules plus nativescan, multilang and advanced_rules. "
         "Highest reach, and the noisiest -- it keeps the five rules "
         "Allegro drops. precision_catalog is still not wired.")

MODELS = (ALLEGRO, BELLADONNA, CIOCCOLATA)
BY_NAME = {m.name.split()[-1].lower(): m for m in MODELS}


def get(name):
    key = str(name).strip().lower().replace("attestor ", "")
    if key not in BY_NAME:
        raise ModelError("no such model: %r (have %s)"
                         % (name, ", ".join(sorted(BY_NAME))))
    return BY_NAME[key]


def inventory():
    """What each tier actually carries, counted rather than described."""
    rows = []
    for model in MODELS:
        rows.append({
            "name": model.name,
            "detector_rules": len(model.rules()),
            "deep": model.deep,
            "dropped": len(model.drop),
            "extra_catalogues": len(model.catalogues),
            "note": model.note,
        })
    return rows


if __name__ == "__main__":                        # pragma: no cover
    print("%-18s %7s %6s %8s %11s" % ("model", "rules", "deep", "dropped",
                                      "catalogues"))
    print("-" * 62)
    for row in inventory():
        print("%-18s %7d %6s %8d %11d"
              % (row["name"], row["detector_rules"], row["deep"],
                 row["dropped"], row["extra_catalogues"]))
    print()
    for row in inventory():
        print("%s: %s" % (row["name"], row["note"]))
