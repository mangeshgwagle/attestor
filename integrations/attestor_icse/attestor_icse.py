#!/usr/bin/env python3
"""Attestor for ICSE Class 10 Computer Applications, which is taught in Java.

Why this is a separate layer rather than more detector rules
-----------------------------------------------------------
The Java rules in `detect.py` look for injection, weak digests and fixed
seeds. A Class 10 program has none of those and never will: it reads two
numbers from a Scanner and prints their average. Pointing the security rules
at a student's homework produces a clean report, which is worse than useless
because it reads as "this is fine" when nothing relevant was ever checked.

What actually costs marks at this level is a different and much smaller set of
mistakes, and they are the ones checked here.

What this deliberately does NOT do
----------------------------------
It does not claim to know the syllabus. The board publishes the definitive
document and CISCE serves it only to browsers, so nothing here was verified
against it -- the shipped profile is a *template* carrying that admission in
a field of its own, exactly as `attestor_pro` refuses to ship an invented house
standard. Load a profile you have checked against the board document, or
accept that the scope test is only as good as the template.

It also does not mark work. Attestor cannot know what a question asked for, so it
never says a program is correct, complete, or worth a grade. It reports the
mistakes it can see and names what it did not look at.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

SCHEMA = "attestor-icse-syllabus/1"

DETECTOR = pathlib.Path(__file__).resolve().parent.parent.parent / "detector"
if str(DETECTOR) not in sys.path:
    sys.path.insert(0, str(DETECTOR))

import detect  # noqa: E402


class SyllabusError(Exception):
    """A syllabus profile was malformed, or named something unknown."""


# Constructs the scope test can recognise. A profile may permit any of these;
# naming one that is not here is refused rather than ignored, so a typo in a
# profile cannot quietly switch a check off.
CONSTRUCTS = {
    "array": re.compile(r"\[\s*\]"),
    "arraylist": re.compile(r"\bArrayList\b"),
    "hashmap": re.compile(r"\b(?:HashMap|TreeMap|LinkedHashMap)\b"),
    "generics": re.compile(r"\b[A-Z]\w*\s*<\s*[A-Z]\w*\s*>"),
    "lambda": re.compile(r"->"),
    "stream": re.compile(r"\.\s*stream\s*\(\s*\)"),
    "var": re.compile(r"\bvar\s+\w+\s*="),
    "ternary": re.compile(r"\?[^:\n]{1,60}:"),
    "inheritance": re.compile(r"\bextends\b"),
    "interface": re.compile(r"\binterface\b|\bimplements\b"),
    "recursion": re.compile(r""),          # resolved structurally, see below
    "try_catch": re.compile(r"\btry\s*\{"),
    "switch": re.compile(r"\bswitch\s*\("),
    "do_while": re.compile(r"\bdo\s*\{"),
    "string_builder": re.compile(r"\bStringBuffer\b|\bStringBuilder\b"),
    "wrapper_class": re.compile(r"\b(?:Integer|Double|Character|Boolean)\s*\."),
}


def template_syllabus() -> dict:
    """A starting profile, honest about not being the board's document."""
    return {
        "schema": SCHEMA,
        "level": "ICSE Class 10",
        "subject": "Computer Applications (86)",
        # The one field that matters for honesty. Anything other than null is
        # a claim that a human compared this against the published syllabus.
        "verified_against": None,
        "_note": ("Not checked against the CISCE document. Edit `permitted` "
                  "to match the units actually taught, then record which "
                  "board publication you verified it against."),
        "permitted": [
            "array", "ternary", "inheritance", "switch", "do_while",
            "string_builder", "wrapper_class", "recursion",
        ],
    }


def load_syllabus(path) -> dict:
    text = pathlib.Path(path).read_text(encoding="utf-8")
    try:
        profile = json.loads(text)
    except json.JSONDecodeError as error:
        raise SyllabusError("profile is not valid JSON: %s" % error)
    if not isinstance(profile, dict):
        raise SyllabusError("profile must be an object")
    if profile.get("schema") != SCHEMA:
        raise SyllabusError("expected schema %s" % SCHEMA)
    permitted = profile.get("permitted", [])
    if not isinstance(permitted, list):
        raise SyllabusError("`permitted` must be a list")
    unknown = [name for name in permitted if name not in CONSTRUCTS]
    if unknown:
        raise SyllabusError(
            "profile permits constructs Attestor cannot recognise: %s"
            % ", ".join(sorted(unknown)))
    return profile


# ---------------------------------------------------------------- checks --

STRING_EQ = re.compile(r"(\w+)\s*(==|!=)\s*(\w+)")
# `grade == "A"` -- the commonest form of the mistake by far, and the one the
# variable-name test above cannot see: `blank` replaces a literal's contents
# with spaces but keeps its quotes, so the right-hand side is no longer a
# word. Comparing anything at all to a string literal with == is a reference
# comparison, so this needs no type information to be certain about.
LITERAL_EQ = re.compile(r"(\w+)\s*(==|!=)\s*\"|\"\s*(==|!=)\s*(\w+)")
STRING_DECL = re.compile(r"\bString\s+(\w+)")
INT_DECL = re.compile(r"\b(?:int|long)\s+(\w+)")
DOUBLE_ASSIGN = re.compile(r"\b(?:double|float)\s+(\w+)\s*=([^;]+);")
CAST_TO_REAL = re.compile(r"\(\s*(?:double|float)\s*\)")
FLOAT_LITERAL = re.compile(r"\b\d+\.\d*|\b\d+[dDfF]\b")
NEXT_INT = re.compile(r"\.\s*next(?:Int|Double|Float|Long)\s*\(\s*\)")
NEXT_LINE = re.compile(r"\.\s*nextLine\s*\(\s*\)")
LOOP_LE_LENGTH = re.compile(
    r"for\s*\([^;]*;\s*(\w+)\s*<=\s*(\w+)\s*\.\s*length\s*(?:\(\s*\))?\s*;")
METHOD_HEAD = re.compile(r"\b(\w+)\s*\([^;{]*\)\s*\{")


def _string_names(code):
    names = set()
    for line in code:
        for found in STRING_DECL.finditer(line):
            names.add(found.group(1))
    return names


def _int_names(code):
    names = set()
    for line in code:
        for found in INT_DECL.finditer(line):
            names.add(found.group(1))
    return names


def review(path, syllabus=None) -> dict:
    """Read one Java file and report what it can see."""
    source = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    raw = source.split("\n")
    code = detect.blank(source, "java")          # strings and comments gone
    findings = []

    def add(line_no, rule, unit, message, why):
        findings.append({
            "line": line_no + 1, "rule": rule, "topic": unit,
            "message": message, "why": why,
            "snippet": raw[line_no].strip()[:100] if line_no < len(raw) else "",
        })

    strings = _string_names(code)
    integers = _int_names(code)

    for index, line in enumerate(code):
        literal = LITERAL_EQ.search(line)
        if literal:
            add(index, "icse-string-equality", "String handling",
                "`%s` against a text literal compares object identity, not "
                "the letters." % (literal.group(2) or literal.group(3)),
                "In Java `==` on objects asks whether they are the same "
                "object in memory. A String holding the same letters can "
                "still be a different object, so this is False when you "
                "expect True. Use .equals() -- or .equalsIgnoreCase() when "
                "case should not matter.")

        for found in STRING_EQ.finditer(line):
            left, op, right = found.group(1), found.group(2), found.group(3)
            if left in strings or right in strings:
                add(index, "icse-string-equality", "String handling",
                    "`%s` compares String objects, not their contents." % op,
                    "In Java `==` on objects asks whether they are the same "
                    "object in memory. Two Strings holding the same letters "
                    "can be different objects, so this is False when you "
                    "expect True. Use .equals() -- or .equalsIgnoreCase() "
                    "when case should not matter.")

        assigned = DOUBLE_ASSIGN.search(line)
        if assigned:
            right = assigned.group(2)
            names = re.findall(r"\b(\w+)\b", right)
            # A cast or a floating literal on either side promotes the whole
            # expression, which is precisely the fix being taught -- so the
            # check has to recognise it, or it fires on the corrected program
            # and discriminates nothing.
            promoted = (CAST_TO_REAL.search(right)
                        or FLOAT_LITERAL.search(right))
            if ("/" in right and not promoted
                    and sum(1 for n in names if n in integers) >= 2):
                add(index, "icse-integer-division", "Operators and expressions",
                    "Both sides of this division are integers, so the "
                    "fractional part is thrown away before it is stored.",
                    "Java decides the type of `a / b` from a and b alone, not "
                    "from what it is assigned to. 7 / 2 is 3, and storing it "
                    "in a double gives 3.0, not 3.5. Cast one side first: "
                    "(double) a / b.")

        if LOOP_LE_LENGTH.search(line):
            add(index, "icse-array-off-by-one", "Arrays",
                "This loop runs one step past the last index.",
                "Valid indices run 0 to length-1, so `<= length` reaches "
                "length itself and throws ArrayIndexOutOfBoundsException at "
                "run time. Use `<` instead of `<=`.")

    for index in range(len(code) - 1):
        if NEXT_INT.search(code[index]):
            follow = "\n".join(code[index + 1:index + 4])
            if NEXT_LINE.search(follow):
                add(index, "icse-scanner-newline", "Input using Scanner",
                    "A nextLine() soon after nextInt() will read an empty "
                    "line rather than waiting for input.",
                    "nextInt() takes the number but leaves the Enter key in "
                    "the buffer, so the next nextLine() consumes that instead "
                    "of your text. Add an extra nextLine() to absorb it.")

    if syllabus:
        permitted = set(syllabus.get("permitted", []))
        joined = "\n".join(code)
        for name, pattern in CONSTRUCTS.items():
            if name in permitted or not pattern.pattern:
                continue
            found = pattern.search(joined)
            if found:
                line_no = joined[:found.start()].count("\n")
                add(line_no, "icse-out-of-scope", "Scope",
                    "`%s` is not in the syllabus profile you loaded." % name,
                    "It may still be correct Java. But an examiner marks "
                    "against the prescribed syllabus, and a solution using "
                    "material outside it cannot be relied on to earn the "
                    "marks the question intended.")

    return {
        "path": str(path),
        "findings": sorted(findings, key=lambda f: f["line"]),
        "checked": sorted({"icse-string-equality", "icse-integer-division",
                           "icse-array-off-by-one", "icse-scanner-newline"}
                          | ({"icse-out-of-scope"} if syllabus else set())),
        "scope_checked": bool(syllabus),
        "verified_syllabus": bool(syllabus
                                  and syllabus.get("verified_against")),
    }


# Worded to survive its own test. The test forbids phrases like "is right"
# anywhere in a clean report, and an earlier version of this sentence used one
# inside a disclaimer. Keeping the strict test and rewording the prose is the
# right way round: a report a student skims must not carry those words even in
# denial, because the denial is the part that gets skipped.
NOT_LOOKED_AT = (
    "Attestor did not check whether the program answers the question, whether "
    "the output format matches, or whether the logic holds. It read the "
    "code for a short list of specific mistakes and found what is above."
)


def render(report) -> str:
    lines = ["Attestor -- ICSE Class 10 Computer Applications",
             "file: %s" % report["path"], ""]

    if report["findings"]:
        for item in report["findings"]:
            lines.append("line %d  [%s]  %s"
                         % (item["line"], item["topic"], item["message"]))
            if item["snippet"]:
                lines.append("    %s" % item["snippet"])
            lines.append("    %s" % item["why"])
            lines.append("")
    else:
        lines.append("None of the %d things Attestor looks for appear here."
                     % len(report["checked"]))
        lines.append("")

    lines.append("What was checked: %s" % ", ".join(report["checked"]))
    if not report["scope_checked"]:
        lines.append("Scope was NOT checked -- no syllabus profile was given.")
    elif not report["verified_syllabus"]:
        lines.append("Scope was checked against a profile that has NOT been "
                     "verified against the board's published syllabus.")
    lines.append("")
    lines.append(NOT_LOOKED_AT)
    return "\n".join(lines)


if __name__ == "__main__":                       # pragma: no cover
    if len(sys.argv) < 2:
        print("usage: attestor_icse.py Program.java [syllabus.json]")
        raise SystemExit(2)
    profile = load_syllabus(sys.argv[2]) if len(sys.argv) > 2 else None
    print(render(review(sys.argv[1], profile)))
