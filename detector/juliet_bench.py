#!/usr/bin/env python3
"""Measure Attestor against NIST Juliet ground truth, per CWE class.

Every other measure of Attestor's detection is graded by Attestor.  The mutation
gauntlet injects defects Attestor's own rules were written for, so it reports 100%
and that number means very little.  Juliet is external ground truth: each test
case ships a flawed variant and a fixed variant of the same file, labelled with
the CWE it plants, by NIST rather than by us.

The criterion here is **differential**.  Juliet's scaffolding -- ``rand()`` for
path selection, C-style casts, ``using namespace``, ``goto``, ``atoi`` -- is
identical in both variants, so "did Attestor report something" counts the harness
and says nothing about the planted flaw.  Only a finding the fixed variant does
*not* also produce can be attributed to the defect.  Measuring this the naive
way reported 51% detection; measuring it correctly reported 10%.

The corpus is not shipped.  It is ~153 MB of separately downloadable public
domain material from NIST, and this module reads whatever the caller supplies.
Without it, callers get an explicit ``corpus-unavailable`` result rather than a
fabricated score.

What a result does and does not mean
------------------------------------
A high per-CWE number means Attestor has a rule matching that shape.  A zero means
he is not looking for that class at all -- which is a statement about coverage,
never a statement that the code under test is safe.

Two archives, and the distinction matters
-----------------------------------------
NIST ships Juliet as separate C/C++ and Java corpora, and this harness reads
both.  Which one you point it at changes what the aggregate means:

* The **C/C++ archive** is overwhelmingly memory-safety material -- a family
  Attestor has never claimed to analyse -- so its aggregate is a ceiling
  measurement rather than a defect count.
* The **Java archive** covers injection, cryptography, resource handling and
  access control, which is what Attestor's Java rules are actually written for.
  It is the fairer measure of the languages this tool claims.

Reporting only the first number would grade Attestor almost entirely on classes
it never claimed while leaving its Java rules unmeasured, which is why Java
support exists here at all.  The two archives are also structurally different:
C separates the variants with `#ifndef OMITBAD`/`OMITGOOD`, while Java puts
`bad()` and `goodG2B()`/`goodB2G()` in one class, so each language needs its own
splitter (`split_variants` and `split_variants_java`).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import random
import re
import sys
import zipfile
from typing import Any, Sequence

import detect
import nativescan

SCHEMA = "attestor.juliet-benchmark/1.0"
VERSION = "4.1.4"

MAX_PER_CWE = 64
MAX_FILE_BYTES = 512 * 1024
DEFAULT_PER_CWE = 12
SAMPLE_SEED = 20260802

# Juliet separates the two variants with these guards; stripping one block
# yields the flawed file and stripping the other yields the fixed file.
_BLOCK = re.compile(
    r"#ifndef\s+(OMITBAD|OMITGOOD)\b(.*?)#endif\s*/\*\s*\1\s*\*/", re.S)
_CASE = re.compile(r"/testcases/CWE(\d+)_")
# Multi-file flow variants (51a/51b, 54a..54e) split the flaw across
# translation units.  They were excluded from this benchmark entirely, which
# was the right call while nothing here could read more than one file at a
# time -- but it hid 50,052 of the archive's 101,231 sources, 49% of the
# corpus, behind an exclusion rather than behind a measurement.
#
# They are now scannable: the parts of one case are concatenated into a single
# translation unit, which is what the linker sees and where the defect
# actually lives.  In the 51 shape the capacity is fixed in part `a`
# (`data = dataBadBuffer`, ten bytes) and the overrun happens in part `b`
# (`strcpy(data, source)` with eleven), so neither file alone contains it.
_MULTIFILE = re.compile(r"_\d+[a-z]\.(c|cpp)\Z")
_MULTIFILE_PART = re.compile(r"\A(.*_\d+)[a-z]\.(c|cpp)\Z")
# Java's flow variants split the same way (`_51a.java`, `_54b.java`). They are
# excluded for the same reason and, unlike the C shape, are not recombined:
# concatenating two Java compilation units is not what the compiler sees, so
# pretending otherwise would invent a translation unit that never exists.
_MULTIFILE_JAVA = re.compile(r"_\d+[a-z]\.java\Z")
_SOURCE_SUFFIXES = (".c", ".cpp", ".java")


class JulietError(ValueError):
    """The supplied corpus is missing or unusable."""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def split_variants(source: str) -> tuple[str, str] | None:
    """(flawed, fixed) for a paired test case, or None when it is not one."""
    kinds = {match.group(1) for match in _BLOCK.finditer(source)}
    if not {"OMITBAD", "OMITGOOD"} <= kinds:
        return None
    flawed = _BLOCK.sub(
        lambda m: "" if m.group(1) == "OMITGOOD" else m.group(2), source)
    fixed = _BLOCK.sub(
        lambda m: "" if m.group(1) == "OMITBAD" else m.group(2), source)
    return flawed, fixed


# Java Juliet carries no preprocessor, so `split_variants` cannot see it. The
# same pairing exists, expressed differently: one class holds `bad()` beside
# `goodG2B()`/`goodB2G()`, and the differential is built by deleting one side's
# methods rather than one side's `#ifndef` block.
#
# This is the half of the corpus that measures a language Attestor actually
# claims to analyse. Scoring only the C/C++ archive graded it almost entirely on
# memory-safety classes it never claimed, while its Java rules -- the second
# largest pack in the distribution -- went unmeasured.
_JAVA_METHOD = re.compile(
    r"^[ \t]*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?void\s+"
    r"(\w+)\s*\([^)]*\)[^{;]*\{", re.M)
_JAVA_BAD = re.compile(r"\Abad\w*\Z")
_JAVA_GOOD = re.compile(r"\Agood\w*\Z")


def _java_body_end(masked: str, brace_at: int) -> int | None:
    """Index just past the `}` closing the block that opens at `brace_at`.

    Brace-matched on the *masked* source -- `detect.blank` blanks comments and
    string contents while preserving every offset -- so a brace inside a literal
    or a comment cannot end a method early. Slicing then happens on the original
    text at the same indices.
    """
    depth = 0
    for index in range(brace_at, len(masked)):
        char = masked[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def split_variants_java(source: str) -> tuple[str, str] | None:
    """(flawed, fixed) for a Java test case, or None when it is not a pair.

    The flawed variant keeps `bad`/`badSink` and drops every `good*` method; the
    fixed variant does the reverse. Both sides must be present, or the file is
    not a differential pair and is skipped rather than scored as a miss.
    """
    try:
        masked = "\n".join(detect.blank(source, "java"))
    except Exception:                            # noqa: BLE001
        return None
    if len(masked) != len(source):               # offsets must line up exactly
        return None

    bad_spans: list[tuple[int, int]] = []
    good_spans: list[tuple[int, int]] = []
    for match in _JAVA_METHOD.finditer(masked):
        name = match.group(1)
        end = _java_body_end(masked, match.end() - 1)
        if end is None:
            continue
        span = (match.start(), end)
        if _JAVA_BAD.match(name):
            bad_spans.append(span)
        elif _JAVA_GOOD.match(name):
            good_spans.append(span)
    if not bad_spans or not good_spans:
        return None

    def without(spans: list[tuple[int, int]]) -> str:
        kept: list[str] = []
        cursor = 0
        for start, end in sorted(spans):
            if start < cursor:                   # overlapping match, bail out
                return source
            kept.append(source[cursor:start])
            cursor = end
        kept.append(source[cursor:])
        return "".join(kept)

    flawed, fixed = without(good_spans), without(bad_spans)
    if flawed == source or fixed == source:
        return None
    return flawed, fixed


def _split_for(source: str, suffix: str) -> tuple[str, str] | None:
    """Dispatch to the splitter the language actually uses."""
    return (split_variants_java(source) if suffix == ".java"
            else split_variants(source))


def _scan(source: str, suffix: str) -> collections.Counter:
    language = ("java" if suffix == ".java"
                else "cpp" if suffix == ".cpp" else "c")
    rules: collections.Counter = collections.Counter()
    for engine in (
            lambda: detect.scan_source(source, "case" + suffix, language,
                                       deep=True),
            lambda: nativescan.scan_text(source, "case" + suffix, language)):
        try:
            for finding in engine():
                rules[finding.rule] += 1
        except Exception:                       # noqa: BLE001 -- one engine
            continue                            # failing must not void the run
    return rules


def _cases(archive: zipfile.ZipFile) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = collections.defaultdict(list)
    for name in archive.namelist():
        if "/testcases/" not in name or not name.endswith(_SOURCE_SUFFIXES):
            continue
        match = _CASE.search(name)
        if not match or _MULTIFILE.search(name) or _MULTIFILE_JAVA.search(name):
            continue
        grouped["CWE-" + match.group(1)].append(name)
    return grouped


def _multifile_cases(archive: zipfile.ZipFile) -> dict[str, list[list[str]]]:
    """{cwe: [[part, part, ...], ...]} for cases split across files."""
    holding: dict[str, dict[str, list[str]]] = collections.defaultdict(
        lambda: collections.defaultdict(list))
    for name in archive.namelist():
        if "/testcases/" not in name or not name.endswith((".c", ".cpp")):
            continue
        cwe = _CASE.search(name)
        part = _MULTIFILE_PART.match(name)
        if not cwe or not part:
            continue
        holding["CWE-" + cwe.group(1)][part.group(1)].append(name)
    return {cwe: [sorted(parts) for _, parts in sorted(cases.items())]
            for cwe, cases in holding.items()}


def combine_parts(archive: zipfile.ZipFile,
                  parts: Sequence[str]) -> tuple[str, str] | None:
    """(source, suffix) for one multi-file case, or None if unreadable.

    Concatenating in part order is not a trick: `51a.c` declares the sink that
    `51b.c` defines, they are compiled and linked as one program, and the
    defect only exists across the join.  Reading them apart is precisely why
    these cases were unscorable before.
    """
    chunks: list[str] = []
    suffix = ".c"
    total = 0
    for name in parts:
        try:
            info = archive.getinfo(name)
            total += info.file_size
            if total > MAX_FILE_BYTES:
                return None
            chunks.append(archive.read(name).decode("utf-8", "replace"))
        except (OSError, KeyError, zipfile.BadZipFile):
            return None
        if name.endswith(".cpp"):
            suffix = ".cpp"
        elif name.endswith(".java"):
            suffix = ".java"
    return ("\n".join(chunks), suffix) if chunks else None


def measure(corpus: str | os.PathLike[str], *,
            per_cwe: int = DEFAULT_PER_CWE,
            multi_file: bool = False) -> dict[str, Any]:
    """Score Attestor against the supplied Juliet archive.

    `multi_file` includes the flow variants whose flaw is split across
    translation units. They are off by default because every number this
    benchmark has previously reported excluded them, and silently changing the
    denominator would make old and new runs look comparable when they are not.
    """
    if not isinstance(per_cwe, int) or isinstance(per_cwe, bool) or \
            not 1 <= per_cwe <= MAX_PER_CWE:
        raise JulietError("per_cwe must be an integer between 1 and %d"
                          % MAX_PER_CWE)
    path = os.fspath(corpus)
    if not os.path.isfile(path):
        raise JulietError("Juliet corpus not found: " + path[:200])
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise JulietError("Juliet corpus is not a readable archive") from exc

    with archive:
        units: dict[str, list[list[str]]] = {
            cwe: [[name] for name in names]
            for cwe, names in _cases(archive).items()}
        multi_cases = 0
        if multi_file:
            for cwe, cases in _multifile_cases(archive).items():
                units.setdefault(cwe, []).extend(cases)
                multi_cases += len(cases)
        grouped = units
        if not grouped:
            raise JulietError("archive contains no Juliet C/C++ test cases")
        chooser = random.Random(SAMPLE_SEED)
        rows: dict[str, Any] = {}
        # Every class a rule genuinely covers, not only its reported primary.
        # A rule that detects both siblings of a CWE parent was previously
        # scored as covering neither but one.
        rule_cwes = {rule: set(detect.covered_cwes(rule))
                     for rule in set(detect.RULE_CWE) | set(detect.RULE_CWE_ALSO)}
        all_covered = {cwe for cwes in rule_cwes.values() for cwe in cwes}
        for cwe, cases in sorted(grouped.items()):
            picked = sorted(cases)
            chooser.shuffle(picked)
            pairs = detected = exact = inverted = 0
            attributed: collections.Counter = collections.Counter()
            for parts in picked[:per_cwe]:
                combined = combine_parts(archive, parts)
                if combined is None:
                    continue
                source, suffix = combined
                variants = _split_for(source, suffix)
                if variants is None:
                    continue
                pairs += 1
                flawed_rules = _scan(variants[0], suffix)
                fixed_rules = _scan(variants[1], suffix)
                introduced = flawed_rules - fixed_rules
                if introduced:
                    detected += 1
                    attributed.update(introduced)
                    if any(cwe in rule_cwes.get(rule, ()) for rule in introduced):
                        exact += 1
                if fixed_rules - flawed_rules:
                    inverted += 1
            if not pairs:
                continue
            rows[cwe] = {
                "pairs": pairs,
                "flaw_introduced_a_finding": detected,
                "finding_matched_the_cwe": exact,
                "fixed_variant_introduced_a_finding": inverted,
                "detection_percent": round(100.0 * detected / pairs, 1),
                "exact_percent": round(100.0 * exact / pairs, 1),
                "inverted_percent": round(100.0 * inverted / pairs, 1),
                "has_rule_for_this_cwe": cwe in all_covered,
                "rules_attributed": attributed.most_common(3),
            }

    total = sum(row["pairs"] for row in rows.values())
    detected = sum(row["flaw_introduced_a_finding"] for row in rows.values())
    exact = sum(row["finding_matched_the_cwe"] for row in rows.values())
    inverted = sum(row["fixed_variant_introduced_a_finding"]
                   for row in rows.values())
    silent = sorted(cwe for cwe, row in rows.items()
                    if row["detection_percent"] == 0.0)
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "corpus": os.path.basename(path),
        "corpus_sha256": _file_digest(path),
        "sample_per_cwe": per_cwe,
        "criterion": "differential: only findings absent from the fixed variant",
        "classes": len(rows),
        "paired_cases": total,
        "detection_percent": round(100.0 * detected / total, 1) if total else 0.0,
        "exact_percent": round(100.0 * exact / total, 1) if total else 0.0,
        "inverted_percent": round(100.0 * inverted / total, 1) if total else 0.0,
        "multi_file_included": multi_file,
        "multi_file_cases_available": multi_cases,
        "classes_never_detected": len(silent),
        "silent_classes": silent,
        "by_cwe": rows,
        "limitations": [
            "a zero means Attestor has no rule for that class, never that the "
            "code under test is safe",
            "Juliet is predominantly memory-safety C/C++, a family Attestor does "
            "not claim to analyse; the aggregate is a ceiling, not a defect count",
            "multi-file flow variants are included only when multi_file=True; "
            "with it off, roughly half the archive is out of scope and the "
            "denominator is not comparable to a run with it on",
            "a multi-file case is scored as its parts concatenated into one "
            "translation unit, which is what the linker sees; it does not "
            "prove Attestor would join the same facts across separately scanned "
            "files on disk",
            "a sampled subset, not the full 101,231-case corpus",
            "'fixed variant introduced' overstates: a Juliet fix ships two "
            "functions (goodG2B and goodB2G) against the flaw's one, so the "
            "corrected file is larger and draws more incidental findings from "
            "unrelated rules -- measured at 100% on CWE-416 for a rule that "
            "produces no finding at all on the fixed variant",
            "some testcases leave the flawed helper outside the OMITBAD guard, "
            "so it appears in both variants and the differential cancels a real "
            "detection -- 9 of the 189 CWE-416 cases score as misses this way",
        ],
    }
    report["report_sha256"] = _sha(
        {key: value for key, value in report.items() if key != "report_sha256"})
    return report


def _file_digest(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_report(report: Any) -> tuple[bool, list[str]]:
    """Recompute a benchmark report's identity and internal consistency."""
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["report is not a mapping"]
    if report.get("schema") != SCHEMA:
        errors.append("unexpected schema")
    rows = report.get("by_cwe")
    if not isinstance(rows, dict):
        return False, errors + ["by_cwe must be a mapping"]
    if sum(row.get("pairs", 0) for row in rows.values()) != \
            report.get("paired_cases"):
        errors.append("paired_cases disagrees with the per-class rows")
    silent = sorted(cwe for cwe, row in rows.items()
                    if row.get("detection_percent") == 0.0)
    if silent != list(report.get("silent_classes", [])):
        errors.append("silent_classes disagrees with the per-class rows")
    recomputed = _sha({key: value for key, value in report.items()
                       if key != "report_sha256"})
    if report.get("report_sha256") != recomputed:
        errors.append("report digest does not match its content")
    return not errors, errors


def render(report: dict[str, Any], *, top: int = 12) -> str:
    lines = [
        "Attestor vs NIST Juliet (%s)" % report["corpus"],
        "=" * 64,
        "criterion : %s" % report["criterion"],
        "cases     : %d pairs across %d CWE classes"
        % (report["paired_cases"], report["classes"]),
        "flaw introduced a finding : %5.1f%%" % report["detection_percent"],
        "  ...with the right CWE   : %5.1f%%" % report["exact_percent"],
        "fixed variant introduced  : %5.1f%%" % report["inverted_percent"],
        "classes never detected    : %d of %d"
        % (report["classes_never_detected"], report["classes"]),
        "",
        "strongest classes:",
    ]
    ranked = sorted(report["by_cwe"].items(),
                    key=lambda item: -item[1]["exact_percent"])
    for cwe, row in ranked[:top]:
        if row["exact_percent"] <= 0.0:
            break
        lines.append("  %-9s pairs=%3d exact=%5.1f%%  %s"
                     % (cwe, row["pairs"], row["exact_percent"],
                        ", ".join(rule for rule, _ in row["rules_attributed"])))
    lines.append("")
    lines.extend("note: " + item for item in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus",
                        help="path to a Juliet zip from NIST (C/C++ or Java)")
    parser.add_argument("--per-cwe", type=int, default=DEFAULT_PER_CWE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = measure(args.corpus, per_cwe=args.per_cwe)
    except JulietError as exc:
        print("corpus-unavailable: %s" % exc)
        return 2
    print(json.dumps(report, indent=1, sort_keys=True) if args.json
          else render(report), end="" if args.json else "")
    return 0


__all__ = [
    "SCHEMA", "VERSION", "DEFAULT_PER_CWE", "MAX_PER_CWE", "JulietError",
    "split_variants", "measure", "verify_report", "render",
]


if __name__ == "__main__":
    raise SystemExit(main())
