#!/usr/bin/env python3
"""Measure a rule on Juliet idioms it has never seen.

What the existing split does not catch
--------------------------------------
`juliet_bench` and `juliet_corpus` both group their held-out split by
*testcase*, which is correct and necessary: the flawed and fixed variants of
one testcase are near-identical text, and splitting them across the boundary
turns the score into a memorisation score.

But a testcase-grouped split says nothing about the other way a rule can be
overfitted. Juliet names its files::

    CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_loop_03.c
    \\_______ class _______/  \\____ family ____/ \\_/
                                                variant

and the *family* is the idiom -- which type, which source, which sink. A rule
written by reading `char_alloca_loop` cases will pass a testcase-grouped
holdout on other `char_alloca_loop` cases and still know nothing about
`wchar_t_declare_cpy`.

That is not hypothetical. Every rule improved in this project was improved by
reading Juliet's idioms: `vfprintf` for CWE-134, `data = dataBuffer - 8` for
CWE-124, the `strn*` family for CWE-121. Each was a real gap, and each was
found by looking at what NIST writes. Whether the resulting rule generalises
is a different question, and this module is the only thing here that asks it.

How to read the result
----------------------
Two numbers per rule: detection on families the author could have seen, and
detection on families held out entirely. A rule that detects the *defect*
scores similarly on both. A rule that has learned Juliet's dialect scores well
on seen families and badly on unseen ones, and the gap is the size of the
problem.

A small unseen sample is noisy, so the family count is reported alongside.
Three held-out families is not a measurement.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
import zipfile

import detect
import juliet_corpus

SCHEMA = "attestor.juliet-families/1.0"
VERSION = "4.1.4"

HOLDOUT_FRACTION = 5          # one family in five is held out
MAX_PAIRS_PER_FAMILY = 12     # so one huge family cannot dominate
MAX_FILE_BYTES = 512 * 1024

# `..._CWE805_char_alloca_loop_03.c` -> family `CWE805_char_alloca_loop`
_VARIANT = re.compile(r"_\d+[a-z]?\Z")
_MULTIFILE = re.compile(r"_\d+[b-z]\.(?:c|cpp)\Z")


def family_of(name: str) -> tuple[str, str] | None:
    """(CWE class, idiom family) for a testcase path, or None."""
    base = name.split("/")[-1]
    if not base.endswith((".c", ".cpp")):
        return None
    stem = base.rsplit(".", 1)[0]
    if "__" not in stem:
        return None
    head, rest = stem.split("__", 1)
    cwe = head.split("_")[0]
    family = _VARIANT.sub("", rest)
    return (cwe, family) if family else None


def is_holdout_family(family: str) -> bool:
    """Stable across runs, and independent of how many families exist."""
    return int(hashlib.sha256(family.encode()).hexdigest(), 16) \
        % HOLDOUT_FRACTION == 0


def measure(archive_path: str, want_cwe: str, rule: str) -> dict:
    """Detection on seen families against detection on unseen ones."""
    seen = {"detected": 0, "pairs": 0, "families": set()}
    unseen = {"detected": 0, "pairs": 0, "families": set()}
    per_family: collections.Counter = collections.Counter()

    with zipfile.ZipFile(archive_path) as archive:
        names = sorted(n for n in archive.namelist()
                       if "/testcases/" in n and n.endswith((".c", ".cpp"))
                       and not _MULTIFILE.search(n))
        for name in names:
            parsed = family_of(name)
            if not parsed or parsed[0] != want_cwe:
                continue
            _, family = parsed
            if per_family[family] >= MAX_PAIRS_PER_FAMILY:
                continue
            try:
                raw = archive.read(name)
            except KeyError:
                continue
            if len(raw) > MAX_FILE_BYTES:
                continue
            variants = juliet_corpus.split_variants(
                raw.decode("utf-8", "replace"))
            if not variants:
                continue
            flawed, fixed = variants
            language = "cpp" if name.endswith(".cpp") else "c"

            def fires(source: str) -> bool:
                try:
                    found = detect.scan_source(source, name, language,
                                               deep=True)
                except Exception:                        # noqa: BLE001
                    return False
                return any(getattr(f, "rule", "") == rule for f in found)

            per_family[family] += 1
            bucket = unseen if is_holdout_family(family) else seen
            bucket["pairs"] += 1
            bucket["families"].add(family)
            # The same differential criterion the rest of this project uses:
            # a finding the fixed variant also produces says nothing.
            if fires(flawed) and not fires(fixed):
                bucket["detected"] += 1

    def summarise(bucket: dict) -> dict:
        return {"families": len(bucket["families"]),
                "pairs": bucket["pairs"],
                "detected": bucket["detected"],
                "detection_percent": round(
                    100.0 * bucket["detected"] / bucket["pairs"], 1)
                if bucket["pairs"] else 0.0}

    seen_out, unseen_out = summarise(seen), summarise(unseen)
    return {
        "schema": SCHEMA, "version": VERSION, "cwe": want_cwe, "rule": rule,
        "seen_families": seen_out, "unseen_families": unseen_out,
        "gap_points": round(seen_out["detection_percent"]
                            - unseen_out["detection_percent"], 1),
        # Stated rather than left to the reader: a handful of held-out
        # families cannot support a conclusion either way.
        "unseen_is_thin": unseen_out["families"] < 4,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("archive", help="Juliet/SARD zip")
    parser.add_argument("--pair", action="append", required=True,
                        metavar="CWE:RULE",
                        help="e.g. CWE124:c-buffer-underwrite; repeatable")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    reports = []
    for pair in args.pair:
        if ":" not in pair:
            print("expected CWE:RULE, got %r" % pair, file=sys.stderr)
            return 2
        cwe, rule = pair.split(":", 1)
        reports.append(measure(args.archive, cwe, rule))

    if args.json:
        print(json.dumps(reports, indent=2))
        return 0

    print("%-9s %-24s %19s %19s %7s"
          % ("CWE", "rule", "seen families", "unseen families", "gap"))
    print("-" * 84)
    for report in reports:
        seen, unseen = report["seen_families"], report["unseen_families"]
        note = "  (thin)" if report["unseen_is_thin"] else ""
        print("%-9s %-24s %6.1f%% %3df/%4dp %6.1f%% %3df/%4dp %+6.1f%s"
              % (report["cwe"], report["rule"],
                 seen["detection_percent"], seen["families"], seen["pairs"],
                 unseen["detection_percent"], unseen["families"],
                 unseen["pairs"], -report["gap_points"], note))
    print("\nA rule that found the defect scores alike on both. A rule that "
          "learned\nJuliet's dialect scores well on seen families and badly "
          "on unseen ones.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
