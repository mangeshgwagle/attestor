#!/usr/bin/env python3
"""Which languages Attestor actually has rules for, and which he only reads.

The failure this exists to prevent
----------------------------------
Attestor classifies far more file types than he has rules for. A `.java` file is
recognised, opened, and scanned -- and comes back with nothing, because
`language_for` reports it as ``text`` and only the three language-agnostic
rules ever run. A Java file containing a command injection and an MD5 digest
produces **zero findings**.

Zero findings is the same output a genuinely clean file produces. Nothing in
the report distinguishes "Attestor looked and found nothing" from "Attestor has no
rules for this language and never looked". Every document in this project
insists that no finding is not evidence of safety; this is the case where the
report itself cannot tell you which one you are reading.

That matters most in exactly the situation Attestor would be pointed at a large
delivery codebase: a scan of a Java or C# repository returns clean, the
summary looks like a pass, and no rule ever ran.

What counts as covered
----------------------
A language is covered when at least one rule names it. The three wildcard
rules -- `hardcoded-secret`, `insecure-http-url` and their relatives -- run on
everything and are deliberately *not* counted: they find credentials and
cleartext URLs in any text, which is useful and is not a review of the
language. Counting them would make every file type look supported.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Iterable, Sequence

import detect

SCHEMA = "attestor.language-coverage/4.2"
VERSION = "4.2"

# Rules registered against "*" run on any text. Real coverage means a rule
# written for the language.
WILDCARD = "*"


def rule_counts() -> dict[str, int]:
    """Language -> number of rules written specifically for it."""
    counts: dict[str, int] = {}
    for rule in detect.RULES:
        for language in getattr(rule, "langs", ()) or ():
            if language != WILDCARD:
                counts[language] = counts.get(language, 0) + 1
    return counts


def wildcard_rules() -> int:
    return sum(1 for rule in detect.RULES
               if WILDCARD in (getattr(rule, "langs", ()) or ()))


def covered_languages() -> frozenset[str]:
    return frozenset(rule_counts())


def language_of(path: str | pathlib.Path) -> str:
    if hasattr(detect, "language_for"):
        return detect.language_for(str(path))
    return "text"


def assess(path: str | pathlib.Path) -> dict[str, Any]:
    """What Attestor can and cannot say about one file."""
    language = language_of(path)
    counts = rule_counts()
    specific = counts.get(language, 0)
    return {
        "path": str(path),
        "language": language,
        "specific_rules": specific,
        "wildcard_rules": wildcard_rules(),
        "covered": specific > 0,
        "note": ("%d rules apply to %s" % (specific, language) if specific
                 else ("no rule targets this file's language; only the %d "
                       "language-agnostic rules ran, so a clean result here "
                       "means unexamined rather than checked"
                       % wildcard_rules())),
    }


def survey(paths: Iterable[str | pathlib.Path]) -> dict[str, Any]:
    """Split a set of files into examined and unexamined, and say why."""
    examined: list[dict[str, Any]] = []
    unexamined: list[dict[str, Any]] = []
    by_language: dict[str, int] = {}
    for path in paths:
        verdict = assess(path)
        by_language[verdict["language"]] = \
            by_language.get(verdict["language"], 0) + 1
        (examined if verdict["covered"] else unexamined).append(verdict)
    return {
        "schema": SCHEMA, "version": VERSION,
        "files": len(examined) + len(unexamined),
        "examined": len(examined),
        "unexamined": len(unexamined),
        "unexamined_languages": sorted(
            {item["language"] for item in unexamined}),
        "by_language": dict(sorted(by_language.items(),
                                   key=lambda kv: -kv[1])),
        "covered_languages": sorted(covered_languages()),
        "rule_counts": dict(sorted(rule_counts().items(),
                                   key=lambda kv: -kv[1])),
        "details": unexamined,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?",
                        help="file or directory to survey")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not args.target:
        counts = rule_counts()
        if args.json:
            print(json.dumps({"schema": SCHEMA, "rule_counts": counts,
                              "wildcard_rules": wildcard_rules()}, indent=2))
            return 0
        print("Languages Attestor has rules for:")
        for language, count in sorted(counts.items(), key=lambda kv: -kv[1]):
            print("  %-10s %3d rules" % (language, count))
        print("  %-10s %3d rules that run on any text"
              % ("(any)", wildcard_rules()))
        print("\nA file in any other language is read, not reviewed.")
        return 0

    root = pathlib.Path(args.target)
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file())
    report = survey(files)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print("files            : %d" % report["files"])
    print("examined         : %d" % report["examined"])
    print("unexamined       : %d" % report["unexamined"])
    if report["unexamined_languages"]:
        print("no rules for     : %s"
              % ", ".join(report["unexamined_languages"]))
        print("\nA clean result for those files means Attestor has no rule for "
              "the language,\nnot that the code is free of defects.")
    # Non-zero when something went unexamined, so a pipeline can notice.
    return 1 if report["unexamined"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
