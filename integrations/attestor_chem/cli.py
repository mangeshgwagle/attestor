#!/usr/bin/env python3
"""Strict offline exam/study CLI for Attestor's pharmacy reference."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys


HERE = Path(__file__).resolve(strict=True).parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import exam
import principles


BOUNDARY = (
    "ATTESTOR PHARMA 4.2 - EXAM THEORY REFERENCE; "
    "NOT A LAB PROTOCOL OR CLINICAL DOSING SOURCE"
)


def _count(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("count must be an integer") from exc
    if not 1 <= number <= 20:
        raise argparse.ArgumentTypeError("count must be between 1 and 20")
    return number


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attestor pharma",
        description=(
            "Offline pharmaceutical-formation study reference. "
            "Not clinical advice, a manufacturing protocol, or a current "
            "pharmacopoeia."),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    find = commands.add_parser("find", allow_abbrev=False)
    find.add_argument("term", nargs="+")

    show = commands.add_parser("show", allow_abbrev=False)
    show.add_argument("key", nargs="+")

    teach = commands.add_parser("teach", allow_abbrev=False)
    teach.add_argument("key", nargs="+")

    why = commands.add_parser("why", allow_abbrev=False)
    why.add_argument("key", nargs="+")

    derive = commands.add_parser("derive", allow_abbrev=False)
    derive.add_argument("target", nargs="+")

    recall = commands.add_parser("recall", allow_abbrev=False)
    recall.add_argument("count", nargs="?", type=_count, default=5)
    recall.add_argument("--seed", type=int)

    commands.add_parser("patterns", allow_abbrev=False)

    listing = commands.add_parser("list", allow_abbrev=False)
    listing.add_argument(
        "kind", nargs="?",
        choices=("formulas", "methods", "preparations", "substances"))

    commands.add_parser("coverage", allow_abbrev=False)
    commands.add_parser("check", allow_abbrev=False)
    return parser


def _emit(text: str) -> None:
    print(BOUNDARY)
    print()
    print(text)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "find":
            query = " ".join(args.term)
            hits = exam.find(query)
            if not hits:
                print("attestor pharma: nothing matches %r" % query, file=sys.stderr)
                return 1
            lines = ["%-12s %-28s %s" % hit for hit in hits]
            _emit("\n".join(lines))
            return 0
        if args.command == "show":
            _emit(exam.show(" ".join(args.key)))
            return 0
        if args.command == "teach":
            _emit(exam.teach(" ".join(args.key)))
            return 0
        if args.command == "why":
            _emit(exam.why(" ".join(args.key)))
            return 0
        if args.command == "derive":
            _emit(principles.derive(" ".join(args.target)))
            return 0
        if args.command == "recall":
            _emit(exam.recall(args.count, seed=args.seed))
            return 0
        if args.command == "patterns":
            lines = ["%-34s %s" % (key, pattern.name)
                     for key, pattern in principles.PATTERNS.items()]
            _emit("\n".join(lines))
            return 0
        if args.command == "list":
            print(BOUNDARY)
            exam._list(args.kind or "")
            return 0
        if args.command == "coverage":
            _emit(exam.coverage())
            return 0
        if args.command == "check":
            print(BOUNDARY)
            return 1 if exam.check() else 0
    except KeyError as exc:
        print("attestor pharma: %s" % str(exc)[:500], file=sys.stderr)
        return 1
    except Exception as exc:  # Defensive CLI boundary; do not leak internals.
        print("attestor pharma: operation failed (%s)" % type(exc).__name__,
              file=sys.stderr)
        return 4
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
