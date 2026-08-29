#!/usr/bin/env python3
"""
googolplex.py -- write the NUMBER googolplex. The digits, not the word.

A googol is 10**100: one followed by 100 zeros (101 digits -- trivial).
A googolplex is 10**(10**100): one followed by a GOOGOL of zeros. Its full decimal
form is 10**100 + 1 digits long.

Attestor knows every one of those digits without computing the (unstorable) integer:
the digit at position 0 is 1, and every other digit is 0. So it will write the
TRUE digits of the TRUE number -- any digit, any range, streamed to a file until
your disk gives up -- and it is honest about the one thing nothing can do: finish.

  * 10**100 digits is 10**20 times more than the ~10**80 atoms in the universe.
  * at 1 TB/s that is ~10**88 seconds of writing -- about 10**71 ages of the cosmos.

That horizon is physics, not a bug. Attestor writes as much of the real number as you
will ever ask for, and tells you exactly where you are against infinity.

    python3 googolplex.py --digits 200        # the first 200 digits (1, then zeros)
    python3 googolplex.py --at 100000000       # the digit at position 100,000,000
    python3 googolplex.py --count              # how many digits googolplex has
    python3 googolplex.py --to plex.txt --max-digits 10000000   # write 10M real digits
    python3 googolplex.py --facts              # the honest physical reality
"""
from __future__ import annotations

import argparse
import sys

GOOGOL = 10 ** 100
TOTAL_DIGITS = GOOGOL + 1                       # '1' followed by a googol zeros
_CHUNK = 1 << 16
_ATOMS = 10 ** 80
_UNIVERSE_SECONDS = 435 * 10 ** 15             # ~1.37e17 s, order of magnitude


def digit(position: int) -> str:
    """The decimal digit of googolplex at `position` (0 = most significant)."""
    if position < 0 or position >= TOTAL_DIGITS:
        raise ValueError("position must be in [0, 10**100]")
    return "1" if position == 0 else "0"


def stream(start: int, count: int):
    """Yield up to `count` digit characters (in chunks) starting at `start`."""
    if start < 0 or count < 0:
        raise ValueError("start and count must be non-negative")
    end = min(start + count, TOTAL_DIGITS)
    position = start
    while position < end:
        if position == 0:
            yield "1"
            position += 1
        else:
            width = min(_CHUNK, end - position)
            yield "0" * width
            position += width


def write(out, start: int, count: int) -> int:
    """Write digits to a text stream; return how many were written."""
    written = 0
    for piece in stream(start, count):
        out.write(piece)
        written += len(piece)
    return written


def facts() -> list:
    return [
        "googolplex = 10**(10**100): a 1 followed by a googol (10**100) zeros.",
        "full decimal length : 10**100 + 1 digits.",
        "atoms in the universe: ~10**80  ->  googolplex has ~10**20 times more DIGITS.",
        "write speed 1 TB/s   : ~10**88 seconds to finish,",
        "age of the universe  : ~1.4x10**17 seconds  ->  ~10**71 universe-lifetimes.",
        "so: Attestor writes the real digits, as many as you ask. Finishing is physics.",
    ]


def _report_written(written: int, target: str) -> str:
    remaining = TOTAL_DIGITS - written
    return ("wrote %s real digits of googolplex to %s.\n"
            "still to go: %s digits (that is essentially all of it -- you have "
            "made no measurable dent, and that is the point)."
            % (format(written, ","), target, format(remaining, ",")))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--digits", type=int, default=100, help="write the first N digits to stdout")
    ap.add_argument("--start", type=int, default=0, help="start position (0 = most significant)")
    ap.add_argument("--at", type=int, help="print only the single digit at this position")
    ap.add_argument("--count", action="store_true", help="print googolplex's digit count")
    ap.add_argument("--to", help="write digits to this file instead of stdout")
    ap.add_argument("--max-digits", type=int, default=1 << 20,
                    help="with --to, how many digits to write before stopping")
    ap.add_argument("--facts", action="store_true", help="print the honest physical reality")
    args = ap.parse_args(argv)

    if args.facts:
        print("\n".join(facts()))
        return 0
    if args.count:
        print("googolplex has this many digits (a mere 101-digit number itself):")
        print(TOTAL_DIGITS)
        return 0
    if args.at is not None:
        print(digit(args.at))
        return 0
    if args.to:
        with open(args.to, "w", encoding="utf-8") as fh:
            written = write(fh, args.start, args.max_digits)
        print(_report_written(written, args.to))
        return 0
    write(sys.stdout, args.start, args.digits)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
