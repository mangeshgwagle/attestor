#!/usr/bin/env python3
"""
clones.py -- find copy-pasted code (duplication), deterministically.

Duplicated blocks are where bugs breed: you fix one copy and forget the other.
This finds them with no compiler and no heuristics you have to trust. It strips
blank lines and comments, normalises whitespace, hashes every window of N code
lines, and wherever a window recurs it grows the match line-by-line into the whole
duplicated block. It then reports each clone as a pair of locations with its size.

Type-1 duplication (identical modulo layout and comments). It reads only -- never
executes or edits. Exit code = number of clone blocks found, so CI can gate on it.

    clones.py src/                       # duplicated blocks across a tree
    clones.py a.py b.py --min-lines 8    # only clones of 8+ lines
    clones.py src/ --json                # machine-readable
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "build", "dist", "node_modules"}
DEFAULT_MIN_LINES = 6


@dataclass
class Clone:
    lines: int
    blocks: list           # [(path, start_line, end_line), ...]


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _normalize(src: str) -> list:
    """(original_lineno, normalized_text) for code lines; blanks/comments dropped."""
    out = []
    for idx, raw in enumerate(src.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append((idx, re.sub(r"\s+", " ", stripped)))
    return out


def _hash(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()


def _window_text(lines: list, start: int, size: int) -> str:
    return "\n".join(text for _lineno, text in lines[start:start + size])


def _seed_windows(index: dict, size: int) -> dict:
    """hash -> [(path, window_start_index), ...] over every N-line window."""
    seeds = {}
    for path, lines in index.items():
        for i in range(len(lines) - size + 1):
            seeds.setdefault(_hash(_window_text(lines, i, size)), []).append((path, i))
    return seeds


def _extend(a: list, ai: int, b: list, bi: int) -> int:
    """How many consecutive normalized lines match starting at a[ai] / b[bi]."""
    length = 0
    while (ai + length < len(a) and bi + length < len(b)
           and a[ai + length][1] == b[bi + length][1]):
        length += 1
    return length


def _partner(group: list, path: str, i: int, consumed: set):
    for cand_path, cand_i in group:
        if (cand_path, cand_i) != (path, i) and (cand_path, cand_i) not in consumed:
            return cand_path, cand_i
    return None


def _consume(consumed: set, path: str, start: int, length: int) -> None:
    for k in range(length):
        consumed.add((path, start + k))


def _block(index: dict, path: str, start: int, length: int) -> tuple:
    lines = index[path]
    return path, lines[start][0], lines[start + length - 1][0]


def find_clones(paths, min_lines: int = DEFAULT_MIN_LINES) -> list:
    index = {path: _normalize(_read(path)) for path in collect_paths(paths)}
    seeds = _seed_windows(index, min_lines)
    consumed = set()
    clones = []
    positions = sorted((path, i) for path, lines in index.items()
                       for i in range(max(0, len(lines) - min_lines + 1)))
    for path, i in positions:
        if (path, i) in consumed:
            continue
        group = seeds.get(_hash(_window_text(index[path], i, min_lines)), [])
        partner = _partner(group, path, i, consumed)
        if partner is None:
            continue
        other_path, other_i = partner
        length = _extend(index[path], i, index[other_path], other_i)
        clones.append(Clone(length, [_block(index, path, i, length),
                                     _block(index, other_path, other_i, length)]))
        _consume(consumed, path, i, length)
        _consume(consumed, other_path, other_i, length)
    clones.sort(key=lambda clone: clone.lines, reverse=True)
    return clones


def collect_paths(paths) -> list:
    out = []
    for raw in paths:
        if os.path.isdir(raw):
            for root, dirs, files in os.walk(raw):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                out += [os.path.join(root, f) for f in sorted(files) if f.endswith(".py")]
        elif raw.endswith(".py") or os.path.isfile(raw):
            out.append(raw)
    return out


def render(clones: list) -> str:
    if not clones:
        return "no duplicated blocks found. clean."
    total = sum(clone.lines for clone in clones)
    lines = ["%d clone block(s), %d duplicated lines" % (len(clones), total), "=" * 60]
    for clone in clones:
        where = "   <->   ".join("%s:%d-%d" % (p, s, e) for p, s, e in clone.blocks)
        lines.append("%d lines:  %s" % (clone.lines, where))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Python files or directories")
    ap.add_argument("--min-lines", type=int, default=DEFAULT_MIN_LINES,
                    help="shortest duplicated block to report (default 6)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    clones = find_clones(args.paths, max(1, args.min_lines))
    if args.json:
        print(json.dumps([asdict(clone) for clone in clones], indent=2))
    else:
        print(render(clones))
    return min(len(clones), 250)


if __name__ == "__main__":
    sys.exit(main())
