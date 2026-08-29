#!/usr/bin/env python3
"""Labelled windows from Attestor's own mutation engine, with no external corpus.

Why this exists
---------------
`train_gate.py` learns from NIST Juliet, which is a 146 MB archive that is not
shipped and has to be fetched.  Everything needed to build an equivalent
corpus is already in this tree: `mutation_gauntlet.mutate` injects one defect
per applicable mutator into real source and hands back both the mutated text
and the untouched baseline it was derived from.  That pair is the same shape
as a Juliet testcase -- one flawed variant, one fixed variant, differing by a
line or two -- so the windowing, grouping and control methodology that
`juliet_corpus` already got right transfers unchanged.

This module therefore borrows rather than reimplements: `juliet_corpus._anchored`
decides which lines a window covers and `juliet_corpus.Example` is the row
type, so a corpus built here and a corpus built from Juliet are the same thing
to everything downstream.

Where the source text comes from
--------------------------------
Not from `codegen.py` alone.  That generator emits clean, dependency-free
stdlib code, and the measurement is unambiguous: 73 generated files yield 32
mutation pairs across 6 mutator kinds, three quarters of them from a single
mutator, because the patterns the other mutators look for -- TLS verification
flags, yaml loaders, shell-enabled subprocess calls -- are simply not present
in that architecture.  Attestor's own 466 Python files yield 714 pairs across 10
kinds.  Real hand-written source is the corpus; generated source is a
supplement, not a substitute.

The grouping key
----------------
`pair` is the source file, never the file-and-mutator.  Two mutations of one
file share almost all of their text, so splitting between them would put
near-identical windows on both sides of the holdout and turn the reported
number into a memorisation score -- the exact failure `juliet_corpus.group_split`
exists to prevent, and the one that previously reported 0.943 where the truth
was near 0.80.  Grouping by file keeps every mutation of a file together.

What this corpus is not
-----------------------
Injected defects are not found defects.  A mutator writes a known pattern at a
known offset, so the labels are exact, but the distribution is the mutators'
distribution and not the distribution of bugs people actually write.  A gate
trained here should be read as "separates these injected patterns from their
own baselines", which is a weaker claim than Juliet's and is why the shuffled
label control below is not optional.
"""
from __future__ import annotations

import argparse
import difflib
import json
import pathlib
import stat as stat_module
import sys
from typing import Iterable, Iterator, Sequence


DEFAULT_DETECTOR = str(
    pathlib.Path(__file__).resolve().parent.parent.parent / "detector")
DEFAULT_WINDOW_LINES = 12
# A single run should not be able to exhaust memory on a laptop.  Both numbers
# are boundaries rather than tuning knobs; raising them costs RAM linearly.
MAX_SOURCE_BYTES = 512 * 1024
MAX_FILES = 20_000
SKIP_DIRS = frozenset({
    "__pycache__", ".git", "node_modules", ".venv", "venv", "build", "dist"})


class CorpusBuildError(ValueError):
    """The requested corpus cannot be built from the requested roots."""


def _detector(path: str):
    if path not in sys.path:
        sys.path.insert(0, path)
    import detect
    import juliet_corpus
    import mutation_gauntlet
    return juliet_corpus, mutation_gauntlet, detect


def iter_sources(roots: Sequence[str],
                 max_files: int = MAX_FILES) -> Iterator[tuple[str, str]]:
    """Yield `(relative_path, text)` for every readable Python file under *roots*.

    The path is relative to its root, never absolute.  It becomes the grouping
    key, and a key carrying `/tmp/tmpzx_i6f62/` would make the corpus identity
    depend on which directory the run happened to use.  Two roots that contain
    the same relative path therefore collapse into one group; that direction is
    safe, because over-grouping only ever keeps more rows on one side of the
    holdout, while under-grouping is the failure that inflates the score.

    Symlinks are not followed.  A file that cannot be decoded is skipped rather
    than replaced character by character: a mutator matching against U+FFFD
    would inject a defect at a position that does not exist in the real bytes.
    """
    seen: set[tuple[int, int]] = set()
    emitted = 0
    for root in roots:
        base = pathlib.Path(root)
        if not base.exists():
            raise CorpusBuildError("corpus root does not exist: %s" % root)
        for path in sorted(base.rglob("*.py")):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            try:
                info = path.lstat()
                if not stat_module.S_ISREG(info.st_mode):
                    continue
                # One physical file reached through two roots must not become
                # two groups; that would split its own mutations across the
                # holdout boundary.
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                if info.st_size > MAX_SOURCE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            emitted += 1
            if emitted > max_files:
                return
            yield path.relative_to(base).as_posix(), text


def examples_from_mutation(juliet_corpus, baseline: str, mutated: str,
                           pair: str, cwe: str,
                           size: int = DEFAULT_WINDOW_LINES) -> list:
    """Diff-anchored windows over the lines a mutator actually changed.

    Both sides of every changed region are emitted, always.  A mutator that
    works by deleting a guard leaves the mutated side with nothing to point at,
    and emitting only the side that has lines would produce a negative and no
    positive at all -- `_anchored` widens a zero-width region to the line it
    sits at for exactly this reason.
    """
    flawed = mutated.splitlines()
    fixed = baseline.splitlines()
    matcher = difflib.SequenceMatcher(None, flawed, fixed, autojunk=False)
    rows: list = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        rows += [juliet_corpus.Example(text, 1, pair, cwe)
                 for text in juliet_corpus._anchored(flawed, i1, i2, size)]
        rows += [juliet_corpus.Example(text, 0, pair, cwe)
                 for text in juliet_corpus._anchored(fixed, j1, j2, size)]
    return rows


def iter_corpus(roots: Sequence[str], detector: str = DEFAULT_DETECTOR,
                size: int = DEFAULT_WINDOW_LINES,
                limit: int | None = None) -> Iterator:
    """Yield labelled `Example` windows built from *roots* by mutation."""
    juliet_corpus, mutation_gauntlet, detect = _detector(detector)
    produced = 0
    for relative, text in iter_sources(roots):
        try:
            mutations = mutation_gauntlet.mutate(text, ".py")
        except Exception:
            # A mutator that cannot parse one file must not end the run; the
            # file simply contributes nothing.
            continue
        for mutation in mutations:
            baseline = mutation.get("baseline_code", text)
            mutated = mutation.get("code")
            if not isinstance(mutated, str) or mutated == baseline:
                continue
            # Mutators carry the rule they are meant to trip, not a CWE.  The
            # detector already maps rule to CWE, so the corpus reports the same
            # taxonomy the scanner does instead of inventing a second one.
            rule = str(mutation.get("expected_rule") or "")
            cwe = str(getattr(detect, "RULE_CWE", {}).get(rule, "") or rule
                      or "CWE-unknown")
            for row in examples_from_mutation(
                    juliet_corpus, baseline, mutated, relative, cwe, size):
                yield row
                produced += 1
                if limit is not None and produced >= limit:
                    return


def build(roots: Sequence[str], detector: str = DEFAULT_DETECTOR,
          size: int = DEFAULT_WINDOW_LINES, limit: int | None = None) -> list:
    rows = list(iter_corpus(roots, detector, size, limit))
    if not rows:
        raise CorpusBuildError(
            "no mutation windows were produced from: %s" % ", ".join(roots))
    return rows


def stats(rows: Sequence) -> dict:
    positive = sum(1 for row in rows if row.label == 1)
    by_cwe: dict[str, int] = {}
    for row in rows:
        by_cwe[row.cwe] = by_cwe.get(row.cwe, 0) + 1
    return {
        "windows": len(rows),
        "positive": positive,
        "negative": len(rows) - positive,
        "groups": len({row.pair for row in rows}),
        "by_cwe": dict(sorted(by_cwe.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attestor_corpus",
        description="Build labelled windows from Attestor's own mutation engine.")
    parser.add_argument("roots", nargs="+", help="directories of Python source")
    parser.add_argument("--detector", default=DEFAULT_DETECTOR)
    parser.add_argument("--window-lines", type=int, default=DEFAULT_WINDOW_LINES)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        rows = build(args.roots, args.detector, args.window_lines, args.limit)
    except CorpusBuildError as exc:
        print("attestor_corpus: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(stats(rows), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
