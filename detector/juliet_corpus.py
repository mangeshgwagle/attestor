#!/usr/bin/env python3
"""Turn a Juliet/SARD archive into labelled training windows Attestor can learn from.

Why this module exists
----------------------
The neural gate was trained on the mutation corpus, which is weak supervision
derived from Attestor's own rules -- so it could only ever learn to agree with the
rules it came from.  Juliet is different: 40,863 of its single-file testcases
ship a flawed and a corrected variant of the *same* function, labelled by
someone other than Attestor.  That is real ground truth, and it is the only corpus
here that can teach the gate something the rules do not already know.

The three leaks
---------------
Juliet is notoriously easy to score well on for reasons that have nothing to do
with finding defects.  Every one of these had to be removed, because each alone
is enough to produce a model that looks excellent and detects nothing:

1. **The comments announce the answer.**  The flawed variant carries
   ``/* POTENTIAL FLAW: Set data to NULL */`` and the fix carries
   ``/* FIX: Check for NULL before dereferencing */``.  A bag-of-words model
   trained on un-stripped Juliet learns the word "FLAW" and nothing else.

2. **The identifiers announce the answer.**  Functions are named
   ``CWE476_NULL_Pointer_Dereference__struct_01_bad`` and ``goodG2B``; sinks are
   ``badSink`` and ``goodSink``.  Stripping comments but keeping names simply
   moves the leak from one token stream to another.

3. **The storage class announces the answer.**  Juliet exports the flawed
   function (``void …_bad()``) and makes every corrected one a ``static``
   helper.  The correlation is perfect, so a model can score well on the single
   token ``static`` while learning nothing about memory safety.  Storage and
   inline specifiers are therefore dropped.

4. **The file name announces the class.**  Which is why the pair key below is
   used only for grouping splits, never as a feature.

Even with all four removed, the two variants still differ in incidental ways --
the fix ships two functions where the flaw ships one, so line offsets drift.
Windows are therefore anchored on the *diff* between the variants rather than
on set difference, which keeps the training signal on the defect instead of on
the shape of Juliet's boilerplate.

What a caller gets
------------------
Examples carrying ``pair`` -- the testcase both halves came from.  Splitting on
that key rather than at random is not optional: the flawed and fixed variants of
one testcase are near-identical text, so a random split puts two halves of the
same pair on opposite sides and the held-out score measures memorisation.  That
mistake previously reported 0.943 here where the true figure was near 0.80.
"""
from __future__ import annotations

import codecs
import hashlib
import os
import pathlib
import re
import stat
import unicodedata
import zipfile
from typing import Iterable, Iterator, NamedTuple

SCHEMA = "attestor.juliet-corpus/1.0"
VERSION = "4.1.4"

DEFAULT_WINDOW_LINES = 4
MAX_WINDOW_LINES = 64

# The public Juliet archive fits comfortably inside these limits.  They are
# security boundaries, not tuning hints: archive metadata is attacker input,
# and ``ZipFile.read`` would otherwise allocate whatever it claims.
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 250_000
MAX_ENTRY_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250.0
READ_CHUNK_BYTES = 64 * 1024
_REPARSE_POINT = 0x400
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)

# Multi-file flow variants (``_51a.c``, ``_51b.c`` ...) split the source and the
# sink across translation units; no single-file scanner can pair them, so they
# are excluded rather than counted as misses.
_MULTIFILE = re.compile(r"_\d+[a-z]\.(?:c|cpp)$")
_TESTCASE = re.compile(r"/testcases/")

_BLOCK = re.compile(r"#ifndef\s+(OMITBAD|OMITGOOD)\b(.*?)#endif\s*/\*\s*\1\s*\*/",
                    re.S)

# Any identifier that carries the label in its name.  Matched case-insensitively
# against whole identifiers, so `data` survives and `badSink` does not.
_LEAKY_NAME = re.compile(
    r"^(?:"
    r"cwe\d+\w*"                      # CWE476_NULL_Pointer_Dereference__…
    r"|\w*_(?:bad|good)\w*"           # …_bad, …_good, …_goodG2B
    r"|(?:bad|good)\w*"               # bad, badSink, goodG2B, goodB2G
    r"|\w*(?:bad|good)(?:sink|source|\d*)"
    r"|[bg]2[gb]\w*"                  # B2G, G2B
    r")$", re.I)
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_NEUTRAL = "fn"
# Perfectly correlated with the label in Juliet and irrelevant to the defect.
_STORAGE = re.compile(r"\b(?:static|extern|inline|register)\s+")


class Example(NamedTuple):
    """One labelled window. `pair` is the grouping key, never a feature."""
    text: str
    label: int          # 1 = drawn from the flawed variant, 0 = from the fix
    pair: str           # testcase path both variants came from
    cwe: str


class CorpusError(ValueError):
    """The archive or the requested shape is unusable."""


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _member_path(info: zipfile.ZipInfo) -> pathlib.PurePosixPath:
    """Validate and canonicalise one ZIP member without extracting it."""
    # On Windows ZipInfo converts backslashes to slashes in ``filename`` but
    # preserves the central-directory spelling in ``orig_filename``.  Inspect
    # the latter so a non-canonical archive cannot become silently acceptable.
    name = getattr(info, "orig_filename", info.filename)
    if (not isinstance(name, str) or not name or name != info.filename
            or "\x00" in name or "\\" in name):
        raise CorpusError("archive contains an invalid member path")
    directory = info.is_dir()
    body = name[:-1] if directory and name.endswith("/") else name
    path = pathlib.PurePosixPath(body)
    windows = pathlib.PureWindowsPath(body)
    canonical = path.as_posix() + ("/" if directory else "")
    if (not body or path.is_absolute() or windows.is_absolute() or windows.drive
            or canonical != name
            or any(part in {"", ".", ".."} for part in path.parts)):
        raise CorpusError("unsafe archive member path: %r" % name)
    return path


def _preflight(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Validate all central-directory metadata before reading one payload."""
    entries = archive.infolist()
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        raise CorpusError("archive has %d entries; limit is %d" %
                          (len(entries), MAX_ARCHIVE_ENTRIES))
    seen: set[str] = set()
    total = 0
    kept: list[zipfile.ZipInfo] = []
    for info in entries:
        path = _member_path(info)
        collision_key = unicodedata.normalize("NFC", path.as_posix()).casefold()
        if collision_key in seen:
            raise CorpusError("duplicate/case-colliding archive member: %s" %
                              info.filename)
        seen.add(collision_key)
        if info.flag_bits & 0x1:
            raise CorpusError("encrypted archive members are not accepted")
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if kind and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise CorpusError("non-regular archive member: %s" % info.filename)
        if info.file_size < 0 or info.compress_size < 0:
            raise CorpusError("negative archive member size")
        if info.file_size > MAX_ENTRY_UNCOMPRESSED_BYTES:
            # An oversized member that this reader could open is still fatal.
            # One it can never open is skipped instead, and the difference is
            # the whole point: failing the archive outright made the real NIST
            # Juliet corpus unreadable, because `C/testcasesupport/main.cpp`
            # is 19.2 MB of generated scaffolding outside `/testcases/`. One
            # member the reader never touches took all 106,316 others with it,
            # and `train_gate` and `rule_forge` with them.
            #
            # Narrowed to non-testcase members so the guard still covers
            # everything that gets read. Skipping is safe rather than lenient
            # even so: the member is never handed to `archive.open`, nothing
            # decompresses, `_stream_member` re-checks the identical limit
            # while reading anything that *is* opened, and its bytes stay out
            # of `total` precisely because they are never expanded.
            if _TESTCASE.search(info.filename):
                raise CorpusError("archive member exceeds %d bytes: %s" %
                                  (MAX_ENTRY_UNCOMPRESSED_BYTES,
                                   info.filename))
            continue
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise CorpusError("archive exceeds %d uncompressed bytes" %
                              MAX_TOTAL_UNCOMPRESSED_BYTES)
        if info.file_size:
            if info.compress_size == 0:
                raise CorpusError("archive member has an impossible size ratio")
            ratio = info.file_size / float(info.compress_size)
            if ratio > MAX_COMPRESSION_RATIO:
                raise CorpusError("archive member compression ratio %.1f exceeds %.1f: %s"
                                  % (ratio, MAX_COMPRESSION_RATIO,
                                     info.filename))
        kept.append(info)
    return kept


def _stream_member(archive: zipfile.ZipFile,
                   info: zipfile.ZipInfo) -> tuple[str, int]:
    """Decode one already-bounded member incrementally."""
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    text: list[str] = []
    total = 0
    try:
        with archive.open(info, "r") as stream:
            while True:
                chunk = stream.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ENTRY_UNCOMPRESSED_BYTES:
                    raise CorpusError("archive member expanded beyond its limit: %s"
                                      % info.filename)
                text.append(decoder.decode(chunk))
            text.append(decoder.decode(b"", final=True))
    except CorpusError:
        raise
    except (OSError, EOFError, RuntimeError, NotImplementedError,
            zipfile.BadZipFile) as error:
        raise CorpusError("cannot read archive member %s: %s"
                          % (info.filename, error)) from error
    if total != info.file_size:
        raise CorpusError("archive member size changed while reading: %s"
                          % info.filename)
    return "".join(text), total


def strip_comments(source: str) -> str:
    """Remove C/C++ comments without being fooled by comment-like literals.

    A regex cannot do this correctly: `printLine("/* not a comment */")` would
    lose half the string, and `"\\""` would end it early.  So this walks the
    source once, tracking whether it is inside a string, a character literal or
    a comment, which is short enough to be obviously right.
    """
    out: list[str] = []
    index, length = 0, len(source)
    while index < length:
        char = source[index]
        pair = source[index:index + 2]
        if pair == "/*":
            end = source.find("*/", index + 2)
            index = length if end < 0 else end + 2
            out.append(" ")
        elif pair == "//":
            end = source.find("\n", index)
            index = length if end < 0 else end
            out.append(" ")
        elif char in "\"'":
            quote, start = char, index
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                if source[index] == "\n" and quote == "\"":
                    break            # unterminated; do not run off the file
                index += 1
            out.append(source[start:index])
        else:
            out.append(char)
            index += 1
    return "".join(out)


def neutralise_names(source: str) -> str:
    """Rewrite identifiers that state the label to a single neutral token."""
    return _IDENTIFIER.sub(
        lambda m: _NEUTRAL if _LEAKY_NAME.match(m.group(0)) else m.group(0),
        source)


def declassify(source: str) -> str:
    """Strip every textual leak and normalise whitespace."""
    cleaned = _STORAGE.sub("", neutralise_names(strip_comments(source)))
    return "\n".join(" ".join(line.split())
                     for line in cleaned.splitlines() if line.strip())


def split_variants(source: str) -> tuple[str, str] | None:
    """(flawed, fixed) for a testcase that carries both, else None."""
    kinds = {match.group(1) for match in _BLOCK.finditer(source)}
    if not {"OMITBAD", "OMITGOOD"} <= kinds:
        return None
    flawed = _BLOCK.sub(
        lambda m: "" if m.group(1) == "OMITGOOD" else m.group(2), source)
    fixed = _BLOCK.sub(
        lambda m: "" if m.group(1) == "OMITBAD" else m.group(2), source)
    return flawed, fixed


def windows(source: str, size: int = DEFAULT_WINDOW_LINES) -> list[str]:
    """Every contiguous `size`-line window of already-declassified source."""
    if not isinstance(size, int) or isinstance(size, bool) or \
            not 1 <= size <= MAX_WINDOW_LINES:
        raise CorpusError("window size must be an int in 1..%d" % MAX_WINDOW_LINES)
    lines = source.splitlines()
    if len(lines) < size:
        return ["\n".join(lines)] if lines else []
    return ["\n".join(lines[start:start + size])
            for start in range(len(lines) - size + 1)]


def cwe_of(path: str) -> str:
    match = re.search(r"/(CWE\d+)_", path)
    return match.group(1).replace("CWE", "CWE-") if match else "CWE-unknown"


MAX_WINDOWS_PER_REGION = 6


def _anchored(lines: list[str], start: int, end: int, size: int) -> list[str]:
    """Windows of `size` lines covering a changed region.

    `start == end` is the important case, not a degenerate one: when the fix
    works by *inserting* a guard, the flawed variant has nothing to point at,
    and the position where the guard is missing is exactly the defect.  A
    zero-width region is therefore widened to the line it sits at rather than
    skipped.
    """
    if not lines:
        return []
    if len(lines) <= size:
        return ["\n".join(lines)]
    start = min(max(start, 0), len(lines) - 1)
    end = min(max(end, start + 1), len(lines))
    lowest = max(0, start - size + 1)
    highest = min(len(lines) - size, end - 1)
    begins = list(range(lowest, max(highest, lowest) + 1))
    if len(begins) > MAX_WINDOWS_PER_REGION:
        step = len(begins) / float(MAX_WINDOWS_PER_REGION)
        begins = [begins[int(index * step)]
                  for index in range(MAX_WINDOWS_PER_REGION)]
    return ["\n".join(lines[begin:begin + size]) for begin in begins]


def examples_from(source: str, pair: str, cwe: str,
                  size: int = DEFAULT_WINDOW_LINES) -> list[Example]:
    """Windows covering the lines that actually differ between the variants.

    Set difference was the obvious way to do this and it was wrong: because the
    fix ships two functions where the flaw ships one, every window after the
    first divergence shifts by a line and counts as "different", so the corpus
    filled up with `#include` headers labelled as defects.  Aligning the two
    variants first and keeping only windows over a changed region puts the
    label back on the code that changed.
    """
    import difflib

    parts = split_variants(source)
    if not parts:
        return []
    flawed = declassify(parts[0]).splitlines()
    fixed = declassify(parts[1]).splitlines()
    matcher = difflib.SequenceMatcher(None, flawed, fixed, autojunk=False)
    rows: list[Example] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # Both sides of every change, always.  Emitting only the side that has
        # lines makes an inserted guard produce negatives and no positive at
        # all, which is the majority of Juliet's NULL-dereference families.
        rows += [Example(text, 1, pair, cwe)
                 for text in _anchored(flawed, i1, i2, size)]
        rows += [Example(text, 0, pair, cwe)
                 for text in _anchored(fixed, j1, j2, size)]
    return rows


def iter_archive(archive_path: str, size: int = DEFAULT_WINDOW_LINES,
                 limit: int | None = None) -> Iterator[Example]:
    """Stream labelled windows from a strictly bounded Juliet ZIP."""
    if not isinstance(size, int) or isinstance(size, bool) or \
            not 1 <= size <= MAX_WINDOW_LINES:
        raise CorpusError("window size must be an int in 1..%d" % MAX_WINDOW_LINES)
    if (limit is not None and
            (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0)):
        raise CorpusError("limit must be a non-negative integer or None")

    path = pathlib.Path(archive_path)
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before):
            raise CorpusError("refusing symlink/reparse archive: %s" % archive_path)
        if not stat.S_ISREG(before.st_mode):
            raise CorpusError("archive is not a regular file: %s" % archive_path)
        if before.st_size > MAX_ARCHIVE_BYTES:
            raise CorpusError("archive exceeds %d bytes" % MAX_ARCHIVE_BYTES)
        descriptor = os.open(path, os.O_RDONLY | _BINARY | _NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        if (not stat.S_ISREG(opened.st_mode) or _is_reparse(opened)
                or (opened.st_dev, opened.st_ino) !=
                (before.st_dev, before.st_ino)
                or opened.st_size != before.st_size
                or opened.st_size > MAX_ARCHIVE_BYTES):
            os.close(descriptor)
            raise CorpusError("archive changed while opening: %s" % archive_path)
        try:
            handle = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        try:
            archive = zipfile.ZipFile(handle)
        except BaseException:
            handle.close()
            raise
    except CorpusError:
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise CorpusError("cannot read %s: %s" % (archive_path, error)) from error
    with handle, archive:
        entries = _preflight(archive)
        selected = [info for info in entries
                    if _TESTCASE.search(info.filename)
                    and info.filename.endswith((".c", ".cpp"))
                    and not _MULTIFILE.search(info.filename)]
        selected.sort(key=lambda info: info.filename)
        if limit is not None:
            selected = selected[:limit]
        actual_total = 0
        for info in selected:
            source, amount = _stream_member(archive, info)
            actual_total += amount
            if actual_total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise CorpusError("streamed data exceeds aggregate boundary")
            yield from examples_from(source, info.filename,
                                     cwe_of(info.filename), size)


def summarise(rows: Iterable[Example]) -> dict:
    """Counts a caller can print or pin in a test."""
    rows = list(rows)
    pairs = {row.pair for row in rows}
    positive = sum(row.label for row in rows)
    by_cwe: dict[str, int] = {}
    for row in rows:
        by_cwe[row.cwe] = by_cwe.get(row.cwe, 0) + 1
    digest = hashlib.sha256(
        "\n".join("%d\t%s" % (row.label, row.text) for row in rows)
        .encode("utf-8")).hexdigest()
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "examples": len(rows),
        "pairs": len(pairs),
        "positive": positive,
        "negative": len(rows) - positive,
        "classes": len(by_cwe),
        "corpus_sha256": digest,
        "limitations": [
            "labels say which variant a window came from, not that the window "
            "is itself the defect",
            "single-file testcases only; multi-file flow variants are excluded",
            "Juliet is synthetic C/C++ and its defects are cleaner than real "
            "ones, so a score here is an upper bound",
        ],
    }


def group_split(rows: Iterable[Example], holdout: float = 0.2,
                seed: int = 0) -> tuple[list[Example], list[Example]]:
    """Split by testcase, so no pair straddles the boundary.

    The flawed and fixed halves of one testcase differ by a line or two.  A
    random split therefore trains on one half and tests on the other, which
    measures recall of memorised text; grouping by `pair` is what makes the
    held-out number mean anything.
    """
    if not 0.0 < holdout < 1.0:
        raise CorpusError("holdout must be between 0 and 1")
    rows = list(rows)
    pairs = sorted({row.pair for row in rows})
    keyed = sorted(pairs, key=lambda name: hashlib.sha256(
        ("%d\t%s" % (seed, name)).encode("utf-8")).hexdigest())
    cut = int(len(keyed) * (1.0 - holdout))
    train_pairs = set(keyed[:cut])
    train = [row for row in rows if row.pair in train_pairs]
    test = [row for row in rows if row.pair not in train_pairs]
    return train, test


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("archive", help="Juliet/SARD zip")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_LINES)
    parser.add_argument("--limit", type=int, default=None,
                        help="only read the first N testcases")
    args = parser.parse_args(argv)
    try:
        rows = list(iter_archive(args.archive, args.window, args.limit))
    except CorpusError as error:
        print("error: %s" % error)
        return 2
    print(json.dumps(summarise(rows), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
