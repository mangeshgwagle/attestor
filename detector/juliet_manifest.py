#!/usr/bin/env python3
"""Juliet's own answer to "which line is the defect".

What this adds
--------------
`juliet_corpus` labels a window by the *file* it came from: 1 if the flawed
variant, 0 if the corrected one. Its docstring is honest that this is weaker
than it looks -- "the label says which variant a window came from, not that
the window is itself the defect" -- so a window of pure boilerplate out of a
flawed file is still labelled 1.

The archive ships a better label and nothing here was reading it. `manifest.xml`
names the exact line::

    <testcase>
      <file path="CWE114_Process_Control__w32_char_connect_socket_01.c">
        <flaw line="121" name="CWE-114: Process Control"/>
      </file>
    </testcase>

Across the C/C++ v1.3 archive that is 64,123 testcases, 105,234 files and
65,263 labelled flaw lines over 119 CWE classes.

What it is good for
-------------------
Three things the variant label cannot do:

* **Training on the defect rather than on the file.** A positive window can be
  centred on the flaw line, and other windows from the same file become
  negatives -- which removes the boilerplate-labelled-positive noise entirely.
* **Naming the class.** 119 CWEs, so a model can be asked which, not merely
  whether.
* **Scoring a rule on the line it fired at.** `juliet_bench`'s `exact_percent`
  asks whether the reported CWE matched. With flaw lines it can ask whether
  the finding landed on the defect, which is the question a reader actually
  has, and which will produce a smaller and more honest number.

Reading XML from an untrusted archive
-------------------------------------
`xml.etree` is the only parser available under this package's stdlib-only
rule, and it is not safe on hostile input by default: a document may declare
entities that expand exponentially (the "billion laughs" shape) and exhaust
memory before any element is produced. CPython's expat does not resolve
*external* entities, so XXE is not the exposure here -- expansion is.

So a DOCTYPE is refused outright before parsing starts. Juliet's manifest has
none, no legitimate SARD manifest needs one, and refusing the whole class of
entity attacks is cheaper and more certain than trying to bound their effect.
"""
from __future__ import annotations

import io
import pathlib
import re
import xml.etree.ElementTree as ElementTree
import zipfile
from typing import Iterator, NamedTuple

SCHEMA = "attestor.juliet-manifest/1.0"
VERSION = "4.2"

MANIFEST_MEMBERS = ("C/manifest.xml", "manifest.xml", "Java/manifest.xml")

# The C/C++ manifest is 15.3 MB. The ceiling leaves room for a larger suite
# while still refusing something that is not a manifest at all.
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_FLAWS = 2_000_000

_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_CWE_IN_NAME = re.compile(r"CWE-(\d+)")


class ManifestError(ValueError):
    """The manifest is missing, unreadable, or not one."""


class Flaw(NamedTuple):
    """One labelled defect: a file, a line, and what NIST calls it."""
    path: str          # as written in the manifest, e.g. CWE114_..._01.c
    line: int
    cwe: str           # normalised to "CWE-114"
    name: str          # the full label, e.g. "CWE-114: Process Control"


def _member(archive: zipfile.ZipFile) -> zipfile.ZipInfo:
    by_name = {info.filename: info for info in archive.infolist()}
    for candidate in MANIFEST_MEMBERS:
        if candidate in by_name:
            return by_name[candidate]
    # Fall back to any manifest.xml at one level, rather than guessing deeply.
    for info in archive.infolist():
        if info.filename.rsplit("/", 1)[-1] == "manifest.xml":
            return info
    raise ManifestError("no manifest.xml in the archive")


def _parse(raw: bytes) -> ElementTree.Element:
    if _DOCTYPE.search(raw[:4096]):
        raise ManifestError(
            "manifest declares a DOCTYPE; refused because entity expansion is "
            "unbounded in the stdlib parser and no real manifest needs one")
    try:
        return ElementTree.parse(io.BytesIO(raw)).getroot()
    except ElementTree.ParseError as error:
        raise ManifestError("manifest is not well-formed XML: %s" % error)


def iter_flaws(archive_path: str) -> Iterator[Flaw]:
    """Every labelled flaw line, streamed in manifest order."""
    path = pathlib.Path(archive_path)
    if not path.is_file():
        raise ManifestError("no archive at %s" % archive_path)
    with zipfile.ZipFile(path) as archive:
        info = _member(archive)
        if info.file_size > MAX_MANIFEST_BYTES:
            raise ManifestError("manifest is %d bytes; limit is %d"
                                % (info.file_size, MAX_MANIFEST_BYTES))
        raw = archive.read(info)
    root = _parse(raw)

    produced = 0
    for testcase in root.iter("testcase"):
        for element in testcase.findall("file"):
            member = (element.get("path") or "").strip()
            if not member:
                continue
            for flaw in element.findall("flaw"):
                line = flaw.get("line")
                name = (flaw.get("name") or "").strip()
                try:
                    number = int(line)
                except (TypeError, ValueError):
                    continue
                if number < 1:
                    continue
                found = _CWE_IN_NAME.search(name)
                # Normalised to CWE-114, not CWE-0114: the rest of this
                # project spells them without padding and a mismatch here
                # would silently join nothing.
                cwe = ("CWE-%d" % int(found.group(1))) if found else ""
                produced += 1
                if produced > MAX_FLAWS:
                    raise ManifestError("manifest declares more than %d flaws"
                                        % MAX_FLAWS)
                yield Flaw(member, number, cwe, name)


def index(archive_path: str) -> dict[str, list[Flaw]]:
    """Flaws grouped by the file they are in.

    Keyed on the manifest's own path, which is a bare filename rather than the
    archive path the source lives at. Callers matching against a zip member
    should compare the basename; joining on the full path finds nothing and
    looks exactly like a corpus with no labels.
    """
    grouped: dict[str, list[Flaw]] = {}
    for flaw in iter_flaws(archive_path):
        grouped.setdefault(flaw.path, []).append(flaw)
    return grouped


def summarise(archive_path: str) -> dict:
    """Counts, for a caller deciding whether the labels are worth using."""
    by_cwe: dict[str, int] = {}
    files = set()
    total = 0
    for flaw in iter_flaws(archive_path):
        total += 1
        files.add(flaw.path)
        by_cwe[flaw.cwe] = by_cwe.get(flaw.cwe, 0) + 1
    return {"schema": SCHEMA, "version": VERSION,
            "flaws": total, "files_with_flaws": len(files),
            "cwe_classes": len(by_cwe),
            "largest": sorted(by_cwe.items(), key=lambda kv: -kv[1])[:10]}


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("archive", help="Juliet/SARD zip")
    parser.add_argument("--file", help="show the flaws for one source file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.file:
            found = index(args.archive).get(args.file, [])
            if args.json:
                print(json.dumps([f._asdict() for f in found], indent=2))
            else:
                print("%s: %d flaw(s)" % (args.file, len(found)))
                for flaw in found:
                    print("  line %-6d %s" % (flaw.line, flaw.name))
            return 0
        report = summarise(args.archive)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("flaws            : %d" % report["flaws"])
            print("files with flaws : %d" % report["files_with_flaws"])
            print("CWE classes      : %d" % report["cwe_classes"])
            print("largest classes  :")
            for cwe, count in report["largest"]:
                print("  %-10s %6d" % (cwe or "(unnamed)", count))
    except ManifestError as error:
        print("juliet-manifest: %s" % error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
