#!/usr/bin/env python3
"""Turn the fetched Juliet C/C++ archive into a labelled, balanced corpus.

Reads ``corpus/raw/juliet-1.3.zip`` (offline), extracts each single-file
testcase's **flawed** and **fixed** variants, copies them under
``corpus/samples/juliet_c/<CWE>/`` and writes one JSON line per sample to
``corpus/manifest.jsonl``:

    {"id": "juliet-c-CWE78-0001", "path": "corpus/samples/juliet_c/CWE78/..._01.c",
     "language": "c", "cwe": "CWE-78", "vulnerable": true, "source": "juliet-1.3",
     "notes": "bad() path present"}

Design notes
------------
* **Balanced by construction.** Every source file ships a flawed and a fixed
  variant (Juliet's ``#ifndef OMITBAD`` / ``#ifndef OMITGOOD`` blocks), so the
  pair becomes one ``vulnerable:true`` and one ``vulnerable:false`` sample.
  That is what lets the evaluator measure *precision* (safe samples flagged) and
  not just recall.
* **Single-file testcases only.** Multi-file *flow* variants (``_51a.c`` …
  ``_54e.c``) split the defect across translation units; no single-file scanner
  can see them, so including them would pollute recall with unfindable flaws.
  They are excluded, exactly as ``detector/juliet_corpus.py`` does.
* **Capped + deterministic.** At most ``MAX_FILES_PER_CWE`` source files per CWE
  (each yielding two samples), selected in sorted filename order, so re-runs are
  byte-identical and the corpus stays under the size/eval-time budget.
"""
from __future__ import annotations

import json
import os
import re
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RAW = os.path.join(HERE, "raw")
SAMPLES = os.path.join(HERE, "samples")
MANIFEST = os.path.join(HERE, "manifest.jsonl")

JULIET_ZIP = os.path.join(RAW, "juliet-1.3.zip")

# Cap per-CWE: each source file becomes 2 samples, so 50 files == 100 samples
# (well within the brief's ~300/CWE budget). Deterministic, balanced.
MAX_FILES_PER_CWE = 50
MAX_CWES = 40                      # upper bound on distinct CWE classes selected
MAX_TOTAL_SAMPLES = 4000           # hard ceiling on manifest size (fast eval)

# Multi-file flow variants split the defect across translation units; exclude.
_MULTIFILE = re.compile(r"_\d+[a-z]\.(?:c|cpp)$")
# A real testcase lives under testcases/CWE####_... ; ignore testcasesupport etc.
_TESTCASE = re.compile(r"/testcases/CWE(\d+)_")
# Juliet separates the flawed and fixed variants with these preprocessor blocks.
_BLOCK = re.compile(
    r"#ifndef\s+(OMITBAD|OMITGOOD)\b(.*?)#endif\s*/\*\s*\1\s*\*/", re.S)


def cwe_of(member: str) -> str | None:
    match = _TESTCASE.search(member)
    return ("CWE-%d" % int(match.group(1))) if match else None


def language_of(member: str) -> str:
    return "cpp" if member.endswith(".cpp") else "c"


def split_variants(source: str) -> tuple[str, str] | None:
    """(flawed, fixed) for a paired testcase, else None."""
    kinds = {m.group(1) for m in _BLOCK.finditer(source)}
    if not {"OMITBAD", "OMITGOOD"} <= kinds:
        return None
    flawed = _BLOCK.sub(
        lambda m: "" if m.group(1) == "OMITGOOD" else m.group(2), source)
    fixed = _BLOCK.sub(
        lambda m: "" if m.group(1) == "OMITBAD" else m.group(2), source)
    return flawed, fixed


def _safe_name(base: str, good: bool) -> str:
    name = os.path.basename(base)
    stem, ext = os.path.splitext(name)
    return "%s.%s%s" % (stem, "good" if good else "bad", ext)


def build() -> tuple[int, int, dict[str, int]]:
    os.makedirs(SAMPLES, exist_ok=True)
    if not os.path.exists(JULIET_ZIP):
        raise SystemExit("missing archive %s -- run `python corpus/fetch.py`"
                         % JULIET_ZIP)

    # 1) Group candidate single-file testcases by CWE.
    by_cwe: dict[str, list[str]] = {}
    with zipfile.ZipFile(JULIET_ZIP) as archive:
        for info in archive.infolist():
            name = info.filename
            if not name.endswith((".c", ".cpp")):
                continue
            if _MULTIFILE.search(name):
                continue
            cwe = cwe_of(name)
            if not cwe:
                continue
            by_cwe.setdefault(cwe, []).append(name)

    # Deterministic: sort CWEs and files, then cap.
    cwes = sorted(by_cwe)[:MAX_CWES]
    selected: list[tuple[str, str]] = []      # (member, cwe)
    for cwe in cwes:
        files = sorted(by_cwe[cwe])[:MAX_FILES_PER_CWE]
        selected.extend((f, cwe) for f in files)

    rows: list[dict] = []
    per_cwe: dict[str, int] = {}
    seq = 0
    with zipfile.ZipFile(JULIET_ZIP) as archive:
        for member, cwe in selected:
            if len(rows) >= MAX_TOTAL_SAMPLES:
                break
            source = archive.read(member).decode("utf-8", errors="replace")
            parts = split_variants(source)
            if parts is None:
                continue
            flawed, fixed = parts
            lang = language_of(member)
            out_dir = os.path.join(SAMPLES, "juliet_c", cwe.replace("-", ""))
            os.makedirs(out_dir, exist_ok=True)

            seq += 1
            sub = cwe.replace("-", "")

            vpath = os.path.join(out_dir, _safe_name(member, good=False))
            with open(vpath, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(flawed)
            rows.append({
                "id": "juliet-c-%s-%04d" % (sub, seq),
                "path": os.path.relpath(vpath, ROOT).replace("\\", "/"),
                "language": lang,
                "cwe": cwe,
                "vulnerable": True,
                "source": "juliet-1.3",
                "notes": "bad() path present",
            })

            if len(rows) >= MAX_TOTAL_SAMPLES:
                break
            spath = os.path.join(out_dir, _safe_name(member, good=True))
            with open(spath, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(fixed)
            rows.append({
                "id": "juliet-c-%s-%04d" % (sub, seq),
                "path": os.path.relpath(spath, ROOT).replace("\\", "/"),
                "language": lang,
                "cwe": cwe,
                "vulnerable": False,
                "source": "juliet-1.3",
                "notes": "good() path (safe variant)",
            })
            per_cwe[cwe] = per_cwe.get(cwe, 0) + 1

    with open(MANIFEST, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    vuln = sum(1 for r in rows if r["vulnerable"])
    safe = len(rows) - vuln
    print("wrote %s" % MANIFEST)
    print("  samples      : %d" % len(rows))
    print("  vulnerable   : %d   safe: %d" % (vuln, safe))
    print("  CWE classes  : %d" % len(per_cwe))
    for cwe in sorted(per_cwe, key=lambda k: -per_cwe[k])[:12]:
        print("    %-10s %d source files -> %d samples"
              % (cwe, per_cwe[cwe], per_cwe[cwe] * 2))
    return len(rows), len(per_cwe), per_cwe


if __name__ == "__main__":
    raise SystemExit(build() and 0 or 1)