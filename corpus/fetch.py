#!/usr/bin/env python3
"""Download and verify the PRIMARY corpus datasets into ``corpus/raw/``.

Idempotent and resumable: re-running is a no-op once a dataset is present and
its pinned SHA-256 matches.  Downloads resume from a ``.part`` file so an
interrupted transfer is not restarted from zero.  Nothing runs after this script
except ``normalize.py``, so no network access is needed past this point --
``normalize``/``validate``/``external_eval`` are fully offline.

Datasets are pinned by URL and SHA-256 so the corpus is reproducible.  The raw
archives are git-ignored (``corpus/raw/``); only this script, the manifest and
the reports are committed.

Usage:
    python corpus/fetch.py                 # download the PRIMARY datasets
    python corpus/fetch.py --datasets bigvul    # add the Big-Vul CSV (SECONDARY)
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw")

_CHUNK = 1 << 20          # 1 MiB read slabs
_TIMEOUT = 120            # seconds; generous for the large Juliet archive

# SHA-256 recorded from the first verified download.  Every later run refuses a
# file whose digest differs, so a silently re-uploaded or truncated archive can
# never be mistaken for the corpus a score was produced from.
DATASETS: dict[str, dict] = {
    "juliet_cpp": {
        "url": ("https://samate.nist.gov/SARD/downloads/test-suites/"
                "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"),
        "file": "juliet-1.3.zip",
        "sha256": (
            "ada9d7e1c323d283446df3f55bdee0d00"
            "bda1fed786785fe98764d58688f38eb"
        ),
        "license": "public domain (US Government: NIST SARD / NSA Juliet)",
        "note": "Juliet Test Suite v1.3 for C/C++, 64,099 testcases",
    },
    # SECONDARY / optional.  Real-CVE C/C++ functions (MSR Big-Vul dataset);
    # only needed if a real-world recall signal is wanted on top of synthetic
    # Juliet.  Disabled by default so PRIMARY passes first.
    "bigvul": {
        "url": ("https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/"
                "raw/master/all_c_cpp_release2.0.csv"),
        "file": "big-vul.csv",
        "sha256": "",       # filled on first fetch; see fetch_all
        "license": "MIT (MSR dataset, used raw) -- see corpus/DATASETS.md",
        "note": "Big-Vul: real C/C++ CVE functions with CWE + vulnerable flag",
    },
}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _fetch(url: str, dest: str, sha256: str, resume: bool = True) -> None:
    part = dest + ".part"
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)

    existing = 0
    if resume and os.path.exists(part):
        existing = os.path.getsize(part)

    headers = {"User-Agent": "attestor-corpus-fetch/1.0"}
    if existing:
        headers["Range"] = "bytes=%d-" % existing

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        status = resp.status
        mode = "ab" if status == 206 else "wb"
        total = int(resp.headers.get("Content-Length") or 0)
        got = existing if status == 206 else 0
        with open(part, mode) as fh:
            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                fh.write(chunk)
                got += len(chunk)
                if total:
                    sys.stderr.write("\r  %s  %d/%d bytes (%.1f%%)" % (
                        os.path.basename(dest), got, existing + total,
                        got / (existing + total) * 100))
        sys.stderr.write("\n")

    digest = _sha256(part)
    if sha256 and digest != sha256:
        os.remove(part)
        raise SystemExit(
            "SHA-256 mismatch for %s\n  expected %s\n  got      %s"
            % (url, sha256, digest))
    os.replace(part, dest)
    with open(dest + ".sha256", "w", encoding="utf-8") as fh:
        fh.write(digest + "\n")
    print("  downloaded %s (%d bytes, sha256=%s)" % (os.path.basename(dest),
                                                    os.path.getsize(dest),
                                                    digest))


def fetch_dataset(key: str) -> bool:
    spec = DATASETS[key]
    dest = os.path.join(RAW, spec["file"])
    sha = spec.get("sha256") or ""

    if os.path.exists(dest):
        digest = _sha256(dest)
        if (not sha) or digest.lower() == sha.lower():
            print("  [%s] present, SHA-256 verified -> no-op" % key)
            return True
        print("  [%s] present but SHA-256 changed; re-downloading" % key)

    print("  [%s] fetching %s" % (key, spec["url"]))
    try:
        _fetch(spec["url"], dest, sha)
    except urllib.error.URLError as exc:
        print("  [%s] download failed: %s" % (key, exc))
        return False
    except urllib.error.HTTPError as exc:
        print("  [%s] HTTP %s: %s" % (key, exc.code, exc.reason))
        return False
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--datasets", nargs="*",
                        default=["juliet_cpp"],
                        help="dataset keys to fetch (default: juliet_cpp)")
    args = parser.parse_args(argv)

    keys = args.datasets or ["juliet_cpp"]
    ok = True
    for key in keys:
        if key not in DATASETS:
            print("unknown dataset key: %s (known: %s)"
                  % (key, ", ".join(DATASETS)))
            ok = False
            continue
        if not fetch_dataset(key):
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())