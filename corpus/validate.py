#!/usr/bin/env python3
"""Validate that every manifest entry is well-formed and the sample file exists.

Exits non-zero on any failure.  Run after `normalize.py` and before
`external_eval.py` so a broken manifest is caught early.

Checks:
* manifest.jsonl exists and is valid JSON Lines
* each line has required fields with correct types
* `path` points to a readable file under corpus/samples/
* `cwe` matches `^CWE-\d+$`
* `language` in expected set
* `vulnerable` is boolean
* `source` non-empty string
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MANIFEST = os.path.join(HERE, "manifest.jsonl")
SAMPLES_ROOT = os.path.join(HERE, "samples")

REQ_FIELDS = {"id", "path", "language", "cwe", "vulnerable", "source", "notes"}
LANGUAGES = {"c", "cpp", "python", "javascript", "typescript", "java", "text"}
CWE_RE = re.compile(r"^CWE-\d+$")


def main() -> int:
    if not os.path.exists(MANIFEST):
        print("FAIL: manifest not found at %s" % MANIFEST, file=sys.stderr)
        return 1

    errors = 0
    lines = 0
    cwe_set = set()
    vuln_count = 0
    safe_count = 0

    with open(MANIFEST, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            lines += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print("FAIL line %d: invalid JSON: %s" % (lineno, exc), file=sys.stderr)
                errors += 1
                continue

            missing = REQ_FIELDS - set(obj.keys())
            if missing:
                print("FAIL line %d: missing fields %s" % (lineno, missing), file=sys.stderr)
                errors += 1
                continue

            # cwe format
            cwe = obj.get("cwe")
            if not isinstance(cwe, str) or not CWE_RE.match(cwe):
                print("FAIL line %d: cwe must match ^CWE-\\d+$, got %r"
                      % (lineno, cwe), file=sys.stderr)
                errors += 1
                continue
            cwe_set.add(cwe)

            # language
            lang = obj.get("language")
            if lang not in LANGUAGES:
                print("FAIL line %d: language %r not in %s"
                      % (lineno, lang, LANGUAGES), file=sys.stderr)
                errors += 1
                continue

            # vulnerable boolean
            vuln = obj.get("vulnerable")
            if not isinstance(vuln, bool):
                print("FAIL line %d: vulnerable must be bool, got %r"
                      % (lineno, vuln), file=sys.stderr)
                errors += 1
                continue
            if vuln:
                vuln_count += 1
            else:
                safe_count += 1

            # source non-empty
            src = obj.get("source")
            if not isinstance(src, str) or not src:
                print("FAIL line %d: source must be non-empty string"
                      % lineno, file=sys.stderr)
                errors += 1
                continue

            # path exists
            path = obj.get("path")
            if not isinstance(path, str) or not path:
                print("FAIL line %d: path must be non-empty string"
                      % lineno, file=sys.stderr)
                errors += 1
                continue
            full = os.path.join(ROOT, path)
            if not os.path.isfile(full):
                print("FAIL line %d: sample file not found: %s"
                      % (lineno, full), file=sys.stderr)
                errors += 1
                continue
            # ensure it's under samples/ (not escaping)
            try:
                full_real = os.path.realpath(full)
                samples_real = os.path.realpath(SAMPLES_ROOT)
                if not full_real.startswith(samples_real):
                    print("FAIL line %d: path escapes corpus/samples/: %s"
                          % (lineno, path), file=sys.stderr)
                    errors += 1
            except OSError:
                pass

    if errors:
        print("\nVALIDATION FAILED: %d errors in %d lines" % (errors, lines),
              file=sys.stderr)
        return 1

    print("OK: %d samples (%d vuln, %d safe), %d CWE classes"
          % (lines, vuln_count, safe_count, len(cwe_set)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())