#!/usr/bin/env python3
"""Source-tree hardening scans -- Trojan Source and secret candidates.

Checks (offline, stdlib, deterministic):
- bidi: Unicode bidirectional control characters in source (CVE-2021-42574
  Trojan Source shape). Exact byte-level detection.
- mixed-script identifiers: heuristic for Cyrillic/Greek characters inside
  otherwise-ASCII identifier context (CVE-2021-42643 shape). Labeled a
  review point, never a verdict.
- secrets: high-entropy assignment/quoted-string candidates with shape
  filters. Values are redacted in every report.

Exit codes: 0 clean, 1 hits found, 2 usage, 4 operational failure.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys

HARDEN_SCHEMA = "attestor-source-hardening-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


BIDI_CHARS = {
    "\u202a": "LRE embedding",
    "\u202b": "RLE embedding",
    "\u202c": "PDF pop",
    "\u202d": "LRO override",
    "\u202e": "RLO override",
    "\u2066": "LRI isolate",
    "\u2067": "RLI isolate",
    "\u2068": "FSI first-strong isolate",
    "\u2069": "PDI pop isolate",
}

BIDI_PATTERN = re.compile("[" + "".join(BIDI_CHARS) + "]")

CYRILLIC_GREEK = re.compile(r"[\u0370-\u03ff\u0400-\u04ff]")
ASCII_LETTERS = re.compile(r"[A-Za-z]")

SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:secret|token|password|passwd|api[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*['\"]([^'\"]{12,})['\"]")
HIGH_ENTROPY_STRING = re.compile(r"['\"]([A-Za-z0-9_/+=\-]{20,})['\"]")

PLACEHOLDERS = {
    "changeme", "change_me", "password", "example", "placeholder",
    "your_password_here", "xxxxxxxxxxxx", "dummy_secret_value",
}
MIN_ENTROPY = 4.0


class HardeningError(ValueError):
    pass


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total)
                for n in counts.values())


def _line_col(text, index):
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index - last_nl
    return {"line": line, "col": col}


def scan_bidi(text):
    hits = []
    for match in BIDI_PATTERN.finditer(text):
        ch = match.group(0)
        info = _line_col(text, match.start())
        info.update({
            "check": "trojan-source-bidi",
            "character": "U+%04X" % ord(ch),
            "role": BIDI_CHARS[ch],
        })
        hits.append(info)
    return hits


def scan_mixed_script(text):
    hits = []
    for match in CYRILLIC_GREEK.finditer(text):
        start = max(match.start() - 24, 0)
        window = text[start:match.end() + 24]
        if ASCII_LETTERS.search(window):
            info = _line_col(text, match.start())
            info.update({
                "check": "mixed-script-context",
                "character": "U+%04X" % ord(match.group(0)),
            })
            hits.append(info)
    return hits


def _redact(value):
    return value[:4] + "...[redacted]" if len(value) > 4 else "[redacted]"


def scan_secrets(text):
    hits = []
    seen_spans = []

    def add(match, kind):
        span = match.span(1)
        for existing in seen_spans:
            if span[0] < existing[1] and existing[0] < span[1]:
                return
        candidate = match.group(1)
        lowered = candidate.lower()
        if lowered in PLACEHOLDERS or set(lowered) == {lowered[0]}:
            return
        entropy = shannon_entropy(candidate)
        if entropy < MIN_ENTROPY:
            return
        seen_spans.append(span)
        info = _line_col(text, match.start())
        info.update({
            "check": kind,
            "entropy": round(entropy, 2),
            "value_preview": _redact(candidate),
        })
        hits.append(info)

    for match in SECRET_ASSIGNMENT.finditer(text):
        add(match, "secret-shaped-assignment")
    for match in HIGH_ENTROPY_STRING.finditer(text):
        add(match, "high-entropy-literal")
    hits.sort(key=lambda h: (h["line"], h["col"]))
    return hits


CHECKS = ("bidi", "mixed-script", "secrets")


def scan_text(text, checks=CHECKS):
    findings = []
    if "bidi" in checks:
        findings.extend(scan_bidi(text))
    if "mixed-script" in checks:
        findings.extend(scan_mixed_script(text))
    if "secrets" in checks:
        findings.extend(scan_secrets(text))
    return sorted(findings,
                  key=lambda f: (f.get("line", 0), f.get("col", 0)))


def scan_file(path, checks=CHECKS):
    with open(path, "rb") as handle:
        blob = handle.read()
    text = blob.decode("utf-8", errors="replace")
    findings = scan_text(text, checks)
    for finding in findings:
        finding["file"] = path
    return findings


def run_selftest():
    checks = []

    trojan = 'if (isAdmin) {\n  \u202e } \n grantAccess();\n'
    bidi_hits = scan_bidi(trojan)
    checks.append(("bidi override detected",
                   any(h["character"] == "U+202E" for h in bidi_hits)))

    clean = "def compute(a):\n    return a * 2\n"
    checks.append(("clean source has no bidi", scan_bidi(clean) == []))

    mixed = 'user_\u0430dmin = load()\n'
    mixed_hits = scan_mixed_script(mixed)
    checks.append(("cyrillic-in-identifier flagged",
                   len(mixed_hits) == 1))

    aws_like = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY"'
    secret_hits = scan_secrets(aws_like)
    checks.append(("high-entropy assignment caught",
                   len(secret_hits) == 1))
    checks.append(("value redacted in report",
                   all("wJalrXUtnFEMI" not in str(h.get("value_preview"))
                       or h["value_preview"].startswith("wJal")
                       and "[redacted]" in h["value_preview"]
                       for h in secret_hits)))

    placeholder = 'password = "changeme"'
    checks.append(("placeholder skipped", scan_secrets(placeholder) == []))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": HARDEN_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="source_hardening42",
        description="Trojan Source + secret-candidate scans")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--checks",
                        help="comma list of: %s" % ", ".join(CHECKS))
    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    checks = ([c.strip() for c in args.checks.split(",")]
              if args.checks else list(CHECKS))
    for check in checks:
        if check not in CHECKS:
            print("source_hardening42: unknown check %r" % check,
                  file=sys.stderr)
            return EXIT_INVALID


    try:
        findings = []
        scanned = 0
        for path in args.files:
            scanned += 1
            findings.extend(scan_file(path, checks))
    except OSError as exc:
        print("source_hardening42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    result = {
        "schema": HARDEN_SCHEMA,
        "tool": "source-hardening-scanner",
        "files_scanned": scanned,
        "findings": findings[:1000],
        "finding_count": len(findings),
        "note": ("secret values are redacted; mixed-script hits are "
                 "review points, not verdicts"),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_FINDING if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
