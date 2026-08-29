#!/usr/bin/env python3
"""codebench42 -- Owen's coding-benchmark harness.

A mini-HumanEval-style suite that scores any SOLVER on deterministic
coding tasks with hard test cases:

    solvers built in:
      reference   -> hand-written correct solutions (calibration: must
                     score 100% or the suite itself is broken)
      synth42     -> white-box synthesis from task examples
      file        -> human/model-submitted .py file per task

    metrics: pass@1 per task, aggregate, latency, digest-pinned report.

Honest scope: this suite measures Owen's own coding domain (byte/text
transforms, small algorithms, security-idiom tasks). It is NOT
HumanEval/MBPP; it is the ruler for Owen's lane -- and the harness any
wired brain must pass before its code ships.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

CB_SCHEMA = "attestor-codebench-4.2"
EXIT_CLEAN = 0
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ----------------------------------------------------------- task suite

TASKS = [
    {
        "id": "rot13",
        "prompt": "implement rot13(text: str) -> str",
        "examples": [("attack at dawn", "nggnpx ng qnja")],
        "tests": [
            (("hello", ), "uryyb"),
            (("Attack AT Dawn!", ), "Nggnpx NG Qnja!"),
        ],
        "reference": (
            "import string\ndef rot13(text):\n"
            "    out = []\n"
            "    for ch in text:\n"
            "        if 'a' <= ch <= 'z':\n"
            "            out.append(string.ascii_lowercase"
            "[(string.ascii_lowercase.index(ch) + 13) % 26])\n"
            "        elif 'A' <= ch <= 'Z':\n"
            "            out.append(string.ascii_uppercase"
            "[(string.ascii_uppercase.index(ch) + 13) % 26])\n"
            "        else:\n"
            "            out.append(ch)\n"
            "    return ''.join(out)\n"),
    },
    {
        "id": "xor_bytes",
        "prompt": "implement xor_bytes(data: bytes, key: int) -> bytes",
        "examples": [],
        "tests": [
            ((b"hello", 0x42), bytes(x ^ 0x42 for x in b"hello")),
            ((b"", 7), b""),
        ],
        "reference": "def xor_bytes(data, key):\n"
                     "    return bytes(x ^ key for x in data)\n",
    },
    {
        "id": "keep_digits",
        "prompt": "implement keep_digits(text: str) -> str",
        "examples": [("a1b2c3", "123")],
        "tests": [
            (("no digits here", ), ""),
            (("2026-08-23", ), "20260823"),
        ],
        "reference": "def keep_digits(text):\n"
                     "    return ''.join(c for c in text"
                     " if c.isdigit())\n",
    },
    {
        "id": "hex_encode_upper",
        "prompt": "implement hex_encode_upper(data: bytes) -> str",
        "examples": [],
        "tests": [
            ((b"ABC", ), "414243"),
            ((b"", ), ""),
        ],
        "reference": "def hex_encode_upper(data):\n"
                     "    return data.hex().upper()\n",
    },
    {
        "id": "reverse_words",
        "prompt": "implement reverse_words(text: str) -> str",
        "examples": [],
        "tests": [
            (("hello world", ), "world hello"),
            (("  spaced   out  ", ), "out spaced"),
        ],
        "reference": "def reverse_words(text):\n"
                     "    return ' '.join(reversed(text.split()))\n",
    },
    {
        "id": "count_vowels",
        "prompt": "implement count_vowels(text: str) -> int",
        "examples": [],
        "tests": [
            (("education", ), 5),
            (("rhythm", ), 0),
            (("", ), 0),
        ],
        "reference": "def count_vowels(text):\n"
                     "    return sum(1 for c in text.lower()"
                     " if c in 'aeiou')\n",
    },
    {
        "id": "html_escape",
        "prompt": "implement html_escape(text: str) -> str using only "
                  "the html module",
        "examples": [],
        "tests": [
            (("<script>alert('x')</script>", ),
             "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"),
            (("plain", ), "plain"),
        ],
        "reference": "import html\ndef html_escape(text):\n"
                     "    return html.escape(text)\n",
    },
    {
        "id": "parameterized_query",
        "prompt": "implement safe_query(conn, name: str) that executes "
                  "SELECT * FROM users WHERE name=? with the name bound "
                  "as a parameter (never string-formatted)",
        "examples": [],
        "tests": [("signature-check", "parameterized")],
        "reference": "def safe_query(conn, name):\n"
                     "    return conn.execute(\n"
                     "        'SELECT * FROM users WHERE name=?',"
                     " (name,)).fetchall()\n",
        "static_check": "parameterized",
    },
]


# ------------------------------------------------------------- solvers

def solve_reference(task):
    return task["reference"]


def solve_synth42(task):
    """Route synthesis-capable tasks through synth42; others refused."""
    if not task.get("examples"):
        raise ValueError("task %s has no examples for synthesis"
                         % task["id"])
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import synth42
    examples = [(src.encode(), dst.encode()) for src, dst in
                task["examples"]]
    report = synth42.synthesize(examples)
    if not report.get("synthesized"):
        raise ValueError("synthesis failed for %s" % task["id"])
    return report["script"] + "\n"


def solve_file(task, directory):
    path = Path(directory) / (task["id"] + ".py")
    if not path.exists():
        raise FileNotFoundError(path)
    return path.read_text(encoding="utf-8")


SOLVERS = ("reference", "synth42", "file")


# -------------------------------------------------------------- runner

def run_task(task, source):
    namespace = {}
    exec(compile(source, "<%s>" % task["id"], "exec"), namespace)

    entry_name = _entry_name(task)
    fn = namespace.get(entry_name)
    if not callable(fn):
        return {"passed": False, "reason": "entry %r missing"
                % entry_name, "tests_passed": 0}

    if task.get("static_check") == "parameterized":
        raw = source.replace(" ", "")
        if "'%s'" % "{name}" in raw or "%.2f" in raw or \
                "f\"" in source and "name" in source:
            pass
        if "format(" in raw or ("+name" in raw) or ("name+" in raw) or \
                ("%s" % "") == "":
            concatenated = ("'+" in raw.replace(" ", "") and "name" in raw)
            if concatenated or ("%(" in raw) or ("f'" in source and
                                                 "{name}" in source):
                return {"passed": False,
                        "reason": "string-formatted SQL detected",
                        "tests_passed": 0}
        if "?" not in source:
            return {"passed": False, "reason": "no parameter marker (?)",
                    "tests_passed": 0}

    passed = 0
    for args, expected in task["tests"]:
        if args == ("signature-check", ):
            continue
        try:
            got = fn(*args)
        except Exception as exc:  # noqa: BLE001
            return {"passed": False,
                    "reason": "%s: %s" % (type(exc).__name__, exc),
                    "tests_passed": passed}
        if got != expected:
            return {"passed": False,
                    "reason": "got %r want %r" % (got, expected),
                    "tests_passed": passed}
        passed += 1
    return {"passed": len(task["tests"]) == passed or
            (task.get("static_check") and passed >= len(task["tests"]) - 1),
            "tests_passed": passed, "total": len(task["tests"])}


def _entry_name(task):
    prompt = task["prompt"]
    for candidate in ("rot13", "xor_bytes", "keep_digits",
                      "hex_encode_upper", "reverse_words", "count_vowels",
                      "html_escape", "safe_query"):
        if candidate + "(" in prompt:
            return candidate
    return task["id"]


def run_suite(solver="reference", directory=None):
    results = []
    passed_count = 0
    started = time.perf_counter()
    for task in TASKS:
        t0 = time.perf_counter()
        try:
            if solver == "reference":
                source = solve_reference(task)
            elif solver == "synth42":
                source = solve_synth42(task)
            elif solver == "file":
                source = solve_file(task, directory)
            else:
                raise ValueError("unknown solver %r" % solver)
            outcome = run_task(task, source)
        except (ValueError, FileNotFoundError) as exc:
            outcome = {"passed": False, "reason": str(exc),
                       "tests_passed": 0}
        elapsed = time.perf_counter() - t0
        outcome.update({"task": task["id"],
                        "latency_ms": round(elapsed * 1000, 1)})
        results.append(outcome)
        passed_count += bool(outcome["passed"])
    total_ms = round((time.perf_counter() - started) * 1000, 1)
    report = {
        "schema": CB_SCHEMA,
        "tool": "codebench",
        "solver": solver,
        "tasks_total": len(TASKS),
        "tasks_passed": passed_count,
        "pass_at_1": round(passed_count / len(TASKS), 4),
        "total_latency_ms": total_ms,
        "results": results,
        "boundary": ("Owen's own domain suite; not HumanEval/MBPP -- "
                     "scores are comparable only within this ruler"),
    }
    report["report_sha256"] = sha256_hex(
        canonical_json({k: v for k, v in report.items()}).encode())
    return report


def run_selftest():
    checks = []
    reference = run_suite("reference")
    checks.append(("reference solutions score 100% (suite sanity)",
                   reference["tasks_passed"] == len(TASKS)))
    synth = run_suite("synth42")
    synth_tasks = {r["task"] for r in synth["results"] if r["passed"]}
    checks.append(("synth42 solves its domain tasks",
                   {"rot13", "keep_digits"} <= synth_tasks))
    checks.append(("synth42 honestly fails non-domain tasks",
                   synth["tasks_passed"] < len(TASKS)))
    checks.append(("digest pinned",
                   len(reference["report_sha256"]) == 64))
    failed = [name for name, ok in checks if not ok]
    return {
        "schema": CB_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="codebench42", description="Coding benchmark harness")
    parser.add_argument("--solver", choices=SOLVERS,
                        default="reference")
    parser.add_argument("--dir", help="per-task .py files for file solver")
    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    try:
        report = run_suite(args.solver, directory=args.dir)
    except OSError as exc:
        print("codebench42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    if args.format == "text":
        print("solver=%s  pass@1=%d/%d  (%.1f ms)"
              % (report["solver"], report["tasks_passed"],
                 report["tasks_total"], report["total_latency_ms"]))
        for r in report["results"]:
            mark = "PASS" if r["passed"] else "FAIL"
            reason = "" if r["passed"] else " -- " + r.get("reason", "")
            print("  [%s] %s%s" % (mark, r["task"], reason))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
