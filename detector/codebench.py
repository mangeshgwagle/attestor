#!/usr/bin/env python3
"""
codebench.py -- the "...and coding?" answer, measured instead of asserted.

"Coding" usually means: read a problem in plain English, write the code that
solves it (HumanEval / MBPP / LiveCodeBench style). Attestor alone is still a
deterministic analyzer/scaffolder, so his direct offline generative score remains
0. The new answer is the multiplied path:

  provider APIs write code -> forge/curry -> Attestor static checks -> crucible ->
  request-aware behavior smoke tests -> repair or reject.

This benchmark keeps those two truths separate. It does not fake a live model in
offline tests. It measures Attestor-alone generation honestly, then measures whether
the assisted forge gate rejects plausible wrong code and accepts repaired code.

    python3 codebench.py            # the coding scorecard
    python3 codebench.py --json     # machine-readable
"""
from __future__ import annotations

import argparse
import json
import tempfile

import codegen
import deepscan
import detect
import forge
import harvest


# --------------------------------------------------------------------------- #
# 1. Direct generative problems -- Attestor alone, no provider API
# --------------------------------------------------------------------------- #
GENERATIVE_PROBLEMS = [
    {"name": "fizzbuzz", "spec": "list of '1'..'n' with Fizz/Buzz/FizzBuzz rules",
     "check": lambda ns: ns["fizzbuzz"](5) == ["1", "2", "Fizz", "4", "Buzz"]},
    {"name": "fib", "spec": "the nth Fibonacci number (0-indexed)",
     "check": lambda ns: ns["fib"](10) == 55},
    {"name": "is_palindrome", "spec": "True if a string reads the same reversed",
     "check": lambda ns: ns["is_palindrome"]("racecar") and not ns["is_palindrome"]("no")},
    {"name": "two_sum", "spec": "indices of two numbers adding to a target",
     "check": lambda ns: sorted(ns["two_sum"]([2, 7, 11], 9)) == [0, 1]},
    {"name": "gcd", "spec": "greatest common divisor of two ints",
     "check": lambda ns: ns["gcd"](54, 24) == 6},
    {"name": "reverse_words", "spec": "reverse the word order of a sentence",
     "check": lambda ns: ns["reverse_words"]("a b c") == "c b a"},
]


ASSISTED_FORGE_CASES = [
    {"request": "merge sorted lists",
     "bad": "def merge(a, b):\n    return a + b\n",
     "good": "def merge(a, b):\n    return sorted(a + b)\n"},
    {"request": "flatten nested list",
     "bad": "def flatten(xs):\n    out = []\n    for x in xs:\n        out += x if isinstance(x, list) else [x]\n    return out\n",
     "good": "def flatten(xs):\n    out = []\n    for x in xs:\n        if isinstance(x, list):\n            out.extend(flatten(x))\n        else:\n            out.append(x)\n    return out\n"},
    {"request": "write fibonacci",
     "bad": "def fib(n):\n    return n\n",
     "good": "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n"},
]


class ScriptedProvider:
    def __init__(self, answers):
        self.answers = list(answers)

    def generate(self, _prompt):
        return self.answers.pop(0)


def attestor_solve(_problem) -> dict:
    """Attestor-alone attempt at a generative problem.

    No provider API is involved here, so there is no stochastic natural-language
    to code model. The answer is still an empty namespace; this is the direct
    baseline, not the new assisted forge path.
    """
    return {}


def run_generative():
    solved = 0
    for problem in GENERATIVE_PROBLEMS:
        namespace = attestor_solve(problem)
        ok = False
        try:
            ok = bool(problem["check"](namespace))
        except Exception:                       # noqa: BLE001 -- any failure = not solved
            ok = False
        solved += 1 if ok else 0
    return solved, len(GENERATIVE_PROBLEMS)


def run_assisted_gate():
    """Score whether forge rejects wrong behavior and accepts the repaired answer.

    This is deliberately offline: the provider is scripted, so the benchmark tests
    Attestor's verification/repair orchestration rather than pretending to benchmark a
    live model that may or may not be configured on this machine.
    """
    solved = 0
    for case in ASSISTED_FORGE_CASES:
        # This benchmark intentionally executes the generated candidate so it can
        # score the runtime transcript.  Production Forge remains opt-in only.
        result = forge.forge(case["request"], ScriptedProvider([case["bad"], case["good"]]),
                             rounds=2, execute=True)
        transcript = result["transcript"]
        rejected_bad = len(transcript) >= 2 and transcript[0].get("ran") is False
        accepted_good = result["ok"] and transcript[-1].get("ran") is True
        solved += 1 if rejected_bad and accepted_good else 0
    return solved, len(ASSISTED_FORGE_CASES)


# --------------------------------------------------------------------------- #
# 2. Scaffolding -- the coding Attestor deterministically does
# --------------------------------------------------------------------------- #
def run_scaffolding():
    """Score 1 only if the generated service compiles AND both engines find it
    clean -- the guarantee that makes his scaffolding worth something."""
    files = codegen.generate(codegen.DEFAULT_SPEC)
    try:
        for rel, content in files.items():
            if rel.endswith(".py"):
                compile(content, rel, "exec")
    except SyntaxError:
        return 0, 1

    regex_findings = 0
    with tempfile.TemporaryDirectory() as tmp:
        codegen.write_files(files, tmp, force=True)
        for path in detect.collect_paths([tmp]):
            regex_findings += len(detect.scan_file(path))
    ast_findings = sum(len(deepscan.analyze(c, r))
                       for r, c in files.items() if r.endswith(".py"))
    clean = regex_findings == 0 and ast_findings == 0
    return (1 if clean else 0), 1


# --------------------------------------------------------------------------- #
# 3. Mechanical bug-fixing -- safe rewrites vs bugs that need understanding
# --------------------------------------------------------------------------- #
FIX_CASES = [
    {"name": "== None -> is None", "novel": False,
     "buggy": "def f(x):\n    return x == None\n", "want": "is None"},
    {"name": "verify=False -> verify=True", "novel": False,
     "buggy": "r = requests.get(u, verify=False)\n", "want": "verify=True"},
    {"name": "md5 -> sha256", "novel": False,
     "buggy": "import hashlib\nh = hashlib.md5(b'x')\n", "want": "sha256"},
    {"name": "bare except -> except Exception", "novel": False,
     "buggy": "try:\n    go()\nexcept:\n    pass\n", "want": "except Exception:"},
    {"name": "off-by-one loop (needs understanding)", "novel": True,
     "buggy": "for i in range(len(a) - 1):\n    use(a[i])\n", "want": "range(len(a))"},
]


def run_fixing():
    def solved(case):
        improved, _ = harvest.improve(case["buggy"])
        return case["want"] in improved and improved != case["buggy"]

    mech = [c for c in FIX_CASES if not c["novel"]]
    novel = [c for c in FIX_CASES if c["novel"]]
    return (sum(solved(c) for c in mech), len(mech),
            sum(solved(c) for c in novel), len(novel))


# --------------------------------------------------------------------------- #
def measure() -> dict:
    gen_solved, gen_total = run_generative()
    gate_solved, gate_total = run_assisted_gate()
    scaf_solved, scaf_total = run_scaffolding()
    mech_solved, mech_total, novel_solved, novel_total = run_fixing()
    return {
        "generative_solved": gen_solved,       # backwards-compatible alias
        "generative_total": gen_total,
        "direct_generative_solved": gen_solved,
        "direct_generative_total": gen_total,
        "assisted_gate_solved": gate_solved,
        "assisted_gate_total": gate_total,
        "scaffolding_solved": scaf_solved,
        "scaffolding_total": scaf_total,
        "mechanical_fix_solved": mech_solved,
        "mechanical_fix_total": mech_total,
        "reasoning_fix_solved": novel_solved,
        "reasoning_fix_total": novel_total,
    }


def report(m: dict) -> str:
    lines = [
        'Can Attestor code? the "...and coding?" scorecard',
        "=" * 66,
        "",
        "1. DIRECT GENERATIVE -- Attestor alone, no provider API",
        "   (this is what HumanEval / MBPP ask: plain English in, code out)",
        f"   Attestor alone: {m['direct_generative_solved']}/{m['direct_generative_total']} solved.",
        "   -> the deterministic core still does not invent novel logic by itself.",
        "",
        "2. ATTESTOR + APIS -- provider writes, Attestor verifies, repairs, and behavior-tests",
        f"   Forge gate: {m['assisted_gate_solved']}/{m['assisted_gate_total']} scripted bad answers rejected,",
        "   then repaired answers accepted by static checks, the crucible, and behavior smoke tests.",
        "   -> with keys configured, this is the real code-writing path: not blind trust",
        "      in a model, but generated code forced through Attestor's verifier.",
        "",
        "3. SCAFFOLDING -- structured spec -> a whole runnable service",
        f"   Attestor: {m['scaffolding_solved']}/{m['scaffolding_total']} "
        "(compiles, clean, reviewed by both engines).",
        "   -> deterministic and guaranteed-clean; an LLM is more flexible here",
        "      but non-deterministic unless Attestor is wrapped around it.",
        "",
        "4. BUG-FIXING -- turn buggy code into fixed code",
        f"   Attestor: {m['mechanical_fix_solved']}/{m['mechanical_fix_total']} on known "
        "mechanical classes; "
        f"{m['reasoning_fix_solved']}/{m['reasoning_fix_total']} on bugs needing reasoning.",
        "   -> perfect on safe rewrites it has a rule for; novel repairs go through forge.",
        "",
        "VERDICT",
        "-" * 66,
        "Attestor alone is still a deterministic reviewer/scaffolder, not a magic offline",
        "reasoning model. Attestor multiplied with provider APIs is now a verified coding",
        "loop: the model proposes, Attestor checks structure, security, import/runtime",
        "health, and request-specific behavior, then sends failures back for repair.",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable metrics only")
    args = ap.parse_args(argv)

    metrics = measure()
    print(json.dumps(metrics, indent=2) if args.json else report(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
