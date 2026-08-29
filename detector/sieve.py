#!/usr/bin/env python3
"""sieve.py -- Attestor's generate/review/improve/review loop.

This is the explicit "sieving" workflow:

  write or load code -> examine it -> fix what can be fixed -> examine again
  -> repeat until clean, stuck, or the pass limit is reached -> print the code.

For a file path, Sieve uses refine.py's verification-gated fixed-point loop.
For a plain-English coding request, Sieve uses Forge when a provider API is
configured: the model proposes, Attestor scans, the crucible runs behavior checks,
and failures are fed back until accepted or the pass budget runs out.
"""
from __future__ import annotations

import argparse
import os
import sys

import brain
import crucible
import forge
import harvest
import nl
import quality
import refine

DEFAULT_PASSES = 200


def _line_count(code: str) -> int:
    return code.count("\n") + (0 if code.endswith("\n") else 1) if code else 0


def _render_static_result(request: str, code: str) -> tuple[str, int]:
    label, smoke = quality.behavior_check(request)
    findings = harvest.scan_content(code, ".py")
    verdict = crucible.verify(code, snippet=smoke)
    lines = [
        'Sieve coding loop: "%s"' % request,
        "=" * 64,
        "No provider API was needed; Attestor used a vetted local solution.",
        "static findings: %d" % len(findings),
        "runtime/behavior: " + ("OK" if verdict.ok else "FAIL -- " + verdict.detail),
    ]
    if label:
        lines.append("behavior gate: " + label)
    lines += ["", code]
    return "\n".join(lines), 0 if not findings and verdict.ok else 1


def _run_file(path: str, rounds: int) -> tuple[str, int]:
    text, remaining = refine.report(path, rounds=rounds)
    header = [
        "Sieve fixed-point refinement",
        "=" * 64,
        "passes allowed: %d" % rounds,
        "source file: " + path,
        "",
    ]
    return "\n".join(header) + text, remaining


def _run_prompt(request: str, bus, rounds: int) -> tuple[str, int]:
    if bus is not None and bus.available():
        result = forge.forge(request, bus, rounds=rounds, execute=True)
        header = [
            "Sieve model-backed coding loop",
            "=" * 64,
            "passes allowed: %d" % rounds,
            "actual passes: %d" % len(result["transcript"]),
            "",
        ]
        return "\n".join(header) + forge.render(result, request), 0 if result["ok"] else 2

    intent = nl.interpret(request)
    if intent["intent"] == "snippet":
        return _render_static_result(request, intent["code"])
    if intent["intent"] == "scaffold":
        return nl.run(intent), 0
    return (
        "Sieve needs a provider API for novel code generation. "
        "Set GROQ_API_KEY, OPENROUTER_API_KEY, MISTRAL_API_KEY, GEMINI_API_KEY, "
        "OPENAI_API_KEY, or OLLAMA_MODEL; offline Attestor can still refine files "
        "and return known vetted snippets.",
        1,
    )


def run(target: str, bus=None, rounds: int = DEFAULT_PASSES) -> tuple[str, int]:
    target = (target or "").strip()
    if not target:
        return "Sieve needs a file path or a coding request.", 2
    if os.path.exists(target):
        return _run_file(target, rounds)
    return _run_prompt(target, bus, rounds)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="+", help="a Python file path or coding request")
    ap.add_argument("--passes", type=int, default=DEFAULT_PASSES,
                    help="max review/improve passes before stopping")
    ap.add_argument("--model", default="", help="pin the model on configured providers")
    args = ap.parse_args(argv)

    bus = brain.from_env(model=args.model)
    text, code = run(" ".join(args.target), bus=bus, rounds=args.passes)
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
