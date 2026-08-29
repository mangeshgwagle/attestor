#!/usr/bin/env python3
"""
benchmark.py -- score Attestor on the axes you CAN actually measure, honestly.

You cannot run a real head-to-head between Attestor and a frontier LLM (GPT-5.5,
Claude, whatever) on "coding" in general -- they are different *kinds* of tool.
Attestor is deterministic static analysis + template scaffolding; an LLM is a
reasoning model that writes novel code from a prompt. On open-ended "here's a
task, write it" work the LLM wins and Attestor is not even a competitor.

But on a few narrow, objective axes a fair comparison exists, and you do NOT need
the model in hand to do it: measure Attestor here, and drop the LLM's numbers into the
blank column from a public leaderboard (SWE-bench Verified, HumanEval,
LiveCodeBench, Aider polyglot) or from someone who has access.

This prints Attestor's column with real, measured numbers -- and is loudly honest
about which rows are a fair fight and which are apples-to-oranges.

    python3 benchmark.py            # print the scorecard
    python3 benchmark.py --json     # machine-readable metrics
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import time

import codegen
import deepscan
import detect


def measure() -> dict:
    """Compute Attestor's objective, LLM-comparable metrics. No network, no API."""
    # --- bug-detection recall on the labelled corpus (mirrors detect.self_test) ---
    corpus = [os.path.join(detect.CORPUS, d) for d in ("c", "cpp", "haskell", "realworld")]
    files = detect.collect_paths(corpus)
    found = set()
    t0 = time.perf_counter()
    for path in files:
        for f in detect.scan_file(path):
            found.add((os.path.basename(path), f.rule))
    scan_ms = (time.perf_counter() - t0) * 1000.0
    detected = detect.EXPECTED & found
    recall = len(detected) / len(detect.EXPECTED) if detect.EXPECTED else 0.0

    # --- deterministic generation + its cleanliness (a precision signal) ---
    t0 = time.perf_counter()
    generated = codegen.generate(codegen.DEFAULT_SPEC)
    gen_ms = (time.perf_counter() - t0) * 1000.0
    gen_lines = codegen.total_lines(generated)
    deterministic = generated == codegen.generate(codegen.DEFAULT_SPEC)

    regex_findings = 0
    ast_findings = 0
    with tempfile.TemporaryDirectory() as tmp:
        codegen.write_files(generated, tmp, force=True)
        for path in detect.collect_paths([tmp]):
            regex_findings += len(detect.scan_file(path))
    for rel, content in generated.items():
        if rel.endswith(".py"):
            ast_findings += len(deepscan.analyze(content, rel))

    return {
        "bug_recall_pct": round(recall * 100, 1),
        "bugs_detected": len(detected),
        "bugs_expected": len(detect.EXPECTED),
        "generated_lines": gen_lines,
        "generated_files": len(generated),
        "generated_regex_findings": regex_findings,
        "generated_ast_findings": ast_findings,
        "deterministic": deterministic,
        "cost_usd": 0.0,
        "corpus_scan_ms": round(scan_ms, 1),
        "generation_ms": round(gen_ms, 1),
    }


# rows where a like-for-like comparison is legitimate, and how to read them
FAIR_ROWS = [
    ("Bug-detection recall (labelled corpus)",
     lambda m: f"{m['bug_recall_pct']}%  ({m['bugs_detected']}/{m['bugs_expected']})",
     "run the LLM as a bug finder on the SAME files; count how many it flags"),
    ("False positives on 2.9k lines of clean gen code",
     lambda m: f"{m['generated_regex_findings'] + m['generated_ast_findings']}  (both engines)",
     "ask the LLM to review the same code; count its false alarms"),
    ("Determinism (same input -> same output)",
     lambda m: "yes (identical)" if m["deterministic"] else "no",
     "an LLM is stochastic; re-run N times and measure output variance"),
    ("Cost per run",
     lambda m: f"${m['cost_usd']:.2f}",
     "LLM: sum the input+output token cost per run"),
    ("Latency: full corpus scan",
     lambda m: f"{m['corpus_scan_ms']} ms",
     "LLM: wall-clock per request (usually seconds)"),
    ("Latency: generate a ~3k-line service",
     lambda m: f"{m['generation_ms']} ms",
     "LLM: time to stream the same amount of code"),
    ("Runs fully offline / air-gapped",
     lambda m: "yes",
     "an API LLM needs network egress and sends your code out"),
]

# rows an LLM wins outright -- Attestor literally cannot play, and pretending
# otherwise would be dishonest
LLM_FAVOURED = [
    "Novel logic from a natural-language spec (Attestor only scaffolds templates)",
    "Understanding intent / ambiguous requirements",
    "Non-boilerplate algorithms, refactors, and one-off problem solving",
    "Explaining tradeoffs, writing docs, answering 'why'",
    "SWE-bench / HumanEval / LiveCodeBench style tasks (generation from a prompt)",
    "Adapting to an unusual spec it has never seen a template for",
]


def report(metrics: dict) -> str:
    lines = []
    lines.append("Attestor  vs  a frontier LLM (e.g. GPT-5.5)  --  the honest scorecard")
    lines.append("=" * 74)
    lines.append("")
    lines.append("FAIR FIGHT (measure Attestor here; paste the LLM's number from a leaderboard")
    lines.append("or a friend with access):")
    lines.append("")
    lines.append(f"  {'metric':<48}{'Attestor':<20}{'GPT-5.5'}")
    lines.append(f"  {'-' * 46}  {'-' * 18}  {'-' * 9}")
    for label, attestor_fn, _how in FAIR_ROWS:
        lines.append(f"  {label:<48}{attestor_fn(metrics):<20}{'?  (fill in)'}")
    lines.append("")
    lines.append("  how to get the LLM's number for each row:")
    for label, _attestor_fn, how in FAIR_ROWS:
        lines.append(f"    - {label.split('(')[0].strip()}: {how}")
    lines.append("")
    lines.append("NOT A FAIR FIGHT -- the LLM wins these outright; Attestor can't play:")
    for item in LLM_FAVOURED:
        lines.append(f"  x  {item}")
    lines.append("")
    lines.append("bottom line: they're different tools. Attestor is deterministic, free, offline,")
    lines.append("and precise on the narrow job of finding/fixing known bug classes and")
    lines.append("scaffolding clean boilerplate. An LLM is a reasoning generalist. Compare")
    lines.append("them only on the rows above; anywhere else is apples-to-oranges.")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable metrics only")
    args = ap.parse_args(argv)

    metrics = measure()
    if args.json:
        print(json.dumps(metrics, indent=2))
    else:
        print(report(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
