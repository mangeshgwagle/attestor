#!/usr/bin/env python3
"""
AttestorVonLuneberg -- a moody, profane, two-faced bug hunter.

He finds the bugs real teams actually ship -- in C, C++, Haskell and Python, plus
leaked secrets in any file -- and tells you about them in one of his two
personalities. He does NOT let you pick which one; it's random each time he wakes
(`he` -- yes, Attestor has a gender). Both faces report the same findings in different
words. He swears (bleeped; --sfw to muzzle him). With --online he checks the
internet; with --deep he thinks harder and checks *many* results.

    python3 attestor.py                     # scan the bundled corpus, random persona
    python3 attestor.py PATH ...            # scan your own code
    python3 attestor.py --deep --online     # think hard, consult the web
    python3 attestor.py --severity HIGH     # only the serious stuff
    python3 attestor.py --sfw               # bleep the profanity
    python3 attestor.py --seed 7            # pin the persona/wording (for CI/tests)
    python3 attestor.py --json              # plain machine output (+refs if --online)
    python3 attestor.py --meet              # who is Attestor?
    python3 attestor.py --self-test         # prove he finds every planted bug
    python3 attestor.py --list-rules

Exit code: number of findings (capped 250), 0 if none. --self-test exits 0/1.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

import detect
import online
import personalities as P

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATHS = [os.path.join(detect.CORPUS, d)
                 for d in ("c", "cpp", "haskell", "realworld")]


def pick_persona(seed):
    """Random, un-choosable personality. --seed only exists to make CI reproducible."""
    rng = random.Random(seed) if seed is not None else random.Random()
    persona = rng.choice([P.HELPFUL, P.SAVAGE])
    return persona, rng


def meet() -> str:
    lines = [
        "AttestorVonLuneberg",
        "=" * 64,
        "A bug hunter with two personalities. He (yes, he) cannot switch between",
        "them on purpose and neither can you -- one wakes up at random every run.",
        "Both find the exact same bugs; they just have very different mouths.",
        "",
        f"  • {P.HELPFUL.name}",
        f"      {P.HELPFUL.tagline}",
        "",
        f"  • {P.SAVAGE.name}",
        f"      {P.SAVAGE.tagline}",
        "",
        "He finds the mistakes real small/medium teams ship: unsafe C string calls,",
        "SQL injection, hardcoded secrets, mutable default args, swallowed",
        "exceptions, integer overflow, float ==, lazy-evaluation traps, and the",
        "subtle UB/abstraction bugs almost no-one catches. --deep makes him think",
        "harder; --online lets him check the internet -- GitHub, and Google (via the",
        "official Custom Search API) -- and count how many other poor souls hit it.",
        "Profanity is on by default; --sfw makes him workplace-safe.",
        "",
        "ONE DOOR: `python3 superattestor.py <anything>` -- a file, a GitHub link, or",
        "plain English -- and he picks the right power himself (deep-read, scaffold,",
        "snippet, or the forge loop). Google AI Studio is benched from its brain.",
        "",
        "Best of all, `python3 forge.py \"<request>\"` MULTIPLIES a real LLM by Attestor:",
        "the model (Gemini/OpenAI via brain.py) writes the code, Attestor's two engines",
        "verify it and auto-fix what they can, and the rest goes BACK to the model to",
        "repair -- looping until Attestor finds nothing. Generation x verification.",
        "",
        "With --deep on a Python file he doesn't just pattern-match -- he parses it",
        "to an AST and *reads* it (`deepscan.py`): explains how it works and finds the",
        "rare semantic bugs regex can't (assert-on-tuple, return-in-finally, duplicate",
        "dict keys, undefined names, unreachable code). `python3 deepscan.py f.py",
        "--explain` shows the read.",
        "",
        "He can also WRITE code: `python3 codegen.py` scaffolds a complete, runnable",
        "service -- ~3,850 lines by default, ~10,600 with --resources 20 (accounts+auth,",
        "caching, metrics, a query builder, migrations, a job queue, circuit breaker,",
        "and more) -- and every line passes BOTH his engines at zero findings.",
        "Or just ask in English:",
        "`python3 nl.py \"make a rest api for Book with fields title, author\"` (a bounded",
        "intent parser, not an LLM -- it refuses honestly outside its vocabulary).",
        "And he can READ the world's code: give `python3 harvest.py` a GitHub file",
        "LINK (or a search query); he reviews it with both engines and hands back an",
        "improved copy, citing the source + license (no API key needed). Or",
        "`python3 comprehend.py <file-or-URL>` -- he reads it in ~10 passes, shows the",
        "structural picture he formed, and improves it (--brain adds real-LLM depth).",
    ]
    return "\n".join(lines)


def run_scan(paths, deep, severity_threshold):
    findings = []
    for path in detect.collect_paths(paths):
        file_findings = detect.scan_file(path, deep=deep)
        # --deep also gives Python files a real AST read (deepscan): the rare,
        # semantic bugs regex can't see. Lazy import avoids a circular one
        # (deepscan imports from detect).
        if deep and path.lower().endswith(".py"):
            import deepscan
            file_findings += deepscan.scan_path(path)
        findings += [f for f in file_findings
                     if detect.SEVERITY_ORDER[f.severity] >= severity_threshold]
    findings.sort(key=detect.Finding.sort_key)
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="files or directories to scan")
    ap.add_argument("--deep", action="store_true",
                    help="think harder: enable higher-recall rules and check many web results")
    ap.add_argument("--online", action="store_true",
                    help="let Attestor consult the internet for references/corroboration")
    ap.add_argument("--sfw", action="store_true", help="bleep all profanity")
    ap.add_argument("--seed", type=int, default=None,
                    help="pin the random persona + wording (for reproducible runs/CI)")
    ap.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH"], default="LOW")
    ap.add_argument("--json", action="store_true",
                    help="plain machine-readable output (no persona)")
    ap.add_argument("--sarif", action="store_true",
                    help="emit SARIF 2.1.0 (for GitHub code scanning / CI)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--meet", action="store_true", help="introduce Attestor and exit")
    args = ap.parse_args(argv)

    if args.meet:
        print(meet()); return 0
    if args.list_rules:
        print(detect.list_rules()); return 0
    if args.self_test:
        persona, _ = pick_persona(args.seed)
        print(P.censor(random.Random(args.seed).choice(persona.wake)
                       if args.seed is not None else persona.wake[0], args.sfw))
        return detect.self_test()

    paths = args.paths or DEFAULT_PATHS
    threshold = detect.SEVERITY_ORDER[args.severity]
    findings = run_scan(paths, args.deep, threshold)

    # ----- SARIF: plain, no persona (CI / code scanning) -----
    if args.sarif:
        print(json.dumps(detect.to_sarif(findings), indent=2))
        return min(len(findings), 250)

    # ----- JSON: plain, no persona (machine consumers) -----
    if args.json:
        online.reset_budget()
        payload = []
        for f in findings:
            d = detect.asdict(f)
            if args.online:
                d["references"] = [{"label": l, "url": u, "status": s}
                                   for (l, u, s) in online.enrich(f.rule, args.deep, True)]
            payload.append(d)
        print(json.dumps(payload, indent=2))
        return min(len(findings), 250)

    # ----- Persona-driven human output -----
    persona, rng = pick_persona(args.seed)
    use_color = not args.no_color and sys.stdout.isatty()

    print(P.censor(rng.choice(persona.wake), args.sfw))
    if args.deep:
        print("   (thinking hard. deep mode on. this is going to hurt.)")
    if args.online:
        online.reset_budget()
        ok, msg = online.connectivity()
        print(P.censor(f"   [net] {msg}", args.sfw))
        print(f"   [net] {online.google_status()}")
        args._connected = ok
    print()

    for f in findings:
        refs = None
        if args.online:
            refs = online.enrich(f.rule, args.deep, getattr(args, "_connected", False))
        print(P.render_finding(persona, f, rng, args.sfw, refs=refs, use_color=use_color))
        print()

    n = len(findings)
    if n == 0:
        print(P.censor(rng.choice(persona.clean), args.sfw))
    else:
        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        tally = ", ".join(f"{sev_counts[s]} {s}" for s in ("HIGH", "MEDIUM", "LOW") if s in sev_counts)
        print(f"— {n} finding{'s' if n != 1 else ''} ({tally}). —")
        print(P.censor(rng.choice(persona.lament), args.sfw))
    return min(n, 250)


if __name__ == "__main__":
    sys.exit(main())
