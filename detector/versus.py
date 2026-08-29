#!/usr/bin/env python3
"""
versus.py -- the honest head-to-head: the same model, alone vs refereed by Attestor.

You can't run "Attestor vs GPT-5.5" -- Attestor is a verifier, not a code-writer, so that
race is apples-to-oranges (see codebench.py for why). What you CAN measure, and
what actually matters, is what Attestor *adds*: give one model a coding task twice --

  A) MODEL ALONE  : one shot, ship whatever it writes
  B) MODEL + ATTESTOR : the forge loop (generate -> both engines verify -> crucible
                    RUNS it -> repair -> repeat until clean)

...then score both dishes with Attestor's three senses (regex detect + AST deepscan +
does-it-actually-run). The gap between A and B is Attestor's value, in numbers.

Point it at any model. For OpenAI's GPT specifically:
    export OPENAI_API_KEY=sk-...
    python3 versus.py "an LRU cache with a TTL" --model gpt-4o     # or gpt-5.5 when real

Free today (no OpenAI needed): set GROQ_API_KEY and it uses Qwen/Llama.
"""
from __future__ import annotations

import argparse

import brain
import crucible
import forge
import harvest


def _measure(code: str, execute: bool = True) -> dict:
    findings = harvest.scan_content(code, ".py")
    return {"code": code,
            "findings": len(findings),
            "runs": crucible.verify(code).ok if execute else None,
            "lines": code.count("\n") + (0 if code.endswith("\n") else 1)}


def baseline(request: str, bus, execute: bool = True) -> dict:
    """One raw shot from the model -- no verification, no repair."""
    try:
        raw = bus.generate(forge._gen_prompt(request))
    except brain.ProviderError as exc:
        return {"error": str(exc)}
    code = brain.strip_fences(raw if isinstance(raw, str)
                              else next(iter(raw.values()), ""))
    return _measure(code, execute)


def versus(request: str, bus, rounds: int = 3, execute: bool = True) -> dict:
    raw = baseline(request, bus, execute)
    result = forge.forge(request, bus, rounds=rounds, execute=execute)
    refereed = _measure(result["code"], execute) if result["code"] else {"error": "no output"}
    refereed["rounds"] = len([r for r in result["transcript"] if "error" not in r])
    return {"request": request, "raw": raw, "attestor": refereed}


def render(v: dict) -> str:
    raw, attestor = v["raw"], v["attestor"]
    if "error" in raw and "error" in attestor:
        return 'versus: "%s"\nboth attempts failed (%s).' % (v["request"], raw["error"])

    def yn(x):
        return "yes" if x else ("--" if x is None else "NO")

    out = ['versus: "%s"' % v["request"], "=" * 60,
           "the SAME model, alone vs refereed by Attestor:", "",
           "  %-12s %-14s %s" % ("", "model alone", "model + Attestor"),
           "  " + "-" * 42,
           "  %-12s %-14s %s" % ("findings", raw.get("findings", "err"),
                                 attestor.get("findings", "err")),
           "  %-12s %-14s %s" % ("runs?", yn(raw.get("runs")), yn(attestor.get("runs"))),
           "  %-12s %-14s %s" % ("lines", raw.get("lines", "-"), attestor.get("lines", "-")),
           "  %-12s %-14s %s" % ("rounds", "1", attestor.get("rounds", "-")),
           ""]

    if "error" not in raw and "error" not in attestor:
        fewer = raw["findings"] - attestor["findings"]
        now_runs = (not raw["runs"]) and attestor["runs"]
        bits = []
        if fewer > 0:
            bits.append("%d fewer issue(s)" % fewer)
        if now_runs:
            bits.append("turned a broken draft into running code")
        if not bits:
            bits.append("the model's raw output was already clean (nothing to add here)")
        out.append("Attestor's value-add: " + ", ".join(bits) + ".")
    out += ["-" * 60, attestor.get("code", "(no output)")]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("request", nargs="+", help="the coding task, in plain English")
    ap.add_argument("--model", default="",
                    help="pin the model (e.g. gpt-4o, or gpt-5.5 when it exists)")
    ap.add_argument("--rounds", type=int, default=3, help="max forge repair rounds")
    ap.add_argument("--no-run", action="store_true", help="score statically only")
    args = ap.parse_args(argv)

    bus = brain.from_env(model=args.model)
    if not bus.available():
        print("versus needs a model. set OPENAI_API_KEY (+ --model gpt-4o) to test GPT,")
        print("or GROQ_API_KEY for a free Qwen/Llama stand-in, then rerun.")
        return 1
    print(render(versus(" ".join(args.request), bus,
                        rounds=args.rounds, execute=not args.no_run)))
    print("\n(this measures the model alone vs the model + Attestor -- not 'Attestor vs the")
    print(" model', which is apples-to-oranges. codebench.py explains why.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
