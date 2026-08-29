#!/usr/bin/env python3
"""
curry.py -- every free model cooks the same dish; Attestor tastes each; the best is served.

The "thick curry": instead of trusting one model, ask EVERY configured provider
(Groq/Qwen, OpenRouter, Mistral, a local Ollama leaf, ...) the same request, then
have Attestor taste each dish with all three of his senses -- the regex detector, the
deepscan AST engine, and the crucible (does it actually run?) -- score them, and
serve the cleanest. A model's raw talent doesn't matter; what survives Attestor's
tasting does.

It's an ensemble, not a vote: the winner is the dish with the fewest problems that
still runs, not the most popular answer. Spices (Qwen, Llama, Nemotron, Mixtral)
are just the models you point each provider at.

    python3 curry.py "a function that flattens a nested list"
    python3 curry.py "an LRU cache class" --out lru.py
    python3 curry.py "..." --no-run          # taste statically only (skip running)
"""
from __future__ import annotations

import argparse

import brain
import crucible
import harvest
import quality
import secret_guard

_PROMPT = ("Write a single, self-contained Python module for this request. "
           "Use clear public function/class names that match the request. "
           "Return ONLY Python code -- no prose, no markdown fences.\n\nRequest: %s")


def _prompt(request: str) -> str:
    return (_PROMPT % request) + quality.prompt_addendum(request)


def cook(request: str, providers, execute: bool = True):
    """Have each provider generate a dish; Attestor tastes every one."""
    dishes = []
    for provider in providers:
        try:
            raw = provider.generate(_prompt(request))
        except brain.ProviderError as exc:
            dishes.append({"cook": provider.name, "error": str(exc)})
            continue
        code = brain.strip_fences(raw if isinstance(raw, str)
                                  else next(iter(raw.values()), ""))
        if not code.strip():
            dishes.append({"cook": provider.name, "error": "empty model response",
                           "evidence_level": "abstained"})
            continue
        improved, _ = harvest.improve(code)          # apply the safe mechanical fixes
        findings = harvest.scan_content(improved, ".py")
        credential_findings = secret_guard.scan_text(improved, "model-candidate.py")
        behavior_label, smoke = quality.behavior_check(request)
        runs = crucible.verify(improved, snippet=smoke).ok if execute else None
        eligible = not findings and not credential_findings and runs is not False
        level = ("behavior_verified" if eligible and runs is True and smoke else
                 "runtime_checked" if eligible and runs is True else
                 "scan_clean" if eligible else "refused")
        dishes.append({
            "cook": provider.name,
            "code": improved,
            "findings": len(findings),
            "credential_findings": len(credential_findings),
            "runs": runs,
            "behavior": bool(smoke),
            "lines": improved.count("\n") + (0 if improved.endswith("\n") else 1),
            "eligible": eligible,
            "evidence_level": level,
        })
    return dishes


def _score(dish):
    # lower is better: does it run? then fewest findings, then fewest lines
    runs_rank = 0 if dish["runs"] else (0.5 if dish["runs"] is None else 1)
    return (runs_rank, dish["findings"], dish["lines"])


def pick(dishes):
    # Never serve a merely "least bad" artifact.  A winner must at least have
    # zero enabled static findings, no credential signal, and no failed runtime
    # check.  Static-only candidates remain clearly labeled as such.
    cooked = [d for d in dishes if "code" in d and d.get("eligible") is True]
    return min(cooked, key=_score) if cooked else None


def render(request: str, dishes, winner) -> str:
    out = ['curry: "%s"' % request, "=" * 64,
           "every free model cooked; Attestor tasted each (both engines + the crucible):",
           "",
           "  %-12s %-8s %-7s %-8s %s" % ("cook", "findings", "runs", "behavior", "lines"),
           "  " + "-" * 40]
    for d in dishes:
        if "error" in d:
            out.append("  %-12s tapped out -- %s" % (d["cook"], d["error"]))
            continue
        runs = "yes" if d["runs"] else ("--" if d["runs"] is None else "NO")
        star = "  <- served" if winner is not None and d is winner else ""
        behavior = "yes" if d.get("behavior") and d["runs"] else ("--" if not d.get("behavior") else "NO")
        out.append("  %-12s %-8d %-7s %-8s %d%s"
                   % (d["cook"], d["findings"], runs, behavior, d["lines"], star))
    out.append("")
    if winner is None:
        out.append("RESULT: every cook tapped out (all providers failed -- 429s / no key?).")
    else:
        level = winner.get("evidence_level", "refused")
        labels = {
            "behavior_verified": "matching behavior check passed; absence of all bugs is not proven",
            "runtime_checked": "bounded runtime check passed; request correctness is not proven",
            "scan_clean": "enabled static scans found nothing; execution and behavior were not checked",
        }
        out.append("RESULT: served %s's candidate -- %s."
                   % (winner["cook"], labels.get(level, "unverified")))
        out.append("Evidence level: " + level)
        out += ["-" * 64, winner["code"]]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("request", nargs="+", help="what to build, in plain English")
    ap.add_argument("--no-run", action="store_true", help="taste statically only")
    ap.add_argument("--out", help="write the winning dish here")
    args = ap.parse_args(argv)

    bus = brain.from_env()
    providers = bus.providers()
    if not providers:
        print("no cooks in the kitchen. set GROQ_API_KEY / OPENROUTER_API_KEY / "
              "MISTRAL_API_KEY, or run Ollama and set OLLAMA_MODEL.")
        return 1
    if len(providers) == 1:
        print("(only one cook -- %s -- so this is really just a taste-test, not a "
              "curry. add another provider key for the full pot.)\n" % providers[0].name)

    request = " ".join(args.request)
    dishes = cook(request, providers, execute=not args.no_run)
    winner = pick(dishes)
    print(render(request, dishes, winner))
    if args.out and winner is not None:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(winner["code"])
        print("\nwrote the winning dish -> " + args.out)
    return 0 if winner is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
