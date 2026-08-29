#!/usr/bin/env python3
"""
forge.py -- Gemini writes, Attestor verifies. The generate -> review -> repair loop.

This is the x*x you asked for. Attestor alone can't write novel code; a raw LLM can,
but it's stochastic and ships bugs. Multiply the two so each covers the other's
weakness:

    the LLM (brain.py: Gemini / OpenAI)  GENERATES the code
    Attestor's two deterministic engines     VERIFY it (regex detect + AST deepscan)
    the safe, mechanical issues          get AUTO-FIXED
    whatever's left                      goes BACK to the LLM to REPAIR
    ...loop until Attestor finds nothing (or the rounds run out).

The LLM brings the ideas; Attestor brings the ground truth. Neither half does this
alone. Needs a working key (see gemcheck.py); if the model 429s mid-loop, forge
stops and hands you the best Attestor-verified version it reached.

    python3 forge.py "a function that merges two sorted lists"  # static gate
    python3 forge.py "an LRU cache class" --run --rounds 4 --out lru.py

Generated code is never executed by default. ``--run`` is an explicit trust
decision and uses crucible.py's restricted subprocess profile.
"""
from __future__ import annotations

import argparse
import hashlib

import brain
import coder
import crucible
import detect
import harvest
import quality
import secret_guard


EVIDENCE_LEVELS = (
    "abstained", "refused", "scan_clean", "runtime_checked",
    "behavior_verified", "verified_improvement",
)


def _gen_prompt(request: str) -> str:
    return coder.generation_prompt(request) + quality.prompt_addendum(request)


def _review(code: str) -> list:
    """Attestor's verdict: both engines (regex + AST) on the code."""
    return harvest.scan_content(code, ".py")


def _static_prompt(code: str, findings) -> str:
    issues = "\n".join(
        "- line %d: %s -- %s" % (f.line, f.rule, f.fix)
        for f in sorted(findings, key=detect.Finding.sort_key))
    return coder.static_repair_prompt("", code, issues)


def _runtime_prompt(code: str, detail: str, behavior_label: str = "",
                    smoke: str = "", request: str = "") -> str:
    return coder.runtime_repair_prompt(request, code, detail, behavior_label, smoke)


def _candidate(answer) -> str:
    """Return one actual code candidate, never a provider failure sentinel."""
    values = answer.values() if isinstance(answer, dict) else (answer,)
    for value in values:
        if not isinstance(value, str) or value.startswith("[failed:"):
            continue
        code = brain.strip_fences(value)
        if code.strip():
            return code
    return ""


def _evidence_level(ok: bool, transcript: list[dict], code: str) -> str:
    if not code.strip():
        return "abstained" if any(row.get("abstained") for row in transcript) else "refused"
    if not ok:
        return "refused"
    records = [row for row in transcript if "error" not in row]
    final = records[-1] if records else {}
    if final.get("ran") is True and final.get("behavior"):
        return "behavior_verified"
    if final.get("ran") is True:
        return "runtime_checked"
    return "scan_clean"


def _finish(ok: bool, code: str, transcript: list[dict], contract: dict,
            execute: bool) -> dict:
    level = _evidence_level(ok, transcript, code)
    return {
        "ok": bool(ok), "code": code, "transcript": transcript,
        "contract": contract, "execution_enabled": execute,
        "sandbox": crucible.sandbox_status() if execute else None,
        "evidence_level": level,
        "artifact_sha256": hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()
        if code else "",
        "assurance": [
            "Model output is a candidate artifact, never independent evidence.",
            "Static-clean means only that the enabled deterministic scans found no issue.",
            "Requirements and practical security remain unproven unless a matching behavior gate ran.",
        ],
    }


def forge(request: str, bus, rounds: int = 3, execute: bool = False) -> dict:
    """The generate -> STATIC verify -> DYNAMIC verify -> repair loop.

    A round only counts as 'ok' when both engines find nothing AND (if execute)
    the code actually imports and runs in the bounded crucible. Static issues and
    runtime crashes are each fed back to the model as the next prompt.
    """
    transcript = []
    behavior_label, smoke = quality.behavior_check(request)
    prompt = _gen_prompt(request)
    code = ""
    for number in range(1, rounds + 1):
        try:
            typed = bus.generate_result(prompt) if hasattr(bus, "generate_result") else None
            answer = typed.content if typed is not None and typed.success else (
                bus.generate(prompt) if typed is None else "")
        except brain.ProviderError as exc:
            transcript.append({"round": number, "error": str(exc)})
            break
        if typed is not None and not typed.success:
            transcript.append({
                "round": number,
                "error": "provider generation " + typed.status.value,
                "abstained": typed.abstained,
                "generation": typed.evidence_dict(),
            })
            break
        code = _candidate(answer)
        if not code:
            transcript.append({
                "round": number, "error": "model abstained or returned an empty candidate",
                "abstained": True,
            })
            break

        improved, applied = harvest.improve(code)      # apply the safe mechanical fixes
        remaining = _review(improved)                   # what Attestor still objects to
        credential_findings = secret_guard.scan_text(improved, "model-candidate.py")
        code = improved
        rec = {
            "round": number,
            "lines": improved.count("\n") + (0 if improved.endswith("\n") else 1),
            "auto_fixed": [note for _, _, note in applied],
            "remaining": remaining,
            "ran": None,
            "behavior": bool(smoke),
            "credential_findings": len(credential_findings),
            "generation": typed.evidence_dict() if typed is not None else {
                "schema": "attestor-generation-evidence/legacy",
                "provider": "unreported", "model": "unreported",
                "status": "success",
                "prompt_sha256": hashlib.sha256(
                    prompt.encode("utf-8", "replace")).hexdigest(),
                "response_sha256": hashlib.sha256(
                    code.encode("utf-8", "replace")).hexdigest(),
            },
            "artifact_sha256": hashlib.sha256(
                improved.encode("utf-8", "replace")).hexdigest(),
            "score": coder.score_candidate(
                improved, remaining, ran=None, behavior=bool(smoke),
                auto_fixed=[note for _, _, note in applied]),
        }
        transcript.append(rec)

        if credential_findings:
            rec["error"] = "candidate contains credential-like material; content is not trusted"
            code = ""
            break

        if remaining:
            prompt = coder.static_repair_prompt(
                request, improved,
                "\n".join("- line %d: %s -- %s" % (f.line, f.rule, f.fix)
                          for f in sorted(remaining, key=detect.Finding.sort_key)))
            continue

        # statically clean -- now the crucible: does it actually RUN?
        if execute:
            verdict = crucible.verify(improved, snippet=smoke)
            rec["ran"] = verdict.ok
            rec["run_detail"] = verdict.detail
            rec["score"] = coder.score_candidate(
                improved, remaining, ran=verdict.ok, behavior=bool(smoke),
                auto_fixed=rec["auto_fixed"])
            if not verdict.ok:
                prompt = _runtime_prompt(
                    improved, verdict.detail, behavior_label, smoke, request=request)
                continue

        return _finish(True, code, transcript, coder.contract(request), execute)

    ok = bool(code.strip()) and not _review(code) and (
        not execute or crucible.verify(code, snippet=smoke).ok)
    return _finish(ok, code, transcript, coder.contract(request), execute)


def render(result: dict, request: str) -> str:
    execution_enabled = bool(result.get("execution_enabled"))
    process = ("The model proposes; Attestor's two scanners and restricted runtime collect evidence; repeat:"
               if execution_enabled else
               "The model proposes; Attestor's two scanners collect evidence; generated execution is OFF by default:")
    out = ['forge: "%s"' % request, "=" * 64,
           process]
    for rec in result["transcript"]:
        if "error" in rec:
            out.append("  round %d: the model tapped out -- %s" % (rec["round"], rec["error"]))
            continue
        fixed = ("; auto-fixed: " + ", ".join(rec["auto_fixed"])) if rec["auto_fixed"] else ""
        n = len(rec["remaining"])
        if n:
            verdict = "%d static issue(s) -> back to the model" % n
        elif rec["ran"] is False:
            verdict = "static-clean but CRASHED (%s) -> back to the model" % rec.get("run_detail", "")
        elif rec["ran"] is True and rec.get("behavior"):
            verdict = "zero enabled static findings; runtime and matching behavior checks passed"
        elif rec["ran"] is True:
            verdict = "zero enabled static findings; bounded runtime check passed"
        else:
            verdict = "zero enabled static findings (static evidence only)"
        score = "; " + coder.render_score(rec["score"]) if rec.get("score") else ""
        out.append("  round %d: model wrote %d lines%s; Attestor -> %s%s"
                   % (rec["round"], rec["lines"], fixed, verdict, score))
    level = result.get("evidence_level", "refused")
    if level == "behavior_verified":
        summary = ("BEHAVIOR-CHECKED CANDIDATE -- zero enabled static findings and the "
                   "bounded request-specific behavior check passed. This is not proof of all correctness.")
    elif level == "runtime_checked":
        summary = ("RUNTIME-CHECKED CANDIDATE -- zero enabled static findings and the "
                   "bounded runtime check passed; request correctness was not proven.")
    elif level == "scan_clean":
        summary = ("STATIC-SCAN-CLEAN CANDIDATE -- zero findings from enabled static checks; "
                   "the code was not executed and requirements/correctness were not proven.")
    elif level == "abstained":
        summary = "ABSTAINED -- the model produced no non-empty candidate."
    else:
        summary = "REFUSED -- the candidate did not earn the required evidence level."
    out += ["",
            "RESULT: " + summary,
            "Evidence level: " + level,
            "-" * 64,
            result["code"] if result.get("code") else "[no candidate artifact released]"]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("request", nargs="+", help="what to build, in plain English")
    ap.add_argument("--rounds", type=int, default=3, help="max generate/repair rounds")
    ap.add_argument("--model", default="",
                    help="pin the model on every provider (e.g. qwen/qwen3-32b)")
    execution = ap.add_mutually_exclusive_group()
    execution.add_argument("--run", action="store_true",
                           help="explicitly trust and run generated code in the restricted crucible")
    execution.add_argument("--no-run", action="store_true",
                           help=argparse.SUPPRESS)
    ap.add_argument("--out", help="write the final code here")
    args = ap.parse_args(argv)

    bus = brain.from_env(model=args.model)
    if not bus.available():
        print("forge needs a real LLM for the generator half. Set GROQ_API_KEY (free,")
        print("generous -- serves Qwen) or GEMINI_API_KEY, then try again. For the")
        print('Qwen + Attestor duo:  $env:GROQ_API_KEY="..."  ;  python3 forge.py "..." --model qwen/qwen3-32b')
        return 1

    request = " ".join(args.request)
    result = forge(request, bus, rounds=args.rounds, execute=args.run)
    print(render(result, request))
    if args.out and result["ok"] and result["code"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["code"])
        print("\nwrote -> " + args.out)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
