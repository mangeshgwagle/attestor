#!/usr/bin/env python3
"""
patchforge.py -- ask API models for patches, then make them earn trust.

Attestor applies safe mechanical fixes first. For every remaining finding, Patch
Forge asks the configured model(s) for a whole-file repair. A patch is accepted
only if it passes:

  1. Attestor static scan (detect.py + deepscan for Python)
  2. optionally, crucible.py's restricted import/runtime gate for Python
  3. request-aware behavior tests when the request has a known smoke test
  4. caller-supplied regression tests

No model patch is trusted just because it looks nice.

Generated patches are not executed by default. Pass ``--run`` only after
deciding the source and requested regression commands are trusted enough to run.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
import shlex
import tempfile

import brain
import confidence
import crucible
import detect
import harvest
import quality
import reproducer


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower() or ".py"


def _scan(source: str, ext: str) -> list:
    return harvest.scan_content(source, ext)


def _answers(answer) -> dict:
    if isinstance(answer, dict):
        return {name: brain.strip_fences(text) for name, text in answer.items()
                if isinstance(text, str) and not text.startswith("[failed:")}
    return {"model": brain.strip_fences(answer)}


def _prompt(source: str, path: str, finding, repro: dict) -> str:
    return (
        "Patch this file to fix the Attestor finding below. Return the COMPLETE "
        "replacement file only: no prose, no markdown fences, no diff.\n\n"
        "File: %s\n"
        "Finding: line %d [%s] %s\n"
        "Message: %s\n"
        "Required fix: %s\n\n"
        "Small reproducer proving the bug:\n%s\n\n"
        "Current file:\n%s"
    ) % (
        path, finding.line, finding.severity, finding.rule,
        finding.message, finding.fix, repro["bug_source"], source,
    )


def _run_callable_regressions(source: str, tests) -> tuple[bool | None, list[str]]:
    details = []
    for test in tests or []:
        name = getattr(test, "__name__", "regression")
        try:
            result = test(source)
        except Exception as exc:                # noqa: BLE001
            details.append("%s failed: %s %s" % (name, type(exc).__name__, exc))
            return False, details
        if isinstance(result, tuple):
            ok, detail = result
        else:
            ok, detail = bool(result), "ok" if result else "failed"
        details.append("%s: %s" % (name, detail))
        if not ok:
            return False, details
    if not tests:
        details.append("no caller-supplied regression tests; behavior is unknown")
        return None, details
    return True, details


def _public_api(source: str, ext: str) -> set[str]:
    if ext != ".py" or not source.strip():
        return set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    return {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and not node.name.startswith("_")
    }


def _candidate_integrity(original: str, candidate: str, ext: str,
                         target_rules: set[str]) -> dict:
    """Bind a candidate to the artifact it claims to improve.

    Static silence alone rewards deletion.  This contract rejects empty or
    near-total erasure, public-API loss, explosive output growth, and candidates
    that do not reduce the rules that caused Patch Forge to run.
    """
    reasons = []
    original_text = original.strip()
    candidate_text = candidate.strip()
    if not candidate_text:
        reasons.append("candidate is empty")
    if len(original_text) >= 80 and len(candidate_text) < max(24, len(original_text) // 5):
        reasons.append("candidate removes more than the bounded preservation policy allows")
    if original_text and len(candidate_text) > max(32_768, len(original_text) * 8):
        reasons.append("candidate exceeds the bounded replacement size policy")
    before_api = _public_api(original, ext)
    after_api = _public_api(candidate, ext)
    missing_api = sorted(before_api - after_api)
    if missing_api:
        reasons.append("candidate removes public API: " + ", ".join(missing_api[:8]))
    before = _scan(original, ext)
    after = _scan(candidate, ext) if candidate_text else []
    before_target = sum(item.rule in target_rules for item in before)
    after_target = sum(item.rule in target_rules for item in after)
    if target_rules and after_target >= before_target:
        reasons.append("candidate did not reduce the targeted finding set")
    before_keys = {(item.rule, item.line) for item in before}
    new_keys = sorted({(item.rule, item.line) for item in after} - before_keys)
    if new_keys:
        reasons.append("candidate introduced new scanner findings")
    return {
        "ok": not reasons,
        "reasons": reasons,
        "original_sha256": hashlib.sha256(original.encode("utf-8", "replace")).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8", "replace")).hexdigest()
        if candidate else "",
        "public_api_before": sorted(before_api),
        "public_api_after": sorted(after_api),
        "target_findings_before": before_target,
        "target_findings_after": after_target,
    }


def _run_command_regression(source: str, command: str, *, trusted: bool = False) -> tuple[bool, str]:
    """Run one explicitly trusted command against candidate.py. No shell."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "candidate.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        try:
            # POSIX shlex semantics remove protective quotes around Windows
            # executable paths while still returning an argv list (never a shell).
            argv = shlex.split(command)
            verdict = crucible.run_trusted_command(
                argv, tmp, trusted=trusted, timeout=15)
        except (TypeError, ValueError) as exc:
            return False, "%s %s" % (type(exc).__name__, exc)
        output = (verdict.stderr or verdict.stdout or "").strip().splitlines()
        detail = output[-1] if output else verdict.detail
        return verdict.ok, detail


def gate(source: str, ext: str, request: str = "", regression_tests=None,
         execute: bool = False) -> dict:
    findings = _scan(source, ext)
    non_empty = bool(source.strip())
    parser_ok = True
    if ext == ".py":
        try:
            ast.parse(source)
        except SyntaxError:
            parser_ok = False
    static_ok = non_empty and parser_ok and not findings

    label, smoke = quality.behavior_check(request) if request else ("", "")
    if ext == ".py" and execute:
        verdict = crucible.verify(source, snippet=smoke)
        crucible_ok = verdict.ok
        crucible_detail = verdict.detail
    elif ext == ".py":
        crucible_ok = None
        crucible_detail = "generated execution disabled; pass execute=True/--run to opt in"
    else:
        crucible_ok = None
        crucible_detail = "crucible is Python-only; static gate used for %s" % ext

    regression_ok, regression_detail = _run_callable_regressions(source, regression_tests)
    ok = static_ok and crucible_ok is not False and regression_ok is not False
    if not ok:
        evidence_level = "refused"
    elif crucible_ok is True and bool(smoke):
        evidence_level = "behavior_verified"
    elif crucible_ok is True:
        evidence_level = "runtime_checked"
    else:
        evidence_level = "scan_clean"
    return {
        "ok": ok,
        "non_empty": non_empty,
        "parser_ok": parser_ok,
        "static_ok": static_ok,
        "findings": findings,
        "crucible_ok": crucible_ok,
        "crucible_detail": crucible_detail,
        "execution_requested": execute,
        "execution_enabled": bool(execute and ext == ".py"),
        "sandbox": crucible.sandbox_status() if execute and ext == ".py" else None,
        "behavior": label or "none",
        "regression_ok": regression_ok,
        "regression_detail": regression_detail,
        "evidence_level": evidence_level,
        "artifact_sha256": hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()
        if source else "",
    }


def patch_source(source: str, path: str, bus, request: str = "", rounds: int = 3,
                 regression_tests=None, execute: bool = False) -> dict:
    if bus is None or not bus.available():
        return {"ok": False, "code": source, "applied": [], "attempts": [],
                "error": "patchforge needs at least one configured API model"}

    ext = _ext(path)
    original = source
    target_rules = {item.rule for item in _scan(source, ext)}
    current, applied = harvest.improve(source)
    attempts = []

    for _round in range(1, max(1, rounds) + 1):
        findings = _scan(current, ext)
        unsafe = [f for f in findings if not confidence.safe_to_autofix(f.rule)]
        if not unsafe:
            final_gate = gate(current, ext, request=request,
                              regression_tests=regression_tests, execute=execute)
            integrity = _candidate_integrity(original, current, ext, target_rules)
            final_gate["integrity"] = integrity
            final_gate["ok"] = bool(final_gate["ok"] and integrity["ok"])
            if not final_gate["ok"]:
                final_gate["evidence_level"] = "refused"
            return {"ok": final_gate["ok"], "code": current, "applied": applied,
                    "attempts": attempts, "gate": final_gate,
                    "evidence_level": final_gate["evidence_level"]}

        finding = sorted(unsafe, key=detect.Finding.sort_key)[0]
        repro = reproducer.make(current, path, finding)
        prompt = _prompt(current, path, finding, repro)
        generation_evidence = {}
        try:
            if hasattr(bus, "generate_results"):
                generated = bus.generate_results(prompt)
                answer = {item.provider: item.content for item in generated if item.success}
                generation_evidence = {
                    item.provider: item.evidence_dict() for item in generated
                }
            else:
                answer = bus.generate(prompt)
        except brain.ProviderError as exc:
            attempts.append({"rule": finding.rule, "error": str(exc)})
            break
        if not _answers(answer):
            attempts.append({
                "rule": finding.rule,
                "error": "all providers failed or abstained",
                "generation": list(generation_evidence.values()),
            })
            break

        accepted = False
        for name, candidate in _answers(answer).items():
            verdict = gate(candidate, ext, request=request,
                           regression_tests=regression_tests, execute=execute)
            integrity = _candidate_integrity(original, candidate, ext, target_rules)
            verdict["integrity"] = integrity
            verdict["ok"] = bool(verdict["ok"] and integrity["ok"])
            if not verdict["ok"]:
                verdict["evidence_level"] = "refused"
            rec = {
                "rule": finding.rule,
                "provider": name,
                "accepted": verdict["ok"],
                "gate": verdict,
                "lines": candidate.count("\n") + (0 if candidate.endswith("\n") else 1),
                "generation": generation_evidence.get(name, {
                    "schema": "attestor-generation-evidence/legacy",
                    "provider": name, "model": "unreported", "status": "success",
                    "prompt_sha256": hashlib.sha256(
                        prompt.encode("utf-8", "replace")).hexdigest(),
                    "response_sha256": hashlib.sha256(
                        candidate.encode("utf-8", "replace")).hexdigest(),
                }),
            }
            attempts.append(rec)
            if verdict["ok"]:
                current = candidate
                accepted = True
                break
        if not accepted:
            break

    final_gate = gate(current, ext, request=request,
                      regression_tests=regression_tests, execute=execute)
    integrity = _candidate_integrity(original, current, ext, target_rules)
    final_gate["integrity"] = integrity
    final_gate["ok"] = bool(final_gate["ok"] and integrity["ok"])
    if not final_gate["ok"]:
        final_gate["evidence_level"] = "refused"
    return {"ok": final_gate["ok"], "code": current, "applied": applied,
            "attempts": attempts, "gate": final_gate,
            "evidence_level": final_gate["evidence_level"]}


def patch_file(path: str, bus, request: str = "", rounds: int = 3,
               regression_tests=None, execute: bool = False) -> dict:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return patch_source(fh.read(), path, bus, request=request, rounds=rounds,
                            regression_tests=regression_tests, execute=execute)


def render(result: dict, path: str = "") -> str:
    out = ["Patch Forge" + (" for " + path if path else ""), "=" * 64]
    if result.get("error"):
        out.append(result["error"])
        return "\n".join(out)
    if result.get("applied"):
        out.append("safe mechanical fixes first:")
        for _rid, count, note in result["applied"]:
            out.append("  %s x%d" % (note, count))
    else:
        out.append("safe mechanical fixes first: none")
    for rec in result["attempts"]:
        if "error" in rec:
            out.append("  %s: model failed -- %s" % (rec["rule"], rec["error"]))
            continue
        gate_info = rec["gate"]
        verdict = "ACCEPTED" if rec["accepted"] else "rejected"
        out.append("  %s via %s: %s (%d lines)" % (
            rec["rule"], rec["provider"], verdict, rec["lines"]))
        out.append("    static=%s crucible=%s regression=%s behavior=%s" % (
            "ok" if gate_info["static_ok"] else "fail",
            ("ok" if gate_info["crucible_ok"] else "fail")
            if gate_info["crucible_ok"] is not None else "skipped",
            ("ok" if gate_info["regression_ok"] else "fail")
            if gate_info["regression_ok"] is not None else "not-run",
            gate_info["behavior"]))
    gate_info = result.get("gate") or {}
    out.append("")
    level = result.get("evidence_level", gate_info.get("evidence_level", "refused"))
    if result.get("ok") and level == "behavior_verified":
        summary = ("behavior-checked candidate: static, restricted-runtime, and matching "
                   "behavior evidence passed")
    elif result.get("ok") and level == "runtime_checked":
        summary = ("runtime-checked candidate: static and bounded runtime evidence passed; "
                   "request correctness remains unproven")
    elif result.get("ok"):
        summary = ("static-scan-clean candidate: enabled static checks passed; execution and "
                   "behavior/regression evidence were not run")
    else:
        summary = "refused; the original/best effort was retained"
    out.append("RESULT: " + summary)
    out.append("Evidence level: " + level)
    if gate_info.get("findings"):
        out.append("remaining findings: %d" % len(gate_info["findings"]))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="file to patch")
    ap.add_argument("--request", default="", help="original coding request for behavior checks")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--model", default="")
    ap.add_argument("--run", action="store_true",
                    help="explicitly trust and execute Python patches/regression commands")
    ap.add_argument("--out", help="write a gate-accepted candidate here (evidence level is reported)")
    ap.add_argument("--test", action="append", default=[],
                    help="regression command to run in a temp dir containing candidate.py")
    args = ap.parse_args(argv)

    if args.test and not args.run:
        print("--test commands execute code; pass --run to make that trust decision explicit")
        return 2

    bus = brain.from_env(mode="compare", model=args.model)

    command_tests = []
    for command in args.test:
        def _test(source, command=command):
            return _run_command_regression(source, command, trusted=args.run)
        _test.__name__ = command
        command_tests.append(_test)

    result = patch_file(args.file, bus, request=args.request, rounds=args.rounds,
                        regression_tests=command_tests, execute=args.run)
    print(render(result, args.file))
    if args.out and result["ok"]:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(result["code"])
        print("\nwrote %s candidate -> %s" % (
            result.get("evidence_level", "scan_clean"), args.out))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
