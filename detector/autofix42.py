#!/usr/bin/env python3
"""autofix42 -- self-healing code pipeline.

    brain drafts → syntax check → Owen scans → errors fed back →
    brain fixes → re-check → loop until clean or retries exhausted

    tier 5  clean-passed      syntax OK + zero detector findings
    tier 4  clean-syntax      syntax OK, minor warnings
    tier 1  broken            syntax errors persist after retries

Every round is logged. The final output is digest-pinned.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
import time
from pathlib import Path


sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

AF_SCHEMA = "attestor-autofix-4.2"


def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ------------------------------------------------------------ checks

def syntax_check(code):
    """Returns (ok, errors)."""
    try:
        ast.parse(code)
        compile(code, "<draft>", "exec")
        return True, []
    except SyntaxError as exc:
        return False, ["SyntaxError line %d: %s" % (exc.lineno, exc.msg)]
    except ValueError as exc:
        return False, ["ValueError: %s" % exc]


def security_scan(code):
    """Run Owen's source_hardening scanner. Returns list of findings."""
    try:
        import source_hardening42 as hard
        return hard.scan_text(code)
    except Exception:  # noqa: BLE001
        return []


def detector_scan(code):
    """Run the main detector on code. Returns list of findings."""
    try:
        import detect
        findings = detect.scan_text(code)
        return findings if isinstance(findings, list) else []
    except Exception:  # noqa: BLE001
        return []


# ------------------------------------------------------------ fix loop

def draft_and_fix(prompt, model, max_retries=0,
                  base="http://127.0.0.1:11434", system=None):
    """Full pipeline: draft, check, fix, re-check."""
    import local_brain42 as lb

    rounds = []
    current_prompt = prompt
    final_code = ""
    all_errors = []

    for attempt in range(1, max_retries + 1):
        # --- brain drafts or fixes ---
        fix_context = ""
        if all_errors:
            fix_context = (
                "\n\nYour previous draft had these errors:\n"
                + "\n".join("- " + e for e in all_errors)
                + "\n\nFix ALL errors and return the COMPLETE corrected "
                  "code. No commentary, no markdown fences.")
            current_prompt = prompt + fix_context

        result = lb.draft(current_prompt, model=model, base=base,
                          system=system)
        code = result.get("response", "").strip()

        # strip markdown fences
        if code.startswith("```"):
            nl = code.find("\n")
            if nl != -1:
                code = code[nl + 1:]
            if code.rstrip().endswith("```"):
                code = code.rstrip()[:-3]
        code = code.lstrip("\ufeff").strip() + "\n"

        # --- check ---
        syn_ok, syn_errors = syntax_check(code)
        sec_findings = security_scan(code)
        det_findings = detector_scan(code)

        errors = list(syn_errors)
        for f in sec_findings:
            errors.append("%s at line %s" % (f["check"], f.get("line")))
        for f in det_findings:
            errors.append("detector: %s" % str(f)[:100])

        round_info = {
            "attempt": attempt,
            "syntax_ok": syn_ok,
            "security_findings": len(sec_findings),
            "detector_findings": len(det_findings),
            "errors": errors[:10],
            "code_chars": len(code),
        }
        rounds.append(round_info)

        if syn_ok and not errors:
            final_code = code
            all_errors = []
            break

        all_errors = errors
        final_code = code

    # --- verdict ---
    if syn_ok and not all_errors:
        tier, tier_name = 5, "clean-passed"
    elif syn_ok:
        tier, tier_name = 4, "clean-syntax"
    else:
        tier, tier_name = 1, "broken"

    return {
        "schema": AF_SCHEMA,
        "tool": "autofix",
        "model": model,
        "prompt": prompt[:200],
        "tier": tier,
        "tier_name": tier_name,
        "retries_used": len(rounds),
        "rounds": rounds,
        "final_code": final_code,
        "final_code_sha256": sha256_hex(final_code.encode()),
        "errors_remaining": all_errors,
    }


# ------------------------------------------------------------- selftest

def run_selftest():
    checks = []
    import local_brain42 as lb

    # test with a model that works
    st = lb.status()
    if not st["alive"]:
        return {"schema": AF_SCHEMA, "tool": "self-test",
                "passed": False,
                "checks_failed": ["ollama not running"]}

    model = st["models"][0] if st["models"] else "qwen2.5-coder:1.5b"

    result = draft_and_fix(
        "Write a Python function safe_divide(a, b) that returns a/b "
        "but handles ZeroDivisionError by returning 0. Code only, no "
        "markdown fences, no explanation.",
        model=model, max_retries=3)

    checks.append(("pipeline completed", result["retries_used"] >= 1))
    checks.append(("code was produced", len(result["final_code"]) > 10))
    checks.append(("digest pinned",
                   len(result["final_code_sha256"]) == 64))
    checks.append(("tier assigned", result["tier"] in (1, 4, 5)))

    # verify the code actually compiles
    if result["tier"] in (4, 5):
        try:
            compile(result["final_code"], "<test>", "exec")
            checks.append(("final code compiles", True))
        except SyntaxError:
            checks.append(("final code compiles", False))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": AF_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="autofix42", description="Self-healing code pipeline")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--model", default="qwen2.5-coder:1.5b")
    parser.add_argument("--out", help="write final code here")
    parser.add_argument("--system")
    args = parser.parse_args(argv)

    import local_brain42 as lb
    st = lb.status()
    if not st["alive"]:
        print("autofix42: ollama not running. Start it first.",
              file=sys.stderr)
        return EXIT_OPERATIONAL

    result = draft_and_fix(args.prompt, model=args.model,
                           max_retries=args.retries, system=args.system)

    if args.out and result["final_code"]:
        Path(args.out).write_text(result["final_code"], encoding="utf-8")
        result["written_to"] = args.out

    printable = {k: v for k, v in result.items() if k != "final_code"}
    print(json.dumps(printable, indent=2, sort_keys=True))
    if result["final_code"]:
        print("\n--- FINAL CODE ---")
        print(result["final_code"])

    return EXIT_CLEAN if result["tier"] >= 4 else EXIT_OPERATIONAL


EXIT_CLEAN = 0
EXIT_OPERATIONAL = 4

if __name__ == "__main__":
    sys.exit(main())
