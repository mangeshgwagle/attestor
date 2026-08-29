#!/usr/bin/env python3
"""attestor2.py -- combined Attestor 2 maximum review mode."""
from __future__ import annotations

import argparse
import json
import os

import codepower
import secmax
import sieve


def run(target: str, bus: object | None = None, rounds: int = sieve.DEFAULT_PASSES) -> tuple[str, int]:
    target = (target or "").strip()
    if not target:
        return "Attestor 2 Max needs a project path, file path, or coding request.", 2
    if not os.path.exists(target):
        code_text, code = codepower.run(target, bus=bus, rounds=rounds)
        return "Attestor 2 Max prompt pipeline\n" + "=" * 72 + "\n" + code_text, code
    code_text, code_status = codepower.run(target, bus=bus, rounds=rounds)
    security_report = secmax.scan([target])
    security_text = secmax.render(security_report)
    risk_status = min(len(security_report["findings"]), 250)
    text = "\n\n".join([
        "Attestor 2 Max Review",
        code_text,
        security_text,
        "Attestor 2 verdict: code_status=%d security_findings=%d" % (
            code_status, len(security_report["findings"])),
    ])
    return text, max(code_status, risk_status)


def to_json(target: str) -> str:
    code_report = codepower.analyze(target) if os.path.exists(target) else {}
    security_report = secmax.scan([target]) if os.path.exists(target) else {}
    return json.dumps({
        "target": target,
        "codepower": code_report,
        "security": json.loads(secmax.to_json(security_report)) if security_report else {},
    }, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="+")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--passes", type=int, default=sieve.DEFAULT_PASSES)
    parser.add_argument("--model", default="")
    args = parser.parse_args(argv)
    target = " ".join(args.target)
    if args.json and os.path.exists(target):
        print(to_json(target))
        return 0
    bus = sieve.brain.from_env(model=args.model)
    text, code = run(target, bus=bus, rounds=args.passes)
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
