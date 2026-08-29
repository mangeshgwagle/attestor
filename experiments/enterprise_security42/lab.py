#!/usr/bin/env python3
"""Attestor 4.2's offline, no-paid-service enterprise-security experiment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence


# Support direct execution under Python isolated mode without trusting CWD or
# PYTHONPATH. Only this fixed, resolved sibling directory is added.
HERE = Path(__file__).resolve(strict=True).parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from engine import (  # noqa: E402
    LabInputError,
    LabOperationalError,
    SourceUnit,
    analyze_tenant,
    build_manifest,
    canonical_json,
    digest_json,
    exit_for_status,
    run_benchmark,
    run_isolation_self_test,
    run_self_test,
    verify_report,
)


class _ParserExit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _Parser(argparse.ArgumentParser):
    def exit(self, status: int = 0, message: str | None = None) -> None:
        if message:
            stream = sys.stdout if status == 0 else sys.stderr
            print(message, end="", file=stream)
        raise _ParserExit(status)

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print("attestor lab: error: " + message[:300], file=sys.stderr)
        raise _ParserExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="attestor lab",
        description=(
            "Offline synthetic enterprise-security measurements. Uses no "
            "paid service, network, target execution, compiler or telemetry."
        ),
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version="Attestor Lab 4.2")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("benchmark", "measure Attestor on the complete bundled paired corpus"),
        ("isolation", "check two synthetic tenant reports for logical leakage"),
        ("self-test", "run and verify the benchmark and isolation checks"),
    ):
        child = commands.add_parser(name, help=help_text, allow_abbrev=False)
        child.add_argument(
            "--format", choices=("text", "json"), default="text")
    return parser


def _text_report(report: dict[str, Any]) -> str:
    lines = [
        "Attestor Enterprise Security Lab 4.2",
        "command=%s status=%s complete=%s" % (
            report["command"], report["status"],
            str(report["complete"]).lower()),
        "incremental_service_cost_usd=0 network=false target_execution=false",
    ]
    if report["command"] == "benchmark":
        aggregate = report["metrics"]["aggregate"]
        lines.append("cases=%d tp=%d tn=%d fp=%d fn=%d" % (
            report["dataset"]["case_count"], aggregate["tp"], aggregate["tn"],
            aggregate["fp"], aggregate["fn"]))
        for cwe, values in report["metrics"]["per_cwe"].items():
            lines.append(
                "%s precision=%s recall=%s f1=%s" % (
                    cwe, values["precision"], values["recall"], values["f1"]))
        lines.append("boundary=" + report["dataset"]["design"])
    elif report["command"] == "isolation":
        for name, passed in sorted(report["checks"].items()):
            lines.append("%s=%s" % (name, str(passed).lower()))
        lines.append("boundary=" + report["claim_boundary"])
    else:
        lines.append("benchmark=%s isolation=%s children_verify=%s" % (
            report["benchmark"]["status"], report["isolation"]["status"],
            str(report["children_verify"]).lower()))
    lines.append("report_sha256=" + report["report_sha256"])
    return "\n".join(lines) + "\n"


def _emit(report: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_text_report(report), end="")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parser().parse_args(arguments)
    except _ParserExit as exc:
        return int(exc.status)

    try:
        if args.command == "benchmark":
            report = run_benchmark()
        elif args.command == "isolation":
            report = run_isolation_self_test()
        else:
            report = run_self_test()
        if not verify_report(report):
            raise LabOperationalError("the generated report did not verify")
        _emit(report, args.format)
        return exit_for_status(report["status"])
    except LabInputError:
        print("attestor-lab: invalid bounded synthetic input", file=sys.stderr)
        return exit_for_status("invalid_input")
    except Exception as exc:  # noqa: BLE001 - do not leak source or internals
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        print(
            "attestor-lab: operation failed (%s); no report was accepted"
            % type(exc).__name__,
            file=sys.stderr,
        )
        return exit_for_status("operational_failure")


if __name__ == "__main__":
    raise SystemExit(main())
