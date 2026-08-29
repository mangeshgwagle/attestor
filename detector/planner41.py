#!/usr/bin/env python3
"""Sequence Attestor's existing capabilities into a plan, and execute it safely.

What was actually missing
-------------------------
Attestor could already scan, rank, propose a fix, verify it without touching the
project, apply it with a backup, and roll it back. Every primitive a planner
needs was here. What he had no way to do was *order* them and carry state from
one step to the next, so he reported and stopped.

This module is that sequencer. It adds no detection and no judgement; it
decides only what to attempt, in what order, and when to stop.

Planning and doing are separate on purpose
------------------------------------------
`plan()` produces an artifact and changes nothing. `execute()` runs one, and
refuses to run one it cannot re-verify. A plan you cannot read before it runs
is not a plan, it is a promise -- and the whole reason to build this in a
security tool rather than hand it to a model is that every step states its
precondition in advance and every outcome is recorded.

Fail closed, everywhere
-----------------------
* `execute()` is a dry run unless explicitly authorised; nothing is written by
  default.
* A fix is only applied through `verified_remediation.apply_remediation`, which
  accepts a previously *accepted* verification and nothing else.
* After a fix is applied the file is re-scanned. If the finding it was supposed
  to remove is still there, the step is rolled back -- an applied change that
  did not achieve its stated purpose is a failure even when the tests pass.
* Every bound is explicit and recorded in the report.

No learned component appears anywhere in this file. The gate's ranking may be
supplied as a *hint* for ordering and can only permute the order in which
findings are attempted; it cannot add a step, remove one, or authorise one.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "attestor.plan/1.0"
RESULT_SCHEMA = "attestor.plan-result/1.0"
VERSION = "4.1.4"

MAX_WALL_SECONDS = 3_600

VERIFY_THEN_APPLY = "verify-then-apply"

PENDING = "pending"
APPLIED = "applied"
REJECTED = "rejected"
ROLLED_BACK = "rolled-back"
SKIPPED = "skipped"
FAILED = "failed"


class PlannerError(ValueError):
    """The plan, its bounds, or the report are unusable."""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False, default=str).encode("utf-8")).hexdigest()


def _finding_key(finding: Mapping[str, Any]) -> tuple:
    return (str(finding.get("path", "")), int(finding.get("line", 0) or 0),
            str(finding.get("rule", "")))


def plan(project_root: str, findings: Sequence[Mapping[str, Any]], *,
         max_steps: int = 0,
         order_hint: Sequence[Mapping[str, Any]] | None = None
         ) -> dict[str, Any]:
    """Decide what to attempt and in what order. Changes nothing.

    Ordering is deterministic: findings are sorted by path, line and rule, so
    the same input always produces the same plan and the same digest. An
    `order_hint` -- the gate's ranking, say -- may permute that order and
    nothing else. It cannot introduce a step or remove one, which is why a
    learned component is allowed to touch it at all.
    """
    if not isinstance(project_root, str) or not project_root.strip():
        raise PlannerError("project_root must be a non-empty path")
    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or \
            not 1 <= max_steps <= 0:
        raise PlannerError("max_steps must be an int in 1..%d" % 0)

    rows = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise PlannerError("every finding must be a mapping")
        path = finding.get("path")
        if not isinstance(path, str) or not path.strip():
            raise PlannerError("every finding must name the file it is in")
        rows.append(finding)

    ordered = sorted(rows, key=_finding_key)
    if order_hint is not None:
        priority = {}
        for position, hint in enumerate(order_hint):
            if isinstance(hint, Mapping):
                priority[(str(hint.get("rule", "")),
                          int(hint.get("line", 0) or 0))] = position
        ordered.sort(key=lambda f: (
            priority.get((str(f.get("rule", "")), int(f.get("line", 0) or 0)),
                         len(priority)),
            _finding_key(f)))

    steps = []
    for index, finding in enumerate(ordered[:max_steps]):
        steps.append({
            "index": index,
            "action": VERIFY_THEN_APPLY,
            "path": finding["path"],
            "rule": finding.get("rule", ""),
            "line": int(finding.get("line", 0) or 0),
            "precondition": "a verification this planner did not produce is "
                            "never applied",
            "success_test": "the finding is absent when the file is scanned "
                            "again",
            "on_failure": "roll back and record the reason",
            "status": PENDING,
        })

    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "project_root": project_root,
        "planned_steps": len(steps),
        "findings_considered": len(ordered),
        "truncated": len(ordered) > len(steps),
        "ordered_by": "gate ranking, then path/line/rule"
                      if order_hint else "path/line/rule",
        "steps": steps,
        "limitations": [
            "a plan is what will be attempted, not what will succeed",
            "only findings with a proposable fix can be acted on; the rest "
            "are reported and left alone",
            "ordering may be hinted by the gate but the set of steps never is",
        ],
    }
    report["plan_sha256"] = _sha(
        {k: v for k, v in report.items() if k != "plan_sha256"})
    return report


def verify_plan(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Recompute a plan's identity. Fails closed on anything unexpected."""
    problems: list[str] = []
    if not isinstance(report, Mapping) or report.get("schema") != SCHEMA:
        return False, ["not a plan produced by this module"]
    body = {k: v for k, v in report.items() if k != "plan_sha256"}
    if report.get("plan_sha256") != _sha(body):
        problems.append("plan digest does not match its contents")
    steps = report.get("steps")
    if not isinstance(steps, list):
        return False, problems + ["plan has no steps"]
    for position, step in enumerate(steps):
        if not isinstance(step, Mapping):
            problems.append("step %d is not a mapping" % position)
            continue
        if step.get("index") != position:
            problems.append("step %d is out of order" % position)
        if step.get("action") != VERIFY_THEN_APPLY:
            problems.append("step %d has an unknown action" % position)
    return not problems, problems


def execute(report: Mapping[str, Any], *,
            verify: Callable[..., Mapping[str, Any]],
            apply_fix: Callable[..., Mapping[str, Any]],
            rescan: Callable[[str], Sequence[Mapping[str, Any]]],
            rollback: Callable[..., Any] | None = None,
            authorized: bool = False,
            max_wall_seconds: float = MAX_WALL_SECONDS) -> dict[str, Any]:
    """Run a plan. A dry run unless `authorized` is explicitly true.

    The callables are injected rather than imported so this module stays
    testable without a repository on disk, and so the planner cannot quietly
    acquire a capability it was not handed. In production they are
    `verified_remediation.verify_remediation`, `.apply_remediation`,
    `.rollback_remediation` and a scan.
    """
    ok, problems = verify_plan(report)
    if not ok:
        raise PlannerError("refusing to execute an unverifiable plan: %s"
                           % "; ".join(problems[:3]))
    if not isinstance(max_wall_seconds, (int, float)) or \
            not 0 < max_wall_seconds <= MAX_WALL_SECONDS:
        raise PlannerError("max_wall_seconds out of range")

    started = time.time()
    outcomes: list[dict[str, Any]] = []
    applied = rejected = rolled_back = skipped = failed = 0

    for step in report["steps"]:
        elapsed = time.time() - started
        if elapsed > max_wall_seconds:
            outcomes.append({**{k: step[k] for k in ("index", "path", "rule",
                                                     "line")},
                             "status": SKIPPED,
                             "detail": "wall-clock budget exhausted"})
            skipped += 1
            continue

        finding = {"path": step["path"], "rule": step["rule"],
                   "line": step["line"]}
        try:
            verification = verify(report["project_root"], step["path"],
                                  [finding])
        except Exception as error:                       # noqa: BLE001
            outcomes.append({**finding, "index": step["index"],
                             "status": FAILED,
                             "detail": "verification raised: %s"
                                       % str(error)[:160]})
            failed += 1
            continue

        accepted = bool(isinstance(verification, Mapping)
                        and verification.get("accepted"))
        if not accepted:
            outcomes.append({**finding, "index": step["index"],
                             "status": REJECTED,
                             "detail": str(verification.get("reason",
                                                            "not accepted"))[:160]
                             if isinstance(verification, Mapping)
                             else "not accepted"})
            rejected += 1
            continue

        if not authorized:
            outcomes.append({**finding, "index": step["index"],
                             "status": SKIPPED,
                             "detail": "verified and would be applied; this "
                                       "run is not authorised to write"})
            skipped += 1
            continue

        try:
            result = apply_fix(verification)
        except Exception as error:                       # noqa: BLE001
            outcomes.append({**finding, "index": step["index"],
                             "status": FAILED,
                             "detail": "apply raised: %s" % str(error)[:160]})
            failed += 1
            continue

        # The step's own success test: the finding it existed to remove has
        # to be gone.  Passing tests is not the same as having worked, and an
        # applied change that left the defect in place is a failure.
        try:
            rescanned = rescan(step["path"])
        except Exception as error:                       # noqa: BLE001
            detail = "re-scan failed after apply: %s" % str(error)[:120]
            status = FAILED
            if rollback is not None:
                try:
                    rollback(result)
                    detail += "; rolled back"
                    status = ROLLED_BACK
                except Exception as rollback_error:      # noqa: BLE001
                    detail += "; rollback raised: %s" % str(rollback_error)[:80]
            outcomes.append({**finding, "index": step["index"],
                             "status": status, "detail": detail})
            if status == ROLLED_BACK:
                rolled_back += 1
            else:
                failed += 1
            continue

        still_there = any(
            str(row.get("rule", "")) == step["rule"]
            for row in (rescanned or [])
            if isinstance(row, Mapping))
        if still_there:
            detail = "finding survived the fix; rolled back"
            if rollback is not None:
                try:
                    rollback(result)
                except Exception as error:               # noqa: BLE001
                    detail = ("finding survived and rollback raised: %s"
                              % str(error)[:120])
            outcomes.append({**finding, "index": step["index"],
                             "status": ROLLED_BACK, "detail": detail})
            rolled_back += 1
            continue

        outcomes.append({**finding, "index": step["index"], "status": APPLIED,
                         "detail": "verified, applied, and confirmed absent "
                                   "on re-scan"})
        applied += 1

    result_report = {
        "schema": RESULT_SCHEMA,
        "version": VERSION,
        "plan_sha256": report["plan_sha256"],
        "authorized": bool(authorized),
        "steps_run": len(outcomes),
        "applied": applied,
        "rejected": rejected,
        "rolled_back": rolled_back,
        "skipped": skipped,
        "failed": failed,
        "elapsed_seconds": round(time.time() - started, 3),
        "outcomes": outcomes,
        "limitations": [
            "a dry run reports what would have been attempted and writes "
            "nothing",
            "the wall-clock budget is checked between steps, so a single "
            "long verification can overrun it; bound the verifier itself if "
            "that matters",
            "'applied' means the finding was gone when the file was scanned "
            "again, not that the program is correct",
            "findings the planner could not fix are untouched and remain "
            "reported",
        ],
    }
    result_report["result_sha256"] = _sha(
        {k: v for k, v in result_report.items() if k != "result_sha256"})
    return result_report


def verify_result(result: Mapping[str, Any],
                  report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Check a result is intact and belongs to the plan it claims."""
    problems: list[str] = []
    if not isinstance(result, Mapping) or result.get("schema") != RESULT_SCHEMA:
        return False, ["not a plan result produced by this module"]
    body = {k: v for k, v in result.items() if k != "result_sha256"}
    if result.get("result_sha256") != _sha(body):
        problems.append("result digest does not match its contents")
    if result.get("plan_sha256") != report.get("plan_sha256"):
        problems.append("result does not belong to this plan")
    if not result.get("authorized") and result.get("applied"):
        problems.append("an unauthorised run reports applied changes")
    return not problems, problems


def scan_tree(root: str, *, extensions: Sequence[str] = (".py", ".c", ".cpp",
                                                         ".h", ".js", ".hs"),
              max_files: int = 2_000) -> list[dict[str, Any]]:
    """Findings across a tree, in the shape `plan()` expects.

    Imported lazily so this module stays importable -- and testable -- without
    dragging the whole detector in behind it.
    """
    import detect

    findings: list[dict[str, Any]] = []
    seen = 0
    for base, directories, files in os.walk(root):
        directories[:] = [d for d in directories
                          if d not in ("__pycache__", ".git", "node_modules",
                                       ".venv", "venv")]
        for name in sorted(files):
            if not name.endswith(tuple(extensions)):
                continue
            seen += 1
            if seen > max_files:
                return findings
            path = os.path.join(base, name)
            try:
                for item in detect.scan_file(path, deep=True):
                    findings.append({
                        "path": os.path.relpath(path, root).replace("\\", "/"),
                        "rule": item.rule,
                        "line": int(getattr(item, "line", 0) or 0),
                        "message": getattr(item, "message", ""),
                    })
            except Exception:                            # noqa: BLE001
                continue                                 # one bad file is not
    return findings                                      # a failed run


def _live_actions(root: str, *, test_command: Sequence[str] | None,
                  authorize_tests: bool):
    """Bind the planner to the real remediation engine."""
    import detect
    import verified_remediation as remediation

    def verify(project_root, path, findings):
        return remediation.verify_remediation(
            project_root, path, findings,
            test_command=list(test_command) if test_command else None,
            authorize_tests=authorize_tests, runtime_policy=None, jobs=1,
            deep=True, require_verified=True, exact_file_scope=True,
            seed=0, fuzz_cases=64)

    def apply_fix(verification):
        return remediation.apply_remediation(
            verification, authorized=True, backup_root=None,
            require_verified=True)

    def rescan(path):
        return [{"rule": item.rule}
                for item in detect.scan_file(os.path.join(root, path),
                                             deep=True)]

    def rollback(result):
        return remediation.rollback_remediation(result, authorized=True)

    return verify, apply_fix, rescan, rollback


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Plan and optionally carry out Attestor's own repairs.")
    parser.add_argument("root", help="project to plan over")
    parser.add_argument("--apply", action="store_true",
                        help="actually write fixes; without it this is a dry "
                             "run that changes nothing")
    parser.add_argument("--rank", action="store_true",
                        help="order steps with the neural gate instead of by "
                             "position; it may reorder work, never choose it")
    parser.add_argument("--test-command", nargs=argparse.REMAINDER,
                        help="argv run to confirm a fix; enables test-backed "
                             "verification")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("error: %s is not a directory" % args.root)
        return 2

    findings = scan_tree(root)
    hint = None
    if args.rank and findings:
        try:
            import advisory41
            import neural_gate
            with open(os.path.join(root, findings[0]["path"]),
                      encoding="utf-8", errors="replace") as handle:
                hint = advisory41.rank(findings, handle.read(),
                                       neural_gate.default_model())
        except Exception:                                # noqa: BLE001
            hint = None                                  # ranking is a luxury

    try:
        report = plan(root, findings, max_steps=min(args.max_steps, 0),
                      order_hint=hint)
    except PlannerError as error:
        print("error: %s" % error)
        return 2

    verify, apply_fix, rescan, rollback = _live_actions(
        root, test_command=args.test_command,
        authorize_tests=bool(args.test_command))
    result = execute(report, verify=verify, apply_fix=apply_fix,
                     rescan=rescan, rollback=rollback, authorized=args.apply)

    if args.json:
        print(json.dumps({"plan": report, "result": result}, indent=2,
                         sort_keys=True))
    else:
        print(render(report, result))
    return 0 if not result["failed"] else 1


def render(report: Mapping[str, Any],
           result: Mapping[str, Any] | None = None) -> str:
    lines = ["Plan: %d step(s) over %s"
             % (report.get("planned_steps", 0), report.get("project_root"))]
    if report.get("truncated"):
        lines.append("  (truncated: more findings than the step budget)")
    for step in report.get("steps", []):
        lines.append("  %2d. %-28s %s:%s"
                     % (step["index"] + 1, step["rule"], step["path"],
                        step["line"]))
    if result is not None:
        lines.append("")
        lines.append("Result: %d applied, %d rejected, %d rolled back, "
                     "%d skipped, %d failed%s"
                     % (result.get("applied", 0), result.get("rejected", 0),
                        result.get("rolled_back", 0), result.get("skipped", 0),
                        result.get("failed", 0),
                        "" if result.get("authorized") else "  [dry run]"))
        for row in result.get("outcomes", []):
            lines.append("  %-11s %-26s %s" % (row["status"], row["rule"],
                                               row.get("detail", "")[:64]))
    lines.extend("  note: " + item for item in report.get("limitations", []))
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
