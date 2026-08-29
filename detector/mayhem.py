#!/usr/bin/env python3
"""Attestor 3.0 Coding Mayhem: the maximum deterministic engineering gate.

Mayhem fuses quality policy, deep multi-language scanning, repository
intelligence, defensive cybersecurity posture, static mutation analysis, and an
optional transactional candidate-patch review.  It is dry by default: no tests
or mutants execute without explicit authorization, and candidate patches are
verified but never applied here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import mutation_gauntlet
import patchguard
import qualitygate
import response_engine
import scanengine
import security_posture


SCHEMA = "attestor-coding-mayhem/3.0"
MUTATION_LANGUAGES = {"python", "javascript", "typescript"}
MAX_MUTATION_BYTES = 512 * 1024


def _mutation_pass(root: Path, limit: int, execute: bool) -> dict[str, Any]:
    files, errors, skipped = scanengine.discover([str(root)])
    candidates = [path for path in files
                  if scanengine._language(path) in MUTATION_LANGUAGES
                  and path.stat().st_size <= MAX_MUTATION_BYTES
                  and not path.name.startswith("test_")]
    candidates = candidates[:max(0, min(int(limit), 64))]
    reports = []
    for path in candidates:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append("%s: %s" % (path, exc))
            continue
        result = mutation_gauntlet.run(source, str(path), execute=execute)
        if result["mutants"]:
            try:
                label = path.relative_to(root).as_posix()
            except ValueError:
                label = str(path)
            reports.append({**result, "path": label})
    total = sum(len(row["mutants"]) for row in reports)
    caught = sum(row["caught"] for row in reports)
    gaps = [{"path": row["path"], **gap} for row in reports for gap in row["gaps"]]
    return {
        "status": "not-applicable" if not total else ("passed" if not gaps else "gaps"),
        "execution_enabled": bool(execute), "files_considered": len(candidates),
        "files_mutated": len(reports), "mutants": total, "caught": caught,
        "survived": len(gaps), "score": round(100 * caught / total, 1) if total else None,
        "gaps": gaps, "reports": reports, "errors": errors, "skipped": skipped,
    }


def _priorities(quality: dict, security: dict, mutation: dict,
                patch: dict | None) -> list[dict[str, Any]]:
    rows = []
    for reason in quality.get("reasons", []):
        rows.append({"priority": "HIGH" if reason["code"] in {
            "scan-failed", "high-threshold", "tests-failed", "tests-timeout"} else "MEDIUM",
                     "category": "quality-gate", "fix": reason["message"],
                     "source": reason["code"]})
    for item in security.get("recommendations", [])[:20]:
        rows.append({"priority": item["priority"], "category": item["category"],
                     "fix": item["fix"], "source": ", ".join(item["rules"][:3])})
    for gap in mutation.get("gaps", [])[:12]:
        rows.append({"priority": "MEDIUM", "category": "mutation-gap",
                     "fix": "Add a regression test/detector for %s in %s." % (
                         gap["mutation"], gap["path"]), "source": gap["target_rule"]})
    if patch and not patch.get("accepted"):
        for reason in patch.get("reasons", []):
            rows.append({"priority": "HIGH", "category": "candidate-patch",
                         "fix": reason, "source": "patchguard"})
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    unique = {}
    for row in rows:
        key = (row["category"], row["fix"])
        previous = unique.get(key)
        if previous is None or rank.get(row["priority"], 0) > rank.get(previous["priority"], 0):
            unique[key] = row
    return sorted(unique.values(), key=lambda row: (
        -rank.get(row["priority"], 0), row["category"], row["fix"]))[:40]


def _readiness(quality: dict, security: dict, mutation: dict,
               patch: dict | None) -> dict[str, Any]:
    severity = security.get("summary", {}).get("severity", {})
    deductions = {
        "critical_findings": min(60, severity.get("CRITICAL", 0) * 20),
        "high_findings": min(45, severity.get("HIGH", 0) * 8),
        "medium_findings": min(20, severity.get("MEDIUM", 0) * 2),
        "low_findings": min(8, severity.get("LOW", 0)),
        "quality_gate_reasons": min(30, len(quality.get("reasons", [])) * 5),
        "surviving_mutants": min(20, mutation.get("survived", 0) * 4),
        "unverified_sources": min(12, security.get("coverage", {}).get("unverified", 0)),
        "rejected_candidate": 20 if patch and not patch.get("accepted") else 0,
    }
    score = max(0, 100 - sum(deductions.values()))
    blockers = (severity.get("CRITICAL", 0) + severity.get("HIGH", 0)
                + len(quality.get("reasons", []))
                + (1 if patch and not patch.get("accepted") else 0))
    if blockers:
        label = "blocked" if score < 50 else "needs-work"
    elif score >= 90:
        label = "release-ready-by-enabled-gates"
    elif score >= 75:
        label = "hardening-recommended"
    else:
        label = "needs-work"
    return {"score": score, "label": label, "blockers": blockers,
            "deductions": deductions}


def run(root: str | Path, *, min_grade: str = "B", max_high: int = 0,
        jobs: int = scanengine.DEFAULT_JOBS, deep: bool = True,
        external_tools: bool = False, use_cache: bool = True,
        cache_path: str = "", mutation_limit: int = 12,
        execute_mutants: bool = False, run_tests: bool = False,
        test_command: list[str] | tuple[str, ...] | None = None,
        test_timeout: int = 120, target: str = "", candidate_source: str | None = None,
        candidate_name: str = "candidate") -> dict[str, Any]:
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        return {"schema": SCHEMA, "root": str(base), "status": "failed",
                "readiness": {"score": 0, "label": "unknown", "blockers": 1},
                "summary": {"errors": 1}, "priorities": [{
                    "priority": "HIGH", "category": "workspace",
                    "fix": "Select a readable project directory.", "source": "invalid-root"}],
                "top_findings": [], "errors": ["workspace is not a readable directory"],
                "assurance": ["No project analysis was performed."]}
    quality_report = qualitygate.evaluate(
        base, min_grade=min_grade, max_high=max_high, run_tests=run_tests,
        test_command=test_command, test_timeout=test_timeout, jobs=jobs, deep=deep,
        external_tools=external_tools, use_cache=use_cache, cache_path=cache_path)
    quality = qualitygate.to_dict(quality_report)
    security = security_posture.assess(
        base, jobs=jobs, deep=deep, external_tools=external_tools,
        use_cache=use_cache, cache_path=cache_path)
    mutation = _mutation_pass(base, mutation_limit, execute_mutants)
    patch = None
    if target or candidate_source is not None:
        if not target or candidate_source is None:
            patch = {"accepted": False, "reasons": [
                "both target and candidate_source are required for candidate verification"]}
        else:
            try:
                patch_report = patchguard.verify_candidate(
                    base, target, candidate_source, name=candidate_name,
                    test_command=test_command if run_tests else None,
                    authorize_tests=run_tests, test_timeout=test_timeout,
                    jobs=max(1, min(int(jobs), 32)), deep=deep)
                patch = patchguard.report_dict(patch_report)
            except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
                patch = {"accepted": False, "reasons": [
                    "candidate verification failed safely: %s" % type(exc).__name__]}
    readiness = _readiness(quality, security, mutation, patch)
    priorities = _priorities(quality, security, mutation, patch)
    operational_failure = (security.get("status") == "failed"
                           or quality.get("scan", {}).get("status") in {"failed", "unsupported"})
    if operational_failure:
        status = "failed"
    elif readiness["blockers"]:
        status = "action-required"
    elif priorities:
        status = "ready-with-notes"
    else:
        status = "ready"
    severity = security.get("summary", {}).get("severity", {})
    return {
        "schema": SCHEMA, "root": str(base), "status": status,
        "readiness": readiness,
        "summary": {
            "files_scanned": security.get("summary", {}).get("files_scanned", 0),
            "security_findings": security.get("summary", {}).get("findings", 0),
            "critical": severity.get("CRITICAL", 0), "high": severity.get("HIGH", 0),
            "quality_gate": quality["status"], "files_graded": quality["grades"]["files_graded"],
            "mutation_score": mutation["score"], "surviving_mutants": mutation["survived"],
            "tests": quality["tests"]["status"],
            "candidate": None if patch is None else ("accepted" if patch.get("accepted") else "rejected"),
        },
        "priorities": priorities,
        "top_findings": security.get("findings", [])[:50],
        "quality": quality, "security": security, "mutation": mutation,
        "candidate_patch": patch,
        "errors": list(security.get("errors", [])) + list(mutation.get("errors", [])),
        "assurance": [
            "Mayhem is dry by default; tests and mutant execution require explicit authorization.",
            "Candidate patches are isolated and verified here but never applied by Mayhem.",
            "Readiness is a transparent heuristic over enabled gates, not a claim of defect-free software.",
            "Dependency CVE status is not guessed without a current advisory source.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--min-grade", choices=("A", "B", "C", "D", "F"), default="B")
    parser.add_argument("--max-high", type=int, default=0)
    parser.add_argument("--jobs", type=int, default=scanengine.DEFAULT_JOBS)
    parser.add_argument("--tools", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--cache", default="")
    parser.add_argument("--mutation-limit", type=int, default=12)
    parser.add_argument("--execute-mutants", action="store_true",
                        help="explicitly execute Python mutants in the restricted runner")
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--test-command-json", default="")
    parser.add_argument("--test-timeout", type=int, default=120)
    parser.add_argument("--target", default="", help="project-relative target for candidate review")
    parser.add_argument("--candidate", default="", help="replacement source file (verification only)")
    parser.add_argument("--candidate-name", default="candidate")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--response-style", choices=response_engine.STYLES, default="professional")
    args = parser.parse_args(argv)
    if args.max_high < 0:
        parser.error("--max-high cannot be negative")
    command = None
    if args.test_command_json:
        try:
            command = json.loads(args.test_command_json)
            qualitygate._validate_command(command)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            parser.error("--test-command-json must be a bounded JSON argv list: %s" % exc)
    if args.run_tests and not command:
        parser.error("--run-tests requires --test-command-json")
    if args.candidate and not args.target:
        parser.error("--candidate requires --target")
    try:
        candidate_source = Path(args.candidate).read_text(encoding="utf-8") if args.candidate else None
    except OSError as exc:
        parser.error("cannot read --candidate: %s" % exc)
    report = run(
        args.root, min_grade=args.min_grade, max_high=args.max_high,
        jobs=args.jobs, external_tools=args.tools, use_cache=not args.no_cache,
        cache_path=args.cache, mutation_limit=args.mutation_limit,
        execute_mutants=args.execute_mutants, run_tests=args.run_tests,
        test_command=command, test_timeout=args.test_timeout,
        target=args.target, candidate_source=candidate_source,
        candidate_name=args.candidate_name)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "sarif":
        print(json.dumps(security_posture.to_sarif(report.get("security", {})), indent=2))
    else:
        print(response_engine.structured(report, args.response_style))
    if report["status"] == "failed":
        return 2
    return 0 if report["status"] in {"ready", "ready-with-notes"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
