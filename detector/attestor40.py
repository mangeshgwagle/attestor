#!/usr/bin/env python3
"""Attestor 4.0 evidence-backed engineering and defensive-security orchestrator.

Attestor 4.0 preserves the verified Attestor 3.5 analysis and transactional-repair
contracts, then adds bounded Engineering Intelligence and Security Fabric
reports.  Analysis is static by default.  Target execution and file mutation
remain separate, explicitly authorized operations with fail-closed gates.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import engineering_engine40
import execution_fabric35
import attestor3
import attestor35
import response40
import security_fabric40
import supply_chain_center
import transactional_repair35
import truth_guard40


SCHEMA = "attestor-maximum/4.0"
VERSION = "4.0.0"
COMPATIBILITY_COMPONENTS = tuple(attestor35.DEFAULT_COMPONENTS)
NEW_COMPONENTS = ("engineering", "security-fabric")
DEFAULT_COMPONENTS = COMPATIBILITY_COMPONENTS + NEW_COMPONENTS
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
MAX_FINDINGS = 4_000
MAX_TOP_FINDINGS = 100
MAX_ATTACK_PATHS = 100
MAX_PUBLIC_BYTES = 16 * 1024 * 1024
ENGINEERING_STATUSES = frozenset({
    "issues-observed", "no-static-issues-with-gaps",
    "no-static-issues-from-bounded-checks", "unavailable",
})
SECURITY_STATUSES = frozenset({"findings", "clean", "partial", "failed"})
_FALSE_STATIC_KEYS = frozenset({
    "target_code_executed", "target_code", "imports_executed", "imports",
    "processes_started", "processes", "external_processes_spawned",
    "network_accessed", "network", "network_probing", "filesystem_writes",
    "target_files_written", "dependencies_installed", "compiler_invoked",
    "compilers", "tests", "benchmarks", "database", "migrations",
    "patch_apply", "automatic_remediation_applied", "raw_secret_material_in_report",
    "symlinks_followed",
})
_GUARD_KEYS = frozenset({
    "truth_guard", "truth_guard_runtime", "truth_guard2", "report_sha256",
    "view_sha256", "source_report_sha256",
})


class Attestor40Error(ValueError):
    """Raised when an Attestor 4.0 boundary or evidence contract is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strip_guard(document: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in document.items()
            if str(key) not in _GUARD_KEYS and not str(key).startswith("_")}


def _component(name: str, function, errors: list[dict[str, str]]) -> Any:
    try:
        return function()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        errors.append({"component": name, "error": type(exc).__name__})
        return None


def _validate_component(name: str, value: Any, schema: str,
                        expected_root: Path) -> dict[str, Any]:
    if type(value) is not dict:
        raise Attestor40Error("%s did not return a JSON evidence object" % name)
    if value.get("schema") != schema:
        raise Attestor40Error("%s returned an unsupported evidence schema" % name)
    try:
        encoded = _canonical(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise Attestor40Error("%s returned non-JSON evidence" % name) from exc
    if len(encoded) > MAX_PUBLIC_BYTES:
        raise Attestor40Error("%s exceeded the 16 MiB evidence boundary" % name)
    if value.get("version") != VERSION:
        raise Attestor40Error("%s returned an unsupported evidence version" % name)
    try:
        component_root = Path(str(value.get("root", ""))).expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise Attestor40Error("%s returned an invalid evidence root" % name) from exc
    if not value.get("root") or component_root != expected_root.resolve():
        raise Attestor40Error("%s evidence root does not match the requested target" % name)
    allowed_statuses = ENGINEERING_STATUSES if name == "engineering" else \
        SECURITY_STATUSES if name == "security-fabric" else frozenset()
    if value.get("status") not in allowed_statuses:
        raise Attestor40Error("%s returned an unsupported evidence status" % name)
    coverage = value.get("coverage")
    if type(coverage) is not dict or type(coverage.get("gaps", [])) is not list:
        raise Attestor40Error("%s coverage must be a structured object" % name)
    if value.get("status") == "partial" and not coverage.get("gaps"):
        raise Attestor40Error("%s partial evidence omitted its coverage gaps" % name)
    claimed = value.get("report_sha256")
    body = {key: item for key, item in value.items() if key != "report_sha256"}
    if not isinstance(claimed, str) or len(claimed) != 64 or claimed != _sha(body):
        raise Attestor40Error("%s evidence digest mismatch" % name)
    findings = value.get("findings", [])
    if type(findings) is not list:
        raise Attestor40Error("%s findings must be a list" % name)
    summary = value.get("summary")
    if (type(summary) is not dict or type(summary.get("findings")) is not int or
            isinstance(summary.get("findings"), bool) or
            summary.get("findings") != len(findings)):
        raise Attestor40Error("%s summary count contradicts its findings" % name)
    contracts = [value[key] for key in ("assurance", "analysis", "execution")
                 if type(value.get(key)) is dict]
    if not contracts:
        raise Attestor40Error("%s omitted its static-analysis execution contract" % name)
    for contract in contracts:
        if any(contract.get(key) is not False for key in _FALSE_STATIC_KEYS if key in contract):
            raise Attestor40Error("%s violated its static-analysis execution contract" % name)
    if name == "engineering":
        analysis = value.get("analysis")
        execution = value.get("execution")
        required_analysis = ("target_code_executed", "network_accessed", "filesystem_writes")
        required_execution = ("target_code", "imports", "processes", "network",
                              "filesystem_writes", "compilers", "tests", "patch_apply")
        if (type(analysis) is not dict or type(execution) is not dict or
                any(analysis.get(key) is not False for key in required_analysis) or
                any(execution.get(key) is not False for key in required_execution)):
            raise Attestor40Error("engineering static-analysis contract is incomplete")
    else:
        assurance = value.get("assurance")
        required_false = (
            "target_code_executed", "network_accessed", "network_probing",
            "external_processes_spawned", "dependencies_installed",
            "target_files_written", "automatic_remediation_applied",
            "raw_secret_material_in_report", "symlinks_followed",
        )
        if (type(assurance) is not dict or
                assurance.get("defensive_static_only") is not True or
                assurance.get("root_containment_enforced") is not True or
                any(assurance.get(key) is not False for key in required_false)):
            raise Attestor40Error("security-fabric static assurance contract is incomplete")
    return value


def _relative_path(raw: Any, project: Path) -> str:
    text = str(raw or "workspace")[:2_000]
    try:
        path = Path(text)
        if path.is_absolute():
            return path.resolve().relative_to(project).as_posix()
        if any(part == ".." for part in path.parts):
            return path.name or "workspace"
        return path.as_posix() or "workspace"
    except (OSError, RuntimeError, ValueError):
        return Path(text).name or "workspace"


def _normalise_finding(row: Mapping[str, Any], source: str, project: Path) -> dict[str, Any]:
    severity = str(row.get("severity", "MEDIUM")).upper()
    if severity not in SEVERITY_RANK:
        severity = "MEDIUM"
    try:
        line = max(1, min(2_147_483_647, int(row.get("line", 1))))
    except (TypeError, ValueError):
        line = 1
    rule = str(row.get("rule") or row.get("rule_id") or "%s/finding" % source)[:300]
    path = _relative_path(row.get("path", "workspace"), project)
    message = str(row.get("message") or row.get("title") or
                  "Structured evidence requires review.")[:4_000]
    fix = str(row.get("fix") or row.get("remediation") or "")[:8_000]
    fingerprint = str(row.get("fingerprint") or _sha([
        source, rule, path, line, message,
    ]))[:128]
    output = {
        "rule": rule, "severity": severity, "path": path, "line": line,
        "message": message, "fix": fix, "fingerprint": fingerprint,
        "source": source, "source_engine": source,
    }
    if row.get("id") not in (None, ""):
        output["id"] = str(row["id"])[:256]
        output["component_finding_id"] = str(row["id"])[:256]
    for key, limit in (("cwe", 80), ("owasp", 80), ("category", 120),
                       ("evidence", 4_000), ("confidence_basis", 1_000)):
        if row.get(key) not in (None, "", [], {}):
            output[key] = (str(row[key])[:limit] if key != "evidence" or
                           not isinstance(row[key], (dict, list)) else row[key])
    score = row.get("detector_score", row.get("confidence"))
    if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 1:
        output["detector_score"] = float(score)
        output["confidence"] = float(score)
        output.setdefault("confidence_basis", "detector score; not an empirical probability")
    return output


def _merge_findings(base: Iterable[Any], engineering: Mapping[str, Any] | None,
                    security: Mapping[str, Any] | None, project: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in base:
        if type(item) is dict:
            rows.append(dict(item))
    for source, report in (("engineering-4.0", engineering), ("security-fabric-4.0", security)):
        if report is None:
            continue
        for item in report.get("findings", []):
            if type(item) is dict:
                rows.append(_normalise_finding(item, source, project))
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = str(row.get("fingerprint") or _sha([
            row.get("rule"), row.get("path"), row.get("line"), row.get("message"),
        ]))
        current = unique.get(identity)
        if current is None or SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")).upper(), 3) > \
                SEVERITY_RANK.get(str(current.get("severity", "MEDIUM")).upper(), 3):
            unique[identity] = row
    return sorted(unique.values(), key=lambda row: (
        -SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")).upper(), 3),
        str(row.get("path", "")), int(row.get("line", 1)),
        str(row.get("rule", "")), str(row.get("fingerprint", "")),
    ))[:MAX_FINDINGS]


def _merge_attack_paths(base: Any, security: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    rows = [dict(row) for row in base if type(row) is dict] if type(base) is list else []
    if security:
        threat = security.get("threat_model") if type(security.get("threat_model")) is dict else {}
        candidates = security.get("attack_paths", threat.get("attack_paths", []))
        if type(candidates) is list:
            severity_by_id = {str(row.get("id", "")): str(row.get("severity", "HIGH"))
                              for row in security.get("findings", []) if type(row) is dict}
            for candidate in candidates:
                if type(candidate) is not dict:
                    continue
                row = dict(candidate)
                row.setdefault("severity", severity_by_id.get(str(row.get("finding_id", "")), "HIGH"))
                rows.append(row)
    unique = {str(row.get("id") or _sha(row)): row for row in rows}
    return sorted(unique.values(), key=lambda row: (
        -SEVERITY_RANK.get(str(row.get("severity", "HIGH")).upper(), 4),
        str(row.get("id", "")),
    ))[:MAX_ATTACK_PATHS]


def _empty_compatibility_report(requested: Path) -> dict[str, Any]:
    """Return a bounded base when no 3.5 compatibility component was requested."""
    return {
        "root": str(requested), "status": "no-findings-with-gaps",
        "summary": {"findings": 0, "attack_paths": 0,
                    "verified_improvements": 0, "refused_improvements": 0,
                    "component_errors": 0},
        "findings": [], "top_findings": [], "priorities": [],
        "attack_paths": [], "improvements": [], "errors": [],
        "coverage": {
            "requested_components": [], "completed_components": [],
            "omitted_components": list(COMPATIBILITY_COMPONENTS),
            "gaps": ["Attestor 3.5 compatibility components were not requested"],
            "absence_proven": False,
        },
        "execution": {"target_code_executed": False,
                      "target_code_may_have_executed": False,
                      "selected_tests_executed": False, "changes_applied": False},
        "engines": {},
    }


def _new_component_improvement_plans(findings: Sequence[Mapping[str, Any]],
                                     max_files: int) -> list[dict[str, Any]]:
    """Expose precise review plans without inventing or claiming a verified patch."""
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in findings:
        if row.get("source_engine") not in {"engineering-4.0", "security-fabric-4.0"}:
            continue
        grouped.setdefault(str(row.get("path") or "workspace"), []).append(row)
    ordered = sorted(grouped, key=lambda path: (
        -max(SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")).upper(), 3)
             for row in grouped[path]), path.casefold()))
    plans = []
    for target in ordered[:max(0, max_files)]:
        rows = grouped[target]
        guidance = list(dict.fromkeys(str(row.get("fix") or row.get("message") or "")[:8_000]
                                      for row in rows if row.get("fix") or row.get("message")))
        plans.append({
            "target": target, "status": "plan-only-review-required",
            "accepted": False, "complete": False,
            "reasons": [
                "Attestor 4.0 produced evidence-backed remediation guidance, but no deterministic edit passed the mandatory scan/build/test gates."
            ],
            "suggested_result": guidance, "rules": sorted(set(str(row.get("rule", ""))
                                                               for row in rows if row.get("rule"))),
            "finding_ids": [str(row.get("id") or row.get("fingerprint", ""))
                            for row in rows[:100]],
            "diff": "", "improved_source": "", "improved_source_withheld": False,
            "withheld_reason": "no verified code candidate exists", "resolved_count": 0,
            "remaining_count": len(rows), "verification": {
                "accepted": False, "state": "not-run-no-deterministic-candidate",
                "required_gates": ["scanner", "build", "test"],
            }, "probes": [], "selected_tests": {}, "edits": [], "refusals": [],
        })
    return plans


def transactional_repair(
        root: str | os.PathLike[str],
        change_set: transactional_repair35.ChangeSet,
        hooks: Sequence[transactional_repair35.VerificationHook], *,
        execution_authorization: execution_fabric35.ExecutionAuthorization | None = None,
        apply: bool = False,
        apply_authorization: transactional_repair35.ApplyAuthorization | None = None,
        fabric: execution_fabric35.ExecutionFabric | None = None,
        policy: transactional_repair35.RepairPolicy | None = None) -> dict[str, Any]:
    """Run a proof-gated multi-file repair; verified dry-run is the default."""
    engine = transactional_repair35.TransactionalRepair(
        root, fabric or execution_fabric35.ExecutionFabric(), policy)
    return dataclasses.asdict(engine.repair(
        change_set, hooks, execution_authorization=execution_authorization,
        apply=apply, apply_authorization=apply_authorization))


def maximum(root: str | os.PathLike[str], *, issue: str = "", improve: bool = True,
            max_improvement_files: int = 3, compiler_checks: bool = False,
            use_cache: bool = True, jobs: int = 4,
            test_command: Sequence[str] | None = None, authorize_tests: bool = False,
            apply_improvements: bool = False, backup_root: str = "",
            advisory_snapshot: Mapping[str, Any] | None = None,
            advisory_keys: Mapping[str, bytes] | None = None,
            rule_packs: Sequence[str] = (), rule_pack_key: bytes | None = None,
            require_signed_packs: bool = False,
            memory_baseline: Mapping[str, Any] | None = None,
            components: Sequence[str] = DEFAULT_COMPONENTS,
            calibration_profile: Mapping[str, Any] | None = None,
            calibration_observations: Iterable[Mapping[str, Any]] | None = None,
            git_base: str = "", symbolic_timeout: float = 45.0,
            truth_key: bytes | None = None, truth_key_id: str = "") -> dict[str, Any]:
    """Run Attestor 4.0 and return a redacted, content-addressed evidence report."""
    requested = Path(root).expanduser().resolve()
    if not requested.exists() or not (requested.is_file() or requested.is_dir()):
        raise Attestor40Error("target does not exist or is not a regular file/directory")
    if not isinstance(issue, str) or len(issue.encode("utf-8")) > 64 * 1024:
        raise Attestor40Error("issue must be text no larger than 64 KiB")
    component_set = set(components)
    unknown = component_set - set(DEFAULT_COMPONENTS)
    if unknown:
        raise Attestor40Error("unknown component(s): " + ", ".join(sorted(unknown)))
    compatibility = tuple(name for name in COMPATIBILITY_COMPONENTS if name in component_set)
    if compatibility:
        base_report = attestor35.maximum(
            requested, improve=improve,
            max_improvement_files=max_improvement_files,
            compiler_checks=compiler_checks, use_cache=use_cache, jobs=jobs,
            test_command=test_command, authorize_tests=authorize_tests,
            apply_improvements=apply_improvements, backup_root=backup_root,
            advisory_snapshot=advisory_snapshot, advisory_keys=advisory_keys,
            rule_packs=rule_packs, rule_pack_key=rule_pack_key,
            require_signed_packs=require_signed_packs,
            memory_baseline=memory_baseline, components=compatibility,
            calibration_profile=calibration_profile,
            calibration_observations=calibration_observations,
            git_base=git_base, symbolic_timeout=symbolic_timeout,
            truth_key=truth_key, truth_key_id=truth_key_id)
        base_public = attestor35.safe_public_report(base_report, truth_key=truth_key)
        if base_public.get("status") == "inconsistent":
            raise Attestor40Error("Attestor 3.5 compatibility evidence failed verification")
        report = _strip_guard(base_public)
    else:
        report = _empty_compatibility_report(requested)
    project = requested if requested.is_dir() else requested.parent
    component_errors: list[dict[str, str]] = []
    jobs_map = {}
    if "engineering" in component_set:
        jobs_map["engineering"] = lambda: engineering_engine40.analyze(
            requested, issue=issue)
    if "security-fabric" in component_set:
        jobs_map["security-fabric"] = lambda: security_fabric40.analyze(requested)
    results: dict[str, Any] = {}
    if jobs_map:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(jobs_map), thread_name_prefix="attestor40") as pool:
            pending = {name: pool.submit(_component, name, function, component_errors)
                       for name, function in jobs_map.items()}
            for name, future in pending.items():
                results[name] = future.result()
    engineering = None
    security = None
    if results.get("engineering") is not None:
        try:
            engineering = _validate_component(
                "engineering", results["engineering"], engineering_engine40.SCHEMA,
                requested)
        except Attestor40Error:
            component_errors.append({"component": "engineering", "error": "evidence-invalid"})
    if results.get("security-fabric") is not None:
        try:
            security = _validate_component(
                "security-fabric", results["security-fabric"], security_fabric40.SCHEMA,
                requested)
        except Attestor40Error:
            component_errors.append({"component": "security-fabric", "error": "evidence-invalid"})

    for name, value in (("engineering", engineering), ("security-fabric", security)):
        if value is not None and value.get("status") in {"failed", "error", "invalid", "unavailable"}:
            component_errors.append({"component": name, "error": "analysis-unavailable"})

    previous_errors = report.get("errors") if type(report.get("errors")) is list else []
    all_errors = [*previous_errors, *component_errors]
    findings = _merge_findings(report.get("findings", []), engineering, security, project)
    attack_paths = _merge_attack_paths(report.get("attack_paths", []), security)
    coverage = dict(report.get("coverage", {})) if type(report.get("coverage")) is dict else {}
    gaps = list(coverage.get("gaps", [])) if type(coverage.get("gaps")) is list else []
    completed = set(str(name) for name in coverage.get("completed_components", [])
                    if isinstance(name, str))
    for name, value in (("engineering", engineering), ("security-fabric", security)):
        if name not in component_set:
            continue
        if value is None or value.get("status") in {"failed", "error", "invalid", "unavailable"}:
            gaps.append("%s analysis did not complete with valid evidence" % name)
            continue
        completed.add(name)
        nested_coverage = value.get("coverage", {})
        if type(nested_coverage) is dict:
            nested_gaps = nested_coverage.get("gaps", nested_coverage.get("coverage_gaps", []))
            if type(nested_gaps) is list:
                for item in nested_gaps:
                    if type(item) is dict:
                        detail = item.get("message") or item.get("kind") or "structured coverage gap"
                        location = item.get("path")
                        gaps.append("%s: %s%s" % (
                            name, detail, " (%s)" % location if location else ""))
                    elif item:
                        gaps.append("%s: %s" % (name, item))
    omitted = sorted(set(DEFAULT_COMPONENTS) - component_set)
    if omitted:
        gaps.append("components not run: " + ", ".join(omitted))
    gaps = list(dict.fromkeys(str(item)[:1_000] for item in gaps if item))
    coverage.update({
        "requested_components": sorted(component_set),
        "completed_components": sorted(completed & component_set),
        "omitted_components": omitted, "gaps": gaps, "absence_proven": False,
    })
    severity = {name: sum(str(row.get("severity", "")).upper() == name
                          for row in findings) for name in SEVERITY_RANK}
    improvements = list(report.get("improvements", [])) \
        if type(report.get("improvements")) is list else []
    plans_40 = _new_component_improvement_plans(findings, max_improvement_files) \
        if improve else []
    improvements.extend(plans_40)
    accepted = sum(type(row) is dict and row.get("accepted") is True for row in improvements)
    refused = sum(type(row) is dict and row.get("accepted") is not True for row in improvements)
    summary = dict(report.get("summary", {})) if type(report.get("summary")) is dict else {}
    summary.update({
        "findings": len(findings), "severity": severity,
        "attack_paths": len(attack_paths), "component_errors": len(all_errors),
        "verified_improvements": accepted, "refused_improvements": refused,
        "engineering_findings": len(engineering.get("findings", [])) if engineering else 0,
        "security_fabric_findings": len(security.get("findings", [])) if security else 0,
    })
    priorities = []
    seen_actions = set()
    for row in findings:
        action = row.get("fix") or row.get("message")
        if action and action not in seen_actions:
            seen_actions.add(action)
            priorities.append({"priority": row.get("severity", "MEDIUM"),
                               "fix": action, "rule": row.get("rule", ""),
                               "path": row.get("path", "")})
        if len(priorities) >= 40:
            break
    status = "failed" if all_errors else (
        "improved-with-review" if findings and accepted else
        "action-required" if findings else
        "no-findings-with-gaps" if gaps else "no-findings-from-enabled-checks")
    execution = dict(report.get("execution", {})) if type(report.get("execution")) is dict else {}
    execution.update({
        "host_execution_fallback": False,
        "engineering_static_analysis": "engineering" in jobs_map,
        "security_fabric_static_analysis": "security-fabric" in jobs_map,
    })
    engines = dict(report.get("engines", {})) if type(report.get("engines")) is dict else {}
    engines.update({
        "compatibility_core": "3.5", "engineering": "evidence-planner/4.0",
        "security_fabric": "defensive-static/4.0", "truth_guard": "2.1",
        "response": "evidence-locked/4.0",
    })
    report.update({
        "schema": SCHEMA, "version": VERSION, "status": status,
        "summary": summary, "findings": findings,
        "top_findings": findings[:MAX_TOP_FINDINGS], "priorities": priorities,
        "attack_paths": attack_paths, "errors": all_errors, "coverage": coverage,
        "improvements": improvements, "improvement_plans_40": plans_40,
        "engineering": engineering or {"schema": engineering_engine40.SCHEMA,
                                        "version": VERSION, "root": str(requested),
                                        "status": "not-run", "summary": {"findings": 0},
                                        "coverage": {"gaps": ["component not run"]},
                                        "findings": []},
        "security_fabric": security or {"schema": security_fabric40.SCHEMA,
                                         "version": VERSION, "root": str(requested),
                                         "status": "not-run", "summary": {"findings": 0},
                                         "coverage": {"gaps": ["component not run"]},
                                         "findings": []},
        "verified_delivery_40": {
            "default": "analysis-and-plan-only",
            "stages": ["scope", "evidence", "plan", "candidate", "scan", "build",
                       "test", "review", "separately-authorized-apply", "rollback"],
            "candidate_generation_is_proof": False,
            "mandatory_repair_gates": ["scanner", "build", "test"],
            "dry_run_by_default": True,
            "separate_execution_authorization": True,
            "separate_apply_authorization": True,
        },
        "execution": execution, "engines": engines,
        "assurance_40": [
            "A finding is an evidence-backed detector result, not proof that an exploit is practical.",
            "A detector score is not presented as an empirical probability without independent labels.",
            "Lexical or parser-derived structure is not described as compiler or formal proof.",
            "Static checks never establish that no defects or vulnerabilities exist.",
            "Target execution has no host fallback and requires separate authorization.",
            "File mutation remains dry-run unless separately authorized after all repair gates pass.",
            "Truth Guard 2.1 rebuilds the public evidence ledger before output is trusted.",
        ],
    })
    return truth_guard40.guard_document(report, key=truth_key, key_id=truth_key_id)


def safe_public_report(report: Mapping[str, Any], *,
                       truth_key: bytes | None = None) -> dict[str, Any]:
    verification = truth_guard40.verify_guarded(report, key=truth_key)
    audit = report.get("truth_guard2") if type(report.get("truth_guard2")) is dict else {}
    if verification.get("ok") and audit.get("status") != "refuted":
        return json.loads(json.dumps(report, ensure_ascii=False, allow_nan=False, default=str))
    return truth_guard40.guard_document({
        "schema": SCHEMA, "version": VERSION, "status": "inconsistent",
        "summary": {"findings": 0, "component_errors": 1},
        "findings": [], "attack_paths": [], "improvements": [], "priorities": [],
        "errors": [{"component": "truth-guard2.1",
                    "error": "public-report-integrity-failure"}],
        "coverage": {"gaps": ["the supplied report failed Truth Guard 2.1 integrity or claim-consistency verification"],
                     "absence_proven": False},
        "response": "Result withheld because its evidence ledger did not verify.",
    })


public_report = safe_public_report


def render(report: Mapping[str, Any], style: str = "professional", *,
           truth_key: bytes | None = None) -> str:
    return response40.render_guarded(
        safe_public_report(report, truth_key=truth_key), style, truth_key=truth_key)


def to_sarif(report: Mapping[str, Any], *, truth_key: bytes | None = None) -> dict[str, Any]:
    sarif = attestor3._generic_sarif(safe_public_report(report, truth_key=truth_key))
    driver = sarif["runs"][0]["tool"]["driver"]
    driver["name"] = "Attestor 4.0"
    driver["semanticVersion"] = VERSION
    return sarif


def _write_improvements(report: Mapping[str, Any], output: str | os.PathLike[str], *,
                        truth_key: bytes | None = None) -> list[str]:
    destination_root = Path(output).expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    written = []
    for row in safe_public_report(report, truth_key=truth_key).get("improvements", []):
        if type(row) is not dict or row.get("accepted") is not True or not row.get("improved_source"):
            continue
        relative = Path(str(row.get("target", "")))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise Attestor40Error("improvement output path is unsafe")
        destination = (destination_root / relative).resolve()
        try:
            destination.relative_to(destination_root)
        except ValueError as exc:
            raise Attestor40Error("improvement output escapes destination") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(str(row["improved_source"]), encoding="utf-8", newline="")
        written.append(str(destination))
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--issue", default="")
    parser.add_argument("--no-improve", action="store_true")
    parser.add_argument("--max-improvement-files", type=int, default=3)
    parser.add_argument("--compiler-checks", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--test-command-json")
    parser.add_argument("--apply-improvements", action="store_true")
    parser.add_argument("--backup-root", default="")
    parser.add_argument("--advisory-snapshot")
    parser.add_argument("--advisory-key-file")
    parser.add_argument("--advisory-key-id", default="default")
    parser.add_argument("--rule-pack", action="append", default=[])
    parser.add_argument("--rule-key-file")
    parser.add_argument("--require-signed-packs", action="store_true")
    parser.add_argument("--calibration-data")
    parser.add_argument("--calibration-profile")
    parser.add_argument("--git-base", default="")
    parser.add_argument("--symbolic-timeout", type=float, default=45.0)
    parser.add_argument("--component", action="append", choices=DEFAULT_COMPONENTS)
    parser.add_argument("--truth-key-file")
    parser.add_argument("--truth-key-id", default="")
    parser.add_argument("--improved-out")
    parser.add_argument("--response-style", choices=response40.STYLES, default="professional")
    parser.add_argument("--format", choices=("text", "json", "sarif", "cyclonedx", "spdx", "vex"),
                        default="text")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    if not 0 <= args.max_improvement_files <= 10:
        parser.error("--max-improvement-files must be between 0 and 10")
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be between 1 and 64")
    command = None
    if args.test_command_json:
        try:
            command = json.loads(args.test_command_json)
        except json.JSONDecodeError as exc:
            parser.error("--test-command-json is invalid: %s" % exc)
        if type(command) is not list or not command or any(
                type(item) is not str or not item for item in command):
            parser.error("--test-command-json must be a non-empty argv list")
    if bool(command) != bool(args.run_tests):
        parser.error("selected tests require both --run-tests and --test-command-json")
    if args.apply_improvements and args.no_improve:
        parser.error("--apply-improvements conflicts with --no-improve")
    if args.calibration_data and args.calibration_profile:
        parser.error("choose --calibration-data or --calibration-profile")

    def load_json(path: str) -> Any:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    try:
        observations = load_json(args.calibration_data) if args.calibration_data else None
        profile = load_json(args.calibration_profile) if args.calibration_profile else None
        if observations is not None and type(observations) is not list:
            parser.error("--calibration-data must contain a JSON list")
        snapshot = supply_chain_center.load_advisory_snapshot(args.advisory_snapshot) \
            if args.advisory_snapshot else None
        advisory_keys = {args.advisory_key_id: Path(args.advisory_key_file).read_bytes()} \
            if args.advisory_key_file else None
        rule_key = Path(args.rule_key_file).read_bytes() if args.rule_key_file else None
        truth_key = Path(args.truth_key_file).read_bytes() if args.truth_key_file else None
        if truth_key and not args.truth_key_id:
            parser.error("--truth-key-file requires --truth-key-id")
        report = maximum(
            args.root, issue=args.issue, improve=not args.no_improve,
            max_improvement_files=args.max_improvement_files,
            compiler_checks=args.compiler_checks, use_cache=not args.no_cache,
            jobs=args.jobs, test_command=command, authorize_tests=args.run_tests,
            apply_improvements=args.apply_improvements, backup_root=args.backup_root,
            advisory_snapshot=snapshot, advisory_keys=advisory_keys,
            rule_packs=args.rule_pack, rule_pack_key=rule_key,
            require_signed_packs=args.require_signed_packs,
            components=tuple(args.component or DEFAULT_COMPONENTS),
            calibration_profile=profile, calibration_observations=observations,
            git_base=args.git_base, symbolic_timeout=args.symbolic_timeout,
            truth_key=truth_key, truth_key_id=args.truth_key_id)
        public = safe_public_report(report, truth_key=truth_key)
        if args.format == "json":
            text = truth_guard40.deterministic_json(public)
        elif args.format == "sarif":
            text = json.dumps(to_sarif(report, truth_key=truth_key), indent=2, sort_keys=True)
        elif args.format == "cyclonedx":
            text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get("cyclonedx", {}),
                              indent=2, sort_keys=True)
        elif args.format == "spdx":
            text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get("spdx", {}),
                              indent=2, sort_keys=True)
        elif args.format == "vex":
            text = json.dumps(public.get("supply_chain", {}).get("vex", {}),
                              indent=2, sort_keys=True)
        else:
            text = response40.render_guarded(public, args.response_style, truth_key=truth_key)
        if args.out:
            Path(args.out).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
        else:
            print(text)
        if args.improved_out:
            _write_improvements(report, args.improved_out, truth_key=truth_key)
        return 2 if public.get("status") in {"failed", "inconsistent", "no-evidence"} else (
            1 if public.get("summary", {}).get("findings", 0) or
            public.get("status") == "no-findings-with-gaps" else 0)
    except (OSError, Attestor40Error, PermissionError, RuntimeError, TypeError, ValueError) as exc:
        print("Attestor 4.0 failed safely: %s" % type(exc).__name__, file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
