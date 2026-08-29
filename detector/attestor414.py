#!/usr/bin/env python3
"""Attestor 4.1.4 profile-bound coding and defensive-security orchestrator.

Attestor 4.1.4 keeps the verified 4.1.3 analyzers as compatibility engines and
adds three sealed operating profiles, conservative finding adjudication,
profile-specific report/resource ceilings, and validation opportunities for
findings that are not yet decisively supported.

The public API accepts only the exact stable profile slugs.  Friendly aliases
are a command-line convenience.  All profiles keep the same authorization,
offline-default, source-binding, fail-closed, and Truth Guard requirements.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

import adjudication414
import attestor3
import attestor41
import repair_director41
import response41
import truth_guard41
import variant414


SCHEMA = "attestor-maximum/4.1.4"
VERSION = "4.1.4"
MAX_PUBLIC_BYTES = truth_guard41.MAX_PUBLIC_BYTES
MAX_COVERAGE_GAPS = 4_000
MAX_PRIORITY_ROWS = 60
MAX_RISK_AREAS = 32
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_GUARD_KEYS = frozenset({
    "truth_guard", "truth_guard_runtime", "truth_guard2", "truth_guard3",
    "report_sha256", "view_sha256", "source_report_sha256",
})


class Attestor414Error(ValueError):
    """A 4.1.4 profile, evidence, or public-report boundary failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Attestor414Error("4.1.4 evidence is not deterministic JSON") from exc


def _copy(value: Any) -> Any:
    raw = _canonical(value)
    if len(raw) > MAX_PUBLIC_BYTES:
        raise Attestor414Error("4.1.4 evidence exceeds the public byte boundary")
    return json.loads(raw.decode("utf-8"))


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _text(value: Any, maximum: int) -> str:
    return str(value or "").replace("\x00", "\\0")[:maximum]


def _api_profile(value: str | variant414.VariantProfile) -> variant414.VariantProfile:
    try:
        if type(value) is variant414.VariantProfile:
            return variant414.require_compiled_profile(value)
        return variant414.profile_for_slug(value)
    except variant414.VariantError as exc:
        raise Attestor414Error(
            "variant must be an exact Attestor 4.1.4 slug at the API boundary"
        ) from exc


def _profile_adjudication_limit(
        profile: variant414.VariantProfile,
        finding_count: int,
) -> int:
    # Depth and plan budgets materially tune the amount of secondary evidence
    # review without pretending that repeated deterministic scans are new proof.
    budget = (
        profile.analysis_depth *
        profile.analysis_passes *
        profile.validation_plan_limit
    )
    return min(
        finding_count,
        profile.max_findings,
        adjudication414.MAX_FINDINGS,
        budget,
    )


def _adjudication_findings(
        findings: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    prepared: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for index, raw in enumerate(findings):
        row = _copy(dict(raw))
        binding = row.pop("source_evidence", None)
        fingerprint = row.get("fingerprint")
        finding_id = (
            str(fingerprint)
            if isinstance(fingerprint, str) and _SHA256.fullmatch(fingerprint)
            else _sha({"index": index, "finding": row})
        )
        row["finding_id"] = finding_id
        prepared.append(row)

        # Source binding proves that cited bytes exist; it does not by itself
        # prove the diagnostic.  Only an explicitly proven producer claim can
        # become supporting adjudication evidence.
        if (
            row.get("evidence_state") == "proven" and
            isinstance(binding, Mapping) and
            binding.get("state") == "bound" and
            _SHA256.fullmatch(str(binding.get("evidence_sha256", "")))
        ):
            evidence.append({
                "finding_id": finding_id,
                "stance": "support",
                "kind": "source-bound-proven-producer-claim",
                "rule": _text(row.get("rule"), 300),
                "path": _text(row.get("path"), 2_000),
                "line": int(row.get("line", 1)),
                "producer_evidence_sha256": str(
                    binding["evidence_sha256"]),
            })
    return prepared, evidence


def _risk_inventory(
        report: Mapping[str, Any],
        profile: variant414.VariantProfile,
) -> list[dict[str, Any]]:
    coverage = report.get("coverage")
    completed = set(
        value for value in (
            coverage.get("completed_components", [])
            if isinstance(coverage, Mapping) else []
        )
        if isinstance(value, str)
    )
    selected_actions = set(profile.worker_actions)
    rows = [
        {
            "id": "source-code-correctness",
            "severity": "high",
            "covered": (
                "coding-static" in selected_actions and
                "semantic-correctness" in completed
            ),
            "familiar": True,
            "basis": "bounded static semantic and correctness adapters",
        },
        {
            "id": "dependencies-and-secrets",
            "severity": "critical",
            "covered": (
                "security-static" in selected_actions and
                {"supply-chain-trust", "secret-lifecycle"} <= completed
            ),
            "familiar": True,
            "basis": "offline dependency and secret-lifecycle adapters",
        },
        {
            "id": "attack-surface-and-authentication",
            "severity": "critical",
            "covered": (
                "attack-static-413" in selected_actions and
                "attack-surface" in completed
            ),
            "familiar": True,
            "basis": "bounded static route, auth, and attack-path adapters",
        },
        {
            "id": "cloud-iac-crypto-and-binary-posture",
            "severity": "high",
            "covered": (
                "posture-static-413" in selected_actions and
                "cloud-iac-security" in completed
            ),
            "familiar": True,
            "basis": "offline posture adapters with explicit tool gaps",
        },
        {
            "id": "dynamic-runtime-behavior",
            "severity": "critical",
            "covered": False,
            "familiar": False,
            "basis": (
                "runtime validation is not performed without separate "
                "plan-bound authorization"
            ),
        },
    ]
    return rows[:MAX_RISK_AREAS]


def _build_adjudication(
        report: Mapping[str, Any],
        profile: variant414.VariantProfile,
) -> tuple[dict[str, Any], dict[str, Any]]:
    findings = [
        row for row in report.get("findings", [])
        if type(row) is dict
    ]
    limit = _profile_adjudication_limit(profile, len(findings))
    selected, evidence = _adjudication_findings(findings[:limit])
    risks = _risk_inventory(report, profile)
    limits = adjudication414.Limits(
        max_findings=limit,
        max_evidence=min(len(evidence), adjudication414.MAX_EVIDENCE),
        max_risk_areas=len(risks),
        max_contradictions=min(
            adjudication414.MAX_CONTRADICTIONS, max(0, limit * 2)),
        max_total_input_bytes=min(
            adjudication414.MAX_TOTAL_INPUT_BYTES,
            profile.max_worker_output_bytes,
        ),
        max_report_bytes=min(
            adjudication414.MAX_REPORT_BYTES,
            profile.max_ui_output_bytes,
        ),
    )
    adjudicated = adjudication414.adjudicate(
        selected, evidence=evidence, high_risk_areas=risks, limits=limits)
    valid, errors = adjudication414.verify_report(adjudicated)
    if not valid:
        raise Attestor414Error(
            "4.1.4 adjudication failed replay verification: " +
            ", ".join(errors[:3]))
    scope = {
        "source_findings": len(findings),
        "adjudicated_findings": limit,
        "omitted_findings": len(findings) - limit,
        "selection": "deterministic report order after profile finding boundary",
        "complete_for_selected_input": True,
        "complete_for_public_findings": limit == len(findings),
        "source_binding_alone_counted_as_diagnostic_proof": False,
    }
    scope["report_sha256"] = _sha(scope)
    return adjudicated, scope


def _opportunity_kind(row: Mapping[str, Any]) -> str:
    text = " ".join(
        _text(row.get(key), 2_000).casefold()
        for key in ("rule", "message", "category", "cwe", "fix")
    )
    if any(token in text for token in (
            "race", "deadlock", "concurr", "thread", "async")):
        return "concurrency-stress"
    if any(token in text for token in (
            "dependency", "package", "sbom", "provenance", "secret",
            "cloud", "iac", "crypto", "tls", "binary")):
        return "dependency-security-validation"
    if any(token in text for token in (
            "inject", "taint", "auth", "permission", "access", "xss",
            "csrf", "ssrf", "traversal", "deserialize")):
        return "security-regression"
    if any(token in text for token in (
            "parser", "syntax", "type", "compiler", "memory", "overflow")):
        return "compiler-sanitizer"
    return "property-fuzz-regression"


def _validation_opportunities(
        adjudication: Mapping[str, Any],
        limit: int,
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for item in adjudication.get("findings", []):
        if not isinstance(item, Mapping):
            continue
        classification = item.get("classification")
        if classification not in {
            adjudication414.CONTESTED, adjudication414.INSUFFICIENT,
        }:
            continue
        finding = item.get("original_finding")
        if not isinstance(finding, Mapping):
            continue
        basis = {
            "source": "adjudicated-finding",
            "classification": str(classification),
            "finding_ref": _text(item.get("finding_ref"), 160),
            "rule": _text(finding.get("rule"), 300),
            "path": _text(finding.get("path"), 2_000),
            "line": int(finding.get("line", 1))
            if type(finding.get("line", 1)) is int else 1,
        }
        kind = _opportunity_kind(finding)
        row = {
            **basis,
            "kind": kind,
            "rationale": (
                "Collect independent, authorized evidence for this " +
                str(classification) + " finding before accepting a repair."
            ),
            "authorization_required": True,
            "executed": False,
            "commands_generated": False,
        }
        row["opportunity_id"] = "ov414-" + _sha(row)[:24]
        candidates.append(row)

    risk_lookup = {
        item.get("area_ref"): item.get("original_area")
        for item in adjudication.get("risk_areas", [])
        if isinstance(item, Mapping)
    }
    for item in adjudication.get("uncovered_high_risk_areas", []):
        if not isinstance(item, Mapping):
            continue
        area = risk_lookup.get(item.get("area_ref"))
        if not isinstance(area, Mapping):
            continue
        row = {
            "source": "uncovered-high-risk-area",
            "classification": "uncovered",
            "finding_ref": "",
            "rule": _text(area.get("id"), 300),
            "path": "",
            "line": 0,
            "kind": "high-risk-coverage-review",
            "rationale": (
                "Obtain separate authorization and evidence for this "
                "uncovered high-risk area; no command was generated."
            ),
            "authorization_required": True,
            "executed": False,
            "commands_generated": False,
        }
        row["opportunity_id"] = "ov414-" + _sha(row)[:24]
        candidates.append(row)

    unique = {
        row["opportunity_id"]: row for row in candidates
    }
    ordered = [unique[key] for key in sorted(unique)]
    retained = ordered[:limit]
    body = {
        "schema": "attestor-validation-opportunities/4.1.4",
        "version": VERSION,
        "status": (
            "opportunities-proposed" if retained
            else "none-generated-within-bounded-scope"
        ),
        "summary": {
            "candidates": len(ordered),
            "retained": len(retained),
            "omitted": max(0, len(ordered) - len(retained)),
            "limit": limit,
        },
        "opportunities": retained,
        "execution": {
            "commands_generated": False,
            "subprocesses_started": False,
            "target_code_executed": False,
            "network_accessed": False,
            "target_files_written": False,
            "authorization_consumed": False,
        },
        "limitations": [
            "These are review opportunities, not executable commands.",
            "No opportunity proves that a finding is correct or incorrect.",
            "Execution requires separate plan-bound authorization and eligible tooling.",
        ],
    }
    body["report_sha256"] = _sha(body)
    return body


def _verify_validation_opportunities(
        report: Any,
        adjudication: Mapping[str, Any],
        limit: int,
) -> bool:
    try:
        return (
            type(report) is dict and
            report == _validation_opportunities(adjudication, limit)
        )
    except (Attestor414Error, TypeError, ValueError):
        return False


def _priorities(findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in findings:
        key = (str(row.get("rule", "")), str(row.get("path", "")))
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "priority": _text(row.get("severity"), 20),
            "rule": _text(row.get("rule"), 300),
            "path": _text(row.get("path"), 2_000),
            "fix": _text(row.get("fix"), 1_500),
        })
        if len(result) >= MAX_PRIORITY_ROWS:
            break
    return result


def _without_source_evidence(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    return [
        {
            key: item for key, item in row.items()
            if key != "source_evidence"
        } if isinstance(row, Mapping) else row
        for row in value
    ]


def _apply_profile_finding_boundary(
        report: dict[str, Any],
        profile: variant414.VariantProfile,
) -> None:
    source_findings = [
        row for row in report.get("findings", [])
        if type(row) is dict
    ]
    retained = source_findings[:profile.max_findings]
    omitted = source_findings[profile.max_findings:]
    summary = (
        dict(report.get("summary", {}))
        if isinstance(report.get("summary"), Mapping) else {}
    )
    before = summary.get("findings_before_public_boundary")
    if type(before) is not int or before < len(source_findings):
        before = len(source_findings)
    report["findings"] = retained
    report["top_findings"] = retained[:attestor41.MAX_TOP_FINDINGS]
    report["priorities"] = _priorities(retained)
    summary["findings"] = len(retained)
    summary["findings_truncated"] = max(0, before - len(retained))
    summary["profile_findings_omitted"] = len(omitted)
    summary["severity"] = {
        severity: sum(
            row.get("severity") == severity for row in retained)
        for severity in attestor41.SEVERITY_RANK
    }
    report["summary"] = summary

    coverage = (
        dict(report.get("coverage", {}))
        if isinstance(report.get("coverage"), Mapping) else {}
    )
    gaps = [
        _text(value, 1_000)
        for value in coverage.get("gaps", [])
        if value
    ] if isinstance(coverage.get("gaps"), list) else []
    if omitted:
        gaps.append(
            "%d finding(s) were omitted by the selected %s %d-finding "
            "public boundary" %
            (len(omitted), profile.slug, profile.max_findings)
        )
    boundaries = (
        dict(coverage.get("public_report_boundaries", {}))
        if isinstance(coverage.get("public_report_boundaries"), Mapping)
        else {}
    )
    boundaries.update({
        "findings_limit": profile.max_findings,
        "findings_omitted": max(0, before - len(retained)),
        "selected_profile": profile.slug,
    })
    coverage["public_report_boundaries"] = boundaries
    coverage["gaps"] = list(dict.fromkeys(gaps))[:MAX_COVERAGE_GAPS]
    coverage["complete"] = (
        coverage.get("complete") is True and not coverage["gaps"])
    coverage["absence_proven"] = False
    report["coverage"] = coverage

    body = {
        "schema": "attestor-profile-finding-boundary/4.1.4",
        "version": VERSION,
        "selected_profile": profile.slug,
        "source_findings": len(source_findings),
        "retained_findings": len(retained),
        "profile_omitted_findings": len(omitted),
        "producer_omitted_findings": max(0, before - len(source_findings)),
        "finding_limit": profile.max_findings,
        "source_findings_sha256": _sha(
            _without_source_evidence(source_findings)),
        "retained_findings_sha256": _sha(
            _without_source_evidence(retained)),
        "omitted_findings_sha256": _sha(
            _without_source_evidence(omitted)),
        "omitted_replay_requires_base_report": bool(omitted),
    }
    body["report_sha256"] = _sha(body)
    report["variant_finding_boundary_414"] = body


def _effective_profile_matches(
        config: Mapping[str, Any],
        profile: variant414.VariantProfile,
) -> bool:
    policy = config.get("variant_effective_policy")
    if not isinstance(policy, Mapping):
        return False
    snapshot = policy.get("snapshot")
    worker = policy.get("worker")
    return (
        policy.get("selected_worker_actions") ==
        list(profile.worker_actions) and
        policy.get("selected_legacy_components") ==
        list(profile.legacy_components) and
        policy.get("jobs") == profile.max_concurrency and
        policy.get("symbolic_timeout_seconds") ==
        profile.symbolic_timeout_seconds and
        type(policy.get("max_improvement_files")) is int and
        0 <= policy["max_improvement_files"] <=
        profile.max_improvement_files and
        isinstance(snapshot, Mapping) and
        snapshot.get("max_files") == profile.max_files and
        snapshot.get("max_file_bytes") == profile.max_file_bytes and
        snapshot.get("max_total_bytes") == profile.max_total_bytes and
        isinstance(worker, Mapping) and
        worker.get("max_seconds") == profile.max_worker_seconds and
        worker.get("max_memory_bytes") ==
        profile.max_worker_memory_bytes and
        worker.get("max_output_bytes") ==
        profile.max_worker_output_bytes
    )


def _response_envelope(
        profile: variant414.VariantProfile,
) -> dict[str, Any]:
    """Build response metadata solely from one canonical compiled profile."""
    selected = variant414.require_compiled_profile(profile)
    language = variant414.response_language_metadata(selected)
    return {
        "engine": "evidence-locked/4.1.4",
        "profile_sha256": variant414.profile_identity(selected),
        "language": language,
        "language_sha256": _sha(language),
        "verified_variant_label": True,
        "adjudication_summary_in_response": True,
        "uncertainty_preserved": True,
        "report_scoped_q_and_a": True,
    }


def maximum(
        root: str | os.PathLike[str],
        *,
        variant: str | variant414.VariantProfile =
        variant414.DEFAULT_PROFILE,
        **options: Any,
) -> dict[str, Any]:
    """Return one source-bound Attestor 4.1.4 report.

    ``variant`` must be an exact canonical slug (or the canonical in-process
    singleton).  Profile-controlled jobs, components, worker resources,
    symbolic timeout, and finding limits cannot be overridden by callers.
    """
    profile = _api_profile(variant)
    if "variant_profile" in options:
        raise Attestor414Error(
            "variant_profile is internal; select one exact 4.1.4 variant")
    values = dict(options)
    values.setdefault(
        "max_improvement_files", profile.max_improvement_files)
    values.setdefault("include_candidate_source", True)
    truth_key = values.get("truth_key")
    truth_key_id = values.get("truth_key_id", "")

    base = attestor41.maximum(
        root, variant_profile=profile, **values)
    base_config = base.get("analysis_config")
    base_analyzer = base.get("analyzer")
    base_verification = truth_guard41.verify_guarded(
        base, root=root,
        config=base_config if isinstance(base_config, Mapping) else None,
        analyzer=base_analyzer if isinstance(base_analyzer, Mapping) else None,
        key=truth_key if isinstance(truth_key, bytes) else None,
        require_fresh=True,
    )
    if (
        not base_verification.get("ok") or
        not attestor41._verify_expected_public_projection_layout(base)
    ):
        raise Attestor414Error(
            "the Attestor 4.1.3 compatibility envelope did not replay-verify")

    selection = variant414.selection_report(profile)
    response_language = variant414.response_language_metadata(profile)
    selection_valid, selection_errors = variant414.verify_report(selection)
    if not selection_valid:
        raise Attestor414Error(
            "compiled variant selection did not verify: " +
            ", ".join(selection_errors[:3]))
    if (
        not isinstance(base_config, Mapping) or
        base_config.get("variant_414") != selection or
        not _effective_profile_matches(base_config, profile)
    ):
        raise Attestor414Error(
            "the compatibility orchestrator did not enforce the selected profile")

    base_ledger = base.get("truth_guard3")
    if not isinstance(base_ledger, Mapping):
        raise Attestor414Error("the compatibility Truth Guard ledger is absent")
    report = _copy({
        key: value for key, value in base.items()
        if key not in _GUARD_KEYS
    })
    _apply_profile_finding_boundary(report, profile)
    adjudication, adjudication_scope = _build_adjudication(report, profile)
    opportunities = _validation_opportunities(
        adjudication, profile.validation_plan_limit)

    coverage = (
        dict(report.get("coverage", {}))
        if isinstance(report.get("coverage"), Mapping) else {}
    )
    gaps = list(coverage.get("gaps", [])) \
        if isinstance(coverage.get("gaps"), list) else []
    if adjudication_scope["omitted_findings"]:
        gaps.append(
            "%d retained finding(s) are outside the selected profile's "
            "secondary adjudication boundary" %
            adjudication_scope["omitted_findings"])
    uncovered = adjudication.get(
        "summary", {}).get("uncovered_high_risk_areas", 0)
    if type(uncovered) is int and uncovered:
        gaps.append(
            "%d high-risk area(s) lack demonstrated coverage in 4.1.4 "
            "adjudication" % uncovered)
    completed = {
        value for value in coverage.get("completed_components", [])
        if isinstance(value, str)
    } if isinstance(coverage.get("completed_components"), list) else set()
    completed.update({
        "variant-profile-4.1.4",
        "finding-adjudication-4.1.4",
        "validation-opportunity-planning-4.1.4",
    })
    coverage["completed_components"] = sorted(completed)
    coverage["gaps"] = list(dict.fromkeys(
        _text(value, 1_000) for value in gaps if value
    ))[:MAX_COVERAGE_GAPS]
    coverage["complete"] = (
        coverage.get("complete") is True and not coverage["gaps"])
    coverage["absence_proven"] = False
    report["coverage"] = coverage

    repair = report.get("repair_director_41")
    repair_summary = (
        repair.get("summary", {})
        if isinstance(repair, Mapping) and
        isinstance(repair.get("summary"), Mapping) else {}
    )
    candidate_output = (
        repair.get("selected_candidate_output")
        if isinstance(repair, Mapping) else None
    )
    improvement_delivery = {
        "schema": "attestor-improvement-delivery/4.1.4",
        "version": VERSION,
        "status": _text(
            repair.get("status") if isinstance(repair, Mapping)
            else "unavailable", 120),
        "candidates": int(repair_summary.get("candidates", 0))
        if type(repair_summary.get("candidates", 0)) is int else 0,
        "static_qualified": int(
            repair_summary.get("static_qualified", 0))
        if type(repair_summary.get("static_qualified", 0)) is int else 0,
        "verified": int(repair_summary.get("verified", 0))
        if type(repair_summary.get("verified", 0)) is int else 0,
        "applied": int(repair_summary.get("applied", 0))
        if type(repair_summary.get("applied", 0)) is int else 0,
        "improved_result_in_repair_director": isinstance(
            candidate_output, Mapping),
        "candidate_state": _text(
            candidate_output.get("state")
            if isinstance(candidate_output, Mapping) else "", 120),
        "automatic_apply": False,
        "review_required": True,
        "limitation": (
            "A generated improvement is a review candidate until separately "
            "authorized scanner, build, and test gates verify it."
        ),
    }
    improvement_delivery["report_sha256"] = _sha(improvement_delivery)

    config = dict(report.get("analysis_config", {}))
    analyzer = dict(report.get("analyzer", {}))
    base_identity = {
        "schema": str(base.get("schema", "")),
        "version": str(base.get("version", "")),
        "truth_guard_report_sha256": str(
            base_ledger.get("report_sha256", "")),
        "truth_guard_ledger_sha256": str(
            base_ledger.get("ledger_sha256", "")),
        "analysis_config_sha256": _sha(base_config),
        "analyzer_sha256": _sha(base_analyzer),
        "replay_verified_before_4_1_4_wrapping": True,
    }
    config.update({
        "version": VERSION,
        "variant_414": selection,
        "attestor414_effective_review": {
            "profile_slug": profile.slug,
            "profile_sha256": variant414.profile_identity(profile),
            "depth_budget": profile.analysis_depth,
            "review_pass_budget": profile.analysis_passes,
            "adjudication_finding_limit":
                adjudication_scope["adjudicated_findings"],
            "validation_opportunity_limit":
                profile.validation_plan_limit,
            "public_finding_limit": profile.max_findings,
            "ui_output_limit_bytes": profile.max_ui_output_bytes,
            "response_language": _copy(response_language),
            "depth_and_pass_values_are_policy_budgets_not_formal_proof":
                True,
        },
        "adjudication_report_sha256":
            adjudication["report_sha256"],
        "validation_opportunities_report_sha256":
            opportunities["report_sha256"],
        "base_413_evidence": base_identity,
    })
    analyzer.update({
        "name": "Attestor",
        "version": VERSION,
        "schema": SCHEMA,
        "variant_slug": profile.slug,
        "variant_profile_sha256": variant414.profile_identity(profile),
        "response_language_414": _copy(response_language),
        "response_language_sha256": _sha(response_language),
        "base_analyzer_sha256": _sha(base_analyzer),
    })
    engines = [
        value for value in analyzer.get("engines", [])
        if isinstance(value, str)
    ]
    for engine in (
        "variant-orchestration/4.1.4",
        "finding-adjudication/4.1.4",
        "validation-opportunities/4.1.4",
    ):
        if engine not in engines:
            engines.append(engine)
    analyzer["engines"] = engines

    report.update({
        "schema": SCHEMA,
        "version": VERSION,
        "attestor_version": VERSION,
        "variant_414": selection,
        "adjudication_414": adjudication,
        "adjudication_scope_414": adjudication_scope,
        "validation_opportunities_414": opportunities,
        "improvement_delivery_414": improvement_delivery,
        "analysis_config": config,
        "analyzer": analyzer,
        "response_414": _response_envelope(profile),
        "assurance_414": [
            "The selected profile changes bounded analysis depth, resource ceilings, and response register, never authorization or evidence requirements.",
            "Source binding proves cited bytes exist; it does not automatically prove the diagnostic.",
            "Supported means supported by supplied decisive evidence, not universal correctness or exploitability proof.",
            "Contested findings remain visible and are not automatically dismissed as false positives.",
            "Insufficient findings remain visible and receive bounded validation opportunities.",
            "The improved result is a review candidate until scanner, build, and test gates verify it.",
            "Dynamic execution, network research, and source apply remain separately authorized operations.",
            "Truth Guard 3 re-binds the complete 4.1.4 envelope to the selected source inventory.",
        ],
    })

    if not attestor41._verify_expected_public_projection_layout(report):
        raise Attestor414Error(
            "the 4.1.4 compatibility projection layout failed closed")
    if len(_canonical(report)) > MAX_PUBLIC_BYTES:
        raise Attestor414Error(
            "the unguarded 4.1.4 report exceeds the hard public boundary")
    guarded = truth_guard41.guard_document(
        report, root=root, config=config, analyzer=analyzer,
        key=truth_key if isinstance(truth_key, bytes) else None,
        key_id=str(truth_key_id or ""),
    )
    if len(_canonical(guarded)) > profile.max_ui_output_bytes:
        raise Attestor414Error(
            "the guarded report exceeds the selected profile output boundary")
    valid, errors = verify_report(
        guarded, root=root,
        truth_key=truth_key if isinstance(truth_key, bytes) else None)
    if not valid:
        raise Attestor414Error(
            "the generated 4.1.4 report failed replay verification: " +
            ", ".join(errors[:3]))
    return guarded


def _selected_profile_from_report(
        report: Mapping[str, Any],
) -> variant414.VariantProfile:
    selection = report.get("variant_414")
    valid, errors = variant414.verify_report(selection)
    if not valid or not isinstance(selection, Mapping):
        raise Attestor414Error(
            "variant selection is invalid: " + ", ".join(errors[:3]))
    selected = selection.get("selected_profile")
    return variant414.load_profile_dict(selected)


def verify_report(
        report: Mapping[str, Any],
        *,
        root: str | os.PathLike[str] | None = None,
        truth_key: bytes | None = None,
) -> tuple[bool, list[str]]:
    """Replay the 4.1.4 variant, adjudication, projection, and Truth Guard chain."""
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["report must be an exact object"]
    try:
        encoded = _canonical(report)
    except Attestor414Error:
        return False, ["report is not deterministic bounded JSON"]
    if len(encoded) > MAX_PUBLIC_BYTES:
        errors.append("report exceeds the hard public boundary")
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        errors.append("report schema or version is invalid")
    try:
        profile = _selected_profile_from_report(report)
    except (Attestor414Error, variant414.VariantError):
        profile = None
        errors.append("variant selection did not verify")

    config = report.get("analysis_config")
    analyzer = report.get("analyzer")
    if not isinstance(config, Mapping) or not isinstance(analyzer, Mapping):
        errors.append("analysis configuration or analyzer identity is absent")
    elif profile is not None:
        selection = report.get("variant_414")
        response_language = variant414.response_language_metadata(profile)
        if (
            config.get("version") != VERSION or
            config.get("variant_414") != selection or
            not _effective_profile_matches(config, profile) or
            analyzer.get("version") != VERSION or
            analyzer.get("schema") != SCHEMA or
            analyzer.get("variant_slug") != profile.slug or
            analyzer.get("variant_profile_sha256") !=
            variant414.profile_identity(profile) or
            analyzer.get("response_language_414") != response_language or
            analyzer.get("response_language_sha256") !=
            _sha(response_language)
        ):
            errors.append(
                "selected variant is not bound to effective configuration")

    findings = report.get("findings")
    if type(findings) is not list or any(type(row) is not dict for row in findings):
        errors.append("public findings are invalid")
        findings = []
    if profile is not None:
        if len(findings) > profile.max_findings:
            errors.append("public findings exceed the selected profile boundary")
        if len(encoded) > profile.max_ui_output_bytes:
            errors.append("report exceeds the selected profile output boundary")

    boundary = report.get("variant_finding_boundary_414")
    if profile is not None:
        if (
            type(boundary) is not dict or
            boundary.get("schema") !=
            "attestor-profile-finding-boundary/4.1.4" or
            boundary.get("version") != VERSION or
            boundary.get("selected_profile") != profile.slug or
            boundary.get("retained_findings") != len(findings) or
            boundary.get("finding_limit") != profile.max_findings or
            not _SHA256.fullmatch(
                str(boundary.get("source_findings_sha256", ""))) or
            boundary.get("retained_findings_sha256") != _sha(
                _without_source_evidence(findings)) or
            not _SHA256.fullmatch(
                str(boundary.get("omitted_findings_sha256", ""))) or
            boundary.get("report_sha256") != _sha({
                key: value for key, value in boundary.items()
                if key != "report_sha256"
            })
        ):
            errors.append("profile finding boundary is invalid")
        else:
            source_count = boundary.get("source_findings")
            retained_count = boundary.get("retained_findings")
            profile_omitted = boundary.get("profile_omitted_findings")
            producer_omitted = boundary.get("producer_omitted_findings")
            if (
                type(source_count) is not int or
                type(retained_count) is not int or
                type(profile_omitted) is not int or
                type(producer_omitted) is not int or
                min(source_count, profile.max_findings) !=
                retained_count or
                max(0, source_count - profile.max_findings) !=
                profile_omitted or
                any(value < 0 for value in (
                    source_count, retained_count,
                    profile_omitted, producer_omitted)) or
                boundary.get("omitted_replay_requires_base_report") !=
                bool(profile_omitted) or
                (not profile_omitted and
                 boundary.get("source_findings_sha256") !=
                 boundary.get("retained_findings_sha256")) or
                (not profile_omitted and
                 boundary.get("omitted_findings_sha256") != _sha([]))
            ):
                errors.append("profile finding boundary arithmetic is invalid")

    adjudicated = report.get("adjudication_414")
    adjudication_valid, adjudication_errors = \
        adjudication414.verify_report(adjudicated)
    if not adjudication_valid:
        errors.extend(
            "adjudication: " + value
            for value in adjudication_errors[:4])
    scope = report.get("adjudication_scope_414")
    if profile is not None and type(scope) is dict:
        expected_limit = _profile_adjudication_limit(
            profile, len(findings))
        if (
            scope.get("source_findings") != len(findings) or
            scope.get("adjudicated_findings") != expected_limit or
            scope.get("omitted_findings") !=
            len(findings) - expected_limit or
            scope.get("complete_for_public_findings") !=
            (expected_limit == len(findings)) or
            scope.get("source_binding_alone_counted_as_diagnostic_proof")
            is not False or
            scope.get("report_sha256") != _sha({
                key: value for key, value in scope.items()
                if key != "report_sha256"
            })
        ):
            errors.append("adjudication scope is invalid")
        if (
            isinstance(adjudicated, Mapping) and
            adjudicated.get("summary", {}).get("findings") !=
            expected_limit
        ):
            errors.append("adjudication count does not match its scope")
        if isinstance(adjudicated, Mapping):
            try:
                expected_findings, expected_evidence = \
                    _adjudication_findings(findings[:expected_limit])
                actual_findings = [
                    row.get("original_finding")
                    for row in adjudicated.get("findings", [])
                    if isinstance(row, Mapping)
                ]
                if sorted(
                    _canonical(row) for row in actual_findings
                ) != sorted(
                    _canonical(row) for row in expected_findings
                ):
                    errors.append(
                        "adjudication findings do not match public findings")

                def evidence_shape(row: Mapping[str, Any]) -> dict[str, Any]:
                    return {
                        key: value for key, value in row.items()
                        if key != "producer_evidence_sha256"
                    }

                actual_evidence = [
                    row.get("original_evidence")
                    for row in adjudicated.get("evidence", [])
                    if isinstance(row, Mapping) and
                    isinstance(row.get("original_evidence"), Mapping)
                ]
                if sorted(
                    _canonical(evidence_shape(row))
                    for row in actual_evidence
                ) != sorted(
                    _canonical(evidence_shape(row))
                    for row in expected_evidence
                ) or any(
                    not _SHA256.fullmatch(str(
                        row.get("producer_evidence_sha256", "")))
                    for row in actual_evidence
                ):
                    errors.append(
                        "adjudication evidence does not match proven public claims")

                expected_risks = _risk_inventory(report, profile)
                actual_risks = [
                    row.get("original_area")
                    for row in adjudicated.get("risk_areas", [])
                    if isinstance(row, Mapping)
                ]
                if sorted(
                    _canonical(row) for row in actual_risks
                ) != sorted(
                    _canonical(row) for row in expected_risks
                ):
                    errors.append(
                        "adjudication risk inventory is stale")
            except (Attestor414Error, TypeError, ValueError):
                errors.append(
                    "adjudication inputs failed deterministic replay")
    else:
        errors.append("adjudication scope is absent")

    opportunities = report.get("validation_opportunities_414")
    if (
        profile is None or not isinstance(adjudicated, Mapping) or
        not _verify_validation_opportunities(
            opportunities, adjudicated,
            profile.validation_plan_limit)
    ):
        errors.append("validation opportunities failed deterministic replay")

    summary = report.get("summary")
    if (
        not isinstance(summary, Mapping) or
        summary.get("findings") != len(findings)
    ):
        errors.append("summary finding count is stale")
    if _without_source_evidence(report.get("top_findings")) != \
            _without_source_evidence(
                findings[:attestor41.MAX_TOP_FINDINGS]):
        errors.append("top finding projection is stale")
    if report.get("priorities") != _priorities(findings):
        errors.append("priority projection is stale")

    improvement = report.get("improvement_delivery_414")
    repair = report.get("repair_director_41")
    repair_summary = (
        repair.get("summary", {})
        if isinstance(repair, Mapping) and
        isinstance(repair.get("summary"), Mapping) else {}
    )
    candidate_output = (
        repair.get("selected_candidate_output")
        if isinstance(repair, Mapping) else None
    )
    repair_counts = {
        key: repair_summary.get(key, 0)
        for key in ("candidates", "static_qualified", "verified", "applied")
    }
    repair_counts_valid = all(
        type(value) is int and value >= 0
        for value in repair_counts.values()
    )
    if (
        type(improvement) is not dict or
        not repair_counts_valid or
        improvement.get("schema") !=
        "attestor-improvement-delivery/4.1.4" or
        improvement.get("version") != VERSION or
        improvement.get("automatic_apply") is not False or
        improvement.get("review_required") is not True or
        improvement.get("status") != _text(
            repair.get("status") if isinstance(repair, Mapping)
            else "unavailable", 120) or
        improvement.get("candidates") !=
        repair_counts["candidates"] or
        improvement.get("static_qualified") !=
        repair_counts["static_qualified"] or
        improvement.get("verified") !=
        repair_counts["verified"] or
        improvement.get("applied") !=
        repair_counts["applied"] or
        improvement.get("improved_result_in_repair_director") !=
        isinstance(candidate_output, Mapping) or
        improvement.get("report_sha256") != _sha({
            key: value for key, value in improvement.items()
            if key != "report_sha256"
        })
    ):
        errors.append("improvement delivery is invalid")

    if isinstance(config, Mapping) and profile is not None:
        effective_review = config.get("attestor414_effective_review")
        base_identity = config.get("base_413_evidence")
        response_language = variant414.response_language_metadata(profile)
        if (
            not isinstance(effective_review, Mapping) or
            effective_review.get("profile_slug") != profile.slug or
            effective_review.get("profile_sha256") !=
            variant414.profile_identity(profile) or
            effective_review.get("depth_budget") !=
            profile.analysis_depth or
            effective_review.get("review_pass_budget") !=
            profile.analysis_passes or
            effective_review.get("adjudication_finding_limit") !=
            _profile_adjudication_limit(profile, len(findings)) or
            effective_review.get("validation_opportunity_limit") !=
            profile.validation_plan_limit or
            effective_review.get("public_finding_limit") !=
            profile.max_findings or
            effective_review.get("ui_output_limit_bytes") !=
            profile.max_ui_output_bytes or
            effective_review.get("response_language") !=
            response_language or
            effective_review.get(
                "depth_and_pass_values_are_policy_budgets_not_formal_proof")
            is not True or
            config.get("adjudication_report_sha256") !=
            (adjudicated.get("report_sha256")
             if isinstance(adjudicated, Mapping) else None) or
            config.get("validation_opportunities_report_sha256") !=
            (opportunities.get("report_sha256")
             if isinstance(opportunities, Mapping) else None)
        ):
            errors.append("effective 4.1.4 review policy is invalid")
        if (
            not isinstance(base_identity, Mapping) or
            base_identity.get("schema") != attestor41.SCHEMA or
            base_identity.get("version") != attestor41.VERSION or
            base_identity.get(
                "replay_verified_before_4_1_4_wrapping") is not True or
            any(not _SHA256.fullmatch(str(base_identity.get(key, "")))
                for key in (
                    "truth_guard_report_sha256",
                    "truth_guard_ledger_sha256",
                    "analysis_config_sha256",
                    "analyzer_sha256"))
        ):
            errors.append("base 4.1.3 evidence identity is invalid")

        if report.get("response_414") != _response_envelope(profile):
            errors.append("profile-bound response language is invalid")

    if not attestor41._verify_expected_public_projection_layout(report):
        errors.append("compatibility public projection layout is invalid")
    verification = truth_guard41.verify_guarded(
        report, root=root,
        config=config if isinstance(config, Mapping) else None,
        analyzer=analyzer if isinstance(analyzer, Mapping) else None,
        key=truth_key, require_fresh=True,
    )
    if not verification.get("ok"):
        errors.extend(
            "truth-guard3: " + value
            for value in verification.get("errors", [])[:4])
    return not errors, list(dict.fromkeys(errors))


def _fallback_report(
        selected: Any,
) -> dict[str, Any]:
    try:
        fallback_root = (
            Path(selected).expanduser().resolve(strict=True)
            if selected else Path.cwd().resolve()
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        fallback_root = Path.cwd().resolve()
    config = {
        "version": VERSION,
        "variant_status": "withheld-unverified",
    }
    analyzer = {
        "name": "Attestor",
        "version": VERSION,
        "schema": SCHEMA,
        "variant_status": "withheld-unverified",
    }
    body = {
        "schema": SCHEMA,
        "version": VERSION,
        "attestor_version": VERSION,
        "root": str(fallback_root),
        "status": "inconsistent",
        "summary": {"findings": 0, "component_errors": 1},
        "findings": [],
        "top_findings": [],
        "attack_paths": [],
        "priorities": [],
        "errors": [{
            "component": "attestor-4.1.4-verifier",
            "error": "public-report-integrity-profile-or-freshness-failure",
        }],
        "coverage": {
            "complete": False,
            "absence_proven": False,
            "gaps": [
                "the supplied 4.1.4 report or variant identity did not verify",
            ],
        },
        "analysis_config": config,
        "analyzer": analyzer,
        "variant_status_414": "withheld-unverified",
        "response": (
            "Result and variant label withheld because source-bound "
            "evidence did not verify."
        ),
    }
    return truth_guard41.guard_document(
        body, root=fallback_root, config=config, analyzer=analyzer)


def safe_public_report(
        report: Mapping[str, Any],
        *,
        root: str | os.PathLike[str] | None = None,
        truth_key: bytes | None = None,
) -> dict[str, Any]:
    selected = (
        root if root is not None else
        report.get("root") if isinstance(report, Mapping) else None
    )
    valid, _errors = verify_report(
        report, root=selected, truth_key=truth_key)
    if valid:
        return _copy(report)
    return _fallback_report(selected)


public_report = safe_public_report


def render(
        report: Mapping[str, Any],
        style: str = "professional",
        *,
        root: str | os.PathLike[str] | None = None,
        truth_key: bytes | None = None,
) -> str:
    selected = root if root is not None else report.get("root")
    public = safe_public_report(
        report, root=selected, truth_key=truth_key)
    try:
        profile = _selected_profile_from_report(public)
    except (Attestor414Error, variant414.VariantError):
        profile = None
    legacy = response41.render_guarded(
        public, style, root=selected, truth_key=truth_key)
    legacy = legacy.replace("Attestor 4.1.3", "Attestor 4.1.4").replace(
        "ATTESTOR 4.1.3", "ATTESTOR 4.1.4")
    if profile is None:
        return (
            "Attestor 4.1.4 — variant identity withheld\n"
            "========================================\n\n" + legacy
        )
    adjudication = public.get("adjudication_414", {})
    adjudication_summary = (
        adjudication.get("summary", {})
        if isinstance(adjudication, Mapping) else {}
    )
    improvement = public.get("improvement_delivery_414", {})
    response_language = variant414.response_language_metadata(profile)
    header = [
        "Attestor 4.1.4 — %s" % profile.display_name,
        "=" * (15 + len(profile.display_name)),
        "",
        "Profile: `%s`; mode: %s; identity: `%s`." % (
            profile.slug,
            profile.mode,
            variant414.profile_identity(profile),
        ),
    ]
    if response_language["tier"] == variant414.RESPONSE_LANGUAGE_C3:
        header.extend([
            "Response language: %s." % response_language["label"],
            (
                "Register: evidence-dense technical English; epistemic "
                "qualifiers and uncertainty remain mandatory."
            ),
        ])
    header.extend([
        (
            "Adjudication: %(supported)d supported, %(contested)d contested, "
            "%(insufficient)d insufficient within the bounded secondary scope."
        ) % {
            "supported": int(adjudication_summary.get("supported", 0)),
            "contested": int(adjudication_summary.get("contested", 0)),
            "insufficient": int(adjudication_summary.get("insufficient", 0)),
        },
        "Improved result: %s; automatic apply: disabled." % (
            "review candidate available"
            if isinstance(improvement, Mapping) and
            improvement.get("improved_result_in_repair_director") is True
            else "no bounded candidate was produced"
        ),
        "",
    ])
    return "\n".join(header) + legacy


def answer(
        report: Mapping[str, Any],
        question: str,
        *,
        root: str | os.PathLike[str] | None = None,
        truth_key: bytes | None = None,
) -> dict[str, Any]:
    selected = root if root is not None else report.get("root")
    public = safe_public_report(
        report, root=selected, truth_key=truth_key)
    result = response41.answer_question(
        public, question, root=selected, truth_key=truth_key)
    try:
        profile = _selected_profile_from_report(public)
    except (Attestor414Error, variant414.VariantError):
        result["variant"] = {
            "verified": False,
            "slug": "",
            "display_name": "",
            "profile_sha256": "",
        }
        result["response_language"] = {
            "verified": False,
            "tier": "",
            "label": "",
            "official_cefr_claim": False,
            "profile_sha256": "",
        }
    else:
        response_language = variant414.response_language_metadata(profile)
        result["variant"] = {
            "verified": True,
            "slug": profile.slug,
            "display_name": profile.display_name,
            "profile_sha256": variant414.profile_identity(profile),
        }
        result["response_language"] = {
            **response_language,
            "verified": True,
            "profile_sha256": variant414.profile_identity(profile),
        }
    adjudication = public.get("adjudication_414")
    result["adjudication"] = (
        _copy(adjudication.get("summary", {}))
        if isinstance(adjudication, Mapping) else {}
    )
    return result


def to_sarif(
        report: Mapping[str, Any],
        *,
        root: str | os.PathLike[str] | None = None,
        truth_key: bytes | None = None,
) -> dict[str, Any]:
    public = safe_public_report(
        report, root=root, truth_key=truth_key)
    sarif = attestor3._generic_sarif(public)
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    driver["name"] = "Attestor 4.1.4"
    driver["semanticVersion"] = VERSION
    try:
        profile = _selected_profile_from_report(public)
    except (Attestor414Error, variant414.VariantError):
        run["properties"] = {"attestorVariantVerified": False}
        return sarif

    selection = public["variant_414"]
    response_language = variant414.response_language_metadata(profile)
    adjudication = public.get("adjudication_414", {})
    run["automationDetails"] = {
        "id": "Attestor/4.1.4/%s/%s" % (
            profile.slug, variant414.profile_identity(profile)[:16])
    }
    run["properties"] = {
        "attestorVariantVerified": True,
        "attestorVariantSlug": profile.slug,
        "attestorVariantDisplayName": profile.display_name,
        "attestorVariantMode": profile.mode,
        "attestorVariantProfileSha256":
            variant414.profile_identity(profile),
        "attestorResponseLanguageTier": response_language["tier"],
        "attestorResponseLanguageLabel": response_language["label"],
        "attestorResponseLanguageAttestorSpecific":
            response_language["attestor_specific_tier"],
        "attestorResponseLanguageOfficialCefrClaim": False,
        "attestorVariantSelectionSha256":
            selection["report_sha256"],
        "attestorAdjudicationSha256": (
            adjudication.get("report_sha256", "")
            if isinstance(adjudication, Mapping) else ""
        ),
    }
    classifications: dict[str, str] = {}
    if isinstance(adjudication, Mapping):
        for item in adjudication.get("findings", []):
            original = (
                item.get("original_finding")
                if isinstance(item, Mapping) else None
            )
            if (
                isinstance(original, Mapping) and
                isinstance(original.get("fingerprint"), str)
            ):
                classifications[original["fingerprint"]] = str(
                    item.get("classification", ""))
    for result in run.get("results", []):
        fingerprint = result.get(
            "partialFingerprints", {}).get(
                "attestorFindingFingerprint/v1", "")
        result.setdefault("properties", {})[
            "attestorAdjudicationClassification"
        ] = classifications.get(fingerprint, "outside-adjudication-scope")
    return sarif


def _cli_failure_output(error: BaseException, output_format: str) -> str:
    """Render a bounded failure without exposing a Python traceback."""
    error_type = type(error).__name__[:120]
    if output_format == "sarif":
        return json.dumps({
            "$schema": (
                "https://json.schemastore.org/sarif-2.1.0.json"),
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Attestor 4.1.4",
                    "semanticVersion": VERSION,
                    "rules": [],
                }},
                "invocations": [{
                    "executionSuccessful": False,
                    "toolExecutionNotifications": [{
                        "descriptor": {"id": "ATTESTOR414-FAILED-CLOSED"},
                        "level": "error",
                        "message": {"text": (
                            "Attestor 4.1.4 analysis failed safely at a bounded "
                            "evidence boundary (%s)." % error_type)},
                    }],
                }],
                "results": [],
            }],
        }, indent=2, sort_keys=True, ensure_ascii=False)
    if output_format == "json":
        return json.dumps({
            "schema": "attestor-cli-failure/4.1.4",
            "version": VERSION,
            "status": "failed",
            "result_available": False,
            "findings": [],
            "summary": {"findings": 0, "component_errors": 1},
            "coverage": {
                "complete": False,
                "absence_proven": False,
                "gaps": [
                    "analysis failed closed before a verified result was "
                    "available"
                ],
            },
            "error": {
                "code": "ATTESTOR414-FAILED-CLOSED",
                "type": error_type,
                "details_disclosed": False,
                "traceback_disclosed": False,
            },
        }, indent=2, sort_keys=True, ensure_ascii=False)
    return "Attestor 4.1.4 failed safely: %s" % error_type


def _emit_cli_failure(error: BaseException, *, output_format: str,
                      out: str | None) -> int:
    output = _cli_failure_output(error, output_format)
    if out:
        try:
            Path(out).write_text(
                output + ("" if output.endswith("\n") else "\n"),
                encoding="utf-8", newline="")
            return 2
        except (OSError, PermissionError, ValueError) as write_error:
            print(
                "Attestor 4.1.4 failure report could not be written: %s" %
                type(write_error).__name__,
                file=os.sys.stderr,
            )
    print(output, file=(os.sys.stderr if output_format == "text" else None))
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--variant", default=variant414.DEFAULT_PROFILE.slug,
        help=(
            "profile slug or CLI alias: Cockroach Janta Party, "
            "South Park, or Gruppe Sechs"
        ),
    )
    parser.add_argument("--issue", default="")
    parser.add_argument("--no-improve", action="store_true")
    parser.add_argument("--compiler-checks", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--semantic-rule-pack", action="append", default=[])
    parser.add_argument("--legacy-rule-pack", action="append", default=[])
    parser.add_argument("--require-signed-packs", action="store_true")
    parser.add_argument("--rule-key-file")
    parser.add_argument("--staged-diff-file")
    parser.add_argument("--history-export-file")
    parser.add_argument("--candidate-json", action="append", default=[])
    parser.add_argument("--truth-key-file")
    parser.add_argument("--truth-key-id", default="")
    parser.add_argument(
        "--response-style", choices=response41.STYLES,
        default="professional")
    parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    try:
        profile = variant414.parse_profile(args.variant)
    except variant414.VariantError as exc:
        parser.error(str(exc))

    def read_bounded(path: str | None, maximum: int) -> str:
        if not path:
            return ""
        raw = Path(path).read_bytes()
        if len(raw) > maximum:
            parser.error("evidence file exceeds its byte boundary")
        return raw.decode("utf-8", "strict")

    try:
        truth_key = (
            Path(args.truth_key_file).read_bytes()
            if args.truth_key_file else None
        )
        rule_key = (
            Path(args.rule_key_file).read_bytes()
            if args.rule_key_file else None
        )
        candidates = [
            repair_director41.candidate_from_provider_text(
                read_bounded(value, repair_director41.MAX_PROVIDER_BYTES),
                args.root,
            )
            for value in args.candidate_json
        ]
        report = maximum(
            args.root,
            variant=profile,
            issue=args.issue,
            improve=not args.no_improve,
            compiler_checks=args.compiler_checks,
            use_cache=not args.no_cache,
            legacy_rule_packs=args.legacy_rule_pack,
            semantic_rule_packs=args.semantic_rule_pack,
            rule_pack_key=rule_key,
            require_signed_packs=args.require_signed_packs,
            staged_diff=read_bounded(
                args.staged_diff_file, 128 * 1024),
            history_export=read_bounded(
                args.history_export_file, 128 * 1024),
            repair_candidates=candidates,
            truth_key=truth_key,
            truth_key_id=args.truth_key_id,
        )
        public = safe_public_report(
            report, root=args.root, truth_key=truth_key)
        if args.format == "json":
            output = json.dumps(
                public, indent=2, sort_keys=True, ensure_ascii=False)
        elif args.format == "sarif":
            output = json.dumps(
                to_sarif(
                    public, root=args.root, truth_key=truth_key),
                indent=2, sort_keys=True, ensure_ascii=False,
            )
        else:
            output = render(
                public, args.response_style,
                root=args.root, truth_key=truth_key)
        if args.out:
            Path(args.out).write_text(
                output + ("" if output.endswith("\n") else "\n"),
                encoding="utf-8", newline="")
        else:
            print(output)
        return (
            2 if public.get("status") in {"failed", "inconsistent"}
            else 1 if public.get("findings") else 0
        )
    except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
        return _emit_cli_failure(
            exc, output_format=args.format, out=args.out)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "SCHEMA",
    "VERSION",
    "Attestor414Error",
    "maximum",
    "verify_report",
    "safe_public_report",
    "public_report",
    "render",
    "answer",
    "to_sarif",
    "main",
]
