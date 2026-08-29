#!/usr/bin/env python3
"""Attestor 3.0 maximum analysis, improvement, and assurance orchestrator.

The default run combines correctness/security scanning, whole-program semantic
analysis, cybersecurity posture, supply-chain evidence, attack paths,
privacy-preserving repository memory, and verified deterministic improvements.
It never applies a change or executes target code without a separate explicit
authorization.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

import repository_memory
import response_engine
import rule_sdk
import runtime_lab
import scanengine
import secret_guard
import security_posture
import semantic_engine
import supply_chain_center
import truth_guard
import verified_remediation


SCHEMA = "attestor-maximum/3.0"
VERSION = "3.0.0"
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
DEFAULT_COMPONENTS = ("scan", "semantic", "security", "supply-chain")
MAX_ATTACK_PATHS = 100
MAX_TOP_FINDINGS = 100
MAX_CUSTOM_RULES = 5_000
MAX_CUSTOM_FINDINGS = 5_000
MAX_TRUTH_FINDING_CLAIMS = 180
MAX_TRUTH_DOCUMENT_NODES = 500_000
MAX_TRUTH_DOCUMENT_BYTES = 16 * 1024 * 1024


class Attestor3Error(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _fingerprint(*values: Any) -> str:
    return hashlib.sha256("\0".join(str(value) for value in values).encode(
        "utf-8", "replace")).hexdigest()


def _truth_claims(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Create bounded, machine-verifiable claims for Attestor's public report."""
    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []
    claims: list[dict[str, Any]] = [
        {"kind": "value", "text": "report status is " + str(report.get("status", "unknown")),
         "evidence_path": "/status", "expected": report.get("status")},
        {"kind": "count", "text": "%d findings from enabled checks" % len(findings),
         "collection_path": "/findings", "expected": len(findings)},
    ]
    for row in findings[:MAX_TRUTH_FINDING_CLAIMS]:
        if not isinstance(row, Mapping):
            continue
        claims.append({
            "kind": "finding",
            "text": "%s at %s:%s" % (
                row.get("rule", "finding"), row.get("path", "workspace"), row.get("line", 1)),
            "rule": row.get("rule", ""), "path": row.get("path", ""),
            "line": row.get("line", 1),
        })
    for row in report.get("improvements", [])[:32]:
        if not isinstance(row, Mapping):
            continue
        claims.append({
            "kind": "improvement",
            "text": "%s improvement for %s" % (
                "verified" if row.get("accepted") is True else "refused",
                row.get("target", "source")),
            "target": row.get("target", ""),
            "expected": "verified" if row.get("accepted") is True else "refused",
        })
    return claims


def _truth_root(report: Mapping[str, Any]) -> Path | None:
    raw = report.get("root")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        target = Path(raw).expanduser().resolve()
    except OSError:
        return None
    return target if target.is_dir() else target.parent


def _truth_document_node_count(
        value: Any, *, maximum: int = MAX_TRUTH_DOCUMENT_NODES,
        boundary: str = "Attestor 3.0 evidence") -> int:
    """Validate a full JSON report before any recursive projection/redaction."""
    if (isinstance(maximum, bool) or not isinstance(maximum, int) or
            maximum < 1):
        raise Attestor3Error("Truth Guard node boundary is invalid")
    seen: set[int] = set()
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > maximum:
            raise Attestor3Error(
                "%s exceeds the %d-node hard boundary" %
                (boundary, maximum))
        if depth > truth_guard.MAX_DEPTH:
            raise Attestor3Error(
                "%s exceeds the %d-level nesting boundary" %
                (boundary, truth_guard.MAX_DEPTH))
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise Attestor3Error(
                    "%s contains a non-finite number" % boundary)
            return
        if type(item) not in {dict, list, tuple}:
            raise Attestor3Error("%s contains a non-JSON value" % boundary)
        marker = id(item)
        if marker in seen:
            raise Attestor3Error("%s contains a cyclic value" % boundary)
        seen.add(marker)
        if type(item) is dict:
            if any(not isinstance(key, str) for key in item):
                raise Attestor3Error(
                    "%s contains a non-string object key" % boundary)
            for key in sorted(item):
                visit(item[key], depth + 1)
        else:
            for child in item:
                visit(child, depth + 1)
        seen.remove(marker)

    visit(value, 0)
    return nodes


def _truth_finding_projection(row: Any) -> Any:
    if type(row) is not dict:
        return None
    projected: dict[str, Any] = {}
    for key in ("rule", "rule_id", "ruleId", "path", "line",
                "severity", "fingerprint"):
        value = row.get(key)
        if key in row and (
                value is None or isinstance(value, (str, bool, int, float))):
            projected[key] = value
    return projected


def _truth_artifact_projection(row: Any) -> Any:
    if type(row) is not dict:
        return None
    projected: dict[str, Any] = {}
    for key in ("id", "name", "evidence_level", "status", "observed",
                "path", "sha256", "verification"):
        if key in row:
            projected[key] = row[key]
    return projected


def _truth_marker_list(value: Any) -> list[None]:
    return [None] * len(value) if type(value) in {list, tuple} else []


def _truth_validation_projection(
        public: Mapping[str, Any], source_nodes: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build the exact-field view consumed by the 100k-node base validator.

    The source report remains intact.  The projection preserves every finding
    identity and every complete improvement proof, plus the collections used
    by Truth Guard's numeric and coverage derivations.  High-cardinality graph
    details remain bound by the source digest but are not duplicated into the
    older independent index.
    """
    payload = {
        key: value for key, value in public.items()
        if key != "report_sha256" and not key.startswith("_")
    }
    source_sha256 = hashlib.sha256(truth_guard._canonical(payload)).hexdigest()
    claimed = public.get("report_sha256")
    if claimed is None:
        integrity_state = "unknown"
        integrity_reason = "source report did not yet provide an integrity digest"
        claimed_text = ""
    elif not isinstance(claimed, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", claimed):
        integrity_state = "mismatch"
        integrity_reason = "source report_sha256 is not a SHA-256 digest"
        claimed_text = "[invalid digest]"
    else:
        claimed_text = claimed.lower()
        integrity_state = (
            "verified" if claimed_text == source_sha256 else "mismatch")
        integrity_reason = (
            "source report digest matches the complete canonical evidence"
            if integrity_state == "verified" else
            "source report digest does not match the complete canonical evidence")

    findings = public.get("findings") \
        if type(public.get("findings")) in {list, tuple} else []
    improvements = public.get("improvements") \
        if type(public.get("improvements")) in {list, tuple} else []
    attack_paths = public.get("attack_paths") \
        if type(public.get("attack_paths")) in {list, tuple} else []
    errors = public.get("errors") \
        if type(public.get("errors")) in {list, tuple} else []
    semantic = public.get("semantic") \
        if type(public.get("semantic")) is dict else {}
    semantic_findings = semantic.get("findings") \
        if type(semantic.get("findings")) in {list, tuple} else []
    semantic_files = semantic.get("files") \
        if type(semantic.get("files")) in {list, tuple} else []
    workspace = public.get("workspace") \
        if type(public.get("workspace")) is dict else {}
    supply_chain = public.get("supply_chain") \
        if type(public.get("supply_chain")) is dict else {}
    inventory = supply_chain.get("inventory") \
        if type(supply_chain.get("inventory")) is dict else {}
    dependencies = inventory.get("dependencies") \
        if type(inventory.get("dependencies")) in {list, tuple} else []

    view: dict[str, Any] = {}
    for key in ("schema", "version", "root", "status"):
        value = public.get(key)
        if key in public and (
                value is None or isinstance(value, (str, bool, int, float))):
            view[key] = value
    if type(public.get("summary")) is dict:
        view["summary"] = public["summary"]
    view.update({
        "findings": [_truth_finding_projection(row) for row in findings],
        "attack_paths": _truth_marker_list(attack_paths),
        "improvements": list(improvements),
        "errors": _truth_marker_list(errors),
        "semantic": {
            "metrics": semantic.get("metrics", {})
            if type(semantic.get("metrics")) is dict else {},
            "findings": [
                _truth_finding_projection(row) for row in semantic_findings
            ],
            "files": _truth_marker_list(semantic_files),
        },
        "workspace": {
            "files_scanned": workspace.get("files_scanned"),
            "files_discovered": workspace.get("files_discovered"),
            "skipped": _truth_marker_list(workspace.get("skipped")),
            "errors": _truth_marker_list(workspace.get("errors")),
        },
        "supply_chain": {
            "inventory": {
                "dependencies": _truth_marker_list(dependencies),
            },
            "advisory_assessment": supply_chain.get(
                "advisory_assessment", {}),
        },
    })
    for key in ("artifacts", "model_artifacts"):
        rows = public.get(key)
        if type(rows) in {list, tuple}:
            view[key] = [_truth_artifact_projection(row) for row in rows]

    view_nodes = _truth_document_node_count(
        view, maximum=truth_guard.MAX_INPUT_NODES,
        boundary="Attestor 3.0 independent-validation view")
    view_sha256 = hashlib.sha256(truth_guard._canonical(view)).hexdigest()
    if integrity_state == "verified":
        view["report_sha256"] = view_sha256
    elif integrity_state == "mismatch":
        # Make the older guard apply its existing mismatch quarantine to every
        # claim; the source integrity row below replaces this synthetic value.
        view["report_sha256"] = "0" * 64
    view_nodes = _truth_document_node_count(
        view, maximum=truth_guard.MAX_INPUT_NODES,
        boundary="Attestor 3.0 independent-validation view")

    integrity = {
        "state": integrity_state,
        "claimed": claimed_text,
        "computed": source_sha256,
        "evidence_refs": [],
        "reason": integrity_reason,
    }
    metadata = {
        "projected": True,
        "source_document_sha256": source_sha256,
        "source_node_count": source_nodes,
        "source_node_count_exact": True,
        "source_node_hard_limit": MAX_TRUTH_DOCUMENT_NODES,
        "independent_node_limit": truth_guard.MAX_INPUT_NODES,
        "view_node_count": view_nodes,
        "view_sha256": view_sha256,
        "collections": {
            "attack_paths": len(attack_paths),
            "dependencies": len(dependencies),
            "errors": len(errors),
            "findings": len(findings),
            "improvements": len(improvements),
            "semantic_files": len(semantic_files),
            "semantic_findings": len(semantic_findings),
        },
        "reason": (
            "the complete source report exceeds the older independent "
            "validator boundary; exact consumed fields are projected while "
            "the complete source remains digest-bound"),
    }
    return view, metadata, integrity


def _truth_assessment(report: Mapping[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in report.items() if not key.startswith("_")}
    source_nodes = _truth_document_node_count(public)
    if len(truth_guard._canonical(public)) > MAX_TRUTH_DOCUMENT_BYTES:
        raise Attestor3Error("Attestor 3.0 evidence exceeds the 16 MiB hard boundary")
    if source_nodes <= truth_guard.MAX_INPUT_NODES:
        return truth_guard.validate_claims(
            _truth_claims(public), public, root=_truth_root(public))
    validation_view, metadata, source_integrity = \
        _truth_validation_projection(public, source_nodes)
    assessment = truth_guard.validate_claims(
        _truth_claims(validation_view), validation_view,
        root=_truth_root(public))
    assessment["report_integrity"] = source_integrity
    assessment["independent_validation"] = metadata
    if assessment.get("status") == "verified":
        assessment["status"] = "partial"
    return assessment


def _validated_public_report(report: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a report view containing only claims that survived Truth Guard."""
    public = {key: value for key, value in report.items() if not key.startswith("_")}
    # JSON round-trip prevents an output renderer from mutating the caller's report.
    view = json.loads(json.dumps(public, ensure_ascii=False, default=str))
    assessment = _truth_assessment(public)

    def finalize(candidate: dict[str, Any]) -> dict[str, Any]:
        _truth_document_node_count(candidate)
        safe = truth_guard.redact_tree(candidate, _validated=True)
        if safe != public:
            source_digest = safe.pop("report_sha256", None)
            if source_digest:
                safe["source_report_sha256"] = source_digest
            safe["view_sha256"] = hashlib.sha256(_canonical(safe)).hexdigest()
        return safe

    if assessment.get("report_integrity", {}).get("state") == "mismatch":
        view.update(status="inconsistent", findings=[], top_findings=[], priorities=[],
                    improvements=[], attack_paths=[])
        view["summary"] = {
            **(view.get("summary", {}) if isinstance(view.get("summary"), dict) else {}),
            "findings": 0, "verified_improvements": 0,
        }
        view.setdefault("errors", []).append({
            "component": "truth-guard", "error": "report-integrity-mismatch"})
        return finalize(view), assessment
    accepted_findings = {
        (claim.get("predicate", {}).get("rule"),
         claim.get("predicate", {}).get("path"),
         claim.get("predicate", {}).get("line"))
        for claim in assessment.get("claims", [])
        if claim.get("kind") == "finding" and claim.get("accepted") is True
    }

    def finding_allowed(row: Any) -> bool:
        if not isinstance(row, Mapping):
            return False
        return (row.get("rule"), _relative(_truth_root(public) or Path(".").resolve(),
                                           str(row.get("path", ""))), row.get("line")) \
            in accepted_findings

    if isinstance(view.get("findings"), list):
        view["findings"] = [row for row in view["findings"] if finding_allowed(row)]
    if isinstance(view.get("top_findings"), list):
        view["top_findings"] = [row for row in view["top_findings"] if finding_allowed(row)]
    known_rule_paths = {(row.get("rule"), row.get("path")) for row in view.get("findings", [])}
    if isinstance(view.get("priorities"), list):
        view["priorities"] = [row for row in view["priorities"] if isinstance(row, Mapping)
                              and (row.get("rule"), row.get("path")) in known_rule_paths]
    verified_targets = {
        claim.get("predicate", {}).get("path")
        for claim in assessment.get("claims", [])
        if claim.get("kind") == "improvement" and claim.get("accepted") is True
        and claim.get("predicate", {}).get("expected") == "verified"
    }
    for row in view.get("improvements", []) if isinstance(view.get("improvements"), list) else []:
        if not isinstance(row, dict) or row.get("accepted") is not True:
            continue
        target = _relative(_truth_root(public) or Path(".").resolve(), str(row.get("target", "")))
        if target not in verified_targets:
            row.update(status="refused", accepted=False, complete=False,
                       improved_source="", diff="", improved_source_withheld=True,
                       withheld_reason="Truth Guard rejected the supplied verification bundle")
            reasons = row.get("reasons")
            row["reasons"] = list(reasons) if isinstance(reasons, list) else (
                [str(reasons)] if reasons else [])
            row["reasons"].append("Truth Guard rejected the supplied verification bundle")
            view["status"] = "inconsistent"
    if isinstance(view.get("summary"), dict):
        view["summary"]["findings"] = len(view.get("findings", []))
        view["summary"]["verified_improvements"] = sum(
            item.get("accepted") is True for item in view.get("improvements", [])
            if isinstance(item, Mapping))
    return finalize(view), assessment


def _row(value: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if hasattr(value, "__dict__"):
        return vars(value)
    return dict(value) if isinstance(value, Mapping) else {}


def _relative(project: Path, raw: str) -> str:
    try:
        path = Path(raw)
        if not path.is_absolute():
            path = project / path
        return path.resolve().relative_to(project).as_posix()
    except (OSError, ValueError):
        return Path(raw).name or "workspace"


def _normalize_finding(value: Any, project: Path, source: str) -> dict[str, Any] | None:
    row = _row(value)
    rule = row.get("rule", row.get("rule_id"))
    if not isinstance(rule, str) or not rule:
        return None
    try:
        line = max(1, int(row.get("line", 1)))
    except (TypeError, ValueError):
        line = 1
    path = _relative(project, str(row.get("path", "workspace")))
    severity = str(row.get("severity", "MEDIUM")).upper()
    if severity not in SEVERITY_RANK:
        severity = "MEDIUM"
    fix = row.get("fix", row.get("remediation", ""))
    message = row.get("message", row.get("detail", "Review the observed evidence."))
    fingerprint = row.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        fingerprint = _fingerprint(rule, path, line, message)
    return {
        **row, "path": path, "line": line, "rule": rule,
        "severity": severity, "message": str(message)[:8_000],
        "fix": str(fix)[:8_000], "confidence": float(row.get("confidence", 0) or 0),
        "source": row.get("source") if isinstance(row.get("source"), str) else source,
        "fingerprint": fingerprint,
    }


def _merge_findings(project: Path, sources: Iterable[tuple[str, Iterable[Any]]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, int], dict[str, Any]] = {}
    for source, values in sources:
        for value in values or []:
            row = _normalize_finding(value, project, source)
            if row is None:
                continue
            key = (row["rule"], row["path"], row["line"])
            existing = merged.get(key)
            if existing is None or SEVERITY_RANK[row["severity"]] > SEVERITY_RANK[existing["severity"]] \
                    or len(row.get("evidence", [])) > len(existing.get("evidence", [])):
                merged[key] = row
    return sorted(merged.values(), key=lambda item: (
        -SEVERITY_RANK[item["severity"]], item["path"].casefold(), item["line"], item["rule"]))


def _component(name: str, function, errors: list[dict[str, str]]):
    try:
        return function()
    except Exception as exc:  # Component isolation: the report records type, not source or secrets.
        errors.append({"component": name, "error": type(exc).__name__})
        return None


def _custom_rules(project: Path, target: Path, packs: Sequence[str],
                  signature_key: bytes | None, require_signed: bool) -> tuple[list[dict], list[dict]]:
    if not packs:
        return [], []
    rules: list[rule_sdk.RuleSpec] = []
    reports = []
    for path in packs:
        loaded, report = rule_sdk.load_pack(path, signature_key=signature_key)
        if require_signed and (signature_key is None or not report.get("signed")):
            raise Attestor3Error(
                "authenticated rule pack required; provide a verification key: %s"
                % Path(path).name)
        rules.extend(loaded); reports.append({"path": str(Path(path).resolve()), **report})
        if len(rules) > MAX_CUSTOM_RULES:
            raise Attestor3Error("custom rule count exceeds %d" % MAX_CUSTOM_RULES)
    files, _, _ = scanengine.discover([str(target)])
    by_selector: dict[str, list[rule_sdk.RuleSpec]] = {}
    for rule in rules:
        for selector in rule.extensions:
            by_selector.setdefault(selector.lower(), []).append(rule)
    findings = []
    for path in files:
        if len(findings) >= MAX_CUSTOM_FINDINGS:
            break
        applicable = list(by_selector.get(path.suffix.lower(), [])) + list(
            by_selector.get(path.name.lower(), []))
        if not applicable:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for finding in rule_sdk.scan_pack(applicable, source, str(path)):
            findings.append(finding)
            if len(findings) >= MAX_CUSTOM_FINDINGS:
                break
    return reports, findings


def _reachability(semantic: Mapping[str, Any] | None) -> dict[str, str]:
    evidence: dict[str, str] = {}
    if not semantic:
        return evidence
    for edge in semantic.get("module_graph", {}).get("edges", []):
        imported = str(edge.get("imported", "")).lstrip(".").split(".", 1)[0]
        if imported:
            evidence[imported] = "reachable"
    return evidence


def _node(value: Any, project: Path) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    kind = str(value.get("kind", value.get("type", "step")))[:64]
    label = value.get("detail", value.get("label", value.get("symbol", value.get("name", kind))))
    row = {"kind": kind, "label": str(label)[:500]}
    if value.get("path"):
        row["path"] = _relative(project, str(value["path"]))
    if value.get("line"):
        try:
            row["line"] = max(1, int(value["line"]))
        except (TypeError, ValueError):
            row.pop("line", None)
    return row


def _attack_paths(project: Path, semantic: Mapping[str, Any] | None,
                  security: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if semantic:
        for finding in semantic.get("findings", []):
            nodes = list(filter(None, (_node(item, project) for item in finding.get("evidence", []))))
            if len(nodes) >= 2:
                rows.append({
                    "id": finding.get("fingerprint", _fingerprint(nodes)),
                    "title": finding.get("message", "Semantic source-to-sink path"),
                    "severity": finding.get("severity", "HIGH"),
                    "rule": finding.get("rule", "semantic-taint"),
                    "nodes": nodes, "confidence": finding.get("confidence", 0),
                    "source": "semantic-engine",
                })
    if security:
        raw_paths = security.get("threat_model", {}).get("attack_paths", [])
        for raw in raw_paths:
            if not isinstance(raw, Mapping):
                continue
            evidence = raw.get("nodes", raw.get("evidence", raw.get("evidence_chain", raw.get("steps", []))))
            nodes = list(filter(None, (_node(item, project) for item in evidence))) if isinstance(evidence, list) else []
            if not nodes:
                for key in ("source", "entrypoint", "boundary", "sink", "target"):
                    if raw.get(key):
                        item = raw[key] if isinstance(raw[key], Mapping) else {"kind": key, "label": raw[key]}
                        node = _node(item, project)
                        if node:
                            nodes.append(node)
            # A single observation is a lead, not a source-to-sink path.  Do
            # not upgrade it into an "attack path" claim without two linked
            # pieces of evidence.
            if len(nodes) >= 2:
                rows.append({
                    "id": str(raw.get("id") or _fingerprint(raw))[:128],
                    "title": str(raw.get("title", raw.get("description", "Security attack path")))[:1_000],
                    "severity": str(raw.get("severity", "HIGH")).upper(),
                    "rule": raw.get("rule", "stride-path"), "nodes": nodes,
                    "confidence": raw.get("confidence", 0), "source": "security-posture",
                })
    unique = {str(row["id"]): row for row in rows}
    return sorted(unique.values(), key=lambda item: (
        -SEVERITY_RANK.get(item["severity"], 0), -len(item["nodes"]), str(item["id"])))[:MAX_ATTACK_PATHS]


def _improve(project: Path, findings: list[dict[str, Any]], *, max_files: int,
             test_command: Sequence[str] | None, authorize_tests: bool,
             apply: bool, backup_root: str,
             exact_file_scope: bool = False
             ) -> tuple[list[dict[str, Any]], list[Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in findings:
        if row["rule"] not in verified_remediation.SUPPORTED_RULES:
            continue
        relative = _relative(project, row["path"])
        target = (project / relative).resolve()
        try:
            target.relative_to(project)
        except ValueError:
            continue
        if target.is_file() and target.suffix.lower() == ".py":
            groups.setdefault(relative, []).append(row)
    ordered = sorted(groups, key=lambda path: (
        -max(SEVERITY_RANK.get(row["severity"], 0) for row in groups[path]), path.casefold()))
    output = []
    internal_reports = []
    for target in ordered[:max(0, max_files)]:
        report = verified_remediation.verify_remediation(
            project, target, groups[target], test_command=test_command,
            authorize_tests=authorize_tests, deep=True, require_verified=True,
            exact_file_scope=exact_file_scope)
        internal_reports.append(report)
        serialized = verified_remediation.report_dict(report)
        proposal = serialized["proposal"]
        validation = serialized.get("validation") or {}
        # Directory requests use a project regression scan.  Exact-file
        # requests preserve their read boundary and compare only that file.
        # Public counts always describe the selected target.
        if report.validation is not None:
            project_before = len(report.validation.baseline.issues)
            project_after = len(report.validation.candidate.issues)
            target_before = sum(
                _relative(project, item.path) == target
                for item in report.validation.baseline.issues)
            target_after = sum(
                _relative(project, item.path) == target
                for item in report.validation.candidate.issues)
            validation.update({
                "scope": (
                    "exact-target-file" if exact_file_scope else
                    "target-file-with-project-regression-scan"),
                "findings_before": target_before,
                "findings_after": target_after,
            })
            if not exact_file_scope:
                validation.update({
                    "project_findings_before": project_before,
                    "project_findings_after": project_after,
                })
        improved = proposal.get("improved_source", "")
        secret_findings = secret_guard.scan_text(improved, target) if improved else []
        safe_to_present = report.accepted and not secret_findings
        row = {
            "target": target, "status": "verified" if report.accepted else "refused",
            "accepted": report.accepted, "complete": report.complete,
            "reasons": list(report.reasons), "diff": proposal.get("unified_diff", ""),
            "improved_source": improved if safe_to_present else "",
            "improved_source_withheld": bool(improved and not safe_to_present),
            "withheld_reason": ("candidate was not accepted" if improved and not report.accepted else
                                "candidate still contains credential-like material" if secret_findings else ""),
            "resolved_count": len(validation.get("resolved_findings", [])),
            "remaining_count": validation.get("findings_after", len(groups[target])),
            "verification": validation,
            "probes": serialized.get("probes", []),
            "selected_tests": serialized.get("selected_tests", {}),
            "edits": proposal.get("edits", []), "refusals": proposal.get("refusals", []),
        }
        if apply and report.accepted:
            applied = verified_remediation.apply_remediation(
                report, authorized=True, backup_root=backup_root or None)
            row["apply"] = dataclasses.asdict(applied)
        output.append(row)
    if not output and findings:
        output.append({
            "target": "workspace", "status": "refused", "accepted": False,
            "complete": False, "reasons": [
                "No finding matched Attestor's conservative deterministic fix set; no guessed change was produced."],
            "diff": "", "improved_source": "", "improved_source_withheld": False,
            "withheld_reason": "", "resolved_count": 0,
            "remaining_count": len(findings), "verification": {}, "probes": [],
            "selected_tests": {}, "edits": [], "refusals": [],
        })
    return output, internal_reports


def _generic_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    rules = {}
    results = []
    for row in report.get("findings", []):
        rules[row["rule"]] = {"id": row["rule"], "name": row["rule"],
                              "shortDescription": {"text": row["message"][:1_000]}}
        results.append({
            "ruleId": row["rule"],
            "level": "error" if row["severity"] in {"CRITICAL", "HIGH"} else
                     "warning" if row["severity"] == "MEDIUM" else "note",
            "message": {"text": row["message"] + ((" Fix: " + row["fix"]) if row.get("fix") else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": row["path"]},
                                                   "region": {"startLine": row["line"]}}}],
            "partialFingerprints": {"attestorFindingFingerprint/v1": row["fingerprint"]},
            "properties": {"source": row.get("source", row.get("source_engine", "")),
                           "confidence": row.get("confidence", 0)},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Attestor 3.0", "semanticVersion": VERSION,
                                              "rules": list(rules.values())}}, "results": results}]}


def _single_file_supply_report(requested: Path) -> dict[str, Any]:
    """Refuse implicit parent-directory inventory for an exact file request."""
    gap = ("single-file scope was preserved; sibling manifests and lockfiles were not "
           "read, so workspace supply-chain analysis was not run")
    return {
        "schema": supply_chain_center.SCHEMA, "version": supply_chain_center.VERSION,
        "root": str(requested), "status": "not-run-file-scope",
        "execution": {"network_access": False, "dependencies_installed": False,
                      "target_code_executed": False, "mode": "offline-static-not-run"},
        "inventory": {"root": str(requested), "dependencies": [], "manifests": [],
                      "errors": [], "lock_coverage": []},
        "risk_findings": [],
        "advisory_assessment": {"state": "unavailable", "findings": [],
                                "reason": gap},
        "sbom": {}, "vex": {}, "provenance": {},
        "coverage": {"scope_kind": "file", "requested_root": str(requested),
                     "effective_root": str(requested), "scope_expanded": False,
                     "gaps": [gap], "absence_proven": False},
    }


def maximum(root: str | os.PathLike[str], *, improve: bool = True,
            max_improvement_files: int = 3, compiler_checks: bool = False,
            use_cache: bool = True, jobs: int = scanengine.DEFAULT_JOBS,
            test_command: Sequence[str] | None = None, authorize_tests: bool = False,
            apply_improvements: bool = False, backup_root: str = "",
            advisory_snapshot: Mapping[str, Any] | None = None,
            advisory_keys: Mapping[str, bytes] | None = None,
            rule_packs: Sequence[str] = (), rule_pack_key: bytes | None = None,
            require_signed_packs: bool = False,
            memory_baseline: Mapping[str, Any] | None = None,
            components: Sequence[str] = DEFAULT_COMPONENTS) -> dict[str, Any]:
    requested = Path(root).expanduser().resolve()
    if not requested.exists() or not (requested.is_file() or requested.is_dir()):
        raise Attestor3Error("target does not exist or is not a regular file/directory")
    project = requested if requested.is_dir() else requested.parent
    component_set = set(components)
    unknown = component_set - set(DEFAULT_COMPONENTS)
    if unknown:
        raise Attestor3Error("unknown component(s): " + ", ".join(sorted(unknown)))
    if test_command and not authorize_tests:
        raise PermissionError("selected tests require explicit authorization")
    if apply_improvements and not improve:
        raise Attestor3Error("applying improvements requires improvement generation")
    errors: list[dict[str, str]] = []
    results: dict[str, Any] = {}

    def scan_job():
        return scanengine.scan([str(requested)], jobs=jobs, deep=True,
                               tools=compiler_checks, use_cache=use_cache)

    def semantic_job():
        return semantic_engine.analyze_repository(
            requested, compiler_checks=compiler_checks)

    def security_job():
        return security_posture.assess(
            requested, jobs=jobs, deep=True, external_tools=compiler_checks,
            use_cache=False)

    jobs_map = {"scan": scan_job, "semantic": semantic_job, "security": security_job}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(3, len(component_set))),
                                               thread_name_prefix="attestor3") as pool:
        pending = {name: pool.submit(_component, name, function, errors)
                   for name, function in jobs_map.items() if name in component_set}
        for name, future in pending.items():
            results[name] = future.result()
    reachability = _reachability(results.get("semantic"))
    if "supply-chain" in component_set:
        if requested.is_file():
            results["supply-chain"] = _single_file_supply_report(requested)
        else:
            results["supply-chain"] = _component(
                "supply-chain", lambda: supply_chain_center.analyze_workspace(
                    project, snapshot=advisory_snapshot, trusted_keys=advisory_keys or {},
                    reachability=reachability), errors)

    scan = results.get("scan")
    semantic = results.get("semantic") or {}
    security = results.get("security") or {}
    supply = results.get("supply-chain") or {}
    pack_reports, pack_findings = _custom_rules(
        project, requested, rule_packs, rule_pack_key, require_signed_packs)
    sources = [
        ("scanengine", scan.issues if scan else []),
        ("semantic-engine", semantic.get("findings", [])),
        ("security-posture", security.get("findings", [])),
        ("supply-chain", supply.get("risk_findings", [])),
        ("rule-sdk", pack_findings),
    ]
    findings = _merge_findings(project, sources)
    improvements, _internal = _improve(
        project, findings, max_files=max_improvement_files,
        test_command=test_command, authorize_tests=authorize_tests,
        apply=apply_improvements, backup_root=backup_root,
        exact_file_scope=requested.is_file()) if improve else ([], [])
    attack_paths = _attack_paths(project, semantic, security)
    memory_snapshot = repository_memory.snapshot_target(requested, findings)
    memory_diff = repository_memory.compare(memory_baseline, memory_snapshot) if memory_baseline else None
    severity = {name: sum(row["severity"] == name for row in findings) for name in SEVERITY_RANK}
    accepted = sum(bool(row.get("accepted")) for row in improvements)
    refused = sum(not bool(row.get("accepted")) for row in improvements)
    component_errors = list(errors)
    if scan:
        component_errors.extend({"component": "scan", "error": "operational-error"}
                                for _ in scan.errors)
    component_errors.extend({"component": "semantic", "error": "operational-error"}
                            for _ in semantic.get("operational_errors", []))
    component_errors.extend({"component": "security", "error": "operational-error"}
                            for _ in security.get("errors", []))
    component_errors.extend({"component": "supply-chain", "error": "inventory-error"}
                            for _ in supply.get("inventory", {}).get("errors", []))
    files_scanned = (scan.files_scanned if scan else
                     semantic.get("metrics", {}).get("files_discovered", 0))
    coverage_gaps = []
    if not component_set:
        coverage_gaps.append("no analysis component was enabled")
    omitted = sorted(set(DEFAULT_COMPONENTS) - component_set)
    if omitted:
        coverage_gaps.append("components not run: " + ", ".join(omitted))
    if files_scanned <= 0:
        coverage_gaps.append("zero source files were scanned")
    if scan and scan.status in {"failed", "unsupported"}:
        coverage_gaps.append("workspace scan status: " + scan.status)
    advisory_state = supply.get("advisory_assessment", {}).get("state")
    if "supply-chain" in component_set and advisory_state != "fresh":
        coverage_gaps.append("advisory intelligence state: " + str(advisory_state or "unavailable"))
    supply_coverage = supply.get("coverage") if type(supply.get("coverage")) is dict else {}
    for gap in supply_coverage.get("gaps", []) if type(supply_coverage.get("gaps")) is list else []:
        if gap:
            coverage_gaps.append(str(gap)[:1_000])
    status = "failed" if component_errors else (
        "action-required" if findings and not accepted else
        "improved-with-review" if findings else
        "no-findings-with-gaps" if coverage_gaps else
        "no-findings-from-enabled-checks")
    priorities = []
    seen_priorities = set()
    for row in findings:
        text = row.get("fix") or row.get("message")
        if text and text not in seen_priorities:
            seen_priorities.add(text)
            priorities.append({"priority": row["severity"], "fix": text,
                               "rule": row["rule"], "path": row["path"]})
        if len(priorities) >= 40:
            break
    report = {
        "schema": SCHEMA, "version": VERSION, "root": str(requested), "status": status,
        "summary": {
            "files_scanned": files_scanned,
            "findings": len(findings), "severity": severity,
            "semantic_findings": semantic.get("metrics", {}).get("semantic_findings", 0),
            "attack_paths": len(attack_paths),
            "dependencies": len(supply.get("inventory", {}).get("dependencies", [])),
            "verified_improvements": accepted, "refused_improvements": refused,
            "component_errors": len(component_errors),
        },
        "findings": findings, "top_findings": findings[:MAX_TOP_FINDINGS],
        "priorities": priorities, "attack_paths": attack_paths,
        "improvements": improvements,
        "semantic": semantic,
        "security": security,
        "supply_chain": supply,
        "workspace": ({
            "version": scan.version, "status": scan.status,
            "files_discovered": scan.files_discovered, "files_scanned": scan.files_scanned,
            "cache_hits": scan.cache_hits, "errors": scan.errors, "skipped": scan.skipped,
            "elapsed_ms": scan.elapsed_ms,
        } if scan else {}),
        "rule_packs": pack_reports,
        "runtime_lab": dataclasses.asdict(runtime_lab.availability()),
        "repository_memory": {
            "snapshot_id": memory_snapshot["snapshot_id"],
            "repository_id": memory_snapshot["repository_id"],
            "files": len(memory_snapshot["files"]),
            "architecture": memory_snapshot["architecture"],
            "privacy": memory_snapshot["privacy"], "diff": memory_diff,
        },
        "standards": {
            **security.get("standards", {}),
            "cyclonedx": supply.get("sbom", {}).get("cyclonedx", {}).get("specVersion", "not-run"),
            "spdx": ("3.0.1" if supply.get("sbom", {}).get("spdx", {}).get("@context") else "not-run"),
            "lsp": "3.18", "sarif": "2.1.0",
        },
        "errors": component_errors,
        "coverage": {
            "requested_components": sorted(component_set),
            "completed_components": sorted(
                name for name in component_set if results.get(name) is not None and
                not (name == "supply-chain" and supply.get("status") == "not-run-file-scope")),
            "omitted_components": omitted,
            "gaps": coverage_gaps,
            "advisory_state": advisory_state or "not-run",
            "absence_proven": False,
        },
        "assurance": [
            "No target code, dependency installation, or network probing is performed unless a separate selected-test authorization is supplied.",
            "Improved source is labeled verified only after parser/compiler, rescan, regression, mutation, property, and fuzz evidence passes.",
            "A refused candidate is never described as an improved result and is never applied.",
            "Repository memory stores hashes and architecture only; source, finding messages, rationales, and secret material are excluded.",
            "Static and compiler evidence is bounded and cannot prove absence of all defects or practical exploitability.",
            "Runtime Lab reports when kernel-grade network isolation is unavailable and refuses execution that cannot meet policy.",
        ],
        "execution": {
            "target_code_executed": None if any(
                row.get("selected_tests", {}).get("returncode") is not None
                or bool(row.get("selected_tests", {}).get("timed_out"))
                for row in improvements) else False,
            "target_code_may_have_executed": any(
                row.get("selected_tests", {}).get("returncode") is not None
                or bool(row.get("selected_tests", {}).get("timed_out"))
                for row in improvements),
            "selected_tests_executed": any(
                row.get("selected_tests", {}).get("returncode") is not None
                or bool(row.get("selected_tests", {}).get("timed_out"))
                for row in improvements),
            "network_access": None if any(
                row.get("selected_tests", {}).get("returncode") is not None
                or bool(row.get("selected_tests", {}).get("timed_out"))
                for row in improvements) else False,
            "network_observed": "unknown" if any(
                row.get("selected_tests", {}).get("returncode") is not None
                or bool(row.get("selected_tests", {}).get("timed_out"))
                for row in improvements) else "not-applicable",
            "network_enforcement": sorted({
                str(row.get("selected_tests", {}).get("network_policy", "not-applicable"))
                for row in improvements
            }),
            "changes_applied": any(bool(row.get("apply")) for row in improvements),
        },
    }
    report["truth_guard"] = _truth_assessment(report)
    report["report_sha256"] = hashlib.sha256(_canonical(report)).hexdigest()
    report["_memory_snapshot"] = memory_snapshot  # removed from normal JSON; used by explicit CLI output.
    return report


def public_report(report: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in report.items() if not key.startswith("_")}


def safe_public_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return the integrity-checked, evidence-filtered public view."""
    return _validated_public_report(report)[0]


def deterministic_json(report: Mapping[str, Any], *, indent: int | None = 2) -> str:
    """Serialize a locally hard-bounded, already-filtered Attestor 3 report."""
    if type(report) is not dict:
        raise Attestor3Error("public report must be a JSON object")
    _truth_document_node_count(report)
    safe = truth_guard.redact_tree(report, _validated=True)
    encoded = json.dumps(
        safe, sort_keys=True, indent=indent, ensure_ascii=False,
        allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_TRUTH_DOCUMENT_BYTES:
        raise Attestor3Error("Attestor 3.0 public JSON exceeds the 16 MiB hard boundary")
    return encoded.decode("utf-8")


def render(report: Mapping[str, Any], style: str = "professional") -> str:
    view, assessment = _validated_public_report(report)
    if style == "classic":
        return deterministic_json(view)
    text = response_engine.structured(view, style)
    summary = assessment.get("summary", {})
    integrity = assessment.get("report_integrity", {}).get("state", "unknown")
    return text + ("\n\nTruth Guard evidence gate\n=========================\n"
                   "- status: %s; report integrity: %s; observed=%s; derived=%s; "
                   "unknown=%s; refuted=%s; contradictions=%s" % (
                       assessment.get("status", "unknown"), integrity,
                       summary.get("observed", 0), summary.get("derived", 0),
                       summary.get("unknown", 0), summary.get("refuted", 0),
                       summary.get("contradictions", 0)))


def to_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    return _generic_sarif(safe_public_report(report))


def _write_improvements(report: Mapping[str, Any], output: str | os.PathLike[str]) -> list[str]:
    root = Path(output).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
    written = []
    for row in safe_public_report(report).get("improvements", []):
        if not row.get("accepted") or not row.get("improved_source"):
            continue
        relative = Path(row["target"])
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise Attestor3Error("improvement output path is unsafe")
        destination = (root / relative).resolve()
        try:
            destination.relative_to(root)
        except ValueError as exc:
            raise Attestor3Error("improvement output escapes destination") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(row["improved_source"], encoding="utf-8", newline="")
        written.append(str(destination))
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--no-improve", action="store_true")
    parser.add_argument("--max-improvement-files", type=int, default=3)
    parser.add_argument("--compiler-checks", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--jobs", type=int, default=scanengine.DEFAULT_JOBS)
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
    parser.add_argument("--memory-baseline")
    parser.add_argument("--memory-out")
    parser.add_argument("--improved-out")
    parser.add_argument("--response-style", choices=response_engine.STYLES, default="professional")
    parser.add_argument("--format", choices=("text", "json", "sarif", "cyclonedx", "spdx", "vex"),
                        default="text")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    if not 0 <= args.max_improvement_files <= 10:
        parser.error("--max-improvement-files must be between 0 and 10")
    test_command = None
    if args.test_command_json:
        try:
            test_command = json.loads(args.test_command_json)
        except json.JSONDecodeError as exc:
            parser.error("--test-command-json is invalid: %s" % exc)
        if not isinstance(test_command, list) or not test_command or any(
                not isinstance(item, str) or not item for item in test_command):
            parser.error("--test-command-json must be a non-empty argv list")
    if args.run_tests and not test_command:
        parser.error("--run-tests requires --test-command-json")
    if test_command and not args.run_tests:
        parser.error("selected tests require --run-tests")
    if args.apply_improvements and args.no_improve:
        parser.error("--apply-improvements conflicts with --no-improve")
    snapshot = supply_chain_center.load_advisory_snapshot(args.advisory_snapshot) \
        if args.advisory_snapshot else None
    advisory_keys = None
    if args.advisory_key_file:
        advisory_keys = {args.advisory_key_id: Path(args.advisory_key_file).read_bytes()}
    rule_key = Path(args.rule_key_file).read_bytes() if args.rule_key_file else None
    memory_baseline = json.loads(Path(args.memory_baseline).read_text(encoding="utf-8")) \
        if args.memory_baseline else None
    try:
        report = maximum(
            args.root, improve=not args.no_improve,
            max_improvement_files=args.max_improvement_files,
            compiler_checks=args.compiler_checks, use_cache=not args.no_cache,
            jobs=args.jobs, test_command=test_command, authorize_tests=args.run_tests,
            apply_improvements=args.apply_improvements, backup_root=args.backup_root,
            advisory_snapshot=snapshot, advisory_keys=advisory_keys,
            rule_packs=args.rule_pack, rule_pack_key=rule_key,
            require_signed_packs=args.require_signed_packs,
            memory_baseline=memory_baseline)
        public = safe_public_report(report)
        if args.format == "json":
            text = deterministic_json(public)
        elif args.format == "sarif":
            text = json.dumps(to_sarif(report), indent=2, sort_keys=True)
        elif args.format == "cyclonedx":
            text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get("cyclonedx", {}), indent=2, sort_keys=True)
        elif args.format == "spdx":
            text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get("spdx", {}), indent=2, sort_keys=True)
        elif args.format == "vex":
            text = json.dumps(public.get("supply_chain", {}).get("vex", {}), indent=2, sort_keys=True)
        else:
            text = render(report, args.response_style)
        if args.out:
            Path(args.out).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
        else:
            print(text)
        if args.memory_out:
            Path(args.memory_out).write_text(
                json.dumps(report["_memory_snapshot"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.improved_out:
            _write_improvements(report, args.improved_out)
        return 2 if public["status"] in {"failed", "inconsistent", "no-evidence"} else (
            1 if public["summary"]["findings"] or public["status"] == "no-findings-with-gaps" else 0)
    except (OSError, Attestor3Error, PermissionError, ValueError, RuntimeError) as exc:
        print("Attestor 3.0 failed safely: %s" % type(exc).__name__, file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
