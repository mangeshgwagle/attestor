#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    import case_file42 as cf
except ImportError:
    import detector.case_file42 as cf

VERSION = "4.3"
WORKFLOW_SCHEMA = "attestor-workflow/4.3"
STAGES = cf.STAGES

_UNKNOWN = "unknown"
_MEASURED = cf.MEASURED
_HYPOTHESIS = cf.HYPOTHESIS

_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")

class WorkflowError(ValueError):
    pass

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowError("%s must be a non-empty string" % label)
    v = value.strip()
    if not _ID_PATTERN.fullmatch(v):
        raise WorkflowError("%s is not a valid identifier" % label)
    return v

def _ensure_unknowns(evidence: Mapping[str, Any]) -> list[str]:
    unknowns = evidence.get("unknowns")
    if unknowns is None:
        return []
    if not isinstance(unknowns, (list, tuple)):
        raise WorkflowError("unknowns must be a list")
    out: list[str] = []
    for item in unknowns:
        if not isinstance(item, str) or not item.strip():
            raise WorkflowError("unknown entry must be a non-empty string")
        if len(item) > 1024:
            raise WorkflowError("unknown entry exceeds 1024 characters")
        out.append(item.strip())
    return out

def _validate_stage_evidence(stage: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        raise WorkflowError("evidence must be a mapping")
    ev = dict(evidence)
    if "status" not in ev:
        ev["status"] = _UNKNOWN
    status = ev["status"]
    if status not in ("pass", "fail", "unknown", "observed", "derived", "unconfirmed", "reachable", "unreachable", "not-exploitable"):
        if stage == "exploitability" and status in ("exploitable",):
            raise WorkflowError("exploitability must never assert exploitable; use reachable + unknowns")
        raise WorkflowError("stage %s has invalid status %r" % (stage, status))
    if status in ("pass", "observed", "derived", "reachable"):
        pass
    if stage == "exploitability":
        if ev.get("verdict") == "exploitable" or ev.get("exploitable") is True:
            raise WorkflowError("exploitability must not claim exploitable; report reachability and unknowns")
        if "reachability" not in ev:
            ev["reachability"] = _UNKNOWN
        if ev["reachability"] not in ("reachable", "unreachable", "unknown", "reachability-unknown"):
            raise WorkflowError("exploitability reachability must be reachable/unreachable/unknown")
        if ev["reachability"] in ("unknown", "reachability-unknown") and not ev.get("unknowns"):
            if "unknowns" not in ev:
                ev["unknowns"] = ["deployment exposure unknown; reachability beyond static scope"]
    if stage == "severity":
        if "cvss_vector" in ev and "cvss_rationale" not in ev:
            raise WorkflowError("severity vector must cite evidence via cvss_rationale")
        if "cvss_vector" not in ev and ev.get("status") != _UNKNOWN:
            ev["status"] = _UNKNOWN
            unknowns = _ensure_unknowns(ev)
            if not unknowns:
                ev["unknowns"] = ["severity vector lacks evidence"]
    if stage == "root_cause":
        if ev.get("status") != _UNKNOWN and "file_line" not in ev and "location" not in ev:
            ev["status"] = _UNKNOWN
            unknowns = _ensure_unknowns(ev)
            if not unknowns:
                ev["unknowns"] = ["root cause must name file:line"]
        if "file_line" in ev:
            fl = ev["file_line"]
            if not isinstance(fl, str) or ":" not in fl:
                raise WorkflowError("root_cause file_line must be file:line")
    if stage == "validation":
        if "reproduces" not in ev:
            ev["reproduces"] = _UNKNOWN
        if ev["reproduces"] not in (True, False, _UNKNOWN, "unconfirmed"):
            raise WorkflowError("validation reproduces must be true/false/unknown")
        if ev["reproduces"] is False:
            ev["status"] = "unconfirmed" if ev.get("status") == _UNKNOWN else ev["status"]
    if stage == "remediation":
        if ev.get("status") not in (_UNKNOWN, "pass", "fail", "observed", "derived"):
            ev["status"] = _UNKNOWN
        if ev.get("status") != _UNKNOWN and "diff_sha256" not in ev and "patch" not in ev and "verified" not in ev:
            ev["status"] = _UNKNOWN
            if not ev.get("unknowns"):
                ev["unknowns"] = ["remediation lacks verified patch evidence"]
    if stage == "regression":
        if ev.get("fails_before_fix") is not True:
            raise WorkflowError("regression honesty gate: fails_before_fix=True required")
        if ev.get("status") == _UNKNOWN:
            raise WorkflowError("regression must be measured with explicit pass/fail, not unknown")
    if stage == "documentation":
        if "claims_checked" not in ev:
            ev["claims_checked"] = False
        if ev.get("status") != _UNKNOWN and not ev.get("claims_checked"):
            ev["status"] = _UNKNOWN
            if not ev.get("unknowns"):
                ev["unknowns"] = ["documentation claims not checked by truth_guard"]
    unknowns = _ensure_unknowns(ev)
    ev["unknowns"] = unknowns
    if ev["status"] == _UNKNOWN and not unknowns:
        ev["unknowns"] = ["insufficient evidence for %s" % stage]
    if ev["status"] != _UNKNOWN and stage not in ("regression",) and not ev.get("unknowns") and stage in ("exploitability", "severity", "root_cause", "validation"):
        pass
    return ev

def create_case(*, subject_path: str, subject_sha256: str, rule: str, summary: str, opened_by: str = "attestor") -> dict[str, Any]:
    return cf.open_case(subject_path=subject_path, subject_sha256=subject_sha256, rule=rule, summary=summary, opened_by=opened_by)

def append_stage(case: Mapping[str, Any], *, stage: str, basis: str, summary: str, evidence: Mapping[str, Any] | None = None, recorded_by: str = "attestor") -> dict[str, Any]:
    if stage not in STAGES:
        raise WorkflowError("unknown stage %r" % stage)
    if basis not in cf.BASES:
        raise WorkflowError("basis must be one of %s" % (cf.BASES,))
    ev = _validate_stage_evidence(stage, dict(evidence or {}))
    if stage == "regression" and basis != cf.MEASURED:
        raise WorkflowError("regression must be measured")
    return cf.append(case, stage=stage, basis=basis, summary=summary, evidence=ev, recorded_by=recorded_by)

def stage_discovery(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.MEASURED, recorded_by: str = "attestor") -> dict[str, Any]:
    ev = dict(evidence)
    if "finding" not in ev and "candidate" not in ev and ev.get("status") != _UNKNOWN:
        ev["status"] = _UNKNOWN
        ev["unknowns"] = ev.get("unknowns") or ["no candidate finding supplied"]
    return append_stage(case, stage="discovery", basis=basis, summary=summary, evidence=ev, recorded_by=recorded_by)

def stage_validation(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.MEASURED, recorded_by: str = "attestor") -> dict[str, Any]:
    return append_stage(case, stage="validation", basis=basis, summary=summary, evidence=evidence, recorded_by=recorded_by)

def stage_severity(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.HYPOTHESIS, recorded_by: str = "attestor") -> dict[str, Any]:
    return append_stage(case, stage="severity", basis=basis, summary=summary, evidence=evidence, recorded_by=recorded_by)

def stage_exploitability(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.MEASURED, recorded_by: str = "attestor") -> dict[str, Any]:
    return append_stage(case, stage="exploitability", basis=basis, summary=summary, evidence=evidence, recorded_by=recorded_by)

def stage_root_cause(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.HYPOTHESIS, recorded_by: str = "attestor") -> dict[str, Any]:
    return append_stage(case, stage="root_cause", basis=basis, summary=summary, evidence=evidence, recorded_by=recorded_by)

def stage_remediation(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.MEASURED, recorded_by: str = "attestor") -> dict[str, Any]:
    return append_stage(case, stage="remediation", basis=basis, summary=summary, evidence=evidence, recorded_by=recorded_by)

def stage_regression(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.MEASURED, recorded_by: str = "attestor") -> dict[str, Any]:
    ev = dict(evidence)
    if ev.get("fails_before_fix") is not True:
        raise WorkflowError("honesty gate: fails_before_fix=True required")
    if ev.get("passes_after_fix") not in (True, False):
        ev["passes_after_fix"] = True
    return append_stage(case, stage="regression", basis=basis, summary=summary, evidence=ev, recorded_by=recorded_by)

def stage_documentation(case: Mapping[str, Any], *, summary: str, evidence: Mapping[str, Any], basis: str = cf.HYPOTHESIS, recorded_by: str = "attestor") -> dict[str, Any]:
    ev = dict(evidence)
    if not ev.get("truth_guard_checked"):
        ev["truth_guard_checked"] = False
        if ev.get("status") != _UNKNOWN:
            ev["status"] = _UNKNOWN
            ev["unknowns"] = ev.get("unknowns") or ["claims not checked by truth_guard"]
    return append_stage(case, stage="documentation", basis=basis, summary=summary, evidence=ev, recorded_by=recorded_by)

def orchestrate(case: Mapping[str, Any], stages: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    cur = dict(case)
    cur["entries"] = list(case.get("entries") or [])
    for stage in STAGES:
        if stage not in stages:
            continue
        spec = stages[stage]
        if not isinstance(spec, Mapping):
            raise WorkflowError("stage spec for %s must be a mapping" % stage)
        summary = str(spec.get("summary", "%s evidence" % stage))
        basis = str(spec.get("basis", cf.MEASURED if stage in ("discovery", "validation", "exploitability", "remediation", "regression") else cf.HYPOTHESIS))
        evidence = spec.get("evidence", {})
        recorded_by = str(spec.get("recorded_by", "attestor"))
        cur = append_stage(cur, stage=stage, basis=basis, summary=summary, evidence=evidence, recorded_by=recorded_by)
    return cur

def workflow_status(case: Mapping[str, Any]) -> dict[str, Any]:
    ok, problems = cf.verify(case)
    completed = cf.stages_completed(case)
    missing = cf.stages_missing(case)
    entries = case.get("entries") or []
    unknowns: list[str] = []
    for e in entries:
        ev = e.get("evidence") or {}
        if ev.get("status") == _UNKNOWN or ev.get("reachability") in ("unknown", "reachability-unknown"):
            unknowns.append("%s: %s" % (e.get("stage"), "; ".join(ev.get("unknowns") or ["unknown"])))
    proven = cf.is_proven(case)
    return {"chain_ok": ok, "problems": problems, "completed": list(completed), "missing": list(missing), "unknowns": unknowns, "proven": proven, "stages_total": len(STAGES)}

def run_full_workflow(*, subject_path: str, subject_sha256: str, rule: str, summary: str, stage_inputs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    case = create_case(subject_path=subject_path, subject_sha256=subject_sha256, rule=rule, summary=summary)
    return orchestrate(case, stage_inputs)
