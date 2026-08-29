#!/usr/bin/env python3
"""Outcome-first, evidence-locked responses for Attestor 4.0.

Rendering happens only after Truth Guard 2.1 verifies the public document.  The
renderer never upgrades "no finding" into "no bug", and it keeps observations,
verified repairs, unknowns, and next actions visibly separate.
"""
from __future__ import annotations

from typing import Any, Mapping

import truth_guard40


STYLES = ("professional", "concise", "mentor", "direct", "executive", "classic")
MAX_FINDINGS = 12
MAX_GAPS = 12
MAX_ACTIONS = 10


def _text(value: Any, limit: int = 1_000) -> str:
    return str(value or "").replace("\x00", "\\0").replace("\r", " ").replace("\n", " ")[:limit]


def _count(document: Mapping[str, Any], key: str, collection: str) -> int:
    rows = document.get(collection)
    if type(rows) is list:
        return len(rows)
    summary = document.get("summary") if type(document.get("summary")) is dict else {}
    value = summary.get(key, 0)
    return int(value) if type(value) is int and value >= 0 else 0


def _severity(document: Mapping[str, Any]) -> dict[str, int]:
    findings = document.get("findings") if type(document.get("findings")) is list else []
    output = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for row in findings:
        if type(row) is dict:
            name = str(row.get("severity", "MEDIUM")).upper()
            output[name if name in output else "MEDIUM"] += 1
    return output


def _outcome(document: Mapping[str, Any]) -> str:
    findings = _count(document, "findings", "findings")
    improvements = sum(type(row) is dict and row.get("accepted") is True
                       for row in document.get("improvements", [])
                       if type(document.get("improvements")) is list)
    errors = _count(document, "component_errors", "errors")
    gaps = document.get("coverage", {}).get("gaps", []) \
        if type(document.get("coverage")) is dict else []
    if errors:
        return "Analysis completed with %d operational error(s); treat coverage as partial." % errors
    if findings and improvements:
        return "%d finding(s) observed; %d complete repair candidate(s) passed the configured gates." % (findings, improvements)
    if findings:
        return "%d finding(s) observed. No repair is described as verified unless its evidence bundle passed." % findings
    if gaps:
        return "No findings were produced by the completed checks, but coverage gaps remain. This is not proof of absence."
    return "No findings were produced by the completed checks. Static analysis still cannot prove that no defects exist."


def _finding_lines(document: Mapping[str, Any], maximum: int) -> list[str]:
    rows = document.get("findings") if type(document.get("findings")) is list else []
    lines = []
    for row in rows[:maximum]:
        if type(row) is not dict:
            continue
        location = "%s:%s" % (_text(row.get("path", "workspace"), 300), row.get("line", 1))
        confidence = row.get("confidence_calibration")
        if type(confidence) is dict and confidence.get("state") == "calibrated":
            evidence = "empirical %.0f%% (%d labels)" % (
                100 * float(confidence.get("calibrated_probability", 0)),
                int(confidence.get("samples", 0)))
        else:
            score = row.get("confidence")
            evidence = "detector score %s; not empirically calibrated" % (
                "%.0f%%" % (100 * float(score)) if isinstance(score, (int, float)) else "unknown")
        lines.append("- [%s] %s at %s — %s (%s)" % (
            _text(row.get("severity", "MEDIUM"), 20).upper(),
            _text(row.get("rule", "finding"), 180), location,
            _text(row.get("message", "Observed evidence requires review."), 600), evidence))
    if len(rows) > maximum:
        lines.append("- %d additional finding(s) remain in the structured report." % (len(rows) - maximum))
    return lines


def _repair_lines(document: Mapping[str, Any]) -> list[str]:
    rows = document.get("improvements") if type(document.get("improvements")) is list else []
    accepted = [row for row in rows if type(row) is dict and row.get("accepted") is True]
    plans = [row for row in rows if type(row) is dict and
             row.get("status") == "plan-only-review-required"]
    refused = [row for row in rows if type(row) is dict and row.get("accepted") is not True and
               row.get("status") != "plan-only-review-required"]
    lines = ["- Verified candidate: %s" % _text(row.get("target", "workspace"), 300)
             for row in accepted[:MAX_ACTIONS]]
    for row in plans[:MAX_ACTIONS - len(lines)]:
        guidance = row.get("suggested_result")
        first = guidance[0] if type(guidance) is list and guidance else \
            "Review the evidence and construct a gated candidate."
        lines.append("- Review-only improvement plan for %s: %s" % (
            _text(row.get("target", "workspace"), 300), _text(first, 700)))
    if refused:
        lines.append("- %d candidate(s) were refused because their configured proof gates did not all pass." % len(refused))
    return lines


def _gap_lines(document: Mapping[str, Any]) -> list[str]:
    coverage = document.get("coverage") if type(document.get("coverage")) is dict else {}
    gaps = coverage.get("gaps") if type(coverage.get("gaps")) is list else []
    lines = ["- " + _text(value, 600) for value in gaps[:MAX_GAPS]]
    if coverage.get("absence_proven") is not True:
        lines.append("- Absence of all defects was not proven.")
    execution = document.get("execution") if type(document.get("execution")) is dict else {}
    if execution.get("sandbox_state") in {"unavailable", "refused", "unknown"}:
        lines.append("- Kernel-isolated execution was %s; no weaker sandbox was silently substituted." %
                     _text(execution.get("sandbox_state"), 40))
    return list(dict.fromkeys(lines))


def _next_actions(document: Mapping[str, Any]) -> list[str]:
    priorities = document.get("priorities") if type(document.get("priorities")) is list else []
    lines = []
    for row in priorities[:MAX_ACTIONS]:
        if type(row) is dict:
            action = _text(row.get("fix") or row.get("message"), 600)
            if action:
                lines.append("- %s" % action)
    if not lines and document.get("findings"):
        lines.append("- Review the highest-severity evidence and authorize a transactional repair run when ready.")
    return list(dict.fromkeys(lines))


def _component_lines(document: Mapping[str, Any]) -> list[str]:
    summary = document.get("summary") if type(document.get("summary")) is dict else {}
    lines = []
    engineering = document.get("engineering")
    if type(engineering) is dict:
        state = _text(engineering.get("status", "unknown"), 40)
        count = summary.get("engineering_findings", 0)
        digest = "digest-verified" if engineering.get("report_sha256") else "no component digest"
        lines.append("- Engineering Intelligence: %s; %s finding(s); %s." %
                     (state, count if type(count) is int else "unknown", digest))
    security = document.get("security_fabric")
    if type(security) is dict:
        state = _text(security.get("status", "unknown"), 40)
        count = summary.get("security_fabric_findings", 0)
        security_summary = security.get("summary") if type(security.get("summary")) is dict else {}
        risk = _text(security_summary.get("risk_label", "not-rated"), 40)
        digest = "digest-verified" if security.get("report_sha256") else "no component digest"
        lines.append("- Security Fabric: %s; %s finding(s); risk %s; %s." %
                     (state, count if type(count) is int else "unknown", risk, digest))
    return lines


def render_guarded(document: Mapping[str, Any], style: str = "professional", *,
                   truth_key: bytes | None = None) -> str:
    """Render only a valid Truth Guard 2.1 document; otherwise abstain safely."""
    if style not in STYLES:
        raise ValueError("unknown Attestor 4.0 response style")
    verification = truth_guard40.verify_guarded(document, key=truth_key)
    if not verification.get("ok"):
        return ("Attestor 4.0 withheld the result because its evidence ledger did not verify. "
                "Re-run the analysis instead of relying on this output.")
    audit = document["truth_guard2"]
    if audit.get("status") == "refuted":
        return ("Attestor 4.0 withheld the result because Truth Guard 2.1 found a "
                "contradiction in its structured claims. Re-run the analysis instead "
                "of relying on this output.")
    severity = _severity(document)
    compact = style in {"concise", "executive", "direct"}
    finding_limit = 5 if compact else MAX_FINDINGS
    title = {
        "mentor": "Here is what the evidence supports",
        "direct": "Evidence-backed result",
        "executive": "Decision summary",
        "classic": "ATTESTOR 4.0 EVIDENCE REPORT",
    }.get(style, "Attestor 4.0 evidence-backed result")
    signature = audit.get("signature") if type(audit.get("signature")) is dict else {}
    authentication = ("HMAC-SHA256 authenticated as %s" % _text(
        signature.get("key_id", "unknown-key"), 80)) if verification.get("authenticated") \
        else "integrity-verified only; not authenticated for a trust boundary"
    lines = [title, "=" * len(title), "", _outcome(document), "",
             "Severity: %d critical, %d high, %d medium, %d low/info." % (
                 severity["CRITICAL"], severity["HIGH"], severity["MEDIUM"],
                 severity["LOW"] + severity["INFO"]),
             "Truth Guard 2.1: %s; %s; %d grounded, %d unknown, %d refuted, %d contradiction(s)." % (
                 audit.get("status", "unknown"), authentication,
                 audit.get("summary", {}).get("grounded", 0),
                 audit.get("summary", {}).get("unknown", 0),
                 audit.get("summary", {}).get("refuted", 0),
                 audit.get("summary", {}).get("contradictions", 0))]
    findings = _finding_lines(document, finding_limit)
    components = _component_lines(document)
    if components:
        lines.extend(["", "Attestor 4.0 engine evidence", "------------------------", *components])
    if findings:
        lines.extend(["", "Observed findings", "-----------------", *findings])
    repairs = _repair_lines(document)
    if repairs:
        lines.extend(["", "Repair evidence", "---------------", *repairs])
    gaps = _gap_lines(document)
    if gaps:
        lines.extend(["", "Limits and unknowns", "-------------------", *gaps])
    actions = _next_actions(document)
    if actions:
        lines.extend(["", "Next actions", "------------", *actions])
    lines.extend(["", "Evidence ledger: %s (%d entries)." % (
        audit.get("evidence_chain_sha256", "unknown"), audit.get("evidence_catalog_size", 0))])
    return "\n".join(lines)
