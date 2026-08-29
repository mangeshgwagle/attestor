#!/usr/bin/env python3
"""Clear, outcome-first response composition for Attestor 3.0."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping

import secret_guard


STYLES = ("professional", "concise", "mentor", "direct", "executive", "classic")
FINDING_ACTIONS = {
    "workspace", "audit", "securitymax", "cybermayhem", "cyber", "polyglot",
    "grade", "nativegrade", "rarebugs", "gauntlet", "qualitygate", "mayhem",
}
MAX_RESPONSE_CHARS = 256 * 1024
MAX_IMPROVED_PREVIEW_CHARS = 24 * 1024
ABSOLUTE_SAFETY_RX = re.compile(
    r"(?i)(?:\b(?:completely|fully|perfectly)\s+(?:secure|safe|correct)\b|"
    r"\bno\s+(?:remaining\s+)?(?:vulnerabilities|bugs|errors)\b|"
    r"\ball\s+(?:vulnerabilities|bugs|errors)\s+(?:are\s+)?(?:fixed|gone|resolved)\b)"
)


@dataclass(frozen=True)
class ResponseSummary:
    outcome: str
    status: str
    action: str
    code: int
    counts: dict[str, int]
    next_step: str
    limitation: str


def _trusted_counts(evidence: Mapping | None) -> dict[str, int]:
    """Read measurements only from an explicitly validated envelope."""
    if not isinstance(evidence, Mapping) or evidence.get("validated") is not True:
        return {}
    values = evidence.get("counts", {})
    if not isinstance(values, Mapping):
        return {}
    out = {}
    for key, value in values.items():
        if (isinstance(key, str) and isinstance(value, int)
                and not isinstance(value, bool) and 0 <= value <= 10_000_000):
            out[key.upper()] = value
    return out


def summarize(text: str, code: int, action: str,
              evidence: Mapping | None = None) -> ResponseSummary:
    action = action or "request"
    counts = _trusted_counts(evidence)
    operational_errors = (evidence.get("operational_errors", [])
                          if isinstance(evidence, Mapping) and evidence.get("validated") is True
                          else [])
    if operational_errors:
        status = "failed"
        outcome = "Attestor could not establish a trustworthy %s result." % action.replace("_", " ")
        next_step = "Resolve the first validated operational error, then rerun the same command."
    elif code == 0:
        status = "completed"
        outcome = "Attestor completed %s." % action.replace("_", " ")
        next_step = "Review the evidence and keep the relevant checks in CI."
    elif action in FINDING_ACTIONS and counts.get("FINDINGS", 0) > 0:
        status = "action-required"
        amount = counts["FINDINGS"]
        outcome = "Attestor completed %s and reported %d item(s) requiring review." % (
            action.replace("_", " "), amount)
        next_step = "Fix CRITICAL/HIGH items first, add a regression test, then rerun the same gate."
    else:
        status = "unverified"
        outcome = ("Attestor returned exit %d for %s, but no validated evidence envelope classified "
                   "that exit as findings or an operational failure.") % (
                       code, action.replace("_", " "))
        next_step = "Inspect the raw output, then rerun through a structured Attestor 3 evidence mode."
    limitation = ("Results describe the enabled checks and observed evidence; they are not proof "
                  "that no other defect or vulnerability exists.")
    return ResponseSummary(outcome, status, action, int(code), counts, next_step, limitation)


def _bounded(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_RESPONSE_CHARS:
        return text, False
    return text[:MAX_RESPONSE_CHARS] + "\n[response truncated at %d characters]" % MAX_RESPONSE_CHARS, True


def _guard_absolute_claims(text: str) -> str:
    lines = []
    for line in text.splitlines():
        lower = line.lower()
        qualified = any(boundary in lower for boundary in (
            "not proof", "cannot prove", "does not prove", "not proven", "unproven",
            "not completely", "never claim",
        ))
        if ABSOLUTE_SAFETY_RX.search(line) and not qualified:
            lines.append("[unsupported absolute safety claim withheld; absence is not proven]")
        else:
            lines.append(line)
    return "\n".join(lines)


def wrap_text(text: str, code: int, action: str = "request",
              style: str = "professional", evidence: Mapping | None = None,
              model_assisted: bool = False) -> str:
    if style not in STYLES:
        raise ValueError("unknown response style: %s" % style)
    if style == "classic":
        guarded = _guard_absolute_claims(text or "")
        if secret_guard.scan_text(guarded, "response.txt"):
            return "[credential-like material withheld by Attestor Truth Guard]"
        return guarded
    raw_detail = _guard_absolute_claims(text or "(no detail was produced)")
    if secret_guard.scan_text(raw_detail, "response.txt"):
        raw_detail = ("[credential-like material withheld by Attestor Truth Guard; "
                      "the secret value is not retained in this response]")
    detail, truncated = _bounded(raw_detail)
    summary = summarize(detail, code, action, evidence=evidence)
    count_text = ", ".join("%s=%d" % item for item in summary.counts.items())
    if style == "concise":
        lines = ["Outcome: " + summary.outcome]
        if count_text:
            lines.append("Counts: " + count_text)
        lines += ["\n" + detail, "\nNext: " + summary.next_step]
        return "\n".join(lines)
    if style == "executive":
        lines = ["Executive outcome", "=================", summary.outcome,
                 "Status: " + summary.status]
        if count_text:
            lines.append("Measured signal: " + count_text)
        lines += ["Decision: " + summary.next_step, "",
                  "Technical evidence", "------------------", detail,
                  "", "Assurance boundary: " + summary.limitation]
        return "\n".join(lines)
    if style == "mentor":
        lead = (summary.outcome + " The useful move now is to work from the strongest evidence "
                "downward, making one verified change at a time.")
    elif style == "direct":
        lead = summary.outcome + " No theatre—here is the evidence and what to do next."
    else:
        lead = summary.outcome
    lines = ["Outcome", "=======", lead]
    if count_text:
        lines += ["", "Measured results: " + count_text]
    lines += ["", "Evidence", "========", detail,
              "", "Next action", "===========", summary.next_step,
              "", "Assurance", "=========", summary.limitation]
    if truncated:
        lines.append("The displayed detail was bounded; use a machine-readable export for the full artifact.")
    if model_assisted:
        lines.append("Model output is a candidate, not factual evidence; only its deterministic gate level is asserted.")
    return "\n".join(lines)


def _safe_text(value, fallback: str = "") -> str:
    text = str(value if value is not None else fallback)
    if secret_guard.scan_text(text, "report-field.txt"):
        return "[REDACTED: credential-like material]"
    return text


def _redact_value(value, path: str = "report"):
    if isinstance(value, Mapping):
        return {str(key): _redact_value(item, path + "." + str(key))
                for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, path + "[]") for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item, path + "[]") for item in value]
    if isinstance(value, str) and secret_guard.scan_text(value, path + ".txt"):
        return "[REDACTED: credential-like material]"
    return value


def _proved_improvement(row) -> tuple[bool, list[str]]:
    """Require the complete deterministic proof bundle before saying VERIFIED."""
    reasons = []
    if not isinstance(row, Mapping):
        return False, ["improvement is not an object"]
    if row.get("accepted") is not True:
        reasons.append("accepted must be the boolean true")
    verification = row.get("verification")
    if not isinstance(verification, Mapping) or verification.get("accepted") is not True:
        reasons.append("verification bundle is missing or refused")
        verification = {}
    if verification.get("compiler_or_parser") != "verified":
        reasons.append("parser/compiler verification is missing")
    if verification.get("new_findings"):
        reasons.append("verification reports new findings")
    if verification.get("new_failures"):
        reasons.append("verification reports new failures")
    probes = row.get("probes")
    if not isinstance(probes, list) or not probes or any(
            not isinstance(probe, Mapping) or probe.get("status") != "passed" for probe in probes):
        reasons.append("required assurance probes are missing or failed")
    selected = row.get("selected_tests", {})
    if isinstance(selected, Mapping) and selected.get("status") in {"failed", "timed-out"}:
        reasons.append("selected tests failed")
    source = row.get("improved_source")
    if not isinstance(source, str) or not source:
        reasons.append("improved source is absent")
    elif secret_guard.scan_text(source, str(row.get("target", "improved-source"))):
        reasons.append("improved source contains credential-like material")
    try:
        resolved = int(row.get("resolved_count", -1))
        remaining = int(row.get("remaining_count", -1))
    except (TypeError, ValueError):
        reasons.append("repair counts are invalid")
    else:
        if resolved != len(verification.get("resolved_findings", [])):
            reasons.append("resolved count contradicts verification evidence")
        if remaining != verification.get("findings_after"):
            reasons.append("remaining count contradicts verification evidence")
    if row.get("reasons"):
        reasons.append("improvement contains refusal reasons")
    return not reasons, reasons


def structured(report: dict, style: str = "professional") -> str:
    """Render a Mayhem/security-style report without losing machine truth."""
    if style == "classic":
        return json.dumps(_redact_value(report), indent=2, sort_keys=True)
    if style not in STYLES:
        raise ValueError("unknown response style: %s" % style)
    if not isinstance(report, Mapping):
        raise TypeError("structured report must be a mapping")
    status = _safe_text(report.get("status", "unknown"), "unknown")[:80]
    readiness = report.get("readiness", report.get("risk", {}))
    readiness = readiness if isinstance(readiness, Mapping) else {}
    score = readiness.get("score")
    label = _safe_text(readiness.get("label", status))
    summary = dict(report.get("summary", {})) if isinstance(report.get("summary"), Mapping) else {}
    priorities = report.get("priorities", report.get("recommendations", []))
    priorities = priorities if isinstance(priorities, list) else []
    all_findings = report.get("findings", [])
    all_findings = all_findings if isinstance(all_findings, list) else []
    findings = report.get("top_findings", all_findings)
    findings = findings if isinstance(findings, list) else []
    improvements = report.get("improvements", report.get("improved_results", []))
    improvements = improvements if isinstance(improvements, list) else []
    integrity = []
    if all_findings and isinstance(summary.get("findings"), int) \
            and summary["findings"] != len(all_findings):
        integrity.append("summary finding count contradicted the canonical finding list; recomputed")
        summary["findings"] = len(all_findings)
    if status.lower() == "clean" and (all_findings or report.get("errors")):
        integrity.append("clean status contradicted findings or operational errors")
        status = "inconsistent"
    if status.lower() == "clean" and summary.get("files_scanned") == 0:
        integrity.append("clean status had zero scanned files")
        status = "no-evidence"
    if status.lower() == "clean":
        status = "no-findings-from-enabled-checks"
    if style == "executive":
        limit = 5
    elif style == "concise":
        limit = 6
    else:
        limit = 12
    outcome = "Attestor finished with evidence status %s" % status
    if score is not None:
        outcome += " and score %s/100 (%s)" % (score, label)
    outcome += "."
    lines = ["Outcome", "=======", outcome, ""]
    if summary:
        lines += ["Measured results", "================"]
        for key, value in summary.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                lines.append("- %s: %s" % (
                    _safe_text(key).replace("_", " "), _safe_text(value)))
        lines.append("")
    lines += ["Fix first", "========="]
    if not priorities:
        lines.append("- No prioritized change was produced by the enabled checks.")
    for row in priorities[:limit]:
        if isinstance(row, str):
            lines.append("- " + _safe_text(row))
        elif isinstance(row, Mapping):
            priority = row.get("priority", row.get("severity", "REVIEW"))
            message = row.get("fix", row.get("message", row.get("category", "review")))
            lines.append("- [%s] %s" % (_safe_text(priority), _safe_text(message)))
    if findings:
        lines += ["", "Highest-priority evidence", "========================="]
        for row in findings[:limit]:
            if not isinstance(row, Mapping):
                continue
            lines.append("- [%s] %s:%s %s — %s" % (
                _safe_text(row.get("severity", "REVIEW")),
                _safe_text(row.get("path", "workspace")),
                _safe_text(row.get("line", 1)),
                _safe_text(row.get("rule", "finding")),
                _safe_text(row.get("message", row.get("detail", "review required")))))
    proved_improvements = []
    refused_improvements = []
    for item in improvements:
        proof_ok, proof_reasons = _proved_improvement(item)
        (proved_improvements if proof_ok else refused_improvements).append(
            (item, proof_reasons))
    if proved_improvements:
        lines += ["", "Verified improved results", "========================="]
        for row, _proof_reasons in proved_improvements[:limit]:
            if not isinstance(row, dict):
                continue
            target = row.get("target", row.get("path", "source"))
            accepted = True
            resolved = row.get("resolved_count", row.get("resolved", 0))
            remaining = row.get("remaining_count", row.get("remaining", 0))
            lines.append("- %s: %s; resolved=%s; remaining=%s" % (
                _safe_text(target), "VERIFIED", resolved, remaining))
            reasons = row.get("reasons", row.get("reason", []))
            if isinstance(reasons, str):
                reasons = [reasons]
            for reason in list(reasons or [])[:4]:
                lines.append("  - " + _safe_text(reason))
            improved = row.get("improved_source", row.get("improved", ""))
            diff = row.get("diff", "")
            if accepted and isinstance(improved, str) and improved:
                preview = improved[:MAX_IMPROVED_PREVIEW_CHARS]
                lines += ["", "  Improved source:", "  ----------------", preview]
                if len(improved) > len(preview):
                    lines.append("  [improved source preview truncated; use JSON or --improved-out for the full artifact]")
            elif isinstance(diff, str) and diff:
                preview = diff[:MAX_IMPROVED_PREVIEW_CHARS]
                lines += ["", "  Candidate diff:", "  ---------------", preview]
                if len(diff) > len(preview):
                    lines.append("  [diff preview truncated; use JSON for the full artifact]")
    if refused_improvements:
        lines += ["", "Refused or unverified improvements", "=================================="]
        for row, proof_reasons in refused_improvements[:limit]:
            target = row.get("target", row.get("path", "source")) \
                if isinstance(row, Mapping) else "source"
            lines.append("- %s: REFUSED" % _safe_text(target))
            for reason in proof_reasons[:4]:
                lines.append("  - " + _safe_text(reason))
    elif not proved_improvements and summary.get(
            "findings", summary.get("actionable_findings", 0)):
        lines += ["", "Improved result", "===============",
                  "- No change was presented as safe by the enabled deterministic fixers. "
                  "The findings remain actionable evidence; use Attestor 3.0 verified improvement "
                  "to generate and prove a candidate result."]
    notes = report.get("assurance", report.get("assurance_notes", []))
    if notes:
        lines += ["", "Assurance boundary", "=================="]
        lines.extend("- " + _safe_text(note) for note in notes)
    if integrity:
        lines += ["", "Report integrity", "================"]
        lines.extend("- " + item for item in integrity)
    lines += ["", "Truth boundary", "==============",
              "- No findings means no findings from enabled checks over observed artifacts; "
              "it is not proof that no other defect or vulnerability exists."]
    if style == "direct":
        lines.insert(3, "No padding: fix the highest-risk evidence, prove the repair, rerun the gate.")
    elif style == "mentor":
        lines.insert(3, "Work top-down: understand one finding, make the smallest safe change, and lock it in with a test.")
    return "\n".join(lines)
