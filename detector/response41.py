#!/usr/bin/env python3
"""Grounded, evidence-state responses and report-scoped Q&A for Attestor 4.1.3."""
from __future__ import annotations

import re
from typing import Any, Mapping

import truth_guard41


VERSION = "4.1.3"
STYLES = ("professional", "concise", "mentor", "direct", "executive", "classic", "technical")
MAX_FINDINGS = 50
MAX_GAPS = 20

_BIDI_CONTROLS = frozenset({
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
})


def _text(value: Any, maximum: int = 1_000) -> str:
    """Return bounded single-line text that cannot steer a terminal display."""
    safe: list[str] = []
    for character in str(value or ""):
        codepoint = ord(character)
        if character in _BIDI_CONTROLS or codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            if character in "\t\r\n":
                safe.append(" ")
            elif codepoint <= 0xFF:
                safe.append("\\x%02x" % codepoint)
            else:
                safe.append("\\u%04x" % codepoint)
        else:
            safe.append(character)
        if len(safe) >= maximum:
            break
    return "".join(safe)


def _verify(document: Mapping[str, Any], *, root=None, key: bytes | None = None) -> dict[str, Any]:
    return truth_guard41.verify_guarded(document, root=root, key=key, require_fresh=True)


def build_fact_model(document: Mapping[str, Any], *, root=None,
                     truth_key: bytes | None = None) -> dict[str, Any]:
    verification = _verify(document, root=root, key=truth_key)
    if not verification.get("ok"):
        return {"verified": False, "verification": verification, "claims": [],
                "evidence": {}, "gaps": []}
    ledger = document["truth_guard3"]
    bindings = ledger.get("finding_evidence") if isinstance(ledger.get("finding_evidence"), list) else []
    finding_rows = document.get("findings") if isinstance(document.get("findings"), list) else []
    bindable_findings = [row for row in finding_rows if isinstance(row, Mapping)]
    claims, catalog = [], {}
    severity_counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    bound_total = 0
    for evidence_index, (finding, binding) in enumerate(zip(bindable_findings, bindings)):
        if not isinstance(binding, Mapping) or binding.get("state") != "bound":
            continue
        bound_total += 1
        severity = _text(finding.get("severity", "MEDIUM"), 20).upper()
        if severity not in severity_counts:
            severity = "MEDIUM"
        severity_counts[severity] += 1
        if len(claims) >= MAX_FINDINGS:
            continue
        citation = "E%d" % (evidence_index + 1)
        source = binding.get("source") if isinstance(binding.get("source"), Mapping) else {}
        claim = {
            "citation": citation,
            "kind": "finding",
            "rule": _text(finding.get("rule") or finding.get("rule_id"), 300),
            "severity": severity,
            "path": _text(finding.get("path"), 2_000),
            "line": int(finding.get("line", 1)) if str(finding.get("line", 1)).isdigit() else 1,
            "message": _text(finding.get("message"), 1_000),
            "fix": _text(finding.get("fix") or finding.get("remediation"), 1_000),
            "evidence_state": (
                finding.get("evidence_state")
                if finding.get("evidence_state") in
                {"proven", "inferred", "unverified", "unavailable"}
                else "inferred"
            ),
            "source_binding": "proven",
        }
        claims.append(claim)
        catalog[citation] = {
            "path": _text(source.get("path"), 2_000),
            "byte_range": [source.get("byte_start", 0), source.get("byte_end", 0)],
            "file_sha256": _text(source.get("file_sha256"), 64),
            "snippet_sha256": _text(source.get("snippet_sha256"), 64),
            "rule_sha256": _text(binding.get("rule_sha256"), 64),
            "config_sha256": _text(binding.get("config_sha256"), 64),
            "analyzer_sha256": _text(binding.get("analyzer_sha256"), 64),
            "input_manifest_sha256": _text(binding.get("input_manifest_sha256"), 64),
            "evidence_sha256": _text(binding.get("evidence_sha256"), 64),
        }
    coverage = document.get("coverage") if isinstance(document.get("coverage"), Mapping) else {}
    coverage_records = [coverage] if coverage else []
    for name in ("engineering", "security_fabric", "semantic_graph_41"):
        section = document.get(name)
        if isinstance(section, Mapping) and isinstance(section.get("coverage"), Mapping):
            coverage_records.append(section["coverage"])
    gaps: list[Any] = []
    for record in coverage_records:
        if isinstance(record.get("gaps"), list):
            gaps.extend(record["gaps"])
        if isinstance(record.get("limitations"), list):
            gaps.extend(record["limitations"])
    complete_states = [record.get("complete") is True for record in coverage_records]
    status = _text(document.get("status", "unknown"), 80)
    command_center: dict[str, Any] = {}
    raw_center = document.get("security_command_center_413")
    if (isinstance(raw_center, Mapping) and
            raw_center.get("schema") == "attestor-security-command-center/4.1" and
            raw_center.get("version") == VERSION):
        metrics = raw_center.get("metrics") \
            if isinstance(raw_center.get("metrics"), Mapping) else {}
        claim_states = metrics.get("claim_states") \
            if isinstance(metrics.get("claim_states"), Mapping) else {}

        def count(name: str) -> int:
            value = metrics.get(name, 0)
            return value if type(value) is int and 0 <= value <= 1_000_000 else 0

        command_center = {
            "status": _text(raw_center.get("status"), 120),
            "attack_paths": count("attack_paths"),
            "coverage_gaps": count("coverage_gaps"),
            "repair_status": _text(raw_center.get("repair_status"), 120),
            "repair_proof_state": _text(
                raw_center.get("repair_proof_state"), 120),
            "regression_status": _text(
                raw_center.get("regression_status"), 120),
            "claim_states": {
                state: (
                    claim_states.get(state, 0)
                    if type(claim_states.get(state, 0)) is int and
                    0 <= claim_states.get(state, 0) <= 1_000_000 else 0)
                for state in ("proven", "inferred", "unverified", "unavailable")
            },
            "automatic_apply": raw_center.get("automatic_apply") is True,
            "permission_retained": raw_center.get("permission_retained") is True,
            "integrity": "bound-by-fresh-truth-guard-report",
        }
    return {
        "verified": True, "verification": verification, "claims": claims,
        "evidence": catalog, "status": status,
        "coverage_complete": bool(complete_states) and all(complete_states) and not gaps,
        "absence_proven": coverage.get("absence_proven") is True,
        "gaps": [_text(value.get("message") if isinstance(value, Mapping) else value, 800)
                 for value in gaps[:MAX_GAPS]],
        "report_sha256": _text(ledger.get("report_sha256"), 64),
        "manifest_sha256": _text(ledger.get("input_manifest_sha256"), 64),
        "authentication": "authenticated-shared-key" if verification.get("authenticated") else "integrity-only",
        "authentication_gap": _text(verification.get("authentication_gap"), 1_000),
        "bound_findings": bound_total, "claims_truncated": bound_total > len(claims),
        "severity_counts": severity_counts,
        "security_command_center": command_center,
    }


def _claim_line(claim: Mapping[str, Any]) -> str:
    location = "%s:%s" % (claim["path"], claim["line"])
    return "- [%s] %s at %s — %s (evidence: %s; source binding: %s) [%s]" % (
        claim["severity"], claim["rule"], location,
        claim["message"] or "The detector recorded this finding.",
        claim["evidence_state"], claim["source_binding"], claim["citation"])


def _source_line(citation: str, evidence: Mapping[str, Any]) -> str:
    byte_range = evidence.get("byte_range", [0, 0])
    return ("- [%s] %s bytes %s..%s; file `%s`; snippet `%s`; rule `%s`; "
            "config `%s`; analyzer `%s`; manifest `%s`.") % (
        citation, evidence.get("path", ""), byte_range[0], byte_range[1],
        evidence.get("file_sha256", ""), evidence.get("snippet_sha256", ""),
        evidence.get("rule_sha256", ""), evidence.get("config_sha256", ""),
        evidence.get("analyzer_sha256", ""), evidence.get("input_manifest_sha256", ""))


def render_guarded(document: Mapping[str, Any], style: str = "professional", *,
                   root=None, truth_key: bytes | None = None) -> str:
    """Render the same verified facts in several presentation styles."""
    if style not in STYLES:
        raise ValueError("unknown Attestor 4.1.3 response style")
    facts = build_fact_model(document, root=root, truth_key=truth_key)
    if not facts["verified"]:
        state = facts["verification"].get("status", "invalid")
        return ("Attestor 4.1.3 withheld this response because Truth Guard 3 classified "
                "the evidence as %s. Re-run the analysis against the current source." % state)
    if facts.get("status", "").casefold() == "inconsistent":
        return ("Attestor 4.1.3 withheld this response because the replay-valid report "
                "declares an inconsistent fallback result. Resolve the conflicting "
                "producer outputs and re-run the analysis.")
    title = {
        "professional": "Attestor 4.1.3 evidence report",
        "concise": "Verified result",
        "mentor": "What the verified evidence supports",
        "direct": "Source-bound result",
        "executive": "Evidence decision brief",
        "classic": "ATTESTOR 4.1.3 TRUTH GUARD 3 REPORT",
        "technical": "Attestor 4.1.3 replay-verified evidence",
    }[style]
    finding_count = facts["bound_findings"]
    if finding_count:
        outcome = "%d source-bound finding(s) are present in this report." % finding_count
    elif not facts["coverage_complete"]:
        outcome = "No finding is present, but coverage is partial; absence is not established."
    else:
        outcome = "No finding is present in the completed bounded checks; this is not a universal safety claim."
    lines = [title, "=" * len(title), "", outcome,
             "Report `%s`; input manifest `%s`; %s." % (
                 facts["report_sha256"], facts["manifest_sha256"], facts["authentication"])]
    center = facts.get("security_command_center", {})
    if center:
        claim_states = center["claim_states"]
        lines.extend([
            "",
            "Security command center",
            "-----------------------",
            "- Status: %s; static attack paths: %d; coverage gaps: %d [R1]." % (
                center["status"], center["attack_paths"], center["coverage_gaps"]),
            "- Claim states: %d proven, %d inferred, %d unverified, %d unavailable [R1]." % (
                claim_states["proven"], claim_states["inferred"],
                claim_states["unverified"], claim_states["unavailable"]),
            "- Repair: %s (%s); regression: %s [R1]." % (
                center["repair_status"], center["repair_proof_state"],
                center["regression_status"]),
            "- Automatic apply: %s; permission retained: %s [R1]." % (
                "enabled" if center["automatic_apply"] else "disabled",
                "yes" if center["permission_retained"] else "no"),
        ])
    if facts["claims"]:
        lines.extend(["", "Claims and citations", "--------------------"])
        lines.extend(_claim_line(claim) for claim in facts["claims"])
        if facts["claims_truncated"]:
            lines.append("- %d additional source-bound finding(s) omitted by the response boundary [R1]." %
                         (finding_count - len(facts["claims"])))
    if facts["gaps"] or not facts["coverage_complete"]:
        lines.extend(["", "Coverage and unknowns", "---------------------"])
        lines.extend("- " + gap for gap in facts["gaps"])
        if not facts["coverage_complete"]:
            lines.append("- Coverage is incomplete or not proven complete [R1].")
    lines.extend(["", "Evidence catalog", "----------------"])
    lines.extend(_source_line(citation, facts["evidence"][citation])
                 for citation in sorted(facts["evidence"], key=lambda value: int(value[1:])))
    lines.append("- [R1] Guarded report `%s`; manifest `%s`." % (
        facts["report_sha256"], facts["manifest_sha256"]))
    if facts["authentication_gap"]:
        lines.extend(["", "Authentication limit", "--------------------",
                      "- " + facts["authentication_gap"]])
    return "\n".join(lines)


def _matching_claims(facts: Mapping[str, Any], question: str) -> list[dict[str, Any]]:
    lowered = question.casefold()
    tokens = {token for token in re.findall(r"[a-z0-9_.-]{3,}", lowered)
              if token not in {"what", "where", "which", "about", "finding", "findings",
                               "error", "errors", "code", "does", "this", "report"}}
    rows = []
    for claim in facts.get("claims", []):
        haystack = " ".join(_text(claim.get(key), 2_000).casefold()
                            for key in ("rule", "severity", "path", "message", "fix"))
        if tokens and any(token in haystack for token in tokens):
            rows.append(claim)
    return rows


def answer_question(document: Mapping[str, Any], question: str, *,
                    root=None, truth_key: bytes | None = None) -> dict[str, Any]:
    """Answer only questions whose answer is present in the guarded report."""
    if not isinstance(question, str) or not question.strip() or len(question) > 2_000:
        raise ValueError("question must be bounded non-empty text")
    facts = build_fact_model(document, root=root, truth_key=truth_key)
    if not facts["verified"]:
        return {"answered": False, "answer": "The report evidence did not replay-verify.",
                "citations": [], "scope": "report-only",
                "abstained_reason": facts["verification"].get("status", "invalid")}
    if facts.get("status", "").casefold() == "inconsistent":
        return {"answered": False,
                "answer": "The report declares inconsistent producer results, so Attestor withheld an answer.",
                "citations": [], "scope": "report-only",
                "abstained_reason": "inconsistent-report"}
    lowered = question.casefold()
    claims = list(facts["claims"])
    if re.search(r"\b(how many|count|number of)\b", lowered) and re.search(r"\b(findings?|errors?|issues?)\b", lowered):
        severities = [name for name in ("critical", "high", "medium", "low", "info") if name in lowered]
        if severities:
            count = sum(facts["severity_counts"].get(name.upper(), 0) for name in severities)
            selected = [row for row in claims if row["severity"].casefold() in severities]
        else:
            count, selected = facts["bound_findings"], claims
        citations = [row["citation"] for row in selected]
        if count > len(selected):
            citations.append("R1")
        return {"answered": True, "answer": "%d matching source-bound finding(s)." % count,
                "citations": citations or ["R1"], "scope": "report-only", "abstained_reason": ""}
    if re.search(r"\b(safe|secure|no bugs?|clean)\b", lowered):
        answer = ("The report cannot establish that the target is safe or bug-free. "
                  + ("Coverage is incomplete." if not facts["coverage_complete"] else
                     "Only the completed bounded checks are represented."))
        return {"answered": True, "answer": answer, "citations": ["R1"],
                "scope": "report-only", "abstained_reason": ""}
    center = facts.get("security_command_center", {})
    if center and re.search(r"\battack\s+paths?\b", lowered):
        return {
            "answered": True,
            "answer": (
                "%d bounded static attack path(s) are recorded; these are not "
                "runtime exploit proofs." % center["attack_paths"]),
            "citations": ["R1"], "scope": "report-only",
            "abstained_reason": "",
        }
    if center and (
            re.search(r"\b(auto(?:matic(?:ally)?)?\s*apply|apply automatically)\b",
                      lowered) or
            re.search(r"\bpermission\b", lowered)):
        return {
            "answered": True,
            "answer": (
                "Automatic apply is %s and permission retention is %s in the "
                "verified report." % (
                    "enabled" if center["automatic_apply"] else "disabled",
                    "enabled" if center["permission_retained"] else "disabled")),
            "citations": ["R1"], "scope": "report-only",
            "abstained_reason": "",
        }
    if center and re.search(r"\b(repair|regression)\b", lowered):
        return {
            "answered": True,
            "answer": "Repair status is %s (%s); regression status is %s." % (
                center["repair_status"], center["repair_proof_state"],
                center["regression_status"]),
            "citations": ["R1"], "scope": "report-only",
            "abstained_reason": "",
        }
    matches = _matching_claims(facts, question)
    if matches:
        rows = matches[:5]
        wants_fix = bool(re.search(r"\b(fix|repair|remediat|improv)\w*\b", lowered))
        if wants_fix:
            answer = " ".join("%s: %s" % (row["rule"], row["fix"] or
                              "No verified remediation text is present.") for row in rows)
        else:
            answer = " ".join("%s at %s:%s: %s" % (
                row["rule"], row["path"], row["line"], row["message"]) for row in rows)
        return {"answered": True, "answer": answer,
                "citations": [row["citation"] for row in rows],
                "scope": "report-only", "abstained_reason": ""}
    return {"answered": False,
            "answer": "The verified report does not contain evidence to answer that question.",
            "citations": [], "scope": "report-only",
            "abstained_reason": "not-present-in-report"}


__all__ = ["STYLES", "build_fact_model", "render_guarded", "answer_question"]
