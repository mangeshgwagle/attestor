#!/usr/bin/env python3
"""Attestor 3.5 universal proof ledger and independent report verifier.

Truth Guard 2 turns a JSON-shaped result into a redacted, content-addressed
evidence ledger.  It re-evaluates machine-checkable claims with the independent
3.0 validator, records contradictions explicitly, and binds the public document
to both a source digest and a chained evidence digest.  It never calls a model,
network, shell, importer, target program, or filesystem writer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

import truth_guard


VERSION = "3.5.0"
SCHEMA = "attestor.truth-guard/2.0"
MAX_DEPTH = 24
MAX_LEAVES = 20_000
MAX_CLAIMS = 2_000
MAX_TEXT = 4_000
MAX_DOCUMENT_NODES = 500_000
MAX_INDEPENDENT_NODES = truth_guard.MAX_INPUT_NODES
MAX_PROJECTED_FINDINGS = 4_000
MAX_PROJECTED_IMPROVEMENTS = 1_000
MAX_PROJECTED_GAPS = 4_000
_ABSOLUTE_SAFETY = re.compile(
    r"(?i)\b(?:completely secure|guaranteed safe|no vulnerabilities|no bugs|"
    r"no errors(?: exist| remain)?|100\s*%\s*(?:safe|secure)|zero risk)\b")
_GUARD_KEYS = frozenset({"truth_guard", "truth_guard_runtime", "truth_guard2",
                         "report_sha256", "view_sha256", "source_report_sha256"})


class TruthGuard35Error(ValueError):
    pass


def _document_node_count(value: Any, *, maximum: int = MAX_DOCUMENT_NODES,
                         boundary: str = "document") -> int:
    """Validate and count JSON nodes before any recursive redaction.

    Truth Guard 1 intentionally accepts no more than 100,000 nodes.  A guarded
    3.5 document may be larger because it contains several already-bounded
    analyzer reports, so the full document has its own hard 500,000-node limit.
    Only a compact, digest-bound view is sent to the older independent
    validator when that smaller limit would otherwise be exceeded.
    """
    if (isinstance(maximum, bool) or not isinstance(maximum, int) or
            maximum < 1):
        raise TruthGuard35Error("node boundary is invalid")
    seen: set[int] = set()
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > maximum:
            raise TruthGuard35Error(
                "%s exceeds the %d-node hard boundary" % (boundary, maximum))
        if depth > MAX_DEPTH:
            raise TruthGuard35Error(
                "%s exceeds the %d-level nesting boundary" %
                (boundary, MAX_DEPTH))
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise TruthGuard35Error(
                    "%s contains a non-finite number" % boundary)
            return
        if type(item) not in {dict, list, tuple}:
            raise TruthGuard35Error(
                "%s contains a non-JSON value" % boundary)
        marker = id(item)
        if marker in seen:
            raise TruthGuard35Error("%s contains a cyclic value" % boundary)
        seen.add(marker)
        if type(item) is dict:
            if any(not isinstance(key, str) for key in item):
                raise TruthGuard35Error(
                    "%s contains a non-string object key" % boundary)
            for key in sorted(item):
                visit(item[key], depth + 1)
        else:
            for child in item:
                visit(child, depth + 1)
        seen.remove(marker)

    visit(value, 0)
    return nodes


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _clean_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if type(document) is not dict:
        raise TruthGuard35Error("guarded document must be a JSON object")
    clean = {str(key): value for key, value in document.items()
             if str(key) not in _GUARD_KEYS and not str(key).startswith("_")}
    _document_node_count(clean)
    try:
        redacted = truth_guard.redact_tree(clean, _validated=True)
        encoded = _canonical(redacted)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise TruthGuard35Error("document is not bounded JSON evidence") from exc
    if len(encoded) > 16 * 1024 * 1024:
        raise TruthGuard35Error("document exceeds the 16 MiB public evidence boundary")
    return redacted


def _project_finding(row: Any) -> dict[str, Any] | None:
    """Retain exactly the scalar finding fields Truth Guard 1 consumes."""
    if type(row) is not dict:
        return None
    projected: dict[str, Any] = {}
    for key in ("rule", "rule_id", "ruleId", "path", "line",
                "severity", "fingerprint"):
        value = row.get(key)
        if value is None or isinstance(value, (str, bool, int, float)):
            if key in row:
                projected[key] = value
    return projected


def _project_refused_improvement(row: Any) -> dict[str, Any] | None:
    """Retain refusals; accepted repairs require their complete proof objects."""
    if type(row) is not dict or row.get("accepted") is True:
        return None
    projected: dict[str, Any] = {}
    for key in ("target", "path", "status", "accepted", "complete"):
        value = row.get(key)
        if value is None or isinstance(value, (str, bool, int, float)):
            if key in row:
                projected[key] = value
    return projected


def _independent_validation_view(
        document: Mapping[str, Any], source_nodes: int
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    """Return a replayable bounded view for the older independent validator."""
    source_sha256 = _sha(document)
    raw_findings = document.get("findings")
    findings = raw_findings if type(raw_findings) is list else []
    raw_improvements = document.get("improvements")
    improvements = raw_improvements if type(raw_improvements) is list else []
    coverage = document.get("coverage") \
        if type(document.get("coverage")) is dict else {}
    raw_gaps = coverage.get("gaps")
    gaps = raw_gaps if type(raw_gaps) is list else []
    source_counts = {
        "findings": len(findings),
        "improvements": len(improvements),
        "gaps": len(gaps),
    }

    if source_nodes <= MAX_INDEPENDENT_NODES:
        metadata = {
            "projected": False,
            "source_document_sha256": source_sha256,
            "source_node_count_lower_bound": source_nodes,
            "source_node_count_exact": True,
            "source_node_hard_limit": MAX_DOCUMENT_NODES,
            "independent_node_limit": MAX_INDEPENDENT_NODES,
            "view_node_count": source_nodes,
            "view_sha256": source_sha256,
            "collections": {
                name: {"source": count, "retained": count, "omitted": 0}
                for name, count in sorted(source_counts.items())
            },
            "reason": (
                "full clean document is within the independent-validator "
                "node boundary"),
        }
        return document, metadata

    projected_findings = []
    for row in findings:
        projected = _project_finding(row)
        if projected is not None:
            projected_findings.append(projected)
        if len(projected_findings) >= MAX_PROJECTED_FINDINGS:
            break

    projected_improvements = []
    for row in improvements:
        projected = _project_refused_improvement(row)
        if projected is not None:
            projected_improvements.append(projected)
        if len(projected_improvements) >= MAX_PROJECTED_IMPROVEMENTS:
            break

    projected_gaps = [
        item for item in gaps
        if item is None or isinstance(item, (str, bool, int, float))
    ][:MAX_PROJECTED_GAPS]
    severity_names = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    projected_summary = {
        "findings": len(projected_findings),
        "severity": {
            name: sum(
                str(row.get("severity", "")).upper() == name
                for row in projected_findings)
            for name in severity_names
        },
        "verified_improvements": 0,
        "refused_improvements": len(projected_improvements),
    }
    view: dict[str, Any] = {}
    for key in ("schema", "version", "root", "status"):
        value = document.get(key)
        if value is None or isinstance(value, (str, bool, int, float)):
            if key in document:
                view[key] = value
    view.update({
        "summary": projected_summary,
        "findings": projected_findings,
        "improvements": projected_improvements,
        "coverage": {
            "absence_proven": False,
            "gaps": projected_gaps,
            "independent_validation_projected": True,
        },
    })
    view_nodes = _document_node_count(
        view, maximum=MAX_INDEPENDENT_NODES,
        boundary="independent validation view")
    retained_counts = {
        "findings": len(projected_findings),
        "improvements": len(projected_improvements),
        "gaps": len(projected_gaps),
    }
    metadata = {
        "projected": True,
        "source_document_sha256": source_sha256,
        "source_node_count_lower_bound": source_nodes,
        "source_node_count_exact": True,
        "source_node_hard_limit": MAX_DOCUMENT_NODES,
        "independent_node_limit": MAX_INDEPENDENT_NODES,
        "view_node_count": view_nodes,
        "view_sha256": _sha(view),
        "collections": {
            name: {
                "source": source_counts[name],
                "retained": retained_counts[name],
                "omitted": source_counts[name] - retained_counts[name],
            }
            for name in sorted(source_counts)
        },
        "reason": (
            "full clean document exceeds the independent-validator node "
            "boundary; independent claims use a deterministic exact-field "
            "projection while full-document integrity remains bound"),
    }
    return view, metadata


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _leaves(value: Any, pointer: str = "", depth: int = 0) -> Iterable[tuple[str, Any]]:
    if depth > MAX_DEPTH:
        yield pointer or "/", "<depth-limit>"
        return
    if type(value) is dict:
        for key in sorted(value):
            yield from _leaves(value[key], pointer + "/" + _pointer_escape(str(key)), depth + 1)
        return
    if type(value) in {list, tuple}:
        for index, item in enumerate(value):
            yield from _leaves(item, pointer + "/" + str(index), depth + 1)
        if not value:
            yield pointer or "/", []
        return
    if isinstance(value, float) and not math.isfinite(value):
        yield pointer or "/", "<non-finite>"
    elif value is None or isinstance(value, (bool, int, float, str)):
        yield pointer or "/", value[:MAX_TEXT] if isinstance(value, str) else value
    else:
        yield pointer or "/", "<unsupported>"


def build_evidence_chain(document: Mapping[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Return a deterministic hash chain over redacted scalar evidence."""
    rows: list[dict[str, Any]] = []
    previous = "0" * 64
    truncated = False
    for index, (pointer, value) in enumerate(_leaves(document)):
        if index >= MAX_LEAVES:
            truncated = True
            break
        value_hash = _sha(value)
        body = {"pointer": pointer, "value_sha256": value_hash,
                "previous_sha256": previous}
        entry_hash = _sha(body)
        row = {"id": "ev35-" + entry_hash[:24], **body,
               "entry_sha256": entry_hash}
        rows.append(row)
        previous = entry_hash
    return rows, truncated


def verify_evidence_chain(rows: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(rows) is not list or len(rows) > MAX_LEAVES:
        return False, ["evidence chain is absent, malformed, or oversized"]
    previous = "0" * 64
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if type(row) is not dict:
            errors.append("evidence entry %d is not an object" % index)
            continue
        pointer = str(row.get("pointer", ""))
        body = {"pointer": pointer,
                "value_sha256": str(row.get("value_sha256", "")),
                "previous_sha256": previous}
        expected = _sha(body)
        if row.get("previous_sha256") != previous:
            errors.append("evidence chain predecessor mismatch at %d" % index)
        if row.get("entry_sha256") != expected:
            errors.append("evidence entry digest mismatch at %d" % index)
        if row.get("id") != "ev35-" + expected[:24] or row.get("id") in seen:
            errors.append("evidence identity mismatch at %d" % index)
        seen.add(str(row.get("id", "")))
        previous = expected
    return not errors, errors


def _claim(claim: Mapping[str, Any], *, state: str, reason: str,
           evidence_ids: Iterable[str] = ()) -> dict[str, Any]:
    body = {"kind": str(claim.get("kind", "statement")),
            "text": str(claim.get("text", ""))[:MAX_TEXT],
            "state": state, "reason": reason,
            "evidence_ids": sorted(set(str(item) for item in evidence_ids if item))}
    body["id"] = "clm35-" + _sha(body)[:24]
    return body


def _independent_claims(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    findings = document.get("findings") if type(document.get("findings")) is list else []
    for row in findings[:MAX_CLAIMS // 2]:
        if type(row) is dict:
            claims.append({"kind": "finding", "text": "%s at %s:%s" % (
                row.get("rule", "finding"), row.get("path", ""), row.get("line", "")),
                "path": row.get("path", ""), "line": row.get("line"),
                "rule": row.get("rule", "")})
    improvements = document.get("improvements") \
        if type(document.get("improvements")) is list else []
    for row in improvements[:MAX_CLAIMS // 2]:
        if type(row) is dict:
            claims.append({"kind": "improvement",
                           "text": "%s improvement for %s" % (
                               "verified" if row.get("accepted") is True else "refused",
                               row.get("target", "workspace")),
                           "target": row.get("target", "workspace"),
                           "expected": "verified" if row.get("accepted") is True else "refused"})
    status = str(document.get("status", "unknown"))
    if not findings and status in {"clean", "complete", "secure"}:
        claims.append({"kind": "coverage", "text": "coverage supports " + status,
                       "scope": "scan", "expected": "complete"})
    return claims[:MAX_CLAIMS]


def _document_root(document: Mapping[str, Any]) -> Path | None:
    """Resolve only an existing report root for independent location checks."""
    raw = document.get("root")
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    try:
        path = Path(raw).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if path.is_file():
        # Do not widen an exact-file report into permission to inspect siblings.
        return None
    return path if path.is_dir() else None


def assess(document: Mapping[str, Any]) -> dict[str, Any]:
    clean = _clean_document(document)
    source_nodes = _document_node_count(clean)
    validation_view, validation_metadata = _independent_validation_view(
        clean, source_nodes)
    chain, truncated = build_evidence_chain(clean)
    evidence_ids = [row["id"] for row in chain]
    v1 = truth_guard.validate_claims(
        _independent_claims(validation_view), validation_view,
        root=_document_root(clean))
    independent_evidence = []
    for row in v1.get("evidence_catalog", [])[:MAX_LEAVES]:
        if type(row) is not dict:
            continue
        evidence_body = {
            "id": str(row.get("id", ""))[:80],
            "kind": str(row.get("kind", "evidence"))[:80],
            "pointer": str(row.get("pointer", ""))[:MAX_TEXT],
            # Store a digest rather than possibly sensitive file/value evidence.
            "value_sha256": _sha(row.get("value")),
            "redacted": row.get("redacted") is True,
            "truncated": row.get("truncated") is True,
        }
        if evidence_body["id"]:
            independent_evidence.append(evidence_body)
    independent_evidence.sort(key=lambda row: row["id"])
    valid_evidence_ids = {row["id"] for row in independent_evidence}
    claims = []
    for row in v1.get("claims", []):
        state = str(row.get("state", "unknown"))
        claims.append(_claim(row, state=state,
                             reason=str(row.get("reason", "independent validation")),
                             evidence_ids=[item for item in row.get("evidence_refs", ())[:8]
                                           if item in valid_evidence_ids]))
    for row in v1.get("numeric_checks", []):
        numeric_state = str(row.get("state", "unknown"))
        consistent = numeric_state == "consistent"
        contradicted = numeric_state in {"contradiction", "refuted", "inconsistent"}
        claims.append(_claim({
            "kind": "count",
            "text": "%s reported %s; independently derived %s" % (
                row.get("reported_path", "count"), row.get("reported"),
                row.get("derived")),
        }, state="derived" if consistent else "refuted" if contradicted else "unknown",
            reason="reported and independently derived counts match" if consistent else
            "reported count contradicts the structured collection" if contradicted else
            "the corresponding structured collection was unavailable",
            evidence_ids=[item for item in row.get("evidence_refs", ())[:8]
                          if item in valid_evidence_ids]))
    status_text = str(clean.get("status", ""))
    if _ABSOLUTE_SAFETY.search(status_text):
        claims.append(_claim({"kind": "status", "text": status_text}, state="refuted",
                             reason="absolute safety status is not evidence-bounded"))
    accepted = sum(row["state"] in {"observed", "derived"} for row in claims)
    refuted = sum(row["state"] == "refuted" for row in claims)
    unknown = sum(row["state"] == "unknown" for row in claims)
    contradictions = list(v1.get("contradictions", []))
    state = "verified" if (
        not refuted and not unknown and not contradictions and not truncated
        and validation_metadata["projected"] is False
    ) \
        else "refuted" if refuted or contradictions else "partial"
    return {
        "schema": SCHEMA, "version": VERSION, "status": state,
        "source_document_sha256": _sha(clean),
        "independent_validation": validation_metadata,
        "evidence_chain": chain,
        "evidence_chain_sha256": _sha(chain),
        "evidence_truncated": truncated,
        "independent_evidence": independent_evidence,
        "independent_evidence_sha256": _sha(independent_evidence),
        "claims": claims,
        "summary": {"claims": len(claims), "grounded": accepted,
                    "refuted": refuted, "unknown": unknown,
                    "contradictions": len(contradictions)},
        "contradictions": contradictions[:256],
        "execution": {"model": False, "network": False, "shell": False,
                      "target_code": False, "filesystem_writes": False},
        "evidence_catalog_size": len(evidence_ids) + len(independent_evidence),
    }


def _signature_payload(audit: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in audit.items() if key != "signature"}


def guard_document(document: Mapping[str, Any], *, key: bytes | None = None,
                   key_id: str = "") -> dict[str, Any]:
    clean = _clean_document(document)
    audit = assess(clean)
    if key is not None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise TruthGuard35Error("HMAC key must contain at least 32 bytes")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", key_id or ""):
            raise TruthGuard35Error("signed ledgers require a bounded key id")
        value = hmac.new(key, _canonical(_signature_payload(audit)), hashlib.sha256).hexdigest()
        audit["signature"] = {"algorithm": "hmac-sha256", "key_id": key_id,
                              "value": value, "state": "signed"}
    else:
        audit["signature"] = {"algorithm": "none", "key_id": "", "value": "",
                              "state": "integrity-only-not-authenticated"}
    public = {**clean, "truth_guard2": audit}
    public["report_sha256"] = _sha(public)
    return public


def verify_guarded(document: Mapping[str, Any], *, key: bytes | None = None) -> dict[str, Any]:
    errors: list[str] = []
    if type(document) is not dict or type(document.get("truth_guard2")) is not dict:
        return {"ok": False, "status": "invalid", "errors": ["Truth Guard 2 ledger is absent"]}
    audit = document["truth_guard2"]
    clean = _clean_document(document)
    expected_report = _sha({key_name: value for key_name, value in document.items()
                            if key_name != "report_sha256"})
    if document.get("report_sha256") != expected_report:
        errors.append("public report digest mismatch")
    if audit.get("source_document_sha256") != _sha(clean):
        errors.append("source document digest mismatch")
    # Re-run the independent assessor.  Without this comparison an attacker
    # could alter claim states or contradiction counts and recompute only the
    # unauthenticated outer report digest.
    rebuilt_audit = assess(clean)
    actual_unsigned_audit = {name: value for name, value in audit.items()
                             if name != "signature"}
    if actual_unsigned_audit != rebuilt_audit:
        errors.append("claim audit does not match independent reassessment")
    rebuilt, rebuilt_truncated = build_evidence_chain(clean)
    if audit.get("evidence_chain") != rebuilt or audit.get("evidence_truncated") != rebuilt_truncated:
        errors.append("evidence chain does not match the public document")
    valid_chain, chain_errors = verify_evidence_chain(audit.get("evidence_chain"))
    if not valid_chain:
        errors.extend(chain_errors)
    if audit.get("evidence_chain_sha256") != _sha(audit.get("evidence_chain", [])):
        errors.append("evidence-chain aggregate digest mismatch")
    if audit.get("independent_evidence_sha256") != _sha(
            audit.get("independent_evidence", [])):
        errors.append("independent-evidence aggregate digest mismatch")
    available_ids = {str(row.get("id", "")) for row in audit.get("evidence_chain", [])
                     if type(row) is dict}
    available_ids.update(str(row.get("id", "")) for row in
                         audit.get("independent_evidence", []) if type(row) is dict)
    if any(ref not in available_ids for claim in audit.get("claims", [])
           if type(claim) is dict for ref in claim.get("evidence_ids", [])):
        errors.append("claim references evidence outside the guarded catalogs")
    signature = audit.get("signature") if type(audit.get("signature")) is dict else {}
    algorithm = signature.get("algorithm")
    if algorithm == "hmac-sha256":
        if key is None:
            errors.append("signed ledger key was not supplied")
        else:
            unsigned = {name: value for name, value in audit.items() if name != "signature"}
            expected = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(signature.get("value", "")), expected):
                errors.append("ledger signature mismatch")
    elif algorithm != "none":
        errors.append("unsupported ledger signature algorithm")
    elif key is not None:
        errors.append("authentication key was supplied for an unsigned ledger")
    authenticated = algorithm == "hmac-sha256" and not errors
    return {"ok": not errors,
            "status": ("authenticated" if authenticated else "integrity-verified")
            if not errors else "invalid",
            "integrity_verified": not errors,
            "authenticated": authenticated,
            "errors": errors}


def guard_output(mode: str, output: Any, *, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Universal mode adapter; free-form output needs a validated envelope."""
    if type(output) is dict:
        return guard_document(output)
    if type(evidence) is dict and evidence.get("validated") is True \
            and type(evidence.get("document")) is dict:
        document = dict(evidence["document"])
        document["mode"] = str(mode)[:80]
        document["response"] = str(output)[:64 * 1024]
        return guard_document(document)
    return guard_document({
        "mode": str(mode)[:80], "status": "abstained",
        "response": "I cannot substantiate free-form output without a validated evidence envelope.",
        "coverage": {"absence_proven": False,
                     "gaps": ["validated evidence envelope was not supplied"]},
    })


def deterministic_json(document: Mapping[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False,
                      allow_nan=False)
