#!/usr/bin/env python3
"""Bounded, evidence-aware finding adjudication for Attestor 4.1.4.

The module is deliberately standalone and input-scoped.  It does not inspect a
target, execute code, contact a network, suppress a finding, or claim that an
uncovered area is safe.  It preserves every supplied finding and adds one of
three conservative labels:

``supported``
    At least one linked supporting evidence item exists, with no contesting
    evidence or structured contradiction.
``contested``
    Contesting evidence or a structured contradiction exists.  This is a
    review signal, not proof that the finding is a false positive.
``insufficient``
    No linked decisive evidence is available.

Contradictions are detected only from explicit finding references, mixed
support/contest evidence, or disagreeing structured ``claim_key`` /
``claim_value`` pairs in the same location.  The implementation intentionally
avoids guessing from natural-language messages.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import math
import re
from typing import Any, Mapping, Sequence


SCHEMA = "attestor-adjudication/4.1.4"
VERSION = "4.1.4"

SUPPORTED = "supported"
CONTESTED = "contested"
INSUFFICIENT = "insufficient"
CLASSIFICATIONS = frozenset({SUPPORTED, CONTESTED, INSUFFICIENT})

MAX_FINDINGS = 2_048
MAX_EVIDENCE = 8_192
MAX_RISK_AREAS = 2_048
MAX_CONTRADICTIONS = 4_096
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_ITEM_BYTES = 256 * 1024
MAX_TEXT_BYTES = 128 * 1024
MAX_REFERENCE_BYTES = 1_024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES_PER_ITEM = 32_768
MAX_CONTAINER_ITEMS = 8_192
MAX_INTEGER_MAGNITUDE = (1 << 63) - 1


class AdjudicationError(ValueError):
    """An input or resource boundary prevents safe adjudication."""


@dataclass(frozen=True)
class Limits:
    """Caller-selectable ceilings that may only tighten compiled boundaries."""

    max_findings: int = MAX_FINDINGS
    max_evidence: int = MAX_EVIDENCE
    max_risk_areas: int = MAX_RISK_AREAS
    max_contradictions: int = MAX_CONTRADICTIONS
    max_total_input_bytes: int = MAX_TOTAL_INPUT_BYTES
    max_report_bytes: int = MAX_REPORT_BYTES


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class _Prepared:
    ref: str
    original: dict[str, Any]
    encoded: bytes
    digest: str


_LIMIT_CAPS = {
    "max_findings": MAX_FINDINGS,
    "max_evidence": MAX_EVIDENCE,
    "max_risk_areas": MAX_RISK_AREAS,
    "max_contradictions": MAX_CONTRADICTIONS,
    "max_total_input_bytes": MAX_TOTAL_INPUT_BYTES,
    "max_report_bytes": MAX_REPORT_BYTES,
}
_STANCE_ALIASES = {
    "support": "support",
    "supported": "support",
    "supports": "support",
    "confirm": "support",
    "confirmed": "support",
    "confirms": "support",
    "corroborate": "support",
    "corroborates": "support",
    "contest": "contest",
    "contested": "contest",
    "contests": "contest",
    "contradict": "contest",
    "contradicts": "contest",
    "refute": "contest",
    "refuted": "contest",
    "refutes": "contest",
    "false-positive": "contest",
    "false_positive": "contest",
}
_COVERED_ALIASES = frozenset({
    "covered", "tested", "analyzed", "analysed", "verified",
})
_UNCOVERED_ALIASES = frozenset({
    "uncovered", "untested", "unanalyzed", "unanalysed", "not-covered",
    "not_covered",
})
_HIGH_RISK_ALIASES = frozenset({"critical", "high", "severe"})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TOP_LEVEL_KEYS = frozenset({
    "schema", "version", "status", "policy", "summary", "findings",
    "evidence", "risk_areas", "contradictions",
    "uncovered_high_risk_areas", "unfamiliar_high_risk_areas",
    "coverage", "execution", "limitations", "report_sha256",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> str:
    """Return Attestor's canonical JSON spelling for a JSON-compatible value."""
    return _canonical(value).decode("utf-8")


def _validate_limits(limits: Limits) -> Limits:
    if type(limits) is not Limits:
        raise AdjudicationError("limits must be an exact Limits value")
    for field in fields(Limits):
        value = getattr(limits, field.name)
        cap = _LIMIT_CAPS[field.name]
        minimum = 1 if field.name in {
            "max_total_input_bytes", "max_report_bytes",
        } else 0
        if type(value) is not int or not minimum <= value <= cap:
            raise AdjudicationError(
                "%s must be between %d and %d" %
                (field.name, minimum, cap))
    return limits


def _validate_json(
        value: Any,
        *,
        depth: int = 0,
        ancestors: set[int] | None = None,
        ) -> int:
    if depth > MAX_JSON_DEPTH:
        raise AdjudicationError("JSON input exceeds the nesting boundary")
    if value is None or type(value) is bool:
        return 1
    if type(value) is int:
        if abs(value) > MAX_INTEGER_MAGNITUDE:
            raise AdjudicationError("integer is outside the interoperable boundary")
        return 1
    if type(value) is float:
        if not math.isfinite(value):
            raise AdjudicationError("non-finite numbers are not accepted")
        return 1
    if type(value) is str:
        try:
            encoded_value = value.encode("utf-8")
        except UnicodeError as exc:
            raise AdjudicationError(
                "text is not valid Unicode") from exc
        if len(encoded_value) > MAX_TEXT_BYTES:
            raise AdjudicationError("text exceeds the per-value byte boundary")
        return 1
    if type(value) not in {list, dict}:
        raise AdjudicationError(
            "inputs must contain only exact JSON value types")

    active = set() if ancestors is None else ancestors
    identity = id(value)
    if identity in active:
        raise AdjudicationError("cyclic JSON input is not accepted")
    if len(value) > MAX_CONTAINER_ITEMS:
        raise AdjudicationError("JSON container exceeds its item boundary")
    active.add(identity)
    nodes = 1
    try:
        if type(value) is list:
            for item in value:
                nodes += _validate_json(
                    item, depth=depth + 1, ancestors=active)
                if nodes > MAX_JSON_NODES_PER_ITEM:
                    raise AdjudicationError(
                        "JSON input exceeds its node boundary")
        else:
            for key, item in value.items():
                if type(key) is not str:
                    raise AdjudicationError(
                        "mapping keys must be exact strings")
                try:
                    encoded_key = key.encode("utf-8")
                except UnicodeError as exc:
                    raise AdjudicationError(
                        "mapping key is not valid Unicode") from exc
                if len(encoded_key) > MAX_REFERENCE_BYTES:
                    raise AdjudicationError(
                        "mapping key exceeds its byte boundary")
                nodes += 1
                nodes += _validate_json(
                    item, depth=depth + 1, ancestors=active)
                if nodes > MAX_JSON_NODES_PER_ITEM:
                    raise AdjudicationError(
                        "JSON input exceeds its node boundary")
    finally:
        active.remove(identity)
    return nodes


def _sequence(
        value: Sequence[Mapping[str, Any]],
        *,
        name: str,
        maximum: int,
        ) -> list[dict[str, Any]]:
    if type(value) not in {list, tuple}:
        raise AdjudicationError("%s must be a bounded list or tuple" % name)
    if len(value) > maximum:
        raise AdjudicationError(
            "%s exceeds its %d-item boundary" % (name, maximum))
    rows: list[dict[str, Any]] = []
    for item in value:
        if type(item) is not dict:
            raise AdjudicationError("%s entries must be exact mappings" % name)
        _validate_json(item)
        encoded = _canonical(item)
        if len(encoded) > MAX_ITEM_BYTES:
            raise AdjudicationError(
                "%s entry exceeds its byte boundary" % name)
        rows.append(json.loads(encoded.decode("utf-8")))
    return rows


def _prepare(kind: str, rows: list[dict[str, Any]]) -> list[_Prepared]:
    ordered = sorted((_canonical(row), row) for row in rows)
    occurrences: dict[str, int] = {}
    result: list[_Prepared] = []
    for encoded, row in ordered:
        digest = _sha(encoded)
        occurrences[digest] = occurrences.get(digest, 0) + 1
        result.append(_Prepared(
            ref="%s-%s-%04d" % (
                kind, digest, occurrences[digest]),
            original=row,
            encoded=encoded,
            digest=digest,
        ))
    return result


def _coalesced_text(
        row: Mapping[str, Any],
        keys: Sequence[str],
        *,
        label: str,
        ) -> str | None:
    values: list[str] = []
    for key in keys:
        if key not in row:
            continue
        value = row[key]
        if type(value) is not str or not value:
            raise AdjudicationError("%s must be a non-empty string" % label)
        if len(value.encode("utf-8")) > MAX_REFERENCE_BYTES:
            raise AdjudicationError("%s exceeds its byte boundary" % label)
        values.append(value)
    if not values:
        return None
    if any(value != values[0] for value in values[1:]):
        raise AdjudicationError("%s fields disagree" % label)
    return values[0]


def _source_finding_id(row: Mapping[str, Any]) -> str | None:
    return _coalesced_text(
        row, ("finding_id", "id"), label="finding identifier")


def _evidence_target_id(row: Mapping[str, Any]) -> str | None:
    return _coalesced_text(
        row, ("finding_id", "target_finding_id"),
        label="evidence finding identifier")


def _optional_locator_text(
        row: Mapping[str, Any], keys: Sequence[str],
        ) -> str | None:
    for key in keys:
        value = row.get(key)
        if type(value) is str and value:
            return value
    return None


def _optional_locator_line(row: Mapping[str, Any]) -> int | None:
    for key in ("line", "line_number"):
        value = row.get(key)
        if type(value) is int and value >= 1:
            return value
    return None


def _locator(row: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    rule = _optional_locator_text(row, ("rule", "rule_id", "check_id"))
    path = _optional_locator_text(row, ("path", "file", "filename"))
    symbol = _optional_locator_text(row, ("symbol", "function"))
    line = _optional_locator_line(row)
    if rule is not None:
        result["rule"] = rule
    if path is not None:
        result["path"] = path
    if symbol is not None:
        result["symbol"] = symbol
    if line is not None:
        result["line"] = line
    return result


def _locator_is_decisive(locator: Mapping[str, Any]) -> bool:
    return (
        len(locator) >= 2 and
        ("path" in locator or "rule" in locator)
    )


def _stance(row: Mapping[str, Any]) -> tuple[str, str]:
    normalized: list[str] = []
    supplied = False
    unrecognized = False
    for key in ("stance", "verdict", "effect"):
        if key not in row:
            continue
        supplied = True
        value = row[key]
        if type(value) is not str:
            raise AdjudicationError(
                "evidence %s must be a string" % key)
        alias = _STANCE_ALIASES.get(value.strip().casefold())
        if alias is not None:
            normalized.append(alias)
        else:
            unrecognized = True
    if "supports" in row:
        supplied = True
        supports = row["supports"]
        if type(supports) is not bool:
            raise AdjudicationError(
                "evidence supports must be an exact boolean")
        normalized.append("support" if supports else "contest")
    distinct = set(normalized)
    if len(distinct) > 1:
        return "unknown", "conflicting-stance-fields"
    if unrecognized:
        return "unknown", "unrecognized-stance-field"
    if distinct:
        return normalized[0], "recognized-stance"
    return "unknown", (
        "unrecognized-stance" if supplied else "stance-not-supplied")


def _contradiction_targets(row: Mapping[str, Any]) -> list[str]:
    if "contradicts" not in row:
        return []
    raw = row["contradicts"]
    values = [raw] if type(raw) is str else raw
    if type(values) is not list:
        raise AdjudicationError(
            "finding contradicts must be a string or list of strings")
    targets: list[str] = []
    for value in values:
        if type(value) is not str or not value:
            raise AdjudicationError(
                "finding contradiction targets must be non-empty strings")
        if len(value.encode("utf-8")) > MAX_REFERENCE_BYTES:
            raise AdjudicationError(
                "finding contradiction target exceeds its byte boundary")
        targets.append(value)
    return sorted(set(targets))


def _claim(
        row: Mapping[str, Any],
        ) -> tuple[str, dict[str, Any], Any] | None:
    if "claim_key" not in row:
        return None
    key = row["claim_key"]
    if type(key) is not str or not key:
        raise AdjudicationError("claim_key must be a non-empty string")
    if len(key.encode("utf-8")) > MAX_REFERENCE_BYTES:
        raise AdjudicationError("claim_key exceeds its byte boundary")
    if "claim_value" not in row:
        raise AdjudicationError("claim_key requires claim_value")
    value = row["claim_value"]
    if value is not None and type(value) not in {bool, int, float, str}:
        raise AdjudicationError(
            "claim_value must be a JSON scalar")
    scope = _locator(row)
    return key, scope, value


def _claim_value_token(value: Any) -> bytes:
    # JSON spells 1 and 1.0 differently, but treating them as contradictory
    # would create noise when two engines serialize the same numeric claim
    # differently.  Booleans remain distinct from numbers.
    if type(value) is int:
        return _canonical(["number", value])
    if type(value) is float:
        normalized: int | float = value
        if value.is_integer() and abs(value) <= MAX_INTEGER_MAGNITUDE:
            normalized = int(value)
        return _canonical(["number", normalized])
    return _canonical([type(value).__name__, value])


def _risk_state(
        row: Mapping[str, Any],
        ) -> tuple[bool, str, str, bool]:
    high = False
    if "high_risk" in row:
        if type(row["high_risk"]) is not bool:
            raise AdjudicationError("high_risk must be an exact boolean")
        high = row["high_risk"]
    for key in ("severity", "risk"):
        if key not in row:
            continue
        value = row[key]
        if type(value) is not str:
            raise AdjudicationError("%s must be a string" % key)
        high = high or value.strip().casefold() in _HIGH_RISK_ALIASES

    coverage_claims: list[str] = []
    if "covered" in row:
        if type(row["covered"]) is not bool:
            raise AdjudicationError("covered must be an exact boolean")
        coverage_claims.append(
            "covered" if row["covered"] else "uncovered")
    if "coverage" in row:
        value = row["coverage"]
        if type(value) is not str:
            raise AdjudicationError("coverage must be a string")
        normalized = value.strip().casefold()
        if normalized in _COVERED_ALIASES:
            coverage_claims.append("covered")
        elif normalized in _UNCOVERED_ALIASES:
            coverage_claims.append("uncovered")
        else:
            coverage_claims.append("unknown")
    distinct_coverage = set(coverage_claims)
    conflict = (
        "covered" in distinct_coverage and
        "uncovered" in distinct_coverage
    )
    if conflict:
        coverage = "unknown"
    elif "unknown" in distinct_coverage:
        coverage = "unknown"
    elif "covered" in distinct_coverage:
        coverage = "covered"
    elif "uncovered" in distinct_coverage:
        coverage = "uncovered"
    else:
        coverage = "unknown"

    if "familiar" in row:
        if type(row["familiar"]) is not bool:
            raise AdjudicationError("familiar must be an exact boolean")
        familiarity = "familiar" if row["familiar"] else "unfamiliar"
    else:
        familiarity = "unknown"
    return high, coverage, familiarity, conflict


def _gap(
        gaps: list[dict[str, Any]],
        code: str,
        count: int,
        message: str,
        ) -> None:
    if count:
        gaps.append({"code": code, "count": count, "message": message})


def _dedupe_rows(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical(row): row for row in rows}
    return [unique[key] for key in sorted(unique)]


def adjudicate(
        findings: Sequence[Mapping[str, Any]],
        evidence: Sequence[Mapping[str, Any]] = (),
        high_risk_areas: Sequence[Mapping[str, Any]] = (),
        *,
        limits: Limits = DEFAULT_LIMITS,
        ) -> dict[str, Any]:
    """Adjudicate bounded generic inputs without inspecting or executing a target."""
    selected_limits = _validate_limits(limits)
    finding_values = _sequence(
        findings, name="findings", maximum=selected_limits.max_findings)
    evidence_values = _sequence(
        evidence, name="evidence", maximum=selected_limits.max_evidence)
    risk_values = _sequence(
        high_risk_areas, name="high_risk_areas",
        maximum=selected_limits.max_risk_areas)
    input_bytes = len(_canonical({
        "findings": finding_values,
        "evidence": evidence_values,
        "high_risk_areas": risk_values,
    }))
    if input_bytes > selected_limits.max_total_input_bytes:
        raise AdjudicationError(
            "combined input exceeds its byte boundary")

    prepared_findings = _prepare("finding", finding_values)
    prepared_evidence = _prepare("evidence", evidence_values)
    prepared_risks = _prepare("area", risk_values)

    finding_by_ref = {item.ref: item for item in prepared_findings}
    source_ids: dict[str, list[str]] = {}
    locators: dict[str, dict[str, Any]] = {}
    for item in prepared_findings:
        source_id = _source_finding_id(item.original)
        if source_id is not None:
            source_ids.setdefault(source_id, []).append(item.ref)
        locators[item.ref] = _locator(item.original)

    evidence_rows: list[dict[str, Any]] = []
    support_by_finding: dict[str, list[str]] = {
        item.ref: [] for item in prepared_findings}
    contest_by_finding: dict[str, list[str]] = {
        item.ref: [] for item in prepared_findings}
    unknown_stance = 0
    unlinked_evidence = 0
    ambiguous_evidence = 0

    for item in prepared_evidence:
        stance, stance_reason = _stance(item.original)
        target_id = _evidence_target_id(item.original)
        matched: list[str] = []
        link_reason = "target-not-supplied"
        if target_id is not None:
            if target_id in finding_by_ref:
                matched = [target_id]
                link_reason = "internal-finding-reference"
            else:
                matched = list(source_ids.get(target_id, []))
                link_reason = (
                    "source-finding-identifier" if len(matched) == 1
                    else "ambiguous-source-finding-identifier"
                    if len(matched) > 1 else
                    "source-finding-identifier-not-found"
                )
        else:
            query = _locator(item.original)
            if _locator_is_decisive(query):
                for finding_ref, candidate in locators.items():
                    if all(candidate.get(key) == value
                           for key, value in query.items()):
                        matched.append(finding_ref)
                link_reason = (
                    "structured-locator" if len(matched) == 1
                    else "ambiguous-structured-locator"
                    if len(matched) > 1 else
                    "structured-locator-not-found"
                )

        link_status = (
            "linked" if len(matched) == 1 else
            "ambiguous" if len(matched) > 1 else
            "unlinked"
        )
        if link_status == "linked":
            finding_ref = matched[0]
            if stance == "support":
                support_by_finding[finding_ref].append(item.ref)
            elif stance == "contest":
                contest_by_finding[finding_ref].append(item.ref)
        elif link_status == "ambiguous":
            ambiguous_evidence += 1
        else:
            unlinked_evidence += 1
        if stance == "unknown":
            unknown_stance += 1
        evidence_rows.append({
            "evidence_ref": item.ref,
            "stance": stance,
            "stance_reason": stance_reason,
            "link_status": link_status,
            "link_reason": link_reason,
            "finding_refs": sorted(matched),
            "original_evidence": item.original,
        })

    contradiction_rows: list[dict[str, Any]] = []
    contradiction_findings: set[str] = set()
    unresolved_contradiction_references = 0
    unscoped_claims = 0

    for finding_ref, item in finding_by_ref.items():
        support_refs = sorted(support_by_finding[finding_ref])
        contest_refs = sorted(contest_by_finding[finding_ref])
        if support_refs and contest_refs:
            contradiction_rows.append({
                "kind": "mixed-evidence",
                "finding_refs": [finding_ref],
                "evidence_refs": sorted([*support_refs, *contest_refs]),
                "detail": (
                    "supporting and contesting evidence target the same finding"),
            })
            contradiction_findings.add(finding_ref)

        for target in _contradiction_targets(item.original):
            candidates = (
                [target] if target in finding_by_ref
                else source_ids.get(target, [])
            )
            if len(candidates) != 1 or candidates[0] == finding_ref:
                unresolved_contradiction_references += 1
                continue
            pair = sorted({finding_ref, candidates[0]})
            contradiction_rows.append({
                "kind": "explicit-finding-reference",
                "finding_refs": pair,
                "evidence_refs": [],
                "detail": "a finding explicitly contradicts another finding",
            })
            contradiction_findings.update(pair)

    claim_groups: dict[
        tuple[str, bytes],
        list[tuple[str, bytes]],
    ] = {}
    claim_scopes: dict[tuple[str, bytes], dict[str, Any]] = {}
    for finding_ref, item in finding_by_ref.items():
        claim = _claim(item.original)
        if claim is None:
            continue
        claim_key, scope, claim_value = claim
        if not _locator_is_decisive(scope):
            unscoped_claims += 1
            continue
        group_key = (claim_key, _canonical(scope))
        claim_groups.setdefault(group_key, []).append(
            (finding_ref, _claim_value_token(claim_value)))
        claim_scopes[group_key] = scope
    for group_key, members in claim_groups.items():
        if len({value for _ref, value in members}) <= 1:
            continue
        finding_refs = sorted(ref for ref, _value in members)
        contradiction_rows.append({
            "kind": "structured-claim-disagreement",
            "finding_refs": finding_refs,
            "evidence_refs": [],
            "detail": (
                "structured claim values disagree within the same locator"),
            "claim_key": group_key[0],
            "locator": claim_scopes[group_key],
        })
        contradiction_findings.update(finding_refs)

    contradiction_rows = _dedupe_rows(contradiction_rows)
    if len(contradiction_rows) > selected_limits.max_contradictions:
        raise AdjudicationError(
            "contradictions exceed their report boundary")

    finding_rows: list[dict[str, Any]] = []
    counts = {SUPPORTED: 0, CONTESTED: 0, INSUFFICIENT: 0}
    for item in prepared_findings:
        support_refs = sorted(support_by_finding[item.ref])
        contest_refs = sorted(contest_by_finding[item.ref])
        reasons: list[str] = []
        if support_refs:
            reasons.append("supporting-evidence-linked")
        if contest_refs:
            reasons.append("contesting-evidence-linked")
        if item.ref in contradiction_findings:
            reasons.append("structured-contradiction-detected")
        if contest_refs or item.ref in contradiction_findings:
            classification = CONTESTED
        elif support_refs:
            classification = SUPPORTED
        else:
            classification = INSUFFICIENT
            reasons.append("no-linked-decisive-evidence")
        counts[classification] += 1
        finding_rows.append({
            "finding_ref": item.ref,
            "source_finding_id": _source_finding_id(item.original),
            "classification": classification,
            "reasons": sorted(reasons),
            "support_evidence_refs": support_refs,
            "contest_evidence_refs": contest_refs,
            "original_finding": item.original,
        })

    risk_rows: list[dict[str, Any]] = []
    uncovered_rows: list[dict[str, Any]] = []
    unfamiliar_rows: list[dict[str, Any]] = []
    risk_coverage_conflicts = 0
    high_risk_count = 0
    for item in prepared_risks:
        high, coverage_state, familiarity, conflict = _risk_state(item.original)
        if conflict:
            risk_coverage_conflicts += 1
        if high:
            high_risk_count += 1
        if high and coverage_state != "covered":
            uncovered_rows.append({
                "area_ref": item.ref,
                "reasons": ["coverage-not-demonstrated"],
            })
        if high and familiarity == "unfamiliar":
            unfamiliar_rows.append({
                "area_ref": item.ref,
                "reasons": ["logic-marked-unfamiliar"],
            })
        row = {
            "area_ref": item.ref,
            "high_risk": high,
            "coverage_state": coverage_state,
            "familiarity": familiarity,
            "original_area": item.original,
        }
        risk_rows.append(row)

    gaps: list[dict[str, Any]] = []
    _gap(
        gaps, "no-findings-supplied", 1 if not finding_rows else 0,
        "No findings were supplied; absence of defects cannot be inferred.")
    _gap(
        gaps, "no-evidence-supplied",
        1 if finding_rows and not evidence_rows else 0,
        "No adjudication evidence was supplied for the findings.")
    _gap(
        gaps, "insufficient-finding-evidence", counts[INSUFFICIENT],
        "Findings lack linked decisive evidence.")
    _gap(
        gaps, "contested-findings-require-review", counts[CONTESTED],
        "Contested findings require review and are not proven false positives.")
    _gap(
        gaps, "unknown-evidence-stance", unknown_stance,
        "Evidence without one unambiguous stance could not affect classification.")
    _gap(
        gaps, "unlinked-evidence", unlinked_evidence,
        "Evidence could not be linked to a supplied finding.")
    _gap(
        gaps, "ambiguous-evidence-links", ambiguous_evidence,
        "Evidence matched more than one finding and was not used to classify.")
    _gap(
        gaps, "contradictory-input", len(contradiction_rows),
        "Structured evidence or findings contain contradictions.")
    _gap(
        gaps, "unresolved-contradiction-reference",
        unresolved_contradiction_references,
        "Explicit contradiction references were missing, ambiguous, or self-referential.")
    _gap(
        gaps, "unscoped-structured-claim", unscoped_claims,
        "Structured claims without a decisive locator were not compared.")
    _gap(
        gaps, "high-risk-inventory-not-supplied",
        1 if not risk_rows else 0,
        "No high-risk-area inventory was supplied.")
    _gap(
        gaps, "uncovered-high-risk-area", len(uncovered_rows),
        "High-risk areas lack demonstrated coverage.")
    _gap(
        gaps, "unfamiliar-high-risk-area", len(unfamiliar_rows),
        "High-risk logic was explicitly marked unfamiliar and needs review.")
    _gap(
        gaps, "conflicting-risk-coverage-claims",
        risk_coverage_conflicts,
        "Risk-area coverage fields disagree and were treated as unknown.")
    gaps.sort(key=_canonical)

    if not finding_rows:
        status = "insufficient"
    elif counts[CONTESTED] or contradiction_rows:
        status = "review-required"
    elif counts[INSUFFICIENT] or uncovered_rows or unfamiliar_rows or gaps:
        status = "attention-required"
    else:
        status = "adjudicated"

    body: dict[str, Any] = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": status,
        "policy": {
            "classifications": sorted(CLASSIFICATIONS),
            "contradiction_sources": [
                "explicit finding references",
                "mixed support and contest evidence",
                "disagreeing structured claims in one locator",
            ],
            "natural_language_inference_used": False,
            "findings_suppressed": False,
        },
        "summary": {
            "findings": len(finding_rows),
            "evidence": len(evidence_rows),
            "risk_areas": len(risk_rows),
            "high_risk_areas": high_risk_count,
            "supported": counts[SUPPORTED],
            "contested": counts[CONTESTED],
            "insufficient": counts[INSUFFICIENT],
            "contradictions": len(contradiction_rows),
            "uncovered_high_risk_areas": len(uncovered_rows),
            "unfamiliar_high_risk_areas": len(unfamiliar_rows),
            "unlinked_evidence": unlinked_evidence,
            "ambiguous_evidence": ambiguous_evidence,
            "input_bytes": input_bytes,
        },
        "findings": finding_rows,
        "evidence": evidence_rows,
        "risk_areas": risk_rows,
        "contradictions": contradiction_rows,
        "uncovered_high_risk_areas": uncovered_rows,
        "unfamiliar_high_risk_areas": unfamiliar_rows,
        "coverage": {
            "complete": False,
            "input_adjudication_complete": not gaps,
            "absence_proven": False,
            "gaps": gaps,
        },
        "execution": {
            "target_inspected": False,
            "target_code_executed": False,
            "network_accessed": False,
            "target_files_written": False,
            "subprocesses_started": False,
        },
        "limitations": [
            "Adjudication is limited to supplied structured inputs.",
            "Supported means supported by supplied evidence, not independently proven.",
            "Contested is a review signal and does not prove a false positive.",
            "Insufficient evidence and uncovered areas do not prove safety or a defect.",
            "Every original finding remains present in the report.",
        ],
    }
    encoded_body = _canonical(body)
    if len(encoded_body) > selected_limits.max_report_bytes:
        raise AdjudicationError("adjudication report exceeds its byte boundary")
    body["report_sha256"] = _sha(encoded_body)
    if len(_canonical(body)) > selected_limits.max_report_bytes:
        raise AdjudicationError("adjudication report exceeds its byte boundary")
    return body


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Verify digest, strict shape, bounds, and all derived adjudication data."""
    errors: list[str] = []
    if type(report) is not dict:
        return False, ["report must be an exact mapping"]
    if set(report) != _TOP_LEVEL_KEYS:
        errors.append("report fields are invalid")
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        errors.append("report identity is invalid")
    try:
        encoded = _canonical(report)
    except (TypeError, ValueError, OverflowError, RecursionError):
        return False, sorted(set([*errors, "report is not canonical JSON"]))
    if len(encoded) > MAX_REPORT_BYTES:
        errors.append("report exceeds its byte boundary")

    claimed = report.get("report_sha256")
    if type(claimed) is not str or _SHA256.fullmatch(claimed) is None:
        errors.append("report_sha256 must be lowercase SHA-256")
    else:
        body = {
            key: value for key, value in report.items()
            if key != "report_sha256"
        }
        try:
            if claimed != _sha(body):
                errors.append("report digest mismatch")
        except (TypeError, ValueError, OverflowError, RecursionError):
            errors.append("report body is not canonical JSON")

    finding_rows = report.get("findings")
    evidence_rows = report.get("evidence")
    risk_rows = report.get("risk_areas")
    if type(finding_rows) is not list or len(finding_rows) > MAX_FINDINGS:
        errors.append("findings collection is invalid")
    if type(evidence_rows) is not list or len(evidence_rows) > MAX_EVIDENCE:
        errors.append("evidence collection is invalid")
    if type(risk_rows) is not list or len(risk_rows) > MAX_RISK_AREAS:
        errors.append("risk-area collection is invalid")

    originals_findings: list[dict[str, Any]] = []
    originals_evidence: list[dict[str, Any]] = []
    originals_risks: list[dict[str, Any]] = []
    if type(finding_rows) is list and len(finding_rows) <= MAX_FINDINGS:
        for row in finding_rows:
            if type(row) is not dict or type(row.get("original_finding")) is not dict:
                errors.append("adjudicated finding is invalid")
                break
            originals_findings.append(row["original_finding"])
    if type(evidence_rows) is list and len(evidence_rows) <= MAX_EVIDENCE:
        for row in evidence_rows:
            if type(row) is not dict or type(row.get("original_evidence")) is not dict:
                errors.append("adjudicated evidence is invalid")
                break
            originals_evidence.append(row["original_evidence"])
    if type(risk_rows) is list and len(risk_rows) <= MAX_RISK_AREAS:
        for row in risk_rows:
            if type(row) is not dict or type(row.get("original_area")) is not dict:
                errors.append("adjudicated risk area is invalid")
                break
            originals_risks.append(row["original_area"])

    if not any(error.startswith("adjudicated ") for error in errors) and all(
            type(value) is list
            for value in (finding_rows, evidence_rows, risk_rows)):
        try:
            expected = adjudicate(
                originals_findings, originals_evidence, originals_risks)
            if _canonical(expected) != encoded:
                errors.append("report derived data is inconsistent")
        except (AdjudicationError, TypeError, ValueError, OverflowError,
                RecursionError):
            errors.append("report originals cannot be safely adjudicated")
    return not errors, sorted(set(errors))
