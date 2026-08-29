#!/usr/bin/env python3
"""Attestor 4.1.3 evidence-bound coding, repair, and defensive-security orchestrator.

The default operation is offline static analysis.  Attestor 4.1.3 replays the
verified 4.0 report, adds one immutable-snapshot semantic/correctness pass and
one supply-chain/secret-lifecycle pass in bounded child processes, then binds
every public finding to source bytes with Truth Guard 3.  Repair candidates
are review artifacts until separately authorized scan/build/test gates pass.

Non-coding public-web research is exposed through :mod:`research_engine41` and
is deliberately separate: callers must explicitly authorize online access.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Mapping, Sequence

import bounded_worker41
import attestor3
import attestor40
import repair_director41
import research_engine41
import response41
import security_validation413
import truth_guard
import truth_guard35
import truth_guard40
import truth_guard41
import variant414


SCHEMA = "attestor-maximum/4.1"
VERSION = "4.1.3"
DEFAULT_COMPONENTS = tuple(attestor40.DEFAULT_COMPONENTS) + (
    "semantic-correctness", "supply-chain-trust", "secret-lifecycle",
    "attack-surface", "web-api-auth", "cloud-iac-security",
    "security-validation", "security-command-center",
    "repair-director", "truth-guard3",
)
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
MAX_FINDINGS = 12_000
MAX_TOP_FINDINGS = 150
MAX_ATTACK_PATHS = 200
MAX_UNBOUND_OBSERVATIONS = 1_000
MAX_RULE_PACK_BYTES = 2 * 1024 * 1024
MAX_SEMANTIC_PACK_PAYLOAD_BYTES = 384 * 1024
MAX_LEGACY_RULE_PACKS = 32
MAX_LEGACY_RULE_PACK_BYTES = 8 * 1024 * 1024
MAX_CALIBRATION_OBSERVATIONS = 200_000
MAX_PUBLIC_BYTES = 32 * 1024 * 1024
PUBLIC_PROJECTION_SCHEMA = "attestor-public-component-projection/4.1"
COMPATIBILITY_AUDIT_PROJECTION_SCHEMA = \
    "attestor-compatibility-audit-projection/4.1"
MAX_PROJECTION_RETAINED_BYTES = 64 * 1024
MAX_PROJECTION_FIELDS = 256
TG2_RETAINED_FIELDS = frozenset({
    "schema", "version", "status", "source_document_sha256",
    "evidence_chain_sha256", "evidence_truncated",
    "independent_evidence_sha256", "independent_validation",
    "summary", "execution", "evidence_catalog_size",
})
TG2_OMITTED_COLLECTION_FIELDS = frozenset({
    "evidence_chain", "independent_evidence", "claims", "contradictions",
})
TG2_SOURCE_FIELDS = (
    TG2_RETAINED_FIELDS | TG2_OMITTED_COLLECTION_FIELDS | {"signature"}
)
COMPATIBILITY_PROJECTION_LIMITATIONS = (
    "The full compatibility evidence chain was replay-verified before this projection.",
    "Only aggregate chain identities, bounded audit state, and per-collection commitments are repeated in the Attestor 4.1.3 envelope.",
    "The copied source signature applies only to the original Truth Guard 2 audit.",
    "The projection digest and Truth Guard 3 provide integrity binding; they authenticate the envelope only when a valid Truth Guard 3 HMAC key is supplied.",
)
UNBOUND_PATH = "__attestor_unbound__/outside-or-invalid-path"
_GUARD_KEYS = frozenset({
    "truth_guard", "truth_guard_runtime", "truth_guard2", "truth_guard3",
    "report_sha256", "view_sha256", "source_report_sha256",
})


class Attestor41Error(ValueError):
    """An Attestor 4.1.3 scope, component, or evidence boundary failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False,
                          default=str).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise Attestor41Error("report evidence is not deterministic JSON") from exc


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _optional_digest(value: Any) -> str:
    return "" if value is None else _sha(value)


def _sha256_text(value: Any) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and
        all(character in "0123456789abcdef" for character in value)
    )


def _source_report_digest_valid(value: Any) -> bool:
    return (
        type(value) is dict and _sha256_text(value.get("report_sha256")) and
        value["report_sha256"] == _sha({
            key: item for key, item in value.items() if key != "report_sha256"
        })
    )


def _value_commitment(value: Any) -> dict[str, Any]:
    encoded = _canonical(value)
    return {
        "kind": (
            "object" if isinstance(value, dict) else
            "array" if isinstance(value, (list, tuple)) else
            "scalar"
        ),
        "source_items": (
            len(value) if isinstance(value, (dict, list, tuple)) else 1
        ),
        "canonical_bytes": len(encoded),
        "sha256": _sha(value),
    }


def _projection_value(value: Any) -> Any:
    """Retain a small exact value or replace it with bounded digest metadata."""
    encoded = _canonical(value)
    if len(encoded) <= MAX_PROJECTION_RETAINED_BYTES:
        return json.loads(encoded.decode("utf-8"))
    count = len(value) if isinstance(value, (dict, list, tuple)) else 1
    return {
        "state": "digest-only-public-projection",
        "source_type": type(value).__name__,
        "source_items": count,
        "source_bytes": len(encoded),
        "source_sha256": _sha(value),
    }


def _public_component_projection(
        name: str, source: Mapping[str, Any], *,
        retain: Sequence[str] = (),
        children: Mapping[str, str] | None = None,
        embedded_children: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Compact an already verified nested report without discarding its identity."""
    if type(source) is not dict:
        raise Attestor41Error("a public projection source is not a JSON object")
    if not all(isinstance(key, str) for key in source):
        raise Attestor41Error(
            "a public projection source contains a non-string field name")
    claimed = source.get("report_sha256")
    if not _source_report_digest_valid(source):
        raise Attestor41Error(
            "a component report digest failed before public projection")
    field_names = sorted(source)
    if len(field_names) > MAX_PROJECTION_FIELDS:
        raise Attestor41Error("a component has too many top-level fields to project")
    child_links: dict[str, Any] = {}
    for source_field, public_field in sorted((children or {}).items()):
        value = source.get(source_field)
        if value is None:
            continue
        child_claimed = (
            value.get("report_sha256")
            if isinstance(value, Mapping) else None
        )
        if child_claimed is not None:
            if type(value) is not dict or not _source_report_digest_valid(value):
                raise Attestor41Error(
                    "a projected child report digest failed verification")
            child_sha = child_claimed
        else:
            child_sha = _sha(value)
        embedded = (embedded_children or {}).get(source_field, value)
        if (isinstance(embedded, Mapping) and
                embedded.get("schema") == PUBLIC_PROJECTION_SCHEMA and
                not _verify_public_component_projection(embedded)):
            raise Attestor41Error(
                "an embedded child projection failed verification")
        source_commitment = _value_commitment(value)
        child_links[source_field] = {
            "embedded_as": _bounded_text(public_field, 160),
            "source_sha256": child_sha,
            "source_bytes": len(_canonical(value)),
            "source_commitment": source_commitment,
            "embedded_sha256": _sha(embedded),
            "embedded_bytes": len(_canonical(embedded)),
        }
    retained: dict[str, Any] = {}
    projected_retained: dict[str, Any] = {}
    for key in sorted(set(str(item) for item in retain)):
        if key in source and key not in set((children or {}).keys()) | {"report_sha256"}:
            retained[key] = _projection_value(source[key])
            if len(_canonical(source[key])) > MAX_PROJECTION_RETAINED_BYTES:
                projected_retained[key] = _value_commitment(source[key])
    omitted = [
        key for key in field_names
        if key not in retained and key not in {"schema", "version", "report_sha256"}
        and key not in child_links
    ]
    collections = {}
    commitments = {}
    for key in omitted:
        value = source.get(key)
        commitments[key] = _value_commitment(value)
        if isinstance(value, (list, tuple, dict)):
            collections[key] = {
                "source_items": len(value),
                "retained_items": 0,
                "omitted_items": len(value),
            }
    source_field_commitments = {
        key: _value_commitment(source[key])
        for key in field_names if key != "report_sha256"
    }
    body = {
        "schema": PUBLIC_PROJECTION_SCHEMA, "version": VERSION,
        "name": _bounded_text(name, 160),
        "status": "digest-bound-public-projection",
        "source": {
            "schema": _bounded_text(source.get("schema"), 160),
            "version": _bounded_text(source.get("version"), 80),
            "report_sha256": claimed,
            "canonical_sha256": _sha(source),
            "canonical_bytes": len(_canonical(source)),
            "top_level_fields": len(field_names),
            "field_commitments_sha256": _sha(source_field_commitments),
            "complete_report_embedded": False,
            "verification_state":
                "digest-recomputed-at-projection-time-original-required-for-independent-replay",
        },
        "retained": retained,
        "projected_retained_fields": projected_retained,
        "children": child_links,
        "worker_attestation": {},
        "omitted_fields": omitted,
        "omitted_commitments": commitments,
        "omitted_collections": collections,
        "requires_original_for_full_replay":
            bool(omitted or projected_retained),
        "limitations": [
            "The complete nested producer report is not repeated in this public envelope.",
            "Its source digest was recomputed during projection construction; independent replay of that digest requires the original report.",
            "Separately listed child evidence is embedded once in full or as its own explicit projection and is bound to this envelope by exact representation digest.",
            "Projection self-digests provide integrity binding, not origin authentication; public authentication requires a verified outer Truth Guard 3 HMAC.",
        ],
    }
    body["report_sha256"] = _sha(body)
    return body


def _commitment_shape_valid(value: Any) -> bool:
    return (
        type(value) is dict and
        set(value) == {
            "kind", "source_items", "canonical_bytes", "sha256"} and
        value.get("kind") in {"object", "array", "scalar"} and
        type(value.get("source_items")) is int and
        value["source_items"] >= 0 and
        type(value.get("canonical_bytes")) is int and
        0 <= value["canonical_bytes"] <= MAX_PUBLIC_BYTES and
        _sha256_text(value.get("sha256"))
    )


def _verify_projected_retained_values(
        retained: Mapping[str, Any],
        projected: Mapping[str, Any]) -> bool:
    try:
        if any(
                key not in projected and
                len(_canonical(value)) > MAX_PROJECTION_RETAINED_BYTES
                for key, value in retained.items()):
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    for key, commitment in projected.items():
        if not _commitment_shape_valid(commitment):
            return False
        descriptor = retained.get(key)
        if (type(descriptor) is not dict or
                set(descriptor) != {
                    "state", "source_type", "source_items",
                    "source_bytes", "source_sha256"} or
                descriptor.get("state") !=
                "digest-only-public-projection" or
                type(descriptor.get("source_type")) is not str or
                type(descriptor.get("source_items")) is not int or
                descriptor["source_items"] < 0 or
                type(descriptor.get("source_bytes")) is not int or
                not MAX_PROJECTION_RETAINED_BYTES <
                descriptor["source_bytes"] <= MAX_PUBLIC_BYTES or
                not _sha256_text(descriptor.get("source_sha256"))):
            return False
        expected_kind = (
            "object" if descriptor["source_type"] == "dict" else
            "array" if descriptor["source_type"] in {"list", "tuple"} else
            "scalar"
        )
        if (commitment["kind"] != expected_kind or
                commitment["source_items"] != descriptor["source_items"] or
                commitment["canonical_bytes"] != descriptor["source_bytes"] or
                commitment["sha256"] != descriptor["source_sha256"]):
            return False
    return True


def _projection_source_commitments_match(
        source: Mapping[str, Any],
        retained: Mapping[str, Any],
        projected_retained: Mapping[str, Any],
        children: Mapping[str, Any],
        omitted_commitments: Mapping[str, Any]) -> bool:
    try:
        commitments = {
            "schema": _value_commitment(source["schema"]),
            "version": _value_commitment(source["version"]),
        }
        for key, item in retained.items():
            commitments[key] = (
                projected_retained[key]
                if key in projected_retained else _value_commitment(item)
            )
        for key, row in children.items():
            commitments[key] = row["source_commitment"]
        commitments.update(omitted_commitments)
        return (
            len(commitments) + 1 == source["top_level_fields"] and
            _sha(commitments) == source["field_commitments_sha256"]
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _worker_attestation_structure_matches_source(
        attestation: Any, source: Mapping[str, Any]) -> bool:
    if attestation == {}:
        return True
    if (type(attestation) is not dict or
            set(attestation) != {
                "schema", "version", "action", "request_sha256",
                "result_sha256", "result_report_sha256", "wrapper_sha256",
                "boundary", "replayed_during_generation",
                "independently_replayable_from_projection",
                "origin_authentication", "verification_state"} or
            attestation.get("schema") != bounded_worker41.SCHEMA or
            attestation.get("version") != bounded_worker41.VERSION or
            attestation.get("action") not in {
                "coding-static", "security-static"} or
            not _sha256_text(attestation.get("request_sha256")) or
            not _sha256_text(attestation.get("result_sha256")) or
            not _sha256_text(attestation.get("result_report_sha256")) or
            not _sha256_text(attestation.get("wrapper_sha256")) or
            type(attestation.get("boundary")) is not dict or
            attestation.get("replayed_during_generation") is not True or
            attestation.get(
                "independently_replayable_from_projection") is not False or
            attestation.get("origin_authentication") !=
            "inherits-outer-truth-guard3-hmac-when-independently-verified" or
            attestation.get("verification_state") !=
            "construction-time-replay-record-original-required-for-independent-verification"):
        return False
    boundary = attestation["boundary"]
    return (
        attestation["result_sha256"] == source.get("canonical_sha256") and
        attestation["result_report_sha256"] ==
        source.get("report_sha256") and
        boundary.get("shell") is False and
        boundary.get("target_code_executed") is False and
        boundary.get("preexec_fn_used") is False
    )


def _verify_public_component_projection(value: Any) -> bool:
    if (type(value) is not dict or
            set(value) != {
                "schema", "version", "name", "status", "source",
                "retained", "projected_retained_fields", "children",
                "worker_attestation", "omitted_fields",
                "omitted_commitments", "omitted_collections",
                "requires_original_for_full_replay", "limitations",
                "report_sha256"} or
            value.get("schema") != PUBLIC_PROJECTION_SCHEMA or
            value.get("version") != VERSION or
            value.get("status") != "digest-bound-public-projection"):
        return False
    claimed = value.get("report_sha256")
    source = value.get("source")
    if (not _sha256_text(claimed) or
            type(source) is not dict or
            set(source) != {
                "schema", "version", "report_sha256", "canonical_sha256",
                "canonical_bytes",
                "top_level_fields", "field_commitments_sha256",
                "complete_report_embedded",
                "verification_state"} or
            not isinstance(source.get("schema"), str) or
            not isinstance(source.get("version"), str) or
            not _sha256_text(source.get("report_sha256")) or
            not _sha256_text(source.get("canonical_sha256")) or
            not _sha256_text(source.get("field_commitments_sha256")) or
            type(source.get("canonical_bytes")) is not int or
            not 0 <= source["canonical_bytes"] <= MAX_PUBLIC_BYTES or
            type(source.get("top_level_fields")) is not int or
            not 1 <= source["top_level_fields"] <= MAX_PROJECTION_FIELDS or
            source.get("complete_report_embedded") is not False or
            source.get("verification_state") !=
            "digest-recomputed-at-projection-time-original-required-for-independent-replay"):
        return False
    try:
        if claimed != _sha({key: item for key, item in value.items()
                            if key != "report_sha256"}):
            return False
        if len(_canonical(value)) > 2 * 1024 * 1024:
            return False
    except (TypeError, ValueError, OverflowError):
        return False
    children = value.get("children")
    worker_attestation = value.get("worker_attestation")
    retained = value.get("retained")
    projected_retained = value.get("projected_retained_fields")
    omitted = value.get("omitted_fields")
    commitments = value.get("omitted_commitments")
    collections = value.get("omitted_collections")
    child_rows_valid = (
        type(children) is dict and len(children) <= MAX_PROJECTION_FIELDS and
        all(
            type(row) is dict and
            set(row) == {
                "embedded_as", "source_sha256", "source_bytes",
                "source_commitment", "embedded_sha256", "embedded_bytes"} and
            isinstance(row.get("embedded_as"), str) and
            1 <= len(row["embedded_as"]) <= 160 and
            _sha256_text(row.get("source_sha256")) and
            type(row.get("source_bytes")) is int and
            0 <= row["source_bytes"] <= MAX_PUBLIC_BYTES and
            type(row.get("source_commitment")) is dict and
            set(row["source_commitment"]) == {
                "kind", "source_items", "canonical_bytes", "sha256"} and
            row["source_commitment"].get("kind") in {
                "object", "array", "scalar"} and
            type(row["source_commitment"].get("source_items")) is int and
            row["source_commitment"]["source_items"] >= 0 and
            row["source_commitment"].get("canonical_bytes") ==
            row["source_bytes"] and
            _sha256_text(row["source_commitment"].get("sha256")) and
            _sha256_text(row.get("embedded_sha256")) and
            type(row.get("embedded_bytes")) is int and
            0 <= row["embedded_bytes"] <= MAX_PUBLIC_BYTES
            for row in children.values()
        )
    )
    embedded_fields = (
        [row["embedded_as"] for row in children.values()]
        if child_rows_valid else []
    )
    return (
        child_rows_valid and
        _worker_attestation_structure_matches_source(
            worker_attestation, source) and
        type(retained) is dict and len(retained) <= MAX_PROJECTION_FIELDS and
        all(isinstance(key, str) for key in retained) and
        type(projected_retained) is dict and
        set(projected_retained).issubset(set(retained)) and
        len(set(embedded_fields)) == len(embedded_fields) and
        type(omitted) is list and len(omitted) <= MAX_PROJECTION_FIELDS and
        omitted == sorted(set(omitted)) and
        all(isinstance(item, str) for item in omitted) and
        type(commitments) is dict and
        set(commitments) == set(omitted) and
        type(collections) is dict and
        set(collections).issubset(set(omitted)) and
        value.get("requires_original_for_full_replay") is
        bool(omitted or projected_retained) and
        len(
            {"schema", "version", "report_sha256"} |
            set(retained) | set(children) | set(omitted)
        ) == source["top_level_fields"] and
        not (set(retained) & set(children) or
             set(retained) & set(omitted) or
             set(children) & set(omitted)) and
        all(
            type(row) is dict and
            set(row) == {
                "kind", "source_items", "canonical_bytes", "sha256"} and
            row.get("kind") in {"object", "array", "scalar"} and
            type(row.get("source_items")) is int and row["source_items"] >= 0 and
            type(row.get("canonical_bytes")) is int and
            0 <= row["canonical_bytes"] <= MAX_PUBLIC_BYTES and
            _sha256_text(row.get("sha256"))
            for row in commitments.values()
        ) and
        all(
            type(row) is dict and
            set(row) == {"source_items", "retained_items", "omitted_items"} and
            type(row.get("source_items")) is int and row["source_items"] >= 0 and
            row.get("retained_items") == 0 and
            row.get("omitted_items") == row.get("source_items")
            for row in collections.values()
        ) and
        all(
            commitments[key].get("kind") in {"object", "array"} and
            row.get("source_items") ==
            commitments[key].get("source_items")
            for key, row in collections.items()
        ) and
        _verify_projected_retained_values(retained, projected_retained) and
        _projection_source_commitments_match(
            source, retained, projected_retained, children, commitments)
    )


def _projection_links_match(
        projection: Mapping[str, Any],
        public_report: Mapping[str, Any]) -> bool:
    if not _verify_public_component_projection(projection):
        return False
    for row in projection.get("children", {}).values():
        public_field = row["embedded_as"]
        if public_field not in public_report:
            return False
        child = public_report[public_field]
        if (isinstance(child, Mapping) and
                child.get("schema") == PUBLIC_PROJECTION_SCHEMA and
                _verify_public_component_projection(child)):
            child_source = child.get("source", {})
            digest = child_source.get("report_sha256")
            child_bytes = child_source.get("canonical_bytes")
        else:
            claimed = (
                child.get("report_sha256")
                if isinstance(child, Mapping) else None
            )
            if claimed is not None:
                if type(child) is not dict or not _source_report_digest_valid(child):
                    return False
                digest = claimed
            else:
                digest = _sha(child)
            child_bytes = len(_canonical(child))
        if (digest != row["source_sha256"] or
                child_bytes != row["source_bytes"] or
                _sha(child) != row["embedded_sha256"] or
                len(_canonical(child)) != row["embedded_bytes"]):
            return False
    return True


def _compatibility_audit_projection(audit: Mapping[str, Any]) -> dict[str, Any]:
    """Retain replay identities without duplicating Truth Guard 2's full chain."""
    if type(audit) is not dict or set(audit) != TG2_SOURCE_FIELDS:
        raise Attestor41Error(
            "the compatibility audit does not match the exact Truth Guard 2 contract")
    if (audit.get("schema") != truth_guard40.SCHEMA or
            audit.get("version") != truth_guard40.VERSION or
            audit.get("status") not in {"verified", "partial"}):
        raise Attestor41Error(
            "the compatibility audit identity or status is not publishable")
    signature = audit.get("signature")
    if not _tg2_source_signature_valid(signature):
        raise Attestor41Error("the compatibility audit signature is invalid")
    encoded = _canonical(audit)
    collections = {}
    commitments = {}
    for key in sorted(TG2_OMITTED_COLLECTION_FIELDS):
        value = audit.get(key)
        if type(value) is not list:
            raise Attestor41Error(
                "a compatibility audit collection has an invalid shape")
        commitment = _value_commitment(value)
        commitments[key] = commitment
        collections[key] = {
            "source_items": len(value),
            "source_sha256": commitment["sha256"],
            "canonical_bytes": commitment["canonical_bytes"],
            "complete_collection_embedded": False,
        }
    retained = {}
    for key in sorted(TG2_RETAINED_FIELDS):
        raw = _canonical(audit[key])
        if len(raw) > MAX_PROJECTION_RETAINED_BYTES:
            raise Attestor41Error(
                "a required compatibility audit field exceeds its exact projection boundary")
        retained[key] = json.loads(raw.decode("utf-8"))
    signature_copy = json.loads(_canonical(signature).decode("utf-8"))
    body = {
        "schema": COMPATIBILITY_AUDIT_PROJECTION_SCHEMA,
        "version": VERSION,
        "status": "verified-before-projection",
        "source_audit": {
            "schema": _bounded_text(audit.get("schema"), 160),
            "version": _bounded_text(audit.get("version"), 80),
            "status": _bounded_text(audit.get("status"), 80),
            "sha256": _sha(audit),
            "canonical_bytes": len(encoded),
            "top_level_fields": len(audit),
            "field_names_sha256": _sha(sorted(audit)),
            "complete_audit_embedded": False,
        },
        "retained": retained,
        "source_signature": signature_copy,
        "omitted_fields": sorted(TG2_OMITTED_COLLECTION_FIELDS),
        "omitted_commitments": commitments,
        "omitted_collections": collections,
        "limitations": list(COMPATIBILITY_PROJECTION_LIMITATIONS),
    }
    body["report_sha256"] = _sha(body)
    return body


def _tg2_source_signature_valid(value: Any) -> bool:
    if (type(value) is not dict or
            set(value) != {"algorithm", "key_id", "value", "state"}):
        return False
    if value.get("algorithm") == "none":
        return (
            value.get("key_id") == "" and value.get("value") == "" and
            value.get("state") == "integrity-only-not-authenticated"
        )
    return (
        value.get("algorithm") == "hmac-sha256" and
        isinstance(value.get("key_id"), str) and
        re.fullmatch(r"[A-Za-z0-9._-]{1,80}", value["key_id"]) is not None and
        _sha256_text(value.get("value")) and value.get("state") == "signed"
    )


def _tg2_independent_validation_valid(
        value: Any, source_document_sha256: str) -> bool:
    expected = {
        "projected", "source_document_sha256",
        "source_node_count_lower_bound", "source_node_count_exact",
        "source_node_hard_limit", "independent_node_limit",
        "view_node_count", "view_sha256", "collections", "reason",
    }
    if (type(value) is not dict or set(value) != expected or
            type(value.get("projected")) is not bool or
            value.get("source_document_sha256") != source_document_sha256 or
            value.get("source_node_count_exact") is not True or
            value.get("source_node_hard_limit") !=
            truth_guard40.MAX_DOCUMENT_NODES or
            value.get("independent_node_limit") !=
            truth_guard40.MAX_INDEPENDENT_NODES or
            not _sha256_text(value.get("view_sha256")) or
            not isinstance(value.get("reason"), str) or not value["reason"]):
        return False
    for key in ("source_node_count_lower_bound", "view_node_count"):
        if type(value.get(key)) is not int or value[key] < 0:
            return False
    if (value["source_node_count_lower_bound"] >
            value["source_node_hard_limit"] or
            value["view_node_count"] > value["independent_node_limit"]):
        return False
    collections = value.get("collections")
    if (type(collections) is not dict or
            set(collections) != {"findings", "improvements", "gaps"}):
        return False
    for row in collections.values():
        if (type(row) is not dict or
                set(row) != {"source", "retained", "omitted"} or
                any(type(row.get(key)) is not int or row[key] < 0
                    for key in ("source", "retained", "omitted")) or
                row["source"] != row["retained"] + row["omitted"]):
            return False
    if value["projected"] is False:
        return (
            value["view_sha256"] == source_document_sha256 and
            value["view_node_count"] ==
            value["source_node_count_lower_bound"] and
            all(row["omitted"] == 0 for row in collections.values())
        )
    return (
        value["source_node_count_lower_bound"] >
        value["independent_node_limit"]
    )


def _canonical_object_size_from_projection(
        retained: Mapping[str, Any],
        commitments: Mapping[str, Any],
        signature: Mapping[str, Any]) -> int:
    lengths = {
        key: len(_canonical(item)) for key, item in retained.items()
    }
    lengths.update({
        key: int(item["canonical_bytes"])
        for key, item in commitments.items()
    })
    lengths["signature"] = len(_canonical(signature))
    return (
        2 + max(0, len(lengths) - 1) +
        sum(len(_canonical(key)) + 1 + size
            for key, size in lengths.items())
    )


def _verify_compatibility_audit_projection(value: Any) -> bool:
    if (type(value) is not dict or
            set(value) != {
                "schema", "version", "status", "source_audit", "retained",
                "source_signature", "omitted_fields",
                "omitted_commitments", "omitted_collections",
                "limitations", "report_sha256"} or
            value.get("schema") != COMPATIBILITY_AUDIT_PROJECTION_SCHEMA or
            value.get("version") != VERSION or
            value.get("status") != "verified-before-projection" or
            not _sha256_text(value.get("report_sha256"))):
        return False
    source = value.get("source_audit")
    retained = value.get("retained")
    omitted = value.get("omitted_fields")
    commitments = value.get("omitted_commitments")
    collections = value.get("omitted_collections")
    if (type(source) is not dict or
            set(source) != {
                "schema", "version", "status", "sha256",
                "canonical_bytes", "top_level_fields",
                "field_names_sha256", "complete_audit_embedded"} or
            source.get("schema") != truth_guard40.SCHEMA or
            source.get("version") != truth_guard40.VERSION or
            source.get("status") not in {"verified", "partial"} or
            not _sha256_text(source.get("sha256")) or
            source.get("top_level_fields") != len(TG2_SOURCE_FIELDS) or
            source.get("field_names_sha256") !=
            _sha(sorted(TG2_SOURCE_FIELDS)) or
            type(source.get("canonical_bytes")) is not int or
            not 0 <= source["canonical_bytes"] <= MAX_PUBLIC_BYTES or
            source.get("complete_audit_embedded") is not False or
            type(retained) is not dict or
            set(retained) != TG2_RETAINED_FIELDS or
            type(omitted) is not list or
            omitted != sorted(TG2_OMITTED_COLLECTION_FIELDS) or
            type(commitments) is not dict or
            set(commitments) != TG2_OMITTED_COLLECTION_FIELDS or
            type(collections) is not dict or
            set(collections) != TG2_OMITTED_COLLECTION_FIELDS):
        return False
    if (retained.get("schema") != source["schema"] or
            retained.get("version") != source["version"] or
            retained.get("status") != source["status"] or
            not _sha256_text(retained.get("source_document_sha256")) or
            retained.get("evidence_chain_sha256") !=
            collections["evidence_chain"].get("source_sha256") or
            retained.get("independent_evidence_sha256") !=
            collections["independent_evidence"].get("source_sha256") or
            type(retained.get("evidence_truncated")) is not bool or
            not _tg2_independent_validation_valid(
                retained.get("independent_validation"),
                retained["source_document_sha256"])):
        return False
    summary = retained.get("summary")
    execution = retained.get("execution")
    if (type(summary) is not dict or
            set(summary) != {
                "claims", "grounded", "refuted", "unknown",
                "contradictions"} or
            any(type(summary.get(key)) is not int or summary[key] < 0
                for key in summary) or
            summary["claims"] != collections["claims"]["source_items"] or
            summary["contradictions"] !=
            collections["contradictions"]["source_items"] or
            summary["grounded"] + summary["refuted"] + summary["unknown"] !=
            summary["claims"] or
            summary["refuted"] != 0 or summary["contradictions"] != 0 or
            type(execution) is not dict or
            set(execution) != {
                "model", "network", "shell", "target_code",
                "filesystem_writes"} or
            any(item is not False for item in execution.values()) or
            type(retained.get("evidence_catalog_size")) is not int or
            retained["evidence_catalog_size"] !=
            collections["evidence_chain"]["source_items"] +
            collections["independent_evidence"]["source_items"]):
        return False
    if source["status"] == "verified" and (
            retained["evidence_truncated"] is not False or
            retained["independent_validation"]["projected"] is not False or
            summary["unknown"] != 0):
        return False
    if any(
            type(row) is not dict or
            set(row) != {
                "source_items", "source_sha256",
                "canonical_bytes", "complete_collection_embedded"} or
            type(row.get("source_items")) is not int or
            row["source_items"] < 0 or
            not _sha256_text(row.get("source_sha256")) or
            type(row.get("canonical_bytes")) is not int or
            not 0 <= row["canonical_bytes"] <= MAX_PUBLIC_BYTES or
            row.get("complete_collection_embedded") is not False
            for row in collections.values()):
        return False
    if any(
            not _commitment_shape_valid(row) or
            row["kind"] != "array" or
            row["source_items"] != collections[key]["source_items"] or
            row["canonical_bytes"] != collections[key]["canonical_bytes"] or
            row["sha256"] != collections[key]["source_sha256"]
            for key, row in commitments.items()):
        return False
    try:
        if (any(len(_canonical(item)) > MAX_PROJECTION_RETAINED_BYTES
                for item in retained.values()) or
                not _tg2_source_signature_valid(
                    value.get("source_signature")) or
                len(_canonical(value.get("source_signature"))) >
                MAX_PROJECTION_RETAINED_BYTES or
                value.get("limitations") !=
                list(COMPATIBILITY_PROJECTION_LIMITATIONS) or
                _canonical_object_size_from_projection(
                    retained, commitments, value["source_signature"]) !=
                source["canonical_bytes"]):
            return False
        return (
            value["report_sha256"] == _sha({
                key: item for key, item in value.items()
                if key != "report_sha256"
            }) and
            len(_canonical(value)) <= 2 * 1024 * 1024
        )
    except (TypeError, ValueError, OverflowError):
        return False


def _bounded_tuple(values: Iterable[Any], maximum: int, label: str) -> tuple[Any, ...]:
    rows: list[Any] = []
    for item in values:
        if len(rows) >= maximum:
            raise Attestor41Error(label + " exceeds its count boundary")
        rows.append(item)
    return tuple(rows)


def _file_input_descriptors(values: Sequence[str | os.PathLike[str]]) -> list[dict[str, Any]]:
    """Describe file inputs by content and opaque location, never by file contents."""
    rows: list[dict[str, Any]] = []
    for value in values:
        try:
            path = Path(value).expanduser().resolve(strict=True)
            if not path.is_file():
                raise OSError("not a regular file")
            digest = hashlib.sha256()
            size = 0
            with path.open("rb") as stream:
                while True:
                    block = stream.read(128 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_LEGACY_RULE_PACK_BYTES:
                        raise Attestor41Error("a legacy rule-pack input exceeds the byte boundary")
                    digest.update(block)
        except Attestor41Error:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise Attestor41Error("a configured rule-pack input is unavailable") from exc
        rows.append({
            "location_sha256": _sha(os.fspath(path).encode("utf-8", "surrogatepass")),
            "content_sha256": digest.hexdigest(),
            "bytes": size,
        })
    return rows


def _strip_guard(document: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in document.items()
            if str(key) not in _GUARD_KEYS and not str(key).startswith("_")}


def _is_link_or_reparse(path: Path) -> bool:
    """Recognize POSIX links and Windows reparse-backed paths before resolve()."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _selected_root(value: str | os.PathLike[str]) -> Path:
    supplied = Path(value).expanduser()
    try:
        spelling = supplied if supplied.is_absolute() else Path.cwd() / supplied
        current = Path(spelling.anchor)
        for part in spelling.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                current = current.parent
                continue
            current = current / part
            if _is_link_or_reparse(current):
                raise Attestor41Error("target path cannot traverse a link or reparse point")
        lexical = Path(os.path.abspath(os.fspath(spelling)))
        requested = lexical.resolve(strict=True)
    except Attestor41Error:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise Attestor41Error("target does not exist") from exc
    if not (requested.is_file() or requested.is_dir()) or _is_link_or_reparse(requested):
        raise Attestor41Error("target must be a real regular file or directory")
    return requested


def _bounded_text(value: Any, maximum: int = 1_000) -> str:
    return str(value or "").replace("\x00", "\\0").replace("\r", " ").replace("\n", " ")[:maximum]


def _inner_digest_valid(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    claimed = value.get("report_sha256")
    if not isinstance(claimed, str) or len(claimed) != 64:
        return False
    return claimed == _sha({key: item for key, item in value.items()
                            if key != "report_sha256"})


def _load_semantic_packs(values: Sequence[str | os.PathLike[str] | Mapping[str, Any]]) -> list[dict[str, Any]]:
    import semantic_rule_sdk41

    rows: list[dict[str, Any]] = []
    if len(values) > 32:
        raise Attestor41Error("semantic rule-pack count exceeds the boundary")
    for value in values:
        if isinstance(value, Mapping):
            row = json.loads(_canonical(dict(value)).decode("utf-8"))
        else:
            path = Path(value).expanduser().resolve(strict=True)
            if not path.is_file() or path.stat().st_size > MAX_RULE_PACK_BYTES:
                raise Attestor41Error("semantic rule pack is missing or oversized")
            try:
                with path.open("rb") as stream:
                    raw = stream.read(MAX_RULE_PACK_BYTES + 1)
                if len(raw) > MAX_RULE_PACK_BYTES:
                    raise Attestor41Error("semantic rule pack is missing or oversized")
                row = semantic_rule_sdk41.load_pack_json(
                    raw, maximum_bytes=MAX_RULE_PACK_BYTES)
            except (OSError, UnicodeError, semantic_rule_sdk41.RulePackError) as exc:
                raise Attestor41Error("semantic rule pack is not valid strict JSON: " + str(exc)) from exc
        if type(row) is not dict or len(_canonical(row)) > MAX_RULE_PACK_BYTES:
            raise Attestor41Error("semantic rule pack must be a bounded JSON object")
        rows.append(row)
    if len(_canonical(rows)) > MAX_SEMANTIC_PACK_PAYLOAD_BYTES:
        raise Attestor41Error("aggregate semantic rule-pack payload exceeds the worker boundary")
    return rows


def _relative_path(raw: Any, requested: Path) -> str:
    base = requested.parent if requested.is_file() else requested
    text = _bounded_text(raw, 8_000).replace("\\", "/")
    if not text or text in {".", "workspace", "<workspace>"}:
        return "workspace"
    try:
        supplied = Path(text)
        lexical = Path(os.path.abspath(os.fspath(
            supplied if supplied.is_absolute() else base / supplied)))
        lexical_relative = lexical.relative_to(base)
        current = base
        for part in lexical_relative.parts:
            current = current / part
            if _is_link_or_reparse(current):
                return UNBOUND_PATH
        resolved = lexical.resolve()
        relative = resolved.relative_to(base).as_posix()
        if requested.is_file() and resolved != requested:
            return UNBOUND_PATH
        return relative or (requested.name if requested.is_file() else "workspace")
    except (OSError, RuntimeError, ValueError):
        return UNBOUND_PATH


def _normalise_finding(row: Mapping[str, Any], source: str, requested: Path) -> dict[str, Any]:
    rule = _bounded_text(row.get("rule") or row.get("rule_id") or "ATTESTOR41-OBSERVATION", 300)
    severity = _bounded_text(row.get("severity", "MEDIUM"), 20).upper()
    if severity not in SEVERITY_RANK:
        severity = "MEDIUM"
    try:
        line = max(1, min(2_147_483_647, int(row.get("line", 1))))
    except (TypeError, ValueError):
        line = 1
    path = _relative_path(row.get("path"), requested)
    message = _bounded_text(
        row.get("message") or row.get("title") or row.get("evidence") or
        "The bounded analyzer recorded this observation.", 1_500)
    fix = _bounded_text(row.get("fix") or row.get("remediation") or
                        "Review the cited source and add a focused regression test before changing it.", 1_500)
    identity = {"rule": rule, "severity": severity, "path": path, "line": line,
                "message": message, "source_engine": source}
    fingerprint = _bounded_text(row.get("fingerprint"), 64)
    if len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint):
        fingerprint = _sha(identity)
    result = {**identity, "fix": fix, "fingerprint": fingerprint,
              "source_engine": source,
              "analysis_level": _bounded_text(row.get("analysis_level") or
                                                row.get("precision") or "bounded-static", 160)}
    evidence_state = row.get("evidence_state")
    result["evidence_state"] = (
        evidence_state if evidence_state in security_validation413.CLAIM_STATES
        else "inferred")
    exploitability = row.get("exploitability")
    if isinstance(exploitability, Mapping):
        score = exploitability.get("score")
        if type(score) is int and 0 <= score <= 100:
            result["exploitability_score"] = score
        band = exploitability.get("band")
        if isinstance(band, str) and band in {"critical", "high", "medium", "low"}:
            result["exploitability_band"] = band
    for key, limit in (("category", 160), ("cwe", 40), ("confidence", 40),
                       ("evidence_id", 160), ("source_kind", 120)):
        if row.get(key) not in (None, ""):
            result[key] = _bounded_text(row.get(key), limit)
    return result


def _bindable(finding: Mapping[str, Any], requested: Path,
              line_counts: dict[str, int] | None = None) -> bool:
    path_text = str(finding.get("path", ""))
    if (not path_text or path_text == UNBOUND_PATH or
            path_text in {"workspace", ".", "<workspace>"}):
        return False
    base = requested.parent if requested.is_file() else requested
    try:
        supplied = Path(path_text)
        target = supplied.resolve() if supplied.is_absolute() else (base / supplied).resolve()
        target.relative_to(base)
        if not target.is_file() or (requested.is_file() and target != requested):
            return False
        raw_line = finding.get("line", 1)
        if isinstance(raw_line, bool):
            return False
        line = int(raw_line)
        if line < 1:
            return False
        cache = line_counts if line_counts is not None else {}
        identity = os.fspath(target)
        if identity not in cache:
            size = target.stat().st_size
            if size > truth_guard41.MAX_FILE_BYTES:
                return False
            newlines = 0
            final = b""
            with target.open("rb") as stream:
                while True:
                    block = stream.read(128 * 1024)
                    if not block:
                        break
                    newlines += block.count(b"\n")
                    final = block[-1:]
            cache[identity] = 1 if size == 0 else newlines + (0 if final == b"\n" else 1)
        return line <= cache[identity]
    except (OSError, RuntimeError, TypeError, ValueError):
        return False


def _deduplicate(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        key = (str(row.get("rule", "")), str(row.get("path", "")),
               int(row.get("line", 1)), str(row.get("message", "")))
        previous = result.get(key)
        if previous is None or SEVERITY_RANK.get(str(row.get("severity")), 0) > \
                SEVERITY_RANK.get(str(previous.get("severity")), 0):
            result[key] = row
    values = list(result.values())
    values.sort(key=lambda row: (-SEVERITY_RANK.get(str(row.get("severity")), 0),
                                 str(row.get("path", "")), int(row.get("line", 1)),
                                 str(row.get("rule", ""))))
    return values


def _taint_findings(graph: Mapping[str, Any], requested: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    graph_body = graph.get("graph") if isinstance(graph.get("graph"), Mapping) else {}
    witnesses = graph_body.get("taint_witnesses") if isinstance(graph_body.get("taint_witnesses"), list) else []
    findings, paths = [], []
    for witness in witnesses[:MAX_ATTACK_PATHS]:
        if not isinstance(witness, Mapping):
            continue
        source = witness.get("source") if isinstance(witness.get("source"), Mapping) else {}
        sink = witness.get("sink") if isinstance(witness.get("sink"), Mapping) else {}
        cwe = _bounded_text(witness.get("cwe") or "CWE-20", 40)
        row = {
            "rule": "ATTESTOR41-SEMANTIC-" + cwe,
            "severity": "HIGH",
            "path": sink.get("path"), "line": sink.get("line", 1),
            "message": "A bounded parser-derived source-to-sink path reaches %s; exploitability is not established." %
                       _bounded_text(sink.get("callee") or "a sensitive operation", 200),
            "fix": "Validate or constrain untrusted data at the trust boundary and use the sink's safe structured API.",
            "cwe": cwe, "analysis_level": witness.get("precision"),
            "evidence_id": witness.get("id"),
        }
        finding = _normalise_finding(row, "semantic-graph/4.1", requested)
        findings.append(finding)
        paths.append({
            "id": _bounded_text(witness.get("id"), 160), "cwe": cwe,
            "source": {"path": _relative_path(source.get("path"), requested),
                       "line": source.get("line", 1),
                       "kind": _bounded_text(source.get("kind") or source.get("callee"), 200)},
            "sink": {"path": finding["path"], "line": finding["line"],
                     "callee": _bounded_text(sink.get("callee"), 200)},
            "cross_file": witness.get("cross_file") is True,
            "evidence": "bounded-parser-derived; not exploit proof",
        })
    return findings, paths


def _gaps_from(section: Any, prefix: str) -> list[str]:
    if not isinstance(section, Mapping):
        return [prefix + ": component evidence unavailable"]
    coverage = section.get("coverage") if isinstance(section.get("coverage"), Mapping) else section
    raw = coverage.get("gaps", []) if isinstance(coverage, Mapping) else []
    if not isinstance(raw, list):
        return [prefix + ": coverage gaps had an invalid shape"]
    rows = []
    for item in raw:
        if isinstance(item, Mapping):
            detail = item.get("reason") or item.get("message") or item.get("kind") or "structured coverage gap"
            location = item.get("path")
            rows.append("%s: %s%s" % (prefix, _bounded_text(detail, 700),
                                      " (%s)" % _bounded_text(location, 300) if location else ""))
        elif item:
            rows.append(prefix + ": " + _bounded_text(item, 900))
    limitations = coverage.get("limitations", []) if isinstance(coverage, Mapping) else []
    if isinstance(limitations, list):
        rows.extend(prefix + " limitation: " + _bounded_text(item, 850)
                    for item in limitations if item)
    if isinstance(coverage, Mapping) and (
            coverage.get("complete") is False or
            coverage.get("semantic_complete") is False or
            coverage.get("complete_within_declared_static_adapters") is False):
        rows.append(prefix + ": declared analysis coverage is incomplete")
    return rows


_WORKER_AUGMENTATION_FIELDS = frozenset({
    "worker_action", "worker_request_sha256", "worker_result_sha256",
    "worker_boundary", "worker_wrapper_sha256",
    "worker_original_report_sha256",
})


def _replay_augmented_worker_report(
        value: Mapping[str, Any], expected_action: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (type(value) is not dict or
            not _source_report_digest_valid(value) or
            value.get("worker_action") != expected_action or
            not _sha256_text(value.get("worker_request_sha256")) or
            not _sha256_text(value.get("worker_result_sha256")) or
            not _sha256_text(value.get("worker_wrapper_sha256")) or
            not _sha256_text(value.get("worker_original_report_sha256")) or
            type(value.get("worker_boundary")) is not dict):
        raise Attestor41Error(
            "an augmented worker report has an invalid digest chain")
    original = {
        key: item for key, item in value.items()
        if key not in _WORKER_AUGMENTATION_FIELDS and key != "report_sha256"
    }
    original["report_sha256"] = value["worker_original_report_sha256"]
    if (not _source_report_digest_valid(original) or
            _sha(original) != value["worker_result_sha256"]):
        raise Attestor41Error(
            "an augmented worker report does not replay to its original result")
    wrapper_body = {
        "schema": bounded_worker41.SCHEMA,
        "version": bounded_worker41.VERSION,
        "status": "completed",
        "action": expected_action,
        "request_sha256": value["worker_request_sha256"],
        "result": original,
        "result_sha256": value["worker_result_sha256"],
        "error": "",
        "boundary": value["worker_boundary"],
    }
    if _sha(wrapper_body) != value["worker_wrapper_sha256"]:
        raise Attestor41Error(
            "an augmented worker report does not replay to its worker wrapper")
    attestation = {
        "schema": bounded_worker41.SCHEMA,
        "version": bounded_worker41.VERSION,
        "action": expected_action,
        "request_sha256": value["worker_request_sha256"],
        "result_sha256": value["worker_result_sha256"],
        "result_report_sha256": value["worker_original_report_sha256"],
        "wrapper_sha256": value["worker_wrapper_sha256"],
        "boundary": json.loads(
            _canonical(value["worker_boundary"]).decode("utf-8")),
        "replayed_during_generation": True,
        "independently_replayable_from_projection": False,
        "origin_authentication":
            "inherits-outer-truth-guard3-hmac-when-independently-verified",
        "verification_state":
            "construction-time-replay-record-original-required-for-independent-verification",
    }
    return original, attestation


def _worker_public_component_projection(
        name: str, source: Mapping[str, Any], *, action: str,
        retain: Sequence[str],
        children: Mapping[str, str],
        embedded_children: Mapping[str, Any]) -> dict[str, Any]:
    original, attestation = _replay_augmented_worker_report(source, action)
    projection = _public_component_projection(
        name, original, retain=retain, children=children,
        embedded_children=embedded_children)
    projection["worker_attestation"] = attestation
    projection["report_sha256"] = _sha({
        key: item for key, item in projection.items()
        if key != "report_sha256"
    })
    if not _verify_public_component_projection(projection):
        raise Attestor41Error("a worker public projection failed verification")
    return projection


def _worker(
        action: str, payload: Mapping[str, Any], *,
        variant_profile: variant414.VariantProfile | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        if variant_profile is None:
            wrapper = bounded_worker41.run(action, payload, timeout=180.0)
        else:
            profile = variant414.require_compiled_profile(variant_profile)
            wrapper = bounded_worker41.run(
                action, payload,
                timeout=float(profile.max_worker_seconds),
                max_output_bytes=profile.max_worker_output_bytes,
                max_memory_bytes=profile.max_worker_memory_bytes,
            )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return None, ["%s worker failed closed before producing evidence: %s" %
                      (action, type(exc).__name__)]
    ok, errors = bounded_worker41.verify_report(wrapper)
    if not ok or wrapper.get("status") != "completed" or not isinstance(wrapper.get("result"), Mapping):
        reason = ", ".join(errors) or _bounded_text(wrapper.get("error") or wrapper.get("status"), 300)
        return None, ["%s worker failed closed: %s" % (action, reason)]
    result = dict(wrapper["result"])
    if not _inner_digest_valid(result):
        return None, [action + " worker returned invalid inner evidence"]
    if action == "coding-static":
        import analysis_snapshot41
        import deep_correctness41
        import semantic_graph41
        import semantic_rule_sdk41
        validators = (
            ("snapshot", analysis_snapshot41.verify_report),
            ("semantic_graph", semantic_graph41.verify_report),
            ("deep_correctness", deep_correctness41.verify_report),
        )
        for name, validator in validators:
            valid, _nested_errors = validator(result.get(name, {}))
            if not valid:
                return None, ["coding-static returned invalid %s evidence" % name]
        rule_reports = result.get("semantic_rule_reports", [])
        if not isinstance(rule_reports, list) or any(
                not semantic_rule_sdk41.verify_report(row)[0]
                for row in rule_reports if isinstance(row, Mapping)) or any(
                    not isinstance(row, Mapping) for row in rule_reports):
            return None, ["coding-static returned invalid semantic rule evidence"]
    elif action == "security-static":
        import secret_lifecycle41
        import supply_chain_trust41
        if not supply_chain_trust41.verify_graph_report(
                result.get("supply_chain_trust", {})):
            return None, ["security-static returned invalid supply-chain evidence"]
        if not secret_lifecycle41.verify_report(result.get("secret_lifecycle", {})):
            return None, ["security-static returned invalid secret-lifecycle evidence"]
    elif action == "attack-static-413":
        import attack_surface413
        valid, _nested_errors = attack_surface413.verify_report(result)
        if not valid:
            return None, ["attack-static-413 returned invalid attack-surface evidence"]
    elif action == "posture-static-413":
        import security_posture413
        if not security_posture413.verify_report(result):
            return None, ["posture-static-413 returned invalid security-posture evidence"]
    else:
        return None, ["unsupported worker action reached the evidence validator"]
    original_report_sha256 = str(result.get("report_sha256", ""))
    result["worker_action"] = action
    result["worker_request_sha256"] = wrapper.get("request_sha256", "")
    result["worker_result_sha256"] = wrapper.get("result_sha256", "")
    result["worker_boundary"] = wrapper.get("boundary", {})
    result["worker_wrapper_sha256"] = wrapper.get("report_sha256", "")
    result["worker_original_report_sha256"] = original_report_sha256
    result["report_sha256"] = _sha({key: value for key, value in result.items()
                                     if key != "report_sha256"})
    return result, []


def _empty_component(schema: str, requested: Path, reason: str) -> dict[str, Any]:
    return {"schema": schema, "version": VERSION, "root": str(requested),
            "status": "not-run", "findings": [], "coverage": {"complete": False, "gaps": [reason]}}


def _unavailable_compatibility_report(
        requested: Path, components: Sequence[str], error: str, *,
        authorize_tests: bool, apply_improvements: bool) -> dict[str, Any]:
    """Keep a legacy proof-boundary failure visible without losing newer evidence."""
    selected = sorted(set(str(item) for item in components))
    omitted = sorted(set(attestor40.DEFAULT_COMPONENTS) - set(selected))
    reason = (
        "Attestor 4.0 compatibility evidence failed closed at its proof boundary "
        "and was not embedded: " + _bounded_text(error, 160)
    )
    not_run = lambda schema: {
        "schema": schema, "version": attestor40.VERSION, "root": str(requested),
        "status": "not-run", "summary": {"findings": 0}, "findings": [],
        "coverage": {"gaps": [reason], "absence_proven": False},
    }
    return {
        "schema": attestor40.SCHEMA, "version": attestor40.VERSION,
        "root": str(requested), "status": "failed",
        "summary": {
            "findings": 0, "attack_paths": 0, "component_errors": 1,
            "verified_improvements": 0, "refused_improvements": 0,
            "engineering_findings": 0, "security_fabric_findings": 0,
        },
        "findings": [], "top_findings": [], "priorities": [],
        "attack_paths": [], "improvements": [], "improvement_plans_40": [],
        "errors": [{"component": "attestor-4.0-compatibility",
                    "error": _bounded_text(error, 160)}],
        "coverage": {
            "requested_components": selected, "completed_components": [],
            "omitted_components": omitted, "gaps": [reason],
            "absence_proven": False,
        },
        "engineering": not_run("attestor-engineering/4.0"),
        "security_fabric": not_run("attestor-security-fabric/4.0"),
        "execution": {
            "compatibility_analysis_attempted": True,
            "compatibility_analysis_completed": False,
            "target_code_executed": None if authorize_tests else False,
            "target_code_may_have_executed": bool(authorize_tests),
            "selected_tests_executed": None if authorize_tests else False,
            "changes_applied": None if apply_improvements else False,
        },
        "engines": {"compatibility_core": "unavailable"},
        "assurance_40": [
            "Unavailable compatibility evidence is a coverage gap, not evidence that no finding exists.",
            "The Attestor 4.1.3 analyzers remain independently bounded and verifiable.",
        ],
    }


def maximum(
        root: str | os.PathLike[str], *, issue: str = "", improve: bool = True,
        max_improvement_files: int = 3, compiler_checks: bool = False,
        use_cache: bool = True, jobs: int = 4,
        test_command: Sequence[str] | None = None, authorize_tests: bool = False,
        apply_improvements: bool = False, backup_root: str = "",
        advisory_snapshot: Mapping[str, Any] | None = None,
        advisory_keys: Mapping[str, bytes] | None = None,
        legacy_rule_packs: Sequence[str] = (), rule_pack_key: bytes | None = None,
        require_signed_packs: bool = False,
        semantic_rule_packs: Sequence[str | os.PathLike[str] | Mapping[str, Any]] = (),
        staged_diff: str = "", history_export: str = "",
        repair_candidates: Sequence[repair_director41.RepairCandidate] = (),
        include_candidate_source: bool = False,
        memory_baseline: Mapping[str, Any] | None = None,
        legacy_components: Sequence[str] = attestor40.DEFAULT_COMPONENTS,
        calibration_profile: Mapping[str, Any] | None = None,
        calibration_observations: Iterable[Mapping[str, Any]] | None = None,
        git_base: str = "", symbolic_timeout: float = 45.0,
        truth_key: bytes | None = None, truth_key_id: str = "",
        variant_profile: variant414.VariantProfile | None = None) -> dict[str, Any]:
    """Return one source-bound Attestor 4.1.3 report; no online access is performed."""
    requested = _selected_root(root)
    if (type(max_improvement_files) is not int or
            not 0 <= max_improvement_files <= 16):
        raise Attestor41Error(
            "max_improvement_files must be an integer between 0 and 16")
    profile: variant414.VariantProfile | None = None
    if variant_profile is not None:
        try:
            profile = variant414.require_compiled_profile(variant_profile)
        except variant414.VariantError as exc:
            raise Attestor41Error("variant profile is not compiled into this release") from exc
        jobs = profile.max_concurrency
        symbolic_timeout = float(profile.symbolic_timeout_seconds)
        legacy_components = profile.legacy_components
        max_improvement_files = min(
            max_improvement_files, profile.max_improvement_files)
    if type(jobs) is not int or not 1 <= jobs <= 64:
        raise Attestor41Error("jobs must be an integer between 1 and 64")
    if not isinstance(issue, str) or len(issue.encode("utf-8")) > 64 * 1024:
        raise Attestor41Error("issue must be text no larger than 64 KiB")
    if not isinstance(staged_diff, str) or len(staged_diff.encode("utf-8")) > 128 * 1024:
        raise Attestor41Error("staged-diff evidence exceeds 128 KiB")
    if not isinstance(history_export, str) or len(history_export.encode("utf-8")) > 128 * 1024:
        raise Attestor41Error("history evidence exceeds 128 KiB")
    try:
        legacy_components_input = _bounded_tuple(
            legacy_components, 64, "legacy component selection")
        legacy_rule_pack_inputs = _bounded_tuple(
            legacy_rule_packs, MAX_LEGACY_RULE_PACKS, "legacy rule-pack selection")
        semantic_rule_pack_inputs = _bounded_tuple(
            semantic_rule_packs, 32, "semantic rule-pack selection")
        repair_candidate_inputs = _bounded_tuple(
            repair_candidates, repair_director41.MAX_CANDIDATES,
            "repair candidate selection")
        test_command_input = (_bounded_tuple(test_command, 256, "test command")
                              if test_command is not None else None)
        calibration_observation_inputs = (
            _bounded_tuple(calibration_observations, MAX_CALIBRATION_OBSERVATIONS,
                           "calibration observations")
            if calibration_observations is not None else None)
    except TypeError as exc:
        raise Attestor41Error("an analysis input sequence is invalid") from exc
    packs = _load_semantic_packs(semantic_rule_pack_inputs)
    legacy_pack_descriptors = _file_input_descriptors(legacy_rule_pack_inputs)
    if packs and rule_pack_key is not None and (
            not isinstance(rule_pack_key, bytes) or not 16 <= len(rule_pack_key) <= 512):
        raise Attestor41Error("semantic rule-pack verification key must contain 16 to 512 bytes")
    if packs and require_signed_packs and rule_pack_key is None:
        raise Attestor41Error("signed semantic rule packs require a verification key")

    compatibility_failure = ""
    try:
        inherited = attestor40.maximum(
            requested, issue=issue, improve=improve,
            max_improvement_files=max_improvement_files,
            compiler_checks=compiler_checks, use_cache=use_cache, jobs=jobs,
            test_command=test_command_input, authorize_tests=authorize_tests,
            apply_improvements=apply_improvements, backup_root=backup_root,
            advisory_snapshot=advisory_snapshot, advisory_keys=advisory_keys,
            rule_packs=legacy_rule_pack_inputs, rule_pack_key=rule_pack_key,
            require_signed_packs=require_signed_packs,
            memory_baseline=memory_baseline, components=legacy_components_input,
            calibration_profile=calibration_profile,
            calibration_observations=calibration_observation_inputs,
            git_base=git_base, symbolic_timeout=symbolic_timeout,
            truth_key=truth_key, truth_key_id=truth_key_id)
        public40 = attestor40.safe_public_report(inherited, truth_key=truth_key)
    except (truth_guard.TruthGuardError, truth_guard35.TruthGuard35Error,
            truth_guard40.TruthGuard40Error) as exc:
        compatibility_failure = type(exc).__name__
        public40 = _unavailable_compatibility_report(
            requested, legacy_components_input, compatibility_failure,
            authorize_tests=authorize_tests,
            apply_improvements=apply_improvements)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise Attestor41Error("Attestor 4.0 compatibility analysis failed closed: " + type(exc).__name__) from exc
    if public40.get("status") == "inconsistent":
        compatibility_failure = "integrity-verification-failed"
        public40 = _unavailable_compatibility_report(
            requested, legacy_components_input, compatibility_failure,
            authorize_tests=authorize_tests,
            apply_improvements=apply_improvements)
    compatibility_audit = public40.get("truth_guard2") \
        if isinstance(public40.get("truth_guard2"), Mapping) else {}
    independent_validation = compatibility_audit.get("independent_validation") \
        if isinstance(compatibility_audit.get("independent_validation"), Mapping) else {}
    compatibility_validation_projected = \
        independent_validation.get("projected") is True
    compatibility_audit_public: Mapping[str, Any] = compatibility_audit
    if not compatibility_failure and compatibility_audit:
        compatibility_audit_public = _compatibility_audit_projection(
            compatibility_audit)
        if not _verify_compatibility_audit_projection(
                compatibility_audit_public):
            raise Attestor41Error(
                "the compatibility audit projection failed verification")
    compatibility_guard40 = (
        {
            "state": "unavailable-failed-closed",
            "schema": _bounded_text(public40.get("schema"), 120),
            "report_sha256": "", "truth_guard2": {},
            "truth_guard2_projected": False,
            "error": compatibility_failure,
        }
        if compatibility_failure else
        {
            "state": (
                "verified-before-embedding-with-bounded-independent-validation"
                if compatibility_validation_projected else
                "verified-before-embedding"
            ),
            "schema": _bounded_text(public40.get("schema"), 120),
            "report_sha256": _bounded_text(public40.get("report_sha256"), 64),
            "truth_guard2": compatibility_audit_public,
            "truth_guard2_projected":
                compatibility_audit_public.get("schema") ==
                COMPATIBILITY_AUDIT_PROJECTION_SCHEMA,
        }
    )
    report = _strip_guard(public40)
    compatibility_projections = []
    if not compatibility_failure:
        for field, retained_fields in (
                ("engineering", (
                    "root", "status", "summary", "coverage", "analysis",
                    "execution", "limits")),
                ("security_fabric", (
                    "root", "status", "summary", "coverage", "assurance",
                    "limits"))):
            component = report.get(field)
            if _source_report_digest_valid(component):
                projection = _public_component_projection(
                    "attestor40-" + field.replace("_", "-"),
                    component, retain=retained_fields)
                if not _verify_public_component_projection(projection):
                    raise Attestor41Error(
                        "a compatibility public projection failed verification")
                report[field] = projection
                compatibility_projections.append(field)
    if compatibility_projections or compatibility_validation_projected:
        compatibility_coverage = report.get("coverage")
        if isinstance(compatibility_coverage, Mapping):
            compatibility_coverage = dict(compatibility_coverage)
        else:
            compatibility_coverage = {}
        compatibility_gaps = compatibility_coverage.get("gaps")
        compatibility_gaps = list(compatibility_gaps) \
            if isinstance(compatibility_gaps, list) else []
        if compatibility_projections:
            compatibility_gaps.append(
                "Attestor 4.0 nested %s evidence was verified, then represented by "
                "digest-bound public projections to avoid duplicating high-cardinality "
                "evidence; normalized findings remain at the top level." %
                " and ".join(name.replace("_", "-")
                             for name in compatibility_projections))
        if compatibility_validation_projected:
            compatibility_gaps.append(
                "Truth Guard 2.1 bound the complete compatibility report digest "
                "and component contracts, but its older independent-claim adapter "
                "validated a deterministic bounded projection")
        compatibility_coverage.update({
            "gaps": list(dict.fromkeys(compatibility_gaps)),
            "absence_proven": False,
        })
        report["coverage"] = compatibility_coverage
    errors = list(report.get("errors", [])) if isinstance(report.get("errors"), list) else []
    component_errors: list[str] = []
    coding: dict[str, Any] | None = None
    security: dict[str, Any] | None = None
    attack: dict[str, Any] | None = None
    posture: dict[str, Any] | None = None
    if requested.is_dir():
        all_worker_actions = (
            "coding-static", "security-static",
            "attack-static-413", "posture-static-413",
        )
        selected_worker_actions = (
            frozenset(profile.worker_actions)
            if profile is not None else frozenset(all_worker_actions))
        coding_payload = {
            "root": str(requested), "rule_packs": packs,
            "rule_pack_key_base64": (
                base64.b64encode(rule_pack_key).decode("ascii")
                if rule_pack_key is not None else ""),
            "require_signed_packs": bool(require_signed_packs),
        }
        if profile is not None:
            coding_payload["snapshot_limits"] = {
                "max_files": profile.max_files,
                "max_file_bytes": profile.max_file_bytes,
                "max_total_bytes": profile.max_total_bytes,
                "max_path_chars": 4_096,
            }
            coding_payload["max_graph_nodes"] = profile.max_graph_nodes
        payloads = {
            "coding-static": coding_payload,
            "security-static": {
                "root": str(requested), "staged_diff": staged_diff,
                "history_export": history_export,
            },
            "attack-static-413": {"root": str(requested)},
            "posture-static-413": {
                "root": str(requested), "staged_diff": staged_diff,
                "history_export": history_export,
            },
        }

        def dispatch_worker(action: str):
            if profile is None:
                return _worker(action, payloads[action])
            return _worker(
                action, payloads[action], variant_profile=profile)

        worker_count = min(
            len(selected_worker_actions),
            profile.max_concurrency if profile is not None else 4)
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, worker_count),
                thread_name_prefix="attestor413") as pool:
            futures = {
                action: pool.submit(dispatch_worker, action)
                for action in all_worker_actions
                if action in selected_worker_actions
            }

            def worker_result(action: str):
                if action not in futures:
                    if profile is None:
                        raise Attestor41Error(
                            "worker selection invariant failed closed")
                    return None, [
                        "%s omitted by compiled variant %s" %
                        (action, profile.slug)]
                return futures[action].result()

            coding, coding_errors = worker_result("coding-static")
            security, security_errors = worker_result("security-static")
            attack, attack_errors = worker_result("attack-static-413")
            posture, posture_errors = worker_result("posture-static-413")
        component_errors.extend(
            coding_errors + security_errors + attack_errors + posture_errors)
    else:
        component_errors.extend([
            "semantic-correctness: exact-file scope is not widened to its parent directory",
            "supply-chain/secret-lifecycle: exact-file scope requires a dedicated artifact scan",
            "attack-surface: exact-file scope is not widened to discover other services",
            "cloud/IaC posture: exact-file scope requires a dedicated artifact scan",
        ])

    base_findings = [_normalise_finding(row, _bounded_text(row.get("source_engine") or "attestor-4.0", 160), requested)
                     for row in report.get("findings", []) if isinstance(row, Mapping)]
    new_findings: list[dict[str, Any]] = []
    attack_paths = list(report.get("attack_paths", [])) if isinstance(report.get("attack_paths"), list) else []
    semantic_graph: Mapping[str, Any] = {}
    deep_correctness: Mapping[str, Any] = {}
    semantic_reports: list[Any] = []
    snapshot: Mapping[str, Any] = {}
    if coding:
        snapshot = coding.get("snapshot") if isinstance(coding.get("snapshot"), Mapping) else {}
        semantic_graph = coding.get("semantic_graph") if isinstance(coding.get("semantic_graph"), Mapping) else {}
        deep_correctness = coding.get("deep_correctness") if isinstance(coding.get("deep_correctness"), Mapping) else {}
        semantic_reports = coding.get("semantic_rule_reports") if isinstance(coding.get("semantic_rule_reports"), list) else []
        taint_rows, paths = _taint_findings(semantic_graph, requested)
        new_findings.extend(taint_rows)
        attack_paths.extend(paths)
        for row in deep_correctness.get("findings", []) if isinstance(deep_correctness.get("findings"), list) else []:
            if isinstance(row, Mapping):
                new_findings.append(_normalise_finding(row, "deep-correctness/4.1", requested))
        for rule_report in semantic_reports:
            if not isinstance(rule_report, Mapping):
                continue
            for row in rule_report.get("findings", []) if isinstance(rule_report.get("findings"), list) else []:
                if isinstance(row, Mapping):
                    new_findings.append(_normalise_finding(row, "semantic-rule-sdk/4.1", requested))

    supply_chain: Mapping[str, Any] = {}
    secret_lifecycle: Mapping[str, Any] = {}
    lifecycle_artifact_observations: list[dict[str, Any]] = []
    if security:
        supply_chain = security.get("supply_chain_trust") if isinstance(security.get("supply_chain_trust"), Mapping) else {}
        secret_lifecycle = security.get("secret_lifecycle") if isinstance(security.get("secret_lifecycle"), Mapping) else {}
        for row in secret_lifecycle.get("findings", []) if isinstance(secret_lifecycle.get("findings"), list) else []:
            if isinstance(row, Mapping):
                enriched = dict(row)
                enriched.setdefault("message", "A secret-shaped value was detected; its value, hash, prefix, and suffix are withheld.")
                enriched.setdefault("remediation", "Revoke and rotate the credential, remove it from every exposed lifecycle source, and add a secret-scanning gate.")
                normalised = _normalise_finding(enriched, "secret-lifecycle/4.1", requested)
                if str(row.get("source_kind", "")) == "workspace":
                    new_findings.append(normalised)
                else:
                    lifecycle_artifact_observations.append({
                        "rule": normalised["rule"], "severity": normalised["severity"],
                        "path": normalised["path"], "line": normalised["line"],
                        "source_engine": normalised["source_engine"],
                        "source_kind": _bounded_text(row.get("source_kind"), 120),
                        "reason": "the finding is bound to supplied lifecycle artifact evidence, not current worktree bytes",
                        "value_exposed": False, "value_hashed": False,
                    })

    semantic_graph_public: Mapping[str, Any] = semantic_graph
    if _source_report_digest_valid(semantic_graph):
        semantic_graph_public = _public_component_projection(
            "semantic-graph",
            semantic_graph,
            retain=(
                "root", "status", "summary", "coverage", "limits",
                "execution", "snapshot_sha256", "shared_snapshot_sha256"))
        if not _verify_public_component_projection(semantic_graph_public):
            raise Attestor41Error(
                "the semantic-graph public projection failed verification")

    coding_public: Mapping[str, Any] = coding or _empty_component(
        "attestor-coding-fabric/4.1", requested, "coding worker not completed")
    if coding and _source_report_digest_valid(coding):
        coding_public = _worker_public_component_projection(
            "coding-fabric-worker",
            coding,
            action="coding-static",
            retain=("execution", "shared_snapshot_sha256"),
            children={
                "snapshot": "analysis_snapshot_41",
                "semantic_graph": "semantic_graph_41",
                "deep_correctness": "deep_correctness_41",
                "semantic_rule_reports": "semantic_rule_reports_41",
            },
            embedded_children={
                "snapshot": snapshot,
                "semantic_graph": semantic_graph_public,
                "deep_correctness": deep_correctness,
                "semantic_rule_reports": semantic_reports,
            })
    security_public: Mapping[str, Any] = security or _empty_component(
        "attestor-security-static-fabric/4.1", requested,
        "security worker not completed")
    if security and _source_report_digest_valid(security):
        security_public = _worker_public_component_projection(
            "security-static-fabric-worker",
            security,
            action="security-static",
            retain=("execution",),
            children={
                "supply_chain_trust": "supply_chain_trust_41",
                "secret_lifecycle": "secret_lifecycle_41",
            },
            embedded_children={
                "supply_chain_trust": supply_chain,
                "secret_lifecycle": secret_lifecycle,
            })
    for projection in (coding_public, security_public):
        if (isinstance(projection, Mapping) and
                projection.get("schema") == PUBLIC_PROJECTION_SCHEMA and
                not _verify_public_component_projection(projection)):
            raise Attestor41Error("a public component projection failed verification")

    attack_surface: Mapping[str, Any] = ({
        key: value for key, value in attack.items()
        if key not in _WORKER_AUGMENTATION_FIELDS | {"report_sha256"}
    } | {"report_sha256": attack.get("worker_original_report_sha256", "")}
        if attack else {})
    attack_surface_paths: list[dict[str, Any]] = []
    if attack:
        for row in attack.get("findings", []) if isinstance(attack.get("findings"), list) else []:
            if isinstance(row, Mapping):
                new_findings.append(
                    _normalise_finding(row, "attack-surface/4.1.3", requested))
        for row in attack.get("attack_paths", []) if isinstance(attack.get("attack_paths"), list) else []:
            if not isinstance(row, Mapping):
                continue
            exploitability = row.get("exploitability")
            band = exploitability.get("band") if isinstance(exploitability, Mapping) else ""
            score = exploitability.get("score") if isinstance(exploitability, Mapping) else None
            attack_surface_paths.append({
                "id": _bounded_text(row.get("id"), 160),
                "title": "Static entry-point path to " +
                         _bounded_text(row.get("category") or "a sensitive sink", 200),
                "category": _bounded_text(row.get("category"), 160),
                "finding_id": _bounded_text(row.get("finding_id"), 160),
                "evidence_state": "inferred",
                "runtime_exploitability": "unverified",
                "exploitability": (
                    _bounded_text(band, 40) +
                    (" (%d/100)" % score if type(score) is int else "")),
                "node_count": len(row.get("nodes", []))
                    if isinstance(row.get("nodes"), list) else 0,
                "edge_count": len(row.get("edges", []))
                    if isinstance(row.get("edges"), list) else 0,
            })
        attack_paths.extend(attack_surface_paths)

    security_posture: Mapping[str, Any] = ({
        key: value for key, value in posture.items()
        if key not in _WORKER_AUGMENTATION_FIELDS | {"report_sha256"}
    } | {"report_sha256": posture.get("worker_original_report_sha256", "")}
        if posture else {})
    posture_artifact_observations: list[dict[str, Any]] = []
    if posture:
        for row in posture.get("findings", []) if isinstance(posture.get("findings"), list) else []:
            if not isinstance(row, Mapping):
                continue
            normalised = _normalise_finding(
                row, "security-posture/4.1.3", requested)
            if str(row.get("path", "")).startswith("__attestor_supplied__/"):
                posture_artifact_observations.append({
                    "rule": normalised["rule"],
                    "severity": normalised["severity"],
                    "path": normalised["path"],
                    "line": normalised["line"],
                    "source_engine": normalised["source_engine"],
                    "reason": "the observation is bound to supplied metadata, not current worktree bytes",
                })
            else:
                new_findings.append(normalised)
    lifecycle_artifact_observations.extend(posture_artifact_observations)

    combined = _deduplicate([*base_findings, *new_findings])
    bindable_rows: list[dict[str, Any]] = []
    quarantined_rows: list[dict[str, Any]] = []
    line_counts: dict[str, int] = {}
    for row in combined:
        if _bindable(row, requested, line_counts):
            bindable_rows.append(row)
        else:
            quarantined_rows.append({
                "rule": row["rule"], "severity": row["severity"],
                "path": row["path"], "line": row["line"],
                "source_engine": row["source_engine"],
                "reason": "no exact regular in-scope source file was available for Truth Guard binding",
            })
    quarantined_rows.extend(lifecycle_artifact_observations)
    findings_total = len(bindable_rows)
    unbound_total = len(quarantined_rows)
    findings_truncated = max(0, findings_total - MAX_FINDINGS)
    unbound_truncated = max(0, unbound_total - MAX_UNBOUND_OBSERVATIONS)
    findings = bindable_rows[:MAX_FINDINGS]
    unbound = quarantined_rows[:MAX_UNBOUND_OBSERVATIONS]

    coverage = dict(report.get("coverage", {})) if isinstance(report.get("coverage"), Mapping) else {}
    gaps = list(coverage.get("gaps", [])) if isinstance(coverage.get("gaps"), list) else []
    gaps.extend(component_errors)
    if (isinstance(coding_public, Mapping) and
            coding_public.get("schema") == PUBLIC_PROJECTION_SCHEMA):
        gaps.append(
            "coding worker envelope: verified child reports are embedded once; "
            "the duplicate full worker envelope is represented by a digest-bound projection")
    if (isinstance(security_public, Mapping) and
            security_public.get("schema") == PUBLIC_PROJECTION_SCHEMA):
        gaps.append(
            "security worker envelope: verified child reports are embedded once; "
            "the duplicate full worker envelope is represented by a digest-bound projection")
    if (isinstance(semantic_graph_public, Mapping) and
            semantic_graph_public.get("schema") ==
            PUBLIC_PROJECTION_SCHEMA):
        gaps.append(
            "semantic graph: the complete verified graph exceeded a practical "
            "single-envelope size, so its digest, counts, coverage, and normalized "
            "source-bound findings are retained in a public projection")
    if coding:
        gaps.extend(_gaps_from(snapshot, "snapshot"))
        gaps.extend(_gaps_from(semantic_graph, "semantic-graph"))
        gaps.extend(_gaps_from(deep_correctness, "deep-correctness"))
        for index, value in enumerate(semantic_reports):
            gaps.extend(_gaps_from(value, "semantic-rule-pack-%d" % (index + 1)))
        boundary = coding.get("worker_boundary") if isinstance(coding.get("worker_boundary"), Mapping) else {}
        if str(boundary.get("memory_limit", "")).startswith("unavailable"):
            gaps.append("coding worker: a portable stdlib hard memory limit is unavailable on Windows")
        if boundary.get("network_kernel_blocked") is not True:
            gaps.append("coding worker: network denial is contractual, not kernel-enforced")
    if security:
        gaps.extend(_gaps_from(supply_chain, "supply-chain"))
        gaps.extend(_gaps_from(secret_lifecycle, "secret-lifecycle"))
        for adapter in supply_chain.get("unavailable_adapters", []) if isinstance(supply_chain.get("unavailable_adapters"), list) else []:
            gaps.append("supply-chain unavailable adapter: " + _bounded_text(adapter, 400))
        boundary = security.get("worker_boundary") if isinstance(security.get("worker_boundary"), Mapping) else {}
        if str(boundary.get("memory_limit", "")).startswith("unavailable"):
            gaps.append("security worker: a portable stdlib hard memory limit is unavailable on Windows")
        if boundary.get("network_kernel_blocked") is not True:
            gaps.append("security worker: network denial is contractual, not kernel-enforced")
    if attack:
        gaps.extend(_gaps_from(attack_surface, "attack-surface"))
        boundary = attack.get("worker_boundary") \
            if isinstance(attack.get("worker_boundary"), Mapping) else {}
        if str(boundary.get("memory_limit", "")).startswith("unavailable"):
            gaps.append("attack-surface worker: a portable stdlib hard memory limit is unavailable on Windows")
        if boundary.get("network_kernel_blocked") is not True:
            gaps.append("attack-surface worker: network denial is contractual, not kernel-enforced")
    if posture:
        raw_posture_gaps = posture.get("gaps", [])
        if isinstance(raw_posture_gaps, list):
            for item in raw_posture_gaps:
                if isinstance(item, Mapping):
                    gaps.append(
                        "security-posture: %s%s" % (
                            _bounded_text(
                                item.get("reason") or item.get("capability") or
                                "structured coverage gap", 700),
                            " (%s)" % _bounded_text(item.get("path"), 300)
                            if item.get("path") else ""))
                elif item:
                    gaps.append("security-posture: " + _bounded_text(item, 900))
        gaps.extend(_gaps_from(security_posture, "security-posture"))
        boundary = posture.get("worker_boundary") \
            if isinstance(posture.get("worker_boundary"), Mapping) else {}
        if str(boundary.get("memory_limit", "")).startswith("unavailable"):
            gaps.append("security-posture worker: a portable stdlib hard memory limit is unavailable on Windows")
        if boundary.get("network_kernel_blocked") is not True:
            gaps.append("security-posture worker: network denial is contractual, not kernel-enforced")
    if unbound_total:
        gaps.append("%d observation(s) were quarantined because exact source-byte binding was unavailable" %
                    unbound_total)
    if findings_truncated:
        gaps.append("%d source-bindable finding(s) were omitted by the %d-finding public-report boundary" %
                    (findings_truncated, MAX_FINDINGS))
    if unbound_truncated:
        gaps.append("%d quarantined observation(s) were omitted by the %d-observation public-report boundary" %
                    (unbound_truncated, MAX_UNBOUND_OBSERVATIONS))
    gaps = list(dict.fromkeys(_bounded_text(item, 1_000) for item in gaps if item))[:4_000]
    completed = set(str(item) for item in coverage.get("completed_components", [])
                    if isinstance(item, str))
    if coding:
        completed.add("semantic-correctness")
    if security:
        completed.update({"supply-chain-trust", "secret-lifecycle"})
    if attack:
        completed.update({"attack-surface", "web-api-auth", "threat-model"})
    if posture:
        completed.update({
            "cloud-iac-security", "crypto-tls-posture", "binary-static-posture",
            "sbom", "provenance-posture",
        })

    repair: Mapping[str, Any]
    if requested.is_dir():
        try:
            repair = repair_director41.direct(
                requested, issue=issue, findings=findings,
                candidates=repair_candidate_inputs, mechanical=improve,
                maximum_candidates=max(1, min(16, max_improvement_files or 1)),
                include_candidate_source=include_candidate_source)
            completed.add("repair-director")
            gaps.extend(_gaps_from(repair, "repair-director"))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            errors.append({"component": "repair-director", "error": type(exc).__name__})
            repair = _empty_component(repair_director41.SCHEMA, requested,
                                      "repair director failed closed")
    else:
        repair = _empty_component(repair_director41.SCHEMA, requested,
                                  "repair candidates require a directory-scoped workspace")
        gaps.extend(_gaps_from(repair, "repair-director"))

    validation_capability: Mapping[str, Any]
    security_test_plans: Mapping[str, Any]
    verified_repair: Mapping[str, Any]
    regression_memory: Mapping[str, Any]
    security_regression: Mapping[str, Any]
    claim_ledger: Mapping[str, Any]
    security_command_center: Mapping[str, Any]
    try:
        validation_capability = security_validation413.capability_report()
        threat_model = (attack_surface.get("threat_model")
                        if isinstance(attack_surface.get("threat_model"), Mapping)
                        else {})
        entry_points = (threat_model.get("entry_points", [])
                        if isinstance(threat_model.get("entry_points"), list)
                        else [])
        security_test_plans = security_validation413.generate_test_plans(
            entry_points, findings, maximum=128)
        root_identity = _sha({
            "domain": "ATTESTOR-4.1.3-PROJECT-IDENTITY",
            "root": os.path.normcase(os.path.abspath(os.fspath(requested))),
        })
        baseline_digest = _sha({
            "attack_surface": attack_surface.get("report_sha256", ""),
            "security_posture": security_posture.get("report_sha256", ""),
            "findings": [row.get("fingerprint", "") for row in findings],
        })
        verified_repair = security_validation413.new_repair_pipeline(
            root_identity_sha256=root_identity,
            patch_sha256=_sha(repair),
            baseline_sha256=baseline_digest)

        reusable_memory: Mapping[str, Any] | None = None
        if (isinstance(memory_baseline, Mapping) and
                memory_baseline.get("schema") == security_validation413.MEMORY_SCHEMA):
            memory_ok, _memory_errors = security_validation413.verify_report(
                dict(memory_baseline), schema=security_validation413.MEMORY_SCHEMA)
            if (memory_ok and
                    memory_baseline.get("root_identity_sha256") == root_identity):
                reusable_memory = json.loads(
                    _canonical(memory_baseline).decode("utf-8"))
        regression_memory = (
            reusable_memory if reusable_memory is not None
            else security_validation413.new_regression_memory(root_identity))
        existing_runs = (regression_memory.get("runs", [])
                         if isinstance(regression_memory.get("runs"), list) else [])
        previous_observed = (
            existing_runs[-1].get("observed_at", -1)
            if existing_runs and isinstance(existing_runs[-1], Mapping) else -1)
        next_observed = previous_observed + 1 \
            if type(previous_observed) is int and previous_observed >= -1 else 0
        report_already_recorded = any(
            isinstance(row, Mapping) and
            row.get("report_sha256") == baseline_digest
            for row in existing_runs)
        if report_already_recorded:
            gaps.append(
                "security regression memory: the identical content-addressed "
                "report was already present and was not replayed")
        elif len(existing_runs) >= security_validation413.MAX_REGRESSION_RUNS:
            gaps.append(
                "security regression memory: the bounded run history is full; "
                "the current report was not appended")
        else:
            regression_memory = security_validation413.record_security_run(
                regression_memory,
                report_sha256=baseline_digest,
                finding_fingerprints=(
                    row["fingerprint"] for row in findings
                    if isinstance(row.get("fingerprint"), str)),
                observed_at=next_observed)
        security_regression = security_validation413.compare_security_runs(
            regression_memory)

        claims: list[dict[str, Any]] = []
        for row in findings[:security_validation413.MAX_CLAIMS - 2]:
            state = row.get("evidence_state")
            if state not in security_validation413.CLAIM_STATES:
                state = "unverified"
            # The final Truth Guard source replay happens after this ledger is
            # constructed.  Until then even direct syntax evidence is
            # conservatively represented as inferred, never prematurely proven.
            if state == "proven":
                state = "inferred"
            claims.append({
                "text": "Attestor recorded %s at %s:%s." % (
                    _bounded_text(row.get("rule"), 300),
                    _bounded_text(row.get("path"), 500),
                    row.get("line", 1)),
                "state": state,
                "evidence": [{
                    "kind": "normalized-static-finding",
                    "locator": "%s:%s" % (
                        _bounded_text(row.get("path"), 500),
                        row.get("line", 1)),
                    "sha256": _sha(row),
                }],
                "limitation": (
                    "This state describes bounded static evidence; deployed "
                    "runtime exploitability was not exercised."),
            })
        claims.append({
            "text": (
                "The Attestor 4.1.3 validation capability contract defaults target "
                "execution, network access, source apply, and permission retention to denied."),
            "state": "proven",
            "evidence": [{
                "kind": "capability-contract",
                "locator": "security_validation_413/defaults",
                "sha256": str(validation_capability.get("report_sha256", "")),
            }],
            "limitation": "A capability contract does not prove an external operating-system sandbox.",
        })
        if gaps:
            claims.append({
                "text": "Universal vulnerability absence is not established for this analysis scope.",
                "state": "unavailable",
                "evidence": [],
                "limitation": "%d bounded coverage gap(s) remain." % len(gaps),
            })
        claim_ledger = security_validation413.claim_ledger(
            claims,
            verified_evidence_sha256=[
                str(validation_capability.get("report_sha256", "")),
            ])
        security_command_center = security_validation413.command_center(
            findings=findings,
            attack_paths=attack_paths[:MAX_ATTACK_PATHS],
            coverage_gaps=gaps,
            repair_pipeline=verified_repair,
            regression=security_regression,
            ledger=claim_ledger)
        completed.update({
            "security-validation", "security-test-planning",
            "security-regression-memory", "evidence-claim-ledger",
            "security-command-center",
        })
        gaps.extend(_gaps_from(validation_capability, "security-validation"))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        errors.append({
            "component": "security-validation-4.1.3",
            "error": type(exc).__name__,
        })
        reason = "security validation failed closed"
        validation_capability = _empty_component(
            security_validation413.SCHEMA, requested, reason)
        security_test_plans = _empty_component(
            "attestor-security-test-plans/4.1", requested, reason)
        verified_repair = _empty_component(
            security_validation413.PIPELINE_SCHEMA, requested, reason)
        regression_memory = _empty_component(
            security_validation413.MEMORY_SCHEMA, requested, reason)
        security_regression = _empty_component(
            "attestor-security-regression-comparison/4.1", requested, reason)
        claim_ledger = _empty_component(
            security_validation413.LEDGER_SCHEMA, requested, reason)
        security_command_center = _empty_component(
            security_validation413.COMMAND_CENTER_SCHEMA, requested, reason)
        gaps.append(reason + ": " + type(exc).__name__)
    gaps = list(dict.fromkeys(
        _bounded_text(item, 1_000) for item in gaps if item))[:4_000]

    severity = {name: sum(row.get("severity") == name for row in findings)
                for name in SEVERITY_RANK}
    severity_before_boundary = {
        name: sum(row.get("severity") == name for row in bindable_rows)
        for name in SEVERITY_RANK
    }
    summary = dict(report.get("summary", {})) if isinstance(report.get("summary"), Mapping) else {}
    summary.update({
        "findings": len(findings), "findings_before_public_boundary": findings_total,
        "findings_truncated": findings_truncated, "severity": severity,
        "severity_before_public_boundary": severity_before_boundary,
        "attack_paths": len(attack_paths[:MAX_ATTACK_PATHS]),
        "unbound_observations": len(unbound),
        "unbound_observations_before_public_boundary": unbound_total,
        "unbound_observations_truncated": unbound_truncated,
        "lifecycle_artifact_observations": len(lifecycle_artifact_observations),
        "semantic_taint_witnesses": len(semantic_graph.get("graph", {}).get("taint_witnesses", []))
            if isinstance(semantic_graph.get("graph"), Mapping) and
               isinstance(semantic_graph.get("graph", {}).get("taint_witnesses"), list) else 0,
        "deep_correctness_findings": len(deep_correctness.get("findings", []))
            if isinstance(deep_correctness.get("findings"), list) else 0,
        "secret_lifecycle_findings": len(secret_lifecycle.get("findings", []))
            if isinstance(secret_lifecycle.get("findings"), list) else 0,
        "attack_surface_findings": len(attack_surface.get("findings", []))
            if isinstance(attack_surface.get("findings"), list) else 0,
        "attack_surface_paths": len(attack_surface_paths),
        "security_posture_findings": len(security_posture.get("findings", []))
            if isinstance(security_posture.get("findings"), list) else 0,
        "security_test_plans": int(security_test_plans.get("plan_count", 0))
            if isinstance(security_test_plans, Mapping) else 0,
        "claim_states": dict(claim_ledger.get("counts", {}))
            if isinstance(claim_ledger.get("counts"), Mapping) else {},
        "security_regression_status": _bounded_text(
            security_regression.get("status"), 120),
        "repair_candidates": int(repair.get("summary", {}).get("candidates", 0))
            if isinstance(repair.get("summary"), Mapping) else 0,
        "component_errors": len(errors) + len(component_errors),
    })
    priorities, seen = [], set()
    for row in findings:
        key = (row["rule"], row["path"])
        if key in seen:
            continue
        seen.add(key)
        priorities.append({"priority": row["severity"], "rule": row["rule"],
                           "path": row["path"], "fix": row["fix"]})
        if len(priorities) >= 60:
            break
    status = "failed" if errors else "action-required" if findings_total or lifecycle_artifact_observations else \
        "no-findings-with-gaps" if gaps else "no-findings-from-enabled-checks"
    execution = dict(report.get("execution", {})) if isinstance(report.get("execution"), Mapping) else {}
    execution.update({
        "attestor41_analyzer_processes_started": requested.is_dir(),
        "attestor41_target_code_executed": False,
        "attestor41_target_modules_imported": False,
        "attestor41_network_accessed": False,
        "attestor41_target_files_written": False,
        "attestor413_attack_surface_executed": attack is not None,
        "attestor413_security_posture_executed": posture is not None,
        "attestor413_validation_target_executed": False,
        "attestor413_validation_network_accessed": False,
        "attestor413_permission_retained": False,
        "attestor413_automatic_apply": False,
        "research_network_accessed": False,
        "repair_apply_performed": repair.get("status") == "applied",
    })
    coverage.update({
        "completed_components": sorted(completed), "gaps": gaps,
        "complete": not gaps, "absence_proven": False,
        "exact_file_scope_preserved": requested.is_file(),
        "public_report_boundaries": {
            "findings_limit": MAX_FINDINGS, "findings_omitted": findings_truncated,
            "unbound_limit": MAX_UNBOUND_OBSERVATIONS,
            "unbound_omitted": unbound_truncated,
        },
    })
    advisory_key_ids = sorted(str(key) for key in advisory_keys) \
        if isinstance(advisory_keys, Mapping) else []
    backup_scope = os.path.abspath(os.fspath(Path(backup_root).expanduser())) \
        if backup_root else ""
    candidate_descriptors = [{
        "candidate_id_sha256": _sha(str(getattr(item, "candidate_id", "")).encode("utf-8")),
        "candidate_sha256": _bounded_text(getattr(item, "digest", ""), 64),
    } for item in repair_candidate_inputs]
    analysis_config = {
        "version": VERSION,
        "issue": {"bytes": len(issue.encode("utf-8")),
                  "sha256": _sha(issue.encode("utf-8"))},
        "legacy_components": sorted(set(str(item) for item in legacy_components_input)),
        "legacy_rule_pack_inputs": legacy_pack_descriptors,
        "semantic_rule_pack_sha256": [_sha(row) for row in packs],
        "rule_pack_policy": {
            "require_signed": bool(require_signed_packs),
            "verification_key_supplied": rule_pack_key is not None,
        },
        "advisory_snapshot_sha256": _optional_digest(advisory_snapshot),
        "advisory_trusted_key_ids": advisory_key_ids,
        "memory_baseline_sha256": _optional_digest(memory_baseline),
        "calibration_profile_sha256": _optional_digest(calibration_profile),
        "calibration_observations_sha256": _optional_digest(calibration_observation_inputs),
        "repair_candidates": candidate_descriptors,
        "candidate_source_requested": bool(include_candidate_source),
        "improve": bool(improve),
        "max_improvement_files": int(max_improvement_files),
        "compiler_checks": bool(compiler_checks),
        "use_cache": bool(use_cache), "jobs": int(jobs),
        "test_command_sha256": _optional_digest(test_command_input),
        "tests_authorized": bool(authorize_tests),
        "apply_improvements_authorized": bool(apply_improvements),
        "backup_scope_supplied": bool(backup_scope),
        "backup_scope_identity_sha256": (_sha(backup_scope.encode("utf-8", "surrogatepass"))
                                         if backup_scope else ""),
        "git_base": _bounded_text(git_base, 500),
        "git_base_sha256": _sha(str(git_base).encode("utf-8")),
        "git_base_bytes": len(str(git_base).encode("utf-8")),
        "symbolic_timeout_seconds": float(symbolic_timeout),
        "staged_diff_supplied": bool(staged_diff),
        "history_export_supplied": bool(history_export),
        "staged_diff_sha256": _sha(staged_diff.encode("utf-8")) if staged_diff else "",
        "history_export_sha256": _sha(history_export.encode("utf-8")) if history_export else "",
        "component_report_sha256": {
            "attack_surface_413": _bounded_text(
                attack_surface.get("report_sha256"), 64),
            "security_posture_413": _bounded_text(
                security_posture.get("report_sha256"), 64),
            "security_validation_413": _bounded_text(
                validation_capability.get("report_sha256"), 64),
            "security_test_plans_413": _bounded_text(
                security_test_plans.get("report_sha256"), 64),
            "security_regression_413": _bounded_text(
                security_regression.get("report_sha256"), 64),
            "claim_ledger_413": _bounded_text(
                claim_ledger.get("report_sha256"), 64),
            "security_command_center_413": _bounded_text(
                security_command_center.get("report_sha256"), 64),
        },
        "truth_authentication": {"enabled": truth_key is not None,
                                 "key_id": _bounded_text(truth_key_id, 160)},
    }
    if profile is not None:
        selection = variant414.selection_report(profile)
        analysis_config["variant_414"] = selection
        analysis_config["variant_effective_policy"] = {
            "selected_worker_actions": list(profile.worker_actions),
            "selected_legacy_components": list(profile.legacy_components),
            "jobs": profile.max_concurrency,
            "symbolic_timeout_seconds": profile.symbolic_timeout_seconds,
            "max_improvement_files": max_improvement_files,
            "snapshot": {
                "max_files": profile.max_files,
                "max_file_bytes": profile.max_file_bytes,
                "max_total_bytes": profile.max_total_bytes,
            },
            "worker": {
                "max_seconds": profile.max_worker_seconds,
                "max_memory_bytes": profile.max_worker_memory_bytes,
                "max_output_bytes": profile.max_worker_output_bytes,
            },
            "individual_analyzers_may_apply_stricter_caps": True,
            "stricter_caps_surface_as_coverage_gaps": True,
        }
    analyzer = {
        "name": "Attestor", "version": VERSION, "schema": SCHEMA,
        "engines": ["attestor-4.0-compatibility", "immutable-snapshot/4.1",
                    "semantic-graph/4.1", "deep-correctness/4.1",
                    "semantic-rule-sdk/4.1", "supply-chain-trust/4.1",
                    "secret-lifecycle/4.1", "attack-surface/4.1.3",
                    "security-posture/4.1.3", "security-validation/4.1.3",
                    "security-command-center/4.1.3", "repair-director/4.1",
                    "truth-guard/3.0"],
    }
    if profile is not None:
        analyzer["variant_profile_sha256"] = \
            variant414.profile_identity(profile)
        analyzer["variant_slug"] = profile.slug
        analyzer["engines"].append("variant-orchestration/4.1.4")
    report.update({
        "schema": SCHEMA, "version": VERSION, "root": str(requested),
        "status": status, "summary": summary, "findings": findings,
        "top_findings": findings[:MAX_TOP_FINDINGS], "unbound_observations": unbound,
        "attack_paths": attack_paths[:MAX_ATTACK_PATHS], "priorities": priorities,
        "errors": errors, "coverage": coverage, "execution": execution,
        "analysis_config": analysis_config, "analyzer": analyzer,
        "compatibility_truth_guard_40": compatibility_guard40,
        "coding_fabric_41": coding_public,
        "analysis_snapshot_41": snapshot,
        "semantic_graph_41": semantic_graph_public,
        "deep_correctness_41": deep_correctness,
        "semantic_rule_reports_41": semantic_reports,
        "security_static_fabric_41": security_public,
        "supply_chain_trust_41": supply_chain,
        "secret_lifecycle_41": secret_lifecycle,
        "attack_surface_413": attack_surface or _empty_component(
            "attestor.attack-surface/4.1", requested,
            "attack-surface worker not completed"),
        "security_posture_413": security_posture or _empty_component(
            "attestor.security-posture/4.1.3", requested,
            "security-posture worker not completed"),
        "security_validation_413": validation_capability,
        "security_test_plans_413": security_test_plans,
        "verified_repair_413": verified_repair,
        "security_regression_memory_413": regression_memory,
        "security_regression_413": security_regression,
        "claim_ledger_413": claim_ledger,
        "security_command_center_413": security_command_center,
        "repair_director_41": repair,
        "security_lab_41": {
            "schema": "attestor-security-lab/4.1", "version": VERSION,
            "status": "not-run", "default": "deny",
            "reason": "dynamic lab work requires an eligible isolated runtime and separate plan-bound authorization",
            "host_fallback": False, "production_targeting": False,
        },
        "research_41": {
            "schema": research_engine41.SCHEMA, "version": VERSION,
            "status": "not-run", "default_network": "denied",
            "activation": "explicit research mode plus online authorization",
            "scope": "normal public web only; no dark web, paywall bypass, login, or form submission",
        },
        "computer_scan_41": {
            "schema": "attestor-computer-scan/4.1", "version": VERSION,
            "status": "not-run", "default_discovery": "denied",
            "activation": "separate pathless computer-scan mode plus per-run authorization",
            "scope": "bounded local home or fixed-drive discovery; read-only and review-only",
            "permission_retained": False, "automatic_apply": False,
        },
        "response_41": {"engine": "evidence-locked/4.1", "styles": list(response41.STYLES),
                         "report_scoped_q_and_a": True, "unsupported_claims_abstained": True},
        "evidence_history_41": {
            "schema": "attestor.evidence-store/4.1", "version": VERSION,
            "status": "not-run", "default_persistence": False,
            "activation": "explicit local history action",
            "stores_source_text_in_index": False,
            "capabilities": ["content-addressed reports", "finding fingerprints",
                             "triage", "expiring suppressions", "run comparison"],
        },
        "attestorbench_41": {
            "schema": "attestor.benchmark-report/4.1", "version": VERSION,
            "status": "not-run", "corpus": "operator-supplied-held-out-only",
            "lanes": ["attestor-only", "model-only", "hybrid"],
            "manufactured_results": False,
        },
        "verified_delivery_41": {
            "default": "offline-static-analysis-and-review-candidates",
            "candidate_is_proof": False, "static_qualification_is_verification": False,
            "mandatory_verification_gates": ["scanner", "build", "test"],
            "separate_execution_authorization": True,
            "separate_apply_authorization": True, "host_execution_fallback": False,
        },
        "assurance_41": [
            "Findings are bounded analyzer observations, not proof of exploitability or universal defect absence.",
            "Parser-derived semantic paths are labeled as such and are not represented as compiler or formal proof.",
            "Static repair qualification is not verification; scan, build, and test gates remain mandatory.",
            "Attack paths and exploitability scores are bounded static hypotheses; runtime exploitability remains unverified.",
            "Cloud, IaC, SBOM, provenance, crypto, and binary checks are offline adapters with explicit coverage gaps.",
            "Dynamic validation and source apply remain denied until separate one-use plan-bound authorization is consumed.",
            "Attestor 4.1.3 performs no research network access from this coding/security analysis entry point.",
            "Truth Guard 3 binds public findings to exact source bytes and fails closed on stale evidence.",
            "No fixed rule count is advertised as intelligence; rules are precise, versioned, bounded, and testable.",
        ],
    })
    if not _verify_expected_public_projection_layout(report):
        raise Attestor41Error(
            "the generated public projection layout failed closed")
    if len(_canonical(report)) > MAX_PUBLIC_BYTES:
        raise Attestor41Error("combined report exceeded the 32 MiB public boundary")
    return truth_guard41.guard_document(
        report, root=requested, config=analysis_config, analyzer=analyzer,
        key=truth_key, key_id=truth_key_id)


def _strict_not_run_41(value: Any, schema: str, root: str) -> bool:
    if (type(value) is not dict or
            set(value) != {
                "schema", "version", "root", "status",
                "findings", "coverage"} or
            value.get("schema") != schema or value.get("version") != VERSION or
            value.get("root") != root or value.get("status") != "not-run" or
            value.get("findings") != []):
        return False
    coverage = value.get("coverage")
    return (
        type(coverage) is dict and
        set(coverage) == {"complete", "gaps"} and
        coverage.get("complete") is False and
        type(coverage.get("gaps")) is list and bool(coverage["gaps"]) and
        all(isinstance(row, str) and 1 <= len(row) <= 1_000
            for row in coverage["gaps"])
    )


def _strict_not_run_40(value: Any, schema: str, root: str) -> bool:
    if (type(value) is not dict or
            set(value) != {
                "schema", "version", "root", "status", "summary",
                "findings", "coverage"} or
            value.get("schema") != schema or
            value.get("version") != attestor40.VERSION or
            value.get("root") != root or value.get("status") != "not-run" or
            value.get("summary") != {"findings": 0} or
            value.get("findings") != []):
        return False
    coverage = value.get("coverage")
    return (
        type(coverage) is dict and
        set(coverage) in ({"gaps"}, {"gaps", "absence_proven"}) and
        ("absence_proven" not in coverage or
         coverage.get("absence_proven") is False) and
        type(coverage.get("gaps")) is list and bool(coverage["gaps"]) and
        all(isinstance(row, str) and 1 <= len(row) <= 1_000
            for row in coverage["gaps"])
    )


def _expected_projection(
        value: Any, *, name: str, source_schema: str,
        child_fields: Mapping[str, str] | None = None,
        worker_action: str = "") -> bool:
    if (not _verify_public_component_projection(value) or
            value.get("name") != name or
            value.get("source", {}).get("schema") != source_schema or
            value.get("children") is None):
        return False
    expected_children = dict(child_fields or {})
    children = value["children"]
    if (set(children) != set(expected_children) or
            any(children[key].get("embedded_as") != public_field
                for key, public_field in expected_children.items())):
        return False
    attestation = value.get("worker_attestation")
    if worker_action:
        return (
            type(attestation) is dict and
            attestation.get("action") == worker_action
        )
    return attestation == {}


def _verify_expected_public_projection_layout(report: Any) -> bool:
    if type(report) is not dict or not isinstance(report.get("root"), str):
        return False
    root = report["root"]
    compatibility = report.get("compatibility_truth_guard_40")
    if type(compatibility) is not dict:
        return False
    state = compatibility.get("state")
    if state == "unavailable-failed-closed":
        if (set(compatibility) != {
                "state", "schema", "report_sha256", "truth_guard2",
                "truth_guard2_projected", "error"} or
                compatibility.get("schema") != attestor40.SCHEMA or
                compatibility.get("report_sha256") != "" or
                compatibility.get("truth_guard2") != {} or
                compatibility.get("truth_guard2_projected") is not False or
                not isinstance(compatibility.get("error"), str) or
                not compatibility["error"] or
                not _strict_not_run_40(
                    report.get("engineering"), "attestor-engineering/4.0", root) or
                not _strict_not_run_40(
                    report.get("security_fabric"),
                    "attestor-security-fabric/4.0", root)):
            return False
    elif state in {
            "verified-before-embedding",
            "verified-before-embedding-with-bounded-independent-validation"}:
        audit = compatibility.get("truth_guard2")
        engineering_projection = _expected_projection(
            report.get("engineering"), name="attestor40-engineering",
            source_schema="attestor-engineering/4.0")
        security_projection = _expected_projection(
            report.get("security_fabric"),
            name="attestor40-security-fabric",
            source_schema="attestor-security-fabric/4.0")
        completed = report.get("coverage", {}).get("completed_components", [])
        completed = set(completed) if isinstance(completed, list) else set()
        if (set(compatibility) != {
                "state", "schema", "report_sha256", "truth_guard2",
                "truth_guard2_projected"} or
                compatibility.get("schema") != attestor40.SCHEMA or
                not _sha256_text(compatibility.get("report_sha256")) or
                compatibility.get("truth_guard2_projected") is not True or
                not _verify_compatibility_audit_projection(audit) or
                not (engineering_projection or _strict_not_run_40(
                    report.get("engineering"),
                    "attestor-engineering/4.0", root)) or
                not (security_projection or _strict_not_run_40(
                    report.get("security_fabric"),
                    "attestor-security-fabric/4.0", root)) or
                ("engineering" in completed and
                 not engineering_projection) or
                ("security-fabric" in completed and
                 not security_projection)):
            return False
    else:
        return False

    coding = report.get("coding_fabric_41")
    if isinstance(coding, Mapping) and coding.get("schema") == \
            PUBLIC_PROJECTION_SCHEMA:
        if (not _expected_projection(
                coding, name="coding-fabric-worker",
                source_schema="attestor-coding-fabric/4.1",
                child_fields={
                    "snapshot": "analysis_snapshot_41",
                    "semantic_graph": "semantic_graph_41",
                    "deep_correctness": "deep_correctness_41",
                    "semantic_rule_reports": "semantic_rule_reports_41",
                },
                worker_action="coding-static") or
                not _projection_links_match(coding, report) or
                not _expected_projection(
                    report.get("semantic_graph_41"),
                    name="semantic-graph",
                    source_schema="attestor.semantic-graph/4.1")):
            return False
    elif (not _strict_not_run_41(
            coding, "attestor-coding-fabric/4.1", root) or
            report.get("analysis_snapshot_41") != {} or
            report.get("semantic_graph_41") != {} or
            report.get("deep_correctness_41") != {} or
            report.get("semantic_rule_reports_41") != []):
        return False

    security = report.get("security_static_fabric_41")
    if isinstance(security, Mapping) and security.get("schema") == \
            PUBLIC_PROJECTION_SCHEMA:
        if (not _expected_projection(
                security, name="security-static-fabric-worker",
                source_schema="attestor-security-static-fabric/4.1",
                child_fields={
                    "supply_chain_trust": "supply_chain_trust_41",
                    "secret_lifecycle": "secret_lifecycle_41",
                },
                worker_action="security-static") or
                not _projection_links_match(security, report)):
            return False
    elif (not _strict_not_run_41(
            security, "attestor-security-static-fabric/4.1", root) or
            report.get("supply_chain_trust_41") != {} or
            report.get("secret_lifecycle_41") != {}):
        return False
    return True


def safe_public_report(report: Mapping[str, Any], *, root: str | os.PathLike[str] | None = None,
                       truth_key: bytes | None = None) -> dict[str, Any]:
    selected = root if root is not None else report.get("root") if isinstance(report, Mapping) else None
    verification = truth_guard41.verify_guarded(
        report, root=selected, key=truth_key, require_fresh=True)
    projections_ok = _verify_expected_public_projection_layout(report)
    if verification.get("ok") and projections_ok:
        return json.loads(_canonical(report).decode("utf-8"))
    try:
        fallback_root = Path(selected).expanduser().resolve(strict=True) if selected else Path.cwd().resolve()
    except (OSError, TypeError, ValueError):
        fallback_root = Path.cwd().resolve()
    fallback = {
        "schema": SCHEMA, "version": VERSION, "root": str(fallback_root),
        "status": "inconsistent", "summary": {"findings": 0, "component_errors": 1},
        "findings": [], "attack_paths": [], "priorities": [],
        "errors": [{"component": "truth-guard3", "error": "public-report-integrity-or-freshness-failure"}],
        "coverage": {"complete": False, "absence_proven": False,
                     "gaps": ["the supplied report failed Truth Guard 3 replay verification"]},
        "response": "Result withheld because its source-bound evidence did not verify.",
    }
    return truth_guard41.guard_document(fallback, root=fallback_root)


public_report = safe_public_report


def render(report: Mapping[str, Any], style: str = "professional", *,
           root: str | os.PathLike[str] | None = None,
           truth_key: bytes | None = None) -> str:
    selected = root if root is not None else report.get("root")
    return response41.render_guarded(
        safe_public_report(report, root=selected, truth_key=truth_key), style,
        root=selected, truth_key=truth_key)


def answer(report: Mapping[str, Any], question: str, *,
           root: str | os.PathLike[str] | None = None,
           truth_key: bytes | None = None) -> dict[str, Any]:
    selected = root if root is not None else report.get("root")
    return response41.answer_question(
        safe_public_report(report, root=selected, truth_key=truth_key), question,
        root=selected, truth_key=truth_key)


def to_sarif(report: Mapping[str, Any], *, root: str | os.PathLike[str] | None = None,
             truth_key: bytes | None = None) -> dict[str, Any]:
    sarif = attestor3._generic_sarif(safe_public_report(report, root=root, truth_key=truth_key))
    driver = sarif["runs"][0]["tool"]["driver"]
    driver["name"] = "Attestor 4.1.3"
    driver["semanticVersion"] = VERSION
    return sarif


def research(question: str, *, online: bool = False, fetch_pages: bool = False,
             backend: research_engine41.SearchBackend | None = None,
             fetcher: research_engine41.SafeWebFetcher | None = None,
             **policy_values: Any) -> dict[str, Any]:
    """Run non-coding research with explicit network authorization."""
    policy = research_engine41.ResearchPolicy(
        allow_network=bool(online), fetch_pages=bool(fetch_pages), **policy_values)
    return research_engine41.research(question, policy=policy, backend=backend, fetcher=fetcher)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--issue", default="")
    parser.add_argument("--no-improve", action="store_true")
    parser.add_argument("--max-improvement-files", type=int, default=3)
    parser.add_argument("--compiler-checks", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--semantic-rule-pack", action="append", default=[])
    parser.add_argument("--legacy-rule-pack", action="append", default=[])
    parser.add_argument("--require-signed-packs", action="store_true")
    parser.add_argument("--rule-key-file")
    parser.add_argument("--staged-diff-file")
    parser.add_argument("--history-export-file")
    parser.add_argument("--candidate-json", action="append", default=[])
    parser.add_argument("--include-candidate-source", action="store_true",
                        help="include a bounded complete selected candidate for review")
    parser.add_argument("--truth-key-file")
    parser.add_argument("--truth-key-id", default="")
    parser.add_argument("--response-style", choices=response41.STYLES, default="professional")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    if not 0 <= args.max_improvement_files <= 16:
        parser.error("--max-improvement-files must be between 0 and 16")
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be between 1 and 64")
    def read_bounded(path: str | None, maximum: int) -> str:
        if not path:
            return ""
        raw = Path(path).read_bytes()
        if len(raw) > maximum:
            parser.error("evidence file exceeds its byte boundary")
        return raw.decode("utf-8", "strict")
    truth_key = Path(args.truth_key_file).read_bytes() if args.truth_key_file else None
    rule_key = Path(args.rule_key_file).read_bytes() if args.rule_key_file else None
    candidates = []
    for value in args.candidate_json:
        candidates.append(repair_director41.candidate_from_provider_text(
            read_bounded(value, repair_director41.MAX_PROVIDER_BYTES), args.root))
    report = maximum(
        args.root, issue=args.issue, improve=not args.no_improve,
        max_improvement_files=args.max_improvement_files,
        compiler_checks=args.compiler_checks, use_cache=not args.no_cache,
        jobs=args.jobs, legacy_rule_packs=args.legacy_rule_pack,
        semantic_rule_packs=args.semantic_rule_pack, rule_pack_key=rule_key,
        require_signed_packs=args.require_signed_packs,
        staged_diff=read_bounded(args.staged_diff_file, 128 * 1024),
        history_export=read_bounded(args.history_export_file, 128 * 1024),
        repair_candidates=candidates,
        include_candidate_source=args.include_candidate_source,
        truth_key=truth_key,
        truth_key_id=args.truth_key_id)
    public = safe_public_report(report, root=args.root, truth_key=truth_key)
    output = json.dumps(public, indent=2, sort_keys=True, ensure_ascii=False) if args.format == "json" else \
        json.dumps(to_sarif(public, root=args.root, truth_key=truth_key), indent=2,
                   sort_keys=True, ensure_ascii=False) if args.format == "sarif" else \
        render(public, args.response_style, root=args.root, truth_key=truth_key)
    if args.out:
        Path(args.out).write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8", newline="")
    else:
        print(output)
    return 2 if public.get("status") in {"failed", "inconsistent"} else \
        1 if public.get("findings") else 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SCHEMA", "VERSION", "DEFAULT_COMPONENTS", "Attestor41Error", "maximum",
           "safe_public_report", "public_report", "render", "answer", "to_sarif",
           "research", "main"]
