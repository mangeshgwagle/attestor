#!/usr/bin/env python3
"""Sealed, deterministic operating variants for Attestor 4.1.4.

Variants tune analysis depth, bounded resource consumption, and response
presentation only.  They are not authority objects and cannot disable Attestor's
permission, evidence, truth, offline-default, or fail-closed controls.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from types import MappingProxyType
from typing import Any, Mapping


VERSION = "4.1.4"
PROFILE_SCHEMA = "attestor-variant-profile/4.1.4"
# Release-bound identity of the detector rule engine. A CI contract recomputes
# this from detect.py so analyzer changes cannot remain history-comparable merely
# because profile budgets stayed unchanged.
ANALYZER_BUILD_SHA256 = "27ea912e3441731d81ad6a709469b6c1543f7e6d558639075db5beb69515f70a"
REPORT_SCHEMA = "attestor-variant-selection/4.1.4"
MAX_CANONICAL_BYTES = 16 * 1024
MAX_CANONICAL_NODES = 512
MAX_CANONICAL_DEPTH = 12
MAX_COLLECTION_ITEMS = 64
MAX_STRING_BYTES = 1_024
MIB = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}", re.ASCII)
DISPLAY_RE = re.compile(r"[A-Za-z][A-Za-z0-9 ]{0,63}", re.ASCII)
LEGACY_COMPONENT_ORDER = (
    "scan",
    "semantic",
    "security",
    "supply-chain",
    "symbolic",
    "polyglot-ir",
    "supply-chain-graph",
    "git-intelligence",
    "execution-fabric",
    "engineering",
    "security-fabric",
)
LEGACY_COMPONENT_ALLOWLIST = frozenset(LEGACY_COMPONENT_ORDER)
WORKER_ACTION_ORDER = (
    "coding-static",
    "security-static",
    "attack-static-413",
    "posture-static-413",
)
WORKER_ACTION_ALLOWLIST = frozenset(WORKER_ACTION_ORDER)
RESPONSE_LANGUAGE_SCHEMA = "attestor-response-language/4.1.4"
RESPONSE_LANGUAGE_C3 = "C3"
RESPONSE_LANGUAGE_EXISTING = "existing"
C3_RESPONSE_LABEL = "C3 (Attestor-specific; not CEFR)"


class VariantError(ValueError):
    """A variant name, profile, or deterministic identity failed closed."""


SECURITY_INVARIANTS: Mapping[str, bool] = MappingProxyType({
    "authorization_required_for_execution": True,
    "authorization_required_for_repairs": True,
    "authorization_scope_binding_required": True,
    "evidence_sha256_required": True,
    "fail_closed": True,
    "network_access_default": False,
    "target_code_execution_default": False,
    "truth_guard_required": True,
})
ENFORCEMENT_CONTRACT: Mapping[str, bool] = MappingProxyType({
    "coding_snapshot_and_graph_caps_only": True,
    "inherited_analyzer_caps_reported_separately": True,
    "inherited_analyzer_limit_hits_are_coverage_gaps": True,
    "resource_scope_is_stage_specific": True,
})
# The outer limit no compiled profile may cross.  Each entry mirrors a real
# constant in the engine that consumes it, so a profile can never promise more
# than the engine will accept and then fail closed mid-run:
#
#   max_file_bytes / max_total_bytes / max_findings -> truth_guard41
#   max_graph_nodes                                 -> semantic_graph41.MAX_AST_NODES
#   max_worker_seconds / max_worker_memory_bytes    -> bounded_worker41
#
# Raising any of these means raising the engine constant it mirrors first, and
# proving the engine still holds at the new value.  Editing only this table
# moves the failure from "profile refuses" to "run dies partway through", which
# is strictly worse.
GENERIC_HARD_CEILINGS: Mapping[str, int] = MappingProxyType({
    "max_files": 10_000,
    "max_file_bytes": 32 * MIB,
    "max_total_bytes": 256 * MIB,
    "max_findings": 20_000,
    "max_graph_nodes": 250_000,
    "max_worker_seconds": 180,
    "max_worker_memory_bytes": 1536 * MIB,
    "max_concurrency": 8,
})


@dataclass(frozen=True, slots=True)
class VariantProfile:
    """One immutable resource policy compiled into this Attestor release."""

    slug: str
    display_name: str
    mode: str
    analysis_depth: int
    analysis_passes: int
    max_files: int
    max_file_bytes: int
    max_total_bytes: int
    max_findings: int
    max_graph_nodes: int
    max_worker_seconds: int
    max_worker_memory_bytes: int
    max_concurrency: int
    legacy_components: tuple[str, ...]
    worker_actions: tuple[str, ...]
    symbolic_timeout_seconds: int
    max_improvement_files: int
    max_worker_output_bytes: int
    max_ui_output_bytes: int
    validation_plan_limit: int

    def __post_init__(self) -> None:
        if (type(self.slug) is not str or SLUG_RE.fullmatch(self.slug) is None or
                type(self.display_name) is not str or
                DISPLAY_RE.fullmatch(self.display_name) is None or
                type(self.mode) is not str or
                self.mode not in {"maximum", "balanced", "lightweight"}):
            raise VariantError("variant text fields are invalid")
        checks = {
            "analysis_depth": (self.analysis_depth, 1, 16),
            "analysis_passes": (self.analysis_passes, 1, 32),
            "max_files": (self.max_files, 1, 100_000),
            "max_file_bytes": (
                self.max_file_bytes, 64 * 1024, 64 * MIB),
            "max_total_bytes": (
                self.max_total_bytes, MIB, 2 * 1024 * MIB),
            "max_findings": (self.max_findings, 1, 100_000),
            "max_graph_nodes": (self.max_graph_nodes, 1, 2_000_000),
            "max_worker_seconds": (self.max_worker_seconds, 1, 1_800),
            "max_worker_memory_bytes": (
                self.max_worker_memory_bytes, 64 * MIB, 4 * 1024 * MIB),
            "max_concurrency": (self.max_concurrency, 1, 32),
            "symbolic_timeout_seconds": (
                self.symbolic_timeout_seconds, 1, 300),
            "max_improvement_files": (
                self.max_improvement_files, 1, 64),
            "max_worker_output_bytes": (
                self.max_worker_output_bytes, MIB, 32 * MIB),
            "max_ui_output_bytes": (
                self.max_ui_output_bytes, MIB, 32 * MIB),
            "validation_plan_limit": (
                self.validation_plan_limit, 1, 128),
        }
        for name, (value, lower, upper) in checks.items():
            if type(value) is not int or not lower <= value <= upper:
                raise VariantError(
                    f"{name} must be an integer between {lower} and {upper}")
        if self.max_total_bytes < self.max_file_bytes:
            raise VariantError(
                "max_total_bytes cannot be smaller than max_file_bytes")
        _validate_selection_tuple(
            self.legacy_components, LEGACY_COMPONENT_ALLOWLIST,
            "legacy_components")
        _validate_selection_tuple(
            self.worker_actions, WORKER_ACTION_ALLOWLIST,
            "worker_actions")


def _validate_selection_tuple(
        value: Any, allowed: frozenset[str], name: str) -> None:
    if (type(value) is not tuple or not value or len(value) > len(allowed) or
            any(type(item) is not str for item in value) or
            len(set(value)) != len(value) or not set(value) <= allowed):
        raise VariantError(
            f"{name} must be a nonempty unique tuple from its compiled allowlist")


# Tuple specs are the immutable source of truth used to detect even a mutated
# canonical object.  Field order exactly follows ``VariantProfile``.
# Cockroach Janta Party is the "spend the machine" profile.  Three budgets are
# raised to what the inherited engines actually support rather than to what the
# old ceiling declared: truth_guard41 accepts 20,000 findings, 32 MiB per file
# and 256 MiB in total, so the previous 12,000 / 4 MiB / 128 MiB were leaving
# real capacity unused.
#
# The remaining budgets are NOT arbitrary and are deliberately left alone:
# max_graph_nodes is semantic_graph41.MAX_AST_NODES, max_worker_seconds is
# bounded_worker41.MAX_TIMEOUT, and max_worker_memory_bytes is
# bounded_worker41.MAX_MEMORY_BYTES.  Each is a real engine constant, and
# raising the profile past one only produces a run that fails closed later.
# Lifting those means lifting the engine limit first -- see the note in
# GENERIC_HARD_CEILINGS.
_COCKROACH_SPEC = (
    "cockroach-janta-party", "Cockroach Janta Party", "maximum",
    12, 16, 10_000, 32 * MIB, 256 * MIB, 20_000, 250_000,
    180, 1536 * MIB, 8,
    LEGACY_COMPONENT_ORDER,
    WORKER_ACTION_ORDER,
    300, 16, 32 * MIB, 32 * MIB, 32,
)
_SOUTH_PARK_SPEC = (
    "south-park", "South Park", "balanced",
    7, 8, 6_000, 3 * MIB, 96 * MIB, 8_000, 180_000,
    120, 768 * MIB, 4,
    (
        "scan", "semantic", "security", "supply-chain", "symbolic",
        "polyglot-ir", "supply-chain-graph", "engineering",
        "security-fabric",
    ),
    WORKER_ACTION_ORDER,
    120, 6, 16 * MIB, 16 * MIB, 16,
)
_GRUPPE_SECHS_SPEC = (
    "gruppe-sechs", "Gruppe Sechs", "lightweight",
    4, 4, 3_000, 2 * MIB, 64 * MIB, 4_000, 120_000,
    60, 384 * MIB, 2,
    (
        "scan", "semantic", "security", "supply-chain", "engineering",
        "security-fabric",
    ),
    ("coding-static", "security-static"),
    45, 2, 8 * MIB, 8 * MIB, 8,
)

COCKROACH_JANTA_PARTY = VariantProfile(*_COCKROACH_SPEC)
SOUTH_PARK = VariantProfile(*_SOUTH_PARK_SPEC)
GRUPPE_SECHS = VariantProfile(*_GRUPPE_SECHS_SPEC)
COMPILED_PROFILES = (
    COCKROACH_JANTA_PARTY,
    SOUTH_PARK,
    GRUPPE_SECHS,
)
PROFILE_SLUGS = tuple(profile.slug for profile in COMPILED_PROFILES)
PROFILES: Mapping[str, VariantProfile] = MappingProxyType({
    profile.slug: profile for profile in COMPILED_PROFILES
})
DEFAULT_PROFILE = SOUTH_PARK
_COMPILED_SPECS: Mapping[str, tuple[Any, ...]] = MappingProxyType({
    _COCKROACH_SPEC[0]: _COCKROACH_SPEC,
    _SOUTH_PARK_SPEC[0]: _SOUTH_PARK_SPEC,
    _GRUPPE_SECHS_SPEC[0]: _GRUPPE_SECHS_SPEC,
})


def _validate_compiled_tiers() -> None:
    """Prove monotonic budgets, global ceilings, and set containment."""
    maximum, balanced, lightweight = COMPILED_PROFILES
    numeric_fields = (
        "analysis_depth", "analysis_passes", "max_files",
        "max_file_bytes", "max_total_bytes", "max_findings",
        "max_graph_nodes", "max_worker_seconds",
        "max_worker_memory_bytes", "max_concurrency",
        "symbolic_timeout_seconds", "max_improvement_files",
        "max_worker_output_bytes", "max_ui_output_bytes",
        "validation_plan_limit",
    )
    if any(
            not getattr(maximum, field) > getattr(balanced, field) >
            getattr(lightweight, field)
            for field in numeric_fields):
        raise VariantError("compiled variant numeric budgets are not strictly tiered")
    if any(
            getattr(profile, field) > ceiling
            for profile in COMPILED_PROFILES
            for field, ceiling in GENERIC_HARD_CEILINGS.items()):
        raise VariantError("compiled variant exceeds a generic inherited hard ceiling")
    maximum_components = set(maximum.legacy_components)
    balanced_components = set(balanced.legacy_components)
    lightweight_components = set(lightweight.legacy_components)
    if not lightweight_components < balanced_components < maximum_components:
        raise VariantError("compiled legacy-component policies are not strict subsets")
    maximum_actions = set(maximum.worker_actions)
    balanced_actions = set(balanced.worker_actions)
    lightweight_actions = set(lightweight.worker_actions)
    # Maximum and balanced intentionally retain all four bounded workers;
    # lightweight is the strict offline-static subset.
    if not lightweight_actions < balanced_actions <= maximum_actions:
        raise VariantError("compiled worker-action policies are not monotonic subsets")


_validate_compiled_tiers()


def _profile_tuple(profile: VariantProfile) -> tuple[Any, ...]:
    return tuple(
        getattr(profile, name)
        for name in VariantProfile.__dataclass_fields__
    )


def require_compiled_profile(value: Any) -> VariantProfile:
    """Return *value* only when it is the intact canonical release singleton."""
    if type(value) is not VariantProfile:
        raise VariantError("variant profile is not a compiled profile")
    canonical = PROFILES.get(value.slug)
    expected = _COMPILED_SPECS.get(value.slug)
    if canonical is not value or expected is None or _profile_tuple(value) != expected:
        raise VariantError("variant profile is forged or no longer canonical")
    return value


def _normalize_alias(value: Any) -> str:
    if type(value) is not str:
        raise VariantError("variant name must be text")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeError as exc:
        raise VariantError("variant name must contain bounded ASCII text") from exc
    if not 1 <= len(encoded) <= 128:
        raise VariantError("variant name is outside the text boundary")
    stripped = value.strip()
    if (not stripped or any(ord(character) < 0x20 or ord(character) == 0x7F
                            for character in stripped) or
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]*", stripped) is None):
        raise VariantError("variant name contains unsupported characters")
    return re.sub(r"[ ._-]+", "-", stripped.casefold()).strip("-")


_RAW_ALIASES = {
    # Stable slugs, exact display names, tier names, and short CLI spellings.
    "cockroach-janta-party": "cockroach-janta-party",
    "cockroach janta party": "cockroach-janta-party",
    "cockroach janta party maximum": "cockroach-janta-party",
    "cockroach": "cockroach-janta-party",
    "cjp": "cockroach-janta-party",
    "maximum": "cockroach-janta-party",
    "max": "cockroach-janta-party",
    "south-park": "south-park",
    "south park": "south-park",
    "south park balanced": "south-park",
    "southpark": "south-park",
    "sp": "south-park",
    "balanced": "south-park",
    "balance": "south-park",
    "default": "south-park",
    "gruppe-sechs": "gruppe-sechs",
    "gruppe sechs": "gruppe-sechs",
    "gruppe sechs lightweight": "gruppe-sechs",
    "gruppesechs": "gruppe-sechs",
    "gs": "gruppe-sechs",
    "lightweight": "gruppe-sechs",
    "light": "gruppe-sechs",
    "lite": "gruppe-sechs",
    "low-resource": "gruppe-sechs",
}
ALIASES: Mapping[str, str] = MappingProxyType({
    _normalize_alias(alias): slug for alias, slug in _RAW_ALIASES.items()
})


def parse_profile(value: Any) -> VariantProfile:
    """Resolve a CLI alias or revalidate a compiled profile object.

    API and UI boundaries should call :func:`profile_for_slug`; aliases are
    deliberately a CLI convenience and are not wire-level identifiers.
    """
    if type(value) is VariantProfile:
        return require_compiled_profile(value)
    normalized = _normalize_alias(value)
    slug = ALIASES.get(normalized)
    if slug is None:
        raise VariantError("unknown Attestor 4.1.4 variant")
    return require_compiled_profile(PROFILES[slug])


def profile_for_slug(value: Any) -> VariantProfile:
    """Resolve only an exact stable slug for API/UI trust boundaries."""
    if type(value) is not str or value not in PROFILES:
        raise VariantError("variant must be one exact compiled slug")
    return require_compiled_profile(PROFILES[value])


def _profile_value(value: Any) -> VariantProfile:
    if type(value) is VariantProfile:
        return require_compiled_profile(value)
    return profile_for_slug(value)


def response_language_metadata(value: Any) -> dict[str, Any]:
    """Return the canonical, non-authority response-language policy.

    ``C3`` is Attestor's own evidence-dense technical register.  It is not a CEFR
    level, language-proficiency certification, or permission grant.  The two
    smaller profiles deliberately retain the established response41 renderer.
    """
    profile = _profile_value(value)
    c3_enabled = profile is COCKROACH_JANTA_PARTY
    return {
        "schema": RESPONSE_LANGUAGE_SCHEMA,
        "tier": (
            RESPONSE_LANGUAGE_C3
            if c3_enabled else RESPONSE_LANGUAGE_EXISTING
        ),
        "label": (
            C3_RESPONSE_LABEL
            if c3_enabled else "Existing response behavior"
        ),
        "attestor_specific_tier": c3_enabled,
        "official_cefr_claim": False,
        "renderer": (
            "c3-evidence-locked/4.1.4"
            if c3_enabled else "response41-existing/4.1.3"
        ),
        "request_override_allowed": False,
    }


def _validate_response_language_profiles() -> None:
    policies = [
        response_language_metadata(profile)
        for profile in COMPILED_PROFILES
    ]
    if (
        policies[0]["tier"] != RESPONSE_LANGUAGE_C3 or
        policies[0]["attestor_specific_tier"] is not True or
        any(
            policy["tier"] == RESPONSE_LANGUAGE_C3 or
            policy["attestor_specific_tier"] is not False
            for policy in policies[1:]
        )
    ):
        raise VariantError(
            "C3 response language must be exclusive to the maximum profile")


_validate_response_language_profiles()


def _canonical(value: Any) -> bytes:
    """Encode small exact JSON without allowing adversarial allocation."""
    pending: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    estimated = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_CANONICAL_NODES or depth > MAX_CANONICAL_DEPTH:
            raise VariantError("variant evidence exceeds the structure boundary")
        if current is None or type(current) is bool:
            estimated += 5
        elif type(current) is int:
            if not -(2 ** 63) <= current <= 2 ** 63 - 1:
                raise VariantError("variant evidence integer is outside the boundary")
            estimated += 24
        elif type(current) is str:
            size = len(current.encode("utf-8"))
            if size > MAX_STRING_BYTES:
                raise VariantError("variant evidence text is outside the boundary")
            estimated += size + 3
        elif type(current) is list:
            if len(current) > MAX_COLLECTION_ITEMS:
                raise VariantError("variant evidence collection is outside the boundary")
            estimated += len(current) + 2
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            if len(current) > MAX_COLLECTION_ITEMS:
                raise VariantError("variant evidence collection is outside the boundary")
            estimated += len(current) + 2
            for key, item in current.items():
                if type(key) is not str or len(key.encode("utf-8")) > MAX_STRING_BYTES:
                    raise VariantError("variant evidence object key is invalid")
                estimated += len(key.encode("utf-8")) + 3
                pending.append((item, depth + 1))
        else:
            raise VariantError("variant evidence contains a non-JSON value")
        if estimated > MAX_CANONICAL_BYTES:
            raise VariantError("variant evidence exceeds the byte boundary")
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise VariantError("variant evidence is not deterministic JSON") from exc
    if len(raw) > MAX_CANONICAL_BYTES:
        raise VariantError("variant evidence exceeds the byte boundary")
    return raw


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


SECURITY_POLICY_SHA256 = _sha(dict(SECURITY_INVARIANTS))
ENFORCEMENT_POLICY_SHA256 = _sha(dict(ENFORCEMENT_CONTRACT))


def profile_dict(value: Any) -> dict[str, Any]:
    """Return a fresh deterministic profile dictionary with its identity."""
    profile = _profile_value(value)
    body = {
        "schema": PROFILE_SCHEMA,
        "version": VERSION,
        "slug": profile.slug,
        "display_name": profile.display_name,
        "mode": profile.mode,
        "analyzer_build_sha256": ANALYZER_BUILD_SHA256,
        "response_language": response_language_metadata(profile),
        "analysis": {
            "depth": profile.analysis_depth,
            "legacy_components": list(profile.legacy_components),
            "passes": profile.analysis_passes,
            "symbolic_timeout_seconds": profile.symbolic_timeout_seconds,
            "worker_actions": list(profile.worker_actions),
        },
        "enforcement_contract": dict(ENFORCEMENT_CONTRACT),
        "resources": {
            "max_concurrency": profile.max_concurrency,
            "max_file_bytes": profile.max_file_bytes,
            "max_files": profile.max_files,
            "max_findings": profile.max_findings,
            "max_graph_nodes": profile.max_graph_nodes,
            "max_improvement_files": profile.max_improvement_files,
            "max_total_bytes": profile.max_total_bytes,
            "max_ui_output_bytes": profile.max_ui_output_bytes,
            "max_worker_memory_bytes": profile.max_worker_memory_bytes,
            "max_worker_output_bytes": profile.max_worker_output_bytes,
            "max_worker_seconds": profile.max_worker_seconds,
            "validation_plan_limit": profile.validation_plan_limit,
        },
        "security_invariants": dict(SECURITY_INVARIANTS),
    }
    body["profile_sha256"] = _sha(body)
    return body


def profile_identity(value: Any) -> str:
    """Return the stable SHA-256 identity of a canonical compiled profile."""
    return profile_dict(value)["profile_sha256"]


def verify_profile_dict(value: Any) -> tuple[bool, list[str]]:
    """Verify exact shape, digest, invariant policy, and compiled identity."""
    errors: list[str] = []
    try:
        _canonical(value)
    except VariantError:
        return False, ["profile dictionary is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["profile dictionary is not an exact object"]
    expected_keys = {
        "schema", "version", "slug", "display_name", "mode",
        "analyzer_build_sha256", "analysis",
        "enforcement_contract", "resources", "response_language",
        "security_invariants",
        "profile_sha256",
    }
    if set(value) != expected_keys:
        errors.append("profile dictionary keys are invalid")
    if value.get("schema") != PROFILE_SCHEMA or value.get("version") != VERSION:
        errors.append("profile dictionary schema or version is invalid")
    slug = value.get("slug")
    profile = PROFILES.get(slug) if type(slug) is str else None
    if profile is None:
        errors.append("profile dictionary slug is not compiled")
    claimed = value.get("profile_sha256")
    if not isinstance(claimed, str) or SHA256_RE.fullmatch(claimed) is None:
        errors.append("profile dictionary digest is invalid")
    else:
        body = {key: item for key, item in value.items()
                if key != "profile_sha256"}
        try:
            actual = _sha(body)
        except VariantError:
            errors.append("profile dictionary body is outside the boundary")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("profile dictionary digest does not match")
    if profile is not None:
        try:
            expected = profile_dict(profile)
        except VariantError:
            errors.append("compiled profile failed canonical validation")
        else:
            if value != expected:
                errors.append("profile dictionary is not the compiled canonical profile")
    return not errors, errors


def load_profile_dict(value: Any) -> VariantProfile:
    """Load exact serialized evidence back to its canonical singleton."""
    valid, errors = verify_profile_dict(value)
    if not valid:
        raise VariantError("; ".join(errors[:3]))
    return require_compiled_profile(PROFILES[value["slug"]])


def selection_report(value: Any) -> dict[str, Any]:
    """Create deterministic, content-addressed variant-selection evidence."""
    selected = profile_dict(value)
    body = {
        "schema": REPORT_SCHEMA,
        "version": VERSION,
        "selected_profile": selected,
        "selected_profile_sha256": selected["profile_sha256"],
        "enforcement_policy_sha256": ENFORCEMENT_POLICY_SHA256,
        "security_policy_sha256": SECURITY_POLICY_SHA256,
    }
    body["report_sha256"] = _sha(body)
    return body


def verify_report(value: Any) -> tuple[bool, list[str]]:
    """Verify a variant-selection report without trusting its claimed slug."""
    errors: list[str] = []
    try:
        _canonical(value)
    except VariantError:
        return False, ["variant report is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["variant report is not an exact object"]
    expected_keys = {
        "schema", "version", "selected_profile",
        "selected_profile_sha256", "enforcement_policy_sha256",
        "security_policy_sha256", "report_sha256",
    }
    if set(value) != expected_keys:
        errors.append("variant report keys are invalid")
    if value.get("schema") != REPORT_SCHEMA or value.get("version") != VERSION:
        errors.append("variant report schema or version is invalid")
    selected = value.get("selected_profile")
    profile_valid, profile_errors = verify_profile_dict(selected)
    if not profile_valid:
        errors.extend("selected " + error for error in profile_errors[:4])
    selected_digest = (
        selected.get("profile_sha256") if type(selected) is dict else None)
    if (value.get("selected_profile_sha256") != selected_digest or
            not isinstance(selected_digest, str) or
            SHA256_RE.fullmatch(selected_digest) is None):
        errors.append("selected profile identity binding is invalid")
    if value.get("security_policy_sha256") != SECURITY_POLICY_SHA256:
        errors.append("variant security-policy identity is invalid")
    if value.get("enforcement_policy_sha256") != ENFORCEMENT_POLICY_SHA256:
        errors.append("variant enforcement-policy identity is invalid")
    claimed = value.get("report_sha256")
    if not isinstance(claimed, str) or SHA256_RE.fullmatch(claimed) is None:
        errors.append("variant report digest is invalid")
    else:
        body = {key: item for key, item in value.items()
                if key != "report_sha256"}
        try:
            actual = _sha(body)
        except VariantError:
            errors.append("variant report body is outside the boundary")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("variant report digest does not match")
    return not errors, errors


__all__ = [
    "ANALYZER_BUILD_SHA256",
    "ALIASES",
    "COCKROACH_JANTA_PARTY",
    "COMPILED_PROFILES",
    "DEFAULT_PROFILE",
    "ENFORCEMENT_CONTRACT",
    "ENFORCEMENT_POLICY_SHA256",
    "GENERIC_HARD_CEILINGS",
    "GRUPPE_SECHS",
    "LEGACY_COMPONENT_ALLOWLIST",
    "LEGACY_COMPONENT_ORDER",
    "PROFILE_SCHEMA",
    "PROFILE_SLUGS",
    "PROFILES",
    "RESPONSE_LANGUAGE_C3",
    "RESPONSE_LANGUAGE_EXISTING",
    "RESPONSE_LANGUAGE_SCHEMA",
    "C3_RESPONSE_LABEL",
    "REPORT_SCHEMA",
    "SECURITY_INVARIANTS",
    "SECURITY_POLICY_SHA256",
    "SOUTH_PARK",
    "VERSION",
    "VariantError",
    "VariantProfile",
    "WORKER_ACTION_ALLOWLIST",
    "WORKER_ACTION_ORDER",
    "load_profile_dict",
    "parse_profile",
    "profile_dict",
    "profile_for_slug",
    "profile_identity",
    "response_language_metadata",
    "require_compiled_profile",
    "selection_report",
    "verify_profile_dict",
    "verify_report",
]
