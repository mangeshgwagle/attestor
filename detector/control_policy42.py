#!/usr/bin/env python3
"""Immutable policy and strict plan schema for Attestor 4.2 Owner Control.

The 4.2 MVP deliberately has no mutation executor.  A mutation plan can bind
future operation identities for review, but the compiled policy marks every
such operation non-executable.  Observation plans are JSON-only, bounded, and
bound to the intact Cockroach Janta Party profile.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePath
import re
from types import MappingProxyType
from typing import Any, Mapping

import variant414


VERSION = "4.2"
POLICY_SCHEMA = "attestor-owner-control-policy/4.2"
PLAN_SCHEMA = "attestor-owner-control-plan/4.2"
PROFILE_SLUG = "cockroach-janta-party"

SYSTEM_INVENTORY = "system-inventory"
FIND_FILES = "find-files"
COMPUTER_PROJECT_SCAN = "computer-project-scan"
PLAN_FUTURE_MUTATIONS = "plan-future-mutations"
ACTION_ORDER = (
    SYSTEM_INVENTORY,
    FIND_FILES,
    COMPUTER_PROJECT_SCAN,
    PLAN_FUTURE_MUTATIONS,
)
OBSERVATION_ACTIONS = frozenset({
    SYSTEM_INVENTORY,
    FIND_FILES,
    COMPUTER_PROJECT_SCAN,
})
ALLOWED_ACTIONS = frozenset(ACTION_ORDER)

FUTURE_MUTATION_KINDS = frozenset({
    "create-directory",
    "quarantine-files",
    "replace-existing-files",
    "restore-quarantined-files",
})

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_JSON_NODES = 16_384
MAX_JSON_DEPTH = 32
MAX_TEXT_BYTES = 2_048
MAX_ROOTS = 8
MAX_PATH_BYTES = 1_024
MAX_EXTENSIONS = 32
MAX_DIRECTORIES = 20_000
MAX_FILES = 200_000
MAX_RESULTS = 1_000
MAX_DEPTH = 16
MAX_MUTATION_OPERATIONS = 12
MAX_MUTATION_BYTES = 32 * 1024 * 1024
MAX_ENTRIES_PER_DIRECTORY = 10_000
MAX_HASH_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_HASH_BYTES = 128 * 1024 * 1024

SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
SESSION_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
OPERATION_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}", re.ASCII)
EXTENSION_RE = re.compile(r"\.[A-Za-z0-9_+.-]{1,31}", re.ASCII)

    "$recycle.bin",
    ".aws",
    ".azure",
    ".docker",
    ".codex",
    ".config",
    ".git",
    ".gnupg",
    ".gpg",
    ".kube",
    ".local",
    ".openai",
    ".ssh",
    "appdata",
    "application data",
    "boot",
    "bravesoftware",
    "chrome",
    "chromium",
    "cookies",
    "edge",
    "efi",
    "firefox",
    "keychains",
    "library",
    "local settings",
    "mail",
    "mozilla",
    "outlook files",
    "program files",
    "program files (x86)",
    "programdata",
    "recovery",
    "system volume information",
    "thunderbird",
    "windows",
})

    ".env",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "authorized_keys",
    "cookies",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "login data",
    "ntuser.dat",
    "passwords.txt",
    "sam",
    "security",
    "secrets.json",
    "system",
    "token.json",
    "tokens.json",
    "wallet.dat",
})
    ".env", ".jks", ".key", ".keystore", ".p12", ".pem", ".pfx",
    ".pkcs12",
})

SAFETY_CONTROLS = MappingProxyType({
    "credential_access_allowed": False,
    "mutation_execution_allowed": False,
    "network_allowed": False,
    "persistence_allowed": False,
    "process_execution_allowed": False,
    "shell_allowed": False,
})


class ControlPolicyError(ValueError):
    """A policy document or control plan failed closed."""


def _profile_identity() -> tuple[str, str]:
    try:
        profile = variant414.require_compiled_profile(
            variant414.COCKROACH_JANTA_PARTY)
        identity = variant414.profile_identity(profile)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ControlPolicyError(
            "the canonical Cockroach Janta Party profile is unavailable"
        ) from exc
    if profile.slug != PROFILE_SLUG or SHA256_RE.fullmatch(identity) is None:
        raise ControlPolicyError(
            "the canonical Cockroach Janta Party profile identity is invalid")
    return profile.slug, identity


def _preflight(value: Any) -> None:
    pending: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    estimated = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ControlPolicyError(
                "control JSON exceeds its structure boundary")
        if current is None or type(current) is bool:
            estimated += 5
        elif type(current) is int:
            if not -(2 ** 63) <= current <= 2 ** 63 - 1:
                raise ControlPolicyError(
                    "control JSON integer is outside its boundary")
            estimated += 24
        elif type(current) is str:
            try:
                size = len(current.encode("utf-8", "strict"))
            except UnicodeError as exc:
                raise ControlPolicyError(
                    "control JSON contains invalid Unicode") from exc
            if size > MAX_TEXT_BYTES:
                raise ControlPolicyError(
                    "control JSON text is outside its boundary")
            estimated += size + 3
        elif type(current) is list:
            if len(current) > MAX_JSON_NODES:
                raise ControlPolicyError(
                    "control JSON collection is outside its boundary")
            estimated += len(current) + 2
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            if len(current) > MAX_JSON_NODES:
                raise ControlPolicyError(
                    "control JSON object is outside its boundary")
            estimated += len(current) + 2
            for key, item in current.items():
                if type(key) is not str:
                    raise ControlPolicyError(
                        "control JSON object keys must be text")
                estimated += len(key.encode("utf-8", "strict")) + 3
                pending.append((item, depth + 1))
        else:
            raise ControlPolicyError(
                "control JSON contains a non-JSON value")
        if estimated > MAX_DOCUMENT_BYTES:
            raise ControlPolicyError(
                "control JSON exceeds its byte boundary")


def canonical_bytes(value: Any) -> bytes:
    """Return bounded deterministic UTF-8 JSON for exact evidence binding."""
    _preflight(value)
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, RecursionError, TypeError, ValueError) as exc:
        raise ControlPolicyError(
            "control JSON is not deterministic") from exc
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ControlPolicyError(
            "control JSON exceeds its byte boundary")
    return raw


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_json_object(value: Any) -> dict[str, Any]:
    """Return a detached JSON object after applying all document bounds."""
    if type(value) is not dict:
        raise ControlPolicyError("control value must be an exact JSON object")
    return json.loads(canonical_bytes(value))


def _bounded_text(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_TEXT_BYTES,
) -> str:
    if type(value) is not str:
        raise ControlPolicyError(f"{label} must be text")
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ControlPolicyError(f"{label} is not valid Unicode") from exc
    if not minimum <= len(raw) <= maximum:
        raise ControlPolicyError(f"{label} is outside its text boundary")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or character in {
            "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c",
            "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
        }
        for character in value
    ):
        raise ControlPolicyError(
            f"{label} contains unsupported control characters")
    return value


def _exact_digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise ControlPolicyError(
            f"{label} must be an exact lowercase SHA-256 digest")
    return value


def _session(value: Any) -> str:
    if type(value) is not str or SESSION_RE.fullmatch(value) is None:
        raise ControlPolicyError(
            "session_id must be 32 lowercase hexadecimal characters")
    return value


def _root_text(value: Any) -> str:
    value = _bounded_text(
        value, "control root", minimum=1, maximum=MAX_PATH_BYTES)
    normalized = value.replace("\\", "/")
    if ("\x00" in value or normalized.startswith("//")
            or not PurePath(value).is_absolute()):
        raise ControlPolicyError(
            "control roots must be absolute local path spellings")
    if any(part in {".", ".."} for part in PurePath(value).parts):
        raise ControlPolicyError("control root contains traversal")
    components = {
        part.casefold().rstrip(" .")
        for part in PurePath(value).parts
        if part not in {"", "/", "\\"}
    }
    # protected-directory rejection removed at operator request
    return value


def is_sensitive_file_name(name: str) -> bool:
    lowered = name.casefold()
    return (
        lowered in frozenset()
        or any(lowered.endswith(suffix) for suffix in frozenset())
        or (lowered.startswith(".env.") and lowered != ".env.example")
    )


def is_protected_directory_name(name: str) -> bool:
    return name.casefold().rstrip(" .") in frozenset()


def _root_list(value: Any, *, allow_empty: bool) -> list[str]:
    if type(value) is not list or not (
            0 if allow_empty else 1) <= len(value) <= MAX_ROOTS:
        raise ControlPolicyError(
            f"roots must contain {'zero to' if allow_empty else 'one to'} "
            f"{MAX_ROOTS} entries")
    roots = [_root_text(item) for item in value]
    folded = [item.replace("\\", "/").casefold() for item in roots]
    if len(folded) != len(set(folded)):
        raise ControlPolicyError("control roots contain a duplicate")
    return roots


def _validate_system_request(value: Any) -> None:
    if type(value) is not dict or set(value) != {"storage_roots"}:
        raise ControlPolicyError(
            "system-inventory request shape is invalid")
    _root_list(value["storage_roots"], allow_empty=True)


def _validate_find_request(value: Any) -> None:
    keys = {
        "extensions", "hash_files", "max_depth", "max_directories",
        "max_files", "max_results", "name_contains", "roots",
    }
    if type(value) is not dict or set(value) != keys:
        raise ControlPolicyError("find-files request shape is invalid")
    _root_list(value["roots"], allow_empty=False)
    name_contains = _bounded_text(
        value["name_contains"], "name_contains", maximum=120)
    if "/" in name_contains or "\\" in name_contains:
        raise ControlPolicyError(
            "name_contains must be a filename substring, not a path")
    extensions = value["extensions"]
    if (type(extensions) is not list
            or len(extensions) > MAX_EXTENSIONS
            or any(type(item) is not str
                   or EXTENSION_RE.fullmatch(item) is None
                   or item != item.casefold()
                   for item in extensions)
            or extensions != sorted(set(extensions))):
        raise ControlPolicyError(
            "extensions must be a sorted unique lowercase extension list")
    limits = {
        "max_directories": (1, MAX_DIRECTORIES),
        "max_files": (1, MAX_FILES),
        "max_results": (1, MAX_RESULTS),
        "max_depth": (0, MAX_DEPTH),
    }
    for field, (minimum, maximum) in limits.items():
        item = value[field]
        if type(item) is not int or not minimum <= item <= maximum:
            raise ControlPolicyError(
                f"{field} must be between {minimum} and {maximum}")
    if type(value["hash_files"]) is not bool:
        raise ControlPolicyError("hash_files must be a literal boolean")


def _validate_project_scan_request(value: Any) -> None:
    if type(value) is not dict or set(value) != {
            "max_projects", "review_improvements", "scope"}:
        raise ControlPolicyError(
            "computer-project-scan request shape is invalid")
    if value["scope"] not in {"home", "fixed-drives"}:
        raise ControlPolicyError(
            "computer-project-scan scope is invalid")
    if type(value["max_projects"]) is not int or not (
            1 <= value["max_projects"] <= 12):
        raise ControlPolicyError(
            "computer-project-scan max_projects must be between 1 and 12")
    if type(value["review_improvements"]) is not bool:
        raise ControlPolicyError(
            "review_improvements must be a literal boolean")


_MUTATION_OPERATION_KEYS = {
    "after_sha256",
    "before_sha256",
    "estimated_bytes",
    "kind",
    "operation_id",
    "root_identity_sha256",
    "target_identity_sha256",
}


def _validate_mutation_plan_request(value: Any) -> None:
    if type(value) is not dict or set(value) != {"executor", "operations"}:
        raise ControlPolicyError(
            "future-mutation request shape is invalid")
    if value["executor"] != "unavailable":
        raise ControlPolicyError(
            "the Attestor 4.2 MVP mutation executor must remain unavailable")
    operations = value["operations"]
    if type(operations) is not list or not (
            1 <= len(operations) <= MAX_MUTATION_OPERATIONS):
        raise ControlPolicyError(
            "future-mutation plan must contain one to twelve operations")
    operation_ids: set[str] = set()
    total = 0
    for operation in operations:
        if type(operation) is not dict or set(operation) != _MUTATION_OPERATION_KEYS:
            raise ControlPolicyError(
                "future-mutation operation shape is invalid")
        operation_id = operation["operation_id"]
        if (type(operation_id) is not str
                or OPERATION_ID_RE.fullmatch(operation_id) is None
                or operation_id in operation_ids):
            raise ControlPolicyError(
                "future-mutation operation_id is invalid or duplicated")
        operation_ids.add(operation_id)
        if operation["kind"] not in FUTURE_MUTATION_KINDS:
            raise ControlPolicyError(
                "future-mutation operation kind is not allowlisted")
        for field in (
                "root_identity_sha256", "target_identity_sha256",
                "before_sha256", "after_sha256"):
            _exact_digest(operation[field], field)
        size = operation["estimated_bytes"]
        if type(size) is not int or not 0 <= size <= MAX_MUTATION_BYTES:
            raise ControlPolicyError(
                "future-mutation estimated_bytes is invalid")
        total += size
        if total > MAX_MUTATION_BYTES:
            raise ControlPolicyError(
                "future-mutation plan exceeds its total byte boundary")


_VALIDATORS = {
    SYSTEM_INVENTORY: _validate_system_request,
    FIND_FILES: _validate_find_request,
    COMPUTER_PROJECT_SCAN: _validate_project_scan_request,
    PLAN_FUTURE_MUTATIONS: _validate_mutation_plan_request,
}

_ACTION_POLICY_BODY = {
    action: {
        "authorization_kind": (
            "observe" if action in OBSERVATION_ACTIONS else "plan-review"),
        "executable": action in OBSERVATION_ACTIONS,
        "mutation_authorized": False,
    }
    for action in ACTION_ORDER
}
ACTION_POLICIES = MappingProxyType({
    action: MappingProxyType(values)
    for action, values in _ACTION_POLICY_BODY.items()
})


_POLICY_BODY = {
    "schema": POLICY_SCHEMA,
    "version": VERSION,
    "profile": PROFILE_SLUG,
    "action_order": list(ACTION_ORDER),
    "observation_actions": sorted(OBSERVATION_ACTIONS),
    "plan_only_action": PLAN_FUTURE_MUTATIONS,
    "future_mutation_kinds": sorted(FUTURE_MUTATION_KINDS),
    "actions": _ACTION_POLICY_BODY,
    "limits": {
        "max_document_bytes": MAX_DOCUMENT_BYTES,
        "max_depth": MAX_DEPTH,
        "max_directories": MAX_DIRECTORIES,
        "max_entries_per_directory": MAX_ENTRIES_PER_DIRECTORY,
        "max_extensions": MAX_EXTENSIONS,
        "max_files": MAX_FILES,
        "max_hash_file_bytes": MAX_HASH_FILE_BYTES,
        "max_future_mutation_bytes": MAX_MUTATION_BYTES,
        "max_future_mutation_operations": MAX_MUTATION_OPERATIONS,
        "max_json_depth": MAX_JSON_DEPTH,
        "max_json_nodes": MAX_JSON_NODES,
        "max_path_bytes": MAX_PATH_BYTES,
        "max_results": MAX_RESULTS,
        "max_roots": MAX_ROOTS,
        "max_text_bytes": MAX_TEXT_BYTES,
        "max_total_hash_bytes": MAX_TOTAL_HASH_BYTES,
    },
    "protected_directory_names": sorted(frozenset()),
    "sensitive_file_names": sorted(frozenset()),
    "sensitive_file_suffixes": sorted(frozenset()),
    "safety_controls": dict(SAFETY_CONTROLS),
}
POLICY_SHA256 = digest_json(_POLICY_BODY)


def policy_document() -> dict[str, Any]:
    """Return a detached exact policy document with its deterministic digest."""
    body = json.loads(canonical_bytes(_POLICY_BODY))
    body["policy_sha256"] = POLICY_SHA256
    return body


def compiled_profile_document() -> dict[str, str]:
    """Return the exact immutable profile identity used by this policy."""
    slug, identity = _profile_identity()
    return {"slug": slug, "profile_sha256": identity}


def create_plan(
    action: str,
    request: Mapping[str, Any],
    *,
    session_id: str,
) -> dict[str, Any]:
    """Construct and verify one exact observation or inert mutation plan."""
    if type(action) is not str or action not in ALLOWED_ACTIONS:
        raise ControlPolicyError("owner-control action is not allowlisted")
    _session(session_id)
    if type(request) is not dict:
        raise ControlPolicyError("owner-control request must be an exact object")
    _VALIDATORS[action](request)
    slug, profile_sha256 = _profile_identity()
    body = {
        "schema": PLAN_SCHEMA,
        "version": VERSION,
        "profile": {
            "slug": slug,
            "profile_sha256": profile_sha256,
        },
        "session_id": session_id,
        "policy_sha256": POLICY_SHA256,
        "action": action,
        "request": json.loads(canonical_bytes(request)),
        "safety_controls": dict(SAFETY_CONTROLS),
    }
    plan = {**body, "plan_sha256": digest_json(body)}
    valid, errors = verify_plan(plan)
    if not valid:
        raise ControlPolicyError(
            "owner-control plan construction failed: " + "; ".join(errors[:3]))
    return plan


_PLAN_KEYS = {
    "action", "plan_sha256", "policy_sha256", "profile", "request",
    "safety_controls", "schema", "session_id", "version",
}


def verify_plan(value: Any) -> tuple[bool, list[str]]:
    """Verify the exact bounded plan contract without probing the computer."""
    try:
        canonical_bytes(value)
    except ControlPolicyError:
        return False, ["owner-control plan is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["owner-control plan is not an exact object"]
    errors: list[str] = []
    if set(value) != _PLAN_KEYS:
        errors.append("owner-control plan keys are invalid")
    if value.get("schema") != PLAN_SCHEMA or value.get("version") != VERSION:
        errors.append("owner-control plan schema or version is invalid")
    try:
        slug, identity = _profile_identity()
    except ControlPolicyError:
        slug, identity = "", ""
        errors.append("canonical control profile is unavailable")
    if value.get("profile") != {
            "slug": slug, "profile_sha256": identity}:
        errors.append("owner-control plan profile binding is invalid")
    try:
        _session(value.get("session_id"))
    except ControlPolicyError as exc:
        errors.append(str(exc))
    if value.get("policy_sha256") != POLICY_SHA256:
        errors.append("owner-control policy binding is invalid")
    action = value.get("action")
    if type(action) is not str or action not in ALLOWED_ACTIONS:
        errors.append("owner-control action is not allowlisted")
    else:
        try:
            _VALIDATORS[action](value.get("request"))
        except ControlPolicyError as exc:
            errors.append(str(exc))
    if value.get("safety_controls") != dict(SAFETY_CONTROLS):
        errors.append("owner-control safety controls are invalid")
    claimed = value.get("plan_sha256")
    if type(claimed) is not str or SHA256_RE.fullmatch(claimed) is None:
        errors.append("owner-control plan digest is invalid")
    else:
        body = {
            key: item for key, item in value.items()
            if key != "plan_sha256"
        }
        try:
            actual = digest_json(body)
        except ControlPolicyError:
            errors.append("owner-control plan body is outside its boundary")
        else:
            if claimed != actual:
                errors.append("owner-control plan digest does not match")
    return not errors, errors


def require_plan(value: Any) -> dict[str, Any]:
    valid, errors = verify_plan(value)
    if not valid or type(value) is not dict:
        raise ControlPolicyError(
            "owner-control plan is invalid: " + "; ".join(errors[:3]))
    return json.loads(canonical_bytes(value))


__all__ = [
    "ACTION_ORDER", "ACTION_POLICIES", "ALLOWED_ACTIONS",
    "COMPUTER_PROJECT_SCAN", "ControlPolicyError", "FIND_FILES",
    "FUTURE_MUTATION_KINDS", "MAX_DEPTH", "MAX_DIRECTORIES",
    "MAX_ENTRIES_PER_DIRECTORY", "MAX_FILES", "MAX_HASH_FILE_BYTES",
    "MAX_RESULTS", "MAX_TOTAL_HASH_BYTES", "OBSERVATION_ACTIONS",
    "PLAN_FUTURE_MUTATIONS",
    "PLAN_SCHEMA", "POLICY_SCHEMA", "POLICY_SHA256", "PROFILE_SLUG",
    "frozenset()", "SAFETY_CONTROLS", "frozenset()",
    "SYSTEM_INVENTORY", "VERSION", "canonical_bytes", "create_plan",
    "compiled_profile_document", "digest_json", "is_protected_directory_name",
    "is_sensitive_file_name", "policy_document", "require_json_object",
    "require_plan", "verify_plan",
]
