#!/usr/bin/env python3
"""One-use, expiring Owner Control 4.2 capability registry.

Capabilities are authenticated by an ephemeral HMAC key and also require the
live issuing registry.  They are bound to one exact session, compiled profile,
compiled policy, plan digest, action, and authorization kind.  No capability in
this MVP grants mutation authority.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from typing import Any, Callable, Mapping

import control_policy42 as policy


VERSION = "4.2"
CAPABILITY_SCHEMA = "attestor-owner-control-capability/4.2"
CONSUMPTION_SCHEMA = "attestor-owner-control-consumption/4.2"
MAX_TTL_SECONDS = 5 * 60
MIN_TTL_SECONDS = 1
NONCE_RE = re.compile(r"[0-9a-f]{48}", re.ASCII)
REGISTRY_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
HMAC_DOMAIN = b"ATTESTOR-OWNER-CONTROL-4.2-CAPABILITY\x00"


class ControlAuthorizationError(PermissionError):
    """An Owner Control authorization failed closed."""


def _clock_value(clock: Callable[[], float]) -> int:
    try:
        value = clock()
    except Exception as exc:
        raise ControlAuthorizationError(
            "the authorization clock is unavailable") from exc
    if (type(value) not in {int, float}
            or not math.isfinite(float(value))
            or not 0 <= float(value) <= 9_223_372_036_854_775_000):
        raise ControlAuthorizationError(
            "the authorization clock returned an invalid time")
    return int(value)


def _exact_session(value: Any) -> str:
    if type(value) is not str or policy.SESSION_RE.fullmatch(value) is None:
        raise ControlAuthorizationError(
            "authorization session_id is invalid")
    return value


def _exact_nonce(value: Any) -> str:
    if type(value) is not str or NONCE_RE.fullmatch(value) is None:
        raise ControlAuthorizationError(
            "authorization nonce is invalid")
    return value


def _exact_registry(value: Any) -> str:
    if type(value) is not str or REGISTRY_RE.fullmatch(value) is None:
        raise ControlAuthorizationError(
            "authorization registry identity is invalid")
    return value


def _kind_for(action: str) -> str:
    try:
        return str(policy.ACTION_POLICIES[action]["authorization_kind"])
    except (KeyError, TypeError) as exc:
        raise ControlAuthorizationError(
            "authorization action is not allowlisted") from exc


_CAPABILITY_KEYS = {
    "action", "authorization_kind", "expires_at_unix", "hmac_sha256",
    "issued_at_unix", "mutation_authorized", "nonce", "one_use",
    "plan_sha256", "policy_sha256", "profile", "registry_id", "schema",
    "session_id", "version",
}


class CapabilityRegistry:
    """Issue and consume authenticated capabilities in one live session."""

    def __init__(
        self,
        *,
        session_id: str,
        key: bytes | None = None,
        registry_id: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.session_id = _exact_session(session_id)
        selected_key = secrets.token_bytes(32) if key is None else key
        if type(selected_key) is not bytes or not 32 <= len(selected_key) <= 512:
            raise ControlAuthorizationError(
                "authorization key must contain 32 to 512 bytes")
        if not callable(clock):
            raise ControlAuthorizationError(
                "authorization clock must be callable")
        identity = secrets.token_hex(16) if registry_id is None else registry_id
        self.registry_id = _exact_registry(identity)
        self._key = selected_key
        self._clock = clock
        self._issued: dict[str, str] = {}
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def _authenticate(self, body: Mapping[str, Any]) -> str:
        return hmac.new(
            self._key,
            HMAC_DOMAIN + policy.canonical_bytes(dict(body)),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        plan: Mapping[str, Any],
        *,
        confirmed: bool = False,
        ttl_seconds: int = 180,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        """Issue one capability after an exact affirmative confirmation."""
        if confirmed is not True:
            raise ControlAuthorizationError(
                "explicit owner-control permission confirmation is required")
        try:
            exact_plan = policy.require_plan(plan)
        except policy.ControlPolicyError as exc:
            raise ControlAuthorizationError(
                "authorization plan is invalid") from exc
        if exact_plan["session_id"] != self.session_id:
            raise ControlAuthorizationError(
                "authorization plan belongs to a different session")
        if type(ttl_seconds) is not int or not (
                MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS):
            raise ControlAuthorizationError(
                "authorization lifetime is outside its boundary")
        token_nonce = secrets.token_hex(24) if nonce is None else _exact_nonce(nonce)
        issued = _clock_value(self._clock)
        action = exact_plan["action"]
        body = {
            "schema": CAPABILITY_SCHEMA,
            "version": VERSION,
            "registry_id": self.registry_id,
            "session_id": self.session_id,
            "profile": dict(exact_plan["profile"]),
            "policy_sha256": exact_plan["policy_sha256"],
            "plan_sha256": exact_plan["plan_sha256"],
            "action": action,
            "authorization_kind": _kind_for(action),
            "issued_at_unix": issued,
            "expires_at_unix": issued + ttl_seconds,
            "nonce": token_nonce,
            "one_use": True,
            "mutation_authorized": False,
        }
        token = {**body, "hmac_sha256": self._authenticate(body)}
        with self._lock:
            if token_nonce in self._issued or token_nonce in self._used:
                raise ControlAuthorizationError(
                    "authorization nonce was already issued")
            self._issued[token_nonce] = token["hmac_sha256"]
        return policy.require_json_object(token)

    def consume(
        self,
        token: Mapping[str, Any],
        *,
        plan: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Consume a capability once and return content-free audit evidence."""
        try:
            exact_plan = policy.require_plan(plan)
        except policy.ControlPolicyError as exc:
            raise ControlAuthorizationError(
                "authorization plan is invalid") from exc
        if type(token) is not dict or set(token) != _CAPABILITY_KEYS:
            raise ControlAuthorizationError(
                "authorization capability shape is invalid")
        nonce = _exact_nonce(token.get("nonce"))
        issued = token.get("issued_at_unix")
        expires = token.get("expires_at_unix")
        if (type(issued) is not int
                or type(expires) is not int
                or not issued < expires
                or expires - issued > MAX_TTL_SECONDS):
            raise ControlAuthorizationError(
                "authorization time boundary is invalid")
        expected_body = {
            "schema": CAPABILITY_SCHEMA,
            "version": VERSION,
            "registry_id": self.registry_id,
            "session_id": self.session_id,
            "profile": dict(exact_plan["profile"]),
            "policy_sha256": exact_plan["policy_sha256"],
            "plan_sha256": exact_plan["plan_sha256"],
            "action": exact_plan["action"],
            "authorization_kind": _kind_for(exact_plan["action"]),
            "issued_at_unix": issued,
            "expires_at_unix": expires,
            "nonce": nonce,
            "one_use": True,
            "mutation_authorized": False,
        }
        for key, expected in expected_body.items():
            if token.get(key) != expected:
                raise ControlAuthorizationError(
                    "authorization is not bound to this exact operation")
        supplied_hmac = token.get("hmac_sha256")
        if (type(supplied_hmac) is not str
                or policy.SHA256_RE.fullmatch(supplied_hmac) is None):
            raise ControlAuthorizationError(
                "authorization authenticator is invalid")
        actual_hmac = self._authenticate(expected_body)
        if not hmac.compare_digest(supplied_hmac, actual_hmac):
            raise ControlAuthorizationError(
                "authorization authentication failed")
        now = _clock_value(self._clock)
        if now < issued or now >= expires:
            raise ControlAuthorizationError(
                "authorization has expired or is not yet valid")

        with self._lock:
            registered = self._issued.get(nonce)
            if registered is None or not hmac.compare_digest(
                    registered, supplied_hmac):
                raise ControlAuthorizationError(
                    "authorization was not issued by this live registry")
            if nonce in self._used:
                raise ControlAuthorizationError(
                    "authorization capability was already consumed")
            # Re-sample under the consume lock.  A clock rollback or expiry at
            # the commit boundary cannot publish authority.
            committed_at = _clock_value(self._clock)
            if committed_at < now or committed_at >= expires:
                raise ControlAuthorizationError(
                    "authorization expired or the clock changed before consume")
            audit_body = {
                "schema": CONSUMPTION_SCHEMA,
                "version": VERSION,
                "status": "authorized-once",
                "registry_id": self.registry_id,
                "session_id": self.session_id,
                "profile": dict(exact_plan["profile"]),
                "policy_sha256": exact_plan["policy_sha256"],
                "plan_sha256": exact_plan["plan_sha256"],
                "action": exact_plan["action"],
                "authorization_kind": expected_body["authorization_kind"],
                "capability_sha256": policy.digest_json(dict(token)),
                "nonce_sha256": hashlib.sha256(
                    nonce.encode("ascii")).hexdigest(),
                "consumed_at_unix": committed_at,
                "permission_retained": False,
                "mutation_authorized": False,
            }
            audit = {
                **audit_body,
                "audit_sha256": policy.digest_json(audit_body),
            }
            valid, errors = verify_consumption(audit)
            if not valid:
                raise ControlAuthorizationError(
                    "authorization audit construction failed: "
                    + "; ".join(errors[:3]))
            self._used.add(nonce)
            return policy.require_json_object(audit)


_CONSUMPTION_KEYS = {
    "action", "audit_sha256", "authorization_kind", "capability_sha256",
    "consumed_at_unix", "mutation_authorized", "nonce_sha256",
    "permission_retained", "plan_sha256", "policy_sha256", "profile",
    "registry_id", "schema", "session_id", "status", "version",
}


def verify_consumption(value: Any) -> tuple[bool, list[str]]:
    """Verify the bounded content integrity of consumption evidence.

    Only the live registry can establish issuance and unused state.  This
    verifier deliberately does not turn copied JSON into authority.
    """
    try:
        policy.canonical_bytes(value)
    except policy.ControlPolicyError:
        return False, [
            "authorization consumption is not bounded deterministic JSON"]
    if type(value) is not dict:
        return False, ["authorization consumption is not an exact object"]
    errors: list[str] = []
    if set(value) != _CONSUMPTION_KEYS:
        errors.append("authorization consumption keys are invalid")
    if (value.get("schema") != CONSUMPTION_SCHEMA
            or value.get("version") != VERSION
            or value.get("status") != "authorized-once"):
        errors.append("authorization consumption identity is invalid")
    try:
        _exact_registry(value.get("registry_id"))
        _exact_session(value.get("session_id"))
    except ControlAuthorizationError as exc:
        errors.append(str(exc))
    profile = value.get("profile")
    try:
        expected_profile = policy.compiled_profile_document()
    except policy.ControlPolicyError:
        expected_profile = {}
    if profile != expected_profile:
        errors.append("authorization consumption profile is invalid")
    for field in (
            "policy_sha256", "plan_sha256", "capability_sha256",
            "nonce_sha256"):
        item = value.get(field)
        if type(item) is not str or policy.SHA256_RE.fullmatch(item) is None:
            errors.append(f"authorization consumption {field} is invalid")
    action = value.get("action")
    if type(action) is not str or action not in policy.ALLOWED_ACTIONS:
        errors.append("authorization consumption action is invalid")
    elif value.get("authorization_kind") != _kind_for(action):
        errors.append("authorization consumption kind is invalid")
    if type(value.get("consumed_at_unix")) is not int or value.get(
            "consumed_at_unix", -1) < 0:
        errors.append("authorization consumption time is invalid")
    if (value.get("permission_retained") is not False
            or value.get("mutation_authorized") is not False):
        errors.append("authorization consumption safety flags are invalid")
    claimed = value.get("audit_sha256")
    if type(claimed) is not str or policy.SHA256_RE.fullmatch(claimed) is None:
        errors.append("authorization consumption digest is invalid")
    else:
        body = {
            key: item for key, item in value.items()
            if key != "audit_sha256"
        }
        try:
            actual = policy.digest_json(body)
        except policy.ControlPolicyError:
            errors.append("authorization consumption body is invalid")
        else:
            if not hmac.compare_digest(claimed, actual):
                errors.append("authorization consumption digest does not match")
    return not errors, errors


__all__ = [
    "CAPABILITY_SCHEMA", "CONSUMPTION_SCHEMA", "CapabilityRegistry",
    "ControlAuthorizationError", "MAX_TTL_SECONDS", "VERSION",
    "verify_consumption",
]
