#!/usr/bin/env python3
"""Trusted Access: verifiable, least-privilege authorization for Attestor resources.

What this is for
----------------
Attestor analyses code and produces evidence; some of that -- a signed baseline, a
report over a private tree, a scan scope -- should only be reachable by people
who were explicitly and verifiably authorized. This module is the gate. It does
not replace Owner Control (which binds a single local capability to an exact
plan); it answers a different question: *may this identity reach this resource,
with these scopes, right now?*

The five principles, and where each lives
-----------------------------------------
* **Explicit authorization.** The answer is deny unless a signed grant names
  the exact resource and scope. There is no ambient permission, no default
  allow, and no wildcard grant -- `_resource_covers` refuses a bare "*".

* **Identity verification.** A grant is not a bearer token. It binds a
  subject's key fingerprint, and `decide` requires the subject to prove
  possession of that key by answering a fresh challenge (`prove_possession`).
  Holding a copy of the grant is not enough; you must also be the subject it
  was issued to. That is the difference between authorization and identity, and
  both are required.

* **Least privilege.** Scopes are an explicit allowlist and the request must be
  a subset (`_scopes_cover`). A grant for `scan:read` cannot be used to write.
  Resources are bounded prefixes, not open globs.

* **Revocation.** Before any allow, the grant id is checked against a signed,
  freshness-bounded revocation list. A revoked or stale-list grant is denied,
  fail-closed, even if everything else about it is valid.

* **Audit logging.** Every decision -- allow or deny -- is emitted as a record
  in an append-only, hash-chained log. Each record commits to the hash of the
  one before it, so deleting, reordering, or editing any entry breaks the chain
  and `AuditLog.verify` reports exactly where.

Safeguards this must not weaken
-------------------------------
It adds a check and removes none. It executes nothing, opens no socket, follows
the same fail-closed discipline as the rest of `detector/` -- adversarial input
resolves to a denial, never an exception -- and it is stdlib-only, so it carries
no new supply chain. HMAC-SHA256 proves possession of a shared secret; it is not
a hardware root of trust or an asymmetric identity, and the keys it trusts are
the caller's to manage and to keep off the machines it protects.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import datetime as _datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sys
from typing import Any, Iterable, Mapping, Sequence


GRANT_SCHEMA = "attestor.trusted-access-grant/4.2"
REVOCATION_SCHEMA = "attestor.trusted-access-revocations/4.2"
CHALLENGE_SCHEMA = "attestor.trusted-access-challenge/4.2"
AUDIT_SCHEMA = "attestor.trusted-access-audit/4.2"
DECISION_SCHEMA = "attestor.trusted-access-decision/4.2"
VERSION = "4.2"
ALGORITHM = "hmac-sha256"

MIN_KEY_BYTES = 32
ID_PATTERN = re.compile(r"[A-Za-z0-9_.:@/+-]{1,256}")
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,128}")
SCOPE_PATTERN = re.compile(r"[a-z0-9_]+:[a-z0-9_]+")
RESOURCE_PATTERN = re.compile(r"[A-Za-z0-9_.:@/+*-]{1,512}")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
FUTURE_SKEW = _datetime.timedelta(minutes=5)
GENESIS = "0" * 64

sys.dont_write_bytecode = True


class TrustedAccessError(ValueError):
    """A grant, proof, or record could not be produced or accepted, fail-closed."""


# --------------------------------------------------------------------------- #
# Canonical encoding and time (shared with the rest of the evidence layer).
# --------------------------------------------------------------------------- #
def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise TrustedAccessError("value is not bounded canonical JSON") from exc


def _sha(value: Any) -> str:
    payload = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(payload).hexdigest()


def _utc_now() -> _datetime.datetime:
    return _datetime.datetime.now(_datetime.timezone.utc)


def _iso(moment: _datetime.datetime) -> str:
    return moment.astimezone(_datetime.timezone.utc).isoformat()


def _parse_time(value: Any, field_name: str) -> _datetime.datetime:
    if not isinstance(value, str) or not value:
        raise TrustedAccessError("%s must be an ISO-8601 UTC timestamp" % field_name)
    clean = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = _datetime.datetime.fromisoformat(clean)
    except ValueError as exc:
        raise TrustedAccessError("%s is not a valid ISO-8601 timestamp" % field_name) from exc
    if parsed.tzinfo is None:
        raise TrustedAccessError("%s must carry a timezone" % field_name)
    return parsed.astimezone(_datetime.timezone.utc)


def _sign(body: Mapping[str, Any], key: bytes, key_id: str) -> dict[str, Any]:
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise TrustedAccessError("signing key must be at least %d bytes" % MIN_KEY_BYTES)
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
        raise TrustedAccessError("key_id is invalid")
    digest = hmac.new(bytes(key), _canonical(dict(body)), hashlib.sha256).hexdigest()
    return {**body, "signature": {"algorithm": ALGORITHM, "key_id": key_id, "digest": digest}}


def _signature_ok(document: Mapping[str, Any], trusted_keys: Mapping[str, bytes]) -> str:
    """Return the trusted key_id if the signature verifies, else raise."""
    signature = document.get("signature")
    if not isinstance(signature, Mapping):
        raise TrustedAccessError("document is not signed")
    if signature.get("algorithm") != ALGORITHM:
        raise TrustedAccessError("unsupported signature algorithm")
    key_id = str(signature.get("key_id", ""))
    if not KEY_ID_PATTERN.fullmatch(key_id):
        raise TrustedAccessError("signature key_id is invalid")
    key = trusted_keys.get(key_id)
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise TrustedAccessError("signature key is not trusted")
    digest = signature.get("digest")
    if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
        raise TrustedAccessError("signature digest is malformed")
    body = {key: value for key, value in document.items() if key != "signature"}
    expected = hmac.new(bytes(key), _canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, digest):
        raise TrustedAccessError("signature verification failed")
    return key_id


# --------------------------------------------------------------------------- #
# Identity: a subject key, its published fingerprint, and proof of possession.
# --------------------------------------------------------------------------- #
def subject_fingerprint(subject_key: bytes) -> str:
    """The public fingerprint of a subject key, safe to embed in a grant."""
    if not isinstance(subject_key, (bytes, bytearray)) or len(subject_key) < MIN_KEY_BYTES:
        raise TrustedAccessError("subject key must be at least %d bytes" % MIN_KEY_BYTES)
    return hashlib.sha256(b"attestor-trusted-access-subject\x00" + bytes(subject_key)).hexdigest()


def new_challenge(resource: str, scope: str, *, now: _datetime.datetime | None = None) -> dict[str, Any]:
    """A fresh, single-use challenge binding the exact request being authorized.

    The nonce makes a captured proof useless for a later request, and binding
    the resource and scope stops a proof gathered for one action being replayed
    to authorize a different, broader one.
    """
    return {
        "schema": CHALLENGE_SCHEMA,
        "version": VERSION,
        "nonce": secrets.token_hex(16),
        "resource": _resource(resource),
        "scope": _scope(scope),
        "issued_at": _iso(now or _utc_now()),
    }


def prove_possession(subject_key: bytes, challenge: Mapping[str, Any]) -> str:
    """The subject's answer to a challenge: HMAC of the challenge under its key."""
    if not isinstance(subject_key, (bytes, bytearray)) or len(subject_key) < MIN_KEY_BYTES:
        raise TrustedAccessError("subject key must be at least %d bytes" % MIN_KEY_BYTES)
    if challenge.get("schema") != CHALLENGE_SCHEMA:
        raise TrustedAccessError("challenge schema is unsupported")
    return hmac.new(bytes(subject_key), _canonical(dict(challenge)), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Validation of the least-privilege primitives.
# --------------------------------------------------------------------------- #
def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise TrustedAccessError("%s is invalid" % label)
    return value


def _resource(value: Any) -> str:
    if not isinstance(value, str) or not RESOURCE_PATTERN.fullmatch(value):
        raise TrustedAccessError("resource is invalid")
    # `*` is permitted only as a single trailing `/*` suffix, and never as the
    # whole pattern. That bans `*`, `/*`, `repo:*`, `a*b` and every other broad
    # spelling, so a grant always names a concrete prefix -- least privilege by
    # construction rather than by reviewer vigilance.
    body = value[:-2] if value.endswith("/*") else value
    if "*" in body or value in {"*", "/*"}:
        raise TrustedAccessError("a wildcard resource is only allowed as a trailing '/*'")
    return value


def _scope(value: Any) -> str:
    if not isinstance(value, str) or not SCOPE_PATTERN.fullmatch(value):
        raise TrustedAccessError("scope must look like 'area:action'")
    return value


def _scopes(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values or len(values) > 64:
        raise TrustedAccessError("scopes must be a non-empty bounded list")
    cleaned = tuple(sorted({_scope(item) for item in values}))
    if not cleaned:
        raise TrustedAccessError("scopes must be a non-empty bounded list")
    return cleaned


def _resource_covers(granted: str, requested: str) -> bool:
    """Does a granted resource pattern cover a concrete requested resource?

    Exact match, or a single trailing `/*` prefix. A bare `*` never reaches
    here -- it is refused at issue time -- so there is no way to widen a grant
    to everything.
    """
    if granted == requested:
        return True
    if granted.endswith("/*"):
        prefix = granted[:-1]                 # keep the trailing slash
        return requested.startswith(prefix) and len(requested) > len(prefix)
    return False


def _scopes_cover(granted: Sequence[str], requested: str) -> bool:
    return requested in set(granted)


# --------------------------------------------------------------------------- #
# Grants and revocation lists.
# --------------------------------------------------------------------------- #
def issue_grant(*, subject_id: str, subject_key_fingerprint: str, resource: str,
                scopes: Iterable[str], authority_key: bytes, authority_key_id: str,
                ttl_seconds: int = 8 * 60 * 60, now: _datetime.datetime | None = None,
                note: str = "") -> dict[str, Any]:
    """Authority mints an explicit, time-bounded, least-privilege grant."""
    if not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 32 * 24 * 60 * 60:
        raise TrustedAccessError("ttl_seconds must be between 60 and 32 days")
    if not DIGEST_PATTERN.fullmatch(str(subject_key_fingerprint)):
        raise TrustedAccessError("subject key fingerprint is invalid")
    moment = now or _utc_now()
    body = {
        "schema": GRANT_SCHEMA,
        "version": VERSION,
        "grant_id": secrets.token_hex(16),
        "subject": {"id": _id(subject_id, "subject id"),
                    "key_fingerprint": subject_key_fingerprint},
        "resource": _resource(resource),
        "scopes": list(_scopes(list(scopes))),
        "issued_at": _iso(moment),
        "expires_at": _iso(moment + _datetime.timedelta(seconds=ttl_seconds)),
        "note": str(note)[:256],
    }
    return _sign(body, authority_key, authority_key_id)


def issue_revocation_list(*, revoked_grant_ids: Iterable[str], authority_key: bytes,
                          authority_key_id: str, ttl_seconds: int = 24 * 60 * 60,
                          now: _datetime.datetime | None = None) -> dict[str, Any]:
    """A signed, freshness-bounded set of grant ids that must be refused."""
    ids = sorted({str(item) for item in revoked_grant_ids})
    if len(ids) > 100_000:
        raise TrustedAccessError("revocation list exceeds its bound")
    for item in ids:
        if not re.fullmatch(r"[0-9a-f]{32}", item):
            raise TrustedAccessError("a revoked grant id is malformed")
    moment = now or _utc_now()
    body = {
        "schema": REVOCATION_SCHEMA,
        "version": VERSION,
        "revoked": ids,
        "generated_at": _iso(moment),
        "expires_at": _iso(moment + _datetime.timedelta(seconds=ttl_seconds)),
    }
    return _sign(body, authority_key, authority_key_id)


# --------------------------------------------------------------------------- #
# The decision.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    subject_id: str = ""
    resource: str = ""
    scope: str = ""
    grant_id: str = ""
    authority_key_id: str = ""
    decided_at: str = ""

    def audit_body(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "resource": self.resource,
            "scope": self.scope,
            "grant_id": self.grant_id,
            "authority_key_id": self.authority_key_id,
            "decision": "allow" if self.allowed else "deny",
            "reason": self.reason,
            "decided_at": self.decided_at,
        }


def _deny(reason: str, **fields: str) -> AccessDecision:
    return AccessDecision(False, reason, decided_at=_iso(_utc_now()), **fields)


def decide(*, grant: Any, resource: str, scope: str, challenge: Mapping[str, Any],
           subject_proof: str, authority_keys: Mapping[str, bytes],
           subject_keys: Mapping[str, bytes],
           revocations: Mapping[str, Any] | None = None,
           now: _datetime.datetime | None = None) -> AccessDecision:
    """Decide one access request. Default deny; every failure is fail-closed.

    The order enforces the principles: authenticate the grant, bound it in
    time, honour revocation, verify the caller's identity by proof of
    possession, then check that the concrete request is inside the grant's
    resource and scope. A hostile input at any step resolves to a denial with a
    reason, never an exception.
    """
    current = now or _utc_now()
    try:
        req_resource = _resource(resource)
        req_scope = _scope(scope)
    except TrustedAccessError as exc:
        return _deny("request is malformed: %s" % exc)

    try:
        # 1. Explicit authorization: a well-formed, authentically signed grant.
        if not isinstance(grant, Mapping) or grant.get("schema") != GRANT_SCHEMA:
            return _deny("no valid grant presented", resource=req_resource, scope=req_scope)
        authority_key_id = _signature_ok(grant, authority_keys)
        grant_id = str(grant.get("grant_id", ""))
        subject = grant.get("subject") if isinstance(grant.get("subject"), Mapping) else {}
        subject_id = str(subject.get("id", ""))
        fingerprint = str(subject.get("key_fingerprint", ""))
        granted_scopes = grant.get("scopes")
        granted_resource = grant.get("resource")
        if (not re.fullmatch(r"[0-9a-f]{32}", grant_id)
                or not ID_PATTERN.fullmatch(subject_id)
                or not DIGEST_PATTERN.fullmatch(fingerprint)
                or not isinstance(granted_resource, str)
                or not isinstance(granted_scopes, list)):
            return _deny("grant structure is invalid", authority_key_id=authority_key_id)

        common = dict(subject_id=subject_id, resource=req_resource, scope=req_scope,
                      grant_id=grant_id, authority_key_id=authority_key_id)

        # 2. Time bound.
        issued = _parse_time(grant.get("issued_at"), "issued_at")
        expires = _parse_time(grant.get("expires_at"), "expires_at")
        if issued > current + FUTURE_SKEW:
            return _deny("grant is not yet valid", **common)
        if expires <= current:
            return _deny("grant has expired", **common)

        # 3. Revocation, enforced before any allow.
        if revocations is not None:
            try:
                _signature_ok(revocations, authority_keys)
                rev_expires = _parse_time(revocations.get("expires_at"), "expires_at")
                if rev_expires <= current:
                    return _deny("revocation list is stale; refusing fail-closed", **common)
                revoked = revocations.get("revoked")
                if not isinstance(revoked, list):
                    return _deny("revocation list is malformed", **common)
                if grant_id in set(revoked):
                    return _deny("grant has been revoked", **common)
            except TrustedAccessError as exc:
                return _deny("revocation list did not verify: %s" % exc, **common)

        # 4. Identity: the caller must prove possession of the subject key.
        subject_key = subject_keys.get(subject_id)
        if not isinstance(subject_key, (bytes, bytearray)) or len(subject_key) < MIN_KEY_BYTES:
            return _deny("subject identity is not established", **common)
        if not hmac.compare_digest(subject_fingerprint(bytes(subject_key)), fingerprint):
            return _deny("grant is not bound to this subject key", **common)
        if not isinstance(challenge, Mapping) or challenge.get("schema") != CHALLENGE_SCHEMA:
            return _deny("challenge is missing or malformed", **common)
        if challenge.get("resource") != req_resource or challenge.get("scope") != req_scope:
            return _deny("challenge does not bind this exact request", **common)
        expected_proof = prove_possession(bytes(subject_key), challenge)
        if not isinstance(subject_proof, str) or not hmac.compare_digest(expected_proof, subject_proof):
            return _deny("proof of possession failed", **common)

        # 5. Least privilege: the concrete request must sit inside the grant.
        if not _resource_covers(granted_resource, req_resource):
            return _deny("resource is outside the grant", **common)
        if not _scopes_cover(granted_scopes, req_scope):
            return _deny("scope is outside the grant", **common)

        return AccessDecision(True, "granted", decided_at=_iso(current), **common)
    except TrustedAccessError as exc:
        return _deny("denied fail-closed: %s" % exc, resource=req_resource, scope=req_scope)
    except Exception as exc:  # noqa: BLE001 - never let hostile input escape as a crash
        return _deny("denied fail-closed (%s)" % type(exc).__name__,
                     resource=req_resource, scope=req_scope)


# --------------------------------------------------------------------------- #
# Tamper-evident, append-only audit log (hash chain).
# --------------------------------------------------------------------------- #
@dataclass
class AuditLog:
    """An append-only log where each record commits to the previous one.

    Removing, reordering, or editing a record breaks the chain, and `verify`
    reports the sequence number where it broke. The log records both allows and
    denies -- a denial is exactly the event a reviewer most wants to see.
    """
    records: list[dict[str, Any]] = field(default_factory=list)

    def append(self, decision: AccessDecision) -> dict[str, Any]:
        prev = self.records[-1]["record_sha256"] if self.records else GENESIS
        body = {
            "schema": AUDIT_SCHEMA,
            "version": VERSION,
            "seq": len(self.records),
            "prev_sha256": prev,
            "event": decision.audit_body(),
        }
        body["record_sha256"] = _sha(body)
        self.records.append(body)
        return body

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev = GENESIS
        for index, record in enumerate(self.records):
            if not isinstance(record, dict) or record.get("seq") != index:
                errors.append("record %d has a wrong sequence number" % index)
                break
            if record.get("prev_sha256") != prev:
                errors.append("record %d does not chain to its predecessor" % index)
                break
            body = {key: value for key, value in record.items() if key != "record_sha256"}
            if record.get("record_sha256") != _sha(body):
                errors.append("record %d digest does not match its contents" % index)
                break
            prev = record["record_sha256"]
        return not errors, errors

    def head(self) -> str:
        return self.records[-1]["record_sha256"] if self.records else GENESIS


def verify_audit_records(records: Sequence[Mapping[str, Any]]) -> tuple[bool, list[str]]:
    log = AuditLog(records=[dict(row) for row in records])
    return log.verify()


# --------------------------------------------------------------------------- #
# Command line.
# --------------------------------------------------------------------------- #
def _read_key(path: str) -> bytes:
    key = Path(path).read_bytes().strip()
    if len(key) < MIN_KEY_BYTES:
        raise TrustedAccessError("key file holds fewer than %d bytes" % MIN_KEY_BYTES)
    return key


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attestor-access",
        description="Issue and verify Trusted Access grants (offline, fail-closed).")
    sub = parser.add_subparsers(dest="command", required=True)

    fp = sub.add_parser("fingerprint", help="print a subject key's public fingerprint")
    fp.add_argument("--subject-key-file", required=True)

    grant = sub.add_parser("issue-grant", help="mint a signed grant")
    grant.add_argument("--authority-key-file", required=True)
    grant.add_argument("--authority-key-id", required=True)
    grant.add_argument("--subject-id", required=True)
    grant.add_argument("--subject-fingerprint", required=True)
    grant.add_argument("--resource", required=True)
    grant.add_argument("--scope", action="append", required=True, dest="scopes")
    grant.add_argument("--ttl-seconds", type=int, default=8 * 60 * 60)

    args = parser.parse_args(argv)
    try:
        if args.command == "fingerprint":
            print(subject_fingerprint(_read_key(args.subject_key_file)))
            return 0
        document = issue_grant(
            subject_id=args.subject_id,
            subject_key_fingerprint=args.subject_fingerprint,
            resource=args.resource, scopes=args.scopes,
            authority_key=_read_key(args.authority_key_file),
            authority_key_id=args.authority_key_id, ttl_seconds=args.ttl_seconds)
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (TrustedAccessError, OSError, ValueError) as exc:
        print("attestor-access: " + str(exc)[:400], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
