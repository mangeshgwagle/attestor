#!/usr/bin/env python3
"""Detached, off-host attestation for a source snapshot.

Why this exists
---------------
`analysis_snapshot41` can prove a report was not *corrupted* -- `verify_report`
recomputes every digest -- but it cannot prove *who* produced it or *from what*.
Attestor's own limitations say so plainly: "SHA-256 supplies equality/integrity
evidence, not authorship or authenticity." That distinction is the whole
game once an attacker has root on the host:

    1. the attacker edits files,
    2. the attacker runs Attestor,
    3. Attestor returns a perfectly valid, self-consistent, sealed report that
       describes the tampered tree as authentic.

Self-verification is defeated by step 3, because the same machine that was
compromised also computed the evidence. What is *not* defeated is a signature
made somewhere the attacker never reached, with a key the host never held.

This module signs a snapshot report off-host and verifies it on a clean
machine. The signature covers the content hash of every file, so a single
changed byte breaks it -- unless the signer's key is available, and the key
lives off the host by construction. The result is tamper-evidence against a
root-level adversary, which is the property a last-defense / forensic workflow
actually needs.

What it is not
--------------
* Not confidentiality. The manifest lists relative paths and content hashes and
  must be treated as sensitive metadata, exactly as the snapshot already warns.
* Not a hardware root of trust. HMAC proves possession of a shared secret, not
  the identity of a person or a TPM-backed boot. It is the same mechanism
  `supply_chain_center` already uses for advisory snapshots, deliberately, so
  there is one signing story in the tree rather than two.
* Not a runtime monitor. It compares a captured state to a signed baseline. It
  says nothing about what a process did between captures.

Stdlib only, like everything in `detector/`.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as _datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping

HERE = Path(__file__).resolve(strict=True).parent
if os.fspath(HERE) not in sys.path:
    sys.path.insert(0, os.fspath(HERE))

import analysis_snapshot41 as snapshot41  # noqa: E402


SCHEMA = "attestor.snapshot-attestation/4.2"
VERSION = "4.2"
ALGORITHM = "hmac-sha256"
MIN_KEY_BYTES = 32
KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,128}")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
MAX_SOURCE_FIELD = 512
# A skew window so a signer clock a few minutes ahead of the verifier does not
# read as a forged future timestamp. Matches the advisory-snapshot tolerance.
FUTURE_SKEW = _datetime.timedelta(minutes=5)

sys.dont_write_bytecode = True


class AttestationError(ValueError):
    """An attestation could not be produced or accepted, fail-closed."""


@dataclass(frozen=True)
class Verification:
    """The outcome of checking an attestation, and why."""
    valid: bool          # signature verified against a trusted key
    authentic: bool      # same as valid; named for the forensic reader
    state: str           # fresh | stale | future-dated | expiry-unknown | invalid
    key_id: str
    generated_at: str
    expires_at: str
    errors: tuple[str, ...] = ()

    @property
    def trustworthy(self) -> bool:
        """Signed by a trusted key and currently within its validity window."""
        return self.valid and self.state in {"fresh", "expiry-unknown"}


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AttestationError("attestation body must be bounded JSON") from exc


def _utc_now() -> _datetime.datetime:
    return _datetime.datetime.now(_datetime.timezone.utc)


def _iso(moment: _datetime.datetime) -> str:
    return moment.astimezone(_datetime.timezone.utc).isoformat()


def _parse_time(value: Any, field_name: str) -> _datetime.datetime:
    if not isinstance(value, str) or not value:
        raise AttestationError("%s must be an ISO-8601 UTC timestamp" % field_name)
    clean = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = _datetime.datetime.fromisoformat(clean)
    except ValueError as exc:
        raise AttestationError("%s is not a valid ISO-8601 timestamp" % field_name) from exc
    if parsed.tzinfo is None:
        raise AttestationError("%s must include a timezone" % field_name)
    return parsed.astimezone(_datetime.timezone.utc)


def _without_signature(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in attestation.items() if key != "signature"}


def _validate_source(source: Any) -> dict[str, Any]:
    if source is None:
        return {}
    if not isinstance(source, dict):
        raise AttestationError("attestation source must be an object")
    clean: dict[str, Any] = {}
    for key, value in source.items():
        if not isinstance(key, str) or not KEY_ID_PATTERN.fullmatch(key):
            raise AttestationError("attestation source key is invalid")
        if not isinstance(value, (str, int, float, bool)) or isinstance(value, bool) and value not in (True, False):
            raise AttestationError("attestation source values must be scalar")
        if len(str(value)) > MAX_SOURCE_FIELD:
            raise AttestationError("attestation source field is oversized")
        clean[key] = value
    return clean


def _require_verifiable_report(report: Mapping[str, Any]) -> None:
    """The report must be a snapshot report that self-verifies before we sign it.

    Signing a malformed or already-inconsistent report would attach authority
    to evidence Attestor would otherwise reject, so the gate is the snapshot
    module's own verifier, unchanged.
    """
    if not isinstance(report, Mapping):
        raise AttestationError("snapshot report must be an object")
    if report.get("schema") != snapshot41.SCHEMA:
        raise AttestationError("attestation only signs a source-snapshot report")
    ok, errors = snapshot41.verify_report(report)
    if not ok:
        raise AttestationError(
            "snapshot report did not self-verify: " + ", ".join(errors[:3]))
    if not DIGEST_PATTERN.fullmatch(str(report.get("snapshot_sha256", ""))):
        raise AttestationError("snapshot report has no valid content identity")


def attest(report: Mapping[str, Any], key: bytes, key_id: str, *,
           generated_at: str | None = None, expires_at: str | None = None,
           source: Mapping[str, Any] | None = None,
           now: _datetime.datetime | None = None) -> dict[str, Any]:
    """Sign a self-verifying snapshot report with a caller-held HMAC key.

    The key is the caller's to manage and must live off the host being
    attested; that separation is the entire security argument. A key shorter
    than 32 bytes is refused rather than stretched, because a weak secret would
    make the signature reversible by the same adversary it defends against.
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
        raise AttestationError("HMAC key must contain at least %d bytes" % MIN_KEY_BYTES)
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
        raise AttestationError("attestation key_id is invalid")
    _require_verifiable_report(report)

    moment = now or _utc_now()
    generated = _iso(moment) if generated_at is None else _iso(_parse_time(generated_at, "generated_at"))
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "version": VERSION,
        "algorithm": ALGORITHM,
        "generated_at": generated,
        # The snapshot identity is bound explicitly, not only through the
        # embedded report, so a verifier can compare it without re-parsing the
        # whole manifest and a mismatched pair fails closed.
        "snapshot_sha256": report["snapshot_sha256"],
        "report": dict(report),
        "source": _validate_source(source),
    }
    if expires_at is not None:
        expires = _parse_time(expires_at, "expires_at")
        if expires <= _parse_time(generated, "generated_at"):
            raise AttestationError("expires_at must be later than generated_at")
        body["expires_at"] = _iso(expires)

    digest = hmac.new(bytes(key), _canonical(body), hashlib.sha256).hexdigest()
    return {**body, "signature": {"algorithm": ALGORITHM, "key_id": key_id, "digest": digest}}


def verify(attestation: Any, trusted_keys: Mapping[str, bytes], *,
           now: _datetime.datetime | None = None) -> Verification:
    """Check an attestation against caller-trusted keys, fail-closed.

    Adversarial input never escapes as an exception: every failure resolves to
    an `invalid` verdict. A verifier that could be crashed by a crafted file
    would be a denial of the very check it exists to provide.
    """
    key_id = generated_at = expires_at = ""
    try:
        if not isinstance(attestation, Mapping):
            raise AttestationError("attestation must be an object")
        if attestation.get("schema") != SCHEMA or attestation.get("version") != VERSION:
            raise AttestationError("unsupported attestation schema or version")
        if attestation.get("algorithm") != ALGORITHM:
            raise AttestationError("unsupported attestation algorithm")

        generated_at = str(attestation.get("generated_at", ""))
        expires_at = str(attestation.get("expires_at", "")) if attestation.get("expires_at") else ""

        signature = attestation.get("signature")
        if not isinstance(signature, Mapping):
            raise AttestationError("attestation has no signature")
        if signature.get("algorithm") != ALGORITHM:
            raise AttestationError("unsupported signature algorithm")
        key_id = str(signature.get("key_id", ""))
        if not KEY_ID_PATTERN.fullmatch(key_id):
            raise AttestationError("attestation key_id is invalid")
        key = trusted_keys.get(key_id)
        if not isinstance(key, (bytes, bytearray)) or len(key) < MIN_KEY_BYTES:
            raise AttestationError("attestation key is not trusted")
        digest = signature.get("digest")
        if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
            raise AttestationError("attestation signature digest is malformed")

        expected = hmac.new(bytes(key), _canonical(_without_signature(attestation)),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, digest):
            raise AttestationError("attestation authentication failed")

        # The signature is good. Now confirm the thing it signed is an
        # internally consistent snapshot whose bound identity matches its
        # report -- a signer could otherwise attest a mismatched pair.
        report = attestation.get("report")
        if not isinstance(report, Mapping):
            raise AttestationError("attestation carries no snapshot report")
        ok, errors = snapshot41.verify_report(report)
        if not ok:
            raise AttestationError(
                "attested report did not verify: " + ", ".join(errors[:3]))
        if report.get("snapshot_sha256") != attestation.get("snapshot_sha256"):
            raise AttestationError("attested snapshot identity does not match its report")

        current = (now or _utc_now())
        if current.tzinfo is None:
            current = current.replace(tzinfo=_datetime.timezone.utc)
        current = current.astimezone(_datetime.timezone.utc)
        generated = _parse_time(generated_at, "generated_at")
        if generated > current + FUTURE_SKEW:
            return Verification(True, True, "future-dated", key_id, generated_at,
                                expires_at, ("attestation is dated in the future",))
        if expires_at:
            if _parse_time(expires_at, "expires_at") <= current:
                return Verification(True, True, "stale", key_id, generated_at,
                                    expires_at, ("attestation has expired",))
            return Verification(True, True, "fresh", key_id, generated_at, expires_at)
        return Verification(True, True, "expiry-unknown", key_id, generated_at,
                            expires_at, ("attestation has no expiry",))
    except (AttestationError, TypeError, ValueError) as exc:
        return Verification(False, False, "invalid", key_id, generated_at,
                            expires_at, (str(exc)[:512],))


def compare(current_report: Mapping[str, Any], baseline: Any,
            trusted_keys: Mapping[str, bytes], *,
            now: _datetime.datetime | None = None) -> dict[str, Any]:
    """Diff a freshly captured report against a *trusted* signed baseline.

    This is the forensic payload. A diff is only meaningful if the thing it is
    measured against is authentic, so the baseline's signature is checked
    first and a failure there refuses to diff at all -- reporting drift from an
    unverified baseline would invite the attacker to supply the baseline too.

    `tampered` is the single bit an incident responder reads: any path added,
    removed, or changed relative to a cryptographically authentic known-good
    state. `changed` is the list that matters most, because those are files
    whose bytes moved while their name did not.
    """
    verification = verify(baseline, trusted_keys, now=now)
    if not verification.valid:
        return {
            "schema": "attestor.snapshot-attestation-compare/4.2",
            "baseline_trusted": False,
            "baseline_state": verification.state,
            "comparable": False,
            "errors": list(verification.errors),
        }
    ok, errors = snapshot41.verify_report(current_report)
    if not ok:
        return {
            "schema": "attestor.snapshot-attestation-compare/4.2",
            "baseline_trusted": True,
            "baseline_state": verification.state,
            "comparable": False,
            "errors": ["current report did not verify: " + ", ".join(errors[:3])],
        }

    baseline_report = baseline["report"]
    old = {row["path"]: row["sha256"]
           for row in baseline_report["inventory"]["files"]}
    new = {row["path"]: row["sha256"]
           for row in current_report["inventory"]["files"]}
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(path for path in set(old) & set(new) if old[path] != new[path])
    tampered = bool(added or removed or changed)
    return {
        "schema": "attestor.snapshot-attestation-compare/4.2",
        "version": VERSION,
        "baseline_trusted": True,
        "baseline_state": verification.state,
        "baseline_key_id": verification.key_id,
        "baseline_generated_at": verification.generated_at,
        "comparable": True,
        "tampered": tampered,
        "baseline_snapshot_sha256": baseline.get("snapshot_sha256", ""),
        "current_snapshot_sha256": current_report.get("snapshot_sha256", ""),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": len(set(old) & set(new)) - len(changed),
    }


def _load_json(path: str) -> Any:
    data = Path(path).read_bytes()
    if len(data) > 256 * 1024 * 1024:
        raise AttestationError("input file exceeds the 256 MiB attestation bound")
    return json.loads(data.decode("utf-8"))


def _read_key(path: str) -> bytes:
    key = Path(path).read_bytes().strip()
    if len(key) < MIN_KEY_BYTES:
        raise AttestationError("key file holds fewer than %d bytes" % MIN_KEY_BYTES)
    return key


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attestor-attest",
        description="Sign or verify a source-snapshot attestation off-host.")
    sub = parser.add_subparsers(dest="command", required=True)

    sign = sub.add_parser("sign", help="sign a snapshot report JSON")
    sign.add_argument("report", help="a source-snapshot report produced by capture")
    sign.add_argument("--key-file", required=True, help=">=32 raw key bytes")
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--expires-at", default=None, help="ISO-8601 UTC")

    check = sub.add_parser("verify", help="verify an attestation")
    check.add_argument("attestation")
    check.add_argument("--key-file", required=True)
    check.add_argument("--key-id", required=True)

    cmp_parser = sub.add_parser(
        "compare", help="diff a current report against a signed baseline")
    cmp_parser.add_argument("current", help="a freshly captured snapshot report")
    cmp_parser.add_argument("baseline", help="a signed attestation")
    cmp_parser.add_argument("--key-file", required=True)
    cmp_parser.add_argument("--key-id", required=True)

    args = parser.parse_args(argv)
    try:
        key = _read_key(args.key_file)
        trusted = {args.key_id: key}
        if args.command == "sign":
            attestation = attest(_load_json(args.report), key, args.key_id,
                                 expires_at=args.expires_at)
            print(json.dumps(attestation, indent=2, sort_keys=True))
            return 0
        if args.command == "verify":
            result = verify(_load_json(args.attestation), trusted)
            print(json.dumps({
                "valid": result.valid, "state": result.state,
                "trustworthy": result.trustworthy, "key_id": result.key_id,
                "generated_at": result.generated_at, "expires_at": result.expires_at,
                "errors": list(result.errors)}, indent=2, sort_keys=True))
            return 0 if result.trustworthy else 1
        result = compare(_load_json(args.current), _load_json(args.baseline), trusted)
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result.get("comparable"):
            return 2
        return 1 if result.get("tampered") else 0
    except (AttestationError, OSError, ValueError) as exc:
        print("attestor-attest: " + str(exc)[:400], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
