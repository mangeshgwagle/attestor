#!/usr/bin/env python3
"""Stage: auth-gated TCS held-out benchmark harness (scaffold, ready for approval).

This is the front door that must be opened by TCS InfoSec before any held-out
repository is analyzed. It wraps attestorbench41 but refuses to run unless an
explicit, signed authorization is presented:

  * a Trusted Access grant whose resource is the TCS held-out prefix
    (``tenant/tcs/...``) and whose scope includes ``scan:read``;
  * signed by a trusted authority key the operator supplies offline;
  * not expired;
  * the corpus/result manifests resolve to real local files (no symlink escape).

Without that, the harness exits deny-fail-closed and analyzes nothing. It does
not manufacture cases, does not invoke any model, and runs only on bytes the
authorization names. This is the gate, not the analysis.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import trusted_access as ta
import attestorbench41 as bench

VERSION = "4.2"
TCS_RESOURCE_PREFIX = "tenant/tcs/"
REQUIRED_SCOPE = "scan:read"
MIN_KEY_BYTES = ta.MIN_KEY_BYTES

DENY = 2


class BenchAuthError(ValueError):
    """Authorization was missing or invalid. Refused fail-closed."""


def _read_key(path: str) -> bytes:
    key = Path(path).read_bytes().strip()
    if len(key) < MIN_KEY_BYTES:
        raise BenchAuthError("authority key file holds fewer than %d bytes" % MIN_KEY_BYTES)
    return key


def verify_authorization(*, authorization_file: str, authority_key_file: str,
                         now: _dt.datetime | None = None) -> dict[str, Any]:
    """Accept only a signed, in-scope, unexpired TCS grant. Fail closed."""
    current = now or ta._utc_now()
    try:
        grant = json.loads(Path(authorization_file).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchAuthError("authorization file is not valid JSON") from exc
    if not isinstance(grant, Mapping) or grant.get("schema") != ta.GRANT_SCHEMA:
        raise BenchAuthError("authorization must be a Trusted Access grant")

    key = _read_key(authority_key_file)
    try:
        sig = grant.get("signature") if isinstance(grant.get("signature"), Mapping) else {}
        kid = str(sig.get("key_id", ""))
        authority_key_id = ta._signature_ok(grant, {kid: key})
    except ta.TrustedAccessError as exc:
        raise BenchAuthError("authorization signature did not verify: %s" % exc)

    resource = str(grant.get("resource", ""))
    if not resource.startswith(TCS_RESOURCE_PREFIX):
        raise BenchAuthError("authorization resource must be under %s" % TCS_RESOURCE_PREFIX)
    scopes = set(grant.get("scopes") or [])
    if REQUIRED_SCOPE not in scopes:
        raise BenchAuthError("authorization must include scope %s" % REQUIRED_SCOPE)
    issued = ta._parse_time(grant.get("issued_at"), "issued_at")
    expires = ta._parse_time(grant.get("expires_at"), "expires_at")
    if issued > current + ta.FUTURE_SKEW:
        raise BenchAuthError("authorization is not yet valid")
    if expires <= current:
        raise BenchAuthError("authorization has expired")
    return {"authority_key_id": authority_key_id, "resource": resource,
            "scopes": sorted(scopes), "grant_id": str(grant.get("grant_id"))}


def _safe_local_file(base: Path, raw: str) -> Path:
    """Mirror attestorbench41's no-escape, no-symlink discipline for inputs."""
    if not raw or "\x00" in raw or len(raw) > 32_768:
        raise BenchAuthError("manifest path is not a bounded local path")
    lexical = Path(base / raw).resolve()
    if not str(lexical).startswith(str(base.resolve())):
        raise BenchAuthError("manifest escapes the authorized directory")
    if ta is not None and getattr(lexical, "is_symlink", lambda: False)():
        raise BenchAuthError("manifest must not be a symlink")
    if not lexical.is_file():
        raise BenchAuthError("manifest does not exist as a regular file")
    return lexical


def run_authorized(*, authorization_file: str, authority_key_file: str,
                   corpus_file: str, results_file: str,
                   reference_hashes_file: str | None = None,
                   authorized_dir: str | None = None,
                   now: _dt.datetime | None = None) -> dict[str, Any]:
    auth = verify_authorization(authorization_file=authorization_file,
                                authority_key_file=authority_key_file, now=now)
    base = Path(authorized_dir) if authorized_dir else Path(corpus_file).resolve().parent
    corpus_path = _safe_local_file(base, corpus_file)
    results_path = _safe_local_file(base, results_file)
    corpus = bench.load_corpus(corpus_path)
    records = bench.load_records(results_path)
    references = []
    if reference_hashes_file:
        ref_path = _safe_local_file(base, reference_hashes_file)
        references = bench._load_json(ref_path)
        if not isinstance(references, list):
            raise BenchAuthError("reference hash manifest must be a JSON list")
    report = bench.evaluate(corpus, records, reference_hashes=references)
    report["tcs_authorization"] = {
        "granted_resource": auth["resource"],
        "granted_scopes": auth["scopes"],
        "grant_id": auth["grant_id"],
    }
    return report


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attestor-tcs-bench",
        description="Auth-gated TCS held-out benchmark (refuses without authorization).")
    sub = parser.add_subparsers(dest="command", required=True)

    auth = sub.add_parser("authorize", help="mint a TCS scan:read grant (InfoSec only)")
    auth.add_argument("--authority-key-file", required=True)
    auth.add_argument("--authority-key-id", required=True)
    auth.add_argument("--subject-id", required=True)
    auth.add_argument("--subject-fingerprint", required=True)
    auth.add_argument("--ttl-seconds", type=int, default=8 * 60 * 60)

    run = sub.add_parser("run", help="run the held-out eval (requires authorization)")
    run.add_argument("--authorization-file", required=True)
    run.add_argument("--authority-key-file", required=True)
    run.add_argument("--corpus", required=True)
    run.add_argument("--results", required=True)
    run.add_argument("--reference-hashes")

    args = parser.parse_args(argv)
    try:
        if args.command == "authorize":
            grant = ta.issue_grant(
                subject_id=args.subject_id,
                subject_key_fingerprint=args.subject_fingerprint,
                resource=TCS_RESOURCE_PREFIX + "held-out-repo",
                scopes=[REQUIRED_SCOPE],
                authority_key=_read_key(args.authority_key_file),
                authority_key_id=args.authority_key_id,
                ttl_seconds=args.ttl_seconds)
            print(json.dumps(grant, indent=2, sort_keys=True))
            return 0
        report = run_authorized(
            authorization_file=args.authorization_file,
            authority_key_file=args.authority_key_file,
            corpus_file=args.corpus,
            results_file=args.results,
            reference_hashes_file=args.reference_hashes,
            authorized_dir=args.authorized_dir)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report.get("release_gate", {}).get("passed") else 1
    except (BenchAuthError, ta.TrustedAccessError, bench.AttestorBenchError, OSError, ValueError) as exc:
        print(json.dumps({"status": "denied", "reason": str(exc)[:400]}, sort_keys=True))
        return DENY


if __name__ == "__main__":
    raise SystemExit(_main())
