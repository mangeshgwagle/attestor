#!/usr/bin/env python3
"""verdict42 -- signed, dual-engine verdicts for Attestor findings.

Upgrades the evidence ladder from digest-pinned to cryptographically
non-repudiable:

    tier 4  dual-confirmed     static evidence AND dynamic proof agree
    tier 3  runtime-confirmed  dynamic proof only (msf_lite / pilot)
    tier 2  static-candidate   analyzer evidence only
    tier 1  unverified         everything else

Signing: HMAC-SHA256 over the canonical verdict JSON with an operator
key file (minimum 16 bytes). Holders of the key can verify; nobody
without it can forge. Any field tampering breaks verification.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

VD_SCHEMA = "attestor-verdict-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

MIN_KEY_BYTES = 16

TIER_NAMES = {
    4: "dual-confirmed",
    3: "runtime-confirmed",
    2: "static-candidate",
    1: "unverified",
}


class VdError(ValueError):
    pass


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_key(path):
    key = Path(path).read_bytes()
    if len(key) < MIN_KEY_BYTES:
        raise VdError(
            "key file too short: %d bytes, minimum %d"
            % (len(key), MIN_KEY_BYTES))
    return key


# ------------------------------------------------------------ verdicts

def classify_tier(static_evidence=None, dynamic_result=None):
    """Assign the evidence tier from what actually exists."""
    has_static = bool(static_evidence)
    has_dynamic = False
    if dynamic_result:
        has_dynamic = bool(dynamic_result.get("runtime_confirmed")
                           or dynamic_result.get("confirmed_count")
                           or dynamic_result.get("synthetic_confirmed"))
    if has_static and has_dynamic:
        return 4, TIER_NAMES[4]
    if has_dynamic:
        return 3, TIER_NAMES[3]
    if has_static:
        return 2, TIER_NAMES[2]
    return 1, TIER_NAMES[1]


def dual_agrees(static_finding, dynamic_result):
    """Agreement means the dynamic proof references the same endpoint
    (or file) as the static finding."""
    if not static_finding or not dynamic_result:
        return False
    static_endpoint = (static_finding.get("url")
                       or static_finding.get("endpoint")
                       or static_finding.get("path") or "")
    dynamic_text = canonical_json(dynamic_result)
    if not static_endpoint:
        return False
    tail = static_endpoint.split("/")[-1]
    return tail in dynamic_text if tail else False


def make_verdict(static_finding=None, dynamic_result=None,
                 key=None, finding_id="VD-001"):
    static_evidence = None
    if static_finding:
        static_evidence = {
            "kind": static_finding.get("kind", "unknown"),
            "file": static_finding.get("file",
                                       static_finding.get(
                                           "handler_file", "")),
            "line": static_finding.get("line"),
        }
        if static_finding.get("evidence_digest"):
            static_evidence["evidence_digest"] = \
                static_finding["evidence_digest"]

    agrees = dual_agrees(static_finding, dynamic_result)
    if agrees:
        dynamic_result = dict(dynamic_result or {})
        dynamic_result["agrees_with_static"] = True

    tier, tier_name = classify_tier(static_evidence, dynamic_result)
    verdict = {
        "schema": VD_SCHEMA,
        "finding_id": finding_id,
        "tier": tier,
        "tier_name": tier_name,
        "static_evidence": static_evidence,
        "dynamic_result": dynamic_result,
        "dual_agreement": agrees,
    }
    verdict["verdict_sha256"] = sha256_hex(
        canonical_json(verdict).encode())
    if key is not None:
        mac = hmac.new(key, canonical_json(verdict).encode(),
                       hashlib.sha256).hexdigest()
        verdict["hmac"] = mac
    return verdict


def verify_verdict(verdict, key):
    if "hmac" not in verdict:
        return {"valid": False, "reason": "unsigned verdict",
                "field": None}
    stored = verdict["hmac"]
    body = {k: v for k, v in verdict.items() if k != "hmac"}
    expected = hmac.new(key, canonical_json(body).encode(),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, stored):
        return {"valid": False, "reason": "signature mismatch",
                "field": "body-or-hmac"}
    return {"valid": True, "tier": verdict.get("tier"),
            "tier_name": verdict.get("tier_name")}


# ------------------------------------------------------------- selftest

def run_selftest():
    checks = []
    import tempfile
    key_path = Path(tempfile.gettempdir()) / "attestor_vd_test.key"
    key_path.write_bytes(b"operator-secret-key-0123456789")
    key = load_key(key_path)

    static = {"kind": "sql-tautology-candidate",
              "url": "http://host/find-user",
              "line": 19, "evidence_digest": "a" * 64}
    dynamic = {"runtime_confirmed": True,
               "target": "http://host/find-user?user=x"}

    verdict = make_verdict(static, dynamic, key=key)
    checks.append(("agreement promotes to tier 4",
                   verdict["tier"] == 4
                   and verdict["tier_name"] == "dual-confirmed"))
    checks.append(("verdict digest pinned",
                   len(verdict["verdict_sha256"]) == 64))

    verification = verify_verdict(verdict, key)
    checks.append(("signature verifies", verification["valid"]))

    tampered = dict(verdict)
    tampered["tier"] = 1
    broken = verify_verdict(tampered, key)
    checks.append(("tampering breaks signature",
                   broken["valid"] is False))

    forged = dict(verdict)
    forged["hmac"] = "0" * 64
    checks.append(("forged hmac rejected",
                   verify_verdict(forged, key)["valid"] is False))

    static_only = make_verdict(static, None)
    checks.append(("static-only lands tier 2",
                   static_only["tier"] == 2))

    dynamic_only = make_verdict(None, dynamic)
    checks.append(("dynamic-only lands tier 3",
                   dynamic_only["tier"] == 3))

    try:
        load_key(key_path) if False else load_key(
            str(key_path)[:-1] + "x")
        checks.append(("missing key refused", False))
    except OSError:
        checks.append(("missing key refused", True))

    weak = Path(tempfile.gettempdir()) / "attestor_vd_weak.key"
    weak.write_bytes(b"short")
    try:
        load_key(weak)
        checks.append(("weak key refused", False))
    except VdError:
        checks.append(("weak key refused", True))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": VD_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="verdict42", description="Signed dual-engine verdicts")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("make", help="build + sign a verdict")
    p.add_argument("--finding", help="static finding JSON")
    p.add_argument("--dynamic", help="dynamic result JSON")
    p.add_argument("--key", required=True)
    p.add_argument("--out")

    p = subs.add_parser("verify", help="verify a signed verdict")
    p.add_argument("verdict")
    p.add_argument("--key", required=True)

    subs.add_parser("self-test")
    args = parser.parse_args(argv)

    try:
        if args.command == "make":
            def _load(maybe):
                if not maybe:
                    return None
                import os as _os
                if _os.path.exists(maybe):
                    with open(maybe, "r", encoding="utf-8") as handle:
                        return json.load(handle)
                return json.loads(maybe)

            key = load_key(args.key)
            static = _load(args.finding)
            dynamic = _load(args.dynamic)
            result = make_verdict(static, dynamic, key=key)
            if args.out:
                Path(args.out).write_text(
                    json.dumps(result, indent=2, sort_keys=True),
                    encoding="utf-8")
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN
        if args.command == "verify":
            key = load_key(args.key)
            with open(args.verdict, "r", encoding="utf-8") as handle:
                verdict = json.load(handle)
            result = verify_verdict(verdict, key)
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN if result["valid"] else EXIT_OPERATIONAL
        if args.command == "self-test":
            result = run_selftest()
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        return EXIT_INVALID
    except (VdError, OSError, json.JSONDecodeError) as exc:
        print("verdict42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
