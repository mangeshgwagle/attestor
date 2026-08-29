#!/usr/bin/env python3
"""Trusted Access: each of the five principles, framed as an attack that fails.

A grant system is only as good as the requests it *refuses*, so almost every
test here is a denial: an attacker holding a stolen grant, a replayed proof, an
expired or revoked capability, a forged signature, a scope reached for but
never granted. The single allow is the control that proves the denials are not
just a broken code path saying no to everything.
"""
from __future__ import annotations

import copy
import datetime as _datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trusted_access as ta  # noqa: E402


AUTHORITY_ID = "authority-2026"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.authority_key = os.urandom(48)
        self.authorities = {AUTHORITY_ID: self.authority_key}
        self.alice_key = os.urandom(48)
        self.subjects = {"alice@acme": self.alice_key}
        self.fingerprint = ta.subject_fingerprint(self.alice_key)
        self.grant = ta.issue_grant(
            subject_id="alice@acme", subject_key_fingerprint=self.fingerprint,
            resource="repo:acme/*", scopes=["scan:read", "assure:read"],
            authority_key=self.authority_key, authority_key_id=AUTHORITY_ID)

    def request(self, resource, scope, *, grant=None, proof_key=None,
                subjects=None, revocations=None, now=None):
        grant = self.grant if grant is None else grant
        proof_key = self.alice_key if proof_key is None else proof_key
        subjects = self.subjects if subjects is None else subjects
        challenge = ta.new_challenge(resource, scope, now=now)
        proof = ta.prove_possession(proof_key, challenge)
        return ta.decide(
            grant=grant, resource=resource, scope=scope, challenge=challenge,
            subject_proof=proof, authority_keys=self.authorities,
            subject_keys=subjects, revocations=revocations, now=now)


class ExplicitAuthorization(Fixture):
    def test_an_in_scope_request_is_allowed(self):
        self.assertTrue(self.request("repo:acme/web", "scan:read").allowed)

    def test_no_grant_is_denied(self):
        decision = ta.decide(
            grant={"schema": "nope"}, resource="repo:acme/web", scope="scan:read",
            challenge=ta.new_challenge("repo:acme/web", "scan:read"),
            subject_proof="x", authority_keys=self.authorities,
            subject_keys=self.subjects)
        self.assertFalse(decision.allowed)

    def test_default_is_deny(self):
        """Even a structurally plausible but unsigned grant is refused."""
        unsigned = {key: value for key, value in self.grant.items() if key != "signature"}
        self.assertFalse(self.request("repo:acme/web", "scan:read", grant=unsigned).allowed)


class LeastPrivilege(Fixture):
    def test_a_scope_not_granted_is_denied(self):
        self.assertFalse(self.request("repo:acme/web", "scan:write").allowed)

    def test_a_resource_outside_the_grant_is_denied(self):
        self.assertFalse(self.request("repo:other/web", "scan:read").allowed)

    def test_the_exact_prefix_boundary_is_respected(self):
        """`repo:acme/*` must not leak to a sibling like `repo:acme-evil`."""
        self.assertFalse(self.request("repo:acme-evil/x", "scan:read").allowed)

    def test_a_wildcard_grant_cannot_be_issued(self):
        for bad in ("*", "/*", "repo:*", "a*b"):
            with self.subTest(resource=bad):
                with self.assertRaises(ta.TrustedAccessError):
                    ta.issue_grant(
                        subject_id="alice@acme", subject_key_fingerprint=self.fingerprint,
                        resource=bad, scopes=["scan:read"],
                        authority_key=self.authority_key, authority_key_id=AUTHORITY_ID)


class IdentityVerification(Fixture):
    def test_holding_the_grant_is_not_enough_without_the_key(self):
        mallory = os.urandom(48)
        decision = self.request("repo:acme/web", "scan:read",
                                proof_key=mallory, subjects={"alice@acme": mallory})
        self.assertFalse(decision.allowed)
        self.assertIn("bound to this subject key", decision.reason)

    def test_a_proof_for_one_request_cannot_authorize_another(self):
        """The nonce and request binding defeat replay."""
        challenge = ta.new_challenge("repo:acme/web", "scan:read")
        proof = ta.prove_possession(self.alice_key, challenge)
        other = ta.new_challenge("repo:acme/web", "assure:read")
        decision = ta.decide(
            grant=self.grant, resource="repo:acme/web", scope="assure:read",
            challenge=other, subject_proof=proof,
            authority_keys=self.authorities, subject_keys=self.subjects)
        self.assertFalse(decision.allowed)

    def test_a_challenge_bound_to_a_different_request_is_refused(self):
        challenge = ta.new_challenge("repo:acme/other", "scan:read")
        proof = ta.prove_possession(self.alice_key, challenge)
        decision = ta.decide(
            grant=self.grant, resource="repo:acme/web", scope="scan:read",
            challenge=challenge, subject_proof=proof,
            authority_keys=self.authorities, subject_keys=self.subjects)
        self.assertFalse(decision.allowed)

    def test_an_unknown_subject_is_denied(self):
        decision = self.request("repo:acme/web", "scan:read", subjects={})
        self.assertFalse(decision.allowed)


class TimeBound(Fixture):
    def test_an_expired_grant_is_denied(self):
        past = _datetime.datetime(2020, 1, 1, tzinfo=_datetime.timezone.utc)
        grant = ta.issue_grant(
            subject_id="alice@acme", subject_key_fingerprint=self.fingerprint,
            resource="repo:acme/*", scopes=["scan:read"],
            authority_key=self.authority_key, authority_key_id=AUTHORITY_ID,
            ttl_seconds=3600, now=past)
        self.assertFalse(self.request("repo:acme/web", "scan:read", grant=grant).allowed)

    def test_a_valid_grant_within_its_window_is_allowed(self):
        now = _datetime.datetime(2026, 6, 1, tzinfo=_datetime.timezone.utc)
        grant = ta.issue_grant(
            subject_id="alice@acme", subject_key_fingerprint=self.fingerprint,
            resource="repo:acme/*", scopes=["scan:read"],
            authority_key=self.authority_key, authority_key_id=AUTHORITY_ID,
            ttl_seconds=3600, now=now)
        later = now + _datetime.timedelta(minutes=30)
        self.assertTrue(self.request("repo:acme/web", "scan:read", grant=grant, now=later).allowed)


class Revocation(Fixture):
    def test_a_revoked_grant_is_denied(self):
        revocations = ta.issue_revocation_list(
            revoked_grant_ids=[self.grant["grant_id"]],
            authority_key=self.authority_key, authority_key_id=AUTHORITY_ID)
        decision = self.request("repo:acme/web", "scan:read", revocations=revocations)
        self.assertFalse(decision.allowed)
        self.assertIn("revoked", decision.reason)

    def test_a_stale_revocation_list_fails_closed(self):
        """An out-of-date revocation list must deny, not silently allow."""
        past = _datetime.datetime(2020, 1, 1, tzinfo=_datetime.timezone.utc)
        revocations = ta.issue_revocation_list(
            revoked_grant_ids=[], authority_key=self.authority_key,
            authority_key_id=AUTHORITY_ID, ttl_seconds=3600, now=past)
        decision = self.request("repo:acme/web", "scan:read", revocations=revocations)
        self.assertFalse(decision.allowed)
        self.assertIn("stale", decision.reason)

    def test_a_forged_revocation_list_is_rejected(self):
        forged = ta.issue_revocation_list(
            revoked_grant_ids=[], authority_key=os.urandom(48),
            authority_key_id=AUTHORITY_ID)
        decision = self.request("repo:acme/web", "scan:read", revocations=forged)
        self.assertFalse(decision.allowed)


class Forgery(Fixture):
    def test_a_grant_signed_with_an_untrusted_key_is_denied(self):
        forged = ta.issue_grant(
            subject_id="alice@acme", subject_key_fingerprint=self.fingerprint,
            resource="repo:acme/*", scopes=["scan:write"],
            authority_key=os.urandom(48), authority_key_id=AUTHORITY_ID)
        self.assertFalse(self.request("repo:acme/web", "scan:write", grant=forged).allowed)

    def test_editing_a_signed_grant_breaks_it(self):
        tampered = copy.deepcopy(self.grant)
        tampered["scopes"] = ["scan:write"]        # privilege escalation attempt
        self.assertFalse(self.request("repo:acme/web", "scan:write", grant=tampered).allowed)


class AuditChain(unittest.TestCase):
    def _log(self, n=5):
        log = ta.AuditLog()
        for i in range(n):
            log.append(ta.AccessDecision(
                i % 2 == 0, "reason-%d" % i, subject_id="alice@acme",
                resource="repo:acme/web", scope="scan:read", grant_id="0" * 32))
        return log

    def test_an_untampered_chain_verifies(self):
        self.assertTrue(self._log().verify()[0])

    def test_editing_a_record_breaks_the_chain(self):
        log = self._log()
        tampered = copy.deepcopy(log.records)
        event = tampered[2]["event"]
        event["decision"] = "allow" if event["decision"] == "deny" else "deny"
        ok, errors = ta.verify_audit_records(tampered)
        self.assertFalse(ok)
        self.assertIn("2", errors[0])

    def test_deleting_a_record_breaks_the_chain(self):
        log = self._log()
        short = [row for index, row in enumerate(copy.deepcopy(log.records)) if index != 1]
        self.assertFalse(ta.verify_audit_records(short)[0])

    def test_reordering_records_breaks_the_chain(self):
        log = self._log()
        swapped = copy.deepcopy(log.records)
        swapped[1], swapped[2] = swapped[2], swapped[1]
        self.assertFalse(ta.verify_audit_records(swapped)[0])

    def test_both_allows_and_denies_are_recorded(self):
        log = ta.AuditLog()
        log.append(ta.AccessDecision(True, "granted"))
        log.append(ta.AccessDecision(False, "denied fail-closed"))
        decisions = [row["event"]["decision"] for row in log.records]
        self.assertEqual(["allow", "deny"], decisions)
        self.assertTrue(log.verify()[0])


class FailClosed(Fixture):
    def test_hostile_grants_never_raise_out_of_decide(self):
        for hostile in (None, 42, "grant", [], {}, {"schema": ta.GRANT_SCHEMA}):
            with self.subTest(value=repr(hostile)[:30]):
                decision = ta.decide(
                    grant=hostile, resource="repo:acme/web", scope="scan:read",
                    challenge=ta.new_challenge("repo:acme/web", "scan:read"),
                    subject_proof="x", authority_keys=self.authorities,
                    subject_keys=self.subjects)
                self.assertFalse(decision.allowed)


if __name__ == "__main__":
    unittest.main()
