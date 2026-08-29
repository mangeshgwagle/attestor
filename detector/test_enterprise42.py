import os, sys, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trusted_access as ta
import enterprise42 as ent
import unittest

AUTH_KEY = b"a"*32
AUTH_ID = "auth-main"
S_KEY_ALICE = b"b"*32
S_KEY_BOB = b"c"*32
S_KEY_APPROVER = b"d"*32

def fp(k): return ta.subject_fingerprint(k)

class TenantIsolation(unittest.TestCase):
    def test_cross_tenant_denied(self):
        g = ent.issue_tenant_grant(tenant_id="acme", subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), suffix="repo/*", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("tenant/other/repo/x", "repo:read")
        proof = ta.prove_possession(S_KEY_ALICE, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=None, resource="tenant/other/repo/x", scope="repo:read", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY}, subject_keys={"alice":S_KEY_ALICE})
        self.assertFalse(dec.allowed)
        self.assertIn("tenant isolation", dec.reason)
    def test_same_tenant_allowed(self):
        g = ent.issue_tenant_grant(tenant_id="acme", subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), suffix="repo/x", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("tenant/acme/repo/x", "repo:read")
        proof = ta.prove_possession(S_KEY_ALICE, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=None, resource="tenant/acme/repo/x", scope="repo:read", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY}, subject_keys={"alice":S_KEY_ALICE})
        self.assertTrue(dec.allowed)
    def test_non_tenant_still_works(self):
        g = ta.issue_grant(subject_id="bob", subject_key_fingerprint=fp(S_KEY_BOB), resource="repo/acme/*", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("repo/acme/x", "repo:read")
        proof = ta.prove_possession(S_KEY_BOB, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=None, resource="repo/acme/x", scope="repo:read", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY}, subject_keys={"bob":S_KEY_BOB})
        self.assertTrue(dec.allowed)

class Approval(unittest.TestCase):
    def test_sensitive_needs_approval(self):
        g = ent.issue_tenant_grant(tenant_id="acme", subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), suffix="repo/x", scopes=["repo:write"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("tenant/acme/repo/x", "repo:write")
        proof = ta.prove_possession(S_KEY_ALICE, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=None, resource="tenant/acme/repo/x", scope="repo:write", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY}, subject_keys={"alice":S_KEY_ALICE})
        self.assertFalse(dec.allowed)
        self.assertIn("dual approval", dec.reason)
    def test_with_approval_passes(self):
        g = ent.issue_tenant_grant(tenant_id="acme", subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), suffix="repo/x", scopes=["repo:write"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        appr = ent.issue_approval(grant=g, approver_id="carol", approver_key=S_KEY_APPROVER, approver_key_id="approver", approver_fingerprint=fp(S_KEY_APPROVER), authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("tenant/acme/repo/x", "repo:write")
        proof = ta.prove_possession(S_KEY_ALICE, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=appr, resource="tenant/acme/repo/x", scope="repo:write", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY, "approver":AUTH_KEY}, subject_keys={"alice":S_KEY_ALICE})
        self.assertTrue(dec.allowed)
    def test_non_sensitive_no_approval(self):
        g = ent.issue_tenant_grant(tenant_id="acme", subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), suffix="repo/x", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("tenant/acme/repo/x", "repo:read")
        proof = ta.prove_possession(S_KEY_ALICE, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=None, resource="tenant/acme/repo/x", scope="repo:read", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY}, subject_keys={"alice":S_KEY_ALICE})
        self.assertTrue(dec.allowed)

class Admin(unittest.TestCase):
    def test_enumerate(self):
        g1 = ent.issue_tenant_grant(tenant_id="acme", subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), suffix="a", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        g2 = ent.issue_tenant_grant(tenant_id="other", subject_id="bob", subject_key_fingerprint=fp(S_KEY_BOB), suffix="b", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        self.assertEqual(1, len(ent.enumerate_grants([g1,g2], tenant_id="acme")))
        self.assertEqual(1, len(ent.enumerate_grants([g1,g2], subject_id="bob")))
    def test_bulk_revoke(self):
        g = ta.issue_grant(subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), resource="repo/x", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        rev = ent.bulk_revoke(grant_ids=[g["grant_id"]], authority_key=AUTH_KEY, authority_key_id=AUTH_ID)
        chal = ta.new_challenge("repo/x", "repo:read")
        proof = ta.prove_possession(S_KEY_ALICE, chal)
        dec = ent.decide_with_isolation_and_approval(grant=g, approval=None, resource="repo/x", scope="repo:read", challenge=chal, subject_proof=proof, authority_keys={AUTH_ID:AUTH_KEY}, subject_keys={"alice":S_KEY_ALICE}, revocations=rev)
        self.assertFalse(dec.allowed)
        self.assertIn("revoked", dec.reason)
    def test_expiry_report(self):
        now = ta._utc_now()
        g_exp = ta.issue_grant(subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), resource="repo/x", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID, ttl_seconds=60, now=now - datetime.timedelta(seconds=120))
        g_soon = ta.issue_grant(subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), resource="repo/y", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID, ttl_seconds=3600, now=now)
        g_ok = ta.issue_grant(subject_id="alice", subject_key_fingerprint=fp(S_KEY_ALICE), resource="repo/z", scopes=["repo:read"], authority_key=AUTH_KEY, authority_key_id=AUTH_ID, ttl_seconds=3600*24, now=now)
        rep = ent.expiry_report([g_exp, g_soon, g_ok], now=now, warning_seconds=4000)
        self.assertEqual(1, len(rep["expired"]))
        self.assertEqual(1, len(rep["expiring_soon"]))
        self.assertEqual(1, len(rep["active"]))

if __name__ == "__main__":
    unittest.main()
