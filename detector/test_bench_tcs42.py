#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import trusted_access as ta
import bench_tcs42 as bt


def _keys():
    import secrets
    authority = secrets.token_bytes(48)
    subject = secrets.token_bytes(48)
    return authority, subject


class AuthGating(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.auth_key, self.subj_key = _keys()
        self.fp = ta.subject_fingerprint(self.subj_key)
        akf = Path(self.tmp) / "authority.key"
        akf.write_bytes(self.auth_key)
        self.akf = str(akf)
        self.kid = "tcs-info-sec-2026"
        self.grant = ta.issue_grant(
            subject_id="tcs-scanner", subject_key_fingerprint=self.fp,
            resource="tenant/tcs/held-out-repo", scopes=["scan:read"],
            authority_key=self.auth_key, authority_key_id=self.kid)
        gf = Path(self.tmp) / "auth.json"
        gf.write_text(json.dumps(self.grant))
        self.gf = str(gf)

    def test_valid_grant_accepted(self):
        auth = bt.verify_authorization(authorization_file=self.gf, authority_key_file=self.akf)
        self.assertEqual(auth["resource"], "tenant/tcs/held-out-repo")
        self.assertIn("scan:read", auth["scopes"])

    def test_wrong_scope_denied(self):
        bad = ta.issue_grant(subject_id="x", subject_key_fingerprint=self.fp,
                             resource="tenant/tcs/held-out-repo", scopes=["repo:read"],
                             authority_key=self.auth_key, authority_key_id=self.kid)
        bf = Path(self.tmp) / "bad.json"
        bf.write_text(json.dumps(bad))
        with self.assertRaises(bt.BenchAuthError):
            bt.verify_authorization(authorization_file=str(bf), authority_key_file=self.akf)

    def test_wrong_resource_prefix_denied(self):
        bad = ta.issue_grant(subject_id="x", subject_key_fingerprint=self.fp,
                             resource="tenant/other/repo", scopes=["scan:read"],
                             authority_key=self.auth_key, authority_key_id=self.kid)
        bf = Path(self.tmp) / "bad2.json"
        bf.write_text(json.dumps(bad))
        with self.assertRaises(bt.BenchAuthError):
            bt.verify_authorization(authorization_file=str(bf), authority_key_file=self.akf)

    def test_expired_grant_denied(self):
        import datetime as _dt
        past = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=2)
        expired = ta.issue_grant(subject_id="x", subject_key_fingerprint=self.fp,
                                 resource="tenant/tcs/held-out-repo", scopes=["scan:read"],
                                 authority_key=self.auth_key, authority_key_id=self.kid,
                                 ttl_seconds=3600, now=past)
        bf = Path(self.tmp) / "exp.json"
        bf.write_text(json.dumps(expired))
        with self.assertRaises(bt.BenchAuthError):
            bt.verify_authorization(authorization_file=str(bf), authority_key_file=self.akf)

    def test_run_authorized_end_to_end(self):
        base = Path(self.tmp) / "work"
        base.mkdir()
        src = base / "src"
        src.mkdir()
        (src / "c1.c").write_text("int main(){return 0;}\n")
        (src / "c2.c").write_text("int main(){return 1;}\n")
        (src / "c3.c").write_text("int main(){return 2;}\n")
        corpus = {
            "schema": "attestor.benchmark-corpus/4.1",
            "name": "tcs-mini",
            "cases": [
                {"id": "c1", "split": "held-out", "source": "src/c1.c", "label": True, "expected_rules": ["asm-direct-execve"]},
                {"id": "c2", "split": "held-out", "source": "src/c2.c", "label": False, "expected_rules": []},
                {"id": "c3", "split": "held-out", "source": "src/c3.c", "label": True, "expected_rules": ["cpp-injection"]},
            ],
        }
        (base / "corpus.json").write_text(json.dumps(corpus))
        records = {
            "schema": "attestor.benchmark-results/4.1",
            "records": [
                {"case_id": "c1", "lane": "attestor-only", "sample": 0, "probability": 0.9, "predicted_positive": True, "status": "completed", "finding_rules": ["asm-direct-execve"]},
                {"case_id": "c2", "lane": "attestor-only", "sample": 0, "probability": 0.1, "predicted_positive": False, "status": "completed", "finding_rules": []},
                {"case_id": "c3", "lane": "attestor-only", "sample": 0, "probability": 0.8, "predicted_positive": True, "status": "completed", "finding_rules": ["cpp-injection"]},
                {"case_id": "c1", "lane": "model-only", "sample": 0, "probability": 0.7, "predicted_positive": True, "status": "completed", "finding_rules": ["asm-direct-execve"]},
                {"case_id": "c1", "lane": "model-only", "sample": 1, "probability": 0.6, "predicted_positive": True, "status": "completed", "finding_rules": ["asm-direct-execve"]},
                {"case_id": "c1", "lane": "hybrid", "sample": 0, "probability": 0.85, "predicted_positive": True, "status": "completed", "finding_rules": ["asm-direct-execve"]},
                {"case_id": "c1", "lane": "hybrid", "sample": 1, "probability": 0.9, "predicted_positive": True, "status": "completed", "finding_rules": ["asm-direct-execve"]},
            ],
        }
        (base / "results.json").write_text(json.dumps(records))
        report = bt.run_authorized(
            authorization_file=self.gf, authority_key_file=self.akf,
            corpus_file=str(base / "corpus.json"),
            results_file=str(base / "results.json"),
            authorized_dir=str(base))
        self.assertIn("tcs_authorization", report)
        self.assertEqual(report["held_out_cases"], 3)
        self.assertTrue(report["tcs_authorization"]["granted_resource"].startswith("tenant/tcs/"))

    def test_run_without_authorization_denied(self):
        with self.assertRaises(bt.BenchAuthError):
            bt.run_authorized(
                authorization_file=str(Path(self.tmp) / "missing.json"),
                authority_key_file=self.akf,
                corpus_file="x", results_file="y")


if __name__ == "__main__":
    unittest.main(verbosity=2)
