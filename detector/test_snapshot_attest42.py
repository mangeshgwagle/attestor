#!/usr/bin/env python3
"""Detached snapshot attestation: tamper-evidence against a root-level adversary.

The property under test is not "a signature round-trips". It is the specific
thing self-verification cannot do: a report produced on a compromised host is
internally consistent -- the attacker's machine computed its digests honestly
over the tampered bytes -- yet an off-host signature over the *known-good*
state still exposes the change. Every test here is a move an attacker with root
would actually make, and each must fail closed.
"""
from __future__ import annotations

import copy
import datetime as _datetime
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import analysis_snapshot41 as snapshot41  # noqa: E402
import snapshot_attest as attest  # noqa: E402


KEY = b"k" * 48
KEY_ID = "forensics-2026-a"
TRUSTED = {KEY_ID: KEY}


def _capture(files: dict[str, str]):
    directory = tempfile.mkdtemp()
    for name, body in files.items():
        Path(directory, name).write_text(body, encoding="utf-8")
    return directory, snapshot41.capture(directory).report()


class SignAndVerify(unittest.TestCase):
    def setUp(self):
        _dir, self.report = _capture({"app.py": "def f():\n    return 1\n"})

    def test_a_signed_report_verifies_and_is_trustworthy(self):
        attestation = attest.attest(self.report, KEY, KEY_ID)
        verification = attest.verify(attestation, TRUSTED)
        self.assertTrue(verification.valid)
        self.assertTrue(verification.trustworthy)
        self.assertEqual(KEY_ID, verification.key_id)

    def test_the_attestation_binds_the_snapshot_identity(self):
        attestation = attest.attest(self.report, KEY, KEY_ID)
        self.assertEqual(attestation["snapshot_sha256"],
                         self.report["snapshot_sha256"])

    def test_a_report_that_does_not_self_verify_is_not_signed(self):
        broken = dict(self.report)
        broken["report_sha256"] = "0" * 64
        with self.assertRaises(attest.AttestationError):
            attest.attest(broken, KEY, KEY_ID)

    def test_a_non_snapshot_report_is_refused(self):
        with self.assertRaises(attest.AttestationError):
            attest.attest({"schema": "something-else"}, KEY, KEY_ID)


class KeyDiscipline(unittest.TestCase):
    def setUp(self):
        _dir, self.report = _capture({"app.py": "x = 1\n"})

    def test_a_short_key_is_refused_rather_than_stretched(self):
        with self.assertRaises(attest.AttestationError):
            attest.attest(self.report, b"tooshort", KEY_ID)

    def test_an_invalid_key_id_is_refused(self):
        for bad in ("", "has spaces", "x" * 200, "semi;colon"):
            with self.subTest(key_id=bad):
                with self.assertRaises(attest.AttestationError):
                    attest.attest(self.report, KEY, bad)

    def test_verification_requires_the_matching_trusted_key(self):
        attestation = attest.attest(self.report, KEY, KEY_ID)
        wrong = attest.verify(attestation, {KEY_ID: b"w" * 48})
        self.assertFalse(wrong.valid)
        self.assertEqual("invalid", wrong.state)

    def test_an_untrusted_key_id_is_rejected(self):
        attestation = attest.attest(self.report, KEY, KEY_ID)
        self.assertFalse(attest.verify(attestation, {"other-key": KEY}).valid)


class AdversaryWithRoot(unittest.TestCase):
    """The scenarios the module exists for."""

    def test_a_tampered_report_self_verifies_but_the_baseline_catches_it(self):
        directory, baseline_report = _capture({
            "app.py": "def f():\n    return 1\n", "util.py": "SAFE = True\n"})
        attestation = attest.attest(baseline_report, KEY, KEY_ID)

        Path(directory, "app.py").write_text(
            "def f():\n    return 1  # backdoor\n", encoding="utf-8")
        Path(directory, "implant.py").write_text(
            "import os\nos.system('curl evil')\n", encoding="utf-8")
        tampered = snapshot41.capture(directory).report()

        # The attacker's own machine computed this honestly, so it self-verifies.
        self.assertTrue(snapshot41.verify_report(tampered)[0])

        result = attest.compare(tampered, attestation, TRUSTED)
        self.assertTrue(result["baseline_trusted"])
        self.assertTrue(result["tampered"])
        self.assertEqual(["app.py"], result["changed"])
        self.assertEqual(["implant.py"], result["added"])

    def test_a_removed_file_is_caught(self):
        directory, baseline_report = _capture({
            "a.py": "1\n", "audit_log.py": "keep = True\n"})
        attestation = attest.attest(baseline_report, KEY, KEY_ID)
        os.remove(Path(directory, "audit_log.py"))
        tampered = snapshot41.capture(directory).report()
        result = attest.compare(tampered, attestation, TRUSTED)
        self.assertTrue(result["tampered"])
        self.assertEqual(["audit_log.py"], result["removed"])

    def test_a_baseline_resigned_with_the_attackers_key_is_rejected(self):
        _dir, report = _capture({"app.py": "x = 1\n"})
        forged = attest.attest(report, os.urandom(48), KEY_ID)  # attacker's key
        self.assertFalse(attest.verify(forged, TRUSTED).valid)

    def test_flipping_one_signature_bit_invalidates_it(self):
        _dir, report = _capture({"app.py": "x = 1\n"})
        attestation = attest.attest(report, KEY, KEY_ID)
        mutated = copy.deepcopy(attestation)
        digest = mutated["signature"]["digest"]
        mutated["signature"]["digest"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        self.assertFalse(attest.verify(mutated, TRUSTED).valid)

    def test_editing_the_report_under_a_good_signature_is_rejected(self):
        """Changing a file hash but keeping the old signature must not verify."""
        _dir, report = _capture({"app.py": "x = 1\n"})
        attestation = attest.attest(report, KEY, KEY_ID)
        mutated = copy.deepcopy(attestation)
        mutated["report"]["inventory"]["files"][0]["sha256"] = "0" * 64
        self.assertFalse(attest.verify(mutated, TRUSTED).valid)

    def test_an_unchanged_tree_is_not_flagged(self):
        directory, baseline_report = _capture({"app.py": "stable = 1\n"})
        attestation = attest.attest(baseline_report, KEY, KEY_ID)
        again = snapshot41.capture(directory).report()
        result = attest.compare(again, attestation, TRUSTED)
        self.assertTrue(result["comparable"])
        self.assertFalse(result["tampered"])


class Freshness(unittest.TestCase):
    def setUp(self):
        _dir, self.report = _capture({"app.py": "x = 1\n"})

    def test_an_expired_attestation_reads_as_stale_not_trustworthy(self):
        past = _datetime.datetime(2020, 1, 1, tzinfo=_datetime.timezone.utc)
        attestation = attest.attest(
            self.report, KEY, KEY_ID,
            generated_at=past.isoformat(),
            expires_at=(past + _datetime.timedelta(days=1)).isoformat())
        verification = attest.verify(attestation, TRUSTED)
        self.assertTrue(verification.valid)          # signature is still good
        self.assertEqual("stale", verification.state)
        self.assertFalse(verification.trustworthy)   # but not currently usable

    def test_a_future_dated_attestation_is_flagged(self):
        future = _datetime.datetime(2999, 1, 1, tzinfo=_datetime.timezone.utc)
        attestation = attest.attest(self.report, KEY, KEY_ID,
                                    generated_at=future.isoformat())
        verification = attest.verify(attestation, TRUSTED)
        self.assertEqual("future-dated", verification.state)
        self.assertFalse(verification.trustworthy)

    def test_expiry_before_generation_is_refused_at_signing(self):
        now = _datetime.datetime(2026, 6, 1, tzinfo=_datetime.timezone.utc)
        with self.assertRaises(attest.AttestationError):
            attest.attest(self.report, KEY, KEY_ID,
                          generated_at=now.isoformat(),
                          expires_at=(now - _datetime.timedelta(days=1)).isoformat())


class CompareRefusesUntrustedBaseline(unittest.TestCase):
    def test_a_diff_against_an_unverified_baseline_is_refused(self):
        """Reporting drift from a baseline the attacker could supply is useless."""
        directory, report = _capture({"app.py": "x = 1\n"})
        forged = attest.attest(report, os.urandom(48), KEY_ID)
        current = snapshot41.capture(directory).report()
        result = attest.compare(current, forged, TRUSTED)
        self.assertFalse(result["baseline_trusted"])
        self.assertFalse(result["comparable"])
        self.assertNotIn("tampered", result)


class FailClosed(unittest.TestCase):
    def test_adversarial_input_never_raises_out_of_verify(self):
        for hostile in (None, 42, "string", [], {}, {"schema": attest.SCHEMA},
                        {"schema": attest.SCHEMA, "version": attest.VERSION,
                         "signature": {"digest": "x"}}):
            with self.subTest(value=repr(hostile)[:40]):
                verification = attest.verify(hostile, TRUSTED)
                self.assertFalse(verification.valid)
                self.assertEqual("invalid", verification.state)


if __name__ == "__main__":
    unittest.main()
