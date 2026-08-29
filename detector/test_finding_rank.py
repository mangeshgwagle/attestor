#!/usr/bin/env python3
"""Tests for finding_rank.py -- deterministic review ordering. Offline."""
import unittest

import finding_rank as fr


def finding(**values):
    row = {"fingerprint": "f" * 64, "path": "app.py", "line": 1,
           "rule": "py-sql-injection", "severity": "HIGH",
           "evidence_state": "inferred"}
    row.update(values)
    return row


class ScoringTests(unittest.TestCase):
    def test_scores_are_integers_on_every_platform(self):
        report = fr.rank([finding(exploitability_score=48),
                          finding(severity="LOW", rule="py-eq-none")])
        for row in report["rows"]:
            self.assertIsInstance(row["score"], int)
            self.assertIsInstance(row["prior_score"], int)
            self.assertTrue(0 <= row["score"] <= fr.SCALE)

    def test_higher_severity_and_bound_evidence_outrank(self):
        strong = finding(severity="CRITICAL", evidence_state="bound",
                         fingerprint="a" * 64)
        weak = finding(severity="LOW", evidence_state="inferred",
                       fingerprint="b" * 64)
        report = fr.rank([weak, strong])
        ranks = {row["fingerprint"]: row["review_rank"] for row in report["rows"]}
        self.assertLess(ranks["a" * 64], ranks["b" * 64])

    def test_contested_ranks_below_supported(self):
        supported = finding(adjudication_classification="supported",
                            fingerprint="a" * 64)
        contested = finding(adjudication_classification="contested",
                            fingerprint="b" * 64)
        report = fr.rank([contested, supported])
        ranks = {row["fingerprint"]: row["review_rank"] for row in report["rows"]}
        self.assertLess(ranks["a" * 64], ranks["b" * 64])

    def test_input_order_is_preserved_and_nothing_is_dropped(self):
        items = [finding(fingerprint=str(index).zfill(64)) for index in range(5)]
        report = fr.rank(items)
        self.assertEqual([row["position"] for row in report["rows"]],
                         list(range(5)))
        self.assertEqual(len(report["rows"]), 5)
        self.assertEqual(sorted(report["order"]), list(range(5)))

    def test_ranking_is_stable_for_equal_scores(self):
        items = [finding(fingerprint=str(index).zfill(64)) for index in range(6)]
        first = fr.rank(items)
        second = fr.rank(items)
        self.assertEqual(first["order"], second["order"])
        self.assertEqual(first["descriptor_sha256"], second["descriptor_sha256"])


class RegimeTests(unittest.TestCase):
    def test_prior_regime_reports_no_probability(self):
        report = fr.rank([finding()])
        self.assertEqual(report["regime"], fr.PRIOR)
        self.assertFalse(report["probability_available"])
        self.assertEqual(report["rows"][0]["regime"], fr.PRIOR)

    def test_calibrated_bin_replaces_the_prior_score(self):
        calibrated = finding(confidence_calibration={
            "state": "calibrated", "calibrated_probability": 0.25})
        report = fr.rank([calibrated])
        self.assertEqual(report["rows"][0]["regime"], fr.CALIBRATED)
        self.assertEqual(report["rows"][0]["score"], 2500)
        self.assertTrue(report["probability_available"])
        self.assertIn("calibration:empirical-bin", report["rows"][0]["reasons"])

    def test_abstaining_calibration_falls_back_to_the_prior(self):
        for state in ("uncalibrated", "insufficient-evidence",
                      "invalid-detector-score"):
            with self.subTest(state=state):
                row = finding(confidence_calibration={
                    "state": state, "calibrated_probability": None})
                report = fr.rank([row])
                self.assertEqual(report["rows"][0]["regime"], fr.PRIOR)
                self.assertFalse(report["probability_available"])

    def test_out_of_range_probability_is_refused(self):
        row = finding(confidence_calibration={
            "state": "calibrated", "calibrated_probability": 1.4})
        self.assertEqual(fr.rank([row])["rows"][0]["regime"], fr.PRIOR)

    def test_mixed_regime_is_reported_as_mixed(self):
        report = fr.rank([
            finding(fingerprint="a" * 64),
            finding(fingerprint="b" * 64, confidence_calibration={
                "state": "calibrated", "calibrated_probability": 0.5})])
        self.assertEqual(report["regime"], "mixed")


class BoundaryTests(unittest.TestCase):
    def test_unknown_severity_does_not_crash_and_is_recorded(self):
        report = fr.rank([finding(severity="SEVERE")])
        self.assertIn("unknown-severity", report["rows"][0]["reasons"])

    def test_hostile_field_types_are_rejected_or_bounded(self):
        report = fr.rank([{"rule": None, "severity": 7, "line": "x",
                           "exploitability_score": "high",
                           "fingerprint": ["not", "a", "string"]}])
        row = report["rows"][0]
        self.assertEqual(row["line"], 0)
        self.assertEqual(row["fingerprint"], "")
        self.assertIsInstance(row["score"], int)

    def test_float_exploitability_score_is_not_trusted(self):
        # A float would cross the platform-dependent arithmetic boundary.
        exact = fr.rank([finding(exploitability_score=50)])["rows"][0]["score"]
        loose = fr.rank([finding(exploitability_score=50.0)])["rows"][0]["score"]
        self.assertNotEqual(exact, loose)

    def test_boolean_is_not_accepted_as_a_score(self):
        report = fr.rank([finding(exploitability_score=True)])
        self.assertNotIn("exploitability-score", report["rows"][0]["reasons"])

    def test_non_mapping_finding_is_refused(self):
        with self.assertRaises(fr.FindingRankError):
            fr.rank(["not a finding"])

    def test_finding_count_boundary_fails_closed(self):
        with self.assertRaises(fr.FindingRankError):
            fr.rank([finding()] * (fr.MAX_FINDINGS + 1))

    def test_empty_input_is_valid(self):
        report = fr.rank([])
        self.assertEqual(report["rows"], [])
        self.assertTrue(fr.verify_descriptor(report)[0])


class VerificationTests(unittest.TestCase):
    def test_descriptor_verifies_and_detects_tampering(self):
        report = fr.rank([finding(fingerprint="a" * 64),
                          finding(fingerprint="b" * 64, severity="LOW")])
        self.assertTrue(fr.verify_descriptor(report)[0])

        reordered = dict(report)
        reordered["order"] = list(reversed(report["order"]))
        ok, errors = fr.verify_descriptor(reordered)
        self.assertFalse(ok)
        self.assertTrue(any("digest" in error or "sorted" in error
                            for error in errors))

    def test_rewritten_score_fails_the_digest(self):
        report = fr.rank([finding()])
        report["rows"][0]["score"] = fr.SCALE
        self.assertFalse(fr.verify_descriptor(report)[0])

    def test_policy_identity_is_stable_and_bound(self):
        self.assertEqual(fr.POLICY_SHA256, fr.rank([])["policy_sha256"])
        self.assertEqual(len(fr.POLICY_SHA256), 64)

    def test_limitations_are_always_reported(self):
        report = fr.rank([finding()])
        self.assertTrue(report["limitations"])
        self.assertTrue(any("not evidence that a finding is safe" in line
                            for line in report["limitations"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
