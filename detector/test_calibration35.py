from __future__ import annotations

import copy
import math
import unittest

import calibration35


def observations(count=24, *, correct=True, rule="r", score=0.85):
    return [{"confidence": score, "outcome": correct, "rule": rule,
             "language": "python", "dataset_id": "fixture-v1",
             "label_source": "independent-test", "label_verified": True}
            for _ in range(count)]


class Calibration35Tests(unittest.TestCase):
    def test_profile_is_deterministic_and_verifiable(self):
        one = calibration35.build_profile(observations())
        two = calibration35.build_profile(reversed(observations()))
        self.assertEqual(one, two)
        self.assertTrue(calibration35.verify_profile(one)[0])

    def test_unverified_labels_are_rejected(self):
        rows = observations(5)
        rows.append({"confidence": 0.9, "outcome": True, "dataset_id": "x",
                     "label_source": "self", "label_verified": False})
        profile = calibration35.build_profile(rows, min_samples=5)
        self.assertEqual(profile["corpus"]["accepted"], 5)
        self.assertEqual(profile["corpus"]["rejected"], 1)

    def test_sparse_evidence_does_not_replace_score(self):
        profile = calibration35.build_profile(observations(5), min_samples=10)
        result = calibration35.apply_profile([{"rule": "r", "language": "python",
                                               "confidence": 0.85}], profile)[0]
        self.assertEqual(result["confidence"], 0.85)
        self.assertEqual(result["confidence_calibration"]["state"], "insufficient-evidence")

    def test_empirical_probability_replaces_score_with_sufficient_evidence(self):
        rows = observations(16, correct=True) + observations(4, correct=False)
        profile = calibration35.build_profile(rows, min_samples=20)
        result = calibration35.apply_profile([{"rule": "r", "language": "python",
                                               "confidence": 0.85}], profile)[0]
        self.assertEqual(result["detector_score"], 0.85)
        self.assertEqual(result["confidence"], 0.8)
        self.assertEqual(result["confidence_calibration"]["basis"], "rule-language:r:python")

    def test_profile_tampering_is_rejected(self):
        profile = calibration35.build_profile(observations())
        forged = copy.deepcopy(profile)
        forged["global"]["bins"][8]["empirical_probability"] = 0.123
        self.assertFalse(calibration35.verify_profile(forged)[0])
        self.assertEqual(calibration35.calibrate_score(0.85, forged)["state"], "uncalibrated")

    def test_nan_detector_score_is_invalid(self):
        self.assertEqual(calibration35.calibrate_score(math.nan, None)["state"],
                         "invalid-detector-score")

    def test_empty_profile_is_honest(self):
        profile = calibration35.build_profile([])
        self.assertIsNone(profile["global"]["brier_score"])
        self.assertEqual(calibration35.calibrate_score(0.9, profile)["state"],
                         "insufficient-evidence")


if __name__ == "__main__":
    unittest.main()
