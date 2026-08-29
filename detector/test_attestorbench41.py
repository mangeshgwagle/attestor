from __future__ import annotations

import itertools
import json
import tempfile
import unittest
from pathlib import Path

import attestorbench41


class AttestorBench41Tests(unittest.TestCase):
    def test_small_or_unaudited_corpus_is_reported_not_promoted(self):
        corpus = {"schema": attestorbench41.CORPUS_SCHEMA, "corpus_sha256": "c" * 64,
                  "cases": [{"id": "vuln", "label": True, "expected_rules": ["rule-a"],
                             "source_sha256": "a" * 64},
                            {"id": "clean", "label": False, "expected_rules": [],
                             "source_sha256": "b" * 64}]}
        records = [{"case_id": case["id"], "lane": lane, "sample": 0,
                    "predicted_positive": case["label"], "probability": .9 if case["label"] else .1,
                    "latency_ms": 1, "peak_memory_bytes": 100, "cost_usd": 0,
                    "status": "completed", "finding_rules": case["expected_rules"]}
                   for lane in attestorbench41.LANES for case in corpus["cases"]]
        report = attestorbench41.evaluate(corpus, records)
        self.assertFalse(report["release_gate"]["passed"])
        self.assertFalse(report["overlap_audit"]["performed"])
        self.assertFalse(report["overlap_audit"]["passed"])
        self.assertFalse(report["release_gate"]["checks"]["minimum_1000_held_out_cases"])

    def test_observed_metrics_include_rule_accuracy_timeout_memory_and_repeats(self):
        corpus = {"schema": attestorbench41.CORPUS_SCHEMA, "corpus_sha256": "c" * 64,
                  "cases": [{"id": "v", "label": True, "expected_rules": ["expected"],
                             "source_sha256": "a" * 64},
                            {"id": "n", "label": False, "expected_rules": [],
                             "source_sha256": "b" * 64}]}
        records = [
            {"case_id": "v", "lane": "attestor-only", "sample": 0, "predicted_positive": True,
             "probability": .8, "latency_ms": 5, "peak_memory_bytes": 200, "cost_usd": 0,
             "status": "completed", "finding_rules": ["expected", "extra"]},
            {"case_id": "n", "lane": "attestor-only", "sample": 0, "predicted_positive": False,
             "probability": .2, "latency_ms": 7, "peak_memory_bytes": 300, "cost_usd": 0,
             "status": "timeout", "finding_rules": []},
        ]
        report = attestorbench41.evaluate(corpus, records, reference_hashes=["f" * 64])
        metrics = report["lanes"]["attestor-only"]
        self.assertEqual(metrics["rule_metrics"]["tp"], 1)
        self.assertEqual(metrics["rule_metrics"]["fp"], 1)
        self.assertEqual(metrics["timeout_rate"], .5)
        self.assertEqual(metrics["peak_memory_bytes"]["max"], 300)
        self.assertEqual(metrics["completed_samples"], 1)
        self.assertEqual(metrics["completed_cases"], 1)
        self.assertEqual(metrics["quality_metrics_population"], "completed-records-only")

    def test_repeat_disagreement_is_measured_within_each_case(self):
        corpus = {"schema": attestorbench41.CORPUS_SCHEMA, "corpus_sha256": "c" * 64,
                  "cases": [{"id": "v", "label": True, "expected_rules": [],
                             "source_sha256": "a" * 64}]}
        records = [{"case_id": "v", "lane": "model-only", "sample": sample,
                    "predicted_positive": predicted, "probability": probability,
                    "latency_ms": 1, "peak_memory_bytes": 1, "cost_usd": 0,
                    "status": "completed", "finding_rules": []}
                   for sample, predicted, probability in ((0, True, .9), (1, False, .1))]
        metrics = attestorbench41.evaluate(corpus, records)["lanes"]["model-only"]
        self.assertEqual(metrics["repeated_completed_cases"], 1)
        self.assertEqual(metrics["repeat_disagreement_case_rate"], 1.0)
        self.assertEqual(metrics["within_case_prediction_stddev_mean"], .5)

    def test_record_loader_rejects_non_list_or_silently_truncated_rule_data(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            record = {"case_id": "case", "lane": "attestor-only", "sample": 0,
                      "predicted_positive": True, "probability": .9,
                      "latency_ms": 1, "peak_memory_bytes": 1, "cost_usd": 0,
                      "status": "completed", "finding_rules": "rule-a"}
            manifest = {"schema": attestorbench41.RESULT_SCHEMA, "records": [record]}
            path = root / "results.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(attestorbench41.AttestorBenchError, "finding_rules"):
                attestorbench41.load_records(path)
            record["finding_rules"] = ["r" * 301]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(attestorbench41.AttestorBenchError, "finding_rules"):
                attestorbench41.load_records(path)

    def test_failed_records_cannot_fake_quality_or_lane_completion(self):
        corpus = {"schema": attestorbench41.CORPUS_SCHEMA, "corpus_sha256": "c" * 64,
                  "cases": [{"id": "v", "label": True, "expected_rules": ["expected"],
                             "source_sha256": "a" * 64},
                            {"id": "n", "label": False, "expected_rules": [],
                             "source_sha256": "b" * 64}]}
        records = [{"case_id": case["id"], "lane": lane, "sample": sample,
                    "predicted_positive": case["label"],
                    "probability": .99 if case["label"] else .01,
                    "latency_ms": 1, "peak_memory_bytes": 1, "cost_usd": 0,
                    "status": "failed", "finding_rules": case["expected_rules"]}
                   for lane in attestorbench41.LANES for case in corpus["cases"]
                   for sample in ((0, 1) if lane != "attestor-only" else (0,))]
        report = attestorbench41.evaluate(corpus, records, reference_hashes=["f" * 64])
        for lane in attestorbench41.LANES:
            metrics = report["lanes"][lane]
            self.assertEqual(metrics["completed_samples"], 0)
            self.assertEqual(metrics["tp"], 0)
            self.assertEqual(metrics["tn"], 0)
            self.assertEqual(metrics["minimum_repeats_per_case"], 0)
        self.assertFalse(report["release_gate"]["checks"]["all_lanes_complete"])
        self.assertFalse(report["release_gate"]["checks"]["stochastic_lanes_repeated"])
        self.assertTrue(any(gap["kind"] == "no-completed-result" for gap in report["gaps"]))

    def test_reference_overlap_requires_bounded_hex_sha256_values(self):
        corpus = {"schema": attestorbench41.CORPUS_SCHEMA, "corpus_sha256": "c" * 64,
                  "cases": []}
        with self.assertRaisesRegex(attestorbench41.AttestorBenchError, "hexadecimal"):
            attestorbench41.evaluate(corpus, [], reference_hashes=["z" * 64])
        with self.assertRaisesRegex(attestorbench41.AttestorBenchError, "10,000-entry"):
            attestorbench41.evaluate(corpus, [], reference_hashes=itertools.repeat("a" * 64))

    def test_manifest_loader_requires_real_held_out_sources(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); (root / "case.py").write_text("print('case')\n", encoding="utf-8")
            manifest = {"schema": attestorbench41.CORPUS_SCHEMA, "name": "fixture", "cases": [{
                "id": "case", "split": "train", "source": "case.py", "label": False,
                "expected_rules": []}]}
            path = root / "corpus.json"; path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(attestorbench41.AttestorBenchError):
                attestorbench41.load_corpus(path)
            manifest["cases"][0]["split"] = "held-out"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            loaded = attestorbench41.load_corpus(path)
            self.assertEqual(loaded["cases"][0]["bytes"], (root / "case.py").stat().st_size)


if __name__ == "__main__":
    unittest.main()
