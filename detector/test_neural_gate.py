#!/usr/bin/env python3
"""Tests for neural_gate.py -- integer-deterministic inference. Offline."""
import copy
import json
import subprocess
import sys
import unittest

import neural_gate as gate

DEFECTIVE = ("def go(url, token):\n"
             "    return requests.get(url, verify=False, timeout=5)\n")
CLEAN = ("def go(url, token):\n"
         "    return requests.get(url, verify=True, timeout=5)\n")


class DeterminismTests(unittest.TestCase):
    """The whole point of the integer path: same answer everywhere, always."""

    def test_features_contain_no_floats(self):
        vector = gate.features(DEFECTIVE)
        self.assertEqual(len(vector), gate.FEATURE_DIM)
        for value in vector:
            self.assertIsInstance(value, int)
            self.assertNotIsInstance(value, bool)

    def test_inference_is_integer_end_to_end(self):
        result = gate.infer(DEFECTIVE, gate.default_model())
        self.assertIsInstance(result["score"], int)
        self.assertIsInstance(result["logit"], int)
        self.assertTrue(0 <= result["score"] <= gate.SCORE_SCALE)
        self.assertEqual(result["arithmetic"], "integer-only")

    def test_repeated_inference_is_identical(self):
        model = gate.default_model()
        first = gate.infer(DEFECTIVE, model)
        for _ in range(5):
            self.assertEqual(gate.infer(DEFECTIVE, model), first)

    def test_token_hashing_is_stable_across_processes(self):
        # str.__hash__ is randomised per process; FNV-1a must not be.
        script = ("import sys;sys.path.insert(0,sys.argv[1]);"
                  "import neural_gate as g;"
                  "print(g._fnv1a('verify'), sum(g.features(sys.argv[2])))")
        seen = set()
        for _ in range(3):
            done = subprocess.run(
                [sys.executable, "-B", "-c", script,
                 str(__import__("pathlib").Path(gate.__file__).parent),
                 DEFECTIVE],
                capture_output=True, text=True, timeout=60, check=True)
            seen.add(done.stdout.strip())
        self.assertEqual(len(seen), 1, "features differ between processes")

    def test_score_is_monotone_in_the_logit(self):
        span = gate.default_model()["logit_span"]
        self.assertEqual(gate._squash(-2 * span, span), 0)
        self.assertEqual(gate._squash(2 * span, span), gate.SCORE_SCALE)
        rising = [gate._squash(step * span // 8, span) for step in range(-8, 9)]
        self.assertEqual(rising, sorted(rising))

    def test_the_score_curve_is_calibrated_not_saturated(self):
        # A hardcoded span pinned 87% of real inputs at the maximum, which
        # destroys the ordering the score exists to provide.
        model = gate.default_model()
        span = model["logit_span"]
        scores = [gate._squash(logit, span)
                  for logit in range(-span, span + 1, max(1, span // 40))]
        saturated = sum(1 for value in scores
                        if value in (0, gate.SCORE_SCALE))
        self.assertLess(saturated, len(scores) // 4)
        self.assertGreater(len(set(scores)), 20)


class ModelIntegrityTests(unittest.TestCase):
    def test_shipped_model_loads_and_verifies(self):
        model = gate.default_model()
        self.assertEqual(model["schema"], gate.SCHEMA)
        self.assertEqual(len(model["model_sha256"]), 64)
        # The artifact declares its own shape; the module constants are only
        # defaults for an artifact that omits them.
        self.assertEqual(len(model["hidden_weights"]), model["hidden"])
        self.assertEqual(len(model["hidden_weights"][0]), model["feature_dim"])

    def test_a_tampered_weight_fails_its_digest(self):
        model = copy.deepcopy(gate.default_model())
        model["hidden_weights"][0][0] += 1
        with self.assertRaises(gate.NeuralGateError):
            gate.load_model(model)

    def test_wrong_shapes_are_refused(self):
        good = gate.default_model()
        for mutate in (
                lambda m: m.__setitem__("hidden_weights", m["hidden_weights"][:-1]),
                lambda m: m.__setitem__("hidden_bias", [0] * (gate.HIDDEN + 1)),
                lambda m: m.__setitem__("output_bias", 1.5),
                lambda m: m.__setitem__("schema", "something-else")):
            broken = copy.deepcopy(good)
            broken.pop("model_sha256", None)
            mutate(broken)
            with self.subTest(mutation=str(mutate)):
                with self.assertRaises(gate.NeuralGateError):
                    gate.load_model(broken)

    def test_float_weights_are_refused(self):
        broken = copy.deepcopy(gate.default_model())
        broken.pop("model_sha256", None)
        broken["hidden_weights"][0][0] = 0.5
        with self.assertRaises(gate.NeuralGateError):
            gate.load_model(broken)


def synthetic(dim, hidden, span=1_000):
    """A shape-valid model of any size, for exercising the width machinery."""
    return {
        "schema": gate.SCHEMA,
        "version": gate.VERSION,
        "feature_dim": dim,
        "hidden": hidden,
        "logit_span": span,
        "hidden_weights": [[(row + column) % 7 - 3 for column in range(dim)]
                           for row in range(hidden)],
        "hidden_bias": [1] * hidden,
        "output_weights": [2] * hidden,
        "output_bias": 3,
    }


class ArchitectureTests(unittest.TestCase):
    """The width lives in the artifact, so a bigger model needs no code change.

    It was a module constant until the gate was retrained on real ground truth
    and 2,593 parameters stopped being the interesting size.  The ceilings are
    a measured latency budget, not a guess: pure-Python inference is
    feature_dim * hidden multiply-accumulates per fragment.
    """

    def test_a_wider_model_loads_and_infers(self):
        model = gate.load_model(synthetic(1024, 64))
        result = gate.infer(DEFECTIVE, model)
        self.assertIsInstance(result["logit"], int)
        self.assertTrue(0 <= result["score"] <= gate.SCORE_SCALE)

    def test_features_honour_the_requested_width(self):
        for dim in (16, 160, 512, 1024):
            with self.subTest(dim=dim):
                self.assertEqual(len(gate.features(DEFECTIVE, dim)), dim)

    def test_a_model_without_a_declared_shape_keeps_the_old_default(self):
        # The originally shipped artifact predates these keys and must still load.
        legacy = synthetic(gate.FEATURE_DIM, gate.HIDDEN)
        legacy.pop("feature_dim")
        legacy.pop("hidden")
        self.assertTrue(gate.load_model(legacy))

    def test_shapes_outside_the_ceiling_are_refused(self):
        # The declared shape is checked before the weights are walked, so
        # these need no million-element rows to reach the failure.
        for dim, hidden in ((gate.MAX_FEATURE_DIM + 1, 8), (16, 0), (0, 8),
                            (16, gate.MAX_HIDDEN + 1), (1.5, 8), (16, True)):
            with self.subTest(dim=dim, hidden=hidden):
                broken = synthetic(8, 8)
                broken["feature_dim"], broken["hidden"] = dim, hidden
                with self.assertRaises(gate.NeuralGateError):
                    gate.load_model(broken)

    def test_a_model_over_the_inference_budget_is_refused(self):
        # Shape-valid and inside both ceilings, but too slow to run: refused
        # at load rather than discovered halfway through a scan.
        oversized = synthetic(8, 8)
        oversized["feature_dim"] = gate.MAX_FEATURE_DIM
        oversized["hidden"] = gate.MAX_HIDDEN
        self.assertGreater(gate.MAX_FEATURE_DIM * gate.MAX_HIDDEN,
                           gate.MAX_PARAMETERS)
        with self.assertRaises(gate.NeuralGateError):
            gate.load_model(oversized)

    def test_declared_width_must_match_the_actual_weights(self):
        lying = synthetic(512, 32)
        lying["feature_dim"] = 256          # rows are still 512 wide
        with self.assertRaises(gate.NeuralGateError):
            gate.load_model(lying)

    def test_features_refuse_an_out_of_range_width(self):
        for dim in (0, -1, gate.MAX_FEATURE_DIM + 1, 2.0, True):
            with self.subTest(dim=dim):
                with self.assertRaises(gate.NeuralGateError):
                    gate.features(DEFECTIVE, dim)

    def test_the_card_reports_the_artifact_shape_not_the_default(self):
        card = gate.model_card()
        resolved = gate.default_model()
        dim = resolved.get("feature_dim", gate.FEATURE_DIM)
        hidden = resolved.get("hidden", gate.HIDDEN)
        self.assertIn("%d-%d-1" % (dim, hidden), card["architecture"])
        self.assertEqual(card["parameters"], dim * hidden + 2 * hidden + 1)


class BoundaryTests(unittest.TestCase):
    """MODEL_INTEGRATION_4.1.4.md: evidence, never a verdict."""

    def test_evidence_is_inferred_and_supports_nothing(self):
        item = gate.evidence(DEFECTIVE, gate.default_model(),
                             path="app.py", line=2)
        self.assertEqual(item["evidence_state"], gate.INFERRED)
        self.assertIs(item["supports_finding"], False)
        self.assertEqual(item["source_engine"], "neural-gate/1.0")
        self.assertEqual(item["path"], "app.py")
        self.assertEqual(item["line"], 2)

    def test_no_output_claims_to_be_a_finding_or_a_probability(self):
        result = gate.infer(DEFECTIVE, gate.default_model())
        self.assertNotIn("rule", result)
        self.assertNotIn("severity", result)
        self.assertNotIn("probability", result)
        self.assertTrue(any("not a probability" in line
                            for line in result["limitations"]))
        self.assertTrue(any("not evidence that the code is safe" in line
                            for line in result["limitations"]))

    def test_model_card_states_it_is_worse_than_the_rules(self):
        card = gate.model_card()
        self.assertTrue(any("100%" in line for line in card["known_weaknesses"]))
        self.assertIn("creating, promoting or suppressing a finding",
                      card["not_for"])
        model = gate.default_model()
        dim, width = model["feature_dim"], model["hidden"]
        self.assertEqual(card["parameters"], dim * width + 2 * width + 1)
        self.assertIn("%d-%d-1" % (dim, width), card["architecture"])

    def test_hostile_input_is_bounded_not_crashing(self):
        model = gate.default_model()
        for source in ("", "\x00\x01\x02", "x" * 300_000, "\n" * 5_000):
            with self.subTest(source=source[:12]):
                result = gate.infer(source, model)
                self.assertTrue(0 <= result["score"] <= gate.SCORE_SCALE)

    def test_non_text_source_is_refused(self):
        for bad in (None, 42, b"bytes", ["lines"]):
            with self.subTest(source=bad):
                with self.assertRaises(gate.NeuralGateError):
                    gate.features(bad)


class SignalTests(unittest.TestCase):
    def test_distinct_inputs_receive_distinct_unsaturated_scores(self):
        # Deliberately not asserting that the risky snippet scores higher: the
        # model is ~65% accurate and gets plenty of individual cases backwards,
        # including this one. Pretending otherwise in a test would be a lie
        # about what was built.
        model = gate.default_model()
        risky = gate.infer(DEFECTIVE, model)
        safe = gate.infer(CLEAN, model)
        self.assertNotEqual(risky["logit"], safe["logit"])
        self.assertNotEqual(risky["score"], safe["score"])
        for result in (risky, safe):
            self.assertTrue(0 <= result["score"] <= gate.SCORE_SCALE)
        # The span is the 95th percentile of training logits, so roughly one
        # input in twenty legitimately pins to an endpoint.
        self.assertGreater(gate.default_model()["logit_span"], 0)

    def test_batch_matches_individual_inference(self):
        model = gate.default_model()
        both = gate.batch([DEFECTIVE, CLEAN], model)
        self.assertEqual(both[0], gate.infer(DEFECTIVE, model))
        self.assertEqual(both[1], gate.infer(CLEAN, model))

    def test_reported_accuracy_is_honest_about_being_weak(self):
        model = gate.default_model()
        accuracy = model.get("held_out_accuracy_percent", 0)
        self.assertGreater(accuracy, 50.0, "no better than a coin flip")
        self.assertLess(accuracy, 100.0, "an implausible claim")


class ResolvedCacheTests(unittest.TestCase):
    """Validation is cached; it must not become a way past validation.

    The first attempt keyed this cache on the digest the artifact claimed,
    which meant a tampered artifact asserting the real digest was handed the
    verified weights and *no error* -- the tampering was silently ignored
    rather than refused.  These pin the behaviour that replaced it.
    """

    SOURCE = "int f(void){ char *p = malloc(8); free(p); return *p; }"

    def clone(self, model):
        import json
        return json.loads(json.dumps(model))

    def test_weights_altered_under_a_valid_digest_are_refused(self):
        forged = self.clone(gate.default_model())
        forged["hidden_bias"] = [0] * forged["hidden"]
        with self.assertRaises(gate.NeuralGateError):
            gate.infer(self.SOURCE, forged)

    def test_a_digest_that_does_not_match_its_weights_is_refused(self):
        forged = self.clone(gate.default_model())
        forged["model_sha256"] = "0" * 64
        with self.assertRaises(gate.NeuralGateError):
            gate.infer(self.SOURCE, forged)

    def test_a_forgery_is_still_refused_after_the_real_model_is_cached(self):
        model = gate.default_model()
        gate.infer(self.SOURCE, model)              # populate the cache
        forged = self.clone(model)
        forged["output_bias"] = model["output_bias"] + 1000
        with self.assertRaises(gate.NeuralGateError):
            gate.infer(self.SOURCE, forged)

    def test_repeated_inference_returns_an_identical_result(self):
        model = gate.default_model()
        self.assertEqual(gate.infer(self.SOURCE, model),
                         gate.infer(self.SOURCE, model))

    def test_an_equal_but_distinct_artifact_scores_the_same(self):
        model = gate.default_model()
        self.assertEqual(gate.infer(self.SOURCE, self.clone(model))["logit"],
                         gate.infer(self.SOURCE, model)["logit"])

    def test_the_cache_stays_bounded(self):
        # A tiny model on purpose: the shipped artifact is 262,401 weights, and
        # validating a fresh copy of it two dozen times is most of a minute for
        # a property that has nothing to do with model size.
        import json
        small = {"schema": gate.SCHEMA, "version": gate.VERSION,
                 "feature_dim": 4, "hidden": 2,
                 "hidden_weights": [[1, 0, 0, 0], [0, 1, 0, 0]],
                 "hidden_bias": [0, 0], "output_weights": [1, 1],
                 "output_bias": 0, "logit_span": 100}
        small["model_sha256"] = gate._sha(small)
        for _ in range(gate._RESOLVED_LIMIT * 3):
            gate.infer(self.SOURCE, json.loads(json.dumps(small)))
        self.assertLessEqual(len(gate._RESOLVED), gate._RESOLVED_LIMIT)


class ProvenanceTests(unittest.TestCase):
    """The card has to describe the corpus the weights actually came from."""

    def test_the_card_names_the_corpus_and_the_grouped_split(self):
        card = gate.model_card()
        self.assertIn("Juliet", card["training_data"])
        self.assertIn("grouped by testcase", card["held_out_split"])

    def test_the_shuffled_label_control_is_reported_and_near_chance(self):
        # Above chance here would mean the pipeline leaks the label, not that
        # the model learned anything.
        control = gate.model_card()["shuffled_label_control_percent"]
        self.assertIsNotNone(control)
        self.assertLess(abs(control - 50.0), 5.0)

    def test_the_synthetic_corpus_caveat_travels_with_every_score(self):
        result = gate.infer("int x = 1;", gate.default_model())
        self.assertTrue(any("synthetic" in line
                            for line in result["limitations"]))
        self.assertEqual(result["evidence_state"], gate.INFERRED)

    def test_the_model_is_wider_than_the_default_and_within_budget(self):
        model = gate.default_model()
        dim, width = model["feature_dim"], model["hidden"]
        self.assertGreater(dim * width, gate.FEATURE_DIM * gate.HIDDEN)
        self.assertLessEqual(dim * width + 2 * width + 1, gate.MAX_PARAMETERS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
