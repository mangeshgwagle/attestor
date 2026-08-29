#!/usr/bin/env python3
"""Prove the trainer's arithmetic without needing 153 MB of NIST material.

The corpus is what makes a *useful* gate; it is not what makes the trainer
correct. What can go wrong here and never announce itself is the quantisation:
a float model that trains beautifully and an integer artifact that scores
differently is still a working model, just not the one that was measured. So
these tests build a small synthetic corpus with a defect a linear model can
find, train on it, and then re-score the held-out half through
`neural_gate.infer` -- the same code path that ships.
"""
from __future__ import annotations

import pathlib
import random
import sys
import unittest

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent
                       / "detector"))

import neural_gate
import train_gate

DIM = 256
HIDDEN = 16


def synthetic(count: int, seed: int = 7):
    """Windows where `strcpy` marks the flaw and `strncpy` marks the fix.

    Noise tokens are shared between the two sides so the separating signal is
    the call and not the surrounding text -- otherwise the test would pass on
    a model that had learned nothing transferable.
    """
    rng = random.Random(seed)
    nouns = ["buf", "dest", "tmp", "line", "record", "field"]
    noise = ["int i;", "size_t n = 0;", "if (n > 0) { n--; }",
             "for (i = 0; i < n; i++) { }", "char *p = NULL;"]
    rows = []
    for index in range(count):
        name = rng.choice(nouns)
        filler = "\n".join(rng.sample(noise, 3))
        if index % 2:
            text = "char %s[64];\n%s\nstrcpy(%s, src);\n" % (name, filler, name)
            rows.append((text, 1))
        else:
            text = ("char %s[64];\n%s\nstrncpy(%s, src, 63);\n"
                    % (name, filler, name))
            rows.append((text, 0))
    rng.shuffle(rows)
    return rows


def featurise(rows, dim=DIM):
    features = np.zeros((len(rows), dim), dtype=np.float32)
    labels = np.zeros(len(rows), dtype=np.float32)
    scale = float(neural_gate.FEATURE_SCALE)
    for row_index, (text, label) in enumerate(rows):
        for index, value in neural_gate.sparse_features(text, dim):
            features[row_index, index] = value / scale
        labels[row_index] = label
    # The trainer takes CSR on the real path; tests build dense and convert,
    # so they exercise the same `batch()` the corpus run does.
    return train_gate.Sparse.from_dense(features), labels


class Auc(unittest.TestCase):
    def test_perfect_ranking(self):
        labels = np.array([0, 0, 1, 1], dtype=np.float32)
        self.assertEqual(train_gate.auc(labels, np.array([1., 2., 3., 4.])), 1.0)

    def test_inverted_ranking(self):
        labels = np.array([0, 0, 1, 1], dtype=np.float32)
        self.assertEqual(train_gate.auc(labels, np.array([4., 3., 2., 1.])), 0.0)

    def test_a_constant_score_is_chance_not_perfect(self):
        # Without averaging tied ranks this returns 1.0, which would make a
        # model that emits one number look flawless.
        labels = np.array([0, 1, 0, 1], dtype=np.float32)
        self.assertEqual(train_gate.auc(labels, np.array([5., 5., 5., 5.])), 0.5)

    def test_single_class_is_chance(self):
        labels = np.array([1, 1, 1], dtype=np.float32)
        self.assertEqual(train_gate.auc(labels, np.array([1., 2., 3.])), 0.5)


class Training(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = synthetic(600)
        cls.train_rows, cls.hold_rows = rows[:450], rows[450:]
        cls.train_x, cls.train_y = featurise(cls.train_rows)
        cls.hold_x, cls.hold_y = featurise(cls.hold_rows)
        cls.model = train_gate.train_float(
            cls.train_x, cls.train_y, HIDDEN, epochs=25, batch=64,
            learning_rate=5e-3, seed=1, quiet=True)
        cls.hold_logits = train_gate.float_logits(cls.model, cls.hold_x)

    def test_it_learns_the_separable_defect(self):
        self.assertGreater(train_gate.auc(self.hold_y, self.hold_logits), 0.95)

    def test_shuffled_labels_do_not_learn(self):
        rng = np.random.default_rng(3)
        control = train_gate.train_float(
            self.train_x, rng.permutation(self.train_y), HIDDEN, epochs=25,
            batch=64, learning_rate=5e-3, seed=1, quiet=True)
        logits = train_gate.float_logits(control, self.hold_x)
        accuracy = float(np.mean((logits > 0) == (self.hold_y == 1)) * 100)
        self.assertTrue(35 < accuracy < 65,
                        "control reached %.1f%%; the features are carrying "
                        "something other than the defect" % accuracy)


class Quantisation(unittest.TestCase):
    """The part that fails silently, so it is checked loudly."""

    @classmethod
    def setUpClass(cls):
        rows = synthetic(600, seed=11)
        cls.hold_rows = rows[450:]
        train_x, train_y = featurise(rows[:450])
        cls.hold_x, cls.hold_y = featurise(cls.hold_rows)
        cls.model = train_gate.train_float(
            train_x, train_y, HIDDEN, epochs=25, batch=64,
            learning_rate=5e-3, seed=2, quiet=True)
        cls.hold_logits = train_gate.float_logits(cls.model, cls.hold_x)
        span = train_gate.calibrate_span(cls.hold_logits,
                                         neural_gate.WEIGHT_SCALE)
        cls.artifact = train_gate.quantise(cls.model, neural_gate, span)

    def test_the_artifact_loads_through_the_shipping_validator(self):
        resolved = neural_gate.load_model(self.artifact)
        self.assertEqual(resolved["feature_dim"], DIM)
        self.assertEqual(resolved["hidden"], HIDDEN)

    def test_integer_auc_tracks_float_auc(self):
        float_auc = train_gate.auc(self.hold_y, self.hold_logits)
        scores = np.array([neural_gate.infer(text, self.artifact)["score"]
                           for text, _ in self.hold_rows], dtype=np.float64)
        integer_auc = train_gate.auc(self.hold_y, scores)
        self.assertLessEqual(
            float_auc - integer_auc, train_gate.MAX_QUANTISATION_AUC_DROP,
            "float %.4f vs integer %.4f -- the shipped model is not the one "
            "that was measured" % (float_auc, integer_auc))

    def test_the_span_does_not_saturate_the_scores(self):
        scores = np.array([neural_gate.infer(text, self.artifact)["score"]
                           for text, _ in self.hold_rows])
        pinned = float(np.mean((scores == 0)
                               | (scores == neural_gate.SCORE_SCALE)))
        # The first hardcoded span in this project pinned 87%, which destroys
        # the ordering the score exists to provide.
        self.assertLess(pinned, 0.5, "%.0f%% of scores are saturated"
                        % (pinned * 100))

    def test_integer_inference_is_reproducible(self):
        text = self.hold_rows[0][0]
        first = neural_gate.infer(text, self.artifact)
        second = neural_gate.infer(text, self.artifact)
        self.assertEqual(first["score"], second["score"])
        self.assertEqual(first["logit"], second["logit"])


class CorpusRefusal(unittest.TestCase):
    def test_missing_archive_is_reported_not_invented(self):
        with self.assertRaises(train_gate.TrainingError) as caught:
            train_gate.load("no-such-file.zip",
                            str(pathlib.Path(__file__).resolve().parent.parent
                                .parent / "detector"), DIM, None)
        self.assertIn("corpus-unavailable", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
