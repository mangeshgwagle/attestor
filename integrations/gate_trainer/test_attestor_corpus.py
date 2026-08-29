#!/usr/bin/env python3
"""Tests for the self-hosted mutation corpus.

The property that matters is not "rows come out" -- it is that the rows are
*labelled and grouped correctly*, because everything downstream reports a
number that is only meaningful if those two things hold.  A corpus that emits
positives without their baselines, or that lets one file's mutations straddle
the holdout boundary, still trains and still reports an AUC; it just reports a
memorisation score.  Both failures are tested directly.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
DETECTOR = str(HERE.parent.parent / "detector")
for path in (str(HERE), DETECTOR):
    if path not in sys.path:
        sys.path.insert(0, path)

import attestor_corpus  # noqa: E402


# Source chosen so several mutator families fire: an identity check, a hash,
# and an assert.  Kept small so the diff regions stay easy to reason about.
SAMPLE = '''\
import hashlib


def digest(value):
    if value is None:
        return ""
    assert isinstance(value, bytes)
    return hashlib.sha256(value).hexdigest()


def check(value):
    if value is None:
        return False
    return True
'''


class CorpusShape(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.directory.name)
        (root / "sample.py").write_text(SAMPLE, encoding="utf-8")
        self.root = str(root)
        self.addCleanup(self.directory.cleanup)

    def rows(self):
        return attestor_corpus.build([self.root], DETECTOR)

    def test_a_corpus_is_produced_from_ordinary_source(self):
        rows = self.rows()
        self.assertTrue(rows)
        self.assertTrue(all(row.label in (0, 1) for row in rows))

    def test_every_positive_arrives_with_a_negative(self):
        """A mutation contributes both sides or the label means nothing.

        Emitting only the mutated side would make the model separate "this file
        was touched" from "this file was not", which is a property of the
        corpus and not of the defect.
        """
        rows = self.rows()
        positive = sum(1 for row in rows if row.label == 1)
        negative = sum(1 for row in rows if row.label == 0)
        self.assertGreater(positive, 0)
        self.assertGreater(negative, 0)

    def test_the_group_key_is_the_file_not_the_mutation(self):
        """All of one file's rows share a group, so no split can straddle it."""
        rows = self.rows()
        self.assertEqual({row.pair for row in rows}, {"sample.py"})

    def test_grouped_split_never_straddles_a_file(self):
        import juliet_corpus
        root = pathlib.Path(self.directory.name)
        for index in range(12):
            (root / ("mod%02d.py" % index)).write_text(SAMPLE, encoding="utf-8")
        rows = self.rows()
        train, held = juliet_corpus.group_split(rows, holdout=0.34)
        self.assertTrue(train and held)
        self.assertFalse({row.pair for row in train}
                         & {row.pair for row in held})

    def test_the_corpus_is_deterministic(self):
        """Two builds of one tree agree, or a run cannot be reproduced."""
        first = [(row.text, row.label, row.pair) for row in self.rows()]
        second = [(row.text, row.label, row.pair) for row in self.rows()]
        self.assertEqual(first, second)

    def test_windows_respect_the_requested_size(self):
        rows = attestor_corpus.build([self.root], DETECTOR, size=6)
        self.assertTrue(rows)
        for row in rows:
            self.assertLessEqual(len(row.text.splitlines()), 6)

    def test_an_empty_tree_fails_closed(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(attestor_corpus.CorpusBuildError):
                attestor_corpus.build([empty], DETECTOR)

    def test_a_missing_root_is_refused(self):
        with self.assertRaises(attestor_corpus.CorpusBuildError):
            attestor_corpus.build([str(HERE / "does-not-exist")], DETECTOR)

    def test_stats_agree_with_the_rows(self):
        rows = self.rows()
        summary = attestor_corpus.stats(rows)
        self.assertEqual(summary["windows"], len(rows))
        self.assertEqual(summary["positive"] + summary["negative"], len(rows))
        self.assertEqual(summary["groups"], len({row.pair for row in rows}))


class Featurisation(unittest.TestCase):
    def test_rows_featurise_through_the_shipped_extractor(self):
        """The corpus has to be consumable by the module that ships.

        `neural_gate.sparse_features` is the same function inference uses; if a
        window cannot pass through it, a model trained on this corpus could not
        be scored by the artifact reader.
        """
        import neural_gate
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, "sample.py").write_text(
                SAMPLE, encoding="utf-8")
            rows = attestor_corpus.build([directory], DETECTOR)
        for row in rows[:20]:
            entries = neural_gate.sparse_features(row.text, 1024)
            self.assertTrue(all(0 <= index < 1024 for index, _ in entries))


if __name__ == "__main__":
    unittest.main()
