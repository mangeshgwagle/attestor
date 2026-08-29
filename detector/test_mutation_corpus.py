#!/usr/bin/env python3
"""Tests for mutation_corpus.py -- labelled mutation outcomes. Offline."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mutation_corpus as mc
import mutation_gauntlet

SOURCE = (
    "import hashlib\n"
    "import requests\n"
    "\n"
    "DEBUG = False\n"
    "\n"
    "def fetch(url, token):\n"
    "    if token is None:\n"
    "        raise ValueError('token required')\n"
    "    digest = hashlib.sha256(token.encode()).hexdigest()\n"
    "    return requests.get(url, verify=True, headers={'x': digest})\n"
)


class CorpusTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "corpus.db"

    def corpus(self):
        store = mc.MutationCorpus(self.path)
        self.addCleanup(store.close)
        return store

    def record(self, store, source=SOURCE, path="candidate.py",
               provenance="unit-test"):
        result = mutation_gauntlet.run(source, path)
        return result, store.record_gauntlet(
            result, source, path=path, provenance=provenance)


class RecordingTests(CorpusTestCase):
    def test_every_mutant_and_the_baseline_are_recorded(self):
        store = self.corpus()
        result, counts = self.record(store)
        self.assertEqual(counts["baseline"], 1)
        self.assertEqual(counts["caught"] + counts["survivor"],
                         len(result["mutants"]))
        self.assertEqual(counts["unresolved"], 0)
        self.assertEqual(store.stats()["examples"],
                         1 + len(result["mutants"]))

    def test_survivor_count_matches_the_gauntlet_gaps(self):
        store = self.corpus()
        result, counts = self.record(store)
        self.assertEqual(counts["survivor"], len(result["gaps"]))

    def test_a_real_survivor_is_recorded_as_the_hard_class(self):
        # A blind detector catches nothing, so every mutant must survive.
        store = self.corpus()
        with mock.patch.object(mutation_gauntlet.harvest, "scan_content",
                               return_value=[]):
            result = mutation_gauntlet.run(SOURCE, "candidate.py")
        counts = store.record_gauntlet(result, SOURCE, path="candidate.py",
                                       provenance="unit-test")
        self.assertGreater(counts["survivor"], 0)
        self.assertEqual(counts["caught"], 0)
        rows = list(store.export(difficulty=mc.SURVIVOR))
        self.assertEqual(len(rows), counts["survivor"])
        for row in rows:
            self.assertFalse(row["detected_by_rules"])
            self.assertEqual(row["label"], mc.DEFECT_INJECTED)
            self.assertTrue(row["expected_rule"])
        self.assertEqual(store.stats()["detection_rate_percent"], 0.0)

    def test_recording_is_idempotent(self):
        store = self.corpus()
        _, first = self.record(store)
        identity = store.corpus_sha256()
        _, second = self.record(store)
        self.assertEqual(second["baseline"], 0)
        self.assertEqual(second["caught"], 0)
        self.assertEqual(second["survivor"], 0)
        self.assertGreater(second["duplicate"], 0)
        self.assertEqual(store.corpus_sha256(), identity)

    def test_baseline_is_labelled_unmutated_not_clean(self):
        store = self.corpus()
        self.record(store)
        rows = list(store.export(difficulty=mc.BASELINE))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], mc.UNMUTATED)
        self.assertNotIn("clean", json.dumps(rows[0]).lower())

    def test_recorded_mutant_content_actually_contains_the_defect(self):
        store = self.corpus()
        self.record(store)
        bodies = {row["mutator_id"]: row["content"]
                  for row in store.export()
                  if row["difficulty"] != mc.BASELINE}
        self.assertIn("verify=False", bodies["tls-verification-disabled"])
        self.assertIn("hashlib.md5", bodies["weak-hash-md5"])

    def test_mutant_rows_point_back_at_their_parent(self):
        store = self.corpus()
        self.record(store)
        rows = list(store.export())
        baseline = [r for r in rows if r["difficulty"] == mc.BASELINE][0]
        mutants = [r for r in rows if r["difficulty"] != mc.BASELINE]
        self.assertTrue(mutants)
        for row in mutants:
            self.assertEqual(row["parent_sha256"], baseline["content_sha256"])


class ProvenanceTests(CorpusTestCase):
    def test_empty_provenance_is_refused(self):
        store = self.corpus()
        result = mutation_gauntlet.run(SOURCE, "candidate.py")
        with self.assertRaises(mc.MutationCorpusError):
            store.record_gauntlet(result, SOURCE, provenance="")

    def test_provenance_survives_into_the_export(self):
        store = self.corpus()
        self.record(store, provenance="github:example/repo@abc123")
        for row in store.export():
            self.assertEqual(row["provenance"], "github:example/repo@abc123")

    def test_stats_carry_the_provenance_notice_and_limitations(self):
        store = self.corpus()
        self.record(store)
        stats = store.stats()
        self.assertIn("Redistribution", stats["provenance_notice"])
        self.assertTrue(any("not labelled clean" in line
                            for line in stats["limitations"]))
        self.assertTrue(any("learns the mutators" in line
                            for line in stats["limitations"]))


class ExportTests(CorpusTestCase):
    def test_survivors_are_exported_first(self):
        store = self.corpus()
        self.record(store)
        order = [row["difficulty"] for row in store.export()]
        if mc.SURVIVOR in order and mc.CAUGHT in order:
            self.assertLess(order.index(mc.SURVIVOR), order.index(mc.CAUGHT))
        self.assertEqual(order[-1], mc.BASELINE)

    def test_difficulty_filter_restricts_the_export(self):
        store = self.corpus()
        _, counts = self.record(store)
        rows = list(store.export(difficulty=mc.CAUGHT))
        self.assertEqual(len(rows), counts["caught"])
        for row in rows:
            self.assertTrue(row["detected_by_rules"])

    def test_content_can_be_withheld(self):
        store = self.corpus()
        self.record(store)
        for row in store.export(include_content=False):
            self.assertNotIn("content", row)
            self.assertEqual(len(row["content_sha256"]), 64)

    def test_unknown_difficulty_filter_is_refused(self):
        store = self.corpus()
        with self.assertRaises(mc.MutationCorpusError):
            list(store.export(difficulty="easy"))

    def test_export_rows_are_json_serialisable(self):
        store = self.corpus()
        self.record(store)
        for row in store.export():
            json.loads(json.dumps(row))


class IdentityTests(CorpusTestCase):
    def test_corpus_identity_is_order_independent(self):
        other = SOURCE.replace("def fetch", "def fetch_two")
        first = mc.MutationCorpus(Path(self.temporary.name) / "a.db")
        self.addCleanup(first.close)
        second = mc.MutationCorpus(Path(self.temporary.name) / "b.db")
        self.addCleanup(second.close)
        for source in (SOURCE, other):
            first.record_gauntlet(
                mutation_gauntlet.run(source, "c.py"), source,
                path="c.py", provenance="unit-test")
        for source in (other, SOURCE):
            second.record_gauntlet(
                mutation_gauntlet.run(source, "c.py"), source,
                path="c.py", provenance="unit-test")
        self.assertEqual(first.corpus_sha256(), second.corpus_sha256())

    def test_identity_changes_when_an_example_is_added(self):
        store = self.corpus()
        self.record(store)
        before = store.corpus_sha256()
        other = SOURCE.replace("DEBUG = False", "DEBUG = False  # note")
        store.record_gauntlet(mutation_gauntlet.run(other, "c.py"), other,
                              path="c.py", provenance="unit-test")
        self.assertNotEqual(store.corpus_sha256(), before)

    def test_detection_rate_ignores_baseline_rows(self):
        store = self.corpus()
        _, counts = self.record(store)
        mutants = counts["caught"] + counts["survivor"]
        expected = round(100.0 * counts["caught"] / mutants, 1)
        self.assertEqual(store.stats()["detection_rate_percent"], expected)


class BoundaryTests(CorpusTestCase):
    def test_oversized_example_is_refused(self):
        store = self.corpus()
        huge = "x = 1\n" * (mc.MAX_EXAMPLE_BYTES // 3)
        with self.assertRaises(mc.MutationCorpusError):
            store.record_gauntlet({"mutants": [], "path": "c.py"}, huge,
                                  provenance="unit-test")

    def test_malformed_gauntlet_result_is_refused(self):
        store = self.corpus()
        for bad in ("not a mapping", {"path": "c.py"}, {"mutants": "no"}):
            with self.subTest(bad=bad):
                with self.assertRaises(mc.MutationCorpusError):
                    store.record_gauntlet(bad, SOURCE, provenance="unit-test")

    def test_unreproducible_mutator_is_counted_not_recorded(self):
        store = self.corpus()
        result = {"path": "c.py", "mutants": [
            {"id": "mutator-from-a-future-build", "expected_rule": "x",
             "caught": False}]}
        counts = store.record_gauntlet(result, SOURCE, path="c.py",
                                       provenance="unit-test")
        self.assertEqual(counts["unresolved"], 1)
        self.assertEqual(counts["survivor"], 0)
        self.assertEqual(
            [row["difficulty"] for row in store.export()], [mc.BASELINE])

    def test_closed_corpus_refuses_further_use(self):
        store = mc.MutationCorpus(self.path)
        store.close()
        with self.assertRaises(mc.MutationCorpusError):
            store.stats()

    def test_empty_corpus_reports_no_detection_rate(self):
        store = self.corpus()
        stats = store.stats()
        self.assertEqual(stats["examples"], 0)
        self.assertIsNone(stats["detection_rate_percent"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
