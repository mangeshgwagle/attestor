from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import evidence_store41
import research_engine41
import truth_guard41


class EvidenceStore41Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "project"
        self.root.mkdir()
        self.database = self.base / "history.sqlite3"
        self.source = self.root / "app.py"
        self.source.write_text("x = input()\nprint(x)\n", encoding="utf-8")
        self.report = {"schema": "fixture/4.1", "status": "partial", "root": str(self.root),
                       "coverage": {"complete": False, "gaps": ["runtime not executed"]},
                       "findings": [
                           {"rule": "fixture", "path": "app.py", "line": 2, "severity": "HIGH",
                            "source_evidence": {"snippet_sha256": "a" * 64, "rule_sha256": "b" * 64}},
                           {"rule": "fixture", "path": "app.py", "line": 2, "severity": "HIGH",
                            "source_evidence": {"snippet_sha256": "a" * 64, "rule_sha256": "b" * 64}},
                       ]}

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _profiled(report, *, slug="south-park", digest="a" * 64):
        analyzer = dict(report.get("analyzer", {}))
        analyzer.update({
            "variant_slug": slug,
            "variant_profile_sha256": digest,
            "engines": ["variant-orchestration/4.1.4"],
        })
        analysis_config = dict(report.get("analysis_config", {}))
        analysis_config["variant_414"] = {
            "schema": "attestor-variant-selection/4.1.4",
            "selected_profile": {
                "slug": slug,
                "profile_sha256": digest,
            },
            "selected_profile_sha256": digest,
        }
        return {
            **report,
            "analyzer": analyzer,
            "analysis_config": analysis_config,
        }

    def test_history_is_durable_bounded_and_duplicate_safe(self):
        store = evidence_store41.EvidenceStore(self.database, max_runs=2)
        first = store.store_report(self.report, created_at="2026-01-01T00:00:00Z")
        self.assertEqual(first["findings"], 2)
        reopened = evidence_store41.EvidenceStore(self.database, max_runs=2)
        self.assertEqual(reopened.get_report(first["run_id"])["schema"], "fixture/4.1")
        annotations = reopened.annotations(first["run_id"])
        self.assertEqual(len(annotations), 2)
        self.assertNotEqual(annotations[0]["fingerprint"], annotations[1]["fingerprint"])

    def test_semantic_delta_tolerates_line_movement(self):
        report_a = {**self.report, "findings": [self.report["findings"][0]]}
        moved = dict(self.report["findings"][0]); moved["line"] = 20
        report_b = {**self.report, "findings": [moved]}
        store = evidence_store41.EvidenceStore(self.database)
        first = store.store_report(report_a, created_at="2026-01-01T00:00:00Z")
        second = store.store_report(report_b, created_at="2026-01-02T00:00:00Z")
        delta = store.compare(first["run_id"], second["run_id"])
        self.assertTrue(delta["comparable"])
        self.assertEqual(
            delta["comparison_reason"],
            "legacy-pair-without-profile-identity")
        self.assertEqual(len(delta["persistent"]), 1)
        self.assertEqual(delta["new"], [])
        self.assertEqual(delta["resolved"], [])
        before = sorted(
            row["fingerprint"] for row in store.annotations(first["run_id"]))
        after = sorted(
            row["fingerprint"] for row in store.annotations(second["run_id"]))
        self.assertEqual(
            delta["delta_sha256"],
            evidence_store41._sha(
                [first["run_id"], second["run_id"], before, after]))

    def test_fingerprints_and_triage_are_scoped_to_the_report_root(self):
        other_root = self.base / "unrelated-project"
        other_root.mkdir()
        finding = self.report["findings"][0]
        first_report = {**self.report, "findings": [finding]}
        second_report = {**self.report, "root": str(other_root), "findings": [finding]}
        store = evidence_store41.EvidenceStore(self.database)
        first = store.store_report(first_report, created_at="2026-01-01T00:00:00Z")
        second = store.store_report(second_report, created_at="2026-01-02T00:00:00Z")
        first_fingerprint = store.annotations(first["run_id"])[0]["fingerprint"]
        second_fingerprint = store.annotations(second["run_id"])[0]["fingerprint"]

        self.assertNotEqual(first_fingerprint, second_fingerprint)
        store.set_triage(first_fingerprint, "investigating",
                         owner="first-team", reason="belongs to the first project")
        self.assertEqual(store.annotations(first["run_id"])[0]["state"], "investigating")
        self.assertIsNone(store.annotations(second["run_id"])[0]["state"])
        delta = store.compare(first["run_id"], second["run_id"])
        self.assertTrue(delta["comparable"])
        self.assertEqual(delta["persistent"], [])
        self.assertEqual(delta["resolved"], [first_fingerprint])
        self.assertEqual(delta["new"], [second_fingerprint])

    def test_matching_414_profile_is_persisted_and_comparable(self):
        before = self._profiled({
            **self.report,
            "findings": [self.report["findings"][0]],
        })
        after = self._profiled({**self.report, "findings": []})
        store = evidence_store41.EvidenceStore(self.database)
        first = store.store_report(
            before, created_at="2026-01-01T00:00:00Z")
        second = store.store_report(
            after, created_at="2026-01-02T00:00:00Z")

        self.assertEqual(first["profile_identity_state"], "identified")
        self.assertEqual(first["variant_slug"], "south-park")
        self.assertEqual(first["variant_profile_sha256"], "a" * 64)
        listed = {
            row["run_id"]: row for row in store.list_runs()
        }[first["run_id"]]
        self.assertEqual(listed["profile_identity_state"], "identified")
        self.assertEqual(listed["variant_slug"], "south-park")
        self.assertEqual(listed["variant_profile_sha256"], "a" * 64)

        delta = store.compare(first["run_id"], second["run_id"])
        self.assertTrue(delta["comparable"])
        self.assertEqual(
            delta["comparison_reason"], "matching-profile-identity")
        self.assertEqual(len(delta["resolved"]), 1)
        self.assertEqual(delta["new"], [])

    def test_different_414_profiles_are_explicitly_non_comparable(self):
        finding = self.report["findings"][0]
        before = self._profiled({
            **self.report,
            "findings": [finding],
        })
        store = evidence_store41.EvidenceStore(self.database)
        first = store.store_report(
            before, created_at="2026-01-01T00:00:00Z")
        cases = [
            ("gruppe-sechs", "a" * 64, "variant-slug-mismatch"),
            ("south-park", "b" * 64,
             "variant-profile-sha256-mismatch"),
        ]
        for index, (slug, digest, reason) in enumerate(cases, start=2):
            with self.subTest(reason=reason):
                after = self._profiled(
                    {**self.report, "findings": []},
                    slug=slug, digest=digest)
                second = store.store_report(
                    after,
                    created_at=f"2026-01-0{index}T00:00:00Z")
                delta = store.compare(first["run_id"], second["run_id"])
                self.assertFalse(delta["comparable"])
                self.assertEqual(delta["comparison_reason"], reason)
                self.assertEqual(delta["new"], [])
                self.assertEqual(delta["resolved"], [])
                self.assertEqual(delta["persistent"], [])

    def test_profiled_to_legacy_comparison_cannot_claim_resolution(self):
        before = self._profiled({
            **self.report,
            "findings": [self.report["findings"][0]],
        })
        after = {**self.report, "findings": []}
        store = evidence_store41.EvidenceStore(self.database)
        first = store.store_report(
            before, created_at="2026-01-01T00:00:00Z")
        second = store.store_report(
            after, created_at="2026-01-02T00:00:00Z")

        delta = store.compare(first["run_id"], second["run_id"])
        self.assertFalse(delta["comparable"])
        self.assertEqual(
            delta["comparison_reason"],
            "profile-identity-presence-mismatch")
        self.assertEqual(delta["new"], [])
        self.assertEqual(delta["resolved"], [])
        self.assertEqual(delta["persistent"], [])

    def test_malformed_or_contradictory_414_identity_is_rejected(self):
        partial = {
            **self.report,
            "analyzer": {"variant_slug": "south-park"},
        }
        uppercase_digest = self._profiled(
            self.report, digest="A" * 64)
        contradictory = self._profiled(self.report)
        contradictory["analysis_config"]["variant_414"][
            "selected_profile_sha256"] = "b" * 64
        store = evidence_store41.EvidenceStore(self.database)
        for report in (partial, uppercase_digest, contradictory):
            with self.subTest(report=report):
                with self.assertRaisesRegex(
                        evidence_store41.EvidenceStoreError,
                        "invalid or incomplete"):
                    store.store_report(report)

    def test_old_database_rows_are_backfilled_from_report_identity(self):
        report = self._profiled({
            **self.report,
            "findings": [self.report["findings"][0]],
        }, slug="gruppe-sechs", digest="c" * 64)
        payload = json.dumps(
            report, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")
        report_digest = hashlib.sha256(payload).hexdigest()
        db = sqlite3.connect(str(self.database))
        try:
            db.executescript("""
                CREATE TABLE blobs(
                    digest TEXT PRIMARY KEY,
                    bytes INTEGER NOT NULL,
                    payload BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE runs(
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    report_digest TEXT NOT NULL REFERENCES blobs(digest),
                    semantic_digest TEXT NOT NULL,
                    schema_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    findings INTEGER NOT NULL,
                    root_digest TEXT NOT NULL
                );
            """)
            db.execute(
                "INSERT INTO blobs(digest,bytes,payload,created_at) "
                "VALUES(?,?,?,?)",
                (report_digest, len(payload), payload,
                 "2026-01-01T00:00:00Z"))
            db.execute(
                "INSERT INTO runs(run_id,created_at,report_digest,"
                "semantic_digest,schema_name,status,findings,root_digest) "
                "VALUES(?,?,?,?,?,?,?,?)",
                ("legacy-schema-run", "2026-01-01T00:00:00Z",
                 report_digest, "d" * 64, "fixture/4.1", "partial", 1,
                 "e" * 64))
            db.commit()
        finally:
            db.close()

        store = evidence_store41.EvidenceStore(self.database)
        row = store.list_runs()[0]
        self.assertEqual(row["profile_identity_state"], "identified")
        self.assertEqual(row["variant_slug"], "gruppe-sechs")
        self.assertEqual(row["variant_profile_sha256"], "c" * 64)

    def test_public_report_ceiling_matches_32_mib(self):
        self.assertEqual(
            evidence_store41.MAX_REPORT_BYTES, 32 * 1024 * 1024)

    def test_database_cap_rolls_back_new_run_and_blob(self):
        store = evidence_store41.EvidenceStore(
            self.database, max_database_bytes=1024 * 1024)
        baseline = store.store_report(
            {**self.report, "findings": [self.report["findings"][0]]},
            created_at="2026-01-01T00:00:00Z")
        oversized = {
            **self.report,
            "findings": [],
            "padding": "x" * (2 * 1024 * 1024),
        }

        with self.assertRaisesRegex(
                evidence_store41.EvidenceStoreError, "configured byte boundary"):
            store.store_report(oversized, created_at="2026-01-02T00:00:00Z")

        self.assertEqual([row["run_id"] for row in store.list_runs()],
                         [baseline["run_id"]])
        db = sqlite3.connect(str(self.database))
        try:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM blobs").fetchone()[0], 1)
        finally:
            db.close()

    def test_triage_and_suppression_require_owner_reason_expiry_and_known_evidence(self):
        store = evidence_store41.EvidenceStore(self.database)
        saved = store.store_report({**self.report, "findings": [self.report["findings"][0]]})
        fingerprint = store.annotations(saved["run_id"])[0]["fingerprint"]
        triage = store.set_triage(fingerprint, "investigating", owner="security", reason="verify sink")
        self.assertEqual(triage["state"], "investigating")
        future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        suppression = store.suppress(fingerprint, owner="security", reason="temporary mitigation",
                                     expires_at=future)
        self.assertEqual(suppression["owner"], "security")
        self.assertEqual(len(store.active_suppressions()), 1)
        with self.assertRaises(evidence_store41.EvidenceStoreError):
            store.set_triage("invented", "open", owner="x", reason="y")
        with self.assertRaises(evidence_store41.EvidenceStoreError):
            store.suppress(fingerprint, owner="security", reason="forever",
                           expires_at="2020-01-01T00:00:00Z")

        self.assertEqual(store.clear(), 1)
        self.assertEqual(store.active_suppressions(), [])
        db = sqlite3.connect(str(self.database))
        try:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM triage").fetchone()[0], 0)
        finally:
            db.close()

    def test_canonical_export_requires_fresh_truth_guard_and_report_supplied_sarif(self):
        report = {"schema": "fixture/4.1", "status": "verified", "root": str(self.root),
                  "coverage": {"complete": True, "gaps": []},
                  "findings": [{"rule": "fixture", "path": "app.py", "line": 2,
                                "severity": "HIGH"}],
                  "sarif": {"version": "2.1.0", "runs": []}}
        guarded = truth_guard41.guard_document(report, root=self.root)
        store = evidence_store41.EvidenceStore(self.database)
        saved = store.store_report(guarded)
        content_type, raw = store.canonical_export(saved["run_id"], "json")
        self.assertIn("application/json", content_type)
        self.assertEqual(json.loads(raw)["truth_guard3"]["schema"], truth_guard41.SCHEMA)
        sarif_type, sarif_raw = store.canonical_export(saved["run_id"], "sarif")
        self.assertIn("sarif", sarif_type)
        self.assertEqual(json.loads(sarif_raw)["version"], "2.1.0")
        self.source.write_text("changed = True\n", encoding="utf-8")
        with self.assertRaises(evidence_store41.EvidenceStoreError):
            store.canonical_export(saved["run_id"], "json")

    def test_verified_research_uses_its_schema_verifier_for_json_export(self):
        report = research_engine41.research("What is plate tectonics?")
        self.assertTrue(research_engine41.verify_report(report)[0])
        store = evidence_store41.EvidenceStore(self.database)
        saved = store.store_report(report)
        content_type, raw = store.canonical_export(saved["run_id"], "json")
        self.assertIn("application/json", content_type)
        self.assertEqual(json.loads(raw)["schema"], "attestor-research/4.1")
        with self.assertRaises(evidence_store41.EvidenceStoreError):
            store.canonical_export(saved["run_id"], "sarif")


if __name__ == "__main__":
    unittest.main()
