#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import supply_chain35
import supply_chain_center
import supply_chain_trust41 as trust41


KEY = b"offline-osv-authentication-key-41" * 2


class SupplyChainTrust41Tests(unittest.TestCase):
    def test_polyglot_graph_uses_local_exact_evidence_and_valid_edges(self):
        fixtures = {
            "package-lock.json": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"a": "1.0.0"}},
                    "node_modules/a": {"name": "a", "version": "1.0.0",
                                       "dependencies": {"b": "2.0.0"}},
                    "node_modules/b": {"name": "b", "version": "2.0.0"},
                },
            }),
            "Cargo.lock": """version = 3
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["lib 2.0.0"]
[[package]]
name = "lib"
version = "2.0.0"
""",
            "uv.lock": """version = 1
[[package]]
name = "py-app"
version = "1.0.0"
dependencies = [{ name = "py-lib" }]
[[package]]
name = "py-lib"
version = "2.0.0"
""",
            "pdm.lock": """[[package]]
name = "pdm-app"
version = "1.0.0"
dependencies = ["pdm-lib"]
[[package]]
name = "pdm-lib"
version = "2.0.0"
""",
            "go.mod": "module example.test/app\nrequire example.test/lib v1.2.3\n",
            "pom.xml": """<project><groupId>x</groupId><artifactId>app</artifactId>
<version>1</version><dependencies><dependency><groupId>x</groupId>
<artifactId>lib</artifactId><version>2</version></dependency></dependencies></project>""",
            "gradle.lockfile": "org.example:library:3.0=runtimeClasspath\n",
            "packages.lock.json": json.dumps({"dependencies": {"net8.0": {
                "Direct": {"type": "Direct", "resolved": "1.0.0",
                           "dependencies": {"Transitive": "2.0.0"}},
                "Transitive": {"type": "Transitive", "resolved": "2.0.0"},
            }}}),
            "composer.lock": json.dumps({"packages": [
                {"name": "vendor/a", "version": "1.0.0", "require": {"vendor/b": "^2"}},
                {"name": "vendor/b", "version": "2.0.0"},
            ]}),
            "yarn.lock": """a@^1:
  version "1.0.0"
  dependencies:
    b "^2"
b@^2:
  version "2.0.0"
""",
            "pnpm-lock.yaml": """lockfileVersion: '9.0'
snapshots:
  a@1.0.0:
    dependencies:
      b: 2.0.0
  b@2.0.0: {}
""",
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, text in fixtures.items():
                (root / name).write_text(text, encoding="utf-8")
            report = trust41.analyze_dependency_graph(root)
            repeat = trust41.analyze_dependency_graph(root)
        ecosystems = {row["ecosystem"] for row in report["manifests"]}
        self.assertTrue({"npm", "cargo", "uv", "pdm", "go", "maven", "gradle",
                         "nuget", "composer", "yarn", "pnpm"} <= ecosystems)
        self.assertTrue(report["nodes"])
        self.assertTrue(report["edges"])
        identifiers = {node["id"] for node in report["nodes"]}
        self.assertTrue(all(edge["source"] in identifiers and edge["target"] in identifiers
                            for edge in report["edges"]))
        self.assertTrue(trust41.verify_graph_report(report))
        self.assertEqual(report, repeat)
        self.assertEqual(report["execution"], {"network": False, "package_managers": False,
                                               "target_code": False,
                                               "dependency_install": False})

    def test_npm_missing_workspace_row_gets_a_real_synthetic_root_node(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package-lock.json").write_text(json.dumps({
                "name": "app", "version": "1.0.0", "lockfileVersion": 3,
                "dependencies": {"a": {"version": "1.0.0"}},
                "packages": {"node_modules/a": {"name": "a", "version": "1.0.0"}},
            }), encoding="utf-8")
            report = trust41.analyze_dependency_graph(root)
        roots = [node for node in report["nodes"] if node["kind"] == "workspace"]
        self.assertEqual(len(roots), 1)
        self.assertTrue(any(edge["source"] == roots[0]["id"] for edge in report["edges"]))
        self.assertTrue(all(edge["source"] in {node["id"] for node in report["nodes"]}
                            for edge in report["edges"]))

    def test_legacy_npm_root_regression_has_no_dangling_edge(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {"dependencies": {"a": "1"}},
                             "node_modules/a": {"name": "a", "version": "1"}},
            }), encoding="utf-8")
            report = supply_chain35.analyze_dependency_graph(root)
        identifiers = {node["id"] for node in report["nodes"]}
        self.assertEqual(len(report["edges"]), 1)
        self.assertIn(report["edges"][0]["source"], identifiers)
        self.assertIn(report["edges"][0]["target"], identifiers)

    def test_graph_digest_detects_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "go.mod").write_text("module example.test/a\nrequire example.test/b v1.0.0\n",
                                               encoding="utf-8")
            report = trust41.analyze_dependency_graph(folder)
        tampered = copy.deepcopy(report)
        tampered["nodes"][0]["version"] = "attacker"
        self.assertTrue(trust41.verify_graph_report(report))
        self.assertFalse(trust41.verify_graph_report(tampered))
        relabeled = copy.deepcopy(report)
        relabeled["root"] = "C:/attacker/relabeled-workspace"
        self.assertFalse(trust41.verify_graph_report(relabeled))
        recursive = copy.deepcopy(report)
        nested: list = []
        cursor = nested
        for _ in range(2_000):
            child: list = []
            cursor.append(child)
            cursor = child
        recursive["unexpected"] = nested
        self.assertFalse(trust41.verify_graph_report(recursive))

    def test_manifest_digest_uses_exact_raw_crlf_bytes(self):
        raw = (b"module example.test/app\r\n"
               b"require example.test/lib v1.2.3\r\n")
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "go.mod").write_bytes(raw)
            report = trust41.analyze_dependency_graph(folder)
        self.assertEqual(report["manifests"][0]["sha256"],
                         hashlib.sha256(raw).hexdigest())

    def test_manifest_read_is_bounded_after_file_discovery(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "go.mod").write_text("module example.test/app\n", encoding="utf-8")
            opened = mock.mock_open()
            opened.return_value.read.return_value = b"x" * (trust41.MAX_FILE_BYTES + 1)
            with mock.patch.object(Path, "open", opened), \
                    mock.patch.object(Path, "read_bytes",
                                      side_effect=AssertionError("unbounded read")):
                report = trust41.analyze_dependency_graph(folder)
        opened.return_value.read.assert_called_once_with(trust41.MAX_FILE_BYTES + 1)
        self.assertFalse(report["manifests"])
        self.assertTrue(any("byte boundary" in gap for gap in report["gaps"]))

    def test_duplicate_json_keys_fail_closed_as_a_partial_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "package-lock.json").write_text(
                '{"lockfileVersion":3,"packages":{},"packages":{}}', encoding="utf-8")
            report = trust41.analyze_dependency_graph(folder)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("duplicate" in gap for gap in report["gaps"]))

    def test_authenticated_offline_osv_round_trip_and_canonical_order(self):
        records = [{"id": "OSV-2", "affected": []},
                   {"id": "OSV-1", "affected": [{"package": {"name": "a"}}]}]
        snapshot = trust41.create_osv_snapshot(
            records, key=KEY, key_id="fixture", sequence=7,
            generated_at="2026-07-17T00:00:00Z")
        encoded = json.dumps(snapshot, sort_keys=True).encode("utf-8")
        result = trust41.import_osv_snapshot(encoded, {"fixture": KEY})
        self.assertTrue(result["accepted"], result)
        self.assertTrue(result["authenticated"])
        self.assertEqual([row["id"] for row in result["records"]], ["OSV-1", "OSV-2"])
        self.assertFalse(result["network"])
        self.assertEqual(result["checkpoint"]["sequence"], 7)

    def test_osv_tampering_wrong_key_rollback_and_equivocation_are_rejected(self):
        snapshot = trust41.create_osv_snapshot(
            [{"id": "OSV-1", "affected": []}], key=KEY, key_id="fixture",
            sequence=4, generated_at="2026-07-17T00:00:00+00:00")
        tampered = copy.deepcopy(snapshot)
        tampered["records"][0]["id"] = "OSV-ATTACKER"
        self.assertFalse(trust41.import_osv_snapshot(tampered, {"fixture": KEY})["accepted"])
        self.assertFalse(trust41.import_osv_snapshot(snapshot, {"fixture": b"x" * 32})["accepted"])

        checkpoint = {"sequence": 5, "payload_sha256": "a" * 64}
        rollback = trust41.import_osv_snapshot(snapshot, {"fixture": KEY}, checkpoint)
        self.assertTrue(any("rollback" in error for error in rollback["errors"]))
        same_sequence = {"sequence": 4, "payload_sha256": "b" * 64}
        equivocation = trust41.import_osv_snapshot(snapshot, {"fixture": KEY}, same_sequence)
        self.assertTrue(any("equivocation" in error for error in equivocation["errors"]))

    def test_osv_hmac_binds_key_id_even_when_trusted_aliases_share_a_key(self):
        snapshot = trust41.create_osv_snapshot(
            [{"id": "OSV-1", "affected": []}], key=KEY, key_id="production",
            sequence=1, generated_at="2026-07-17T00:00:00Z")
        relabeled = copy.deepcopy(snapshot)
        relabeled["authentication"]["key_id"] = "attacker-label"
        result = trust41.import_osv_snapshot(
            relabeled, {"production": KEY, "attacker-label": KEY})
        self.assertFalse(result["accepted"])
        self.assertFalse(result["authenticated"])
        extra = copy.deepcopy(snapshot)
        extra["authentication"]["ignored"] = "unsigned metadata"
        self.assertFalse(trust41.import_osv_snapshot(
            extra, {"production": KEY})["accepted"])
        malformed = copy.deepcopy(snapshot)
        malformed["authentication"]["tag"] = 7
        self.assertFalse(trust41.import_osv_snapshot(
            malformed, {"production": KEY})["accepted"])
        with self.assertRaises(trust41.SupplyChainTrustError):
            trust41.create_osv_snapshot(
                [{"id": "OSV-1", "affected": []}], key=KEY,
                key_id="team\u202esecurity", sequence=1,
                generated_at="2026-07-17T00:00:00Z")

    def test_graph_and_advisory_text_escape_terminal_controls(self):
        unsafe_name = "caf\N{LATIN SMALL LETTER E WITH ACUTE}\u0085\u202ehidden"
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/example": {"name": unsafe_name, "version": "1"},
                },
            }), encoding="utf-8")
            report = trust41.analyze_dependency_graph(folder)
        package = next(node for node in report["nodes"] if node["kind"] == "package")
        self.assertEqual(package["name"],
                         "caf\N{LATIN SMALL LETTER E WITH ACUTE}\\x85\\u202ehidden")

        snapshot = trust41.create_osv_snapshot(
            [{"id": "OSV-1", "affected": [],
              "summary": "caf\N{LATIN SMALL LETTER E WITH ACUTE}\x1b[31m\u0085\u202e"}],
            key=KEY, key_id="fixture", sequence=1,
            generated_at="2026-07-17T00:00:00Z")
        self.assertEqual(
            snapshot["records"][0]["summary"],
            "caf\N{LATIN SMALL LETTER E WITH ACUTE}\\x1b[31m\\x85\\u202e")
        rendered = trust41._terminal_text("\x1b" * 100, 63)
        self.assertLessEqual(len(rendered), 63)
        self.assertNotIn("\x1b", rendered)
        self.assertEqual(len(rendered) % len("\\x1b"), 0)

    def test_osv_invalid_time_duplicate_ids_and_duplicate_json_are_rejected(self):
        with self.assertRaises(trust41.SupplyChainTrustError):
            trust41.create_osv_snapshot(
                [{"id": "OSV-1", "affected": []}, {"id": "OSV-1", "affected": []}],
                key=KEY, key_id="fixture", sequence=1, generated_at="2026-07-17T00:00:00Z")
        with self.assertRaises(trust41.SupplyChainTrustError):
            trust41.create_osv_snapshot(
                [], key=KEY, key_id="fixture", sequence=1, generated_at="2026-07-17")
        with self.assertRaises(trust41.SupplyChainTrustError):
            trust41.import_osv_snapshot('{"schema":"x","schema":"y"}', {"fixture": KEY})

    def test_not_affected_requires_an_intact_exhaustive_content_addressed_proof(self):
        component = "pkg:npm/a@1.0.0"
        unverified = supply_chain35.vex_disposition("OSV-1", component, False)
        self.assertEqual(unverified["status"], "under_investigation")
        proof = supply_chain35.make_reachability_proof(
            component, reachable=False,
            entrypoints=["<all-observed-entrypoints>", "route:/health"], call_chains=[],
            analysis_sha256="a" * 64, inventory_sha256="b" * 64)
        self.assertTrue(supply_chain35.verify_reachability_proof(proof, component))
        self.assertTrue(supply_chain_center.verify_exhaustive_reachability_proof(proof, component))
        self.assertEqual(supply_chain35.vex_disposition("OSV-1", component, proof)["status"],
                         "not_affected")
        proof["inventory_sha256"] = "c" * 64
        self.assertFalse(supply_chain35.verify_reachability_proof(proof, component))
        self.assertFalse(supply_chain_center.verify_exhaustive_reachability_proof(proof, component))

    def test_malformed_reachability_objects_never_raise_or_create_not_affected(self):
        malformed = {"schema": supply_chain35.REACHABILITY_PROOF_SCHEMA,
                     "reachable": False, "entrypoints": [object()]}
        self.assertFalse(supply_chain35.verify_reachability_proof(malformed))
        self.assertFalse(supply_chain_center.verify_exhaustive_reachability_proof(malformed))
        self.assertEqual(supply_chain35.vex_disposition("OSV-1", "pkg:npm/a@1", malformed)["status"],
                         "under_investigation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
