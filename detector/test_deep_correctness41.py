from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import analysis_snapshot41 as snapshot41
import deep_correctness41 as deep


class DeepCorrectness41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.current = self.base / "current"
        self.previous = self.base / "previous"
        self.current.mkdir()
        self.previous.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def write(root: Path, name: str, value: str) -> Path:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8", newline="")
        return path

    def rules(self, report: dict) -> set[str]:
        return {row["rule"] for row in report["findings"]}

    def test_lock_order_race_and_async_candidates_are_parser_evidenced_not_proven(self) -> None:
        self.write(self.current, "concurrency.py", """
import asyncio
import threading

left = threading.Lock()
right = threading.Lock()
counter = 0

def first():
    global counter
    counter += 1
    with left:
        with right:
            pass

def second():
    global counter
    counter += 1
    with right:
        with left:
            pass

async def worker():
    asyncio.create_task(do_work())
    try:
        await do_work()
    except asyncio.CancelledError:
        pass
""".lstrip())
        report = deep.analyze(self.current)
        rules = self.rules(report)
        self.assertIn("concurrency/inconsistent-lock-order", rules)
        self.assertIn("concurrency/shared-global-write-race-candidate", rules)
        self.assertIn("async/discarded-task-handle", rules)
        self.assertIn("async/cancellation-swallowed", rules)
        self.assertEqual(report["summary"]["deadlock_candidates"], 1)
        self.assertFalse(report["concurrency"]["runtime_deadlocks_or_races_proven"])
        self.assertTrue(all(not row["runtime_proven"] for row in report["findings"]))

    def test_resource_and_transaction_typestate_distinguishes_closed_and_escaped(self) -> None:
        self.write(self.current, "resources.py", """
import socket
import sqlite3
import subprocess

def leak():
    file_handle = open("data.txt")
    sock = socket.socket()
    process = subprocess.Popen(["tool"])
    db = sqlite3.connect("db.sqlite")
    db.begin()

def closed():
    file_handle = open("data.txt")
    file_handle.close()

def escaped():
    file_handle = open("data.txt")
    return file_handle
""".lstrip())
        report = deep.analyze(self.current)
        rules = self.rules(report)
        self.assertIn("resource/may-leak", rules)
        self.assertIn("transaction/begin-without-terminal", rules)
        states = {(row["owner"], row["resource"]): row["state"]
                  for row in report["resources"]["states"]}
        self.assertEqual(states[("resources.closed", "file_handle")], "closed")
        self.assertEqual(states[("resources.escaped", "file_handle")], "escaped")
        self.assertFalse(any(row["rule"] == "resource/may-leak" and
                             row["path"] == "resources.py" and row["line"] == 13
                             for row in report["findings"]))
        self.assertFalse(report["static_contract"]["target_code_executed"])
        self.assertFalse(report["static_contract"]["database_accessed"])

    def test_openapi_json_schema_and_avro_baseline_changes(self) -> None:
        old_api = {
            "openapi": "3.0.0",
            "paths": {
                "/old": {"get": {"responses": {"200": {}}}},
                "/items": {"post": {"parameters": [], "responses": {"201": {}}}},
            },
            "components": {"schemas": {"Item": {
                "type": "object", "properties": {
                    "id": {"type": "string"},
                    "status": {"type": "string", "enum": ["new", "done"]}},
                "required": ["id"]}}},
        }
        new_api = {
            "openapi": "3.0.0",
            "paths": {
                "/items": {"post": {
                    "parameters": [{"name": "tenant", "in": "header", "required": True,
                                    "schema": {"type": "string"}}],
                    "responses": {"400": {}}}},
            },
            "components": {"schemas": {"Item": {
                "type": "object", "properties": {
                    "id": {"type": "integer"},
                    "status": {"type": "string", "enum": ["new"]},
                    "name": {"type": "string"}},
                "required": ["id", "name"]}}},
        }
        self.write(self.previous, "openapi.json", json.dumps(old_api))
        self.write(self.current, "openapi.json", json.dumps(new_api))
        self.write(self.previous, "event.avsc", json.dumps({
            "type": "record", "name": "Event",
            "fields": [{"name": "id", "type": "string"}]}))
        self.write(self.current, "event.avsc", json.dumps({
            "type": "record", "name": "Event",
            "fields": [{"name": "id", "type": "long"},
                       {"name": "tenant", "type": "string"}]}))
        report = deep.analyze(self.current, baseline=self.previous)
        rules = self.rules(report)
        expected = {
            "compatibility/contract-removed",
            "compatibility/openapi-required-parameter-added",
            "compatibility/openapi-success-response-removed",
            "compatibility/schema-property-type-changed",
            "compatibility/schema-enum-narrowed",
            "compatibility/schema-required-property-added",
            "compatibility/avro-field-type-changed",
            "compatibility/avro-field-added-without-default",
        }
        self.assertTrue(expected <= rules, expected - rules)
        self.assertTrue(report["compatibility"]["comparison_performed"])
        self.assertFalse(report["compatibility"]["breaking_changes_proven"])
        self.assertTrue(all(row["signature_sha256"] for row in
                            report["compatibility"]["contracts"]))

    def test_graphql_and_protobuf_baseline_changes_are_labelled_lexical(self) -> None:
        self.write(self.previous, "schema.graphql", """
type Query {
  user(id: ID): String
  oldField: String
}
input Filter {
  query: String
}
enum Color {
  RED
  BLUE
}
""".lstrip())
        self.write(self.current, "schema.graphql", """
type Query {
  user(id: ID!, tenant: ID!): String
}
input Filter {
  query: String
  limit: Int!
}
enum Color {
  RED
}
""".lstrip())
        self.write(self.previous, "service.proto", """
syntax = "proto3";
message User {
  string id = 1;
  string name = 2;
}
service Users {
  rpc Get (User) returns (User);
}
""".lstrip())
        self.write(self.current, "service.proto", """
syntax = "proto3";
message User {
  int64 id = 1;
}
service Users {
}
""".lstrip())
        report = deep.analyze(self.current, baseline=self.previous)
        rules = self.rules(report)
        expected = {
            "compatibility/graphql-field-removed",
            "compatibility/graphql-required-argument-added",
            "compatibility/graphql-argument-became-required",
            "compatibility/graphql-argument-type-changed",
            "compatibility/graphql-required-input-added",
            "compatibility/graphql-enum-value-removed",
            "compatibility/protobuf-field-number-removed",
            "compatibility/protobuf-field-number-reused",
            "compatibility/protobuf-rpc-removed",
        }
        self.assertTrue(expected <= rules, expected - rules)
        levels = {row["analysis_level"] for row in report["compatibility"]["contracts"]}
        self.assertIn("bounded-graphql-lexical-signature", levels)
        self.assertIn("bounded-protobuf-lexical-signature", levels)

    def test_migration_rollback_evidence_and_forward_only_analysis(self) -> None:
        self.write(self.current, "001.up.sql", "ALTER TABLE users DROP COLUMN legacy;\n")
        self.write(self.current, "001.down.sql", "ALTER TABLE users ADD COLUMN legacy TEXT;\n")
        self.write(self.current, "002.sql", """
ALTER TABLE users DROP COLUMN obsolete;
-- down
ALTER TABLE users DROP COLUMN restored_only_during_rollback;
""".lstrip())
        report = deep.analyze(self.current, baseline=self.previous)
        operations = report["migrations"]["operations"]
        self.assertEqual(len(operations), 2)
        self.assertTrue(all(row["rollback_observed"] for row in operations))
        self.assertNotIn("migration/rollback-evidence-missing", self.rules(report))
        self.assertFalse(report["migrations"]["database_or_migration_executed"])

    def test_no_baseline_abstains_from_compatibility_and_report_is_deterministic(self) -> None:
        self.write(self.current, "app.py", "def safe():\n    return 1\n")
        first = deep.analyze(snapshot41.capture(self.current))
        second = deep.analyze(snapshot41.capture(self.current))
        self.assertEqual(first, second)
        self.assertFalse(first["compatibility"]["comparison_performed"])
        self.assertIn("compatibility-baseline-not-supplied",
                      {row["reason"] for row in first["coverage"]["gaps"]})
        self.assertTrue(deep.verify_report(first)[0])
        first["summary"]["findings"] = 999
        self.assertFalse(deep.verify_report(first)[0])

    def test_parse_and_ast_budgets_create_explicit_gaps(self) -> None:
        self.write(self.current, "bad.py", "def broken(:\n")
        self.write(self.current, "bad.json", "{not-json")
        report = deep.analyze(self.current, limits=deep.CorrectnessLimits(
            max_ast_nodes_per_file=100, max_contracts=10, max_evidence=100,
            max_findings=100, max_gaps=100, max_contract_fields=100,
            max_json_depth=16))
        reasons = {row["reason"] for row in report["coverage"]["gaps"]}
        self.assertIn("python-parse-error", reasons)
        self.assertIn("json-contract-parse-error", reasons)

    def test_public_domain_collections_obey_evidence_and_finding_budgets(self) -> None:
        self.write(self.current, "app.py", "value = 1\n")
        lock_pairs = [("a", "b"), ("b", "a"), ("c", "d"),
                      ("d", "c"), ("e", "f")]
        python_row = {
            "lock_orders": [
                {"path": "app.py", "owner": f"owner{i}", "left": left,
                 "right": right, "line": i + 1, "precision": "fixture",
                 "evidence_id": f"lock-{i}"}
                for i, (left, right) in enumerate(lock_pairs)],
            "resources": [
                {"path": "app.py", "owner": "owner", "resource": f"r{i}",
                 "line": i + 1, "state": "open"} for i in range(5)],
            "global_writes": [
                {"path": "app.py", "owner": "owner", "symbol": f"g{i}",
                 "line": i + 1, "evidence_id": f"global-{i}"} for i in range(5)],
            "async_checks": [],
        }
        contracts = {
            f"contract:{i}": {
                "key": f"contract:{i}", "kind": "json-schema",
                "path": f"schema{i}.json", "name": f"Schema{i}", "line": 1,
                "analysis_level": "fixture", "signature": {},
                "signature_sha256": f"digest-{i}", "evidence_id": f"contract-{i}"}
            for i in range(5)
        }
        changes = [
            {"rule": f"compatibility/change-{i}", "path": "schema.json",
             "line": i + 1, "message": f"change {i}", "breaking_proven": False,
             "evidence_ids": [f"change-{i}-{part}" for part in range(5)]}
            for i in range(2)
        ]
        migrations = [
            {"path": "migration.sql", "line": i + 1, "operation": f"operation-{i}",
             "analysis_level": "fixture", "rollback_observed": False,
             "transaction_observed": False, "evidence_id": f"migration-{i}",
             "execution_performed": False} for i in range(5)
        ]
        limits = deep.CorrectnessLimits(
            max_ast_nodes_per_file=100, max_contracts=10, max_evidence=4,
            max_findings=1, max_gaps=50, max_contract_fields=10, max_json_depth=8)
        with mock.patch.object(deep, "_python_analysis", return_value=python_row), \
                mock.patch.object(deep, "_contracts", return_value=contracts), \
                mock.patch.object(deep, "_compare_contracts", return_value=changes), \
                mock.patch.object(deep, "_migration_analysis", return_value=migrations):
            report = deep.analyze(
                snapshot41.capture(self.current), baseline=snapshot41.capture(self.previous),
                limits=limits)

        self.assertEqual([
            len(report["concurrency"]["lock_orders"]),
            len(report["concurrency"]["deadlock_candidates"]),
            len(report["concurrency"]["global_writes"]),
            len(report["resources"]["states"]),
            len(report["compatibility"]["contracts"]),
            len(report["compatibility"]["changes"]),
            len(report["compatibility"]["changes"][0]["evidence_ids"]),
            len(report["migrations"]["operations"]),
        ], [4, 1, 4, 4, 4, 1, 4, 4])
        reasons = {row["reason"] for row in report["coverage"]["gaps"]}
        self.assertTrue({
            "concurrency-lock-order-budget-reached",
            "concurrency-deadlock-candidate-budget-reached",
            "concurrency-global-write-budget-reached", "resource-state-budget-reached",
            "compatibility-contract-budget-reached", "compatibility-change-budget-reached",
            "compatibility-change-evidence-budget-reached",
            "migration-operation-budget-reached",
        } <= reasons)
        self.assertEqual(report["summary"]["resource_states"], 4)
        self.assertTrue(deep.verify_report(report)[0])


if __name__ == "__main__":
    unittest.main()
