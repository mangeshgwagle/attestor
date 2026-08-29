from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import engineering_engine40 as eng40
import polyglot_ir35
import truth_guard35


class EngineeringEngine40Tests(unittest.TestCase):
    def test_report_is_deterministic_json_safe_and_never_executes_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "executed.txt"
            secret = "literal-must-not-be-copied-into-evidence"
            (root / "app.py").write_text(
                "from pathlib import Path\n"
                f"SECRET = {secret!r}\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "def public(value: int) -> int:\n    return value + 1\n",
                encoding="utf-8")
            first = eng40.analyze(root)
            second = eng40.analyze(root)
        self.assertEqual(first, second)
        self.assertFalse(marker.exists())
        self.assertEqual(first["schema"], eng40.SCHEMA)
        self.assertEqual(first["version"], eng40.VERSION)
        self.assertTrue(eng40.verify_report(first)[0])
        self.assertFalse(first["execution"]["target_code"])
        self.assertFalse(first["execution"]["processes"])
        encoded = json.dumps(first, allow_nan=False, sort_keys=True)
        self.assertNotIn(secret, encoded)

    def test_python_architecture_cycle_and_reverse_impact_are_exactly_scoped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.py").write_text("import b\ndef a(): return b.b()\n", encoding="utf-8")
            (root / "b.py").write_text("import c\ndef b(): return c.c()\n", encoding="utf-8")
            (root / "c.py").write_text("import a\ndef c(): return 1\n", encoding="utf-8")
            report = eng40.analyze(root, changed_paths=["c.py"])
        self.assertEqual(report["impact"]["status"], "complete-for-known-static-graph")
        self.assertEqual(report["impact"]["changed_paths"], ["c.py"])
        self.assertEqual(set(report["impact"]["affected_paths"]), {"a.py", "b.py", "c.py"})
        self.assertEqual(report["architecture"]["cycles"][0]["members"],
                         ["a.py", "b.py", "c.py"])
        self.assertIn("architecture/dependency-cycle",
                      {row["rule"] for row in report["findings"]})

    def test_polyglot_cross_file_impact_is_lexical_not_compiler_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.js").write_text(
                "import { value } from './b.js';\nexport function get(){ return value; }\n",
                encoding="utf-8")
            (root / "b.js").write_text("export const value = 1;\n", encoding="utf-8")
            report = eng40.analyze(root, changed_paths=["b.js"])
        self.assertEqual(set(report["impact"]["affected_paths"]), {"a.js", "b.js"})
        edge = report["architecture"]["dependency_edges"][0]
        self.assertEqual((edge["source"], edge["target"]), ("a.js", "b.js"))
        self.assertFalse(report["analysis"]["compiler_invoked"])
        self.assertIn("bounded-lexical-not-compiler",
                      {row.get("analysis_level") for row in report["inventory"]["functions"]})

    def test_api_and_data_contracts_create_specific_test_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "api.py").write_text(
                "from pydantic import BaseModel\n"
                "class User(BaseModel):\n    name: str\n    age: int | None = None\n"
                "@app.get('/users/{id}')\ndef get_user(id: int) -> User:\n    return User(name='x')\n",
                encoding="utf-8")
            (root / "openapi.json").write_text(json.dumps({
                "openapi": "3.1.0",
                "paths": {"/health": {"get": {"operationId": "health"}}},
                "components": {"schemas": {"Health": {
                    "type": "object", "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"]}}},
            }), encoding="utf-8")
            report = eng40.analyze(root, changed_paths=["api.py"])
        self.assertEqual(len(report["contracts"]["api_routes"]), 2)
        self.assertEqual(len(report["contracts"]["data_contracts"]), 2)
        kinds = {row["kind"] for row in report["test_plan"]["cases"]}
        self.assertIn("api-contract", kinds)
        self.assertIn("data-contract", kinds)
        self.assertFalse(report["test_plan"]["tests_executed"])

    def test_duplicate_route_and_invalid_json_schema_are_evidence_backed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one.py").write_text(
                "@app.get('/same')\ndef one(): return 1\n", encoding="utf-8")
            (root / "two.py").write_text(
                "@router.get('/same')\ndef two(): return 2\n", encoding="utf-8")
            (root / "user.schema.json").write_text(json.dumps({
                "type": "object", "properties": {"name": {"type": "string"}},
                "required": ["missing"]}), encoding="utf-8")
            report = eng40.analyze(root)
        rules = {row["rule"] for row in report["findings"]}
        self.assertIn("api/duplicate-literal-route", rules)
        self.assertIn("contract/required-property-not-declared", rules)
        self.assertEqual(len(report["contracts"]["duplicate_routes"]), 1)
        self.assertEqual(report["summary"]["findings"], len(report["findings"]))

    def test_openapi_route_plus_one_implementation_is_not_a_duplicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "api.py").write_text(
                "@app.get('/health')\ndef health(): return {'ok': True}\n",
                encoding="utf-8")
            (root / "openapi.json").write_text(json.dumps({
                "openapi": "3.1.0", "paths": {"/health": {"get": {}}},
            }), encoding="utf-8")
            report = eng40.analyze(root)
        self.assertEqual(report["contracts"]["duplicate_routes"], [])
        self.assertNotIn("api/duplicate-literal-route",
                         {row["rule"] for row in report["findings"]})

    def test_sql_migration_risks_produce_expand_contract_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "001_schema.sql").write_text(
                "CREATE TABLE users (id INTEGER, name TEXT);\n"
                "ALTER TABLE users DROP COLUMN name;\n",
                encoding="utf-8")
            report = eng40.analyze(root, issue="database migration removes a column")
        self.assertIn("migration/drop-column", {row["rule"] for row in report["findings"]})
        self.assertEqual(report["contracts"]["data_contracts"][0]["kind"], "sql-table")
        self.assertIn("expand-contract-migration",
                      {row["phase"] for row in report["refactor_plan"]["steps"]})
        self.assertFalse(report["refactor_plan"]["changes_applied"])

    def test_performance_concurrency_and_debug_checks_are_parser_derived(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "worker.py").write_text(
                "import asyncio\nimport time\n"
                "async def run():\n"
                "    time.sleep(1)\n"
                "    asyncio.create_task(other())\n"
                "def first():\n    lock_a.acquire()\n    lock_b.acquire()\n"
                "def second():\n    lock_b.acquire()\n    lock_a.acquire()\n"
                "def nested(items):\n"
                "    for left in items:\n"
                "        for right in items:\n            pass\n"
                "def hidden():\n"
                "    try:\n        risky()\n"
                "    except Exception:\n        pass\n",
                encoding="utf-8")
            report = eng40.analyze(root, issue="async deadlock is slow and hangs")
        rules = {row["rule"] for row in report["findings"]}
        self.assertIn("concurrency/blocking-call-in-async", rules)
        self.assertIn("concurrency/discarded-task-handle", rules)
        self.assertIn("concurrency/inconsistent-lock-order", rules)
        self.assertIn("performance/nested-loop-review", rules)
        self.assertIn("debug/broad-exception-suppression", rules)
        gates = {row["gate"] for row in report["debug_plan"]["steps"]}
        self.assertIn("schedule-control", gates)
        self.assertIn("measurement", gates)

    def test_mutable_defaults_and_unreachable_statements_have_normalized_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bad.py").write_text(
                "def collect(values=[]):\n"
                "    return values\n"
                "    values.append(1)\n",
                encoding="utf-8")
            report = eng40.analyze(root)
        rules = {row["rule"] for row in report["findings"]}
        self.assertIn("python/mutable-default-argument", rules)
        self.assertIn("python/unreachable-after-terminal", rules)
        for finding in report["findings"]:
            self.assertRegex(finding["fingerprint"], r"^[0-9a-f]{64}$")
            self.assertTrue(finding["remediation"])
            self.assertTrue(finding["evidence_ids"])

    def test_issue_to_patch_workflow_stores_digest_not_raw_issue_and_has_gates(self):
        unique = "bug token TOP-SECRET-RAW-ISSUE-8791 in API response"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "api.py").write_text("def response(value): return value\n", encoding="utf-8")
            report = eng40.analyze(root, issue=unique, changed_paths=["api.py"])
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn(unique, encoded)
        workflow = report["patch_workflow"]
        self.assertEqual(workflow["status"], "PLAN")
        self.assertFalse(workflow["patch_generated"])
        self.assertFalse(workflow["patch_applied"])
        self.assertFalse(workflow["writes_performed"])
        self.assertTrue(workflow["separate_execution_authorization_required"])
        self.assertTrue(workflow["separate_apply_authorization_required"])
        self.assertEqual(workflow["gates"][-1]["name"], "separate-apply-authorization")
        self.assertTrue(all("satisfied" in gate for gate in workflow["gates"]))

    def test_invalid_changed_path_is_rejected_without_expanding_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("def app(): return 1\n", encoding="utf-8")
            report = eng40.analyze(root, changed_paths=["../outside.py", "app.py"])
        self.assertEqual(report["impact"]["changed_paths"], ["app.py"])
        self.assertEqual(report["impact"]["status"], "partial")
        self.assertIn("invalid-changed-path", {row["kind"] for row in report["coverage"]["gaps"]})

    def test_syntax_and_resource_failures_are_gaps_not_false_compiler_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
            (root / "large.py").write_text("#" + "x" * 2_000, encoding="utf-8")
            report = eng40.analyze(root, limits=eng40.Limits(max_file_bytes=1_024))
        kinds = {row["kind"] for row in report["coverage"]["gaps"]}
        self.assertIn("python-parse-error", kinds)
        self.assertIn("file-too-large", kinds)
        self.assertEqual(report["coverage"]["state"], "partial")
        self.assertFalse(report["analysis"]["compiler_invoked"])
        self.assertFalse(report["coverage"]["semantic_complete"])

    def test_evidence_and_record_catalogs_stop_at_their_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = "\n".join("def f%d(value): return value" % index
                               for index in range(180)) + "\n"
            (root / "many.py").write_text(source, encoding="utf-8")
            report = eng40.analyze(root, limits=eng40.Limits(max_evidence=100))
        kinds = {row["kind"] for row in report["coverage"]["gaps"]}
        self.assertIn("evidence-boundary", kinds)
        self.assertIn("function-boundary", kinds)
        self.assertLessEqual(len(report["evidence"]), 100)
        self.assertLessEqual(len(report["inventory"]["functions"]), 100)

    def test_issue_classification_is_prefix_bounded(self):
        issue = "performance bug " + ("SENSITIVE-LONG-TAIL-" * 1_000)
        with tempfile.TemporaryDirectory() as temporary:
            report = eng40.analyze(
                temporary, issue=issue, limits=eng40.Limits(max_issue_chars=32))
        profile = report["patch_workflow"]["issue"]
        self.assertTrue(profile["truncated_for_classification"])
        self.assertEqual(profile["sha256_scope"], "bounded-prefix")
        self.assertEqual(profile["characters"], len(issue))
        self.assertNotIn(issue, json.dumps(report))

    def test_missing_root_returns_complete_unavailable_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = eng40.analyze(Path(temporary) / "missing")
        self.assertEqual(report["status"], "unavailable")
        self.assertEqual(report["summary"]["findings"], 0)
        self.assertEqual(report["findings"], [])
        self.assertFalse(report["execution"]["filesystem_writes"])
        self.assertTrue(eng40.verify_report(report)[0])

    def test_root_and_nested_symlinks_are_never_followed(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            external = Path(outside) / "external.py"
            external.write_text("def external(): return 1\n", encoding="utf-8")
            nested = root / "linked.py"
            root_link = root / "root-link"
            try:
                nested.symlink_to(external)
                root_link.symlink_to(Path(outside), target_is_directory=True)
            except OSError:
                self.skipTest("symbolic links are unavailable to this test account")
            report = eng40.analyze(root)
            refused = eng40.analyze(root_link)
        self.assertNotIn("linked.py", {row["path"] for row in report["inventory"]["files"]})
        self.assertIn("symlink-skipped", {row["kind"] for row in report["coverage"]["gaps"]})
        self.assertEqual(refused["status"], "unavailable")
        self.assertEqual(refused["coverage"]["gaps"][0]["kind"], "root-symlink-refused")

    def test_supplied_ir_is_bounded_labeled_and_root_bound(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as other:
            root = Path(temporary)
            (root / "app.js").write_text("export function app(){ return 1; }\n", encoding="utf-8")
            ir = polyglot_ir35.analyze(root)
            report = eng40.analyze(root, ir=ir)
            forged = copy.deepcopy(ir)
            forged["root"] = str(Path(other).resolve())
            refused = eng40.analyze(root, ir=forged)
        self.assertEqual(report["analysis"]["ir_source"], "supplied-bounded-document")
        self.assertIn("supplied-ir-not-independently-reparsed",
                      {row["kind"] for row in report["coverage"]["gaps"]})
        self.assertIn("supplied-ir-refused",
                      {row["kind"] for row in refused["coverage"]["gaps"]})
        self.assertEqual(refused["inventory"]["languages"].get("javascript", 0), 0)

    def test_duplicate_json_keys_are_refused_as_contract_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bad.schema.json").write_text(
                '{"type":"object","properties":{},"properties":{}}', encoding="utf-8")
            report = eng40.analyze(root)
        self.assertEqual(report["contracts"]["data_contracts"], [])
        self.assertIn("json-contract-parse-error",
                      {row["kind"] for row in report["coverage"]["gaps"]})

    def test_file_target_and_cli_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "single.py"
            target.write_text("def single(value): return value\n", encoding="utf-8")
            report = eng40.analyze(target, changed_paths=["single.py"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = eng40.main([str(target), "--compact"])
        self.assertIn(code, (0, 1))
        self.assertEqual(report["inventory"]["files"][0]["path"], "single.py")
        self.assertEqual(json.loads(output.getvalue())["schema"], eng40.SCHEMA)

    def test_iterative_cycle_detection_handles_graph_deeper_than_python_recursion(self):
        nodes = ["n%04d.py" % index for index in range(1_500)]
        edges = [{"source": nodes[index], "target": nodes[index + 1]}
                 for index in range(len(nodes) - 1)]
        self.assertEqual(eng40._strongly_connected(nodes, edges), [])

    def test_report_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = eng40.analyze(temporary)
        forged = copy.deepcopy(report)
        forged["summary"]["findings"] = 999
        ok, errors = eng40.verify_report(forged)
        self.assertFalse(ok)
        self.assertIn("report digest mismatch", errors)

    def test_normalized_findings_and_summary_are_truth_guard_compatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "def collect(values=[]): return values\n", encoding="utf-8")
            report = eng40.analyze(root)
            guarded = truth_guard35.guard_document(report)
            self.assertEqual(report["summary"]["findings"], len(report["findings"]))
            self.assertTrue(truth_guard35.verify_guarded(guarded)["ok"])
            self.assertEqual(guarded["truth_guard2"]["summary"]["refuted"], 0)


if __name__ == "__main__":
    unittest.main()
