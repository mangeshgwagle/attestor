from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import analysis_snapshot41 as snapshot41
import semantic_graph41 as graph41


class SemanticGraph41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, value: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8", newline="")
        return path

    def test_python_graph_contains_parser_derived_symbols_calls_and_flow(self) -> None:
        self.write("app.py", """
import os

def choose(flag):
    value = os.getenv("VALUE")
    if flag:
        return value
    return "safe"

choose(True)
""".lstrip())
        report = graph41.build(snapshot41.capture(self.root))
        self.assertTrue(graph41.verify_report(report)[0])
        self.assertIn("app.choose", {row["qualified"] for row in report["graph"]["symbols"]})
        self.assertIn("app.choose", {row["resolved"] for row in report["graph"]["calls"]})
        self.assertTrue(report["graph"]["control_flow"])
        self.assertTrue(report["graph"]["data_flow"])
        self.assertIn("control-flow-path-merge-is-conservative",
                      {row["reason"] for row in report["coverage"]["gaps"]})
        self.assertFalse(report["static_contract"]["target_code_executed"])

    def test_data_flow_stops_constructing_rows_at_the_item_budget(self) -> None:
        self.write("wide.py", "first = one + two\nsecond = three + four\n")
        public_row = graph41._public_row
        with mock.patch.object(graph41, "MAX_ITEMS", 3), mock.patch.object(
                graph41, "_public_row", wraps=public_row) as rows:
            report = graph41.build(self.root)
        data_calls = [call for call in rows.call_args_list
                      if call.args and call.args[0] == "sg41-data-"]
        self.assertEqual(len(data_calls), 3)
        self.assertEqual(len(report["graph"]["data_flow"]), 3)
        self.assertIn("graph-item-budget",
                      {row["reason"] for row in report["coverage"]["gaps"]})

    def test_selected_node_budget_is_enforced_before_public_rows_are_built(
            self) -> None:
        self.write("bounded.py", """
import os

def first(value):
    copy = value
    return os.getenv(copy)

def second(value):
    return first(value)
""".lstrip())
        public_row = graph41._public_row
        with mock.patch.object(
                graph41, "_public_row", wraps=public_row) as rows:
            report = graph41.build(self.root, max_nodes=3)
        graph_rows = report["graph"]
        observed = sum(len(collection) for collection in graph_rows.values())
        self.assertEqual(observed, 3)
        self.assertEqual(rows.call_count, 3)
        budget_gap = next(
            row for row in report["coverage"]["gaps"]
            if row["reason"] == "selected-graph-node-budget")
        self.assertEqual(budget_gap["limit"], 3)
        self.assertEqual(budget_gap["constructed_nodes"], 3)
        self.assertTrue(graph41.verify_report(report)[0])

    def test_selected_node_budget_is_validated_before_snapshot_capture(
            self) -> None:
        for value in (True, "3", 0, graph41.MAX_AST_NODES + 1):
            with self.subTest(value=value), mock.patch.object(
                    snapshot41, "capture",
                    side_effect=AssertionError("snapshot must not be captured")):
                with self.assertRaisesRegex(
                        graph41.SemanticGraphError, "max_nodes"):
                    graph41.build(self.root, max_nodes=value)

    def test_cross_file_relative_import_taint_and_statement_order(self) -> None:
        self.write("pkg/__init__.py", "")
        self.write("pkg/source.py", """
def untrusted():
    value = input()
    return value
""".lstrip())
        self.write("pkg/sink.py", """
from .source import untrusted

def actual():
    value = untrusted()
    eval(value)
    value = "safe"

def must_not_invent():
    value = "safe"
    eval(value)
    value = input()

def converted():
    eval(int(input()))
""".lstrip())
        report = graph41.build(self.root)
        witnesses = report["graph"]["taint_witnesses"]
        self.assertEqual(len(witnesses), 1)
        witness = witnesses[0]
        self.assertTrue(witness["cross_file"])
        self.assertEqual(witness["source"]["path"], "pkg/source.py")
        self.assertEqual(witness["sink"]["path"], "pkg/sink.py")
        self.assertEqual(witness["sink"]["line"], 5)
        edge = next(row for row in report["graph"]["imports"]
                    if row["path"] == "pkg/sink.py")
        self.assertEqual(edge["resolved_path"], "pkg/source.py")

    def test_cache_hits_content_adapter_invalidation_and_removal(self) -> None:
        target = self.write("a.py", "def f():\n    return 1\n")
        cache = graph41.SemanticCache()
        first = graph41.build(snapshot41.capture(self.root), cache=cache)
        second = graph41.build(snapshot41.capture(self.root), cache=cache)
        self.assertEqual(first["cache"]["misses"], ["a.py"])
        self.assertEqual(second["cache"]["hits"], ["a.py"])
        self.assertEqual(first["graph_sha256"], second["graph_sha256"])
        target.write_text("def f():\n    return 2\n", encoding="utf-8")
        third = graph41.build(snapshot41.capture(self.root), cache=cache)
        self.assertEqual(third["cache"]["invalidated"], ["a.py"])

        registry = graph41.default_registry()
        original = registry.get("python")
        self.assertIsNotNone(original)
        changed_registry = graph41.AdapterRegistry()
        changed_registry.register(graph41.Adapter(
            original.name, original.languages, original.level, original.available,
            original.extractor, cache_token="different-parser-contract"))
        fourth = graph41.build(snapshot41.capture(self.root), cache=cache,
                               registry=changed_registry)
        self.assertEqual(fourth["cache"]["invalidated"], ["a.py"])
        target.unlink()
        empty = graph41.build(snapshot41.capture(self.root), cache=cache)
        self.assertEqual(empty["cache"]["removed"], ["a.py"])

    def test_import_alias_keyword_sink_and_attribute_taint_are_resolved(self) -> None:
        self.write("pkg/__init__.py", "")
        self.write("pkg/source.py", "def get():\n    return 1\n")
        self.write("aliases.py", """
import pkg.source
from builtins import input as ask

class Box:
    def unsafe(self):
        self.value = ask()
        eval(source=self.value)

pkg.source.get()
""".lstrip())
        report = graph41.build(self.root)
        witness = report["graph"]["taint_witnesses"][0]
        self.assertEqual(witness["source"]["callee"], "builtins.input")
        self.assertEqual(witness["sink"]["line"], 7)
        call = next(row for row in report["graph"]["calls"]
                    if row["callee"] == "pkg.source.get")
        self.assertEqual(call["resolved"], "pkg.source.get")

    def test_javascript_default_is_honestly_bounded_and_compiler_adapter_is_explicit(self) -> None:
        self.write("web.ts", "export function run(x: string) { return parse(x); }\n")
        bounded = graph41.build(self.root)
        self.assertIn("bounded-structural-not-compiler",
                      {row["reason"] for row in bounded["coverage"]["gaps"]})
        js_adapter = next(row for row in bounded["adapters"]
                          if "typescript" in row["languages"])
        self.assertEqual(js_adapter["analysis_level"], "bounded-structural-lexical")
        self.assertFalse(bounded["static_contract"]["compiler_invoked"])

        def precomputed(item):
            facts, _ = graph41._extract_js(item)
            return facts, []

        adapter = graph41.compiler_js_ts_adapter(
            precomputed, compiler="fixture-ts-compiler", compiler_version="1.2.3",
            compiler_sha256="a" * 64, cache_token="fixture-facts-v1")
        compiled = graph41.build(
            self.root, registry=graph41.default_registry(js_ts_adapter=adapter))
        js_adapter = next(row for row in compiled["adapters"]
                          if row["name"] == "javascript-typescript-compiler")
        self.assertEqual(js_adapter["compiler_evidence"]["binary_sha256"], "a" * 64)
        self.assertFalse(js_adapter["compiler_invoked"])
        ts_symbols = [row for row in compiled["graph"]["symbols"]
                      if row["path"] == "web.ts"]
        self.assertTrue(ts_symbols)
        self.assertTrue(all(row["analysis_level"] == "compiler-derived"
                            for row in ts_symbols))

    def test_unsupported_files_and_invalid_adapter_output_are_explicit_gaps(self) -> None:
        self.write("notes.txt", "not semantically parsed\n")
        report = graph41.build(self.root)
        self.assertIn("semantic-language-unsupported",
                      {row["reason"] for row in report["coverage"]["gaps"]})

        self.write("x.py", "x = 1\n")

        def wrong(_item):
            return {"path": "other.py", "language": "python"}, []

        registry = graph41.AdapterRegistry()
        registry.register(graph41.Adapter("broken", ("python",), "fixture", True, wrong))
        failed = graph41.build(self.root, registry=registry)
        self.assertIn("semantic-adapter-failed-closed",
                      {row["reason"] for row in failed["coverage"]["gaps"]})

    def test_tampered_graph_or_report_digest_is_rejected(self) -> None:
        self.write("a.py", "x = 1\n")
        report = graph41.build(self.root)
        report["graph"]["symbols"][0]["name"] = "tampered"
        valid, errors = graph41.verify_report(report)
        self.assertFalse(valid)
        self.assertTrue(any("digest" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
