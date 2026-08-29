#!/usr/bin/env python3
"""Adversarial contracts for Attestor 3.5's bounded symbolic engine."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import symbolic_engine35
import symbolic_worker35


def write_project(root: Path, files: dict[str, str]) -> None:
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


class SourceContractTests(unittest.TestCase):
    def analyze(self, body: str, **limits: int) -> dict:
        return symbolic_engine35.analyze_source(body, filename="app.py", **limits)

    def test_direct_source_to_sink_has_typed_deterministic_witness(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    return os.system(command)\n")
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule"], "symbolic-taint/command")
        self.assertEqual(finding["cwe"], "CWE-78")
        self.assertEqual([step["kind"] for step in finding["witness"]],
                         ["source", "assignment", "sink"])
        self.assertEqual(finding["evidence_level"], "bounded-symbolic-witness")

    def test_finite_allowlist_sanitizes_only_true_branch(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    if command in {'status', 'health'}:\n"
            "        os.system(command)\n")
        self.assertEqual(report["findings"], [])

    def test_guard_clause_refines_surviving_branch(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    if command not in ('status', 'health'):\n"
            "        return 'rejected'\n"
            "    os.system(command)\n")
        self.assertEqual(report["findings"], [])

    def test_module_level_literal_allowlist_refines_branch(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "ALLOWED = {'status', 'health'}\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    if command not in ALLOWED:\n"
            "        return 'rejected'\n"
            "    os.system(command)\n")
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"], [])

    def test_literal_dict_keys_form_a_finite_allowlist(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "ALLOWED = {'status': 1, 'health': 2}\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    if command in ALLOWED:\n"
            "        os.system(command)\n")
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["findings"], [])

    def test_unrelated_branch_does_not_launder_taint(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run(admin):\n"
            "    command = request.args.get('cmd')\n"
            "    if admin:\n"
            "        os.system(command)\n")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["path_predicates"], ["admin"])

    def test_equality_validation_is_path_sensitive(self):
        safe = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    if command == 'status':\n"
            "        os.system(command)\n")
        unsafe = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    command = request.args.get('cmd')\n"
            "    if command != 'status':\n"
            "        os.system(command)\n")
        self.assertEqual(safe["findings"], [])
        self.assertEqual(len(unsafe["findings"]), 1)

    def test_context_specific_sanitizer_does_not_claim_universal_safety(self):
        shell_safe = self.analyze(
            "from flask import request\nimport os, shlex\n"
            "def run():\n"
            "    os.system(shlex.quote(request.args.get('cmd')))\n")
        code_unsafe = self.analyze(
            "from flask import request\nimport shlex\n"
            "def run():\n"
            "    eval(shlex.quote(request.args.get('code')))\n")
        self.assertEqual(shell_safe["findings"], [])
        self.assertEqual(len(code_unsafe["findings"]), 1)
        self.assertEqual(code_unsafe["findings"][0]["rule"], "symbolic-taint/code")

    def test_report_is_json_shaped_hashed_and_deterministic(self):
        source = "def clean(value):\n    return value.strip()\n"
        first = self.analyze(source)
        second = self.analyze(source)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(json.dumps(first)), first)
        digest = first.pop("report_sha256")
        payload = json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.assertEqual(digest, hashlib.sha256(payload.encode("utf-8")).hexdigest())

    def test_analysis_does_not_execute_target_or_echo_source_lines(self):
        secret = "ATTESTOR_TEST_SECRET_NEVER_REPORT_THIS"
        source = (
            "from pathlib import Path\n"
            "Path('SHOULD_NOT_EXIST').write_text('executed')\n"
            "def f():\n"
            "    password = '" + secret + "'\n"
            "    return password\n")
        report = self.analyze(source)
        self.assertFalse(report["analysis"]["target_code_executed"])
        self.assertFalse(report["analysis"]["filesystem_written"])
        self.assertNotIn(secret, json.dumps(report))

    def test_branch_predicates_redact_literal_values(self):
        secret = "SUPER_SECRET_BRANCH_VALUE"
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def f():\n"
            "    value = request.args.get('x')\n"
            "    if value != '" + secret + "':\n"
            "        os.system(value)\n")
        encoded = json.dumps(report)
        self.assertNotIn(secret, encoded)
        self.assertIn("<str-literal>", report["findings"][0]["path_predicates"][0])


class FieldAndAliasTests(unittest.TestCase):
    def analyze(self, body: str) -> dict:
        return symbolic_engine35.analyze_source(body, filename="fields.py")

    def test_known_safe_dict_key_is_not_tainted_by_sibling(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    values = {'dangerous': request.args.get('cmd'), 'safe': 'status'}\n"
            "    os.system(values['safe'])\n")
        self.assertEqual(report["findings"], [])

    def test_tainted_lookup_key_does_not_taint_allowlisted_value(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    operation = request.args.get('operation')\n"
            "    command = {'health': 'status', 'help': 'help'}.get(operation, 'help')\n"
            "    os.system(command)\n")
        self.assertEqual(report["findings"], [])

    def test_exact_tainted_field_and_unknown_field_read_are_detected(self):
        exact = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    values = {'dangerous': request.args.get('cmd'), 'safe': 'status'}\n"
            "    os.system(values['dangerous'])\n")
        unknown = self.analyze(
            "from flask import request\nimport os\n"
            "def run(key):\n"
            "    values = {'dangerous': request.args.get('cmd'), 'safe': 'status'}\n"
            "    os.system(values[key])\n")
        self.assertEqual(len(exact["findings"]), 1)
        self.assertEqual(len(unknown["findings"]), 1)
        self.assertIn("field-read", [row["kind"] for row in exact["findings"][0]["witness"]])

    def test_field_overwrite_kills_only_that_field_taint(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    values = {'command': request.args.get('cmd')}\n"
            "    values['command'] = 'status'\n"
            "    os.system(values['command'])\n")
        self.assertEqual(report["findings"], [])

    def test_object_aliases_share_field_updates(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    original = {'command': 'status'}\n"
            "    alias = original\n"
            "    alias['command'] = request.args.get('cmd')\n"
            "    os.system(original['command'])\n")
        self.assertEqual(len(report["findings"]), 1)

    def test_interprocedural_field_mutation_updates_aliased_heap(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def update(values, command):\n"
            "    values['command'] = command\n"
            "def run():\n"
            "    original = {'command': 'status'}\n"
            "    alias = original\n"
            "    update(alias, request.args.get('cmd'))\n"
            "    os.system(original['command'])\n")
        self.assertEqual(len(report["findings"]), 1)

    def test_scalar_alias_survives_reassignment_of_original(self):
        report = self.analyze(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    original = request.args.get('cmd')\n"
            "    alias = original\n"
            "    original = 'status'\n"
            "    os.system(alias)\n")
        self.assertEqual(len(report["findings"]), 1)


class CallsLoopsAndLimitsTests(unittest.TestCase):
    def test_unresolved_helper_conservatively_propagates_taint(self):
        report = symbolic_engine35.analyze_source(
            "from flask import request\nimport os\n"
            "def run():\n"
            "    command = custom_normalizer(request.args.get('cmd'))\n"
            "    os.system(command)\n")
        self.assertEqual(len(report["findings"]), 1)
        kinds = [row["kind"] for row in report["findings"][0]["witness"]]
        self.assertIn("unknown-call", kinds)
        self.assertEqual(report["metrics"]["unknown_calls"], 1)

    def test_known_helper_uses_bounded_call_context_and_call_witness(self):
        report = symbolic_engine35.analyze_source(
            "from flask import request\nimport os\n"
            "def normalize(value):\n"
            "    return value.strip()\n"
            "def run():\n"
            "    os.system(normalize(request.args.get('cmd')))\n")
        self.assertEqual(len(report["findings"]), 1)
        kinds = [row["kind"] for row in report["findings"][0]["witness"]]
        self.assertIn("call", kinds)
        self.assertGreaterEqual(report["metrics"]["call_contexts"], 1)

    def test_interprocedural_guard_clause_returns_only_validated_path(self):
        report = symbolic_engine35.analyze_source(
            "import os\n"
            "def validated(value):\n"
            "    if value not in {'status', 'health'}:\n"
            "        raise ValueError('rejected')\n"
            "    return value\n"
            "def run():\n"
            "    os.system(validated(input()))\n")
        self.assertEqual(report["findings"], [])

    def test_finally_preserves_tainted_return_flow(self):
        report = symbolic_engine35.analyze_source(
            "import os\n"
            "def identity(value):\n"
            "    try:\n"
            "        return value\n"
            "    finally:\n"
            "        pass\n"
            "def run():\n"
            "    os.system(identity(input()))\n")
        self.assertEqual(len(report["findings"]), 1)

    def test_cross_file_import_flow_is_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "helper.py": "def normalize(value):\n    return value.strip()\n",
                "app.py": (
                    "from flask import request\nimport os\n"
                    "from helper import normalize as clean\n"
                    "def run():\n"
                    "    os.system(clean(request.args.get('cmd')))\n"),
            })
            report = symbolic_engine35.analyze_repository(root)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["metrics"]["python_modules_parsed"], 2)
        self.assertGreaterEqual(report["metrics"]["call_contexts"], 1)

    def test_package_relative_import_flow_is_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "pkg/__init__.py": "from .helper import normalize\n",
                "pkg/helper.py": "def normalize(value):\n    return value.strip()\n",
                "pkg/app.py": (
                    "from flask import request\nimport os\n"
                    "from .helper import normalize\n"
                    "def run():\n"
                    "    os.system(normalize(request.args.get('cmd')))\n"),
            })
            report = symbolic_engine35.analyze_repository(root)
        self.assertEqual(len(report["findings"]), 1)
        self.assertGreaterEqual(report["metrics"]["call_contexts"], 1)

    def test_loop_preserves_taint_and_reports_widening_limit(self):
        report = symbolic_engine35.analyze_source(
            "from flask import request\nimport os\n"
            "def run(items):\n"
            "    command = request.args.get('cmd')\n"
            "    for item in items:\n"
            "        command = command.strip()\n"
            "    os.system(command)\n",
            max_loop_iterations=1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["status"], "partial")
        self.assertIn("max_loop_iterations", report["limits"]["hit"])
        self.assertEqual(report["metrics"]["loop_widenings"], 1)

    def test_state_limit_widens_instead_of_dropping_unsafe_branch(self):
        report = symbolic_engine35.analyze_source(
            "from flask import request\nimport os\n"
            "def run(flag):\n"
            "    command = request.args.get('cmd')\n"
            "    if flag:\n"
            "        command = 'status'\n"
            "    else:\n"
            "        command = command.strip()\n"
            "    os.system(command)\n",
            max_states=1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["status"], "partial")
        self.assertIn("max_states", report["limits"]["hit"])

    def test_recursive_call_limit_is_explicit_and_taint_is_not_erased(self):
        report = symbolic_engine35.analyze_source(
            "import os\n"
            "def bounce(value):\n"
            "    return bounce(value)\n"
            "def run():\n"
            "    os.system(bounce(input()))\n",
            max_call_depth=1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["status"], "partial")
        self.assertTrue({"max_call_depth", "recursive_call_widening"} &
                        set(report["limits"]["hit"]))

    def test_call_context_limit_widens_and_preserves_taint(self):
        report = symbolic_engine35.analyze_source(
            "import os\n"
            "def identity(value):\n"
            "    return value\n"
            "def run():\n"
            "    identity('first context')\n"
            "    os.system(identity(input()))\n",
            max_call_contexts=1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["status"], "partial")
        self.assertIn("max_call_contexts", report["limits"]["hit"])

    def test_dynamic_sql_query_is_a_sink_but_bound_parameters_are_not(self):
        unsafe = symbolic_engine35.analyze_source(
            "from flask import request\n"
            "def run(cursor):\n"
            "    cursor.execute('SELECT ' + request.args.get('column'))\n")
        safe = symbolic_engine35.analyze_source(
            "from flask import request\n"
            "def run(cursor):\n"
            "    value = request.args.get('value')\n"
            "    cursor.execute('SELECT * FROM t WHERE id=?', (value,))\n")
        self.assertEqual(len(unsafe["findings"]), 1)
        self.assertEqual(unsafe["findings"][0]["rule"], "symbolic-taint/sql")
        self.assertEqual(safe["findings"], [])

    def test_step_limit_is_explicit_not_silently_complete(self):
        source = "def f():\n" + "\n".join("    x%d = %d" % (i, i) for i in range(20)) + "\n"
        report = symbolic_engine35.analyze_source(source, max_steps=5)
        self.assertEqual(report["status"], "partial")
        self.assertIn("max_steps", report["limits"]["hit"])


class RepositoryBoundaryTests(unittest.TestCase):
    def test_parse_error_is_explicit_partial_coverage(self):
        report = symbolic_engine35.analyze_source("def broken(:\n")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["metrics"]["parse_errors"], 1)
        self.assertEqual(report["findings"], [])

    def test_file_limit_is_explicit_and_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {"b.py": "def b(): return 2\n",
                                 "a.py": "def a(): return 1\n"})
            first = symbolic_engine35.analyze_repository(root, max_files=1)
            second = symbolic_engine35.analyze_repository(root, max_files=1)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "partial")
        self.assertEqual(first["metrics"]["files_discovered"], 1)
        self.assertEqual(first["skipped"][0]["reason"], "max_files reached")
        self.assertIn("max_files", first["limits"]["hit"])

    def test_aggregate_byte_limit_stops_before_ast_and_is_explicit(self):
        first_source = "def first():\n    return 1\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "a.py": first_source,
                "b.py": "def second():\n    return 2\n",
            })
            limit = (root / "a.py").stat().st_size
            first = symbolic_engine35.analyze_repository(
                root, max_total_bytes=limit)
            second = symbolic_engine35.analyze_repository(
                root, max_total_bytes=limit)
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "partial")
        self.assertIn("analysis-limits", first["partial_reasons"])
        self.assertIn("coverage-gaps", first["partial_reasons"])
        self.assertIn("max_total_bytes", first["limits"]["hit"])
        self.assertEqual(first["limits"]["input"]["hit"], ["max_total_bytes"])
        self.assertTrue(first["limits"]["input"]["truncated"])
        self.assertEqual(first["metrics"]["files_considered"], 2)
        self.assertEqual(first["metrics"]["files_discovered"], 1)
        self.assertEqual(first["metrics"]["input_bytes"], limit)
        self.assertEqual(first["skipped"][0]["reason"], "max_total_bytes reached")
        self.assertIn(
            "repository input truncated at max_total_bytes",
            first["coverage"]["coverage_gaps"])

    def test_bounded_read_catches_file_growth_after_stat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "a.py"
            target.write_text("x = 1\n", encoding="utf-8")
            original_open = Path.open

            def growing_open(path, mode="r", *args, **kwargs):
                if path == target.resolve() and mode == "rb":
                    return io.BytesIO(b"x" * 1_000_000)
                return original_open(path, mode, *args, **kwargs)

            with mock.patch.object(Path, "open", growing_open):
                report = symbolic_engine35.analyze_repository(
                    root, max_bytes=1024, max_total_bytes=8)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["metrics"]["input_bytes"], 0)
        self.assertIn("max_total_bytes", report["limits"]["hit"])
        self.assertEqual(report["skipped"][0]["candidate_bytes_at_least"], 9)

    def test_invalid_utf8_cannot_bypass_aggregate_read_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_bytes(b"\xff\xfe\xff\xfe")
            (root / "b.py").write_text("value = 1\n", encoding="utf-8")
            report = symbolic_engine35.analyze_repository(
                root, max_total_bytes=4)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["metrics"]["input_bytes"], 4)
        self.assertEqual(report["metrics"]["parse_errors"], 1)
        self.assertIn("max_total_bytes", report["limits"]["hit"])
        self.assertTrue(any(
            row["reason"] == "max_total_bytes reached"
            for row in report["skipped"]))

    def test_in_memory_source_honors_total_byte_boundary(self):
        report = symbolic_engine35.analyze_source(
            "value = 1\n", max_total_bytes=4)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["metrics"]["python_modules_parsed"], 0)
        self.assertEqual(report["metrics"]["input_bytes"], 0)
        self.assertIn("max_total_bytes", report["limits"]["hit"])
        self.assertEqual(report["skipped"][0]["reason"], "max_total_bytes reached")

    def test_worker_forwards_total_byte_boundary(self):
        first_source = "def first():\n    return 1\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "a.py": first_source,
                "b.py": "def second():\n    return 2\n",
            })
            limit = (root / "a.py").stat().st_size
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = symbolic_worker35.main([
                    str(root), "--max-files", "10",
                    "--max-total-bytes", str(limit),
                    "--max-states", "16", "--max-steps", "1000",
                    "--max-contexts", "4",
                ])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(
            report["limits"]["configured"]["max_total_bytes"],
            limit)
        self.assertIn("max_total_bytes", report["limits"]["hit"])

    def test_invalid_limits_and_unknown_options_are_rejected(self):
        with self.assertRaises(ValueError):
            symbolic_engine35.analyze_source("", max_states=0)
        with self.assertRaises(TypeError):
            symbolic_engine35.analyze_source("", imaginary_limit=1)

    def test_non_python_file_target_is_explicitly_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "input.txt")
            path.write_text("not Python", encoding="utf-8")
            report = symbolic_engine35.analyze_repository(path)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["skipped"][0]["reason"], "not a Python source file")


if __name__ == "__main__":
    unittest.main(verbosity=2)
