#!/usr/bin/env python3
"""
Tests for codegen.py -- Attestor's scaffolding code generator.

These prove the generator's three promises: it writes >1000 lines of *valid*
Python, the generated service's own tests pass, and the output is clean enough
that Attestor's detector finds nothing in it.
"""
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
import ast
import json
import os

import codegen
import deepscan
import detect


class ForceCleanTests(unittest.TestCase):
    """--force replaces a previous generation; it does not empty a directory."""

    FILES = {"app.py": "print(1)\n", "pkg/mod.py": "X = 1\n"}
    # Enough of the signature to be recognised as a previous generation.
    SIGNATURE = ("manage.py", "config.py", "Makefile")

    @staticmethod
    def _put(directory, relative, content="x"):
        path = os.path.join(directory, relative.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)

    def write_into(self, populate):
        with tempfile.TemporaryDirectory() as raw:
            out = os.path.join(raw, "service")
            os.mkdir(out)
            populate(out)
            try:
                codegen.write_files(self.FILES, out, force=True)
                wrote, message = True, ""
            except SystemExit as exc:
                wrote, message = False, str(exc)
            survivors = set()
            for root, _dirs, names in os.walk(out):
                for name in names:
                    survivors.add(os.path.relpath(
                        os.path.join(root, name), out).replace(os.sep, "/"))
            return wrote, message, survivors

    def mark_generated(self, out, paths):
        self._put(out, codegen._GENERATION_MARKER, json.dumps({
            "schema": codegen._GENERATION_SCHEMA,
            "generator_version": codegen.GENERATED_VERSION,
            "paths": sorted(paths),
        }, sort_keys=True, separators=(",", ":")) + "\n")

    def test_regenerating_over_a_previous_generation_is_allowed(self):
        def populate(out):
            self._put(out, "app.py", "stale")
            for name in self.SIGNATURE:
                self._put(out, name)
            self.mark_generated(out, {"app.py", *self.SIGNATURE})
        wrote, _, survivors = self.write_into(populate)
        self.assertTrue(wrote)
        self.assertEqual(survivors, {"app.py", "pkg/mod.py"})

    def test_orphans_of_an_earlier_spec_are_still_removed(self):
        # A previous generation's leftovers must not survive a regenerate;
        # that is the whole point of --force.
        def populate(out):
            for name in self.SIGNATURE:
                self._put(out, name)
            self._put(out, "models/oldthing.py", "stale")
            self.mark_generated(out, {*self.SIGNATURE,
                                      "models/oldthing.py"})
        wrote, _, survivors = self.write_into(populate)
        self.assertTrue(wrote)
        self.assertNotIn("models/oldthing.py", survivors)

    def test_runtime_databases_and_logs_are_never_silently_deleted(self):
        def populate(out):
            self._put(out, "app.py", "stale")
            self._put(out, "__pycache__/app.cpython-311.pyc")
            self._put(out, "service.db")
            self._put(out, "server.log")
        wrote, message, survivors = self.write_into(populate)
        self.assertFalse(wrote)
        self.assertIn("service.db", message)
        self.assertIn("server.log", message)
        self.assertIn("service.db", survivors)
        self.assertIn("server.log", survivors)

    def test_common_service_filenames_are_not_generation_provenance(self):
        def populate(out):
            for name in self.SIGNATURE:
                self._put(out, name, "important")
        wrote, message, survivors = self.write_into(populate)
        self.assertFalse(wrote)
        self.assertIn("Makefile", message)
        self.assertTrue(set(self.SIGNATURE).issubset(survivors))

    def test_an_unrelated_file_refuses_the_clean_and_survives(self):
        def populate(out):
            self._put(out, "app.py", "stale")
            self._put(out, "THESIS.docx", "years of work")
        wrote, message, survivors = self.write_into(populate)
        self.assertFalse(wrote)
        self.assertIn("THESIS.docx", message)
        self.assertIn("would not regenerate", message)
        self.assertIn("THESIS.docx", survivors)

    def test_a_directory_attestor_never_generated_is_refused_entirely(self):
        wrote, _, survivors = self.write_into(
            lambda out: self._put(out, "notes.txt", "important"))
        self.assertFalse(wrote)
        self.assertEqual(survivors, {"notes.txt"})

    def test_nested_unrelated_content_is_also_protected(self):
        wrote, _, survivors = self.write_into(
            lambda out: self._put(out, "docs/private/report.md", "keep"))
        self.assertFalse(wrote)
        self.assertIn("docs/private/report.md", survivors)

    def test_force_is_still_required_for_a_non_empty_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            out = os.path.join(raw, "service")
            os.mkdir(out)
            self._put(out, "app.py", "stale")
            with self.assertRaises(SystemExit) as caught:
                codegen.write_files(self.FILES, out, force=False)
            self.assertIn("--force", str(caught.exception))


class CodegenTests(unittest.TestCase):
    def test_generates_a_substantial_service(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        self.assertGreater(codegen.total_lines(files), 3500)
        self.assertGreaterEqual(len(files), 80)

    def test_resources_flag_can_reach_10k_lines(self):
        # dial the resource count up; the fixed library stays, resources repeat
        files = codegen.generate(codegen.big_spec(20))
        self.assertGreater(codegen.total_lines(files), 10000)

    def test_resource_count_must_be_positive(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                codegen.big_spec(value)

    def test_infrastructure_modules_present(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        for expected in ("security.py", "accounts.py", "ratelimit.py", "cache.py",
                         "metrics.py", "retry.py", "validators.py", "pagination.py",
                         "middleware.py", "errors.py", "openapi.py", "health.py",
                         "manage.py", "seed.py", "tests/test_integration.py",
                         "tests/test_auth.py", ".github/workflows/ci.yml",
                         # the new "batteries" library
                         "querybuilder.py", "migrations.py", "router.py", "di.py",
                         "events.py", "jobs.py", "circuitbreaker.py", "structlog.py",
                         "result.py", "datastructures.py"):
            self.assertIn(expected, files)

    def test_generated_python_compiles(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        for rel, content in files.items():
            if rel.endswith(".py"):
                compile(content, rel, "exec")     # SyntaxError => test failure

    def test_attestor_approves_his_own_output(self):
        with tempfile.TemporaryDirectory() as d:
            codegen.write_files(codegen.generate(codegen.DEFAULT_SPEC), d, force=True)
            findings = []
            for path in detect.collect_paths([d]):
                findings += detect.scan_file(path)
            self.assertEqual(
                findings, [],
                msg=f"detector flagged generated code: {[(f.rule, f.line) for f in findings]}")

    def test_deepscan_approves_his_own_output(self):
        # the AST engine must also find nothing -- no undefined names, no unused
        # imports, no dead code in anything the generator emits.
        files = codegen.generate(codegen.DEFAULT_SPEC)
        findings = []
        for rel, content in files.items():
            if rel.endswith(".py"):
                findings += deepscan.analyze(content, rel)
        self.assertEqual(
            findings, [],
            msg=f"deepscan flagged generated code: {[(f.rule, f.path, f.line) for f in findings]}")

    def test_generated_service_tests_pass(self):
        with tempfile.TemporaryDirectory() as d:
            codegen.write_files(codegen.generate(codegen.DEFAULT_SPEC), d, force=True)
            r = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                cwd=d, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, msg=(r.stderr or "")[-600:])

    def test_generated_auth_requires_configured_secret_when_enabled(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        self.assertIn("SECRET_KEY_CONFIGURED", files["config.py"])
        self.assertIn("SECRET_KEY must be set", files["app.py"])
        self.assertIn("SECRET_KEY must contain at least 32 bytes", files["app.py"])
        self.assertIn("integration-test-secret-at-least-32-bytes",
                      files["tests/test_integration.py"])

    def test_generated_service_is_secure_by_default(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        self.assertIn('REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true")',
                      files["config.py"])
        self.assertIn("REQUIRE_AUTH=true", files["Dockerfile"])
        self.assertIn("USER appuser", files["Dockerfile"])
        self.assertIn('VOLUME ["/data"]', files["Dockerfile"])
        self.assertNotIn("SECRET_KEY=", files["Dockerfile"])
        self.assertIn("does NOT auto-load .env", files[".env.example"])
        self.assertIn("MAX_BODY_BYTES=1048576", files[".env.example"])

    def test_generated_server_enforces_resource_limits(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        app = files["app.py"]
        self.assertIn("ThreadingHTTPServer", app)
        self.assertIn("threading.BoundedSemaphore(max_workers)", app)
        self.assertIn("daemon_threads = False", app)
        self.assertIn("block_on_close = True", app)
        self.assertIn("self._discard_body()", app)
        self.assertIn("self.wfile.flush()", app)
        self.assertIn("request.settimeout(self.request_timeout)", app)
        self.assertIn("length > self.server.max_body_bytes", app)
        self.assertIn("PayloadTooLarge", app)
        self.assertIn("RequestTimeout", files["errors.py"])

    def test_generated_metadata_matches_python_syntax_and_dependencies(self):
        files = codegen.generate(codegen.DEFAULT_SPEC)
        for rel, content in files.items():
            if rel.endswith(".py"):
                ast.parse(content, filename=rel, feature_version=(3, 8))
        self.assertIn('requires-python = ">=3.8"', files["pyproject.toml"])
        self.assertIn("dependencies = []", files["pyproject.toml"])
        self.assertIn("Requires Python >= 3.8", files["requirements.txt"])
        self.assertIn('version = "3.1.0"', files["pyproject.toml"])

    def test_force_refuses_untracked_stale_file_then_replaces_owned_output(self):
        first = {"resources": [{"name": "OldThing", "fields": {"name": "str"}}]}
        second = {"resources": [{"name": "NewThing", "fields": {"name": "str"}}]}
        with tempfile.TemporaryDirectory() as d:
            codegen.write_files(codegen.generate(first), d, force=True)
            stale_dir = os.path.join(d, "stale")
            os.makedirs(stale_dir)
            with open(os.path.join(stale_dir, "leftover.txt"), "w", encoding="utf-8") as fh:
                fh.write("stale")
            with self.assertRaises(SystemExit) as caught:
                codegen.write_files(codegen.generate(second), d, force=True)
            self.assertIn("stale/leftover.txt", str(caught.exception).replace("\\", "/"))
            self.assertTrue(os.path.exists(os.path.join(d, "models", "oldthing.py")))
            os.unlink(os.path.join(stale_dir, "leftover.txt"))
            os.rmdir(stale_dir)
            codegen.write_files(codegen.generate(second), d, force=True)
            self.assertFalse(os.path.exists(os.path.join(d, "models", "oldthing.py")))
            self.assertFalse(os.path.exists(stale_dir))
            self.assertTrue(os.path.isfile(os.path.join(d, "models", "newthing.py")))

    def test_force_validates_paths_before_cleaning(self):
        with tempfile.TemporaryDirectory() as d:
            sentinel = os.path.join(d, "keep.txt")
            with open(sentinel, "w", encoding="utf-8") as fh:
                fh.write("keep")
            with self.assertRaises(ValueError):
                codegen.write_files({"../escape.py": "pass\n"}, d, force=True)
            self.assertTrue(os.path.isfile(sentinel))
        with self.assertRaises(SystemExit):
            codegen._clean_output_dir(".")

    def test_check_gate_compiles_tests_and_scans(self):
        spec = {"resources": [{"name": "Widget", "fields": {"label": "str"}}]}
        with tempfile.TemporaryDirectory() as d:
            codegen.write_files(codegen.generate(spec), d, force=True)
            output = StringIO()
            with redirect_stdout(output):
                passed = codegen.check_generated(d, timeout=120)
            self.assertTrue(passed, output.getvalue())
            self.assertIn("compiled", output.getvalue())
            self.assertIn("generated tests passed", output.getvalue())
            self.assertIn("deepscan: 0", output.getvalue())

    def test_generated_integration_is_reliable_when_repeated(self):
        spec = {"resources": [{"name": "Widget", "fields": {"label": "str"}}]}
        with tempfile.TemporaryDirectory() as d:
            codegen.write_files(codegen.generate(spec), d, force=True)
            for attempt in range(5):
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "unittest",
                     "tests.test_integration", "-q"],
                    cwd=d, capture_output=True, text=True, timeout=60)
                self.assertEqual(
                    result.returncode, 0,
                    msg="integration attempt %d failed:\n%s" %
                        (attempt + 1, (result.stdout + result.stderr)[-2000:]))

    def test_custom_spec(self):
        spec = {"resources": [{"name": "Widget",
                               "fields": {"label": "str", "qty": "int"}}]}
        files = codegen.generate(spec)
        self.assertIn("models/widget.py", files)
        compile(files["models/widget.py"], "widget.py", "exec")

    def test_bad_specs_fail_fast_with_plain_errors(self):
        # found by the smoke test: these used to traceback mid-generation
        cases = [
            ({}, "resources"),
            ({"resources": []}, "resources"),
            ({"resources": [{"name": "X", "fields": {"a": "datetime"}}]}, "datetime"),
            ({"resources": [{"name": "X", "fields": {"a": ["str"]}}]}, "unknown type"),
            ({"resources": [{"name": "bad name", "fields": {"a": "str"}}]}, "identifier"),
            ({"resources": [{"name": "X", "fields": {}}]}, "fields"),
            ({"resources": [{"name": "X", "fields": {"not a name": "str"}}]}, "field name"),
            ({"resources": [{"name": "class", "fields": {"value": "str"}}]},
             "Python keyword"),
            ({"resources": [{"name": "Class", "fields": {"value": "str"}}]},
             "Python keyword"),
            ({"resources": [{"name": "Account", "fields": {"value": "str"}}]},
             "accounts subsystem"),
            ({"resources": [{"name": "Accounts", "fields": {"value": "str"}}]},
             "accounts subsystem"),
            ({"resources": [{"name": "X", "fields": {"id": "int"}}]},
             "primary key"),
            ({"resources": [{"name": "X", "fields": {"self": "str"}}]},
             "method parameters"),
            ({"resources": [{"name": "X", "fields": {"to_dict": "str"}}]},
             "model API"),
            ({"resources": [{"name": "X", "fields": {"class": "str"}}]},
             "Python keyword"),
            ({"resources": [
                {"name": "User", "fields": {"value": "str"}},
                {"name": "user", "fields": {"value": "str"}}]},
             "normalize to the same name"),
            ({"resources": [{"name": "X", "fields": {"Name": "str", "name": "str"}}]},
             "normalize to the same name"),
        ]
        for spec, needle in cases:
            with self.assertRaises(ValueError) as ctx:
                codegen.generate(spec)
            self.assertIn(needle, str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
