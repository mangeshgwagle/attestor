"""CLI contract checks: help, routing, trusted startup, and JSON output."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent


def load_cli(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT_CLI = load_cli("attestor_interface_root", ROOT / "attestor_cli.py")
CLI = load_cli("attestor_interface_installed", ROOT / "detector" / "cli.py")


class CliInterfaceTests(unittest.TestCase):
    def invoke(self, module, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = module.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_help_is_short_and_points_to_assessment_workflow(self):
        for module in (ROOT_CLI, CLI):
            with self.subTest(module=module.__name__):
                code, out, err = self.invoke(module, [])
                self.assertEqual(code, 0)
                self.assertLess(len(out.splitlines()), 30)
                for command in ("security", "ui", "check", "report", "help <command>"):
                    self.assertIn(command, out)
                self.assertEqual(err, "")

    def test_help_command_shows_subcommand_options(self):
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(ROOT / "detector" / "cli.py"),
             "help", "check"], capture_output=True, text=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("--effort", completed.stdout)
        self.assertIn("--json", completed.stdout)

    def test_unknown_command_has_suggestion_and_json_is_one_object(self):
        for module in (ROOT_CLI, CLI):
            code, out, err = self.invoke(module, ["securty", "--json"])
            self.assertEqual(code, 2)
            payload = json.loads(out)
            self.assertIn("security", payload["error"])
            self.assertEqual(payload["exit_code"], 2)
            self.assertEqual(err, "")

    def test_list_filters_and_outputs_clean_json(self):
        for module in (ROOT_CLI, CLI):
            code, out, err = self.invoke(module, ["list", "security", "--json"])
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertTrue(payload["commands"])
            self.assertTrue(all("security" in (r["command"] + r["description"])
                                for r in payload["commands"]))
            self.assertEqual(err, "")

    def test_invalid_system_option_is_a_json_usage_error(self):
        for module in (ROOT_CLI, CLI):
            code, out, err = self.invoke(module, ["status", "--json", "--bogus"])
            self.assertEqual(code, 2)
            self.assertIn("unrecognized", json.loads(out)["error"])
            self.assertEqual(err, "")

    def test_version_json_contains_no_banner(self):
        for module in (ROOT_CLI, CLI):
            code, out, err = self.invoke(module, ["--version", "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["version"], module.VERSION)
            self.assertEqual(err, "")

    def test_status_reports_missing_components_instead_of_claiming_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(ROOT_CLI, "ROOT", Path(directory)), \
                    mock.patch.object(ROOT_CLI, "DETECTOR", Path(directory) / "detector"):
                code, out, err = self.invoke(ROOT_CLI, ["status", "--json"])
                self.assertEqual(code, 0)
                self.assertFalse(json.loads(out)["ok"])
                self.assertEqual(err, "")
                code, out, _ = self.invoke(ROOT_CLI, ["doctor", "--json"])
                self.assertEqual(code, 4)
                self.assertFalse(json.loads(out)["ok"])

    def test_root_routes_security_and_ui_with_arguments_intact(self):
        for command, module in (("security", "security_assessment"), ("ui", "attestor_ui")):
            with mock.patch.object(ROOT_CLI, "_run_detector_module", return_value=3) as runner:
                result = ROOT_CLI.main([command, "--out", "folder with spaces"])
                self.assertEqual(result, 3)
                runner.assert_called_once_with(module, ["--out", "folder with spaces"])

    def test_installed_entrypoint_routes_without_parsing_backend_arguments(self):
        for command, name in (("security", "security_assessment"), ("ui", "attestor_ui")):
            backend = types.SimpleNamespace(main=mock.Mock(return_value=3))
            with mock.patch.dict(sys.modules, {name: backend}):
                result = CLI.main([command, "--out", "folder with spaces"])
            self.assertEqual(result, 3)
            backend.main.assert_called_once_with(["--out", "folder with spaces"])

    def test_verify_executes_the_pinned_backup_and_preserves_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            backup = location / "attestor_cli.py.bak"
            backup.write_text("import sys\nraise SystemExit(3 if sys.argv[1:] == ['verify'] else 9)\n",
                              encoding="utf-8")
            (location / "attestor_cli.py.bak.sha256").write_text(
                hashlib.sha256(backup.read_bytes()).hexdigest(), encoding="utf-8")
            with mock.patch.object(ROOT_CLI, "ROOT", location):
                self.assertEqual(ROOT_CLI.main(["verify"]), 3)

    def test_scan_and_verify_refuse_a_changed_backup_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            (location / "attestor_cli.py.bak").write_text("raise RuntimeError('should not execute')")
            (location / "attestor_cli.py.bak.sha256").write_text("0" * 64)
            with mock.patch.object(ROOT_CLI, "ROOT", location), \
                    mock.patch.object(ROOT_CLI.subprocess, "run") as child:
                for command in ("scan", "verify"):
                    code, out, err = self.invoke(ROOT_CLI, [command, "--json"])
                    self.assertEqual(code, 4)
                    self.assertIn("integrity", json.loads(out)["error"])
                    self.assertEqual(err, "")
                child.assert_not_called()

    def test_check_json_is_clean_and_scanner_failures_are_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "clean.py"
            source.write_text("answer = 42\n", encoding="utf-8")
            code, out, err = self.invoke(CLI, ["check", directory, "--effort", "low", "--json"])
            self.assertEqual(code, 0, err + out)
            self.assertEqual(json.loads(out)["status"], "clean")
            self.assertEqual(err, "")

            def unavailable(*_args):
                CLI._scan_errors[:] = ["core: scanner unavailable"]
                return []

            with mock.patch.object(CLI, "_run_effort", side_effect=unavailable):
                code, out, err = self.invoke(CLI, ["check", directory, "--json"])
            self.assertEqual(code, 3)
            payload = json.loads(out)
            self.assertEqual(payload["status"], "incomplete")
            self.assertEqual(payload["scanner_errors"], ["core: scanner unavailable"])
            self.assertEqual(err, "")

    def test_secret_scan_json_has_no_human_preamble(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "clean.py"
            source.write_text("answer = 42\n", encoding="utf-8")
            code, out, err = self.invoke(CLI, ["secrets", str(source), "--json"])
            self.assertEqual(code, 0, out + err)
            self.assertEqual(json.loads(out), [])
            self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
