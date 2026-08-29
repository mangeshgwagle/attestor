from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "attestor_cli.py"
GATED_COMMANDS = ("review", "fix", "pro", "ui")


class Attestor42UnifiedCliTests(unittest.TestCase):
    def _run(
        self,
        *arguments: str,
        cwd: Path | None = None,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({
            "CI": "1",
            "NO_COLOR": "1",
            "PYTHONPATH": str(
                Path(tempfile.gettempdir()) / "attestor-untrusted-pythonpath"),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-X",
                "utf8",
                str(CLI),
                *arguments,
            ],
            cwd=cwd or Path(tempfile.gettempdir()).resolve(),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

    def _output(self, completed: subprocess.CompletedProcess[str]) -> str:
        return completed.stdout + completed.stderr

    def _assert_no_traceback(
        self, completed: subprocess.CompletedProcess[str]
    ) -> None:
        self.assertNotIn("Traceback", self._output(completed))

    def test_help_lists_the_phase_one_surface(self) -> None:
        completed = self._run("--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = self._output(completed).lower()
        self.assertIn("usage:", output)
        for command in (
                "scan", "lang", "control", "pharma", "lab", "assure",
                "verify", "status"):
            with self.subTest(command=command):
                self.assertIn(command, output)
        self._assert_no_traceback(completed)

    def test_version_and_status_identify_42_and_command_availability(self) -> None:
        version = self._run("--version")
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertIn("4.2", version.stdout)
        self._assert_no_traceback(version)

        status = self._run("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        output = self._output(status).lower()
        self.assertIn("4.2", output)
        for command in (
                "scan", "lang", "control", "pharma", "lab", "assure",
                "verify"):
            with self.subTest(command=command):
                self.assertIn(command, output)
        for command in GATED_COMMANDS:
            with self.subTest(gated_command=command):
                self.assertIn(command, output)
        self.assertIn("history/provenance/lock", output)
        self.assertIn("incomplete", output)
        self._assert_no_traceback(status)

    def test_help_and_status_do_not_require_optional_component_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-standalone-") as directory:
            standalone = Path(directory) / "attestor_cli.py"
            standalone.write_text(
                CLI.read_text(encoding="utf-8"), encoding="utf-8")
            for arguments in (("--help",), ("status",)):
                with self.subTest(arguments=arguments):
                    completed = subprocess.run(
                        [
                            sys.executable, "-I", "-B", "-X", "utf8",
                            str(standalone), *arguments,
                        ],
                        cwd=Path(tempfile.gettempdir()).resolve(),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(
                        completed.returncode, 0, self._output(completed))
                    self._assert_no_traceback(completed)

    def test_missing_scan_target_fails_clearly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-missing-") as directory:
            missing = Path(directory) / "does-not-exist.py"
            completed = self._run("scan", str(missing), "--format", "json")
        self.assertEqual(completed.returncode, 2, self._output(completed))
        output = self._output(completed).lower()
        self.assertTrue(
            any(word in output for word in ("missing", "not exist", "unavailable")),
            output,
        )
        self._assert_no_traceback(completed)

    def test_small_existing_source_scan_is_static_and_uncached(self) -> None:
        target = ROOT / "detector" / "test_version42.py"
        completed = self._run("scan", str(target), "--format", "json")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["files_discovered"], 1)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["cache_hits"], 0)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["skipped"], [])
        self.assertEqual(len(report["files"]), 1)
        scanned = report["files"][0]
        self.assertIs(scanned["cached"], False)
        self.assertEqual(scanned["language"], "python")
        self.assertTrue(scanned["tools"])
        self.assertTrue(all(not check["command"] for check in scanned["tools"]))
        self.assertEqual(
            [(check["name"], check["status"]) for check in scanned["tools"]],
            [("python-compile", "passed")],
        )
        self._assert_no_traceback(completed)

    def test_relative_scan_target_uses_the_callers_working_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-cwd-") as directory:
            caller = Path(directory)
            source = caller / "caller_scope_sample.py"
            source.write_text(
                "def evaluate(user_input):\n"
                "    return eval(user_input)\n",
                encoding="utf-8",
            )
            completed = self._run(
                "scan", ".", "--format", "json", cwd=caller)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "findings")
        self.assertTrue(report["issues"])
        self.assertIn("caller_scope_sample.py", json.dumps(report))
        self._assert_no_traceback(completed)

    def test_scan_rejects_caller_attempts_to_enable_tools_or_cache(self) -> None:
        target = ROOT / "detector" / "test_version42.py"
        for arguments in (
            ("--tools",),
            ("--cache", "caller-selected-cache.json"),
            ("--no-cache",),
        ):
            with self.subTest(arguments=arguments):
                completed = self._run("scan", str(target), *arguments)
                self.assertEqual(completed.returncode, 3, self._output(completed))
                output = self._output(completed).lower()
                self.assertTrue(
                    any(word in output for word in ("disabled", "gated", "policy", "reject")),
                    output,
                )
                self._assert_no_traceback(completed)

    def test_unsupported_and_partially_skipped_scans_exit_incomplete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-unsupported-") as directory:
            empty = Path(directory) / "empty"
            empty.mkdir()
            unsupported = self._run(
                "scan", str(empty), "--format", "json")
            unsupported_report = json.loads(unsupported.stdout)
            self.assertEqual(unsupported_report["status"], "unsupported")
            self.assertEqual(
                unsupported.returncode, 3, self._output(unsupported))
            self._assert_no_traceback(unsupported)

            for output_format in ("markdown", "html"):
                with self.subTest(output_format=output_format):
                    rendered = self._run(
                        "scan", str(empty), "--format", output_format)
                    self.assertEqual(
                        rendered.returncode, 3, self._output(rendered))
                    self.assertIn("incomplete", rendered.stdout.lower())
                    self._assert_no_traceback(rendered)

        with tempfile.TemporaryDirectory(prefix="attestor-cli-partial-") as directory:
            scope = Path(directory)
            (scope / "small.py").write_text("answer = 42\n", encoding="utf-8")
            (scope / "oversized.py").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            partial = self._run(
                "scan", str(scope), "--format", "json")
        partial_report = json.loads(partial.stdout)
        self.assertIn(partial_report["status"], ("clean", "findings"))
        self.assertTrue(partial_report["skipped"])
        self.assertEqual(partial.returncode, 3, self._output(partial))
        self._assert_no_traceback(partial)

    def test_scan_verification_gap_uses_the_stable_incomplete_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-failed-") as directory:
            source = Path(directory) / "invalid.py"
            source.write_text("def broken(:\n", encoding="utf-8")
            completed = self._run(
                "scan", str(source), "--format", "json")
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"], [])
        self.assertTrue(any(
            check["status"] == "failed"
            for file_result in report["files"]
            for check in file_result["tools"]
        ))
        self.assertEqual(completed.returncode, 3, self._output(completed))
        self._assert_no_traceback(completed)

    def test_out_of_scope_source_link_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-link-") as directory:
            base = Path(directory)
            scope = base / "scope"
            scope.mkdir()
            outside = base / "outside.py"
            outside.write_text("outside_secret = 'not-for-this-scan'\n", encoding="utf-8")
            linked = scope / "linked.py"
            try:
                linked.symlink_to(outside)
            except (NotImplementedError, OSError) as exc:
                self.skipTest("file symlinks are unavailable: %s" % type(exc).__name__)
            completed = self._run(
                "scan", str(scope), "--format", "json")
        self.assertEqual(completed.returncode, 2, self._output(completed))
        output = self._output(completed).lower()
        self.assertRegex(output, r"(?:symbolic link|symlink|reparse|link|scope)")
        self._assert_no_traceback(completed)

    def test_scan_rejects_a_regular_file_reached_through_a_linked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-ancestor-") as directory:
            base = Path(directory)
            outside = base / "outside"
            outside.mkdir()
            target = outside / "external.py"
            target.write_text("outside_secret = 'not-for-this-scan'\n", encoding="utf-8")
            linked_parent = base / "linked-parent"
            try:
                linked_parent.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(
                    "directory symlinks are unavailable: %s" % type(exc).__name__)
            completed = self._run(
                "scan", str(linked_parent / target.name), "--format", "json")
        self.assertEqual(completed.returncode, 2, self._output(completed))
        self.assertRegex(
            self._output(completed).lower(),
            r"(?:symbolic link|symlink|reparse|link|scope)")
        self._assert_no_traceback(completed)

    def test_lang_help_is_an_exact_safe_passthrough(self) -> None:
        completed = self._run("lang", "--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("AttestorLang 4.2", completed.stdout)
        self.assertIn("run-bytecode", completed.stdout)
        self._assert_no_traceback(completed)

    def test_lang_passthrough_preserves_argument_boundaries(self) -> None:
        completed = self._run("lang", "encode-a1z26", "HALT")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "8-1-12-20")
        self._assert_no_traceback(completed)

    def test_control_help_is_an_exact_safe_passthrough(self) -> None:
        completed = self._run("control", "--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Attestor 4.2 Owner Control", completed.stdout)
        for command in ("policy", "plan", "run"):
            with self.subTest(command=command):
                self.assertIn(command, completed.stdout)
        self._assert_no_traceback(completed)

    def test_pharma_exposes_formation_reasoning_and_coverage_boundary(self) -> None:
        help_result = self._run("pharma", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("pharmaceutical-formation study", help_result.stdout)

        answer = self._run("pharma", "show", "boric_acid")
        self.assertEqual(answer.returncode, 0, answer.stderr)
        for heading in (
                "PRINCIPLE", "REACTION", "PROCEDURE", "PURIFICATION",
                "IDENTIFICATION", "LIMIT TESTS", "ASSAY", "USES", "STORAGE"):
            with self.subTest(heading=heading):
                self.assertIn(heading, answer.stdout)
        self.assertIn("why:", answer.stdout)
        self.assertIn("NOT A LABORATORY", answer.stdout)

        lesson = self._run("pharma", "teach", "boric acid")
        self.assertEqual(lesson.returncode, 0, lesson.stderr)
        self.assertIn("WORKED EXAM ANSWER", lesson.stdout)
        self.assertIn("TRANSFERABLE REASONING", lesson.stdout)
        self.assertIn("CLOSE THE ANSWER", lesson.stdout)

        coverage = self._run("pharma", "coverage")
        self.assertEqual(coverage.returncode, 0, coverage.stderr)
        self.assertIn("16 worked pharmaceutical substances", coverage.stdout)
        self.assertIn("Not yet bound to a named board", coverage.stdout)

        check = self._run("pharma", "check")
        self.assertEqual(check.returncode, 0, self._output(check))
        self.assertIn("16 preparation entries passed", check.stdout)
        self.assertIn("20 equations conserve atoms", check.stdout)
        for completed in (help_result, answer, lesson, coverage, check):
            self._assert_no_traceback(completed)

    def test_pharma_passthrough_preserves_a_multiword_search(self) -> None:
        completed = self._run("pharma", "find", "boric acid")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("boric_acid", completed.stdout)
        self._assert_no_traceback(completed)

    def test_assure_help_exposes_only_the_reviewed_surface(self) -> None:
        completed = self._run("assure", "--help")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = self._output(completed).lower()
        self.assertIn("directory", output)
        self.assertIn("--format", output)
        self.assertIn("text", output)
        self.assertIn("json", output)
        self.assertNotIn("--execute", output)
        self.assertNotIn("--tools", output)
        self._assert_no_traceback(completed)

    def test_assure_rejects_extra_passthrough_before_child_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-assure-extra-") as directory:
            for forbidden in ("--tools", "--cache", "--out"):
                with self.subTest(forbidden=forbidden):
                    completed = self._run(
                        "assure", directory, forbidden, "blocked",
                        "--format", "json")
                    self.assertEqual(
                        completed.returncode, 2, self._output(completed))
                    self.assertIn(
                        "unrecognized", self._output(completed).lower())
                    self._assert_no_traceback(completed)

    def test_assure_reconstructs_arguments_and_preserves_stable_child_exit(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "attestor_cli42_assure_test_target", CLI)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        previous_dont_write_bytecode = sys.dont_write_bytecode
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous_dont_write_bytecode

        with mock.patch.object(
                module, "_trusted_child", return_value=3) as child:
            code = module.main([
                "assure", "relative folder", "--format", "json"])
        self.assertEqual(code, 3)
        child.assert_called_once_with(
            module.ASSURANCE_CLI,
            ["--format", "json", "--", "relative folder"],
        )

        stderr = io.StringIO()
        with mock.patch.object(
                module, "_trusted_child", return_value=17), \
                redirect_stderr(stderr):
            code = module.main(["assure", "."])
        self.assertEqual(code, 4)
        self.assertIn("invalid exit status", stderr.getvalue())

    def test_assure_runs_from_caller_cwd_with_honest_incomplete_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-assure-cwd-") as directory:
            caller = Path(directory)
            (caller / "safe.py").write_text("answer = 42\n", encoding="utf-8")

            completed = self._run(
                "assure", ".", "--format", "json", cwd=caller)
            self.assertEqual(completed.returncode, 3, self._output(completed))
            report = json.loads(completed.stdout)
            self.assertEqual(report["schema"], "attestor.assurance/4.2-experimental")
            self.assertEqual(report["status"], "incomplete")
            self.assertIs(report["complete"], False)
            self.assertEqual(
                report["coverage"]["status_precedence"],
                "incomplete-outranks-findings",
            )
            self.assertIs(report["execution"]["engine_started_processes"], False)
            self.assertIs(
                report["execution"]["target_or_tool_processes_started"], False)
            self.assertRegex(report["report_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn(str(caller), completed.stdout)
            self._assert_no_traceback(completed)

            rendered = self._run("assure", ".", cwd=caller)
            self.assertEqual(rendered.returncode, 3, self._output(rendered))
            self.assertIn(
                "experimental assurance: incomplete", rendered.stdout.lower())
            self.assertRegex(rendered.stdout, r"report_sha256=[0-9a-f]{64}")
            self._assert_no_traceback(rendered)

    def test_assure_missing_directory_is_invalid_without_a_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-assure-missing-") as directory:
            missing = Path(directory) / "missing"
            completed = self._run(
                "assure", str(missing), "--format", "json")
        self.assertEqual(completed.returncode, 2, self._output(completed))
        self.assertEqual(completed.stdout, "")
        self.assertIn("directory", completed.stderr.lower())
        self._assert_no_traceback(completed)

    def test_verify_propagates_the_current_release_audit_failure(self) -> None:
        completed = self._run("verify")
        self.assertEqual(completed.returncode, 1, self._output(completed))
        report = json.loads(completed.stdout)
        self.assertIs(report["ok"], False)
        self.assertTrue(report["forbidden"])
        self._assert_no_traceback(completed)

    def test_unexpected_scan_exception_uses_operational_exit_without_details(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "attestor_cli42_test_target", CLI)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        previous_dont_write_bytecode = sys.dont_write_bytecode
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous_dont_write_bytecode

        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="attestor-cli-exception-") as directory:
            source = Path(directory) / "small.py"
            source.write_text("answer = 42\n", encoding="utf-8")
            with mock.patch.object(
                    module, "_load_detector_module",
                    side_effect=RuntimeError("private operational detail")), \
                    redirect_stdout(stdout), redirect_stderr(stderr):
                code = module.main([
                    "scan", str(source), "--format", "json"])
        self.assertEqual(code, 4)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("scan failed (RuntimeError)", stderr.getvalue())
        self.assertNotIn("private operational detail", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_verify_is_audit_only_and_cannot_create_an_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="attestor-cli-verify-") as directory:
            archive = Path(directory) / "release.zip"
            completed = self._run("verify", "--archive", str(archive))
            self.assertFalse(archive.exists())
        self.assertEqual(completed.returncode, 2, self._output(completed))
        self.assertIn("archive", self._output(completed).lower())
        self._assert_no_traceback(completed)

        explicit_root = self._run("verify", str(ROOT))
        self.assertEqual(
            explicit_root.returncode, 2, self._output(explicit_root))
        self._assert_no_traceback(explicit_root)

    def test_gated_commands_fail_with_the_stable_gated_exit(self) -> None:
        for command in GATED_COMMANDS:
            with self.subTest(command=command):
                completed = self._run(command)
                self.assertEqual(completed.returncode, 3, self._output(completed))
                output = self._output(completed).lower()
                self.assertIn(command, output)
                self.assertTrue(
                    any(word in output for word in ("unavailable", "disabled", "gated", "phase")),
                    output,
                )
                self._assert_no_traceback(completed)

    def test_launchers_are_isolated_preserve_cwd_and_inject_no_permission(self) -> None:
        for filename in ("attestor.ps1", "attestor.sh"):
            with self.subTest(filename=filename):
                text = (ROOT / filename).read_text(encoding="utf-8")
                normalized = " ".join(text.split())
                self.assertIn("-I -B -X utf8", normalized)
                self.assertIn("attestor_cli.py", text)
                self.assertNotIn("--permission", text)
                self.assertNotRegex(
                    text,
                    re.compile(r"^\s*cd(?:\s|/)", re.MULTILINE | re.IGNORECASE),
                )
                if filename == "attestor.ps1":
                    self.assertIn("@args", text)
                    self.assertNotIn("%*", text)
                else:
                    self.assertIn('$ATTESTOR_LAUNCH_DIR/attestor_cli.py', text)

    @unittest.skipUnless(os.name == "nt", "PowerShell launcher is Windows-only")
    def test_powershell_launcher_preserves_shell_metacharacter_argument(self) -> None:
        completed = subprocess.run(
            [
                "powershell.exe", "-NoLogo", "-NoProfile",
                "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "attestor.ps1"),
                "lang", "encode-a1z26", "A&B",
            ],
            cwd=Path(tempfile.gettempdir()).resolve(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 2, self._output(completed))
        self.assertNotIn("not recognized", self._output(completed).lower())
        self.assertNotIn("Traceback", self._output(completed))


if __name__ == "__main__":
    unittest.main()
