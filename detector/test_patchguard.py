import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import patchguard


VULNERABLE = "def transform(user):\n    return eval(user)\n"
SAFE = "def transform(user):\n    return user\n"


class PatchGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()

    def write(self, relative, content):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="")
        return path

    def test_resolved_high_finding_is_accepted_with_unified_diff(self):
        self.write("app.py", VULNERABLE)
        report = patchguard.verify_candidate(self.project, "app.py", SAFE)

        self.assertTrue(report.accepted, report.reasons)
        self.assertEqual({item.rule for item in report.resolved_issues},
                         {"dangerous-eval"})
        self.assertFalse(report.new_issues)
        self.assertIn("--- a/app.py", report.diff)
        self.assertIn("+++ b/app.py", report.diff)
        self.assertEqual(report.candidate.verification, "verified")

    def test_exact_file_scope_does_not_copy_or_hash_siblings(self):
        self.write("app.py", VULNERABLE)
        sibling = self.write("sibling.py", "VALUE = 1\n")
        with mock.patch.object(
                patchguard, "_copy_project",
                side_effect=AssertionError("project copy must not run")), \
                mock.patch.object(
                    patchguard, "_project_manifest",
                    side_effect=AssertionError("project manifest must not run")):
            report = patchguard.verify_candidate(
                self.project, "app.py", SAFE, exact_file_scope=True)
        self.assertTrue(report.accepted, report.reasons)
        self.assertEqual(report.verification_scope, "exact-file")

        sibling.write_text("VALUE = 2\n", encoding="utf-8", newline="")
        applied = patchguard.apply_candidate(
            report, SAFE, authorized=True, backup_root=self.base / "backups")
        self.assertTrue(applied.applied)

    def test_exact_file_scope_refuses_project_test_execution(self):
        self.write("app.py", VULNERABLE)
        with self.assertRaises(PermissionError):
            patchguard.verify_candidate(
                self.project, "app.py", SAFE, exact_file_scope=True,
                test_command=[sys.executable, "-c", "pass"],
                authorize_tests=True)

    def test_new_high_finding_and_syntax_error_are_rejected(self):
        self.write("app.py", SAFE)
        unsafe = patchguard.verify_candidate(self.project, "app.py", VULNERABLE)
        broken = patchguard.verify_candidate(
            self.project, "app.py", "def transform(:\n    pass\n")

        self.assertFalse(unsafe.accepted)
        self.assertIn("dangerous-eval", {item.rule for item in unsafe.new_issues})
        self.assertTrue(unsafe.high_regressions)
        self.assertIn("candidate introduced new static findings", unsafe.reasons)
        self.assertFalse(broken.accepted)
        self.assertIn("candidate failed its syntax/compiler check", broken.reasons)

    @unittest.skipUnless(
        shutil.which("clang") or shutil.which("gcc"), "C compiler unavailable")
    def test_native_candidate_must_pass_real_compiler(self):
        self.write("main.c", "int value(void) { return 1; }\n")
        report = patchguard.verify_candidate(
            self.project, "main.c", "int value(void) { return 1 }\n")

        self.assertFalse(report.accepted)
        self.assertEqual(report.candidate.verification, "failed")
        self.assertIn("candidate failed its syntax/compiler check", report.reasons)

    def test_target_must_stay_inside_project_and_avoid_links(self):
        self.write("app.py", SAFE)
        with self.assertRaises(ValueError):
            patchguard.verify_candidate(self.project, "../app.py", SAFE)
        with self.assertRaises(ValueError):
            patchguard.verify_candidate(self.project, str(self.project / "app.py"), SAFE)

        link = self.project / "linked.py"
        try:
            link.symlink_to(self.project / "app.py")
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(ValueError):
            patchguard.verify_candidate(self.project, "linked.py", SAFE)

    def test_authorized_tests_run_in_copy_with_minimal_environment(self):
        self.write("app.py", SAFE)
        candidate = "def transform(user):\n    return user.strip()\n"
        code = (
            "import os; from pathlib import Path; "
            "assert 'ATTESTOR_TEST_SECRET' not in os.environ; "
            "assert 'user.strip()' in Path('app.py').read_text(); "
            "Path('sandbox-marker').write_text('isolated')"
        )
        with mock.patch.dict(os.environ, {"ATTESTOR_TEST_SECRET": "must-not-leak"}):
            report = patchguard.verify_candidate(
                self.project, "app.py", candidate,
                test_command=[sys.executable, "-c", code], authorize_tests=True,
            )

        self.assertTrue(report.accepted, report.reasons)
        self.assertEqual(report.test.status, "passed")
        self.assertFalse((self.project / "sandbox-marker").exists())
        self.assertEqual((self.project / "app.py").read_text(encoding="utf-8"), SAFE)

    def test_tests_require_explicit_authorization_and_argv(self):
        self.write("app.py", SAFE)
        with self.assertRaises(PermissionError):
            patchguard.verify_candidate(
                self.project, "app.py", SAFE,
                test_command=[sys.executable, "-c", "pass"],
            )
        with self.assertRaises(PermissionError):
            patchguard.run_test_command([sys.executable, "-c", "pass"], self.project)
        with self.assertRaises(TypeError):
            patchguard.run_test_command(
                "%s -c pass" % sys.executable, self.project, authorized=True)

    def test_test_output_and_runtime_are_bounded(self):
        output = patchguard.run_test_command(
            [sys.executable, "-c",
             "import sys; sys.stdout.write('x'*20000); sys.stderr.write('y'*20000)"],
            self.project, authorized=True, max_output=128,
        )
        timeout = patchguard.run_test_command(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            self.project, authorized=True, timeout=0.08, max_output=128,
        )

        self.assertTrue(output.passed)
        self.assertTrue(output.truncated)
        captured_stdout = output.stdout.split("\n[output truncated", 1)[0]
        captured_stderr = output.stderr.split("\n[output truncated", 1)[0]
        self.assertLessEqual(len(captured_stdout.encode()) + len(captured_stderr.encode()), 128)
        self.assertTrue(timeout.timed_out)
        self.assertEqual(timeout.status, "failed")
        self.assertLess(timeout.elapsed_ms, 1500)

    def test_test_cannot_rewrite_candidate_behind_the_gate(self):
        self.write("app.py", SAFE)
        command = [
            sys.executable, "-c",
            "from pathlib import Path; Path('app.py').write_text('changed')",
        ]
        report = patchguard.verify_candidate(
            self.project, "app.py", SAFE + "\n",
            test_command=command, authorize_tests=True,
        )
        self.assertFalse(report.accepted)
        self.assertIn("test command modified the candidate target", report.reasons)
        self.assertEqual((self.project / "app.py").read_text(encoding="utf-8"), SAFE)

    def test_existing_unrelated_compiler_failure_is_not_a_new_regression(self):
        self.write("app.py", SAFE)
        self.write("already_broken.py", "def broken(:\n")
        candidate = SAFE.replace("return user", "return user.strip()")
        report = patchguard.verify_candidate(self.project, "app.py", candidate)

        self.assertTrue(report.accepted, report.reasons)
        self.assertEqual(report.candidate.verification, "verified")
        self.assertFalse(report.new_failures)

    def test_candidates_are_ranked_with_accepted_patch_first(self):
        self.write("app.py", VULNERABLE)
        ranked = patchguard.rank_candidates(self.project, "app.py", {
            "broken": "def transform(:\n",
            "good": SAFE,
            "still-vulnerable": VULNERABLE,
        })

        self.assertEqual(ranked[0].name, "good")
        self.assertTrue(ranked[0].accepted)
        self.assertGreater(ranked[0].score, ranked[-1].score)

    def test_regression_artifact_is_explicit_and_compilable(self):
        self.write("app.py", VULNERABLE)
        report = patchguard.verify_candidate(self.project, "app.py", SAFE)
        artifact = patchguard.generate_regression_test_artifact(report)

        self.assertIn("dangerous-eval", artifact.rules)
        self.assertIn("CONFIRMED_CAPS", artifact.content)
        compile(artifact.content, artifact.suggested_path, "exec")
        with self.assertRaises(PermissionError):
            patchguard.write_regression_test_artifact(self.project, artifact)
        output = patchguard.write_regression_test_artifact(
            self.project, artifact, authorized=True)
        self.assertTrue(output.is_file())
        with self.assertRaises(FileExistsError):
            patchguard.write_regression_test_artifact(
                self.project, artifact, authorized=True)

        # The generated artifact is executable and detects recurrence, rather
        # than being a metadata-only report.
        self.write("app.py", SAFE)
        namespace = {"__name__": "generated_regression", "__file__": str(output)}
        with mock.patch.dict(os.environ, {"ATTESTOR_PROJECT_ROOT": str(self.project)}):
            exec(compile(artifact.content, str(output), "exec"), namespace)  # noqa: S102
            passing = unittest.TestResult()
            namespace["AttestorPatchRegression"](
                "test_confirmed_findings_do_not_recur").run(passing)
        self.assertTrue(passing.wasSuccessful(), passing.failures)

        self.write("app.py", VULNERABLE)
        with mock.patch.dict(os.environ, {"ATTESTOR_PROJECT_ROOT": str(self.project)}):
            failing = unittest.TestResult()
            namespace["AttestorPatchRegression"](
                "test_confirmed_findings_do_not_recur").run(failing)
        self.assertFalse(failing.wasSuccessful())

    def test_apply_requires_consent_then_supports_integrity_checked_rollback(self):
        target = self.write("app.py", VULNERABLE)
        report = patchguard.verify_candidate(self.project, "app.py", SAFE)
        with self.assertRaises(PermissionError):
            patchguard.apply_candidate(report, SAFE)

        applied = patchguard.apply_candidate(
            report, SAFE, authorized=True, backup_root=self.base / "backups")
        self.assertTrue(applied.applied)
        self.assertEqual(target.read_text(encoding="utf-8"), SAFE)
        self.assertEqual(Path(applied.backup).read_text(encoding="utf-8"), VULNERABLE)
        with self.assertRaises(PermissionError):
            patchguard.rollback_apply(applied)

        rolled_back = patchguard.rollback_apply(applied, authorized=True)
        self.assertTrue(rolled_back.rolled_back)
        self.assertEqual(target.read_text(encoding="utf-8"), VULNERABLE)

    def test_stale_apply_is_refused(self):
        target = self.write("app.py", VULNERABLE)
        report = patchguard.verify_candidate(self.project, "app.py", SAFE)
        target.write_text("# user changed it\n" + VULNERABLE, encoding="utf-8", newline="")
        with self.assertRaises(RuntimeError):
            patchguard.apply_candidate(
                report, SAFE, authorized=True, backup_root=self.base / "backups")

    def test_apply_refuses_changes_elsewhere_in_verified_project(self):
        self.write("app.py", VULNERABLE)
        dependency = self.write("dependency.py", "VALUE = 1\n")
        report = patchguard.verify_candidate(self.project, "app.py", SAFE)
        dependency.write_text("VALUE = 2\n", encoding="utf-8", newline="")

        with self.assertRaises(RuntimeError):
            patchguard.apply_candidate(
                report, SAFE, authorized=True, backup_root=self.base / "backups")

    def test_failed_post_apply_check_restores_original(self):
        target = self.write("app.py", VULNERABLE)
        report = patchguard.verify_candidate(self.project, "app.py", SAFE)
        with mock.patch.object(
                patchguard, "_post_apply_check", return_value=(False, "forced failure")):
            result = patchguard.apply_candidate(
                report, SAFE, authorized=True, backup_root=self.base / "backups")

        self.assertFalse(result.applied)
        self.assertTrue(result.rolled_back)
        self.assertEqual(target.read_text(encoding="utf-8"), VULNERABLE)

    def test_cli_is_dry_run_unless_apply_is_present(self):
        target = self.write("app.py", VULNERABLE)
        candidate = self.base / "candidate.py"
        candidate.write_text(SAFE, encoding="utf-8", newline="")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = patchguard.main([
                str(self.project), "app.py", str(candidate),
            ])

        self.assertEqual(status, 0)
        self.assertIn("DRY RUN", stdout.getvalue())
        self.assertEqual(target.read_text(encoding="utf-8"), VULNERABLE)

    def test_cli_test_command_requires_run_tests_flag(self):
        self.write("app.py", SAFE)
        candidate = self.base / "candidate.py"
        candidate.write_text(SAFE, encoding="utf-8", newline="")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                patchguard.main([
                    str(self.project), "app.py", str(candidate),
                    "--test-command", sys.executable, "-c", "pass",
                ])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
