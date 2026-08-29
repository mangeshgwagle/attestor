from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest import mock

import superattestor


class SuperAttestorCJP414Tests(unittest.TestCase):
    def test_perform_forwards_literal_permissions_and_json(self) -> None:
        preview_digest = "a" * 64
        report = {
            "schema": "attestor-cjp-local-control/4.1.4",
            "status": "previewed",
            "action": "preview-file-edit",
        }
        with mock.patch.object(
                superattestor.cjp_control414, "control",
                return_value=report) as run:
            text, code = superattestor.perform(
                {
                    "action": "cjpcontrol414",
                    "request_file": "permission.json",
                },
                output_format="json",
                cjp_permission_confirmed=True,
                cjp_apply=True,
                cjp_apply_confirmed=True,
                cjp_preview_evidence_sha256=preview_digest,
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text), report)
        run.assert_called_once_with(
            "permission.json",
            permission_confirmed=True,
            apply=True,
            apply_confirmed=True,
            preview_evidence_sha256=preview_digest,
        )

    def test_authorization_required_is_a_denied_exit(self) -> None:
        denied = {
            "schema": "attestor-cjp-local-control/4.1.4",
            "status": "authorization-required",
            "action": "none",
        }
        with mock.patch.object(
                superattestor.cjp_control414, "control",
                return_value=denied):
            text, code = superattestor.perform(
                {
                    "action": "cjpcontrol414",
                    "request_file": "never-read.json",
                },
                output_format="json",
            )
        self.assertEqual(code, 2)
        self.assertEqual(
            json.loads(text)["status"], "authorization-required")

    def test_applied_with_incomplete_cleanup_is_a_visible_warning_exit(
            self) -> None:
        hostile = "transaction-lock-cleanup:\x1b[31mOSError"
        applied = {
            "schema": "attestor-cjp-local-control/4.1.4",
            "status": "applied",
            "action": "preview-file-edit",
            "transaction": {
                "status": "applied",
                "backup_directory": "backup",
                "rolled_back": False,
                "cleanup_complete": False,
                "cleanup_errors": [hostile],
            },
        }
        with mock.patch.object(
                superattestor.cjp_control414, "control",
                return_value=applied):
            text, code = superattestor.perform(
                {
                    "action": "cjpcontrol414",
                    "request_file": "permission.json",
                },
                output_format="text",
                cjp_permission_confirmed=True,
            )
        self.assertEqual(code, 1)
        self.assertIn("Cleanup complete: no", text)
        self.assertIn("\\u001b", text)
        self.assertNotIn("\x1b", text)

    def test_cli_forwards_separate_preview_and_apply_confirmations(self) -> None:
        preview_digest = "b" * 64
        with mock.patch.object(
                superattestor, "perform", return_value=("{}", 0)) as perform, \
                mock.patch.object(
                    superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stdout(io.StringIO()):
            code = superattestor.main([
                "--cjp-control",
                "--confirm-cjp-permission",
                "--apply-cjp-edit",
                "--confirm-cjp-apply",
                "--cjp-preview-evidence-sha256", preview_digest,
                "--format", "json",
                "--", "permission.json",
            ])
        self.assertEqual(code, 0)
        call = perform.call_args
        self.assertEqual(call.args[0], {
            "action": "cjpcontrol414",
            "request_file": "permission.json",
        })
        self.assertTrue(call.kwargs["cjp_permission_confirmed"])
        self.assertTrue(call.kwargs["cjp_apply"])
        self.assertTrue(call.kwargs["cjp_apply_confirmed"])
        self.assertEqual(
            call.kwargs["cjp_preview_evidence_sha256"],
            preview_digest)
        self.assertIsNone(call.kwargs["variant_profile"])

    def test_apply_confirmation_requires_apply_flag(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit) as raised:
            superattestor.main([
                "--cjp-control", "--confirm-cjp-apply",
                "--", "permission.json"])
        self.assertEqual(raised.exception.code, 2)

    def test_apply_requires_prior_preview_evidence_digest(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit) as raised:
            superattestor.main([
                "--cjp-control", "--confirm-cjp-permission",
                "--apply-cjp-edit", "--confirm-cjp-apply",
                "--", "permission.json"])
        self.assertEqual(raised.exception.code, 2)

    def test_cjp_flags_are_rejected_for_other_modes(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit) as raised:
            superattestor.main([
                "--attestor414", "--confirm-cjp-permission", "."])
        self.assertEqual(raised.exception.code, 2)

    def test_cjp_cannot_be_combined_with_another_top_level_mode(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit) as raised:
            superattestor.main([
                "--cjp-control", "--attestor414", "permission.json"])
        self.assertEqual(raised.exception.code, 2)

    def test_cjp_rejects_variant_override_and_non_session_formats(self) -> None:
        for extra in (
                ["--variant", "south-park"],
                ["--format", "sarif"],
        ):
            with self.subTest(extra=extra), redirect_stderr(
                    io.StringIO()), self.assertRaises(SystemExit) as raised:
                superattestor.main([
                    "--cjp-control", *extra, "--", "permission.json"])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
