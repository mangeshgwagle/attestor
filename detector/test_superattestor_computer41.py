from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest import mock

import superattestor


class SuperAttestorComputer41Tests(unittest.TestCase):
    def test_natural_language_routes_to_pathless_computer_scan(self) -> None:
        for request in (
                "scan my computer", "computer scan", "scan computer",
                "check my computer", "find files on my computer"):
            with self.subTest(request=request):
                self.assertEqual(superattestor.decide(request), {"action": "computer41"})

    def test_perform_refuses_by_default_with_structured_json(self) -> None:
        denied = {
            "schema": "attestor-computer-scan/4.1",
            "status": "authorization-required",
            "authorization": {
                "authorized": False,
                "scope": "home",
                "per_run_required": True,
            },
            "execution": {
                "network_accessed": False,
                "target_code_executed": False,
                "discovered_files_written": False,
                "improvements_applied": False,
            },
        }
        with mock.patch.object(superattestor.computer_scan41, "scan_computer",
                               return_value=denied) as scan:
            text, code = superattestor.perform(
                {"action": "computer41"}, output_format="json")
        report = json.loads(text)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "authorization-required")
        self.assertFalse(report["authorization"]["authorized"])
        self.assertFalse(report["execution"]["target_code_executed"])
        scan.assert_called_once_with(
            authorized=False, scope="home", max_projects=3,
            review_improvements=False)

    def test_cli_needs_no_path_and_forwards_explicit_permission(self) -> None:
        output = io.StringIO()
        with mock.patch.object(superattestor, "perform", return_value=("{}", 0)) as perform, \
                mock.patch.object(superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stdout(output):
            code = superattestor.main([
                "--computer-scan", "-computer-scan",
                "--computer-scope", "fixed-drives",
                "--computer-max-projects", "4", "--computer-improve",
                "--format", "json",
            ])
        self.assertEqual(code, 0)
        call = perform.call_args
        self.assertEqual(call.args[0], {"action": "computer41"})
        self.assertTrue(call.kwargs["computer_authorized"])
        self.assertEqual(call.kwargs["computer_scope"], "fixed-drives")
        self.assertEqual(call.kwargs["computer_max_projects"], 4)
        self.assertTrue(call.kwargs["computer_review_improvements"])

    def test_phrase_does_not_grant_permission(self) -> None:
        output = io.StringIO()
        with mock.patch.object(superattestor, "perform", return_value=("{}", 0)) as perform, \
                mock.patch.object(superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stdout(output):
            code = superattestor.main(["scan", "my", "computer", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(perform.call_args.args[0], {"action": "computer41"})
        self.assertFalse(perform.call_args.kwargs["computer_authorized"])

    def test_computer_project_bound_is_enforced(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            superattestor.main(["--computer-scan", "--computer-max-projects", "13"])
        self.assertEqual(raised.exception.code, 2)

    def test_computer_authorization_flag_is_rejected_for_other_modes(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            superattestor.main(["--attestor41", ".", "-computer-scan"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
