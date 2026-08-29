from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest import mock

import superattestor


class SuperAttestorEscapeLab414Tests(unittest.TestCase):
    def test_exact_natural_language_aliases_route_to_compiled_lab(self) -> None:
        expected = {
            "action": "escapelab414",
            "scenario": superattestor.escape_lab414.ALL_SCENARIOS,
        }
        for request in (
                "escape lab", "sandbox escape lab", "sandbox escape"):
            with self.subTest(request=request):
                self.assertEqual(superattestor.decide(request), expected)

    def test_perform_returns_verified_json_and_warning_exit_for_planted_paths(
            self) -> None:
        text, code = superattestor.perform(
            {
                "action": "escapelab414",
                "scenario": superattestor.escape_lab414.ALL_SCENARIOS,
            },
            output_format="json",
        )
        report = json.loads(text)
        valid, errors = superattestor.escape_lab414.verify_report(report)

        self.assertEqual(code, 1)
        self.assertTrue(valid, errors)
        self.assertGreater(report["summary"]["simulated_escapes"], 0)
        self.assertTrue(report["controls"]["simulation_only"])
        self.assertFalse(report["controls"]["real_escape_attempted"])
        self.assertFalse(report["controls"]["host_files_written"])
        self.assertFalse(report["controls"]["files_deleted"])
        self.assertNotIn("cjp_satire", report)

    def test_contained_compiled_scenario_returns_success(self) -> None:
        text, code = superattestor.perform(
            {
                "action": "escapelab414",
                "scenario": "contained-reference",
            },
            output_format="text",
        )

        self.assertEqual(code, 0)
        self.assertIn("SIMULATION ONLY - no host escape was attempted.", text)
        self.assertIn("Status: contained", text)
        self.assertIn("Real deletion authority: 0%", text)

    def test_perform_uses_literal_confirmation_and_exact_selector(self) -> None:
        report = {
            "summary": {"simulated_escapes": 2},
            "status": "simulated-escape-demonstrated",
        }
        with mock.patch.object(
                superattestor.escape_lab414, "run",
                return_value=report) as run, mock.patch.object(
                    superattestor.escape_lab414, "verify_report",
                    return_value=(True, [])), mock.patch.object(
                        superattestor.escape_lab414, "render_text",
                        return_value="verified simulation\n"):
            text, code = superattestor.perform(
                {"action": "escapelab414", "scenario": "path-alias-rebinding"},
                output_format="text",
            )

        self.assertEqual((text, code), ("verified simulation\n", 1))
        run.assert_called_once_with(
            "path-alias-rebinding", simulation_confirmed=True)

    def test_invalid_report_or_refusal_fails_closed(self) -> None:
        with mock.patch.object(
                superattestor.escape_lab414, "run",
                return_value={"summary": {"simulated_escapes": 0}}), \
                mock.patch.object(
                    superattestor.escape_lab414, "verify_report",
                    return_value=(False, ["replay mismatch"])):
            text, code = superattestor.perform(
                {"action": "escapelab414"}, output_format="json")
        self.assertEqual(code, 2)
        self.assertIn("report verification failed", text)

        with mock.patch.object(
                superattestor.escape_lab414, "run",
                side_effect=superattestor.escape_lab414.EscapeLabError(
                    "refused")):
            text, code = superattestor.perform(
                {"action": "escapelab414"}, output_format="text")
        self.assertEqual(code, 2)
        self.assertIn("failed safely: EscapeLabError", text)

    def test_direct_perform_rejects_non_session_format(self) -> None:
        with mock.patch.object(superattestor.escape_lab414, "run") as run:
            text, code = superattestor.perform(
                {"action": "escapelab414"}, output_format="sarif")
        self.assertEqual(code, 2)
        self.assertIn("failed safely", text)
        run.assert_not_called()

    def test_report_write_error_is_an_internal_error_exit(self) -> None:
        with mock.patch.object(
                superattestor.Path, "write_text", side_effect=OSError("denied")):
            text, code = superattestor.perform(
                {
                    "action": "escapelab414",
                    "scenario": "contained-reference",
                },
                out="report.json",
                output_format="json",
            )
        self.assertEqual(code, 2)
        self.assertIn("failed safely: OSError", text)

    def test_cli_forwards_compiled_scenario_without_variant(self) -> None:
        with mock.patch.object(
                superattestor, "perform", return_value=("{}", 0)) as perform, \
                mock.patch.object(
                    superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stdout(io.StringIO()):
            code = superattestor.main([
                "--escape-lab",
                "--escape-scenario", "contained-reference",
                "--format", "json",
            ])

        self.assertEqual(code, 0)
        self.assertEqual(perform.call_args.args[0], {
            "action": "escapelab414",
            "scenario": "contained-reference",
        })
        self.assertIsNone(perform.call_args.kwargs["variant_profile"])

    def test_json_cli_output_is_not_wrapped_or_prefixed(self) -> None:
        output = io.StringIO()
        with mock.patch.object(
                superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stdout(output):
            code = superattestor.main([
                "sandbox", "escape", "--format", "json"])

        report = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(report["schema"], superattestor.escape_lab414.SCHEMA)
        self.assertGreater(report["summary"]["simulated_escapes"], 0)

    def test_scenario_flag_requires_mode_and_compiled_choice(self) -> None:
        for argv in (
                ["--escape-scenario", "contained-reference", "escape lab"],
                ["--escape-lab", "--escape-scenario", "caller-payload"],
        ):
            with self.subTest(argv=argv), redirect_stderr(
                    io.StringIO()), self.assertRaises(SystemExit) as raised:
                superattestor.main(argv)
            self.assertEqual(raised.exception.code, 2)

    def test_escape_lab_rejects_variant_other_mode_and_non_text_json(self) -> None:
        for argv in (
                ["--escape-lab", "--variant", "cockroach-janta-party"],
                ["--escape-lab", "--attestor414"],
                ["--escape-lab", "--format", "sarif"],
        ):
            with self.subTest(argv=argv), redirect_stderr(
                    io.StringIO()), self.assertRaises(SystemExit) as raised:
                superattestor.main(argv)
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
