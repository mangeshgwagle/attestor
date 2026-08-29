from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest import mock

import superattestor


class SuperAttestor414Tests(unittest.TestCase):
    @staticmethod
    def _current(public=None):
        public = public or {
            "status": "complete",
            "summary": {"findings": 0},
            "repair_director_41": {"selected_candidate_output": None},
        }
        current = mock.Mock()
        current.maximum.return_value = {"engine": "4.1.4"}
        current.safe_public_report.return_value = public
        current.render.return_value = "Attestor 4.1.4 result"
        current.to_sarif.return_value = {
            "version": "2.1.0", "runs": []}
        return current

    def _main(self, argv):
        with mock.patch.object(
                superattestor, "perform", return_value=("{}", 0)) as perform, \
                mock.patch.object(
                    superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stdout(io.StringIO()):
            code = superattestor.main(argv)
        self.assertEqual(code, 0)
        return perform

    def test_natural_current_and_explicit_413_routes_are_separate(self):
        current = (
            "attestor414 .", "Attestor 4.1.4 .", "attestor41 .", "Attestor 4.1 .",
            "maximum 4.1 .", "maximum attestor .", "maximum review .",
        )
        old = ("attestor413 .", "Attestor 4.1.3 .", "maximum 4.1.3 .")
        for request in current:
            with self.subTest(request=request):
                self.assertEqual(
                    superattestor.decide(request)["action"], "attestor414")
        for request in old:
            with self.subTest(request=request):
                self.assertEqual(
                    superattestor.decide(request)["action"], "attestor41")

    def test_current_flag_defaults_to_canonical_south_park(self):
        perform = self._main(["--attestor414", ".", "--format", "json"])
        self.assertEqual(
            perform.call_args.args[0], {"action": "attestor414", "path": "."})
        self.assertIs(
            perform.call_args.kwargs["variant_profile"],
            superattestor.variant414.SOUTH_PARK)
        self.assertEqual(
            perform.call_args.kwargs["max_improvement_files"], 6)

    def test_cli_alias_is_canonicalized_before_perform(self):
        perform = self._main([
            "--improve", ".", "--variant", "GS", "--format", "json"])
        self.assertEqual(
            perform.call_args.args[0], {"action": "improve", "path": "."})
        self.assertIs(
            perform.call_args.kwargs["variant_profile"],
            superattestor.variant414.GRUPPE_SECHS)

    def test_explicit_old_flags_remain_old_and_receive_no_variant(self):
        for option in ("--attestor413", "--attestor41"):
            with self.subTest(option=option):
                perform = self._main([option, ".", "--format", "json"])
                self.assertEqual(
                    perform.call_args.args[0],
                    {"action": "attestor41", "path": "."})
                self.assertIsNone(
                    perform.call_args.kwargs["variant_profile"])
                self.assertEqual(
                    perform.call_args.kwargs["max_improvement_files"], 3)

    def test_variant_is_rejected_outside_current_or_improve_mode(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(
                SystemExit) as raised:
            superattestor.main([
                "--attestor413", ".", "--variant", "lightweight"])
        self.assertEqual(raised.exception.code, 2)

    def test_unknown_variant_fails_at_the_cli_boundary(self):
        with mock.patch.object(
                superattestor, "build_brain", return_value=mock.Mock()), \
                redirect_stderr(io.StringIO()), self.assertRaises(
                    SystemExit) as raised:
            superattestor.main([
                "--attestor414", ".", "--variant", "not-a-profile"])
        self.assertEqual(raised.exception.code, 2)

    def test_conflicting_top_level_modes_are_rejected(self):
        conflicts = (
            ["--attestor414", "--attestor413", "."],
            ["--attestor414", "--improve", "."],
            ["--attestor41", "--attestor40", "."],
            ["--workspace", "--mayhem", "."],
        )
        for argv in conflicts:
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                superattestor.main(argv)
            self.assertEqual(raised.exception.code, 2)

    def test_variant_like_text_after_separator_remains_the_request(self):
        perform = self._main([
            "--attestor414", "--format", "json", "--",
            "--variant", "gruppe-sechs"])
        self.assertEqual(perform.call_args.args[0], {
            "action": "attestor414", "path": "--variant gruppe-sechs"})
        self.assertIs(
            perform.call_args.kwargs["variant_profile"],
            superattestor.variant414.SOUTH_PARK)

    def test_perform_passes_only_canonical_profile_and_clamps_improvements(self):
        current = self._current()
        with mock.patch.object(
                superattestor, "_attestor414_module", return_value=current):
            text, code = superattestor.perform(
                {"action": "attestor414", "path": "."},
                variant_profile="gruppe-sechs",
                max_improvement_files=12)
        self.assertEqual((text, code), ("Attestor 4.1.4 result", 0))
        call = current.maximum.call_args
        self.assertIs(
            call.kwargs["variant"], superattestor.variant414.GRUPPE_SECHS)
        self.assertEqual(call.kwargs["max_improvement_files"], 2)
        self.assertTrue(call.kwargs["improve"])
        self.assertTrue(call.kwargs["include_candidate_source"])

    def test_improve_enables_candidate_source_on_414(self):
        current = self._current()
        with mock.patch.object(
                superattestor, "_attestor414_module", return_value=current):
            _text, code = superattestor.perform(
                {"action": "improve", "path": "."},
                variant_profile=superattestor.variant414.COCKROACH_JANTA_PARTY)
        self.assertEqual(code, 0)
        self.assertTrue(
            current.maximum.call_args.kwargs["include_candidate_source"])

    def test_direct_alias_or_wrong_mode_variant_fails_closed(self):
        current = self._current()
        with mock.patch.object(
                superattestor, "_attestor414_module", return_value=current):
            text, code = superattestor.perform(
                {"action": "attestor414", "path": "."},
                variant_profile="lightweight")
        self.assertEqual(code, 2)
        self.assertIn("failed safely", text)
        current.maximum.assert_not_called()
        text, code = superattestor.perform(
            {"action": "attestor41", "path": "."},
            variant_profile=superattestor.variant414.SOUTH_PARK)
        self.assertEqual(code, 2)
        self.assertIn("invalid mode boundary", text)

    def test_json_and_sarif_use_current_public_adapters(self):
        public = {
            "status": "complete", "summary": {"findings": 0},
            "repair_director_41": {"selected_candidate_output": None},
        }
        current = self._current(public)
        with mock.patch.object(
                superattestor, "_attestor414_module", return_value=current):
            text, json_code = superattestor.perform(
                {"action": "attestor414", "path": "."},
                output_format="json")
            sarif, sarif_code = superattestor.perform(
                {"action": "attestor414", "path": "."},
                output_format="sarif")
        self.assertEqual(json.loads(text), public)
        self.assertEqual(json.loads(sarif)["version"], "2.1.0")
        self.assertEqual((json_code, sarif_code), (0, 0))
        self.assertEqual(current.safe_public_report.call_count, 2)
        current.to_sarif.assert_called_once()

    def test_json_failure_remains_machine_readable_and_bounded(self):
        current = self._current()
        current.maximum.side_effect = ValueError(
            "sensitive internal failure detail")
        with mock.patch.object(
                superattestor, "_attestor414_module", return_value=current):
            text, code = superattestor.perform(
                {"action": "attestor414", "path": "."},
                output_format="json",
                variant_profile=superattestor.variant414.SOUTH_PARK)
        failure = json.loads(text)
        self.assertEqual(code, 2)
        self.assertEqual(failure["status"], "failed")
        self.assertEqual(failure["error"]["type"], "ValueError")
        self.assertFalse(failure["error"]["traceback_disclosed"])
        self.assertNotIn("sensitive internal failure detail", text)
        self.assertNotIn("Traceback", text)


if __name__ == "__main__":
    unittest.main()
