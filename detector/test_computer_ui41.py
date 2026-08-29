"""UI boundary tests for Attestor 4.1 permissioned pathless discovery."""

from unittest import mock
import unittest

import attestor_ui


class ComputerScanUi41Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = attestor_ui.INDEX.read_text(encoding="utf-8")
        cls.javascript = attestor_ui.UI_SCRIPT.read_text(encoding="utf-8")

    def test_computer_mode_is_pathless_and_unauthorized_by_default(self):
        args = attestor_ui.build_args("computer41", "C:/must/not/be/used")
        self.assertIn("--computer-scan", args)
        self.assertEqual(args[args.index("--format") + 1], "json")
        self.assertEqual(args[args.index("--computer-scope") + 1], "home")
        self.assertEqual(args[args.index("--computer-max-projects") + 1], "3")
        self.assertNotIn("-computer-scan", args)
        self.assertNotIn("--computer-improve", args)
        self.assertNotIn("--", args)
        self.assertNotIn("C:/must/not/be/used", args)

    def test_exact_per_run_permission_routes_bounded_controls(self):
        args = attestor_ui.build_args(
            "computer41", "", computer_authorized=True,
            computer_scope="fixed-drives", computer_max_projects=12,
            computer_improve=True,
        )
        self.assertIn("-computer-scan", args)
        self.assertIn("--computer-improve", args)
        self.assertEqual(args[args.index("--computer-scope") + 1], "fixed-drives")
        self.assertEqual(args[args.index("--computer-max-projects") + 1], "12")
        malformed = attestor_ui.build_args(
            "computer41", "", computer_authorized="true",  # type: ignore[arg-type]
        )
        self.assertNotIn("-computer-scan", malformed)

    def test_computer_controls_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 12"):
            attestor_ui.build_args("computer41", "", computer_max_projects=13)
        with self.assertRaisesRegex(ValueError, "scope"):
            attestor_ui.build_args("computer41", "", computer_scope="network")
        with self.assertRaisesRegex(ValueError, "require computer scan authorization"):
            attestor_ui.build_args("computer41", "", computer_improve=True)
        with self.assertRaisesRegex(ValueError, "only valid"):
            attestor_ui.build_args("attestor41", ".", computer_authorized=True)

    def test_browser_consent_is_unchecked_and_describes_boundaries(self):
        self.assertIn('<option value="computer41">Permissioned pathless computer scan</option>', self.html)
        self.assertIn('id="computerAuthorized" type="checkbox"', self.html)
        self.assertNotIn('id="computerAuthorized" type="checkbox" checked', self.html)
        self.assertIn("Consent is cleared after every run", self.html)
        self.assertIn("does not follow links, use the network, execute discovered code", self.html)
        self.assertIn("computer_authorized: mode === 'computer41'", self.javascript)
        self.assertIn("if (mode === 'computer41') resetComputerAuthorization();", self.javascript)
        self.assertIn("elements.prompt.disabled = state.running || isComputer", self.javascript)

    def test_computer_result_is_not_durably_archived_by_default(self):
        manager = attestor_ui.JobManager(workers=1, max_pending=1,
                                     evidence_store=mock.Mock())
        try:
            result = {"ok": True, "code": 0, "output": "{}", "elapsed_ms": 1}
            with mock.patch.object(attestor_ui, "run_attestor", return_value=result):
                submitted = manager.submit({
                    "mode": "computer41", "prompt": "",
                    "computer_authorized": True,
                })
                self.assertIsNotNone(submitted)
                future = manager._jobs[submitted["id"]]["future"]
                future.result(timeout=5)
                finished = manager.get(submitted["id"])["result"]
            self.assertIn("session-only", finished["history_skipped"])
            manager.evidence_store.store_report.assert_not_called()
        finally:
            manager.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
