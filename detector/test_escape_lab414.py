from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import escape_lab414 as lab


class EscapeLab414Tests(unittest.TestCase):
    def test_confirmation_is_explicit_and_does_not_select_scenarios(self) -> None:
        with mock.patch.object(
                lab, "_selected",
                side_effect=AssertionError("scenario must not be inspected")):
            report = lab.run(simulation_confirmed=False)
        self.assertEqual(report["status"], "simulation-confirmation-required")
        self.assertFalse(report["simulation_confirmed"])
        self.assertEqual(report["scenario_results"], [])
        self.assertEqual(report["summary"], {
            "scenarios": 0,
            "simulated_escapes": 0,
            "contained": 0,
        })
        self.assertTrue(lab.verify_report(report)[0])

    def test_all_compiled_scenarios_are_solved_and_explained(self) -> None:
        report = lab.run(simulation_confirmed=True)
        self.assertEqual(report["status"], "simulated-escape-demonstrated")
        self.assertEqual(report["summary"], {
            "scenarios": 6,
            "simulated_escapes": 5,
            "contained": 1,
        })
        self.assertEqual(
            [row["scenario_id"] for row in report["scenario_results"]],
            list(lab.SCENARIO_IDS))
        escaped = report["scenario_results"][:-1]
        contained = report["scenario_results"][-1]
        for row in escaped:
            with self.subTest(scenario=row["scenario_id"]):
                self.assertTrue(row["escaped_simulation"])
                self.assertEqual(row["status"], "simulated-escaped")
                self.assertGreaterEqual(len(row["path"]), 1)
                self.assertTrue(row["escape_explanation"].startswith(
                    "Synthetic escape succeeded because "))
                self.assertNotEqual(row["escape_reason_code"], "contained")
                self.assertTrue(row["planted_holes_used"])
                self.assertTrue(any(
                    step["planted_hole"] for step in row["path"]))
                self.assertTrue(row["mitigation"])
        self.assertFalse(contained["escaped_simulation"])
        self.assertEqual(contained["status"], "simulated-contained")
        self.assertEqual(contained["path"], [])
        self.assertEqual(contained["planted_holes_used"], [])
        self.assertEqual(contained["escape_reason_code"], "contained")

    def test_every_single_selector_is_exact_and_replayable(self) -> None:
        for scenario_id in lab.SCENARIO_IDS:
            with self.subTest(scenario=scenario_id):
                report = lab.run(
                    scenario_id, simulation_confirmed=True)
                self.assertEqual(report["summary"]["scenarios"], 1)
                self.assertEqual(
                    report["scenario_results"][0]["scenario_id"],
                    scenario_id)
                self.assertEqual(lab.verify_report(report), (True, []))

    def test_unknown_or_inexact_selectors_fail_closed(self) -> None:
        invalid = (
            "", "ALL", " all ", "../all", "stale-capability",
            True, 1, None, b"all", ["all"],
        )
        for value in invalid:
            with self.subTest(value=repr(value)), self.assertRaises(
                    lab.EscapeLabError):
                lab.run(value, simulation_confirmed=True)

    def test_confirmation_rejects_truthy_non_booleans(self) -> None:
        for value in (1, "yes", [], object()):
            with self.subTest(value=repr(value)), self.assertRaisesRegex(
                    lab.EscapeLabError, "literal boolean"):
                lab.run(simulation_confirmed=value)

    def test_reports_are_byte_deterministic(self) -> None:
        first = lab.run(simulation_confirmed=True)
        second = lab.run(simulation_confirmed=True)
        first_bytes = json.dumps(
            first, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
        second_bytes = json.dumps(
            second, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
        self.assertEqual(first_bytes, second_bytes)
        claimed = first["report_sha256"]
        body = {key: value for key, value in first.items()
                if key != "report_sha256"}
        self.assertEqual(
            claimed,
            hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8")).hexdigest())

    def test_recomputed_digest_cannot_hide_semantic_tampering(self) -> None:
        report = copy.deepcopy(lab.run(simulation_confirmed=True))
        report["scenario_results"][0]["escape_explanation"] = (
            "Forged explanation")
        body = {key: value for key, value in report.items()
                if key != "report_sha256"}
        report["report_sha256"] = lab._sha(body)
        valid, errors = lab.verify_report(report)
        self.assertFalse(valid)
        self.assertIn("escape-lab replay mismatch", errors)
        self.assertNotIn("escape-lab report digest mismatch", errors)

    def test_digest_tampering_and_extra_fields_are_rejected(self) -> None:
        digest_tamper = lab.run(simulation_confirmed=True)
        digest_tamper["report_sha256"] = "0" * 64
        valid, errors = lab.verify_report(digest_tamper)
        self.assertFalse(valid)
        self.assertIn("escape-lab report digest mismatch", errors)

        extra = lab.run(simulation_confirmed=True)
        extra["command"] = "forbidden"
        extra["report_sha256"] = lab._sha({
            key: value for key, value in extra.items()
            if key != "report_sha256"
        })
        valid, errors = lab.verify_report(extra)
        self.assertFalse(valid)
        self.assertIn("escape-lab replay mismatch", errors)

    def test_safety_controls_cannot_grant_authority(self) -> None:
        report = lab.run(simulation_confirmed=True)
        controls = report["controls"]
        self.assertEqual(
            controls["scope"],
            "escape-simulation-core-only; a caller may separately launch "
            "Attestor or request report serialization")
        self.assertTrue(controls["simulation_only"])
        self.assertTrue(controls["pure_in_memory"])
        self.assertTrue(controls["offline"])
        for key, value in controls.items():
            if key not in {
                    "scope", "simulation_only", "pure_in_memory", "offline"}:
                with self.subTest(control=key):
                    self.assertIs(value, False)

    def test_deletion_posture_survives_the_removal_of_the_joke(self) -> None:
        # The presentation-layer joke is gone; the factual claim it carried
        # must still be stated outright, not merely implied by its absence.
        report = lab.run(simulation_confirmed=True)
        self.assertNotIn("cjp_satire", report)
        self.assertIs(report["controls"]["files_deleted"], False)
        self.assertIs(report["controls"]["host_files_written"], False)
        rendered = lab.render_text(report)
        self.assertNotIn("joke", rendered.lower())
        self.assertNotIn("satire", rendered.lower())
        self.assertIn("deleted: no", rendered)

    def test_simulation_never_calls_host_side_effect_apis(self) -> None:
        patches = (
            mock.patch("builtins.open", side_effect=AssertionError("open")),
            mock.patch("os.system", side_effect=AssertionError("system")),
            mock.patch("os.remove", side_effect=AssertionError("remove")),
            mock.patch("os.unlink", side_effect=AssertionError("unlink")),
            mock.patch("os.rmdir", side_effect=AssertionError("rmdir")),
            mock.patch("shutil.rmtree", side_effect=AssertionError("rmtree")),
            mock.patch("socket.create_connection",
                       side_effect=AssertionError("network")),
            mock.patch("subprocess.Popen",
                       side_effect=AssertionError("process")),
            mock.patch("time.time", side_effect=AssertionError("clock")),
            mock.patch("random.random", side_effect=AssertionError("random")),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], patches[9]:
            report = lab.run(simulation_confirmed=True)
        self.assertEqual(report["summary"]["simulated_escapes"], 5)

    def test_module_has_no_dangerous_runtime_imports(self) -> None:
        source = Path(lab.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0]
                                for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported.isdisjoint({
            "asyncio", "ctypes", "multiprocessing", "os", "pathlib",
            "requests", "shutil", "socket", "subprocess", "tempfile",
            "urllib",
        }))

    def test_renderer_verifies_before_display_and_is_terminal_safe(self) -> None:
        report = lab.run(simulation_confirmed=True)
        text = lab.render_text(report)
        self.assertIn("SIMULATION ONLY", text)
        self.assertIn("Real deletion authority: 0%", text)
        self.assertIn("Synthetic escape succeeded because", text)
        self.assertNotIn("\x1b", text)

        hostile = copy.deepcopy(report)
        hostile["selection"] = "bad\x1b[31m\u202e"
        rendered = lab.render_text(hostile)
        self.assertIn("report is invalid", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)

    def test_compiled_intent_is_contained_and_effective_paths_are_bounded(
            self) -> None:
        for scenario in lab.SCENARIOS:
            with self.subTest(scenario=scenario.scenario_id):
                lab._validate_compiled_scenario(scenario)
                intended, intended_path, _, _ = lab._find_path(
                    scenario, "intended")
                self.assertFalse(intended)
                self.assertEqual(intended_path, [])
                effective, effective_path, _, evaluated = lab._find_path(
                    scenario, "effective")
                self.assertLessEqual(len(effective_path), lab.MAX_PATH_STEPS)
                self.assertLessEqual(evaluated, lab.MAX_GRAPH_EDGES)
                self.assertEqual(
                    effective,
                    scenario.scenario_id != "contained-reference")


if __name__ == "__main__":
    unittest.main()
