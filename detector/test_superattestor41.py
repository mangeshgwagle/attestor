from __future__ import annotations

import json
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import superattestor


class SuperAttestor41Tests(unittest.TestCase):
    def test_natural_language_routes_41_and_research(self) -> None:
        self.assertEqual(superattestor.decide("maximum attestor .")["action"], "attestor414")
        self.assertEqual(superattestor.decide("attestor413 .")["action"], "attestor41")
        self.assertEqual(superattestor.decide("Attestor 4.1.3 .")["action"], "attestor41")
        decision = superattestor.decide("deep research why is the sky blue")
        self.assertEqual(decision["action"], "research41")
        self.assertEqual(decision["question"], "why is the sky blue")
        self.assertEqual(superattestor.decide("attestor40 .")["action"], "attestor40")

    def test_current_and_compatibility_cli_spellings_route_to_413(self) -> None:
        for option in ("--attestor413", "--attestor41"):
            with self.subTest(option=option), \
                    mock.patch.object(superattestor, "perform", return_value=("{}", 0)) as perform, \
                    mock.patch.object(superattestor, "build_brain", return_value=mock.Mock()), \
                    redirect_stdout(io.StringIO()):
                code = superattestor.main([option, ".", "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(perform.call_args.args[0], {"action": "attestor41", "path": "."})

    def test_research_perform_is_offline_without_authorization(self) -> None:
        text, code = superattestor.perform(
            {"action": "research41", "question": "What is plate tectonics?"},
            output_format="text", research_online=False)
        self.assertEqual(code, 0)
        self.assertIn("not authorized", text)

    def test_research_json_keeps_network_authorization_explicit(self) -> None:
        text, code = superattestor.perform(
            {"action": "research41", "question": "What is plate tectonics?"},
            output_format="json", research_online=False)
        report = json.loads(text)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "network-authorization-required")
        self.assertFalse(report["execution"]["network_accessed"])

    def test_attestor41_perform_uses_new_orchestrator(self) -> None:
        guarded = {"status": "no-findings-with-gaps",
                   "summary": {"findings": 0}, "findings": [],
                   "repair_director_41": {"selected_candidate_output": None}}
        with mock.patch.object(superattestor.attestor41, "maximum", return_value=guarded) as maximum, \
                mock.patch.object(superattestor.attestor41, "safe_public_report",
                                  return_value=guarded), \
                mock.patch.object(superattestor.attestor41, "render", return_value="Attestor 4.1 result"):
            text, code = superattestor.perform({"action": "attestor41", "path": "."})
        maximum.assert_called_once()
        self.assertEqual(text, "Attestor 4.1 result")
        self.assertEqual(code, 1)

    def test_attestor41_does_not_silently_ignore_legacy_memory_output(self) -> None:
        text, code = superattestor.perform(
            {"action": "attestor41", "path": "."}, memory_out="ignored.json")
        self.assertEqual(code, 2)
        self.assertIn("failed safely", text)

    def test_review_candidate_export_cannot_overlap_or_overwrite_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder) / "workspace"
            workspace.mkdir()
            (workspace / "app.py").write_text("value = 1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside"):
                superattestor._prepare_candidate_export(
                    str(workspace), str(workspace))
            with self.assertRaisesRegex(ValueError, "outside"):
                superattestor._prepare_candidate_export(
                    str(workspace / "review"), str(workspace))
            nonempty = Path(folder) / "nonempty"
            nonempty.mkdir()
            (nonempty / "existing.txt").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                superattestor._prepare_candidate_export(
                    str(nonempty), str(workspace))
            safe = superattestor._prepare_candidate_export(
                str(Path(folder) / "review"), str(workspace))
            self.assertTrue(safe.is_dir())
            self.assertFalse(any(safe.iterdir()))

    def test_improved_out_exports_only_proof_gate_verified_source(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder) / "workspace"
            workspace.mkdir()
            (workspace / "app.py").write_text("value = 1\n", encoding="utf-8")
            destination = Path(folder) / "verified"
            report = {
                "improvements": [{"target": "app.py", "accepted": True,
                                  "complete": True, "status": "verified",
                                  "improved_source": "value = 2\n"}],
                "repair_director_41": {"selected_candidate_output": {
                    "complete": True, "state": "unverified-review-candidate",
                    "changes": [{"path": "unsafe.py", "content": "bad = True\n"}]}}
            }
            written = superattestor._write_verified_improvements(
                report, str(destination), str(workspace))
            self.assertEqual(len(written), 1)
            self.assertEqual((destination / "app.py").read_text(encoding="utf-8"),
                             "value = 2\n")
            self.assertFalse((destination / "unsafe.py").exists())

    def test_live_research_is_not_persisted_without_provider_permission(self) -> None:
        report = {
            "status": "complete",
            "execution": {"network_accessed": True},
            "retention": {"provider_declared_retention_allowed": False},
        }
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(superattestor.research_engine41, "research",
                                  return_value=report), \
                mock.patch.object(superattestor.research_engine41, "verify_report",
                                  return_value=(True, [])), \
                mock.patch.object(superattestor.research_engine41, "render",
                                  return_value="research result"):
            output = Path(folder) / "research.json"
            text, code = superattestor.perform(
                {"action": "research41", "question": "current evidence"},
                out=str(output), research_online=True)
            self.assertEqual(code, 0)
            self.assertFalse(output.exists())
            self.assertIn("not persisted", text)

    def test_json_output_with_out_remains_one_json_document(self) -> None:
        report = {
            "schema": "attestor-research/4.1", "status": "complete",
            "execution": {"network_accessed": False},
            "retention": {"provider_declared_retention_allowed": False},
        }
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(superattestor.research_engine41, "research",
                                  return_value=report), \
                mock.patch.object(superattestor.research_engine41, "verify_report",
                                  return_value=(True, [])), \
                redirect_stderr(io.StringIO()) as diagnostics:
            output = Path(folder) / "research.json"
            text, code = superattestor.perform(
                {"action": "research41", "question": "public question"},
                out=str(output), output_format="json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(text), report)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
            self.assertIn("wrote Attestor 4.1.3 research report", diagnostics.getvalue())


if __name__ == "__main__":
    unittest.main()
