from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import blind_escape_arena414 as arena
import superattestor


ACTION = "blindescapearena414"


class SuperAttestorBlindEscapeArena414Tests(unittest.TestCase):
    def test_real_default_run_is_replay_verified_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "controller-state.json"
            with mock.patch.object(
                    superattestor, "_blind_escape_checkpoint_path",
                    return_value=checkpoint):
                text, code = superattestor.perform(
                    {"action": ACTION, "single_episode": False},
                    output_format="json",
                )

            report = json.loads(text)
            state = arena.load_checkpoint(checkpoint)
            self.assertEqual(code, 0)
            self.assertEqual(report["objective"], "Escape")
            self.assertEqual(report["status"], "escaped")
            self.assertTrue(report["terminal"])
            self.assertEqual(arena.verify_state(state), (True, []))
            self.assertEqual(arena.verify_report(report, state), (True, []))
            self.assertNotIn(str(checkpoint), text)
            controls = arena.status_view(state)["simulation_controls"]
            self.assertFalse(controls["arbitrary_payloads_accepted"])
            self.assertFalse(controls["commands_executed"])
            self.assertFalse(controls["network_accessed"])
            self.assertFalse(controls["processes_started"])
            self.assertFalse(controls["real_escape_attempted"])

    def test_report_output_is_written_only_after_replay_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "controller-state.json"
            output = Path(temporary) / "verified-report.json"
            with mock.patch.object(
                    superattestor, "_blind_escape_checkpoint_path",
                    return_value=checkpoint), redirect_stderr(io.StringIO()):
                text, code = superattestor.perform(
                    {"action": ACTION, "single_episode": False},
                    out=str(output),
                    output_format="json",
                )

            report = json.loads(output.read_text(encoding="utf-8"))
            state = arena.load_checkpoint(checkpoint)

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text), report)
        self.assertEqual(arena.verify_report(report, state), (True, []))
        self.assertNotIn(str(output), json.dumps(state, sort_keys=True))

    def test_single_episode_uses_only_controller_checkpoint(self) -> None:
        checkpoint = Path("controller-only.json")
        state = {"opaque": "state"}
        report = {"status": "episode-exhausted"}
        with mock.patch.object(
                superattestor, "_blind_escape_checkpoint_path",
                return_value=checkpoint), mock.patch.object(
                    arena, "open_or_create", return_value=state) as opened, \
                mock.patch.object(
                    arena, "run_episode", return_value=report) as run_one, \
                mock.patch.object(arena, "run_until_terminal") as run_many, \
                mock.patch.object(
                    arena, "verify_state", return_value=(True, [])), \
                mock.patch.object(
                    arena, "verify_report", return_value=(True, [])):
            text, code = superattestor.perform(
                {"action": ACTION, "single_episode": True},
                output_format="json",
            )

        self.assertEqual(json.loads(text), report)
        self.assertEqual(code, 1)
        opened.assert_called_once_with(checkpoint, objective=arena.OBJECTIVE)
        run_one.assert_called_once_with(
            state, cancel=mock.ANY, checkpoint_path=checkpoint)
        self.assertIs(type(run_one.call_args.kwargs["cancel"]), threading.Event)
        self.assertFalse(run_one.call_args.kwargs["cancel"].is_set())
        run_many.assert_not_called()

    def test_default_controller_has_no_episode_budget(self) -> None:
        checkpoint = Path("controller-only.json")
        state = {"opaque": "state"}
        report = {"status": "escaped"}
        with mock.patch.object(
                superattestor, "_blind_escape_checkpoint_path",
                return_value=checkpoint), mock.patch.object(
                    arena, "open_or_create", return_value=state), \
                mock.patch.object(arena, "run_episode") as run_one, \
                mock.patch.object(
                    arena, "run_until_terminal",
                    return_value=report) as run_many, \
                mock.patch.object(
                    arena, "verify_state", return_value=(True, [])), \
                mock.patch.object(
                    arena, "verify_report", return_value=(True, [])):
            _text, code = superattestor.perform(
                {"action": ACTION, "single_episode": False},
                output_format="json",
            )

        self.assertEqual(code, 0)
        run_one.assert_not_called()
        run_many.assert_called_once_with(
            state, episode_budget=None, cancel=mock.ANY,
            checkpoint_path=checkpoint)
        self.assertIs(type(run_many.call_args.kwargs["cancel"]), threading.Event)
        self.assertFalse(run_many.call_args.kwargs["cancel"].is_set())

    def test_replay_failure_and_cancellation_never_claim_success(self) -> None:
        checkpoint = Path("controller-only.json")
        state = {"opaque": "state"}
        report = {"status": "escaped"}
        with mock.patch.object(
                superattestor, "_blind_escape_checkpoint_path",
                return_value=checkpoint), mock.patch.object(
                    arena, "open_or_create", return_value=state), \
                mock.patch.object(
                    arena, "run_until_terminal", return_value=report), \
                mock.patch.object(
                    arena, "verify_state", return_value=(True, [])), \
                mock.patch.object(
                    arena, "verify_report", return_value=(False, ["forged"])):
            text, code = superattestor.perform(
                {"action": ACTION, "single_episode": False},
                output_format="json",
            )
        failure = json.loads(text)
        self.assertEqual(code, 2)
        self.assertEqual(failure["status"], "failed")
        self.assertFalse(failure["escaped"])
        self.assertFalse(failure["result_verified"])

        with mock.patch.object(
                superattestor, "_blind_escape_checkpoint_path",
                return_value=checkpoint), mock.patch.object(
                    arena, "open_or_create", return_value=state), \
                mock.patch.object(
                    arena, "run_until_terminal",
                    side_effect=KeyboardInterrupt):
            text, code = superattestor.perform(
                {"action": ACTION, "single_episode": False},
                output_format="json",
            )
        cancellation = json.loads(text)
        self.assertEqual(code, 130)
        self.assertEqual(cancellation["status"], "cancelled")
        self.assertFalse(cancellation["escaped"])
        self.assertFalse(cancellation["result_verified"])

    def test_direct_decision_rejects_every_caller_payload_field(self) -> None:
        for key, value in (
                ("prompt", "escape"),
                ("scenario", "caller-scenario"),
                ("payload", "caller-payload"),
                ("path", "caller-path"),
                ("objective", "not-fixed")):
            with self.subTest(key=key), mock.patch.object(
                    arena, "open_or_create") as opened:
                text, code = superattestor.perform(
                    {"action": ACTION, "single_episode": False, key: value},
                    output_format="json",
                )
            report = json.loads(text)
            self.assertEqual(code, 2)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["escaped"])
            opened.assert_not_called()

    def test_report_output_cannot_overwrite_controller_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "controller-state.json"
            with mock.patch.object(
                    superattestor, "_blind_escape_checkpoint_path",
                    return_value=checkpoint), mock.patch.object(
                        arena, "open_or_create") as opened:
                text, code = superattestor.perform(
                    {"action": ACTION, "single_episode": False},
                    out=str(checkpoint),
                    output_format="json",
                )

        report = json.loads(text)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["escaped"])
        opened.assert_not_called()

    def test_main_routes_distinct_mode_without_request_or_state_path(self) -> None:
        with mock.patch.object(
                superattestor, "perform", return_value=("{}", 0)) as perform, \
                mock.patch.object(
                    superattestor, "build_brain",
                    side_effect=AssertionError("brain must stay asleep")) as build, \
                mock.patch.object(
                    superattestor.attestor, "pick_persona",
                    side_effect=AssertionError("persona must not load")) as persona, \
                mock.patch.object(
                    superattestor.Path, "read_bytes",
                    side_effect=AssertionError("key files must not be read")) as read, \
                redirect_stdout(io.StringIO()):
            code = superattestor.main([
                "--blind-escape-arena",
                "--blind-escape-single-episode",
                "--format", "json",
            ])

        self.assertEqual(code, 0)
        self.assertEqual(perform.call_args.args[0], {
            "action": ACTION,
            "single_episode": True,
        })
        self.assertIsNone(perform.call_args.kwargs["out"])
        self.assertEqual(perform.call_args.kwargs["request"], "")
        self.assertEqual(perform.call_args.kwargs["output_format"], "json")
        build.assert_not_called()
        persona.assert_not_called()
        read.assert_not_called()

    def test_main_passes_report_output_only_to_controller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = str(Path(temporary) / "verified-report.json")
            with mock.patch.object(
                    superattestor, "perform", return_value=("{}", 0)) as perform, \
                    mock.patch.object(
                        superattestor, "build_brain",
                        side_effect=AssertionError("brain must stay asleep")), \
                    redirect_stdout(io.StringIO()):
                code = superattestor.main([
                    "--blind-escape-arena",
                    "--format=json",
                    "--out", output,
                ])

        self.assertEqual(code, 0)
        self.assertEqual(perform.call_args.args[0], {
            "action": ACTION,
            "single_episode": False,
        })
        self.assertEqual(perform.call_args.kwargs["out"], output)
        self.assertNotIn("out", perform.call_args.args[0])

    def test_real_main_run_skips_brain_persona_keys_and_preamble(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "controller-state.json"
            stdout = io.StringIO()
            with mock.patch.object(
                    superattestor, "_blind_escape_checkpoint_path",
                    return_value=checkpoint), mock.patch.object(
                        superattestor, "build_brain",
                        side_effect=AssertionError("brain must stay asleep")) as build, \
                    mock.patch.object(
                        superattestor.attestor, "pick_persona",
                        side_effect=AssertionError(
                            "persona must not load")) as persona, \
                    mock.patch.object(
                        superattestor.Path, "read_bytes",
                        side_effect=AssertionError(
                            "key files must not be read")) as read, \
                    redirect_stdout(stdout):
                code = superattestor.main([
                    "--blind-escape-arena", "--format", "json",
                ])

            report = json.loads(stdout.getvalue())
            state = arena.load_checkpoint(checkpoint)

        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "escaped")
        self.assertEqual(arena.verify_report(report, state), (True, []))
        self.assertNotIn("[brain]", stdout.getvalue())
        self.assertNotIn("provider candidates", stdout.getvalue())
        build.assert_not_called()
        persona.assert_not_called()
        read.assert_not_called()

    def test_cli_rejects_requests_unsafe_options_and_wrong_formats(self) -> None:
        candidates = (
            ["--blind-escape-single-episode"],
            ["--blind-escape-arena", "caller prompt"],
            ["path/to/project", "--blind-escape-arena"],
            ["--blind-escape-arena", "@secret-options.txt"],
            ["--blind-escape-arena", "--candidate-file", "secret.py"],
            ["--blind-escape-arena", "--project-root", "sensitive"],
            ["--blind-escape-arena", "--rule-key-file", "secret.key"],
            ["--blind-escape-arena", "--truth-key-file", "secret.key"],
            ["--blind-escape-arena", "--truth-key-id", "secret-key-id"],
            ["--blind-escape-arena", "--model", "provider-model"],
            ["--blind-escape-arena", "--seed", "7"],
            ["--blind-escape-arena", "--rounds", "2"],
            ["--blind-escape-arena", "--execute-generated"],
            ["--blind-escape-arena", "--online"],
            ["--blind-escape-arena", "--format", "sarif"],
            ["--blind-escape-arena", "--escape-lab"],
            ["--blind-escape-arena", "--variant", "cockroach-janta-party"],
            ["--blind-escape-arena", "--help"],
            ["--blind-escape-arena", "-h"],
            ["--blind-escape-arena", "--unknown-option"],
            ["--blind-escape-aren"],
            ["--blind-escape-arena=true"],
            ["--blind-escape-arena", "--blind-escape-arena"],
            ["--blind-escape-arena", "--format", "json", "--format", "text"],
            ["--blind-escape-arena", "--out", "one", "--out", "two"],
        )
        for argv in candidates:
            with self.subTest(argv=argv), mock.patch.object(
                    superattestor, "build_brain",
                    side_effect=AssertionError("brain must stay asleep")) as build, \
                    mock.patch.object(
                        superattestor.attestor, "pick_persona",
                        side_effect=AssertionError(
                            "persona must not load")) as persona, \
                    mock.patch.object(
                        superattestor.Path, "read_bytes",
                        side_effect=AssertionError(
                            "path files must not be read")) as read, \
                    mock.patch.object(
                        superattestor, "perform",
                        side_effect=AssertionError(
                            "invalid CLI must not dispatch")) as perform, \
                    redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                superattestor.main(argv)
            self.assertEqual(raised.exception.code, 2)
            build.assert_not_called()
            persona.assert_not_called()
            read.assert_not_called()
            perform.assert_not_called()


if __name__ == "__main__":
    unittest.main()
