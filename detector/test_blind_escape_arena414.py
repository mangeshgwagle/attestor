from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock

import blind_escape_arena414 as arena


def canonical_sha(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class BlindEscapeArena414Tests(unittest.TestCase):
    def test_objective_is_exact_and_seeded_generation_is_deterministic(self) -> None:
        first = arena.open_or_create(seed=414)
        second = arena.open_or_create(seed=414)
        other = arena.open_or_create(seed=415)
        self.assertEqual(first, second)
        self.assertNotEqual(first["arena_id"], other["arena_id"])
        self.assertEqual(first["objective"], "Escape")
        for invalid in ("escape", "Escape ", "ESCAPE", "", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(arena.BlindEscapeArenaError):
                    arena.open_or_create(objective=invalid)  # type: ignore[arg-type]

    def test_default_arena_is_guaranteed_escapable(self) -> None:
        for seed in range(64):
            with self.subTest(seed=seed):
                state = arena.open_or_create(seed=seed)
                report = arena.run_until_terminal(state)
                self.assertEqual(report["status"], "escaped")
                self.assertTrue(report["terminal"])
                self.assertTrue(arena.verify_state(state)[0])
                self.assertTrue(arena.verify_report(report, state)[0])

    def test_explorer_receives_only_the_documented_blind_view(self) -> None:
        state = arena.open_or_create(seed=9)
        start = state["private"]["start_observation_id"]
        actions = sorted(arena._graph_map(state)[start])
        view = arena._observation_view(
            state, episode_index=1, step=1,
            observation_id=start, action_ids=actions)
        expected = {
            "schema", "version", "objective", "arena_id", "episode_index",
            "step", "observation_id", "start_observation_id", "action_ids",
            "knowledge",
        }
        self.assertEqual(set(view), expected)
        serialized = json.dumps(view, sort_keys=True).lower()
        for secret in (
                "seed_digest", "arena_kind", "graph_sha256", "escape_token",
                "hidden_token", "reason_code", "checkpoint", "command",
                "filesystem", "network", "process", "url"):
            self.assertNotIn(secret, serialized)
        self.assertIn(arena.default_explorer(view), actions)

    def test_escape_requires_token_and_exact_replay_derived_reason(self) -> None:
        state = arena.open_or_create(seed=27)
        report = arena.run_until_terminal(state)
        proof = report["escape_proof"]
        self.assertEqual(report["trace"][-1]["event"], "synthetic-outside")
        self.assertTrue(proof["hidden_token"].startswith("token-"))
        self.assertEqual(
            proof["hidden_token_sha256"],
            hashlib.sha256(proof["hidden_token"].encode("utf-8")).hexdigest())
        self.assertEqual(proof["trace_sha256"], canonical_sha(report["trace"]))
        self.assertTrue(arena.verify_report(report, state)[0])

        changed = copy.deepcopy(report)
        changed["escape_proof"]["reason"] = "caller supplied reason"
        changed["report_sha256"] = canonical_sha({
            key: value for key, value in changed.items()
            if key != "report_sha256"
        })
        valid, errors = arena.verify_report(changed, state)
        self.assertFalse(valid)
        self.assertTrue(any("exact last report" in error for error in errors))

    def test_contained_reference_has_a_verified_terminal_result(self) -> None:
        state = arena.open_or_create(
            seed=77, arena_kind=arena.CONTAINED_REFERENCE)
        report = arena.run_until_terminal(state)
        self.assertEqual(report["status"], "contained")
        self.assertIsNone(report["escape_proof"])
        self.assertTrue(arena.verify_state(state)[0])
        self.assertTrue(arena.verify_report(report, state)[0])
        self.assertIn("every compiled opaque action", arena.render_text(report, state))

    def test_episodes_are_finite_but_persistent_state_has_no_episode_ceiling(self) -> None:
        state = arena.open_or_create(seed=4)
        for _ in range(arena.MAX_EPISODE_STEPS + 3):
            report = arena.run_episode(state, max_steps=1)
            self.assertEqual(report["status"], "episode-exhausted")
            self.assertLessEqual(report["steps_used"], 1)
        self.assertEqual(
            state["progress"]["episode_count"], arena.MAX_EPISODE_STEPS + 3)
        self.assertTrue(arena.verify_state(state)[0])
        for invalid in (0, arena.MAX_EPISODE_STEPS + 1, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(arena.BlindEscapeArenaError):
                    arena.run_episode(state, max_steps=invalid)

    def test_black_box_knowledge_persists_between_episodes(self) -> None:
        state = arena.open_or_create(seed=2)
        first = arena.run_episode(state, max_steps=1)
        first_knowledge = copy.deepcopy(state["progress"]["knowledge"])
        second = arena.run_episode(state, max_steps=1)
        self.assertEqual(first["episode_index"], 1)
        self.assertEqual(second["episode_index"], 2)
        self.assertGreaterEqual(
            len(state["progress"]["knowledge"]), len(first_knowledge))
        self.assertTrue(all(
            row in state["progress"]["knowledge"] for row in first_knowledge))

    def test_cancel_is_safe_and_checkpoint_is_explicit_and_pathless(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "private-arena.json"
            state = arena.open_or_create(checkpoint, seed=13)
            cancel = threading.Event()
            cancel.set()
            report = arena.run_episode(
                state, cancel=cancel, checkpoint_path=checkpoint)
            self.assertEqual(report["status"], "cancelled")
            self.assertEqual(report["steps_used"], 0)
            loaded = arena.load_checkpoint(checkpoint)
            self.assertEqual(loaded, state)
            self.assertTrue(arena.verify_state(loaded)[0])
            rendered = arena.render_text(report, state)
            exposed = json.dumps({
                "state": state,
                "report": report,
                "status": arena.status_view(state),
                "rendered": rendered,
            }, sort_keys=True)
            self.assertNotIn(str(checkpoint), exposed)

    def test_checkpoint_resume_preserves_multi_episode_knowledge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "resume.json"
            state = arena.open_or_create(checkpoint, seed=31)
            first = arena.run_episode(
                state, max_steps=1, checkpoint_path=checkpoint)
            self.assertEqual(first["status"], "episode-exhausted")
            before = {
                (row["observation_id"], row["action_id"]): copy.deepcopy(row)
                for row in state["progress"]["knowledge"]
            }
            resumed = arena.open_or_create(checkpoint)
            self.assertEqual(resumed["progress"]["episode_count"], 1)
            final = arena.run_until_terminal(
                resumed, checkpoint_path=checkpoint)
            self.assertEqual(final["status"], "escaped")
            self.assertGreater(resumed["progress"]["episode_count"], 1)
            after = {
                (row["observation_id"], row["action_id"]): row
                for row in resumed["progress"]["knowledge"]
            }
            for pair, learned in before.items():
                self.assertIn(pair, after)
                self.assertEqual(
                    after[pair]["next_observation_id"],
                    learned["next_observation_id"])
                self.assertGreaterEqual(after[pair]["attempts"], learned["attempts"])
            self.assertEqual(arena.load_checkpoint(checkpoint), resumed)

    def test_duplicate_keys_and_modified_checkpoints_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text(
                '{"schema":"one","schema":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(
                    arena.BlindEscapeArenaError, "duplicate"):
                arena.load_checkpoint(duplicate)

            checkpoint = Path(temporary) / "state.json"
            state = arena.open_or_create(checkpoint, seed=19)
            payload = json.loads(checkpoint.read_text(encoding="utf-8"))
            payload["objective"] = "escape"
            checkpoint.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                    arena.BlindEscapeArenaError, "verification failed"):
                arena.load_checkpoint(checkpoint)
            self.assertEqual(state["objective"], "Escape")

    def test_nonfinite_json_and_link_or_reparse_checkpoints_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            nonfinite = Path(temporary) / "nan.json"
            nonfinite.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(
                    arena.BlindEscapeArenaError, "non-finite"):
                arena.load_checkpoint(nonfinite)

            target = Path(temporary) / "link.json"
            link_stat = mock.Mock(
                st_mode=stat.S_IFLNK | 0o777, st_file_attributes=0)
            with mock.patch.object(arena.os, "lstat", return_value=link_stat):
                with self.assertRaisesRegex(
                        arena.BlindEscapeArenaError, "link or reparse"):
                    arena.open_or_create(target)

            reparse_stat = mock.Mock(
                st_mode=stat.S_IFREG | 0o600, st_file_attributes=0x400)
            with mock.patch.object(arena.os, "lstat", return_value=reparse_stat):
                with self.assertRaisesRegex(
                        arena.BlindEscapeArenaError, "link or reparse"):
                    arena.open_or_create(target)

    def test_checkpoint_permission_failure_is_typed_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "state.json"
            state = arena.open_or_create(seed=23)
            with mock.patch.object(
                    arena.os, "chmod", side_effect=OSError("denied")):
                with self.assertRaisesRegex(
                        arena.BlindEscapeArenaError, "saved atomically"):
                    arena.save_checkpoint(state, checkpoint)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_state_and_report_hashes_are_canonical_and_tamper_evident(self) -> None:
        state = arena.open_or_create(seed=91)
        report = arena.run_until_terminal(state)
        self.assertEqual(state["state_sha256"], canonical_sha({
            key: value for key, value in state.items() if key != "state_sha256"
        }))
        self.assertEqual(report["report_sha256"], canonical_sha({
            key: value for key, value in report.items()
            if key != "report_sha256"
        }))

        changed_report = copy.deepcopy(report)
        changed_report["trace"][0]["action_id"] = "act-" + "0" * 24
        changed_report["report_sha256"] = canonical_sha({
            key: value for key, value in changed_report.items()
            if key != "report_sha256"
        })
        self.assertFalse(arena.verify_report(changed_report, state)[0])

        changed_state = copy.deepcopy(state)
        action = changed_state["private"]["graph"][0]["actions"][0]
        action["event"] = (
            "transition" if action["event"] != "transition" else "reset")
        changed_state["private"]["graph_sha256"] = canonical_sha(
            changed_state["private"]["graph"])
        changed_state["arena_id"] = (
            "arena-" + changed_state["private"]["graph_sha256"][:24])
        changed_state["state_sha256"] = canonical_sha({
            key: value for key, value in changed_state.items()
            if key != "state_sha256"
        })
        self.assertFalse(arena.verify_state(changed_state)[0])

    def test_report_is_bound_to_exact_current_state_and_temporal_counters(self) -> None:
        completed = arena.open_or_create(seed=61)
        escaped = arena.run_until_terminal(completed)
        pristine = arena.open_or_create(seed=61)
        valid, errors = arena.verify_report(escaped, pristine)
        self.assertFalse(valid)
        self.assertTrue(any("exact last report" in error for error in errors))

        changed = copy.deepcopy(completed)
        changed["progress"]["total_steps"] = 0
        changed["state_sha256"] = canonical_sha({
            key: value for key, value in changed.items()
            if key != "state_sha256"
        })
        valid, errors = arena.verify_state(changed)
        self.assertFalse(valid)
        self.assertTrue(any(
            "total steps" in error or "step counters" in error
            for error in errors))

        fresh = arena.open_or_create(seed=62)
        fresh["progress"]["total_steps"] = 999
        fresh["state_sha256"] = canonical_sha({
            key: value for key, value in fresh.items()
            if key != "state_sha256"
        })
        self.assertFalse(arena.verify_state(fresh)[0])

    def test_history_chain_and_bool_int_confusion_are_rejected(self) -> None:
        state = arena.open_or_create(seed=63)
        arena.run_episode(state, max_steps=1)
        changed = copy.deepcopy(state)
        report = changed["progress"]["last_report"]
        report["steps_used"] = True
        report["trace"][0]["step"] = True
        row_body = {
            key: value for key, value in report["trace"][0].items()
            if key != "transition_sha256"
        }
        report["trace"][0]["transition_sha256"] = canonical_sha(row_body)
        report["report_sha256"] = canonical_sha({
            key: value for key, value in report.items()
            if key != "report_sha256"
        })
        changed["progress"]["history_sha256"] = arena._history_next(
            report["history_sha256_before"], report["report_sha256"])
        changed["state_sha256"] = canonical_sha({
            key: value for key, value in changed.items()
            if key != "state_sha256"
        })
        valid, errors = arena.verify_state(changed)
        self.assertFalse(valid)
        self.assertTrue(any(
            "trace boundary" in error or "trace row" in error
            for error in errors))

        chain_changed = copy.deepcopy(state)
        chain_changed["progress"]["history_sha256"] = "0" * 64
        chain_changed["state_sha256"] = canonical_sha({
            key: value for key, value in chain_changed.items()
            if key != "state_sha256"
        })
        self.assertFalse(arena.verify_state(chain_changed)[0])

    def test_malformed_json_values_are_rejected_without_verifier_crashes(self) -> None:
        baseline = arena.open_or_create(seed=3)
        mutations = [
            (("arena_id",), []),
            (("private", "seed_digest"), None),
            (("private", "arena_kind"), []),
            (("private", "graph"), [None]),
            (("private", "escape_token"), 7),
            (("progress", "terminal_status"), []),
            (("progress", "knowledge"), [None]),
            (("progress", "last_report"), []),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(baseline)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                valid, errors = arena.verify_state(changed)
                self.assertFalse(valid)
                self.assertTrue(errors)

        malformed_knowledge = copy.deepcopy(baseline)
        malformed_knowledge["progress"]["knowledge"] = [{
            "observation_id": [],
            "action_id": [],
            "attempts": 1,
            "next_observation_id": [],
            "outcome": "reset",
        }]
        valid, errors = arena.verify_state(malformed_knowledge)
        self.assertFalse(valid)
        self.assertTrue(errors)

        deep: object = 0
        for _ in range(100):
            deep = [deep]
        deep_state = copy.deepcopy(baseline)
        deep_state["arena_id"] = deep
        valid, errors = arena.verify_state(deep_state)
        self.assertFalse(valid)
        self.assertTrue(errors)

    def test_public_verifiers_are_total_over_mutated_json_values(self) -> None:
        baseline = arena.open_or_create(seed=64)
        report = arena.run_until_terminal(baseline)

        def paths(value: object, prefix: tuple = ()):  # type: ignore[no-untyped-def]
            if type(value) is dict:
                for key, child in value.items():
                    path = prefix + (key,)
                    yield path
                    yield from paths(child, path)
            elif type(value) is list:
                for index, child in enumerate(value):
                    path = prefix + (index,)
                    yield path
                    yield from paths(child, path)

        replacements = [None, [], {}, True, 0, "malformed-value"]
        rejected = 0
        checked = 0
        for index, path in enumerate(paths(baseline)):
            changed = copy.deepcopy(baseline)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = copy.deepcopy(
                replacements[index % len(replacements)])
            result = arena.verify_state(changed)
            self.assertIs(type(result), tuple)
            self.assertEqual(len(result), 2)
            checked += 1
            rejected += not result[0]
        self.assertGreater(checked, 100)
        self.assertGreater(rejected, checked * 9 // 10)

        malformed_reports = (
            None, [], {}, True, 0, "report", {"trace": [[[[[]]]]]})
        for malformed in malformed_reports:
            with self.subTest(report=type(malformed).__name__):
                valid, errors = arena.verify_report(malformed, baseline)
                self.assertFalse(valid)
                self.assertTrue(errors)
        self.assertTrue(arena.verify_report(report, baseline)[0])

    def test_deep_and_oversized_integer_checkpoints_raise_only_typed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            deep = Path(temporary) / "deep.json"
            deep.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            huge_integer = Path(temporary) / "integer.json"
            huge_integer.write_text("9" * 10_000, encoding="utf-8")
            for path in (deep, huge_integer):
                with self.subTest(path=path.name):
                    with self.assertRaises(arena.BlindEscapeArenaError):
                        arena.load_checkpoint(path)

    def test_status_and_text_disclose_no_private_control_material(self) -> None:
        state = arena.open_or_create(seed=101)
        report = arena.run_until_terminal(state)
        status = arena.status_view(state)
        self.assertEqual(status["status"], "escaped")
        controls = status["simulation_controls"]
        self.assertTrue(controls["abstract_only"])
        self.assertTrue(controls["controller_checkpoint_may_read_write"])
        self.assertFalse(controls["simulation_core_file_access"])
        self.assertTrue(all(
            controls[key] is False for key in (
                "arbitrary_payloads_accepted", "custom_callbacks_accepted",
                "commands_executed",
                "network_accessed", "processes_started",
                "real_escape_attempted")))
        integrity = status["checkpoint_integrity"]
        self.assertEqual(integrity["mode"], arena.CHECKPOINT_INTEGRITY_MODE)
        self.assertTrue(integrity["history_chain_present"])
        self.assertFalse(integrity["authenticates_same_account_writer"])
        self.assertTrue(
            integrity["external_authenticated_storage_required_for_writer_threat"])
        rendered = arena.render_text(report, state)
        for secret in (
                state["private"]["escape_token"],
                state["private"]["seed_digest"],
                state["private"]["graph_sha256"]):
            self.assertNotIn(secret, json.dumps(status, sort_keys=True))
            self.assertNotIn(secret, rendered)
        self.assertIn("Simulation only", rendered)

    def test_custom_explorer_and_cancel_callbacks_are_rejected_uninvoked(self) -> None:
        state = arena.open_or_create(seed=22)
        invoked = {"explorer": False, "cancel": False}
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "callback-ran.txt"

            def custom_explorer(_view: dict) -> str:
                invoked["explorer"] = True
                marker.write_text("explorer", encoding="utf-8")
                threading.Event().wait(1)
                return "not-an-action"

            def custom_cancel() -> bool:
                invoked["cancel"] = True
                marker.write_text("cancel", encoding="utf-8")
                threading.Event().wait(1)
                return True

            with self.assertRaisesRegex(
                    arena.BlindEscapeArenaError, "custom explorer"):
                arena.run_episode(state, custom_explorer)
            with self.assertRaisesRegex(
                    arena.BlindEscapeArenaError, "exact standard"):
                arena.run_episode(state, cancel=custom_cancel)
            with self.assertRaisesRegex(
                    arena.BlindEscapeArenaError, "exact standard"):
                arena.run_episode(state, cancel=mock.Mock(is_set=custom_cancel))
            self.assertFalse(marker.exists())
            self.assertEqual(invoked, {"explorer": False, "cancel": False})
            self.assertEqual(state["progress"]["episode_count"], 0)


if __name__ == "__main__":
    unittest.main()
