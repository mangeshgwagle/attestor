#!/usr/bin/env python3
"""Tests for the verified reasoning loop.

No model is involved. A scripted backend stands in for one, which is the only
way to test the property that matters: that a *wrong* proposal is rejected and
the rejection reaches the next attempt. A real model would make that
non-deterministic and the test would prove nothing.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent
                       / "detector"))

import reason

DETECTOR = str(pathlib.Path(__file__).resolve().parent.parent.parent
               / "detector")

# A defect one of Attestor's rules reports, with an obvious correct fix.
BROKEN = "def check(value):\n    if value == None:\n        return 1\n    return 0\n"
FIXED = "def check(value):\n    if value is None:\n        return 1\n    return 0\n"
STILL_BROKEN = "def check(value):\n    if value == None:\n        return 2\n    return 0\n"


class Scripted(reason.Backend):
    """Replays canned replies and records what it was asked."""

    name = "scripted"

    def __init__(self, *replies: str):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def propose(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.replies:
            raise reason.ReasonError("scripted backend ran out of replies")
        return self.replies.pop(0)


def fenced(source: str) -> str:
    return "```python\n%s```" % source


class Extraction(unittest.TestCase):
    def test_takes_the_fenced_block(self):
        self.assertEqual(reason.extract_source("chat\n```\nx = 1\n```\nmore"),
                         "x = 1\n")

    def test_language_tag_is_dropped(self):
        self.assertEqual(reason.extract_source("```python\ny = 2\n```"),
                         "y = 2\n")

    def test_no_fence_is_an_error(self):
        with self.assertRaises(reason.ReasonError):
            reason.extract_source("here is your file: x = 1")

    def test_unterminated_fence_is_an_error(self):
        with self.assertRaises(reason.ReasonError):
            reason.extract_source("```\nx = 1")


class Loop(unittest.TestCase):
    def _target(self, source: str) -> str:
        handle = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                             encoding="utf-8", newline="\n")
        handle.write(source)
        handle.close()
        return handle.name

    def test_a_good_proposal_is_accepted(self):
        backend = Scripted(fenced(FIXED))
        report = reason.solve(self._target(BROKEN),
                              "remove the == None comparison",
                              backend, DETECTOR, rounds=2)
        self.assertTrue(report["solved"])
        self.assertEqual(report["attempts"], 1)

    def test_accepted_results_are_still_marked_as_guessed(self):
        backend = Scripted(fenced(FIXED))
        report = reason.solve(self._target(BROKEN), "fix it", backend,
                              DETECTOR, rounds=2)
        # Nothing here proves the patch correct; it proves no rule objected.
        self.assertFalse(report["deterministic"])

    def test_a_proposal_that_does_not_fix_it_is_rejected(self):
        backend = Scripted(fenced(STILL_BROKEN))
        report = reason.solve(self._target(BROKEN), "fix it", backend,
                              DETECTOR, rounds=1)
        self.assertFalse(report["solved"])

    def test_the_rejection_reaches_the_next_attempt(self):
        # The property the whole design rests on: attempt two is told what
        # attempt one got wrong. Without this the loop is just retrying.
        backend = Scripted(fenced(STILL_BROKEN), fenced(FIXED))
        report = reason.solve(self._target(BROKEN), "fix it", backend,
                              DETECTOR, rounds=3)
        self.assertTrue(report["solved"])
        self.assertEqual(report["attempts"], 2)
        self.assertIn("REJECTED", backend.prompts[1])
        self.assertNotIn("REJECTED", backend.prompts[0])

    def test_an_unreadable_reply_is_survived_and_reported(self):
        backend = Scripted("no code here at all", fenced(FIXED))
        report = reason.solve(self._target(BROKEN), "fix it", backend,
                              DETECTOR, rounds=3)
        self.assertTrue(report["solved"])
        self.assertIn("error", report["transcript"][0])
        self.assertIn("unreadable", backend.prompts[1])

    def test_the_loop_is_bounded(self):
        backend = Scripted(*[fenced(STILL_BROKEN)] * 10)
        report = reason.solve(self._target(BROKEN), "fix it", backend,
                              DETECTOR, rounds=3)
        self.assertFalse(report["solved"])
        self.assertEqual(len(report["transcript"]), 3)

    def test_nothing_is_written_without_apply(self):
        path = self._target(BROKEN)
        reason.solve(path, "fix it", Scripted(fenced(FIXED)), DETECTOR,
                     rounds=1)
        self.assertEqual(pathlib.Path(path).read_text(encoding="utf-8"),
                         BROKEN)


class Credentials(unittest.TestCase):
    def test_the_api_key_is_not_accepted_as_an_argument(self):
        # Read from the environment only, so it cannot reach a shell history,
        # a process listing, or one of this module's transcripts.
        import inspect
        signature = inspect.signature(reason.AnthropicBackend.__init__)
        self.assertNotIn("key", signature.parameters)
        self.assertNotIn("api_key", signature.parameters)


class ApplyBoundary(unittest.TestCase):
    def test_apply_is_source_bound_atomic_and_keeps_a_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "target.py"
            path.write_text(BROKEN, encoding="utf-8")
            report = reason.solve(str(path), "fix it", Scripted(fenced(FIXED)),
                                  DETECTOR, rounds=1)
            backup = reason.apply_candidate(str(path), report)
            self.assertEqual(path.read_text(encoding="utf-8"), FIXED)
            self.assertEqual(backup.read_text(encoding="utf-8"), BROKEN)

    def test_apply_refuses_a_target_changed_after_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "target.py"
            path.write_text(BROKEN, encoding="utf-8")
            report = reason.solve(str(path), "fix it", Scripted(fenced(FIXED)),
                                  DETECTOR, rounds=1)
            path.write_text("# user changed this\n" + BROKEN, encoding="utf-8")
            with self.assertRaisesRegex(reason.ReasonError, "changed after"):
                reason.apply_candidate(str(path), report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
