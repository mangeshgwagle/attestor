#!/usr/bin/env python3
"""Tests for the Piet frontend.

Pictures are built in code rather than shipped as files, so what each test
asserts is visible next to the assertion instead of living in a PNG nobody
opens.

One thing these deliberately do not do is run a complete Piet program end to
end. Terminating requires the pointer to fail all eight attempts to leave the
final block, and in a one-dimensional picture it can always turn round and
walk back the way it came -- so a terminating program needs two-dimensional
black walls placed so the return path is blocked at the specific exit corner.
That is a picture-authoring puzzle rather than a property of this translator,
and inventing a picture to make a test pass would be testing the picture.
What is testable is that each transition decodes to the right command, that a
walk which never ends is stopped and reported, and that the commands with no
honest translation are refused by name.
"""
from __future__ import annotations

import unittest

import mc_asm
import piet

LIGHT_RED = (0xFF, 0xC0, 0xC0)
RED = (0xFF, 0x00, 0x00)
DARK_RED = (0xC0, 0x00, 0x00)
DARK_MAGENTA = (0xC0, 0x00, 0xC0)
YELLOW = (0xFF, 0xFF, 0x00)
BLACK = (0x00, 0x00, 0x00)
WHITE = (0xFF, 0xFF, 0xFF)


def first(grid, count):
    """The first `count` transitions, as command names."""
    out = []
    for command, _size in piet.walk(grid, limit=count):
        out.append(command)
        if len(out) == count:
            return out
    return out


class TransitionsDecode(unittest.TestCase):
    """A command comes from the change between two blocks, never one block."""

    def test_lightness_step_of_one_at_the_same_hue_is_push(self):
        self.assertEqual(first([[LIGHT_RED, LIGHT_RED, LIGHT_RED, RED]], 1),
                         ["push"])

    def test_push_carries_the_size_of_the_block_being_left(self):
        grid = [[LIGHT_RED, LIGHT_RED, LIGHT_RED, RED]]
        command, size = next(iter(piet.walk(grid, limit=1)))
        self.assertEqual((command, size), ("push", 3))

    def test_two_lightness_steps_is_pop(self):
        self.assertEqual(first([[LIGHT_RED, DARK_RED]], 1), ["pop"])

    def test_one_hue_step_is_add(self):
        self.assertEqual(first([[RED, YELLOW]], 1), ["add"])

    def test_five_hue_steps_and_one_lightness_is_out_number(self):
        self.assertEqual(first([[RED, DARK_MAGENTA]], 1), ["out_number"])


class WalksThatDoNotEnd(unittest.TestCase):
    def test_an_oscillating_picture_is_stopped_and_reported(self):
        """Two blocks side by side is enough to loop forever.

        The pointer runs to the end, is blocked by the edge, turns back, and
        re-enters the block it just left. Nothing about the state changed, so
        it does this indefinitely. The first version of `walk` had no limit
        and hung on a five-codel picture.
        """
        with self.assertRaises(piet.PietError) as caught:
            list(piet.walk([[LIGHT_RED, RED]], limit=20))
        self.assertIn("does not terminate", str(caught.exception))

    def test_the_frontend_refuses_such_a_picture_rather_than_hanging(self):
        with self.assertRaises(piet.PietError):
            piet.piet([[LIGHT_RED, LIGHT_RED, LIGHT_RED, RED, DARK_MAGENTA]])


class WhatCannotBeTranslated(unittest.TestCase):
    def test_a_picture_with_no_transitions_is_refused(self):
        with self.assertRaises(piet.PietError) as caught:
            piet.piet([[RED, RED, RED]])
        self.assertIn("no instructions", str(caught.exception))

    def test_the_command_table_marks_pointer_and_switch_as_data_dependent(self):
        # These are the two that make static translation impossible: both
        # take the new direction off the stack.
        self.assertEqual(piet.COMMANDS[3][1], "pointer")
        self.assertEqual(piet.COMMANDS[3][2], "switch")
        self.assertNotIn("pointer", piet.STATIC)
        self.assertNotIn("switch", piet.STATIC)

    def test_roll_and_input_have_no_mc_asm_equivalent(self):
        for command in ("roll", "in_number", "in_char"):
            with self.subTest(command=command):
                self.assertNotIn(command, piet.TO_MC_ASM)

    def test_every_static_command_either_maps_or_is_push(self):
        """No command may be silently dropped.

        A frontend that skipped one would emit a program that runs and is
        wrong, which is the outcome `whitespace` refuses arbitrary labels to
        avoid, for the same reason.
        """
        for command in piet.STATIC:
            if command in (None, "push"):
                continue
            with self.subTest(command=command):
                self.assertIn(command, piet.TO_MC_ASM)


class ColourTable(unittest.TestCase):
    def test_eighteen_colours_plus_black_and_white(self):
        self.assertEqual(len(piet.COLOURS), 18)
        self.assertNotIn(piet.WHITE, piet.COLOURS)
        self.assertNotIn(piet.BLACK, piet.COLOURS)

    def test_every_hue_and_lightness_pair_appears_once(self):
        self.assertEqual(sorted(piet.COLOURS.values()),
                         sorted((h, l) for h in range(6) for l in range(3)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
