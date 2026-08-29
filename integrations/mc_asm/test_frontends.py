#!/usr/bin/env python3
"""Tests for the alternative notations that lower onto mc.asm.

Each frontend is checked twice: that it translates a program correctly, and
that it *refuses* what it cannot translate. The refusals matter more. A
frontend that silently drops a construct produces a program that runs and is
wrong, which is the one outcome the three-backend check cannot catch -- all
three backends would agree, on the wrong program.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import frontends
import mc_asm

S, T, L = " ", "\t", "\n"


def ws_push(value: int) -> str:
    return S + S + S + "".join(T if b == "1" else S
                               for b in bin(value)[2:]) + L


def run(source: str) -> str:
    return mc_asm.execute(source)


class Brainfuck(unittest.TestCase):
    def test_hello_style_output(self):
        program = ("++++++++[>+++++++++<-]>."
                   "+++++++++++++++++++++++++++++++++.")
        self.assertEqual(run(frontends.brainfuck(program)), "Hi")

    def test_cells_start_at_zero(self):
        self.assertEqual(run(frontends.brainfuck(".")), "\x00")

    def test_pointer_moves(self):
        # 65 on cell 1, then move right and put 66 there.
        program = "+" * 65 + ">" + "+" * 66 + "<.>."
        self.assertEqual(run(frontends.brainfuck(program)), "AB")

    def test_loops_run_and_terminate(self):
        self.assertEqual(run(frontends.brainfuck("+++[>+<-]>" + "+" * 62 + ".")),
                         "A")

    def test_non_instructions_are_comments(self):
        plain = frontends.brainfuck("+" * 65 + ".")
        noisy = frontends.brainfuck("add 65 then print: " + "+" * 65 + ".")
        self.assertEqual(plain, noisy)

    def test_unbalanced_brackets_are_refused(self):
        for bad in ("[", "[[]", "]", "+[+"):
            with self.subTest(source=bad):
                with self.assertRaises(mc_asm.McAsmError):
                    frontends.brainfuck(bad)


class Whitespace(unittest.TestCase):
    def test_push_and_print_a_character(self):
        source = ws_push(72) + T + L + S + S + L + L + L
        self.assertEqual(run(frontends.whitespace(source)), "H")

    def test_arithmetic(self):
        source = (ws_push(20) + ws_push(22) + T + S + S + S
                  + T + L + S + T + L + L + L)
        self.assertEqual(run(frontends.whitespace(source)), "42")

    def test_non_whitespace_is_ignored(self):
        bare = ws_push(65) + T + L + S + S + L + L + L
        commented = "".join(c + "x" for c in bare)
        self.assertEqual(run(frontends.whitespace(commented)), "A")

    def test_source_with_no_whitespace_is_refused(self):
        # Note the argument has no spaces: "no whitespace here" would be four
        # perfectly good instructions, which is the joke of the language and
        # was the bug in the first version of this test.
        with self.assertRaises(mc_asm.McAsmError):
            frontends.whitespace("nowhitespacehereatall")

    def test_unsupported_instruction_is_refused_not_skipped(self):
        # Whitespace's labelled flow has no structured equivalent here, and
        # dropping it would produce a program that runs and is wrong.
        with self.assertRaises(mc_asm.McAsmError) as caught:
            frontends.whitespace(ws_push(1) + L + S + S + S + T + L)
        self.assertIn("unsupported", str(caught.exception))


PLAY = """
The Tragedy of Two Numbers.

Romeo, a young man.
Juliet, a lady.

Act I: The only act.
Scene I: The only scene.

[Enter Romeo and Juliet]

Romeo: Thou art as good as %s.
Romeo: Open thy heart!

[Exeunt]
"""


class Shakespeare(unittest.TestCase):
    def test_a_noun_is_worth_one(self):
        self.assertEqual(run(frontends.shakespeare(PLAY % "a flower")), "1")

    def test_a_negative_noun(self):
        self.assertEqual(run(frontends.shakespeare(PLAY % "a pig")), "-1")

    def test_adjectives_double(self):
        self.assertEqual(run(frontends.shakespeare(PLAY % "a fair flower")),
                         "2")
        self.assertEqual(
            run(frontends.shakespeare(PLAY % "a big sweet hero")), "4")

    def test_sums(self):
        self.assertEqual(
            run(frontends.shakespeare(
                PLAY % "the sum of a fair flower and a big sweet hero")), "6")

    def test_stage_directions_do_not_swallow_the_speech(self):
        # `[Enter Romeo and Juliet]` has no sentence punctuation, so it used
        # to run into the line after it and the assignment was skipped
        # silently -- the program printed an uninitialised slot instead.
        self.assertNotEqual(run(frontends.shakespeare(PLAY % "a flower")),
                            "0")

    def test_an_unknown_noun_is_refused(self):
        with self.assertRaises(mc_asm.McAsmError):
            frontends.shakespeare(PLAY % "a microservice")

    def test_a_play_with_no_code_is_refused(self):
        with self.assertRaises(mc_asm.McAsmError):
            frontends.shakespeare("The Tragedy of Nothing.\n\nRomeo, a man.\n")


class EveryFrontendReachesTheSameMachine(unittest.TestCase):
    def test_all_produce_runnable_mc_asm(self):
        sources = {
            "brainfuck": frontends.brainfuck("+" * 65 + "."),
            "whitespace": frontends.whitespace(
                ws_push(65) + T + L + S + S + L + L + L),
            "shakespeare": frontends.shakespeare(
                PLAY % "the sum of a flower and a flower"),
        }
        for name, source in sources.items():
            with self.subTest(frontend=name):
                # Parses as ordinary mc.asm, whatever wrote it.
                self.assertTrue(mc_asm.parse(source))

    def test_the_registry_lists_what_exists(self):
        self.assertEqual(set(frontends.FRONTENDS),
                         {"brainfuck", "whitespace", "shakespeare"})


class ShakespeareArithmetic(unittest.TestCase):
    """All four of SPL's arithmetic phrases, not just the sum.

    Before these the frontend could add and nothing else, and it added by
    scanning the sentence for nouns and totalling them -- which gives the
    right answer for a sum and the wrong one for everything else.
    """

    def value(self, phrase):
        return run(frontends.shakespeare(
            PLAY.replace("%s", phrase, 1) if "%s" in PLAY else PLAY))

    def test_the_four_phrases(self):
        for phrase, expected in (
                ("the sum of a flower and a flower", "2"),
                ("the difference between a big flower and a flower", "1"),
                ("the product of a big flower and a big big flower", "8"),
                ("the quotient between a big big flower and a flower", "4")):
            with self.subTest(phrase=phrase):
                self.assertEqual(run(frontends.shakespeare(PLAY % phrase)),
                                 expected)

    def test_a_character_can_be_used_as_a_value(self):
        play = (PLAY % "a big flower").replace(
            "Romeo: Open thy heart!",
            "Romeo: Thou art as good as the sum of thyself and a flower.\n"
            "Romeo: Open thy heart!")
        self.assertEqual(run(frontends.shakespeare(play)), "3")


class ShakespeareConditionals(unittest.TestCase):
    """Questions and their answers, which the subset had none of.

    Two bugs had to go first, and both are worth remembering. A question
    cannot be recognised by its question mark -- sentences are split on
    `[.!?]`, so the mark is gone before any rule sees the line. And the
    assignment prefix has to be stripped before the value is read, because
    `_value_tokens` resolves pronouns to characters: leaving "Thou art" in
    front made every assignment mean "copy the target's own value", so the
    noun after it was never reached and every program printed 0.
    """

    def ask(self, setup, question, conditional):
        play = (PLAY % setup).replace(
            "Romeo: Open thy heart!",
            "Romeo: %s?\nRomeo: %s, open thy heart!" % (question, conditional))
        return run(frontends.shakespeare(play))

    def test_greater_than(self):
        self.assertEqual(
            self.ask("a big flower", "Art thou better than a flower", "If so"),
            "2")

    def test_greater_than_when_false_stays_silent(self):
        self.assertEqual(
            self.ask("a flower", "Art thou better than a big flower", "If so"),
            "")

    def test_equality(self):
        self.assertEqual(
            self.ask("a big flower", "Art thou as good as a big flower",
                     "If so"), "2")

    def test_less_than(self):
        self.assertEqual(
            self.ask("a flower", "Art thou worse than a big flower", "If so"),
            "1")

    def test_inequality_is_tested_before_equality(self):
        # "not as good as" contains "as good as"; matching the shorter phrase
        # first would invert the sense of every negated comparison.
        self.assertEqual(
            self.ask("a big flower", "Art thou not as good as a flower",
                     "If so"), "2")

    def test_if_not_runs_on_the_false_branch(self):
        self.assertEqual(
            self.ask("a flower", "Art thou better than a big flower",
                     "If not"), "1")

    def test_a_question_it_cannot_read_is_refused(self):
        with self.assertRaises(frontends.FrontendError):
            frontends.shakespeare((PLAY % "a flower").replace(
                "Romeo: Open thy heart!",
                "Romeo: Am I the very model of a modern major general?"))


class Composition(unittest.TestCase):
    """Several notations in one program, on one machine.

    An honest note on what these prove. Brainfuck and Shakespeare both claim
    slot 1 when written alone, so composing them without relocation is a
    hazard -- but no ordering tried here actually produces different output,
    because Shakespeare assigns its characters before reading them and
    Brainfuck rebuilds its pointer on entry. So the region split is not
    demonstrated to fix a visible bug; it makes the independence a property
    of the composer rather than a coincidence of these two programs.
    """

    BF = "+++++++++++++++++++++++++++++++++++++++++++++++++."   # prints "1"

    def test_two_notations_produce_both_outputs_in_order(self):
        program = frontends.compose([("brainfuck", self.BF),
                                     ("shakespeare", PLAY % "a flower")])
        self.assertEqual(run(program), "11")

    def test_a_composed_section_matches_what_it_prints_alone(self):
        alone = run(frontends.brainfuck(self.BF))
        composed = run(frontends.compose([("brainfuck", self.BF)]))
        self.assertEqual(alone, composed)

    def test_sections_are_given_disjoint_memory(self):
        first = frontends.brainfuck(self.BF, base=0)
        second = frontends.brainfuck(self.BF, base=frontends.REGION)
        self.assertNotEqual(first, second,
                            "a relocated section must address different slots")
        # Both still work; only where they keep their tape has changed.
        self.assertEqual(run(first), run(second))

    def test_whitespace_is_refused_rather_than_mistranslated(self):
        """It takes heap addresses off the stack, so it cannot be moved.

        Refusing matches what `whitespace` already does about arbitrary
        labels: a frontend that silently mistranslates is worse than one
        that declines.
        """
        with self.assertRaises(frontends.FrontendError) as caught:
            frontends.compose([("whitespace", " \t\n")])
        self.assertIn("cannot be given a private region", str(caught.exception))

    def test_an_unknown_notation_is_named_with_the_alternatives(self):
        with self.assertRaises(frontends.FrontendError) as caught:
            frontends.compose([("malbolge", "anything")])
        self.assertIn("brainfuck", str(caught.exception))

    def test_too_many_sections_for_the_machine(self):
        with self.assertRaises(frontends.FrontendError) as caught:
            frontends.compose([("brainfuck", "+")] * 32)
        self.assertIn("exceed", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
