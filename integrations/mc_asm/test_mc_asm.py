#!/usr/bin/env python3
"""Tests for mc.asm.

The interesting cases are the notation's edges -- what 0 means, what an
unbalanced block does, and whether a program that never terminates stops
being the interpreter's problem.
"""
from __future__ import annotations

import unittest

import mc_asm


def run(readable: str, *pushed: int) -> str:
    return mc_asm.execute(mc_asm.assemble(readable), list(pushed))


class Notation(unittest.TestCase):
    def test_letters_are_a1z26(self):
        self.assertEqual(mc_asm.encode("print"), "16-18-9-14-20")
        self.assertEqual(mc_asm.decode_word("16-18-9-14-20"), "PRINT")

    def test_leading_zero_marks_a_number(self):
        self.assertEqual(mc_asm.assemble("#42"), "0-4-2")
        self.assertEqual(mc_asm.decode("0-4-2"), "42")

    def test_the_same_digits_mean_different_things(self):
        # 4-2 is a word; 0-4-2 is a number. This is the whole trick, so it is
        # worth a test that would fail loudly if the marker were dropped.
        self.assertEqual(mc_asm.decode("4-2"), "DB")
        self.assertEqual(mc_asm.decode("0-4-2"), "42")

    def test_zero_is_not_a_letter(self):
        with self.assertRaises(mc_asm.McAsmError):
            mc_asm.decode_word("0-1")

    def test_twenty_seven_is_not_a_letter(self):
        with self.assertRaises(mc_asm.McAsmError):
            mc_asm.decode_word("27")

    def test_non_mc_asm_is_refused(self):
        for bad in ("print", "12a", "1--2", "#5"):
            with self.subTest(token=bad):
                with self.assertRaises(mc_asm.McAsmError):
                    mc_asm.parse(bad)

    def test_assemble_round_trips_through_decode(self):
        readable = "#3 #4 ADD PRINT"
        self.assertEqual(mc_asm.decode(mc_asm.assemble(readable)),
                         "3 4 ADD PRINT")


class Arithmetic(unittest.TestCase):
    def test_addition(self):
        self.assertEqual(run("#2 #3 ADD PRINT"), "5")

    def test_subtraction_order(self):
        # Postfix: `7 3 SUB` is 7-3, not 3-7. Getting this backwards is the
        # classic stack-language bug and silently produces plausible numbers.
        self.assertEqual(run("#7 #3 SUB PRINT"), "4")

    def test_division_order_and_floor(self):
        self.assertEqual(run("#7 #2 DIV PRINT"), "3")

    def test_divide_by_zero_is_an_error_not_a_crash(self):
        with self.assertRaises(mc_asm.McAsmError):
            run("#1 #0 DIV")

    def test_stack_words(self):
        self.assertEqual(run("#1 #2 SWAP PRINT PRINT"), "12")
        self.assertEqual(run("#5 DUP ADD PRINT"), "10")
        self.assertEqual(run("#1 #2 OVER PRINT PRINT PRINT"), "121")

    def test_empty_stack_is_reported(self):
        with self.assertRaises(mc_asm.McAsmError):
            run("ADD")


class Text(unittest.TestCase):
    def test_emit_writes_a_letter(self):
        self.assertEqual(run("#8 EMIT #9 EMIT"), "HI")

    def test_zero_emits_a_space(self):
        self.assertEqual(run("#8 EMIT #0 EMIT #9 EMIT"), "H I")

    def test_emit_refuses_a_code_that_is_not_a_letter(self):
        with self.assertRaises(mc_asm.McAsmError):
            run("#27 EMIT")


class ControlFlow(unittest.TestCase):
    def test_if_taken(self):
        self.assertEqual(run("#1 IF #7 PRINT END"), "7")

    def test_if_not_taken(self):
        self.assertEqual(run("#0 IF #7 PRINT END"), "")

    def test_if_else(self):
        self.assertEqual(run("#0 IF #1 PRINT ELSE #2 PRINT END"), "2")
        self.assertEqual(run("#1 IF #1 PRINT ELSE #2 PRINT END"), "1")

    def test_while_counts(self):
        program = ("#1 #0 STORE "
                   "WHILE #0 LOAD #4 LT DO "
                   "#0 LOAD PRINT #0 LOAD #1 ADD #0 STORE END")
        self.assertEqual(run(program), "123")

    def test_while_that_never_runs(self):
        self.assertEqual(run("WHILE #0 DO #9 PRINT END"), "")

    def test_unbalanced_block_is_a_parse_error(self):
        for bad in ("#1 IF #2 PRINT", "END", "#1 IF #2 PRINT ELSE",
                    "WHILE #1 DO #2 PRINT"):
            with self.subTest(source=bad):
                with self.assertRaises(mc_asm.McAsmError):
                    mc_asm.parse(mc_asm.assemble(bad))

    def test_else_without_if_is_refused(self):
        with self.assertRaises(mc_asm.McAsmError):
            mc_asm.parse(mc_asm.assemble("#1 ELSE #2 PRINT END"))


class Limits(unittest.TestCase):
    def test_a_non_terminating_program_stops(self):
        # The point is that it *stops*: an interpreter that hangs on an
        # obvious mistake is harder to debug than one that says so.
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("WHILE #1 DO END")
        self.assertIn("does not terminate", str(caught.exception))

    def test_memory_slots_are_bounded(self):
        # Written against the constant, not against a number: this test used
        # slot 99, which stopped being out of range the moment the tape grew
        # from 16 cells to 4096 for Brainfuck.
        beyond = mc_asm.MEMORY_SLOTS
        with self.assertRaises(mc_asm.McAsmError):
            run("#1 #%d STORE" % beyond)
        with self.assertRaises(mc_asm.McAsmError):
            run("#%d LOAD" % beyond)

    def test_the_last_slot_is_usable(self):
        # The other half of the bound: off-by-one here would quietly lose the
        # top cell of the tape.
        self.assertEqual(run("#7 #%d STORE #%d LOAD PRINT"
                             % (mc_asm.MEMORY_SLOTS - 1,
                                mc_asm.MEMORY_SLOTS - 1)), "7")

    def test_a_known_word_must_have_an_implementation(self):
        # PUTC shipped once as a WORDS entry with no branch in the
        # interpreter: accepted by the parser, ignored at run time, empty
        # output and no error. The dispatch now refuses instead.
        self.assertTrue(mc_asm.WORDS <= _implemented_words())


def _implemented_words() -> set:
    """Every word the interpreter actually dispatches on.

    Both spellings: `word == "ADD"` and `word in ("DIV", "MOD")`. Reading only
    the first reported MOD as unimplemented, which it is not -- a test that
    cries wolf about correct code is worse than no test.
    """
    import inspect
    import re as _re
    body = inspect.getsource(mc_asm.run)
    words = set(_re.findall(r'word == "(\w+)"', body))
    for group in _re.findall(r'word in \(([^)]*)\)', body):
        words.update(_re.findall(r'"(\w+)"', group))
    return words | {"WHILE"}      # a bare label; nothing to execute


class Programs(unittest.TestCase):
    def test_factorial(self):
        program = (
            "#5 #0 STORE "          # n
            "#1 #1 STORE "          # accumulator
            "WHILE #0 LOAD #0 GT DO "
            "  #1 LOAD #0 LOAD MUL #1 STORE "
            "  #0 LOAD #1 SUB #0 STORE "
            "END #1 LOAD PRINT")
        self.assertEqual(run(program), "120")

    def test_value_pushed_before_the_program_starts(self):
        self.assertEqual(run("#2 MUL PRINT", 21), "42")


class Subroutines(unittest.TestCase):
    """Routines are numbered, because everything in this language is.

    Before these, nothing could be factored: a sequence used twice had to be
    written twice, in a notation whose entire premise is compactness. `DEF n`
    names a routine with the literal that follows it, which is what lets a
    CALL to a routine that does not exist be caught before anything runs.
    """

    def test_a_routine_can_be_called_more_than_once(self):
        self.assertEqual(run(
            "DEF #7 DUP ADD END "        # routine 7 doubles the top
            "#5 #7 CALL #7 CALL PRINT"), "20")

    def test_a_definition_is_stepped_over_when_not_called(self):
        # If ordinary execution fell into the body, this would print twice.
        self.assertEqual(run("DEF #1 #99 PRINT END #7 PRINT"), "7")

    def test_routines_nest(self):
        self.assertEqual(run(
            "DEF #2 DUP ADD END "            # 2: double
            "DEF #1 #2 CALL #2 CALL END "    # 1: double twice
            "#3 #1 CALL PRINT"), "12")

    def test_the_return_address_is_not_on_the_value_stack(self):
        """A routine leaving a value behind must still return correctly.

        Keeping return addresses on the value stack is the classic way to get
        this wrong: the leftover 9 would be read as the place to return to.
        """
        self.assertEqual(run(
            "DEF #4 #9 END "             # leaves 9 behind, then returns
            "#4 CALL PRINT"), "9")

    def test_ret_returns_early(self):
        self.assertEqual(run(
            "DEF #3 #1 PRINT RET #2 PRINT END "
            "#3 CALL"), "1")


class SubroutineMisuse(unittest.TestCase):
    def test_calling_a_routine_that_was_never_defined(self):
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("#9 CALL")
        self.assertIn("never defined", str(caught.exception))

    def test_defining_the_same_routine_twice(self):
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("DEF #1 END DEF #1 END")
        self.assertIn("twice", str(caught.exception))

    def test_a_definition_without_a_number(self):
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("DEF DUP END")
        self.assertIn("routine's number", str(caught.exception))

    def test_returning_with_nothing_to_return_to(self):
        with self.assertRaises(mc_asm.McAsmError):
            run("RET")

    def test_recursion_without_a_base_case_stops(self):
        """Bounded like 0, and for the same reason.

        Without the depth limit this exhausts the interpreter's own stack and
        surfaces as a Python traceback, which tells the author of an mc.asm
        program nothing they can act on.
        """
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("DEF #1 #1 CALL END #1 CALL")
        self.assertIn("call depth", str(caught.exception))


class LocalFrames(unittest.TestCase):
    """Routines got code reuse before they got anywhere private to work.

    Every routine addressed the same global slots, so two routines using
    scratch space quietly overwrote each other -- the same problem `compose`
    solves for whole notations, one level further down. A frame is taken from
    the top of memory downward, so locals and the globals STORE/LOAD address
    from zero grow towards each other and meeting is a reported error rather
    than silent overlap.
    """

    def test_a_nested_routine_does_not_clobber_its_caller(self):
        # The case that could not be written before: both routines use
        # local 0, and the caller's value survives the call.
        self.assertEqual(run(
            "DEF #1 #1 FRAME #7 #0 PUT #0 GET PRINT END "
            "DEF #2 #1 FRAME #9 #0 PUT #1 CALL #0 GET PRINT END "
            "#2 CALL"), "79")

    def test_a_frame_is_released_when_the_routine_returns(self):
        """Otherwise memory leaks downward until an unrelated FRAME fails.

        Called three times; if the frames were not released, the third call
        would be working 12 slots lower than the first.
        """
        self.assertEqual(run(
            "DEF #1 #4 FRAME #5 #0 PUT END "
            "#1 CALL #1 CALL #1 CALL #99 PRINT"), "99")

    def test_locals_survive_across_work_in_the_same_routine(self):
        self.assertEqual(run(
            "DEF #1 #2 FRAME #3 #0 PUT #4 #1 PUT "
            "  #0 GET #1 GET MUL PRINT END "
            "#1 CALL"), "12")

    def test_reading_a_local_with_no_frame_open(self):
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("#0 GET")
        self.assertIn("no frame open", str(caught.exception))

    def test_a_local_outside_the_frame_is_refused(self):
        with self.assertRaises(mc_asm.McAsmError) as caught:
            run("DEF #1 #2 FRAME #5 GET END #1 CALL")
        self.assertIn("outside this routine's frame", str(caught.exception))

    def test_a_negative_frame_is_refused(self):
        with self.assertRaises(mc_asm.McAsmError):
            run("#1 NEG FRAME")


class Comparisons(unittest.TestCase):
    def test_le_ge_ne(self):
        for expression, expected in (
                ("#3 #3 LE", "1"), ("#4 #3 LE", "0"),
                ("#3 #3 GE", "1"), ("#2 #3 GE", "0"),
                ("#3 #4 NE", "1"), ("#3 #3 NE", "0")):
            with self.subTest(expression=expression):
                self.assertEqual(run(expression + " PRINT"), expected)

    def test_depth_reports_the_stack_height(self):
        self.assertEqual(run("#7 #8 #9 DEPTH PRINT"), "3")
        self.assertEqual(run("DEPTH PRINT"), "0")


class StackAndLogic(unittest.TestCase):
    def test_rot_moves_the_third_item_to_the_top(self):
        # (a b c -- b c a); PRINT pops, so the order out is a, c, b.
        self.assertEqual(run("#1 #2 #3 ROT PRINT PRINT PRINT"), "132")

    def test_three_rots_return_the_stack_to_where_it_started(self):
        self.assertEqual(run("#1 #2 #3 ROT ROT ROT PRINT PRINT PRINT"), "321")

    def test_and_or_are_boolean_not_bitwise(self):
        self.assertEqual(run("#2 #4 AND PRINT"), "1")   # bitwise would be 0
        self.assertEqual(run("#2 #4 OR PRINT"), "1")
        self.assertEqual(run("#0 #4 AND PRINT"), "0")
        self.assertEqual(run("#0 #0 OR PRINT"), "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
