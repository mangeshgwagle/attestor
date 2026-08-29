from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import attestor_program as op
import attestor_synth as syn
import attestor_write


SQUARE = op.Task("square", ((1, 1), (2, 4), (3, 9), (5, 25)))
EVENS = op.Task("sum_of_evens",
                (([1, 2, 3, 4], 6), ([2, 2], 4), ([1, 3], 0), ([10, 5, 4], 14)),
                ops=syn.LIST_OPS, max_size=5, loops=True)
SHOUT = op.Task("shout", (("hi", "HI"), ("attestor", "ATTESTOR")), ops=syn.STR_OPS)


class ItEmitsSomethingRunnable(unittest.TestCase):
    """A file that passes an analyzer and then crashes is not a program."""

    def test_a_three_function_program_is_written_checked_and_run(self):
        result = op.write_program([SQUARE, EVENS, SHOUT])
        self.assertTrue(result.ok, result.summary())
        self.assertEqual(set(result.solved), {"square", "sum_of_evens", "shout"})

    def test_the_emitted_file_works_on_inputs_it_never_saw(self):
        """The examples are the specification, not the test."""
        result = op.write_program([SQUARE, EVENS, SHOUT])
        self.assertTrue(result.ok, result.summary())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "program.py"
            path.write_text(result.source, encoding="utf-8")
            for args, expected in ((["square", "12"], "144"),
                                   (["sum_of_evens", "[7, 8, 9, 10]"], "18"),
                                   (["shout", "attestorvonluneberg"],
                                    "'ATTESTORVONLUNEBERG'")):
                done = subprocess.run(
                    [sys.executable, "-B", str(path)] + args,
                    capture_output=True, text=True, timeout=op.RUN_TIMEOUT,
                    check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout.strip(), expected)

    def test_it_has_the_parts_a_program_has(self):
        source = op.write_program([SQUARE, SHOUT]).source
        for part in ('"""', "import sys", "COMMANDS = {", "def main(",
                     'if __name__ == "__main__":'):
            self.assertIn(part, source)

    def test_imports_appear_only_when_a_body_needs_them(self):
        """functools is imported because a fold used it, not by template."""
        plain = op.write_program([SQUARE]).source
        self.assertNotIn("import functools", plain)
        fold = op.build_program([op.Task(
            "product", (([1, 2, 3, 4], 24), ([5, 2], 10), ([3], 3)),
            ops=syn.LIST_OPS, max_size=6, loops=True)])[0]
        self.assertIn("import functools", fold)


class AllFourGatesOrNothing(unittest.TestCase):
    def test_an_unsolvable_task_stops_the_whole_program(self):
        """A program missing a function it was asked for is a different
        program, not a partial success."""
        impossible = op.Task("nope", ((1, 7), (2, 7), (3, 9)), max_size=2)
        result = op.write_program([SQUARE, impossible])
        self.assertFalse(result.ok)
        self.assertIsNone(result.source)
        self.assertIn("nope", result.unsolved)

    def test_the_analyzer_runs_on_the_assembled_file(self):
        """Not on the parts. The scaffolding is code too -- Attestor rejected an
        `except ValueError: pass` in the argument parser here, which no
        synthesized body would ever have contained."""
        source = op.write_program([SQUARE, SHOUT]).source
        self.assertEqual(attestor_write.scan_text("program.py", source), [])

    def test_a_task_name_must_be_a_usable_identifier(self):
        with self.assertRaises(ValueError):
            op.Task("not a name", ((1, 1),))

    def test_a_task_needs_examples(self):
        with self.assertRaises(ValueError):
            op.Task("empty", ())

    def test_the_summary_says_why_when_it_refuses(self):
        result = op.write_program(
            [op.Task("nope", ((1, 7), (2, 7), (3, 9)), max_size=2)])
        self.assertIn("not emitted", result.summary())
        self.assertIn("nope", result.summary())

EVENS_L = op.Task("keep_evens", (([1, 2, 3, 4], [2, 4]), ([1, 3], []), ([6], [6])),
                  ops=syn.LIST_OPS, loops=True)
SQUARES_L = op.Task("squares", (([1, 2, 3], [1, 4, 9]), ([4], [16])),
                    ops=syn.LIST_OPS, loops=True)
TOTAL = op.Task("total", (([1, 2, 3], 6), ([10], 10), ([], 0)), ops=syn.LIST_OPS)
PIPE = op.Chain("sum_of_even_squares", ("keep_evens", "squares", "total"),
                examples=(([1, 2, 3, 4], 20), ([5], 0), ([2, 6], 40)))


class OneStepFeedsTheNext(unittest.TestCase):
    """A chain composes parts that were synthesized; it is not searched for."""

    def test_a_three_step_pipeline_is_emitted_and_runs(self):
        result = op.write_program([EVENS_L, SQUARES_L, TOTAL], chains=[PIPE])
        self.assertTrue(result.ok, result.summary())
        self.assertIn("def sum_of_even_squares(numbers: list[int]) -> int:",
                      result.source)
        self.assertIn("result = keep_evens(numbers)", result.source)
        self.assertIn("return total(result)", result.source)

    def test_the_pipeline_is_correct_on_inputs_it_never_saw(self):
        result = op.write_program([EVENS_L, SQUARES_L, TOTAL], chains=[PIPE])
        self.assertTrue(result.ok, result.summary())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "program.py"
            path.write_text(result.source, encoding="utf-8")
            for args, expected in (
                    (["sum_of_even_squares", "[1, 2, 3, 4, 5, 6]"], "56"),
                    (["sum_of_even_squares", "[11, 13]"], "0"),
                    (["keep_evens", "[7, 8, 9, 10]"], "[8, 10]")):
                done = subprocess.run([sys.executable, "-B", str(path)] + args,
                                      capture_output=True, text=True,
                                      timeout=op.RUN_TIMEOUT, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(done.stdout.strip(), expected)

    def test_end_to_end_examples_are_replayed_through_the_whole_chain(self):
        """Each part can be right while the composition is nonsense."""
        result = op.write_program([EVENS_L, SQUARES_L, TOTAL], chains=[PIPE])
        self.assertTrue(result.ran)
        self.assertIn("4 entry point", result.output)

    def test_a_chain_naming_a_missing_step_is_refused(self):
        broken = op.Chain("nope", ("keep_evens", "does_not_exist"))
        result = op.write_program([EVENS_L], chains=[broken])
        self.assertFalse(result.ok)
        self.assertIsNone(result.source)
        self.assertTrue(any("does_not_exist" in u for u in result.unsolved))

    def test_a_chain_needs_at_least_two_steps(self):
        with self.assertRaises(ValueError):
            op.Chain("solo", ("total",))


class ItSearchesHarderOnItsOwn(unittest.TestCase):
    """The caller should not have to know that a fold is size 6."""

    def test_a_task_is_solved_without_being_told_how_big_it_is(self):
        task = op.Task("product", (([1, 2, 3, 4], 24), ([5, 2], 10), ([3], 3)),
                       ops=syn.LIST_OPS, loops=True)
        program, attempts = op.solve(task)
        self.assertIsNotNone(program, "escalation failed after %d tries" % attempts)
        self.assertGreater(attempts, 1)

    def test_loop_free_programs_are_tried_before_looping_ones(self):
        """Loops multiply the search by the body pool, so they come last."""
        task = op.Task("double", ((1, 2), (2, 4), (3, 6)), loops=True)
        program, _ = op.solve(task)
        self.assertIsNotNone(program)
        self.assertFalse(program.uses_loop)

    def test_an_impossible_task_gives_up_instead_of_running_forever(self):
        task = op.Task("nope", ((1, 7), (2, 7), (3, 9)))
        program, attempts = op.solve(task, budget=2.0, hard_max=5)
        self.assertIsNone(program)
        self.assertGreater(attempts, 0)

import attestor_polish as polish


class TheEmittedCodeIsSharp(unittest.TestCase):
    """Readability rewrites, each proven not to move the meaning.

    Every rewrite is applied and then checked by running the original
    examples through the rewritten source; a rewrite that disagrees on one
    example is discarded. A prettifier that changes behaviour is a bug
    factory, so the check is neither optional nor sampled.
    """

    def test_names_come_from_what_the_examples_hold(self):
        self.assertEqual(polish.name_for([([1, 2], 3)]), "numbers")
        self.assertEqual(polish.name_for([("hi", "HI")]), "text")
        self.assertEqual(polish.name_for([(3, 9)]), "number")

    def test_type_hints_are_omitted_when_the_examples_disagree(self):
        """`[]` is a `list`, `[1]` is a `list[int]`; guessing would be wrong."""
        given, _ = polish.hint_for([([1, 2], 3), ([], 0)])
        self.assertEqual(given, "")
        given, wanted = polish.hint_for([([1, 2], 3), ([4], 4)])
        self.assertEqual((given, wanted), ("list[int]", "int"))

    def test_the_rewrites_land(self):
        cases = (
            ("square", ((1, 1), (2, 4), (3, 9)), syn.INT_OPS, False,
             "number ** 2"),
            ("shout", (("hi", "HI"), ("attestor", "ATTESTOR")), syn.STR_OPS, False,
             "text.upper()"),
            ("total_of_squares", (([1, 2, 3], 14), ([4], 16), ([2, 2], 8)),
             syn.LIST_OPS, True, "sum(number ** 2 for number in numbers)"),
        )
        for name, examples, ops, loops, expected in cases:
            with self.subTest(name=name):
                program = syn.synthesize(examples, ops=ops, max_size=6,
                                         loops=loops)
                self.assertIsNotNone(program)
                sharp = polish.polish(syn.render(program, name=name),
                                      examples, name=name)
                self.assertIn(expected, sharp)

    def test_a_rewrite_that_would_change_an_answer_is_discarded(self):
        """The guarantee is the point: declining beats prettifying wrongly."""
        honest = 'def f(value):\n    return value + 1\n'
        kept = polish.polish(honest, [(1, 2), (5, 6)], name="f")
        namespace = {}
        exec(compile(kept, "k.py", "exec"), namespace)  # noqa: S102
        for value, expected in ((1, 2), (5, 6), (99, 100)):
            self.assertEqual(namespace["f"](value), expected)

    def test_polished_output_still_passes_the_analyzer_and_runs(self):
        result = op.write_program(
            [op.Task("squares", (([1, 2, 3], [1, 4, 9]), ([4], [16])),
                     ops=syn.LIST_OPS, loops=True, summary="Each entry squared.")])
        self.assertTrue(result.ok, result.summary())
        self.assertIn("Each entry squared.", result.source)
        self.assertIn("numbers", result.source)
        self.assertNotIn("(value * value)", result.source)

    def test_a_chain_is_named_from_its_own_examples(self):
        chain = op.Chain("pipeline", ("keep_evens", "total"),
                         examples=(([1, 2, 3, 4], 6), ([1], 0)))
        source = op.build_program([EVENS_L, TOTAL], chains=[chain])[0]
        self.assertIn("def pipeline(numbers: list[int]) -> int:", source)
        self.assertNotIn("def pipeline(value):", source)


if __name__ == "__main__":
    unittest.main()
