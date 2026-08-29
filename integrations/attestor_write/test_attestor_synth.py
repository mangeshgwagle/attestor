from __future__ import annotations

import unittest

import attestor_synth as syn


def compiled(source: str, name: str = "f"):
    namespace: dict = {}
    exec(compile(source, "%s.py" % name, "exec"), namespace)  # noqa: S102
    return namespace[name]


class ItFindsProgramsNobodyWroteATemplateFor(unittest.TestCase):
    def check(self, examples, ops, size=syn.MAX_SIZE):
        program = syn.synthesize(examples, ops=ops, max_size=size)
        self.assertIsNotNone(program, "no program found")
        return program

    def test_arithmetic(self):
        for examples, size in ((((1, 1), (2, 4), (3, 9), (5, 25)), 4),
                               (((-3, 3), (4, 4), (-9, 9)), 4),
                               (((1, 3), (2, 5), (3, 7), (10, 21)), 5)):
            with self.subTest(examples=examples):
                self.check(examples, syn.INT_OPS, size)

    def test_strings(self):
        self.check((("hi", "IH"), ("word", "DROW")), syn.STR_OPS)
        self.check((("word", "ORD"), ("java", "AVA")), syn.STR_OPS)

    def test_lists(self):
        self.check((([1, 2, 3], 5), ([10, 1, 1], 2), ([4, 5], 5)), syn.LIST_OPS)

    def test_the_smallest_program_is_returned_first(self):
        """Enumerated by size, so the first match is the simplest match."""
        program = self.check((((-3, 3), (4, 4), (-9, 9))), syn.INT_OPS)
        self.assertLessEqual(program.size, 2)


class TheRenderedSourceIsTheDeliverable(unittest.TestCase):
    """The text has to compute what the verified tree computed.

    It did not, at first: templates were handed the variable *and* the
    arguments, so `{0}` bound to the variable and the last argument was
    dropped. `(x * 2) + 1` rendered as `(value + value)` -- source that
    passed nothing, from a search that had genuinely succeeded. Evaluation
    and rendering agreeing is the whole contract of a synthesizer, so it is
    checked by compiling the output and re-running the examples through it.
    """

    CASES = (
        ((((1, 3), (2, 5), (3, 7), (10, 21))), syn.INT_OPS, 5),
        ((((1, 2), (2, 6), (3, 12), (4, 20))), syn.INT_OPS, 5),
        ((((1, 1), (2, 4), (3, 9))), syn.INT_OPS, 4),
        (((("hi", "IH"), ("word", "DROW"))), syn.STR_OPS, 4),
        (((([1, 2, 3], 5), ([10, 1, 1], 2))), syn.LIST_OPS, 4),
    )

    def test_compiled_output_reproduces_every_example(self):
        for examples, ops, size in self.CASES:
            with self.subTest(examples=examples):
                program = syn.synthesize(examples, ops=ops, max_size=size)
                self.assertIsNotNone(program)
                fn = compiled(syn.render(program, name="f"))
                for value, expected in examples:
                    self.assertEqual(fn(value), expected)

    def test_a_nested_program_does_not_lose_an_argument(self):
        """The exact shape that was rendering wrong."""
        examples = ((1, 3), (2, 5), (3, 7), (10, 21))
        program = syn.synthesize(examples, max_size=5)
        source = syn.render(program)
        self.assertNotEqual(source.strip(), "def transform(value):\n    return (value + value)")
        self.assertEqual(compiled(source, "transform")(4), 9)


class TheBoundsAreRealAnswers(unittest.TestCase):
    def test_out_of_budget_returns_none_rather_than_guessing(self):
        """None means "not in this space", which is a fact, not a failure."""
        self.assertIsNone(
            syn.synthesize(((1, 3), (2, 5), (3, 7)), max_size=2))

    def test_an_unreachable_target_is_not_forced(self):
        self.assertIsNone(
            syn.synthesize(((1, 7), (2, 7), (3, 9)), max_size=3))

    def test_examples_are_required(self):
        with self.assertRaises(ValueError):
            syn.synthesize([])

    def test_a_candidate_that_raises_is_discarded_not_fatal(self):
        """Division by zero is reachable in the grammar and must not escape."""
        program = syn.synthesize(((4, 2), (10, 5), (8, 4)), max_size=4)
        self.assertIsNotNone(program)


class AttestorChecksWhatItWrote(unittest.TestCase):
    def test_the_emitted_function_passes_the_analyzer(self):
        program, source = syn.write_function(
            ((1, 1), (2, 4), (3, 9)), name="square")
        self.assertIsNotNone(program)
        self.assertIsNotNone(source, "Attestor faulted its own output")
        import attestor_write
        self.assertEqual(attestor_write.scan_text("square.py", source), [])
        self.assertEqual(compiled(source, "square")(6), 36)

    def test_nothing_is_returned_when_no_program_exists(self):
        program, source = syn.write_function(((1, 7), (2, 7), (3, 9)),
                                             max_size=3)
        self.assertIsNone(program)
        self.assertIsNone(source)


class LoopsAndStructuralRecursion(unittest.TestCase):
    """Loops arrive as higher-order operators whose body is also synthesized.

    Recursion is restricted to the structural kind: `fold` consumes one
    element per step and stops when the sequence is exhausted, so a
    synthesized fold terminates by construction. General self-recursion is
    not in the grammar on purpose -- an enumerative search over arbitrary
    recursive programs spends its time building things that never return.
    """

    CASES = (
        ("map", (([1, 2, 3], [1, 4, 9]), ([4], [16])), 4),
        ("filter", (([1, 2, 3, 4], [2, 4]), ([1, 3], []), ([6], [6])), 4),
        ("count", (([1, 2, 3], 2), ([2, 4], 0), ([7], 1)), 4),
        ("fold", (([1, 2, 3, 4], 24), ([5, 2], 10), ([3], 3)), 6),
        ("map+sum", (([1, 2, 3], 14), ([4], 16), ([2, 2], 8)), 6),
    )

    def test_each_loop_form_is_reachable_and_correct(self):
        for label, examples, size in self.CASES:
            with self.subTest(form=label):
                program = syn.synthesize(examples, ops=syn.LIST_OPS,
                                         max_size=size, loops=True)
                self.assertIsNotNone(program, "%s not synthesized" % label)
                fn = compiled(syn.render(program, name="f"))
                for value, expected in examples:
                    self.assertEqual(fn(list(value)), expected)

    def test_a_fold_is_real_recursion_and_terminates(self):
        program = syn.synthesize((([1, 2, 3, 4], 24), ([5, 2], 10), ([3], 3)),
                                 ops=syn.LIST_OPS, max_size=6, loops=True)
        self.assertTrue(program.uses_loop)
        fn = compiled(syn.render(program, name="f"))
        self.assertEqual(fn(list(range(1, 9))), 40320)

    def test_loops_are_off_unless_asked_for(self):
        """The pool multiplies the search, so it is opt-in."""
        self.assertIsNone(syn.synthesize(
            (([1, 2, 3], [1, 4, 9]),), ops=syn.LIST_OPS, max_size=4))

    def test_the_probe_set_distinguishes_even_from_falsy(self):
        """`not item` and `item % 2 == 0` agree on {3, -1, 0}.

        With a probe set that thin the pool dropped `is_even` as a duplicate
        and every "sum the even ones" task came back not-found.
        """
        program = syn.synthesize(
            (([1, 2, 3, 4], 6), ([2, 2], 4), ([1, 3], 0), ([10, 5, 4], 14)),
            ops=syn.LIST_OPS, max_size=5, loops=True)
        self.assertIsNotNone(program)
        self.assertEqual(compiled(syn.render(program, name="f"))([2, 3, 8]), 10)


class ItAnswersTheExamplesItWasGiven(unittest.TestCase):
    def test_the_smallest_fitting_program_may_not_generalise(self):
        """Under-specified examples get an under-specified program.

        `[1,-2,3] -> [1,3]` and `[-5] -> []` are both satisfied by
        `sorted(value)[1:]`, which is smaller than the filter and has
        nothing to do with sign. The synthesizer is not wrong here -- it
        returns the smallest program fitting what it was told, and the
        remedy is another example, not a cleverer search.
        """
        weak = (([1, -2, 3], [1, 3]), ([-5], []))
        program = syn.synthesize(weak, ops=syn.LIST_OPS, max_size=4, loops=True)
        self.assertIsNotNone(program)
        fn = compiled(syn.render(program, name="f"))
        for value, expected in weak:
            self.assertEqual(fn(list(value)), expected)

        strong = weak + (([4, -1, -9, 2], [4, 2]), ([0, 5], [5]))
        better = syn.synthesize(strong, ops=syn.LIST_OPS, max_size=4, loops=True)
        self.assertIsNotNone(better)
        sharper = compiled(syn.render(better, name="f"))
        for value, expected in strong:
            self.assertEqual(sharper(list(value)), expected)


class TheGrammarIsLarge(unittest.TestCase):
    def test_operator_inventory(self):
        counts = syn.operator_count()
        self.assertGreaterEqual(counts["total_distinct"], 100)
        for grammar in ("int", "str", "list", "predicate", "body"):
            self.assertGreaterEqual(counts[grammar], 20)
        self.assertEqual(counts["loop"], len(syn.LOOP_OPS))

    def test_every_operator_renders_with_its_own_arity(self):
        """A template that ignores an argument silently computes the wrong
        thing -- which is exactly how `(x * 2) + 1` once rendered as
        `(value + value)`."""
        for op in syn.ALL_OPS:
            with self.subTest(op=op.name):
                parts = ["a%d" % i for i in range(max(op.arity, 1))]
                text = op.template.format(*parts)
                if op.arity and not op.body:
                    for part in parts[:op.arity]:
                        self.assertIn(part, text,
                                      "%s drops %s" % (op.name, part))


if __name__ == "__main__":
    unittest.main()
