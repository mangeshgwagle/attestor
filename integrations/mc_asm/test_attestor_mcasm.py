"""Attestor analysing the language this project invented."""
from __future__ import annotations

import unittest

import compiler
import attestor_mcasm as attestor
import attestorvm


def rules(text: str):
    return [f.rule for f in attestor.analyse_source(attestorvm._as_source(text))]


class ItProvesThingsATextRuleCouldNot(unittest.TestCase):
    """The analysis reads bytecode, not source.

    mc.asm source is A1Z26 -- `1-4-4` is ADD -- so a regex over the text
    sees digits and hyphens. In the bytecode every opcode's stack effect is
    known and jumps are resolved, which is what makes depth tracking
    possible at all.
    """

    def test_a_correct_program_is_clean(self):
        for text in ("21 1 ADD PRINT NL",
                     "DEF 1 DUP ADD RET END 5 1 CALL PRINT",
                     "1 2 3 ROT PRINT PRINT PRINT"):
            with self.subTest(text=text):
                self.assertEqual(rules(text), [])

    def test_a_stack_underflow_is_found(self):
        self.assertIn("mcasm-stack-underflow", rules("9 ADD PRINT"))

    def test_a_literal_zero_divisor_is_found(self):
        self.assertIn("mcasm-divide-by-zero", rules("10 0 DIV PRINT"))
        self.assertIn("mcasm-divide-by-zero", rules("10 0 MOD PRINT"))

    def test_a_nonzero_divisor_is_not_reported(self):
        self.assertEqual(rules("10 2 DIV PRINT"), [])

    def test_a_routine_nobody_calls_is_found(self):
        self.assertIn("mcasm-unused-routine",
                      rules("DEF 1 DUP ADD RET END 5 PRINT"))

    def test_a_routine_that_is_called_is_not_reported(self):
        self.assertNotIn("mcasm-unused-routine",
                         rules("DEF 1 DUP ADD RET END 5 1 CALL PRINT"))

    def test_depth_is_merged_pessimistically_across_branches(self):
        """Where two paths disagree, the shallower one decides.

        The question is whether an operand *can* be missing, not whether it
        usually is, so keeping the smaller depth is the sound direction.
        """
        self.assertIn("mcasm-stack-underflow",
                      rules("1 IF 7 END ADD PRINT"))


class AttestorFoundDeadCodeInTheCompiler(unittest.TestCase):
    """These two findings were real, and the fix went into the compiler.

    A DEF's routine id was emitted as a runtime PUSH that the DEF's own jump
    skipped over, and `RET END` emitted two RETs with the second
    unreachable. Both fired on every program containing a routine.
    """

    SOURCE = "DEF 1 DUP ADD RET END 21 1 CALL PRINT NL"

    def test_no_unreachable_code_is_emitted_for_a_routine(self):
        self.assertNotIn("mcasm-unreachable", rules(self.SOURCE))

    def test_the_routine_id_is_not_pushed_at_runtime(self):
        code = attestorvm.build(attestorvm._as_source(self.SOURCE))
        self.assertEqual(len(code), 14)

    def test_the_program_still_produces_the_same_answer(self):
        code = attestorvm.build(attestorvm._as_source(self.SOURCE))
        self.assertEqual(compiler.run_bytecode(code), "42\n")

    def test_a_duplicate_ret_is_not_emitted(self):
        code = attestorvm.build(attestorvm._as_source(self.SOURCE))
        ret = compiler.OPCODES["RET"]
        pairs = [1 for index in range(len(code) - 1)
                 if code[index] == ret and code[index + 1] == ret]
        self.assertEqual(pairs, [])


class TheCommandLine(unittest.TestCase):
    def test_it_reports_a_status_that_reflects_the_findings(self):
        import pathlib
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            good = pathlib.Path(tmp) / "good.mcasm"
            good.write_text(attestorvm._as_source("21 1 ADD PRINT"), encoding="utf-8")
            bad = pathlib.Path(tmp) / "bad.mcasm"
            bad.write_text(attestorvm._as_source("9 ADD PRINT"), encoding="utf-8")
            self.assertEqual(attestor.main([str(good)]), 0)
            self.assertEqual(attestor.main([str(bad)]), 1)

    def test_a_missing_file_is_an_error_not_a_traceback(self):
        self.assertEqual(attestor.main(["nowhere.mcasm"]), 2)


if __name__ == "__main__":
    unittest.main()
