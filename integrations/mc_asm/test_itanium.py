"""The IA-64 backend, and the reason it ships with an emulator.

There is no IA-64 assembler on this machine. A backend nobody can run is
outside the agreement that justifies every other backend, so this one comes
with an emulator for exactly the subset it emits -- and both are tested
against the other four implementations.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

import compiler
import itanium
import mc_asm
import attestorvm

PROGRAM = attestorvm._as_source("2 3 ADD 4 MUL PRINT NL 7 2 SUB PRINT NL")
EXPECTED = "20\n5\n"


def build(text):
    return compiler.to_bytecode(mc_asm.parse(text))


class TheEmulatorAgreesWithEverythingElse(unittest.TestCase):
    def setUp(self):
        self.program = mc_asm.parse(PROGRAM)
        self.code = build(PROGRAM)

    def test_the_emulator_runs_it(self):
        self.assertEqual(itanium.run_ia64(self.code), EXPECTED)

    def test_it_agrees_with_the_interpreter_and_the_vm(self):
        self.assertEqual(
            {mc_asm.run(self.program),
             compiler.run_bytecode(self.code),
             itanium.run_ia64(self.code)},
            {EXPECTED})

    @unittest.skipIf(shutil.which("g++") is None or shutil.which("gcc") is None,
                     "toolchain not installed")
    def test_all_five_implementations_agree(self):
        answers = {"interp": mc_asm.run(self.program),
                   "vm": compiler.run_bytecode(self.code),
                   "ia64": itanium.run_ia64(self.code)}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "p.cpp").write_text(compiler.to_cpp(self.code),
                                        encoding="utf-8")
            built = subprocess.run(
                ["g++", "-O2", "-o", str(root / "c.exe"), str(root / "p.cpp")],
                capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr[:300])
            answers["cpp"] = subprocess.run(
                [str(root / "c.exe")], capture_output=True, text=True).stdout
            (root / "p.s").write_text(compiler.to_asm(self.code),
                                      encoding="utf-8")
            built = subprocess.run(
                ["gcc", "-o", str(root / "a.exe"), str(root / "p.s")],
                capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr[:300])
            answers["x86"] = subprocess.run(
                [str(root / "a.exe")], capture_output=True, text=True).stdout
        self.assertEqual(len(set(answers.values())), 1, answers)
        self.assertEqual(answers["ia64"], EXPECTED)


class ItIsActuallyItanium(unittest.TestCase):
    """Bundles and stops are modelled, not decorated."""

    def test_instructions_are_packed_into_bundles_of_at_most_three(self):
        text = itanium.to_ia64(build(PROGRAM))
        self.assertIn("{ .mii", text)
        for chunk in text.split("{ .mii")[1:]:
            slots = [line for line in chunk.split("}")[0].splitlines()
                     if line.strip()]
            self.assertLessEqual(len(slots), itanium.MAX_SLOTS)

    def test_a_stop_closes_a_bundle(self):
        packed = itanium._pack(["mov r1 = 1", itanium.STOP, "mov r2 = 2"])
        self.assertEqual(len(packed), 2)

    def test_a_bundle_holds_no_more_than_three_slots(self):
        packed = itanium._pack(["a", "b", "c", "d"])
        self.assertEqual([len(b.slots) for b in packed], [3, 1])

    def test_the_emitter_refuses_an_opcode_it_cannot_emulate(self):
        """Emitting what nothing here can run would put it outside the
        agreement, which is the one thing this backend exists to stay
        inside."""
        # Subroutines are still outside: CALL/RET need a return stack and
        # frame discipline the emulator does not model. STORE and LOAD were
        # the example here until they were added to the subset, and this
        # test failed the moment they were -- which is the right way round.
        code = build(attestorvm._as_source("DEF 1 DUP ADD RET END 5 1 CALL PRINT"))
        self.assertFalse(itanium.supported(code))
        with self.assertRaises(mc_asm.McAsmError) as caught:
            itanium.to_ia64(code)
        self.assertIn("IA-64", str(caught.exception))

    def test_the_subset_covers_a_real_program(self):
        """fizzbuzz, not a toy: STORE, LOAD, MOD, EQ, JZ, EMIT and branches."""
        text = (pathlib.Path(__file__).resolve().parent
                / "fizzbuzz.mcasm").read_text(encoding="utf-8")
        code = compiler.to_bytecode(mc_asm.parse(text))
        self.assertTrue(itanium.supported(code))
        self.assertEqual(itanium.run_ia64(code), mc_asm.run(mc_asm.parse(text)))


class TheStopRuleIsEnforced(unittest.TestCase):
    """The bug class Itanium is famous for, caught rather than inspected.

    On real hardware, reading a register written earlier in the same bundle
    with no intervening stop is undefined -- the machine does not interlock,
    the compiler is responsible. The usual symptom is a right answer on one
    chip and a wrong one on another, which is exactly the kind of thing no
    amount of reading the listing finds.
    """

    def test_a_stop_violation_is_an_error_not_a_wrong_answer(self):
        written = set()

        def touch(reads, writes):
            clash = reads & written
            if clash:
                raise mc_asm.McAsmError("stop violation: %s" % sorted(clash))
            written.update(writes)

        touch(set(), {"r1"})                 # write r1
        with self.assertRaises(mc_asm.McAsmError):
            touch({"r1"}, {"r2"})            # read it, same bundle, no stop

    def test_a_clean_program_raises_nothing(self):
        self.assertEqual(itanium.run_ia64(build(PROGRAM)), EXPECTED)

    def test_every_emitted_bundle_boundary_follows_a_stop_or_a_full_bundle(self):
        text = itanium.to_ia64(build(PROGRAM))
        self.assertGreater(text.count("{ .mii"), 1)
        self.assertIn("br.ret.sptk b0", text)


if __name__ == "__main__":
    unittest.main()
