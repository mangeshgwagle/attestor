"""All four ways of running mc.asm must agree, subroutines included.

Until now the compiled backends refused any program containing DEF, CALL,
RET, FRAME, GET, PUT, ROT or DEPTH -- eight of the language's 38 words had
no bytecode form, so procedures worked on the interpreter and nowhere else.
That put the most useful half of the language outside the three-way
agreement that is the only reason the compiled backends exist.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

import compiler
import mc_asm


def source(text: str) -> str:
    """Plain words to A1Z26. Numbers are `0-` then their digits."""
    return " ".join(
        "0-" + "-".join(token) if token.isdigit()
        else "-".join(str(ord(letter) - 64) for letter in token.upper())
        for token in text.split())


# A routine with two locals, plus the two stack words that had no opcode.
WITH_ROUTINES = source(
    "DEF 1 2 FRAME 3 0 PUT 4 1 PUT 0 GET 1 GET MUL RET END "
    "1 CALL PRINT NL 1 2 3 ROT PRINT PRINT PRINT NL DEPTH PRINT NL")
EXPECTED = "12\n132\n0\n"


class EveryWordHasABytecodeForm(unittest.TestCase):
    def test_no_word_is_interpreter_only(self):
        structural = {"IF", "ELSE", "END", "DO", "WHILE", "DEF"}
        for word in mc_asm.WORDS:
            if word in structural:
                continue
            with self.subTest(word=word):
                self.assertTrue(
                    word in compiler.OPCODES or word in compiler.LOWERED,
                    "%s still has no bytecode form" % word)

    def test_the_eight_that_were_missing_are_present(self):
        for word in ("ROT", "DEPTH", "CALL", "RET", "FRAME", "GET", "PUT"):
            self.assertIn(word, compiler.OPCODES)


class TheBackendsAgree(unittest.TestCase):
    def setUp(self):
        self.program = mc_asm.parse(WITH_ROUTINES)
        self.code = compiler.to_bytecode(self.program)

    def test_the_interpreter_runs_it(self):
        self.assertEqual(mc_asm.run(self.program), EXPECTED)

    def test_the_bytecode_vm_runs_it(self):
        self.assertEqual(compiler.run_bytecode(self.code), EXPECTED)

    def test_a_routine_gets_an_address(self):
        self.assertEqual(set(self.code.routines), {1})

    def _build_and_run(self, text, name, command):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source_file = root / name
            source_file.write_text(text, encoding="utf-8")
            binary = root / "out.exe"
            built = subprocess.run(command + ["-o", str(binary),
                                              str(source_file)],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr[:400])
            done = subprocess.run([str(binary)], capture_output=True,
                                  text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr[:400])
            return done.stdout

    @unittest.skipIf(shutil.which("g++") is None, "g++ not installed")
    def test_the_cpp_backend_runs_it(self):
        self.assertEqual(
            self._build_and_run(compiler.to_cpp(self.code), "p.cpp",
                                ["g++", "-O2"]),
            EXPECTED)

    @unittest.skipIf(shutil.which("gcc") is None, "gcc not installed")
    def test_the_x86_backend_runs_it(self):
        self.assertEqual(
            self._build_and_run(compiler.to_asm(self.code), "p.s", ["gcc"]),
            EXPECTED)

    @unittest.skipIf(shutil.which("g++") is None or shutil.which("gcc") is None,
                     "toolchain not installed")
    def test_all_four_produce_the_same_bytes(self):
        """The differential criterion, applied to a compiler.

        Four implementations either produce identical output or one of them
        is wrong, and which is wrong is usually obvious from which three
        agree.
        """
        answers = {
            "interpreter": mc_asm.run(self.program),
            "bytecode": compiler.run_bytecode(self.code),
            "cpp": self._build_and_run(compiler.to_cpp(self.code), "p.cpp",
                                       ["g++", "-O2"]),
            "x86-64": self._build_and_run(compiler.to_asm(self.code), "p.s",
                                          ["gcc"]),
        }
        self.assertEqual(len(set(answers.values())), 1, answers)
        self.assertEqual(answers["interpreter"], EXPECTED)


if __name__ == "__main__":
    unittest.main()
