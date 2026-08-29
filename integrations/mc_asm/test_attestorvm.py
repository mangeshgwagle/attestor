"""The VM as a tool: build, run, inspect, debug."""
from __future__ import annotations

import io
import pathlib
import tempfile
import unittest

import compiler
import mc_asm
import attestorvm

_HERE = pathlib.Path(__file__).resolve().parent


DOUBLE = attestorvm._as_source("DEF 1 DUP ADD RET END 21 1 CALL PRINT NL")
EXPECTED = "42\n"


class SourceEntry(unittest.TestCase):
    def test_words_numbers_and_a1z26_all_parse(self):
        self.assertEqual(attestorvm._as_source("ADD"), "1-4-4")
        self.assertEqual(attestorvm._as_source("21"), "0-2-1")
        self.assertEqual(attestorvm._as_source("1-4-4"), "1-4-4")

    def test_a_bare_number_is_a_number_not_the_letter_A(self):
        """`1` is ambiguous; at a prompt it means one.

        Reading it as A1Z26 made `21 1 CALL` fail with "A is not a word this
        language knows", which is a baffling way to be told you typed a
        number.
        """
        self.assertEqual(attestorvm._as_source("1"), "0-1")
        self.assertEqual(attestorvm._as_source("-5"), "-0-5")

    def test_a_comment_ends_the_line(self):
        self.assertEqual(attestorvm._as_source("ADD ; and the rest"), "1-4-4")


class ObjectFiles(unittest.TestCase):
    def roundtrip(self):
        code = attestorvm.build(DOUBLE)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "p.mcb"
            attestorvm.save(code, path)
            return code, attestorvm.load(path), path.read_text(encoding="utf-8")

    def test_a_built_object_reloads_identically(self):
        code, back, _ = self.roundtrip()
        self.assertEqual(list(back), list(code))
        self.assertEqual(back.routines, code.routines)

    def test_a_reloaded_object_still_runs(self):
        _, back, _ = self.roundtrip()
        self.assertEqual(compiler.run_bytecode(back), EXPECTED)

    def test_the_object_is_readable_text(self):
        """Diffable on purpose: this project's method is comparing two
        implementations, and a format you cannot read is one you cannot
        diff."""
        _, _, text = self.roundtrip()
        self.assertIn(attestorvm.MAGIC, text)
        self.assertIn("routines", text)

    def test_a_truncated_object_is_refused_when_loaded(self):
        """Loudly, and at load, rather than halfway through a run."""
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "p.mcb"
            attestorvm.save(attestorvm.build(DOUBLE), path)
            body = path.read_text(encoding="utf-8").replace('"code": [', '"code": [99, ')
            path.write_text(body, encoding="utf-8")
            with self.assertRaises(mc_asm.McAsmError) as caught:
                attestorvm.load(path)
            self.assertIn("digest", str(caught.exception))

    def test_a_file_that_is_not_an_object_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "p.mcb"
            path.write_text("not json at all", encoding="utf-8")
            with self.assertRaises(mc_asm.McAsmError):
                attestorvm.load(path)


class Inspection(unittest.TestCase):
    def setUp(self):
        self.code = attestorvm.build(DOUBLE)

    def test_the_listing_names_the_routine_and_the_jump_targets(self):
        listing = attestorvm.disassemble(self.code)
        self.assertIn("<- routine 1", listing)
        self.assertIn("<- jump target", listing)
        self.assertIn("CALL", listing)

    def test_a_trace_shows_the_call_and_the_return(self):
        text = attestorvm.trace(self.code)
        self.assertIn("CALL", text)
        self.assertIn("RET", text)
        self.assertIn("output:", text)
        self.assertIn("42", text)

    def test_a_trace_is_capped_so_a_long_loop_cannot_flood_the_terminal(self):
        text = attestorvm.trace(self.code, limit=3)
        self.assertIn("more steps", text)
        self.assertLess(len(text.splitlines()), 12)

    def test_stats_counts_every_instruction(self):
        text = attestorvm.stats(self.code)
        self.assertIn("instructions in", text)
        self.assertIn("CALL", text)

    def test_the_observer_does_not_change_the_answer(self):
        """A debugger that disagrees with the runtime is worse than none."""
        seen = []
        watched = compiler.run_bytecode(self.code,
                                        observer=lambda p, s: seen.append(p))
        self.assertEqual(watched, compiler.run_bytecode(self.code))
        self.assertEqual(watched, EXPECTED)
        self.assertTrue(seen)


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = attestorvm.main(list(args))
        return status, out.getvalue()

    def test_run_build_and_run_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "p.mcasm"
            source.write_text(DOUBLE, encoding="utf-8")
            status, text = self.run_cli("run", str(source))
            self.assertEqual((status, text), (0, EXPECTED))

            obj = root / "p.mcb"
            status, text = self.run_cli("build", str(source), "-o", str(obj))
            self.assertEqual(status, 0)
            self.assertIn("1 routine", text)

            status, text = self.run_cli("run", str(obj))
            self.assertEqual((status, text), (0, EXPECTED))

    def test_a_missing_file_is_an_error_not_a_traceback(self):
        self.assertEqual(attestorvm.main(["run", "nowhere.mcasm"]), 2)

    def test_no_command_prints_help(self):
        self.assertEqual(attestorvm.main([]), 2)


class Repl(unittest.TestCase):
    def test_it_accumulates_lines_and_shows_the_answer(self):
        typed = iter(["21", "DUP ADD PRINT", ":q"])
        said = []
        attestorvm.repl(read=lambda _p: next(typed), write=said.append)
        self.assertTrue(any("42" in line for line in said))

    def test_a_bad_line_is_reported_and_does_not_end_the_session(self):
        typed = iter(["NONSENSEWORD", "21 PRINT", ":q"])
        said = []
        attestorvm.repl(read=lambda _p: next(typed), write=said.append)
        self.assertTrue(any("21" in line for line in said))

    def test_a_failed_line_is_not_kept_in_history(self):
        """Otherwise every later line inherits the error."""
        typed = iter(["9 9 ADD ADD", "7 PRINT", ":q"])
        said = []
        attestorvm.repl(read=lambda _p: next(typed), write=said.append)
        self.assertTrue(any("7" in line for line in said))


class AMachineYouCanKeep(unittest.TestCase):
    """The shape the VM needs to be used inside something.

    The module functions are right for a command line, where every run
    starts from nothing. They are wrong for Attestor's analyser or a test
    harness, which load once and run repeatedly.
    """

    def test_the_same_machine_runs_twice_with_the_same_answer(self):
        machine = attestorvm.Machine(DOUBLE)
        self.assertEqual(machine.run(), EXPECTED)
        self.assertEqual(machine.run(), EXPECTED)

    def test_nothing_is_carried_between_runs(self):
        """A VM that remembers the last run is one whose second answer you
        cannot trust."""
        machine = attestorvm.Machine(attestorvm._as_source("7 PRINT"))
        first = machine.run()
        self.assertEqual(machine.run(), first)

    def test_it_can_count_what_it_executed(self):
        machine = attestorvm.Machine(DOUBLE)
        machine.run(count=True)
        self.assertGreater(machine.last_steps, 0)
        self.assertIn("CALL", machine.last_counts)

    def test_it_exposes_the_routines_and_the_listing(self):
        machine = attestorvm.Machine(DOUBLE)
        self.assertEqual(set(machine.routines), {1})
        self.assertIn("CALL", machine.disassemble())
        self.assertEqual(len(machine), len(machine.code))

    def test_attestor_can_check_the_loaded_program(self):
        clean = attestorvm.Machine(attestorvm._as_source("21 1 ADD PRINT"))
        self.assertEqual(clean.check(), [])
        broken = attestorvm.Machine(attestorvm._as_source("9 ADD PRINT"))
        self.assertTrue(broken.check())

    def test_the_differential_check_is_one_call(self):
        self.assertTrue(attestorvm.Machine(DOUBLE).agrees_with_interpreter())

    def test_both_engines_get_the_same_step_budget(self):
        """Impossible until the interpreter took max_steps as a parameter.

        Comparing them meant patching mc_asm.0 from outside, and a
        differential check that needs monkey-patching is one nobody runs.
        """
        machine = attestorvm.Machine(DOUBLE, max_steps=3)
        with self.assertRaises(mc_asm.McAsmError):
            machine.agrees_with_interpreter()

    def test_a_machine_from_bytecode_says_it_cannot_compare(self):
        """Rather than pretending; the interpreter cannot run bytecode."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "p.mcb"
            attestorvm.save(attestorvm.build(DOUBLE), path)
            machine = attestorvm.Machine.from_path(path)
            self.assertEqual(machine.run(), EXPECTED)
            with self.assertRaises(ValueError):
                machine.agrees_with_interpreter()

    def test_it_needs_exactly_one_of_source_or_code(self):
        with self.assertRaises(ValueError):
            attestorvm.Machine()
        with self.assertRaises(ValueError):
            attestorvm.Machine(DOUBLE, code=attestorvm.build(DOUBLE))


class TheParserIsCached(unittest.TestCase):
    def test_a_repeated_token_gives_the_same_instruction_value(self):
        """The cache must not confuse two tokens that decode differently."""
        program = mc_asm.parse(attestorvm._as_source("1 1 ADD 2 ADD PRINT"))
        pushes = [i.value for i in program if i.kind == "push"]
        self.assertEqual(pushes, [1, 1, 2])

    def test_fizzbuzz_still_parses_to_the_same_answer(self):
        text = pathlib.Path(_HERE / "fizzbuzz.mcasm").read_text(encoding="utf-8")
        self.assertTrue(attestorvm.Machine(text).agrees_with_interpreter())


if __name__ == "__main__":
    unittest.main()
