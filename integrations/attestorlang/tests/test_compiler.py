from __future__ import annotations

import base64
import pathlib
import sys
import unittest

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

import bytecode as bc
import compiler
from model import SourceError
import vm


def source(body: str, capabilities: tuple[str, ...] = ("console.write",)) -> str:
    requirements = "".join(f"requires {name};\n" for name in capabilities)
    return f"attestor 4.2;\n{requirements}scene Main {{\n{body}\n}}\n"


def output(report: dict) -> bytes:
    return base64.b64decode(report["output"]["base64"], validate=True)


class StructuredLanguage(unittest.TestCase):
    def test_immutable_let_arithmetic_and_shakespeare_output(self):
        program = compiler.compile_source(source(
            'let x: i64 = 6 * 7; Attestor says text("answer="); '
            'Attestor says number(x);'))
        report = vm.execute(program)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(output(report), b"answer=42")

    def test_subtraction_needs_no_whitespace_and_keeps_precedence(self):
        program = compiler.compile_source(source(
            "let x=4-2*3; Attestor says number(x);"))
        self.assertEqual(output(vm.execute(program)), b"-2")

    def test_minimum_i64_literal_is_representable(self):
        program = compiler.compile_source(source(
            "let x=-9223372036854775808; Attestor says number(x);"))
        self.assertEqual(output(vm.execute(program)), b"-9223372036854775808")

    def test_actor_name_is_syntactic_not_authority(self):
        program = compiler.compile_source(source('Hamlet says number(9);'))
        self.assertEqual(output(vm.execute(program)), b"9")

    def test_duplicate_immutable_binding_is_refused(self):
        with self.assertRaisesRegex(SourceError, "already defined"):
            compiler.compile_source(source("let x = 1; let x = 2;", ()))

    def test_binding_type_is_checked(self):
        with self.assertRaisesRegex(SourceError, "does not match"):
            compiler.compile_source(source('let x: i64 = "wrong";', ()))

    def test_unknown_binding_is_refused(self):
        with self.assertRaisesRegex(SourceError, "unknown immutable"):
            compiler.compile_source(source("Attestor says number(missing);"))

    def test_effect_must_be_declared(self):
        with self.assertRaisesRegex(SourceError, "undeclared capabilities"):
            compiler.compile_source(source("Attestor says number(1);", ()))

    def test_unsupported_capability_is_refused(self):
        bad = source("", ("host.exec",))
        with self.assertRaisesRegex(SourceError, "unsupported capability"):
            compiler.compile_source(bad)

    def test_source_requires_exact_header_and_main_scene(self):
        for bad in (
            "scene Main {}",
            "attestor 4.1; scene Main {}",
            "attestor 4.2; scene Other {}",
            "attestor 4.2; scene Main {} scene Main {}",
        ):
            with self.subTest(source=bad):
                with self.assertRaises(SourceError):
                    compiler.compile_source(bad)

    def test_invisible_non_ascii_whitespace_is_refused_outside_text(self):
        with self.assertRaises(SourceError):
            compiler.compile_source("attestor\u00a04.2; scene Main {}")

    def test_deep_parentheses_fail_at_the_language_boundary(self):
        nested = "(" * 2000 + "1" + ")" * 2000
        with self.assertRaisesRegex(SourceError, "nesting exceeds"):
            compiler.compile_source(source(f"let x = {nested};", ()))

    def test_deep_unary_chain_fails_at_the_language_boundary(self):
        nested = "-" * 2000 + "1"
        with self.assertRaisesRegex(SourceError, "nesting exceeds"):
            compiler.compile_source(source(f"let x = {nested};", ()))


class AssemblyAndA1Z26(unittest.TestCase):
    def test_asr_is_signed_arithmetic_shift(self):
        program = compiler.compile_source(source(
            "asm { push -8; push 2; asr; print; }"))
        self.assertEqual(output(vm.execute(program)), b"-2")

    def test_pure_asr_expression(self):
        program = compiler.compile_source(source(
            "let x = asr(-64, 3); Attestor says number(x);"))
        self.assertEqual(output(vm.execute(program)), b"-8")

    def test_human_asm_and_a1z26_lower_identically(self):
        human = compiler.compile_source(source("asm { push 42; print; }"))
        numeric = compiler.compile_source(source(
            "a1z26 { 0-4-2 16-18-9-14-20 }"))
        self.assertEqual(human, numeric)
        self.assertEqual(bc.encode(human), bc.encode(numeric))

    def test_a1z26_refuses_out_of_alphabet_components(self):
        with self.assertRaisesRegex(SourceError, "1 through 26"):
            compiler.compile_source(source("a1z26 { 27-1 }", ()))

    def test_asm_unknown_word_is_refused(self):
        with self.assertRaisesRegex(SourceError, "unknown assembly"):
            compiler.compile_source(source("asm { syscall; }", ()))

    def test_assembly_stack_is_verified(self):
        with self.assertRaisesRegex(Exception, "empty stack|expects"):
            compiler.compile_source(source("asm { add; }", ()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
