from __future__ import annotations

import base64
import hashlib
import pathlib
import sys
import unittest

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

import bytecode as bc
import compiler
from model import I64_MAX, Limits, TRIT_WORD_MAX, canonical_json
import vm


def make(body: str, caps=("console.write",)) -> bc.Program:
    requirements = "".join(f"requires {cap};" for cap in caps)
    return compiler.compile_source(
        f"attestor 4.2; {requirements} scene Main {{ {body} }}")


def output(report: dict) -> bytes:
    return base64.b64decode(report["output"]["base64"], validate=True)


class IntegerSemantics(unittest.TestCase):
    def test_checked_overflow_traps(self):
        report = vm.execute(make(
            f"asm {{ push {I64_MAX}; push 1; add; print; }}"))
        self.assertEqual(report["status"], "trapped")
        self.assertIn("overflow", report["error"]["message"])

    def test_explicit_wrapping_add(self):
        report = vm.execute(make(
            f"asm {{ push {I64_MAX}; push 1; addw; print; }}"))
        self.assertEqual(output(report), str(-(2 ** 63)).encode("ascii"))

    def test_floor_division_and_modulo(self):
        program = make(
            "asm { push -7; push 2; div; print; push 32; putc; "
            "push -7; push 2; mod; print; }")
        self.assertEqual(output(vm.execute(program)), b"-4 1")

    def test_division_by_zero_traps(self):
        report = vm.execute(make("asm { push 1; push 0; div; print; }"))
        self.assertEqual(report["status"], "trapped")
        self.assertIn("zero", report["error"]["message"])

    def test_shift_count_is_bounded(self):
        report = vm.execute(make("asm { push 1; push 64; asr; print; }"))
        self.assertEqual(report["status"], "trapped")
        self.assertIn("0 and 63", report["error"]["message"])


class MalbolgeInspiredOperations(unittest.TestCase):
    def test_crazy_table_orientation_is_pinned(self):
        self.assertEqual(vm.crazy(0, 0), sum(3 ** i for i in range(10)))
        self.assertEqual(vm.crazy(1, 0) % 3, 1)
        self.assertEqual(vm.crazy(0, 1) % 3, 0)

    def test_rotrit_rotates_exactly_ten_trits(self):
        self.assertEqual(vm.rotrit(1), 3 ** 9)
        self.assertEqual(vm.rotrit(3 ** 9), 3 ** 8)

    def test_ternary_domain_is_enforced(self):
        report = vm.execute(make(
            f"let x = rotrit({TRIT_WORD_MAX + 1}); Attestor says number(x);"))
        self.assertEqual(report["status"], "trapped")
        self.assertIn("10-trit", report["error"]["message"])


class Brainfuck(unittest.TestCase):
    def test_embedded_program_outputs_A(self):
        report = vm.execute(make(
            "brainfuck { +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++. }"))
        self.assertEqual(output(report), b"A")

    def test_loop_lowering(self):
        report = vm.execute(make(
            "brainfuck { +++[>++++++++++++++++++++++<-]>-. }"))
        self.assertEqual(output(report), b"A")

    def test_input_is_virtual_and_eof_is_zero(self):
        program = make("brainfuck { ,.,. }", ("console.write", "input.read"))
        report = vm.execute(
            program,
            granted_capabilities=("console.write", "input.read"),
            input_bytes=b"Z",
        )
        self.assertEqual(output(report), b"Z\x00")
        self.assertEqual(report["usage"]["input_consumed"], 1)

    def test_tape_underflow_traps(self):
        report = vm.execute(make("brainfuck { < }", ()))
        self.assertEqual(report["status"], "trapped")
        self.assertIn("left boundary", report["error"]["message"])

    def test_tape_overflow_traps(self):
        report = vm.execute(
            make("brainfuck { >> }", ()), limits=Limits(tape_cells=2))
        self.assertEqual(report["status"], "trapped")
        self.assertIn("right boundary", report["error"]["message"])

    def test_unbalanced_brackets_are_compile_errors(self):
        for body in ("brainfuck { [ }", "brainfuck { ] }"):
            with self.subTest(body=body):
                with self.assertRaises(Exception):
                    make(body, ())


class CapabilitiesAndEvidence(unittest.TestCase):
    def test_missing_runtime_grant_refuses_before_step_zero(self):
        report = vm.execute(make("Attestor says number(1);"), granted_capabilities=())
        self.assertEqual(report["status"], "refused")
        self.assertEqual(report["usage"]["steps"], 0)
        self.assertEqual(report["capabilities"]["denied"], ["console.write"])

    def test_output_boundary_traps_without_overflowing_report(self):
        program = make('Attestor says text("abcd");')
        report = vm.execute(program, limits=Limits(max_output_bytes=3))
        self.assertEqual(report["status"], "trapped")
        self.assertEqual(output(report), b"")

    def test_step_boundary_is_deterministic(self):
        program = make("brainfuck { +[+] }", ())
        report = vm.execute(program, limits=Limits(max_steps=20))
        self.assertEqual(report["status"], "trapped")
        self.assertEqual(report["usage"]["steps"], 20)

    def test_identical_runs_have_identical_reports(self):
        program = make("Attestor says number(42);")
        one = vm.execute(program, source_bytes=b"same")
        two = vm.execute(program, source_bytes=b"same")
        self.assertEqual(one, two)
        self.assertEqual(one["report_sha256"], two["report_sha256"])

    def test_virtual_input_digest_binds_same_length_inputs(self):
        program = make("brainfuck { ,. }", ("console.write", "input.read"))
        first = vm.execute(
            program, granted_capabilities=("console.write", "input.read"),
            input_bytes=b"A")
        second = vm.execute(
            program, granted_capabilities=("console.write", "input.read"),
            input_bytes=b"B")
        self.assertNotEqual(first["usage"]["input_sha256"],
                            second["usage"]["input_sha256"])
        self.assertNotEqual(first["report_sha256"], second["report_sha256"])

    def test_report_replay_verification(self):
        report = vm.execute(make("Attestor says number(42);"))
        self.assertEqual(vm.verify_report(report), (True, []))
        changed = {**report, "status": "trapped"}
        valid, errors = vm.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("does not match" in error for error in errors))

    def test_report_verifier_checks_output_even_with_recomputed_report_hash(self):
        report = vm.execute(make("Attestor says number(42);"))
        changed = {**report, "output": {**report["output"], "base64": "NDM="}}
        unsigned = dict(changed)
        unsigned.pop("report_sha256")
        changed["report_sha256"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()
        valid, errors = vm.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("output" in error for error in errors))

    def test_execution_boundary_is_explicit(self):
        report = vm.execute(make("", ()))
        self.assertTrue(report["execution"])
        self.assertTrue(all(value is False for value in report["execution"].values()))

    def test_report_verifier_rejects_extra_effects_with_a_recomputed_digest(self):
        report = vm.execute(make("", ()))
        changed = {**report, "execution": {
            **report["execution"], "filesystem_mutated": True}}
        unsigned = dict(changed)
        unsigned.pop("report_sha256")
        changed["report_sha256"] = hashlib.sha256(
            canonical_json(unsigned)).hexdigest()
        valid, errors = vm.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("execution boundary" in error for error in errors))

    def test_report_verifier_rejects_impossible_runtime_limits(self):
        report = vm.execute(make("", ()))
        changed = {**report, "limits": {
            **report["limits"], "max_steps": 10_000_001}}
        unsigned = dict(changed)
        unsigned.pop("report_sha256")
        changed["report_sha256"] = hashlib.sha256(
            canonical_json(unsigned)).hexdigest()
        valid, errors = vm.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("limits" in error for error in errors))

    def test_refusal_cannot_claim_post_execution_steps(self):
        report = vm.execute(
            make("Attestor says number(1);"), granted_capabilities=())
        changed = {**report, "usage": {**report["usage"], "steps": 1}}
        unsigned = dict(changed)
        unsigned.pop("report_sha256")
        changed["report_sha256"] = hashlib.sha256(
            canonical_json(unsigned)).hexdigest()
        valid, errors = vm.verify_report(changed)
        self.assertFalse(valid)
        self.assertTrue(any("post-execution" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
