from __future__ import annotations

import pathlib
import hashlib
import json
import sys
import unittest

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))

import bytecode as bc
import compiler
from model import BytecodeError


class Container(unittest.TestCase):
    def test_round_trip_is_exact_and_deterministic(self):
        source = "attestor 4.2; scene Main { let x = 42; }"
        program = compiler.compile_source(source)
        one = bc.encode(program)
        two = bc.encode(program)
        self.assertEqual(one, two)
        self.assertEqual(bc.decode(one), program)

    def test_arbitrary_native_bytes_are_not_owvm(self):
        for raw in (b"\x90\x90\xc3", b"MZ" + b"\0" * 100,
                    b"\x7fELF" + b"\0" * 100):
            with self.subTest(raw=raw[:4]):
                with self.assertRaises(BytecodeError):
                    bc.decode(raw)

    def test_payload_damage_is_detected(self):
        blob = bytearray(bc.encode(bc.Program(code=((bc.HALT,),))))
        blob[-1] ^= 1
        with self.assertRaisesRegex(BytecodeError, "SHA-256"):
            bc.decode(bytes(blob))

    def test_trailing_bytes_are_detected(self):
        blob = bc.encode(bc.Program(code=((bc.HALT,),))) + b"x"
        with self.assertRaises(BytecodeError):
            bc.decode(blob)

    def test_boolean_format_value_is_not_integer_format_one(self):
        payload = json.dumps({
            "capabilities": [], "code": [[bc.HALT]], "constants": [],
            "format": True, "local_types": [],
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        blob = (bc.MAGIC + len(payload).to_bytes(4, "big")
                + hashlib.sha256(payload).digest() + payload)
        with self.assertRaisesRegex(BytecodeError, "format"):
            bc.decode(blob)

    def test_disassembly_names_virtual_opcodes(self):
        program = bc.Program(code=((bc.PUSH_I64, -8), (bc.PUSH_I64, 2),
                                   (bc.ASR,), (bc.POP,), (bc.HALT,)))
        text = bc.disassemble(program)
        self.assertIn("ASR", text)
        self.assertIn("PUSH_I64 -8", text)


class Verifier(unittest.TestCase):
    def test_unknown_opcode_is_refused(self):
        with self.assertRaisesRegex(BytecodeError, "unknown opcode"):
            bc.verify(bc.Program(code=((999,), (bc.HALT,))))

    def test_stack_underflow_is_refused_before_execution(self):
        with self.assertRaisesRegex(BytecodeError, "expects i64"):
            bc.verify(bc.Program(code=((bc.ADD,), (bc.HALT,))))

    def test_missing_effect_declaration_is_refused(self):
        program = bc.Program(code=((bc.PUSH_I64, 1), (bc.PRINT_NUMBER,),
                                   (bc.HALT,)))
        with self.assertRaisesRegex(BytecodeError, "console.write"):
            bc.verify(program)

    def test_invalid_jump_target_is_refused(self):
        program = bc.Program(code=((bc.BF_JZ, 99), (bc.HALT,)))
        with self.assertRaisesRegex(BytecodeError, "jump target"):
            bc.verify(program)

    def test_unreachable_instruction_is_refused(self):
        program = bc.Program(code=((bc.BF_JZ, 2), (bc.BF_JNZ, 2),
                                   (bc.HALT,)), capabilities=())
        # All three are reachable; construct an actually unreachable middle
        # instruction by a jump whose two successors coincide at index 2.
        program = bc.Program(code=((bc.BF_JZ, 2), (bc.HALT,), (bc.HALT,)))
        with self.assertRaises(BytecodeError):
            bc.verify(program)

    def test_immutable_local_cannot_be_rewritten(self):
        program = bc.Program(
            code=((bc.PUSH_I64, 1), (bc.STORE_LOCAL, 0),
                  (bc.PUSH_I64, 2), (bc.STORE_LOCAL, 0), (bc.HALT,)),
            local_types=("i64",),
        )
        with self.assertRaisesRegex(BytecodeError, "rewrites"):
            bc.verify(program)

    def test_control_flow_join_requires_same_stack(self):
        program = bc.Program(code=(
            (bc.BF_JZ, 2), (bc.PUSH_I64, 1), (bc.HALT,)))
        with self.assertRaisesRegex(BytecodeError, "inconsistent state|HALT"):
            bc.verify(program)

    def test_exactly_one_final_halt_is_required(self):
        for code in (((bc.PUSH_I64, 1),),
                     ((bc.HALT,), (bc.HALT,))):
            with self.subTest(code=code):
                with self.assertRaises(BytecodeError):
                    bc.verify(bc.Program(code=code))


if __name__ == "__main__":
    unittest.main(verbosity=2)
