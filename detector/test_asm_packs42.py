#!/usr/bin/env python3
"""Assembly rule packs: x86-64 and IBM High Level Assembler.

Two dialects that share nothing but the word "assembler", so each gets its own
masker and its own tests. The masking is where this pack can go wrong quietly,
and both failure modes are asserted directly:

* In x86 a mnemonic can appear inside a string constant, and a comment can
  describe the exact instruction the rule hunts for.
* In HLASM `*` in column 1 opens a comment but `*` anywhere else is
  multiplication and the location counter, so a masker that treats the
  character as a delimiter erases arithmetic. `DC C'MODESET KEY=ZERO'` is data
  that reads exactly like the privileged instruction it names.

Every rule is also run against a clean variant of the same program, because a
rule that fires on both tells a reviewer nothing.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detect  # noqa: E402


X86_MALICIOUS = (
    "section .text\n"
    "    mov rsp, rax\n"                 # stack pivot
    "    mov rax, 59\n"
    "    syscall\n"                      # direct execve
    "    int 0x80\n"                     # legacy gate
    + "    nop\n" * 20 +                 # sled
    '    .section .data,"awx"\n'         # W^X
)

X86_CLEAN = (
    "section .text\n"
    "global _start\n"
    "_start:\n"
    "    mov rax, 1\n"
    "    mov rdi, 1\n"
    "    syscall\n"
    "    push rbp\n"
    "    mov rbp, rsp\n"
    "    pop rbp\n"
    "    ret\n"
    '    .section .note.GNU-stack,"",@progbits\n'
)

HLASM_PRIVILEGED = (
    "MAIN     CSECT\n"
    "         MODESET KEY=ZERO            GO AUTHORISED\n"
    "         SPKA  0(R2)                 SET PSW KEY\n"
    "         SVC   120                   RAW SUPERVISOR CALL\n"
    "         EX    R3,MOVEIT             VARIABLE LENGTH MOVE\n"
)

HLASM_CLEAN = (
    "MAIN     CSECT\n"
    "         LA    R1,4095*2             ARITHMETIC USES STAR\n"
    "         MVC   TARGET(80),SOURCE     FIXED LENGTH MOVE\n"
    "         BR    R14\n"
)


def fired(source: str, lang: str) -> set[str]:
    return {row.rule for row in detect.scan_source(source, "t", lang, deep=True)
            if row.rule.startswith(("asm-", "hlasm-"))}


class LanguageDetection(unittest.TestCase):
    def test_the_two_dialects_are_recognised_separately(self):
        for suffix, expected in ((".asm", "asm"), (".s", "asm"), (".nasm", "asm"),
                                 (".mlc", "hlasm"), (".hlasm", "hlasm")):
            with self.subTest(suffix=suffix):
                self.assertEqual(detect.language_for("x" + suffix), expected)

    def test_the_dialects_do_not_share_rules(self):
        """An HLASM rule must never fire on x86 and vice versa."""
        self.assertFalse({r for r in fired(X86_MALICIOUS, "asm")
                          if r.startswith("hlasm-")})
        self.assertFalse({r for r in fired(HLASM_PRIVILEGED, "hlasm")
                          if r.startswith("asm-")})


class X86Rules(unittest.TestCase):
    def test_every_x86_rule_fires(self):
        found = fired(X86_MALICIOUS, "asm")
        for rule in ("asm-stack-pivot", "asm-direct-execve", "asm-legacy-int80",
                     "asm-nop-sled", "asm-writable-executable-section"):
            with self.subTest(rule=rule):
                self.assertIn(rule, found)

    def test_ordinary_assembly_is_silent(self):
        self.assertEqual(set(), fired(X86_CLEAN, "asm"))

    def test_a_shell_path_below_the_code_is_still_found(self):
        """Shellcode usually labels its path after the instructions."""
        payload = ('section .text\n    lea rdi,[path]\n    syscall\n'
                   'path: db "/bin/sh",0\n')
        self.assertIn("asm-direct-execve", fired(payload, "asm"))

    def test_a_comment_describing_an_instruction_is_not_one(self):
        prose = ('; mov rsp, rax would be a stack pivot\n'
                 '; .section .data,"awx" is forbidden here\n'
                 '    ret\n')
        self.assertEqual(set(), fired(prose, "asm"))

    def test_a_mnemonic_inside_a_string_is_not_an_instruction(self):
        data = 'section .data\n    msg: db "mov rsp, rax and int 0x80",0\n'
        self.assertEqual(set(), fired(data, "asm"))

    def test_short_nop_padding_is_not_a_sled(self):
        """Alignment padding is ordinary; a landing pad is not."""
        padded = "section .text\n_f:\n" + "    nop\n" * 4 + "    ret\n"
        self.assertNotIn("asm-nop-sled", fired(padded, "asm"))


class HlasmRules(unittest.TestCase):
    def test_every_hlasm_rule_fires(self):
        found = fired(HLASM_PRIVILEGED, "hlasm")
        for rule in ("hlasm-authorized-mode", "hlasm-storage-key-change",
                     "hlasm-supervisor-call", "hlasm-execute-variable-length"):
            with self.subTest(rule=rule):
                self.assertIn(rule, found)

    def test_ordinary_hlasm_is_silent(self):
        self.assertEqual(set(), fired(HLASM_CLEAN, "hlasm"))

    def test_star_in_column_one_is_a_comment(self):
        commented = ("MAIN     CSECT\n"
                     "* MODESET KEY=ZERO WOULD BE PRIVILEGED\n"
                     "         BR    R14\n")
        self.assertEqual(set(), fired(commented, "hlasm"))

    def test_star_elsewhere_is_arithmetic_not_a_comment(self):
        """`*` is also multiply and the location counter; masking must keep it."""
        masked = detect.blank("         LA    R1,4095*2   NOTE\n", "hlasm")[0]
        self.assertIn("4095*2", masked)

    def test_a_privileged_instruction_named_in_data_is_not_executed(self):
        data = ("MAIN     CSECT\n"
                "         DC    C'MODESET KEY=ZERO'   THIS IS DATA\n"
                "         BR    R14\n")
        self.assertEqual(set(), fired(data, "hlasm"))

    def test_the_sequence_number_field_is_not_code(self):
        """Columns 73-80 are card sequence numbers, never instructions."""
        line = "         BR    R14" + " " * 45 + "SVC   120\n"
        self.assertEqual(set(), fired(line, "hlasm"))


class Taxonomy(unittest.TestCase):
    def test_weakness_classes_are_declared_where_unambiguous(self):
        for rule in ("asm-writable-executable-section", "asm-legacy-int80",
                     "hlasm-authorized-mode", "hlasm-storage-key-change",
                     "hlasm-execute-variable-length"):
            with self.subTest(rule=rule):
                self.assertRegex(detect.RULE_CWE.get(rule, ""), r"^CWE-\d+$")

    def test_attacker_techniques_carry_an_attack_id_not_a_cwe(self):
        """A NOP sled is a construction, not a weakness class."""
        for rule in ("asm-nop-sled", "asm-stack-pivot", "asm-direct-execve"):
            with self.subTest(rule=rule):
                self.assertEqual("", detect.RULE_CWE.get(rule, ""))
                self.assertRegex(detect.attack_technique(rule), r"^T\d{4}(?:\.\d{3})?$")


class MaskingPreservesOffsets(unittest.TestCase):
    def test_masking_never_changes_line_length(self):
        """Rules report columns, so a masker must not shift anything."""
        for source, lang in ((X86_MALICIOUS, "asm"), (HLASM_PRIVILEGED, "hlasm")):
            with self.subTest(lang=lang):
                for raw, masked in zip(source.split("\n"), detect.blank(source, lang)):
                    self.assertEqual(len(raw), len(masked))

    def test_the_literal_view_keeps_operands(self):
        """`ctx.literal` must retain quoted operands, unlike the code view."""
        line = '    .section .data,"awx"   ; comment\n'
        self.assertIn('"awx"', detect.blank_comments(line, "asm")[0])
        self.assertNotIn("comment", detect.blank_comments(line, "asm")[0])


if __name__ == "__main__":
    unittest.main()
