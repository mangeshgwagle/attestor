#!/usr/bin/env python3
"""Build divergence: capabilities in the artifact that the source never asked for.

The property under test is the one source review cannot establish on its own.
Two builds of the *same clean source* are compared: an honest one, and one that
opens a socket and execs. A checker that flagged both, or neither, would be
useless -- so every test here pairs the accusation with its acquittal.

The second half guards the direction that matters more in practice. A false
positive here accuses a clean build of being backdoored, which is the most
expensive wrong answer this module can give, so source that legitimately
declares a capability must silence the corresponding finding completely.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build_divergence42 as bd  # noqa: E402


PURE_SOURCE = """\
import math


def area(radius):
    return math.pi * radius * radius
"""

NETWORKING_SOURCE = """\
import socket
import subprocess


def fetch(host):
    s = socket.socket()
    s.connect((host, 80))
    return s


def run(cmd):
    return subprocess.run(cmd, shell=False)
"""

HONEST_ASM = """\
    .section .text
area:
    mulsd %xmm0, %xmm0
    ret
    .section .note.GNU-stack,"",@progbits
"""

BACKDOORED_ASM = """\
    .section .text
area:
    mulsd %xmm0, %xmm0
    ret
_hidden:
    mov $41, %eax
    syscall
    mov $59, %eax
    syscall
    call setuid
"""


def build(source: str, assembly: str) -> tuple[str, str]:
    root = Path(tempfile.mkdtemp())
    (root / "src").mkdir()
    (root / "asm").mkdir()
    (root / "src" / "unit.py").write_text(source, encoding="utf-8")
    (root / "asm" / "unit.s").write_text(assembly, encoding="utf-8")
    return str(root / "src"), str(root / "asm")


class CatchesTheDivergence(unittest.TestCase):
    def setUp(self):
        src, asm = build(PURE_SOURCE, BACKDOORED_ASM)
        self.report = bd.compare(src, asm)

    def test_the_report_self_verifies(self):
        ok, errors = bd.verify_report(self.report)
        self.assertTrue(ok, errors[:3])

    def test_status_is_divergent(self):
        self.assertEqual("divergent", self.report["status"])

    def test_it_names_the_capabilities_the_source_never_asked_for(self):
        unexplained = set(self.report["summary"]["unexplained"])
        self.assertIn(bd.NETWORK, unexplained)
        self.assertIn(bd.PROCESS_EXEC, unexplained)
        self.assertIn(bd.PRIVILEGE, unexplained)

    def test_every_finding_points_at_a_line_in_the_listing(self):
        """A claim with no site is an accusation nobody can check."""
        for finding in self.report["findings"]:
            with self.subTest(capability=finding["capability"]):
                self.assertTrue(finding["assembly_evidence"])
                for site in finding["assembly_evidence"]:
                    self.assertGreaterEqual(site["line"], 1)
                    self.assertTrue(site["reason"])

    def test_no_finding_claims_runtime_proof(self):
        for finding in self.report["findings"]:
            self.assertFalse(finding["runtime_verified"])
            self.assertEqual("inferred", finding["evidence_state"])


class AcquitsTheHonestBuild(unittest.TestCase):
    def test_matching_source_and_assembly_are_consistent(self):
        src, asm = build(PURE_SOURCE, HONEST_ASM)
        report = bd.compare(src, asm)
        self.assertEqual("consistent", report["status"])
        self.assertEqual([], report["findings"])

    def test_declared_capabilities_silence_the_finding(self):
        """The expensive wrong answer is accusing a clean build."""
        src, asm = build(NETWORKING_SOURCE, BACKDOORED_ASM)
        report = bd.compare(src, asm)
        unexplained = set(report["summary"]["unexplained"])
        self.assertNotIn(bd.NETWORK, unexplained)
        self.assertNotIn(bd.PROCESS_EXEC, unexplained)

    def test_a_syscall_named_in_a_comment_is_not_a_syscall(self):
        """Masking applies here too: prose about execve is not execve."""
        commented = ("    .section .text\n"
                     "# mov $59, %eax followed by syscall would be execve\n"
                     "area:\n    ret\n")
        src, asm = build(PURE_SOURCE, commented)
        report = bd.compare(src, asm)
        self.assertEqual("consistent", report["status"])


class ReportIntegrity(unittest.TestCase):
    def test_a_tampered_status_fails_verification(self):
        src, asm = build(PURE_SOURCE, BACKDOORED_ASM)
        report = dict(bd.compare(src, asm))
        report["status"] = "consistent"          # hide the divergence
        ok, errors = bd.verify_report(report)
        self.assertFalse(ok)
        self.assertTrue(any("status" in message or "digest" in message
                            for message in errors), errors)

    def test_a_dropped_finding_fails_verification(self):
        src, asm = build(PURE_SOURCE, BACKDOORED_ASM)
        report = dict(bd.compare(src, asm))
        report["findings"] = report["findings"][:1]
        self.assertFalse(bd.verify_report(report)[0])

    def test_hostile_input_never_raises(self):
        for hostile in (None, 42, "report", [], {}, {"schema": bd.SCHEMA}):
            with self.subTest(value=repr(hostile)[:30]):
                self.assertFalse(bd.verify_report(hostile)[0])


class StaysInsideTheBoundary(unittest.TestCase):
    def test_nothing_is_compiled_or_executed(self):
        src, asm = build(PURE_SOURCE, BACKDOORED_ASM)
        execution = bd.compare(src, asm)["execution"]
        for key in ("target_code_executed", "compiler_invoked",
                    "processes_started", "network_accessed", "files_written"):
            with self.subTest(contract=key):
                self.assertFalse(execution[key])

    def test_the_limits_are_stated_in_the_report(self):
        """The report must say a divergence is not proof of a backdoor."""
        src, asm = build(PURE_SOURCE, BACKDOORED_ASM)
        text = " ".join(bd.compare(src, asm)["limitations"]).lower()
        self.assertIn("review point", text)
        self.assertIn("compiler", text)

    def test_a_missing_listing_directory_fails_closed(self):
        src, _asm = build(PURE_SOURCE, HONEST_ASM)
        with self.assertRaises(bd.BuildDivergenceError):
            bd.compare(src, os.path.join(src, "does-not-exist"))


if __name__ == "__main__":
    unittest.main()
