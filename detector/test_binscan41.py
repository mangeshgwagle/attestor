#!/usr/bin/env python3
"""Tests for binscan41.py.

The ELF fixtures are built here rather than checked in, so the test states
exactly which bytes produce which verdict -- a committed binary would hide the
thing under test. Each case turns off one mitigation and asserts that one goes
missing and the others do not, which is what stops a parser bug from reading
the same field for every check.
"""
import os
import struct
import tempfile
import unittest

import binscan41 as binscan


def elf64(*, etype=3, gnu_stack_flags=4, relro=True, bind_now=True,
          canary=True, fortify=True, rpath=False) -> bytes:
    """A structurally valid ELF64 carrying only the headers binscan reads."""
    headers = []
    if gnu_stack_flags is not None:
        headers.append((binscan.PT_GNU_STACK, gnu_stack_flags, 0, 0))
    if relro:
        headers.append((binscan.PT_GNU_RELRO, 4, 0, 0))

    dynamic = b""
    if rpath:
        dynamic += struct.pack("<Qq", binscan.DT_RPATH, 0)
    if bind_now:
        dynamic += struct.pack("<Qq", binscan.DT_BIND_NOW, 0)
    dynamic += struct.pack("<Qq", binscan.DT_NULL, 0)

    phoff, phentsize = 64, 56
    dynoff = phoff + phentsize * (len(headers) + 1)
    headers.append((binscan.PT_DYNAMIC, 4, dynoff, len(dynamic)))

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2                      # 64-bit
    header[5] = 1                      # little endian
    struct.pack_into("<H", header, 16, etype)
    struct.pack_into("<Q", header, 32, phoff)
    struct.pack_into("<HH", header, 54, phentsize, len(headers))

    table = b""
    for ptype, flags, offset, size in headers:
        entry = bytearray(phentsize)
        struct.pack_into("<II", entry, 0, ptype, flags)
        struct.pack_into("<QQQ", entry, 8, offset, 0, size)
        table += bytes(entry)

    blob = bytes(header) + table + dynamic
    if canary:
        blob += b"__stack_chk_fail\x00"
    if fortify:
        blob += b"__memcpy_chk\x00__printf_chk\x00"
    return blob


class ElfTests(unittest.TestCase):
    def inspect(self, blob):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sample.elf")
            with open(path, "wb") as handle:
                handle.write(blob)
            return binscan.inspect(path)

    def missing(self, blob):
        return set(self.inspect(blob)["missing_mitigations"])

    def test_a_fully_hardened_binary_reports_nothing_missing(self):
        report = self.inspect(elf64())
        self.assertEqual(report["missing_mitigations"], [])
        self.assertTrue(report["hardened"])
        self.assertEqual(report["format"], "elf")
        self.assertEqual(report["bits"], 64)

    def test_an_executable_stack_is_caught(self):
        self.assertEqual(
            self.missing(elf64(gnu_stack_flags=4 | binscan.PF_X)), {"nx"})

    def test_a_missing_stack_header_is_treated_as_executable(self):
        # An absent PT_GNU_STACK is the dangerous case, not a neutral one.
        self.assertEqual(self.missing(elf64(gnu_stack_flags=None)), {"nx"})

    def test_a_fixed_load_address_is_caught(self):
        self.assertEqual(self.missing(elf64(etype=2)), {"pie"})

    def test_partial_relro_is_not_counted_as_full(self):
        self.assertEqual(self.missing(elf64(bind_now=False)), {"relro"})

    def test_no_relro_at_all_is_caught(self):
        self.assertIn("relro", self.missing(elf64(relro=False, bind_now=False)))

    def test_a_missing_canary_is_caught(self):
        self.assertIn("stack_canary", self.missing(elf64(canary=False)))

    def test_a_baked_in_library_path_is_caught(self):
        self.assertEqual(self.missing(elf64(rpath=True)), {"no_rpath"})

    def test_the_canary_and_fortify_checks_admit_being_heuristics(self):
        checks = self.inspect(elf64())["checks"]
        self.assertTrue(checks["stack_canary"].get("soft"))
        self.assertTrue(checks["fortify"].get("soft"))
        self.assertFalse(checks["nx"].get("soft"))

    def test_a_32_bit_binary_is_read_as_32_bit(self):
        blob = bytearray(elf64())
        blob[4] = 1
        # The 32-bit header layout differs, so this must either parse as
        # 32-bit or refuse -- never silently report 64-bit fields.
        try:
            self.assertEqual(self.inspect(bytes(blob))["bits"], 32)
        except binscan.BinaryError:
            pass


class ReportIntegrityTests(unittest.TestCase):
    def report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sample.elf")
            with open(path, "wb") as handle:
                handle.write(elf64())
            return binscan.inspect(path)

    def test_a_clean_report_verifies(self):
        self.assertTrue(binscan.verify_report(self.report())[0])

    def test_a_tampered_report_is_caught(self):
        report = self.report()
        report["hardened"] = False
        self.assertFalse(binscan.verify_report(report)[0])

    def test_a_foreign_object_is_not_a_report(self):
        for bad in ({}, {"schema": "something/1.0"}, None, "text"):
            with self.subTest(value=bad):
                self.assertFalse(binscan.verify_report(bad)[0])

    def test_the_report_states_what_it_does_not_claim(self):
        report = self.report()
        self.assertTrue(any("never what its code does" in line
                            for line in report["limitations"]))


class RefusalTests(unittest.TestCase):
    def test_a_non_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "notes.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("this is not a binary\n")
            with self.assertRaises(binscan.BinaryError):
                binscan.inspect(path)

    def test_a_missing_file_is_refused(self):
        with self.assertRaises(binscan.BinaryError):
            binscan.inspect(os.path.join(tempfile.gettempdir(), "no-such.bin"))

    def test_a_truncated_elf_is_refused_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "short.elf")
            with open(path, "wb") as handle:
                handle.write(b"\x7fELF\x02\x01" + b"\x00" * 8)
            with self.assertRaises(binscan.BinaryError):
                binscan.inspect(path)


class FuzzTests(unittest.TestCase):
    def test_random_bytes_are_refused_not_crashed_on(self):
        """Malformed input must raise BinaryError and nothing else.

        A truncated ELF originally escaped as struct.error, which would take
        a whole scan down on one corrupt artifact. Every parse path here is
        reachable from a file an attacker chose, so the only acceptable
        outcomes are a report or a clean refusal.
        """
        import random

        rng = random.Random(20260805)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "fuzz.bin")
            for index in range(200):
                blob = bytearray(rng.randbytes(rng.choice([8, 64, 200, 900])))
                blob[0:4] = b"\x7fELF" if index % 2 else b"MZ\x00\x00"
                with open(path, "wb") as handle:
                    handle.write(bytes(blob))
                try:
                    binscan.inspect(path)
                except binscan.BinaryError:
                    pass
                except Exception as error:      # noqa: BLE001 -- the point
                    self.fail("random input raised %s: %s"
                              % (type(error).__name__, error))


class RenderTests(unittest.TestCase):
    def test_missing_mitigations_are_marked_and_named(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sample.elf")
            with open(path, "wb") as handle:
                handle.write(elf64(etype=2))
            text = binscan.render(binscan.inspect(path))
        self.assertIn("MISS", text)
        self.assertIn("pie", text)
        self.assertIn("missing: pie", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
