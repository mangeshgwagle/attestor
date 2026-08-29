from __future__ import annotations

import ast
import os
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
CLI = PACKAGE / "cli.py"
EXAMPLES = PACKAGE / "examples"
sys.path.insert(0, str(PACKAGE))

from frontends import a1z26
from model import SourceError
import cli


class A1Z26Helpers(unittest.TestCase):
    def test_round_trip(self):
        encoded = a1z26.encode_assembly("#42 PRINT")
        self.assertEqual(encoded, "0-4-2 16-18-9-14-20")
        self.assertEqual(a1z26.decode_assembly(encoded), "#42 PRINT")

    def test_it_is_letters_only_not_fake_encryption(self):
        with self.assertRaises(SourceError):
            a1z26.encode_word("EXEC!")


class IsolatedCli(unittest.TestCase):
    def _run(self, *arguments: str, cwd: str | None = None):
        return subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8", str(CLI), *arguments],
            cwd=cwd, capture_output=True, text=True, timeout=20,
            env={"PYTHONPATH": "C:\\definitely-not-a-package"},
        )

    def test_help_works_in_isolated_mode_from_unrelated_cwd(self):
        with tempfile.TemporaryDirectory(prefix="attestorlang-cli-") as directory:
            done = self._run("--help", cwd=directory)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("AttestorLang 4.2", done.stdout)

    def test_check_and_run_examples(self):
        checked = self._run("check", str(EXAMPLES / "tour.owl"))
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("valid AttestorLang 4.2", checked.stdout)
        ran = self._run("run", str(EXAMPLES / "tour.owl"))
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertIn("AttestorLang 4.2: completed", ran.stdout)

    def test_compile_disassemble_and_run_bytecode(self):
        with tempfile.TemporaryDirectory(prefix="attestorlang-bytecode-") as directory:
            bytecode_path = pathlib.Path(directory) / "tour.owb"
            compiled = self._run(
                "compile", str(EXAMPLES / "a1z26.owl"), "--out",
                str(bytecode_path))
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            disassembled = self._run("disasm", str(bytecode_path))
            self.assertEqual(disassembled.returncode, 0, disassembled.stderr)
            self.assertIn("PRINT_NUMBER", disassembled.stdout)
            ran = self._run("run-bytecode", str(bytecode_path))
            self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_compile_refuses_to_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory(prefix="attestorlang-output-") as directory:
            output = pathlib.Path(directory) / "existing.owb"
            output.write_bytes(b"keep-me")
            done = self._run(
                "compile", str(EXAMPLES / "a1z26.owl"), "--out", str(output))
            self.assertEqual(done.returncode, 2)
            self.assertIn("refusing to overwrite", done.stderr)
            self.assertEqual(output.read_bytes(), b"keep-me")

    def test_compile_refuses_existing_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory(prefix="attestorlang-output-") as directory:
            root = pathlib.Path(directory)
            target = root / "target.owb"
            link = root / "link.owb"
            target.write_bytes(b"keep-target")
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("file symlinks are unavailable to this account")
            done = self._run(
                "compile", str(EXAMPLES / "a1z26.owl"), "--out", str(link))
            self.assertEqual(done.returncode, 2)
            self.assertEqual(target.read_bytes(), b"keep-target")
            self.assertTrue(link.is_symlink())


class ExclusiveOutput(unittest.TestCase):
    def test_close_failure_cannot_report_a_successful_output(self):
        real_close = os.close

        def close_then_fail(descriptor: int) -> None:
            real_close(descriptor)
            raise OSError("simulated close failure")

        with tempfile.TemporaryDirectory(prefix="attestorlang-close-") as directory:
            output = pathlib.Path(directory) / "new.owb"
            with mock.patch.object(cli.os, "close", side_effect=close_then_fail):
                with self.assertRaisesRegex(
                        cli.AttestorLangError, "finalization failed"):
                    cli._write_new_regular(str(output), b"verified bytes")
            self.assertFalse(output.exists())


class RuntimeImportBoundary(unittest.TestCase):
    def test_vm_core_has_no_host_effect_imports(self):
        forbidden = {"ctypes", "mmap", "os", "pathlib", "shutil", "socket", "subprocess"}
        for filename in ("vm.py", "bytecode.py", "compiler.py"):
            tree = ast.parse((PACKAGE / filename).read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.lstrip(".").split(".", 1)[0])
            self.assertFalse(forbidden & imported, (filename, forbidden & imported))

    def test_vm_source_has_no_native_execution_primitives(self):
        text = (PACKAGE / "vm.py").read_text(encoding="utf-8").casefold()
        for forbidden in ("createprocess", "os.system", "popen(", "shell=true",
                          "prot_exec", "windll", "cdll("):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
