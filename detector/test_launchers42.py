from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent.parent


class Attestor42LauncherTests(unittest.TestCase):
    def _run_python_entrypoint(self, relative: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8", str(ROOT / relative), "--help"],
            cwd=Path(os.environ.get("TEMP", str(ROOT))).resolve(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            timeout=20,
            check=False,
        )

    def test_isolated_attestorlang_entrypoint(self) -> None:
        completed = self._run_python_entrypoint("integrations/attestorlang/cli.py")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("AttestorLang 4.2", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)

    def test_isolated_owner_control_entrypoint(self) -> None:
        completed = self._run_python_entrypoint("detector/owner_control42.py")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Owner Control", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)

    def test_root_launchers_are_exact_and_do_not_auto_authorize(self) -> None:
        expected = {
            "Run_AttestorLang.bat": "integrations\\attestorlang\\cli.py %*",
            "Run_AttestorLang.sh": "integrations/attestorlang/cli.py \"$@\"",
            "Run_Owner_Control_4.2.bat": "detector\\owner_control42.py %*",
            "Run_Owner_Control_4.2.sh": "detector/owner_control42.py \"$@\"",
        }
        for filename, command in expected.items():
            with self.subTest(filename=filename):
                text = (ROOT / filename).read_text(encoding="utf-8")
                self.assertIn(" -I -B -X utf8 ", text)
                self.assertIn(command, text)
                self.assertNotIn("--permission", text)

    @unittest.skipUnless(os.name == "nt", "Windows launcher smoke")
    def test_windows_launchers_help(self) -> None:
        for filename in ("Run_AttestorLang.bat", "Run_Owner_Control_4.2.bat"):
            with self.subTest(filename=filename):
                completed = subprocess.run(
                    ["cmd.exe", "/d", "/c", str(ROOT / filename), "--help"],
                    cwd=Path(os.environ.get("TEMP", str(ROOT))).resolve(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    timeout=30,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
