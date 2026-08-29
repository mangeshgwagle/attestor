#!/usr/bin/env python3
"""Attestor 4.2 safety boundary for the inherited native mc.asm backends."""
from __future__ import annotations

import unittest
from unittest import mock

import compiler
import mc_asm


SOURCE = mc_asm.assemble("#7 PRINT")


class NativeBackendBoundaryTests(unittest.TestCase):
    def test_verify_never_builds_or_runs_native_code_by_default(self) -> None:
        with mock.patch.object(compiler.shutil, "which", return_value="tool"), \
                mock.patch.object(compiler, "_build_and_run") as execute:
            report = compiler.verify(SOURCE)
        execute.assert_not_called()
        self.assertTrue(report["agree"])
        self.assertEqual(
            {row["skipped"] for row in report["backends"].values()},
            {"native execution requires explicit opt-in"},
        )

    def test_exact_opt_in_is_required_for_native_differential_backends(self) -> None:
        expected = mc_asm.execute(SOURCE)
        with mock.patch.object(compiler.shutil, "which", return_value="tool"), \
                mock.patch.object(
                    compiler, "_build_and_run", return_value=expected
                ) as execute:
            report = compiler.verify(SOURCE, allow_native_execution=True)
        self.assertEqual(execute.call_count, 2)
        self.assertTrue(report["agree"])
        self.assertTrue(all(
            row.get("matches") is True for row in report["backends"].values()
        ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
