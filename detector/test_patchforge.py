#!/usr/bin/env python3
"""Focused security tests for Patch Forge's opt-in execution policy."""
import sys
import unittest

import patchforge


class FakeBrain:
    def __init__(self, answer):
        self.answer = answer

    def available(self):
        return True

    def generate(self, _prompt):
        return {"fake": self.answer}


class PatchForgeSecurityTests(unittest.TestCase):
    def test_gate_is_static_only_by_default(self):
        gate = patchforge.gate("result = 1 / 0\n", ".py")
        self.assertTrue(gate["ok"])
        self.assertIsNone(gate["crucible_ok"])
        self.assertFalse(gate["execution_enabled"])
        self.assertIn("execution disabled", gate["crucible_detail"])

    def test_explicit_execution_rejects_runtime_crash(self):
        gate = patchforge.gate("result = 1 / 0\n", ".py", execute=True)
        self.assertFalse(gate["ok"])
        self.assertFalse(gate["crucible_ok"])
        self.assertEqual(gate["sandbox"]["profile"], "attestor-python-restricted-v1")

    def test_model_patch_cannot_delete_public_api_without_opt_in(self):
        source = "def make(keys):\n    return dict.fromkeys(keys, [])\n"
        candidate = "result = 1 / 0\n"
        result = patchforge.patch_source(source, "app.py", FakeBrain(candidate))
        self.assertFalse(result["ok"])
        self.assertIsNone(result["gate"]["crucible_ok"])
        self.assertIn("removes public API", " ".join(
            result["attempts"][0]["gate"]["integrity"]["reasons"]))
        self.assertIn("refused", patchforge.render(result).lower())

    def test_static_candidate_preserving_api_is_labeled_not_behavior_verified(self):
        source = "def make(keys):\n    return dict.fromkeys(keys, [])\n"
        candidate = "def make(keys):\n    return {key: [] for key in keys}\n"
        result = patchforge.patch_source(source, "app.py", FakeBrain(candidate))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["evidence_level"], "scan_clean")
        self.assertIsNone(result["gate"]["regression_ok"])
        self.assertIn("behavior/regression evidence were not run", patchforge.render(result))

    def test_regression_command_requires_explicit_trust(self):
        command = '"%s" -c "print(123)"' % sys.executable
        denied, detail = patchforge._run_command_regression("x = 1\n", command)
        self.assertFalse(denied)
        self.assertIn("disabled", detail)
        allowed, detail = patchforge._run_command_regression(
            "x = 1\n", command, trusted=True)
        self.assertTrue(allowed, detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
