#!/usr/bin/env python3
"""Tests for forge.py -- the generate/verify/repair loop. Offline: a scripted
stand-in for the LLM, so no key or network is needed to test the orchestration."""
import unittest

import brain
import coder
import forge

# a bug only the AST engine sees (undefined name) -> forces a repair round
BUGGY = "def merge(a, b):\n    if a == None:\n        return b\n    return combined\n"
CLEAN = "def merge(a, b):\n    if a is None:\n        return b\n    return sorted(a + b)\n"


WRONG_MERGE = "def merge(a, b):\n    return a + b\n"

class ScriptedBrain:
    def __init__(self, answers):
        self._answers = list(answers)

    def available(self):
        return True

    def generate(self, _prompt):
        return self._answers.pop(0) if self._answers else CLEAN


class ExplodingBrain:
    def available(self):
        return True

    def generate(self, _prompt):
        raise brain.ProviderError("429 quota")


class ProvenanceProvider(brain.Provider):
    name = "fixture-provider"
    _model = "fixture-model"

    def generate(self, _prompt):
        return CLEAN


class ForgeTests(unittest.TestCase):
    def test_repairs_until_attestor_is_satisfied(self):
        result = forge.forge("merge lists", ScriptedBrain([BUGGY, CLEAN]), rounds=3)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["transcript"]), 2)   # one repair round was needed
        self.assertEqual(result["code"].strip(), CLEAN.strip())

    def test_clean_on_first_try_stops_immediately(self):
        result = forge.forge("x", ScriptedBrain([CLEAN]), rounds=3)
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["transcript"]), 1)

    def test_auto_fix_is_recorded(self):
        result = forge.forge("x", ScriptedBrain([BUGGY, CLEAN]), rounds=3)
        self.assertIn("== None -> is None", result["transcript"][0]["auto_fixed"])

    def test_gives_up_after_rounds_but_returns_best_effort(self):
        result = forge.forge("x", ScriptedBrain([BUGGY, BUGGY, BUGGY]), rounds=3)
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["transcript"]), 3)

    def test_provider_error_stops_the_loop(self):
        result = forge.forge("x", ExplodingBrain(), rounds=3)
        self.assertFalse(result["ok"])
        self.assertIn("error", result["transcript"][0])

    def test_prompt_includes_behavior_smoke(self):
        prompt = forge._gen_prompt("write fibonacci")
        self.assertIn("Attestor Coding Contract", prompt)
        self.assertIn("behavioral smoke test", prompt)
        self.assertIn("assert fn(10) == 55", prompt)

    def test_transcript_includes_coder_score(self):
        result = forge.forge("merge sorted lists", ScriptedBrain([CLEAN]), rounds=1,
                             execute=True)
        score = result["transcript"][0]["score"]
        self.assertEqual(score["grade"], "excellent")
        self.assertIn("coder score", coder.render_score(score))
    def test_render_reports_each_round(self):
        result = forge.forge("merge", ScriptedBrain([BUGGY, CLEAN]), rounds=3)
        text = forge.render(result, "merge")
        self.assertIn("round 1", text)
        self.assertIn("round 2", text)
        self.assertIn("STATIC-SCAN-CLEAN CANDIDATE", text)
        self.assertIn("requirements/correctness were not proven", text)

    def test_execution_gate_catches_a_statically_clean_crash(self):
        # 'result = 1 / 0' is valid code with no bad pattern -> both static engines
        # pass it; only running it reveals the crash. The crucible must bounce it.
        crashes = "result = 1 / 0\n"
        result = forge.forge("x", ScriptedBrain([crashes, CLEAN]), rounds=3,
                             execute=True)
        self.assertTrue(result["ok"])
        self.assertFalse(result["transcript"][0]["ran"])   # round 1 ran and crashed
        self.assertTrue(result["transcript"][1]["ran"])     # round 2 actually runs

    def test_behavior_gate_repairs_wrong_merge(self):
        result = forge.forge("merge sorted lists", ScriptedBrain([WRONG_MERGE, CLEAN]), rounds=3,
                             execute=True)
        self.assertTrue(result["ok"])
        self.assertFalse(result["transcript"][0]["ran"])
        self.assertTrue(result["transcript"][0]["behavior"])
        self.assertTrue(result["transcript"][1]["ran"])
    def test_generated_execution_is_off_by_default(self):
        crashes = "result = 1 / 0\n"
        result = forge.forge("x", ScriptedBrain([crashes]), rounds=1)
        self.assertTrue(result["ok"])                       # static-clean is enough
        self.assertIsNone(result["transcript"][0]["ran"])   # never executed
        self.assertFalse(result["execution_enabled"])
        self.assertIn("static evidence only", forge.render(result, "x"))

    def test_empty_model_response_is_abstention_not_verified_code(self):
        result = forge.forge("write a compiler", ScriptedBrain([""]), rounds=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["evidence_level"], "abstained")
        self.assertEqual(result["code"], "")
        self.assertIn("ABSTAINED", forge.render(result, "write a compiler"))

    def test_typed_provider_provenance_reaches_verification_transcript(self):
        result = forge.forge("merge lists", brain.Brain([ProvenanceProvider()]), rounds=1)
        evidence = result["transcript"][0]["generation"]
        self.assertEqual((evidence["provider"], evidence["model"]),
                         ("fixture-provider", "fixture-model"))
        self.assertEqual(evidence["status"], "success")
        self.assertRegex(evidence["prompt_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(evidence["response_sha256"], r"^[0-9a-f]{64}$")

    def test_explicit_execution_opt_in_uses_restricted_profile(self):
        result = forge.forge("x", ScriptedBrain([CLEAN]), rounds=1, execute=True)
        self.assertTrue(result["ok"])
        self.assertTrue(result["execution_enabled"])
        self.assertEqual(result["sandbox"]["profile"], "attestor-python-restricted-v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
