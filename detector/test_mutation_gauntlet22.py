from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest import mock

import mutation_gauntlet


class MutationGauntlet22Tests(unittest.TestCase):
    def test_unrelated_baseline_finding_does_not_kill_mutant(self):
        existing = SimpleNamespace(rule="debug-enabled", line=1, message="already present")
        # Same finding before and after, for every scan the run performs: the
        # mutant introduces nothing, so none of them may count as caught.
        with mock.patch.object(mutation_gauntlet.harvest, "scan_content",
                               return_value=[existing]):
            result = mutation_gauntlet.run("value is None\n", "candidate.py")
        self.assertTrue(result["mutants"])
        self.assertEqual(result["caught"], 0)
        self.assertEqual(len(result["gaps"]), len(result["mutants"]))
        for mutant in result["mutants"]:
            self.assertEqual(mutant["introduced_rules"], [])

    def test_dynamic_execution_is_off_by_default(self):
        source = "def value(x):\n    return x is None\n"
        with mock.patch.object(mutation_gauntlet.crucible, "verify") as verify:
            result = mutation_gauntlet.run(source, "candidate.py")
        verify.assert_not_called()
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(result["mutants"][0]["execution"], "disabled")

    def test_pattern_inside_a_string_literal_is_not_mutated(self):
        # Attestor's own fix tables hold "is None" and "verify=True" as replacement
        # *values*.  Editing those changes no behavior, the scanner correctly
        # stays silent, and scoring it as a survivor invents a blind spot.
        source = ('FIXES = [\n'
                  '    ("py-eq-none", "is None"),\n'
                  '    ("tls", "verify=True"),\n'
                  ']\n')
        self.assertEqual(mutation_gauntlet.mutate(source, ".py"), [])
        result = mutation_gauntlet.run(source, "fixtable.py")
        self.assertEqual(result["gaps"], [])

    def test_pattern_inside_a_comment_is_not_mutated(self):
        source = "# historical note: we used to write x is None here\nx = 1\n"
        self.assertEqual(mutation_gauntlet.mutate(source, ".py"), [])

    def test_live_code_is_still_mutated_past_a_string_decoy(self):
        source = ('NOTE = "always compare with is None"\n'
                  'def check(value):\n'
                  '    return value is None\n')
        mutants = {m["id"]: m for m in mutation_gauntlet.mutate(source, ".py")}
        self.assertEqual(set(mutants), {"none-identity-regression",
                                        "none-identity-reversed"})
        # The decoy string must survive untouched in every variant.
        for mutant in mutants.values():
            self.assertIn('"always compare with is None"', mutant["code"])
        self.assertIn("return value == None",
                      mutants["none-identity-regression"]["code"])
        self.assertIn("return None == value",
                      mutants["none-identity-reversed"]["code"])

    def test_deep_only_expected_rules_can_actually_fire(self):
        # py-assert-validation is declared deep=True; a shallow scan would make
        # this mutator a permanent survivor no rule change could ever fix.
        source = ("def withdraw(balance, amount):\n"
                  "    if amount > balance:\n"
                  "        raise ValueError('insufficient')\n"
                  "    return balance - amount\n")
        result = mutation_gauntlet.run(source, "account.py")
        assert_mutants = [m for m in result["mutants"]
                          if m["id"] == "assert-validation"]
        self.assertEqual(len(assert_mutants), 1)
        self.assertTrue(assert_mutants[0]["caught"])
        self.assertIn("py-assert-validation",
                      assert_mutants[0]["introduced_rules"])

    def test_javascript_mutators_are_language_scoped(self):
        source = "if (left === right) node.textContent = value;\n"
        result = mutation_gauntlet.run(source, "client.js")
        ids = {item["id"] for item in result["mutants"]}
        self.assertEqual(ids, {"strict-equality-weakened", "safe-dom-write-weakened"})
        self.assertEqual(result["gaps"], [])
        self.assertEqual(result["mutation_score"], 100.0)


SERVICE = ('"""Service."""\n'
           'from __future__ import annotations\n'
           'import hashlib\n'
           'import requests\n'
           '\n'
           'def go(url, token):\n'
           '    if token is None:\n'
           '        raise ValueError("token")\n'
           '    d = hashlib.sha256(token.encode()).hexdigest()\n'
           '    return requests.get(url, verify=True, timeout=5, headers={"d": d})\n')


class EquivalenceMutatorTests(unittest.TestCase):
    """Same defect, spelling the canonical rule pattern cannot reach."""

    def test_every_equivalence_mutator_names_a_canonical_parent(self):
        canonical = {m["id"] for m in mutation_gauntlet.MUTATORS
                     if not m.get("equivalence_of")}
        for mutant in mutation_gauntlet.EQUIVALENCE_MUTATORS:
            with self.subTest(mutator=mutant["id"]):
                self.assertIn(mutant["equivalence_of"], canonical)
                self.assertNotEqual(mutant["id"], mutant["equivalence_of"])

    def test_prelude_is_inserted_after_docstring_and_future_import(self):
        mutants = {m["id"]: m for m in mutation_gauntlet.mutate(SERVICE, ".py")}
        code = mutants["tls-verification-indirect"]["code"]
        lines = code.splitlines()
        self.assertEqual(lines[0], '"""Service."""')
        self.assertEqual(lines[1], "from __future__ import annotations")
        self.assertIn("_TLS_VERIFY_ENABLED = False", lines[2])
        compile(code, "mutant.py", "exec")     # must still be valid Python

    def test_prelude_baseline_keeps_line_numbers_aligned(self):
        mutants = {m["id"]: m for m in mutation_gauntlet.mutate(SERVICE, ".py")}
        mutant = mutants["tls-verification-indirect"]
        self.assertIn("_TLS_VERIFY_ENABLED = False", mutant["baseline_code"])
        self.assertNotIn("verify=_TLS_VERIFY_ENABLED", mutant["baseline_code"])
        self.assertEqual(len(mutant["code"].splitlines()),
                         len(mutant["baseline_code"].splitlines()))

    def test_mutator_without_prelude_baselines_against_the_original(self):
        mutants = {m["id"]: m for m in mutation_gauntlet.mutate(SERVICE, ".py")}
        self.assertEqual(mutants["weak-hash-reflective"]["baseline_code"],
                         SERVICE)

    def test_every_mutant_body_is_still_syntactically_valid(self):
        for mutant in mutation_gauntlet.mutate(SERVICE, ".py"):
            with self.subTest(mutator=mutant["id"]):
                compile(mutant["code"], "mutant.py", "exec")
                compile(mutant["baseline_code"], "baseline.py", "exec")

    def test_unparseable_source_skips_prelude_mutators_only(self):
        broken = "def f(:\n    x is None\n"
        ids = {m["id"] for m in mutation_gauntlet.mutate(broken, ".py")}
        self.assertIn("none-identity-reversed", ids)          # no prelude
        self.assertNotIn("tls-verification-indirect", ids)    # needs a prelude

    def test_equivalence_variants_are_detected_not_just_the_canonical_form(self):
        # These variants were survivors when they were written: the rules
        # matched their own canonical fixtures and nothing else. They are the
        # reason detect.py grew alias, reflection and module-flag awareness, so
        # catching them now is the assertion -- a regression here means a rule
        # narrowed back to its own fixture.
        result = mutation_gauntlet.run(SERVICE, "service.py")
        by_id = {m["id"]: m for m in result["mutants"]}
        variants = [m for m in result["mutants"] if m["equivalence_of"]]
        self.assertTrue(variants, "the equivalence catalog should apply here")
        for mutant in variants:
            with self.subTest(mutator=mutant["id"]):
                self.assertTrue(
                    by_id[mutant["equivalence_of"]]["caught"],
                    "canonical form must be caught for the pair to mean anything")
                self.assertTrue(
                    mutant["caught"],
                    "%s reaches the same defect as %s and must be detected"
                    % (mutant["id"], mutant["equivalence_of"]))

    def test_any_survivor_is_reported_as_a_gap_with_a_usable_seed(self):
        # Survivors are expected to be empty here; the contract is that when
        # one does appear it arrives with a compilable seed to work from.
        result = mutation_gauntlet.run(SERVICE, "service.py")
        self.assertEqual(
            [gap["mutation"] for gap in result["gaps"]], [],
            "a known-defect mutant went undetected")
        for gap in result["gaps"]:
            self.assertTrue(gap["target_rule"])
            compile(gap["seed"], "seed.py", "exec")

    def test_gap_seeds_stay_compilable_when_detection_is_blinded(self):
        with mock.patch.object(mutation_gauntlet.harvest, "scan_content",
                               return_value=[]):
            result = mutation_gauntlet.run(SERVICE, "service.py")
        self.assertEqual(len(result["gaps"]), len(result["mutants"]))
        for gap in result["gaps"]:
            self.assertTrue(gap["target_rule"])
            self.assertTrue(gap["why"])
            compile(gap["seed"], "seed.py", "exec")


if __name__ == "__main__":
    unittest.main()
