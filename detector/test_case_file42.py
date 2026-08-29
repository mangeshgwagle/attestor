#!/usr/bin/env python3
"""The case file must be tamper-evident, honest about basis, and hard to fool.

The tests that matter here are the adversarial ones. A record that merely
accumulates text would pass a happy-path suite and still be worthless as
evidence, so most of what follows tries to break it: rewrite a stage, delete
one, forge a digest, or claim a fix is proven when the regression test never
failed in the first place.
"""
from __future__ import annotations

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import case_file42 as cf  # noqa: E402


SUBJECT = dict(
    subject_path="src/Dao.java",
    subject_sha256="a" * 64,
    rule="java-sql-injection",
    summary="tainted parameter concatenated into a SQL statement",
)


def opened():
    return cf.open_case(**SUBJECT)


def worked_case():
    case = opened()
    case = cf.append(case, stage="discovery", basis=cf.MEASURED,
                     summary="taint reaches executeQuery",
                     evidence={"path": "src/Dao.java", "line": 4})
    case = cf.append(case, stage="remediation", basis=cf.MEASURED,
                     summary="parameterised the statement",
                     evidence={"diff_sha256": "b" * 64})
    case = cf.append(case, stage="regression", basis=cf.MEASURED,
                     summary="test fails before the fix, passes after",
                     evidence={"fails_before_fix": True, "passes_after_fix": True})
    return case


class ChainIsTamperEvident(unittest.TestCase):
    def test_a_fresh_case_verifies(self):
        ok, problems = cf.verify(worked_case())
        self.assertTrue(ok, problems)

    def test_editing_a_summary_breaks_the_chain(self):
        case = worked_case()
        case["entries"][0]["summary"] = "nothing to see here"
        ok, problems = cf.verify(case)
        self.assertFalse(ok)
        self.assertTrue(any("digest" in p for p in problems), problems)

    def test_editing_evidence_breaks_the_chain(self):
        case = worked_case()
        case["entries"][0]["evidence"]["line"] = 999
        ok, _ = cf.verify(case)
        self.assertFalse(ok)

    def test_deleting_a_middle_entry_is_detected(self):
        case = worked_case()
        del case["entries"][1]
        ok, problems = cf.verify(case)
        self.assertFalse(ok)
        self.assertTrue(any("chain" in p or "index" in p for p in problems), problems)

    def test_a_forged_digest_does_not_help(self):
        """Recomputing the edited entry's own digest still breaks the successor."""
        case = worked_case()
        entry = case["entries"][0]
        entry["summary"] = "forged"
        body = {k: v for k, v in entry.items() if k != "entry_sha256"}
        entry["entry_sha256"] = cf._entry_digest(body, entry["prev_sha256"])
        ok, problems = cf.verify(case)
        self.assertFalse(ok, "re-digesting one entry must not repair the chain")
        self.assertTrue(any("chain" in p for p in problems), problems)

    def test_appending_does_not_mutate_the_original(self):
        first = opened()
        second = cf.append(first, stage="discovery", basis=cf.MEASURED, summary="x")
        self.assertEqual([], first["entries"])
        self.assertEqual(1, len(second["entries"]))

    def test_verify_never_raises_on_hostile_input(self):
        for hostile in (None, 42, "case", {}, {"schema": cf.CASE_SCHEMA},
                        {"schema": cf.CASE_SCHEMA, "entries": "no"},
                        {"schema": cf.CASE_SCHEMA, "entries": [1, 2]}):
            ok, problems = cf.verify(hostile)
            self.assertFalse(ok)
            self.assertTrue(problems)


class RegressionHonestyGate(unittest.TestCase):
    """The gate that stops the pipeline certifying a fix it never proved."""

    def test_a_regression_that_never_failed_is_refused(self):
        case = opened()
        with self.assertRaises(cf.CaseFileError) as caught:
            cf.append(case, stage="regression", basis=cf.MEASURED,
                      summary="test passes", evidence={"passes_after_fix": True})
        self.assertIn("fails_before_fix", str(caught.exception))

    def test_claiming_false_is_also_refused(self):
        case = opened()
        with self.assertRaises(cf.CaseFileError):
            cf.append(case, stage="regression", basis=cf.MEASURED, summary="t",
                      evidence={"fails_before_fix": False})

    def test_a_regression_may_not_be_a_hypothesis(self):
        case = opened()
        with self.assertRaises(cf.CaseFileError):
            cf.append(case, stage="regression", basis=cf.HYPOTHESIS, summary="t",
                      evidence={"fails_before_fix": True})

    def test_a_smuggled_regression_entry_fails_verification(self):
        """Bypassing append must not produce a case that verifies."""
        case = worked_case()
        case["entries"][2]["evidence"]["fails_before_fix"] = False
        body = {k: v for k, v in case["entries"][2].items() if k != "entry_sha256"}
        case["entries"][2]["entry_sha256"] = cf._entry_digest(
            body, case["entries"][2]["prev_sha256"])
        ok, problems = cf.verify(case)
        self.assertFalse(ok)
        self.assertTrue(any("pre-fix" in p for p in problems), problems)


class ProofIsStrict(unittest.TestCase):
    def test_a_full_workflow_is_proven(self):
        self.assertTrue(cf.is_proven(worked_case()))

    def test_remediation_without_regression_is_not_proven(self):
        case = opened()
        case = cf.append(case, stage="discovery", basis=cf.MEASURED, summary="found")
        case = cf.append(case, stage="remediation", basis=cf.MEASURED, summary="fixed")
        self.assertFalse(cf.is_proven(case), "a proposal is not a proof")

    def test_a_broken_chain_is_never_proven(self):
        case = worked_case()
        case["entries"][0]["summary"] = "tampered"
        self.assertFalse(cf.is_proven(case))

    def test_hypotheses_are_excluded_from_measured_evidence(self):
        case = opened()
        case = cf.append(case, stage="root_cause", basis=cf.HYPOTHESIS,
                         summary="probably a missing sanitiser")
        case = cf.append(case, stage="discovery", basis=cf.MEASURED, summary="taint path")
        measured = cf.measured_only(case)
        self.assertEqual(1, len(measured))
        self.assertEqual("discovery", measured[0]["stage"])


class EvidenceIsSafeToShare(unittest.TestCase):
    def test_secret_shaped_keys_are_redacted(self):
        case = cf.append(opened(), stage="discovery", basis=cf.MEASURED,
                         summary="found", evidence={"api_key": "AKIAIOSFODNN7EXAMPLE",
                                                    "password": "hunter2",
                                                    "line": 12})
        stored = case["entries"][0]["evidence"]
        self.assertEqual(cf.REDACTED, stored["api_key"])
        self.assertEqual(cf.REDACTED, stored["password"])
        self.assertEqual(12, stored["line"])

    def test_secret_shaped_values_are_redacted_even_under_a_bland_key(self):
        case = cf.append(opened(), stage="discovery", basis=cf.MEASURED,
                         summary="found", evidence={"note": "ghp_" + "a" * 30})
        self.assertEqual(cf.REDACTED, case["entries"][0]["evidence"]["note"])

    def test_nested_secrets_are_redacted(self):
        case = cf.append(opened(), stage="discovery", basis=cf.MEASURED, summary="f",
                         evidence={"env": {"token": "abc123", "port": 8080}})
        env = case["entries"][0]["evidence"]["env"]
        self.assertEqual(cf.REDACTED, env["token"])
        self.assertEqual(8080, env["port"])


class InputIsValidated(unittest.TestCase):
    def test_an_unknown_stage_is_refused(self):
        with self.assertRaises(cf.CaseFileError):
            cf.append(opened(), stage="vibes", basis=cf.MEASURED, summary="x")

    def test_an_unknown_basis_is_refused(self):
        with self.assertRaises(cf.CaseFileError):
            cf.append(opened(), stage="discovery", basis="probably", summary="x")

    def test_a_bad_subject_digest_is_refused(self):
        bad = dict(SUBJECT, subject_sha256="not-a-digest")
        with self.assertRaises(cf.CaseFileError):
            cf.open_case(**bad)

    def test_appending_to_a_non_case_is_refused(self):
        with self.assertRaises(cf.CaseFileError):
            cf.append({"schema": "something-else"}, stage="discovery",
                      basis=cf.MEASURED, summary="x")

    def test_non_finite_numbers_are_refused(self):
        with self.assertRaises(cf.CaseFileError):
            cf.append(opened(), stage="discovery", basis=cf.MEASURED, summary="x",
                      evidence={"ratio": float("inf")})


class ReportingIsHonest(unittest.TestCase):
    def test_missing_stages_are_named(self):
        case = cf.append(opened(), stage="discovery", basis=cf.MEASURED, summary="f")
        missing = cf.stages_missing(case)
        self.assertIn("remediation", missing)
        self.assertNotIn("discovery", missing)

    def test_render_states_unproven_and_lists_gaps(self):
        text = cf.render(cf.append(opened(), stage="discovery",
                                   basis=cf.MEASURED, summary="found"))
        self.assertIn("proven  : no", text)
        self.assertIn("not established", text)

    def test_render_flags_a_broken_chain(self):
        case = worked_case()
        case["entries"][0]["summary"] = "tampered"
        self.assertIn("BROKEN", cf.render(case))

    def test_canonical_json_is_stable_across_key_order(self):
        self.assertEqual(cf.digest_json({"a": 1, "b": 2}),
                         cf.digest_json({"b": 2, "a": 1}))


if __name__ == "__main__":
    unittest.main()
