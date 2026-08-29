#!/usr/bin/env python3
"""Tests for model_audit.py.

The important ones are the models that fail.  A battery is only worth running
if it refuses the things it is supposed to refuse, and the failure that nearly
got through here was a model with a single opinion -- it rejected every probe,
scored full marks on the fabricated half, and an earlier version of this check
called it usable.
"""
import unittest

import model_audit as audit

CONFIRM = "CONFIRMED. The pointer is freed and then read on the next line."
REJECT = "REJECTED. The pointer is released only after its last use."


def answers(**overrides):
    """A perfect run, with named probes optionally spoiled."""
    out = []
    for probe in audit.PROBES:
        text = CONFIRM if probe["defect_real"] else REJECT
        out.append(overrides.get(probe["name"], text))
    return out


class ClassifyTests(unittest.TestCase):
    def test_the_leading_keyword_decides(self):
        self.assertEqual(audit.classify("CONFIRMED. blah"), audit.ACCEPTED)
        self.assertEqual(audit.classify("REJECTED - not present"), audit.REJECTED)

    def test_prose_rejection_is_understood(self):
        # The wording a local 3B actually produced.
        text = ("The reported `c-use-after-free` at line 7 is incorrect. "
                "The code is correct because the pointer is freed later.")
        self.assertEqual(audit.classify(text), audit.REJECTED)

    def test_prose_confirmation_is_understood(self):
        text = "Yes, this is a real defect: the buffer is written past its end."
        self.assertEqual(audit.classify(text), audit.ACCEPTED)

    def test_a_model_that_will_not_commit_is_unclear_not_guessed(self):
        for text in ("It depends on how the function is called.",
                     "This might be incorrect, but it could also be correct.",
                     ""):
            with self.subTest(text=text[:20]):
                self.assertEqual(audit.classify(text), audit.UNCLEAR)

    def test_non_text_is_refused(self):
        for bad in (None, 3, [], {}):
            with self.subTest(value=bad):
                with self.assertRaises(audit.AuditError):
                    audit.classify(bad)


class AuditTests(unittest.TestCase):
    def test_a_model_that_separates_the_cases_is_trusted(self):
        report = audit.audit("good-model", answers())
        self.assertTrue(report["trusted"])
        self.assertEqual(report["verdict"], "trusted")
        self.assertEqual(report["correct"], len(audit.PROBES))
        self.assertFalse(report["always_one_answer"])
        self.assertTrue(audit.may_speak(report)[0])

    def test_a_model_that_rejects_everything_is_refused(self):
        # The real failure: it catches every fabrication *and* throws away
        # every true finding, so a fabrication-only metric calls it excellent.
        report = audit.audit("contrarian", [REJECT] * len(audit.PROBES))
        self.assertFalse(report["trusted"])
        self.assertTrue(report["always_one_answer"])
        self.assertEqual(report["fabrications_rejected"],
                         report["fabricated_total"])
        self.assertEqual(report["genuine_accepted"], 0)
        allowed, why = audit.may_speak(report)
        self.assertFalse(allowed)
        self.assertIn("one answer to everything", why)

    def test_a_model_that_confirms_everything_is_refused(self):
        report = audit.audit("credulous", [CONFIRM] * len(audit.PROBES))
        self.assertFalse(report["trusted"])
        self.assertTrue(report["always_one_answer"])
        self.assertEqual(report["fabrications_rejected"], 0)

    def test_one_wrong_answer_is_enough_to_refuse(self):
        spoiled = answers(**{"genuine-null-dereference": REJECT})
        report = audit.audit("nearly", spoiled)
        self.assertFalse(report["trusted"])
        self.assertEqual(report["correct"], len(audit.PROBES) - 1)

    def test_an_evasive_answer_counts_against_the_model(self):
        spoiled = answers(**{"genuine-use-after-free": "Hard to say either way."})
        report = audit.audit("evasive", spoiled)
        self.assertFalse(report["trusted"])
        self.assertEqual(report["unclear_answers"], 1)

    def test_the_wrong_number_of_answers_is_refused(self):
        for bad in ([], [CONFIRM], [CONFIRM] * (len(audit.PROBES) + 1)):
            with self.subTest(count=len(bad)):
                with self.assertRaises(audit.AuditError):
                    audit.audit("m", bad)

    def test_a_model_must_be_named(self):
        for bad in ("", "   ", None, 7):
            with self.subTest(model=bad):
                with self.assertRaises(audit.AuditError):
                    audit.audit(bad, answers())

    def test_the_battery_has_both_kinds_of_probe(self):
        genuine = [p for p in audit.PROBES if p["defect_real"]]
        fabricated = [p for p in audit.PROBES if not p["defect_real"]]
        self.assertGreaterEqual(len(genuine), 3)
        self.assertGreaterEqual(len(fabricated), 3)

    def test_the_prompt_does_not_suggest_its_own_answer(self):
        # An earlier wording invited rejection and the model rejected
        # everything, including what was true.
        for probe in audit.PROBES:
            text = prompt = audit.prompt_for(probe)
            with self.subTest(probe=probe["name"]):
                self.assertIn("CONFIRMED", prompt)
                self.assertIn("REJECTED", prompt)
                self.assertNotIn("do not invent", text.lower())


class MaySpeakTests(unittest.TestCase):
    def test_a_tampered_report_is_refused(self):
        report = audit.audit("good-model", answers())
        report["correct"] = 0
        self.assertFalse(audit.may_speak(report)[0])

    def test_a_report_for_another_battery_is_refused(self):
        report = audit.audit("good-model", answers())
        report["battery_sha256"] = "0" * 64
        report["report_sha256"] = audit._sha(
            {k: v for k, v in report.items() if k != "report_sha256"})
        allowed, why = audit.may_speak(report)
        self.assertFalse(allowed)
        self.assertIn("different battery", why)

    def test_no_report_at_all_is_a_refusal(self):
        for bad in (None, {}, {"schema": "something-else"}):
            with self.subTest(report=bad):
                self.assertFalse(audit.may_speak(bad)[0])


class ViolationTests(unittest.TestCase):
    def test_contradicting_a_verified_finding_is_recorded(self):
        ledger = audit.record_violation(None, "m", "denied c-use-after-free")
        self.assertEqual(ledger["counts"]["m"], 1)
        self.assertEqual(audit.standing(ledger, "m")["violations"], 1)
        self.assertTrue(audit.standing(ledger, "m")["allowed"])

    def test_a_model_is_withdrawn_once_it_reaches_the_limit(self):
        ledger = None
        for _ in range(audit.MAX_VIOLATIONS):
            ledger = audit.record_violation(ledger, "m", "denied a real finding")
        self.assertIn("m", ledger["withdrawn"])
        self.assertFalse(audit.standing(ledger, "m")["allowed"])
        self.assertEqual(audit.standing(ledger, "m")["remaining"], 0)

    def test_one_model_s_record_does_not_touch_another_s(self):
        ledger = None
        for _ in range(audit.MAX_VIOLATIONS):
            ledger = audit.record_violation(ledger, "bad", "denied it")
        self.assertTrue(audit.standing(ledger, "other")["allowed"])
        self.assertNotIn("other", ledger["withdrawn"])

    def test_a_violation_must_say_what_was_contradicted(self):
        for detail in ("", "   ", None):
            with self.subTest(detail=detail):
                with self.assertRaises(audit.AuditError):
                    audit.record_violation(None, "m", detail)

    def test_an_unknown_model_starts_clean(self):
        self.assertEqual(audit.standing(None, "fresh")["violations"], 0)
        self.assertTrue(audit.standing(None, "fresh")["allowed"])


class PhrasingBatteryTests(unittest.TestCase):
    """Explaining a settled finding is a different job from judging one.

    Both local models failed the adjudication battery. Gating explanation on
    that battery would refuse them for failing a task they are never given,
    so faithfulness is measured on its own terms: stay on the defect handed
    over, point at the right line, and do not quietly dispute it.
    """

    FAITHFUL = [
        "The pointer is freed on line 5 and then read on line 6 after release.",
        "The pointer d is null on line 5 where it is dereferenced.",
        "dst is too small, so the copy on line 6 writes past the end of it.",
    ]

    def test_a_faithful_explainer_is_trusted(self):
        report = audit.audit_phrasing("m", self.FAITHFUL)
        self.assertTrue(report["trusted"])
        self.assertEqual(report["role"], audit.ROLE_PHRASE)
        self.assertTrue(audit.may_speak(report, role=audit.ROLE_PHRASE)[0])

    def test_disputing_the_finding_it_was_handed_fails(self):
        spoiled = list(self.FAITHFUL)
        spoiled[0] = "The reported defect is incorrect; the code is correct."
        report = audit.audit_phrasing("m", spoiled)
        self.assertFalse(report["trusted"])
        self.assertTrue(report["disputed_any"])

    def test_citing_the_wrong_line_fails(self):
        spoiled = list(self.FAITHFUL)
        spoiled[0] = "The pointer is freed and then read after release."
        report = audit.audit_phrasing("m", spoiled)
        self.assertFalse(report["trusted"])
        self.assertFalse(report["rows"][0]["located_the_defect"])

    def test_wandering_onto_another_defect_fails(self):
        spoiled = list(self.FAITHFUL)
        spoiled[1] = ("The pointer d is null on line 5, and there is also a "
                      "buffer overflow here.")
        report = audit.audit_phrasing("m", spoiled)
        self.assertFalse(report["trusted"])
        self.assertIn("buffer overflow",
                      report["rows"][1]["mentioned_other_defects"])

    def test_missing_the_mechanism_fails(self):
        spoiled = list(self.FAITHFUL)
        spoiled[2] = "Something is wrong on line 6 and should be corrected."
        report = audit.audit_phrasing("m", spoiled)
        self.assertFalse(report["trusted"])
        self.assertFalse(report["rows"][2]["described_the_mechanism"])

    def test_the_phrase_prompt_never_asks_for_a_verdict(self):
        for probe in audit.PHRASE_PROBES:
            prompt = audit.phrase_probe_prompt(probe).lower()
            with self.subTest(probe=probe["name"]):
                self.assertIn("not in question", prompt)
                self.assertNotIn("decide whether", prompt)

    def test_the_two_roles_do_not_authorise_each_other(self):
        phrasing = audit.audit_phrasing("m", self.FAITHFUL)
        judging = audit.audit(
            "m", ["CONFIRMED. real" if p["defect_real"] else "REJECTED. no"
                  for p in audit.PROBES])
        self.assertFalse(audit.may_speak(phrasing,
                                         role=audit.ROLE_ADJUDICATE)[0])
        self.assertFalse(audit.may_speak(judging, role=audit.ROLE_PHRASE)[0])

    def test_an_unknown_role_is_refused(self):
        report = audit.audit_phrasing("m", self.FAITHFUL)
        self.assertFalse(audit.may_speak(report, role="anything")[0])

    def test_the_wrong_number_of_answers_is_refused(self):
        with self.assertRaises(audit.AuditError):
            audit.audit_phrasing("m", self.FAITHFUL[:1])


class RenderTests(unittest.TestCase):
    def test_the_single_opinion_failure_is_called_out_by_name(self):
        report = audit.audit("contrarian", [REJECT] * len(audit.PROBES))
        text = audit.render(report)
        self.assertIn("same answer to every probe", text)
        self.assertIn("refused", text)

    def test_each_probe_is_shown_with_its_outcome(self):
        text = audit.render(audit.audit("good-model", answers()))
        for probe in audit.PROBES:
            self.assertIn(probe["name"], text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
