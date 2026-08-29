#!/usr/bin/env python3
"""Tests for advisory41.py.

The cases that matter are the ones where the model misbehaves. A layer that
only works when the model is well behaved is not a boundary, it is a hope.
"""
import unittest

import advisory41 as advisory
import model_audit

FINDING = {"rule": "c-use-after-free", "line": 6, "severity": "HIGH",
           "message": "'p' was released on line 5 and is read again here."}

CODE = ("void f(void)\n{\n    char * p = malloc(100);\n"
        "    if (p == NULL) { exit(-1); }\n    free(p);\n"
        "    printLine(p);\n}\n")

GOOD_TEXT = ("The pointer p is released by free on line 5 and then passed to "
             "printLine on line 6, so the read touches memory the allocator "
             "may already have reused. Move the free below the last use.")

DENIAL = ("The reported c-use-after-free at line 6 is incorrect. The code is "
          "correct because the pointer is freed only after its final use.")


FAITHFUL = [
    "The pointer is freed on line 5 and then read on line 6 after release.",
    "The pointer d is null on line 5 where it is dereferenced.",
    "dst is too small, so the copy on line 6 writes past the end of it.",
]


def passing_audit(model_id="good-model"):
    """A *phrasing* clearance -- the only one that unlocks this layer."""
    return model_audit.audit_phrasing(model_id, FAITHFUL)


def failing_audit():
    return model_audit.audit_phrasing(
        "contrarian", ["The report is incorrect; the code is fine."] * 3)


def adjudication_audit():
    return model_audit.audit(
        "judge", ["CONFIRMED. real" if probe["defect_real"] else "REJECTED. no"
                  for probe in model_audit.PROBES])


class PromptTests(unittest.TestCase):
    def test_the_prompt_never_offers_a_verdict(self):
        prompt = advisory.phrase_prompt(FINDING, CODE)
        lowered = prompt.lower()
        for invitation in ("decide whether", "is it correct", "confirmed",
                           "rejected", "if it is not"):
            self.assertNotIn(invitation, lowered)
        self.assertIn("not in question", lowered)

    def test_the_prompt_carries_the_finding_and_the_code(self):
        prompt = advisory.phrase_prompt(FINDING, CODE)
        self.assertIn("c-use-after-free", prompt)
        self.assertIn("line 6", prompt)
        self.assertIn("printLine(p)", prompt)

    def test_a_finding_missing_its_parts_is_refused(self):
        for broken in ({"line": 1, "message": "m"},
                       {"rule": "r", "message": "m"},
                       {"rule": "r", "line": 1},
                       {"rule": "", "line": 1, "message": "m"}):
            with self.subTest(finding=sorted(broken)):
                with self.assertRaises(advisory.AdvisoryError):
                    advisory.phrase_prompt(broken, CODE)

    def test_empty_code_is_refused(self):
        with self.assertRaises(advisory.AdvisoryError):
            advisory.phrase_prompt(FINDING, "   ")


class GenerationTests(unittest.TestCase):
    def make(self, text, **kwargs):
        options = {"model_id": "good-model", "audit_report": passing_audit()}
        options.update(kwargs)
        return advisory.make_advisory(FINDING, CODE, lambda _: text, **options)

    def test_a_good_explanation_is_issued(self):
        item = self.make(GOOD_TEXT)
        self.assertEqual(item["status"], advisory.ISSUED)
        self.assertIn("printLine", item["text"])
        self.assertEqual(item["evidence_state"], advisory.INFERRED)

    def test_a_model_that_disputes_the_finding_is_withheld_and_charged(self):
        # It was told the defect was settled. Volunteering otherwise is the
        # exact failure both local models showed, so it costs them.
        item = self.make(DENIAL)
        self.assertEqual(item["status"], advisory.WITHHELD)
        self.assertEqual(item["text"], "")
        self.assertIn("disputed", item["reason"])
        self.assertIn("denied c-use-after-free", item["violation"])

    def test_an_unaudited_model_is_silent(self):
        item = self.make(GOOD_TEXT, audit_report=None)
        self.assertEqual(item["status"], advisory.WITHHELD)
        self.assertIn("no audit report", item["reason"])

    def test_a_model_that_failed_its_audit_is_silent(self):
        item = self.make(GOOD_TEXT, audit_report=failing_audit(),
                         model_id="contrarian")
        self.assertEqual(item["status"], advisory.WITHHELD)
        self.assertIn("failed its audit", item["reason"])

    def test_clearance_to_judge_does_not_grant_clearance_to_explain(self):
        # The two roles are audited separately on purpose; one must never be
        # accepted in place of the other.
        item = self.make(GOOD_TEXT, audit_report=adjudication_audit(),
                         model_id="judge")
        self.assertEqual(item["status"], advisory.WITHHELD)
        self.assertIn("role", item["reason"])

    def test_a_withdrawn_model_is_silent_even_with_a_passing_audit(self):
        ledger = None
        for _ in range(model_audit.MAX_VIOLATIONS):
            ledger = model_audit.record_violation(ledger, "good-model", "denied")
        item = self.make(GOOD_TEXT, ledger=ledger)
        self.assertEqual(item["status"], advisory.WITHHELD)
        self.assertIn("withdrawn", item["reason"])

    def test_a_crashing_model_withholds_rather_than_propagates(self):
        def explode(_):
            raise RuntimeError("out of memory")
        item = advisory.make_advisory(FINDING, CODE, explode,
                                      model_id="m",
                                      audit_report=passing_audit())
        self.assertEqual(item["status"], advisory.WITHHELD)
        self.assertIn("generation failed", item["reason"])

    def test_an_empty_answer_is_withheld(self):
        for text in ("", "   ", None):
            with self.subTest(text=text):
                self.assertEqual(self.make(text)["status"], advisory.WITHHELD)

    def test_runaway_output_is_bounded(self):
        item = self.make("the pointer is stale. " * 5000)
        self.assertLessEqual(len(item["text"]), advisory.MAX_ADVISORY_CHARS)

    def test_generate_must_be_callable(self):
        with self.assertRaises(advisory.AdvisoryError):
            advisory.make_advisory(FINDING, CODE, "not a function",
                                   model_id="m", audit_report=passing_audit())

    def test_charging_violations_moves_the_ledger(self):
        denied = self.make(DENIAL)
        ledger = advisory.charge_violations(None, [denied])
        self.assertEqual(model_audit.standing(ledger, "good-model")["violations"], 1)

    def test_a_clean_run_charges_nothing(self):
        ledger = advisory.charge_violations(None, [self.make(GOOD_TEXT)])
        self.assertIsNone(ledger)


class SeparationTests(unittest.TestCase):
    REPORT = {"schema": "attestor.report/1.0", "findings": [dict(FINDING)],
              "status": "action-required"}

    def build(self, text=GOOD_TEXT):
        item = advisory.make_advisory(FINDING, CODE, lambda _: text,
                                      model_id="good-model",
                                      audit_report=passing_audit())
        return advisory.attach(self.REPORT, [item])

    def test_the_report_passes_through_byte_identical(self):
        before = dict(self.REPORT)
        envelope = self.build()
        self.assertEqual(envelope["report"], before)
        self.assertIs(envelope["report"], self.REPORT)

    def test_separation_verifies(self):
        ok, problems = advisory.verify_separation(self.build())
        self.assertTrue(ok, problems)

    def test_advisory_text_smuggled_into_the_report_is_caught(self):
        envelope = self.build()
        envelope["report"] = dict(self.REPORT, explanation=GOOD_TEXT)
        ok, problems = advisory.verify_separation(envelope)
        self.assertFalse(ok)
        self.assertTrue(any("explanation" in p for p in problems))

    def test_a_tampered_report_digest_is_caught(self):
        envelope = self.build()
        envelope["report_sha256"] = "0" * 64
        self.assertFalse(advisory.verify_separation(envelope)[0])

    def test_counts_distinguish_issued_from_withheld(self):
        good = advisory.make_advisory(FINDING, CODE, lambda _: GOOD_TEXT,
                                      model_id="m", audit_report=passing_audit())
        bad = advisory.make_advisory(FINDING, CODE, lambda _: DENIAL,
                                     model_id="m", audit_report=passing_audit())
        envelope = advisory.attach(self.REPORT, [good, bad])
        self.assertEqual(envelope["advisory"]["issued"], 1)
        self.assertEqual(envelope["advisory"]["withheld"], 1)

    def test_a_foreign_object_cannot_be_attached(self):
        with self.assertRaises(advisory.AdvisoryError):
            advisory.attach(self.REPORT, [{"schema": "something/1.0"}])

    def test_a_non_envelope_does_not_verify(self):
        for bad in ({}, {"schema": "other"}, {"schema":
                    "attestor.advisory-envelope/1.0"}):
            with self.subTest(value=bad):
                self.assertFalse(advisory.verify_separation(bad)[0])


class RankingTests(unittest.TestCase):
    """The gate orders review. It never decides anything.

    The width used has to come from the artifact: the shipped model is trained
    on twelve-line windows while the corpus builder still defaults to four, and
    feeding it the wrong width never raises -- it just scores worse quietly.
    """

    SOURCE = "\n".join("line %d" % i for i in range(1, 61))
    FINDINGS = [{"rule": "r-one", "line": 10, "message": "m"},
                {"rule": "r-two", "line": 40, "message": "m"}]

    def gate(self, **overrides):
        import neural_gate
        model = dict(neural_gate.default_model())
        model.update(overrides)
        if overrides:
            model.pop("model_sha256", None)
            model["model_sha256"] = neural_gate._sha(model)
        return model

    def test_the_window_width_comes_from_the_artifact(self):
        for declared in (4, 8, 12):
            with self.subTest(window=declared):
                rows = advisory.rank(self.FINDINGS, self.SOURCE,
                                     self.gate(window_lines=declared))
                self.assertTrue(all(r["window_lines"] == declared for r in rows))

    def test_every_row_is_inferred_evidence_bound_to_the_model(self):
        model = self.gate()
        rows = advisory.rank(self.FINDINGS, self.SOURCE, model)
        self.assertEqual(len(rows), len(self.FINDINGS))
        for row in rows:
            self.assertEqual(row["evidence_state"], advisory.INFERRED)
            self.assertEqual(row["model_sha256"], model["model_sha256"])
            self.assertLessEqual(row["score"], row["scale"])

    def test_rows_come_back_highest_first(self):
        rows = advisory.rank(self.FINDINGS, self.SOURCE, self.gate())
        self.assertEqual([r["score"] for r in rows],
                         sorted((r["score"] for r in rows), reverse=True))

    def test_ranking_does_not_touch_the_findings(self):
        before = [dict(item) for item in self.FINDINGS]
        advisory.rank(self.FINDINGS, self.SOURCE, self.gate())
        self.assertEqual(self.FINDINGS, before)

    def test_a_model_declaring_an_unusable_window_is_refused(self):
        for bad in (0, -1, advisory.MAX_WINDOW_LINES + 1, "12", 2.5):
            with self.subTest(window=bad):
                with self.assertRaises(advisory.AdvisoryError):
                    advisory.rank(self.FINDINGS, self.SOURCE,
                                  self.gate(window_lines=bad))

    def test_a_window_at_the_top_of_a_file_is_clamped_not_negative(self):
        text = advisory.window_for(self.SOURCE, 1, 12)
        self.assertTrue(text.startswith("line 1"))
        self.assertEqual(len(text.splitlines()), 12)

    def test_a_window_past_the_end_still_returns_lines(self):
        self.assertTrue(advisory.window_for(self.SOURCE, 10_000, 12).strip())
        self.assertEqual(advisory.window_for("", 5, 12), "")

    def test_a_ranking_not_marked_inferred_is_caught(self):
        rows = advisory.rank(self.FINDINGS, self.SOURCE, self.gate())
        rows[0]["evidence_state"] = "supported"
        envelope = advisory.attach({"schema": "r"}, [], rows)
        ok, problems = advisory.verify_separation(envelope)
        self.assertFalse(ok)
        self.assertTrue(any("not marked inferred" in p for p in problems))

    def test_a_report_carrying_a_ranking_key_is_caught(self):
        rows = advisory.rank(self.FINDINGS, self.SOURCE, self.gate())
        envelope = advisory.attach({"schema": "r", "ranking": rows}, [], rows)
        ok, problems = advisory.verify_separation(envelope)
        self.assertFalse(ok)
        self.assertTrue(any("'ranking'" in p for p in problems))

    def test_non_text_source_is_refused(self):
        with self.assertRaises(advisory.AdvisoryError):
            advisory.rank(self.FINDINGS, None, self.gate())


class RenderTests(unittest.TestCase):
    def test_the_boundary_is_stated_in_the_output(self):
        item = advisory.make_advisory(FINDING, CODE, lambda _: GOOD_TEXT,
                                      model_id="m", audit_report=passing_audit())
        text = advisory.render(advisory.attach({"schema": "r"}, [item]))
        self.assertIn("outside the verified report", text)
        self.assertIn("no advisory created, removed, promoted or suppressed",
                      text)

    def test_a_withheld_advisory_says_why(self):
        item = advisory.make_advisory(FINDING, CODE, lambda _: DENIAL,
                                      model_id="m", audit_report=passing_audit())
        text = advisory.render(advisory.attach({"schema": "r"}, [item]))
        self.assertIn("withheld", text)
        self.assertIn("disputed", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
