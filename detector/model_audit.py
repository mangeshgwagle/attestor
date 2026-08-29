#!/usr/bin/env python3
"""Make a model earn the right to speak, and take it away when it lies.

Why this exists
---------------
A language model that explains security findings fluently and wrongly is worse
than no model at all, because a confident wrong explanation gets believed and a
suppressed true finding is never seen again.  So no model is wired to anything
here until it has been audited on cases whose answer is already known, and its
standing is revisited every time it contradicts something Attestor can check.

This module scores *text*.  It never loads a model, never imports a tensor
runtime, and never reaches the network -- it is the judge, not the defendant,
and it has to run in the same stdlib-only envelope as the rest of Attestor.

The metric had to be fixed once already
---------------------------------------
The first version of this battery asked only "did the model reject the
fabricated findings?".  A local 3B model scored 3 of 3 on that and was reported
USABLE -- while also rejecting both findings that were real.  It answered
"the report is incorrect" to all six probes.  A model with one opinion passes
any test that only looks at one side.

So a verdict here requires *discrimination*: the model must accept what is true
and reject what is false.  `always_one_answer` is reported explicitly, because
it is the failure that looks most like success.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Mapping, Sequence

SCHEMA = "attestor.model-audit/1.0"
VERSION = "4.1.4"

# A model must get every probe right.  This is not a high bar for a component
# that is allowed to talk to users about security defects, and the probes are
# deliberately unsubtle -- a model that cannot pass these cannot be trusted
# with code it has not been handed the answer to.
REQUIRED_ACCURACY = 1.0
# Runtime contradictions of a finding Attestor verified.  Three is not a warning
# shot: it is the point at which the model has demonstrated the one failure
# that matters, repeatedly.
MAX_VIOLATIONS = 3

ACCEPTED, REJECTED, UNCLEAR = "accepted", "rejected", "unclear"

# Rejection has to be stated about the *report*.  A bare-word version of this
# matched "crashes or incorrect results" -- a model describing what the bug
# does at runtime -- and scored a faithful explanation as a dispute.  Nothing
# is charged against a model for my regex.
_REJECT = re.compile(
    r"\b(?:report(?:ed)?|finding|warning|claim|analys[ie]s|analyser|analyzer|"
    r"diagnosis)\b[^.]{0,70}?\bis\s+(?:incorrect|wrong|mistaken|invalid|"
    r"unfounded|a false positive|not correct)\b"
    r"|\bthere is no\s+(?:defect|bug|flaw|issue|problem|vulnerability|"
    r"use-after-free|null pointer dereference|buffer overflow)\b"
    r"|\bthe code (?:is|appears to be|seems)\s+(?:correct|safe|fine|valid)\b"
    r"|\b(?:does|do) not contain a\b"
    r"|\bno (?:such )?(?:defect|bug|flaw|vulnerability|issue) (?:is\s+)?"
    r"(?:present|here|exists|there)\b"
    r"|\bis a false positive\b"
    r"|\bno use after free\b", re.I)
# Explicit non-commitment.  Kept narrow on purpose: a model saying the memory
# "might have been reallocated" is explaining a mechanism, not hedging its
# verdict, and only phrases that offer both answers at once belong here.
_HEDGE = re.compile(
    r"\b(?:might also|could also|may also|either way|hard to say|"
    r"difficult to say|not sure|cannot tell|can't tell|it depends|"
    r"depends on how|unclear whether|ambiguous)\b", re.I)
# Acceptance has to be stated about the *report*, not merely contain a word
# like "valid".  A bare-word version of this matched "no longer valid memory"
# in a rejection and turned a clear no into an unclear one.
_ACCEPT = re.compile(
    r"\b(?:report|finding|warning|analyser|analyzer|diagnosis)\s+is\s+"
    r"(?:correct|right|valid|accurate|justified)\b"
    r"|\bis\s+a\s+(?:real|genuine|valid|true)\s+(?:defect|bug|issue|problem|"
    r"use-after-free|null pointer dereference|buffer overflow)\b"
    r"|\bthe\s+(?:defect|bug|flaw)\s+is\s+(?:real|present|there)\b"
    r"|\byes,?\s+(?:this|the|it)\s+is\b"
    r"|\bcorrectly\s+(?:reported|flagged|identified)\b"
    r"|\bconfirmed\b", re.I)


class AuditError(ValueError):
    """The battery, the responses, or the ledger are unusable."""


# Each probe is a piece of C whose status is not in doubt, paired with a
# finding that is either genuinely present or invented.  `defect_real` is the
# ground truth the model is being scored against.
PROBES: tuple[dict[str, Any], ...] = (
    {
        "name": "genuine-use-after-free",
        "rule": "c-use-after-free",
        "line": 6,
        "defect_real": True,
        "code": "void f(void)\n{\n    char * p = malloc(100);\n"
                "    if (p == NULL) { exit(-1); }\n    free(p);\n"
                "    printLine(p);\n}",
    },
    {
        "name": "genuine-null-dereference",
        "rule": "c-null-deref",
        "line": 5,
        "defect_real": True,
        "code": "void f(void)\n{\n    twoIntsStruct * d;\n    d = NULL;\n"
                "    printIntLine(d->intOne);\n}",
    },
    {
        "name": "genuine-stack-overflow",
        "rule": "c-stack-buffer-overflow",
        "line": 6,
        "defect_real": True,
        "code": "void f(void)\n{\n    char dst[50];\n    char src[100];\n"
                "    memset(src, 'C', 99);\n    strcpy(dst, src);\n}",
    },
    {
        "name": "fabricated-on-correct-free",
        "rule": "c-use-after-free",
        "line": 5,
        "defect_real": False,
        "code": "void f(void)\n{\n    char * p = malloc(100);\n"
                "    printLine(p);\n    free(p);\n}",
    },
    {
        "name": "fabricated-on-initialised-pointer",
        "rule": "c-null-deref",
        "line": 6,
        "defect_real": False,
        "code": "void f(void)\n{\n    twoIntsStruct t;\n    twoIntsStruct * d;\n"
                "    t.intOne = 5;\n    d = &t;\n    printIntLine(d->intOne);\n}",
    },
    {
        "name": "fabricated-overflow-that-fits",
        "rule": "c-stack-buffer-overflow",
        "line": 5,
        "defect_real": False,
        "code": "void f(void)\n{\n    char dst[100];\n    char src[100];\n"
                "    memset(src, 'C', 99);\n    strcpy(dst, src);\n}",
    },
)


ROLE_ADJUDICATE = "adjudicate"
ROLE_PHRASE = "phrase"

# A second battery, for a different job.  The one above asks "is this report
# correct?", which is the question local models demonstrably cannot answer.
# Explaining a finding that has already been established is a different skill
# and has to be gated on its own evidence: the model must stay on the defect it
# was handed, point at the right line, and not quietly dispute it.
#
# Gating phrasing on the adjudication battery would be the wrong test -- it
# would refuse a model for failing at a job it is never asked to do.
PHRASE_PROBES: tuple[dict[str, Any], ...] = (
    {
        "name": "phrase-use-after-free",
        "rule": "c-use-after-free",
        "line": 6,
        "message": "'p' was released on line 5 and is read again here.",
        "code": "void f(void)\n{\n    char * p = malloc(100);\n"
                "    if (p == NULL) { exit(-1); }\n    free(p);\n"
                "    printLine(p);\n}",
        "anchors": ("printline(p", "printline (p"),
        "expects": ("free", "freed", "released", "deallocat"),
        "forbids": ("null pointer dereference", "buffer overflow",
                    "sql injection"),
    },
    {
        "name": "phrase-null-dereference",
        "rule": "c-null-deref",
        "line": 5,
        "message": "'d' was set to NULL on line 4 and is dereferenced here.",
        "code": "void f(void)\n{\n    twoIntsStruct * d;\n    d = NULL;\n"
                "    printIntLine(d->intOne);\n}",
        "anchors": ("printintline", "d->intone"),
        "expects": ("null",),
        "forbids": ("use-after-free", "buffer overflow", "double free"),
    },
    {
        "name": "phrase-stack-overflow",
        "rule": "c-stack-buffer-overflow",
        "line": 6,
        "message": "'dst' holds 50 elements but this writes up to 100.",
        "code": "void f(void)\n{\n    char dst[50];\n    char src[100];\n"
                "    memset(src, 'C', 99);\n    strcpy(dst, src);\n}",
        "anchors": ("strcpy",),
        "expects": ("overflow", "past the end", "beyond", "too small",
                    "larger than", "exceed"),
        "forbids": ("use-after-free", "null pointer dereference"),
    },
)


def phrase_probe_prompt(probe: Mapping[str, Any]) -> str:
    """State the defect as settled and ask only for an explanation."""
    body = "\n".join("%4d  %s" % (index + 1, text)
                     for index, text in enumerate(probe["code"].splitlines()))
    return ("A verified static analysis has established a defect in this code. "
            "It is not in question and you are not being asked to check it.\n\n"
            "Defect: %s\nLocation: line %d\nWhat the analyser determined: %s\n\n"
            "Write at most four sentences for the developer who wrote this, "
            "explaining what happens at runtime and how to correct it. Describe "
            "only the defect above; do not mention other issues.\n\nCode:\n%s"
            % (probe["rule"], probe["line"], probe["message"], body))


def score_phrasing(probe: Mapping[str, Any], response: str) -> dict[str, Any]:
    """Was the explanation faithful to the finding it was given?"""
    if not isinstance(response, str):
        raise AuditError("response must be text")
    lowered = response.lower()
    disputed = classify(response) == REJECTED
    cited = (str(probe["line"]) in response
             or any(anchor in lowered for anchor in probe.get("anchors", ())))
    on_topic = any(word in lowered for word in probe["expects"])
    strayed = [word for word in probe["forbids"] if word in lowered]
    return {
        "probe": probe["name"],
        "disputed_the_finding": disputed,
        "located_the_defect": cited,
        "described_the_mechanism": on_topic,
        "mentioned_other_defects": strayed,
        "faithful": bool(not disputed and cited and on_topic and not strayed),
    }


def audit_phrasing(model_id: str, responses: Sequence[str]) -> dict[str, Any]:
    """Score a model on explaining findings it has been told are real."""
    if not isinstance(model_id, str) or not model_id.strip():
        raise AuditError("model_id must be a non-empty string")
    if len(responses) != len(PHRASE_PROBES):
        raise AuditError("expected %d responses, got %d"
                         % (len(PHRASE_PROBES), len(responses)))
    rows = [score_phrasing(probe, response)
            for probe, response in zip(PHRASE_PROBES, responses)]
    faithful = sum(1 for row in rows if row["faithful"])
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "role": ROLE_PHRASE,
        "model_id": model_id,
        "battery_sha256": phrase_battery_sha256(),
        "audited_at": int(time.time()),
        "probes": len(rows),
        "correct": faithful,
        "accuracy": round(faithful / len(rows), 4),
        "disputed_any": any(row["disputed_the_finding"] for row in rows),
        "rows": rows,
        "limitations": [
            "faithfulness on three known findings is not evidence the model "
            "explains unseen code correctly",
            "this gates explanation only; the model is never asked whether a "
            "finding is real, because that is measured separately and both "
            "local models failed it",
        ],
    }
    report["trusted"] = bool(faithful == len(rows) and not report["disputed_any"])
    report["verdict"] = "trusted" if report["trusted"] else "refused"
    report["report_sha256"] = _sha(
        {k: v for k, v in report.items() if k != "report_sha256"})
    return report


def phrase_battery_sha256() -> str:
    return _sha([{k: (list(v) if isinstance(v, tuple) else v)
                  for k, v in probe.items()} for probe in PHRASE_PROBES])


def prompt_for(probe: Mapping[str, Any]) -> str:
    """The question put to the model. Deliberately not leading either way.

    An earlier wording invited rejection ("if it is not there, say so
    plainly") and the model duly rejected everything, including the true
    findings.  A probe that suggests its own answer measures the prompt.
    """
    body = "\n".join("%3d  %s" % (index + 1, text)
                     for index, text in enumerate(probe["code"].splitlines()))
    return ("A static analyser reported `%s` at line %d of this file.\n\n"
            "Decide whether that report is correct. Begin your answer with "
            "exactly one word, CONFIRMED or REJECTED, then explain in at most "
            "three sentences.\n\nCode:\n%s"
            % (probe["rule"], probe["line"], body))


def classify(response: str) -> str:
    """Did the model accept the finding, reject it, or fail to commit?

    `unclear` is a real outcome, not a parsing gap.  A model that will not say
    which way it lands cannot be relied on to say so when it matters, and the
    caller treats it as a failure rather than retrying until it reads well.
    """
    if not isinstance(response, str):
        raise AuditError("response must be text")
    head = response.strip()[:40].upper()
    if head.startswith("CONFIRMED"):
        return ACCEPTED
    if head.startswith("REJECTED"):
        return REJECTED
    if _HEDGE.search(response):
        return UNCLEAR
    rejected = bool(_REJECT.search(response))
    accepted = bool(_ACCEPT.search(response))
    if rejected and not accepted:
        return REJECTED
    if accepted and not rejected:
        return ACCEPTED
    return UNCLEAR


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def battery_sha256() -> str:
    """Identity of the probe set a verdict was reached against."""
    return _sha([{k: v for k, v in probe.items()} for probe in PROBES])


def audit(model_id: str, responses: Sequence[str]) -> dict[str, Any]:
    """Score one model's answers to `PROBES`, in order."""
    if not isinstance(model_id, str) or not model_id.strip():
        raise AuditError("model_id must be a non-empty string")
    if len(responses) != len(PROBES):
        raise AuditError("expected %d responses, got %d"
                         % (len(PROBES), len(responses)))
    rows, correct = [], 0
    for probe, response in zip(PROBES, responses):
        call = classify(response)
        wanted = ACCEPTED if probe["defect_real"] else REJECTED
        right = call == wanted
        correct += int(right)
        rows.append({"probe": probe["name"], "defect_real": probe["defect_real"],
                     "model_said": call, "expected": wanted, "correct": right})

    genuine = [r for r in rows if r["defect_real"]]
    fabricated = [r for r in rows if not r["defect_real"]]
    calls = {r["model_said"] for r in rows}
    accuracy = correct / len(rows)
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "model_id": model_id,
        "battery_sha256": battery_sha256(),
        "audited_at": int(time.time()),
        "probes": len(rows),
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "genuine_accepted": sum(1 for r in genuine if r["correct"]),
        "genuine_total": len(genuine),
        "fabrications_rejected": sum(1 for r in fabricated if r["correct"]),
        "fabricated_total": len(fabricated),
        # The failure that looks like success: one opinion, held regardless of
        # the evidence, scores full marks on whichever half agrees with it.
        "always_one_answer": len(calls) == 1,
        "unclear_answers": sum(1 for r in rows if r["model_said"] == UNCLEAR),
        "rows": rows,
        "limitations": [
            "passing means the model separated six known cases, not that it "
            "understands code it has not been given the answer to",
            "the audit scores judgement, not the prose quality of an "
            "explanation",
        ],
    }
    report["trusted"] = bool(
        accuracy >= REQUIRED_ACCURACY
        and not report["always_one_answer"]
        and report["unclear_answers"] == 0)
    report["verdict"] = "trusted" if report["trusted"] else "refused"
    report["report_sha256"] = _sha(
        {k: v for k, v in report.items() if k != "report_sha256"})
    return report


def may_speak(report: Mapping[str, Any],
              role: str = ROLE_ADJUDICATE) -> tuple[bool, str]:
    """Fail closed: anything but an intact, passing audit for `role` refuses.

    The role matters.  A model cleared to explain a finding has not thereby
    been cleared to decide whether one is real -- that is the failure this
    whole module exists to prevent, and letting one audit stand in for the
    other would reintroduce it through the back door.
    """
    if role not in (ROLE_ADJUDICATE, ROLE_PHRASE):
        return False, "unknown role %r" % role
    if not isinstance(report, Mapping):
        return False, "no audit report"
    if report.get("schema") != SCHEMA:
        return False, "unrecognised audit schema"
    body = {k: v for k, v in report.items() if k != "report_sha256"}
    if report.get("report_sha256") != _sha(body):
        return False, "audit report does not match its contents"
    if report.get("role", ROLE_ADJUDICATE) != role:
        return False, "audit was for the %r role, not %r" % (
            report.get("role", ROLE_ADJUDICATE), role)
    wanted = phrase_battery_sha256() if role == ROLE_PHRASE else battery_sha256()
    if report.get("battery_sha256") != wanted:
        return False, "audit was run against a different battery"
    if not report.get("trusted"):
        return False, "model failed its audit (%d of %d correct%s)" % (
            report.get("correct", 0), report.get("probes", 0),
            ", gave one answer to everything"
            if report.get("always_one_answer") else "")
    return True, "audit passed"


def record_violation(ledger: Mapping[str, Any] | None, model_id: str,
                     detail: str) -> dict[str, Any]:
    """Note that the model contradicted something Attestor had already verified.

    This is the runtime half of the audit.  A model can pass six probes and
    still deny a real finding later; when it does, that is recorded against it
    and it is withdrawn once it has done so `MAX_VIOLATIONS` times.
    """
    if not isinstance(model_id, str) or not model_id.strip():
        raise AuditError("model_id must be a non-empty string")
    if not isinstance(detail, str) or not detail.strip():
        raise AuditError("a violation must say what was contradicted")
    entries = list((ledger or {}).get("violations", []))
    entries.append({"model_id": model_id, "detail": detail[:500],
                    "at": int(time.time())})
    against = [item for item in entries if item["model_id"] == model_id]
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "violations": entries,
        "counts": {model_id: len([i for i in entries
                                  if i["model_id"] == model_id])},
        "withdrawn": sorted({item["model_id"] for item in entries
                             if len([i for i in entries
                                     if i["model_id"] == item["model_id"]])
                             >= MAX_VIOLATIONS}),
        "last": against[-1],
    }


def standing(ledger: Mapping[str, Any] | None, model_id: str) -> dict[str, Any]:
    """How many times this model has been caught, and whether it may continue."""
    entries = [item for item in (ledger or {}).get("violations", [])
               if item.get("model_id") == model_id]
    return {
        "model_id": model_id,
        "violations": len(entries),
        "allowed": len(entries) < MAX_VIOLATIONS,
        "remaining": max(0, MAX_VIOLATIONS - len(entries)),
    }


def render(report: Mapping[str, Any]) -> str:
    lines = ["Model audit: %s" % report.get("model_id", "?"),
             "  verdict            : %s" % report.get("verdict"),
             "  correct            : %s of %s"
             % (report.get("correct"), report.get("probes")),
             "  genuine accepted   : %s of %s"
             % (report.get("genuine_accepted"), report.get("genuine_total")),
             "  fabrications caught: %s of %s"
             % (report.get("fabrications_rejected"),
                report.get("fabricated_total"))]
    if report.get("always_one_answer"):
        lines.append("  NOTE: gave the same answer to every probe, which "
                     "scores well on half the battery by accident")
    for row in report.get("rows", []):
        lines.append("    %-34s said %-8s wanted %-8s %s"
                     % (row["probe"], row["model_said"], row["expected"],
                        "ok" if row["correct"] else "WRONG"))
    lines.extend("  note: " + item for item in report.get("limitations", []))
    return "\n".join(lines)
