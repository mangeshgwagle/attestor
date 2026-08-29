#!/usr/bin/env python3
"""Let a model phrase a finding Attestor already made. Never let it judge one.

The distinction this module exists to enforce
---------------------------------------------
Measured, on this machine, with no network: asked whether a reported defect was
real, two local instruct models answered "the report is incorrect" to *every*
probe -- including a use-after-free one of them described accurately in the very
next sentence.  Asked instead to explain a defect presented as established, the
same model produced a correct and useful paragraph.

So the model is given exactly one job: turn a finding Attestor has already decided
into prose a developer can read.  It is never asked whether the finding is
real, because that is the question it demonstrably cannot answer, and it is
never in a position to remove one, because the text it produces is not part of
the payload Truth Guard verifies.

Three enforcement points, in order of how much work they do
-----------------------------------------------------------
1. The prompt states the defect as settled and asks only for explanation.  A
   question that offers the model a verdict will get one.
2. The answer is checked *after* generation.  A model can volunteer "actually
   this is fine" whether or not it was asked; when it does, the text is
   discarded and the model is charged with a violation under
   ``model_audit.record_violation``.  Being helpful is not a defence.
3. ``attach`` puts advisories in an envelope *beside* the report, never inside
   it, and ``verify_separation`` re-derives the report's digest to prove the
   advisory text did not enter it.

Why no model is imported here
-----------------------------
Generation is supplied by the caller as a plain callable.  Attestor imports no
third-party package in any of its modules, and that property is load-bearing
for the no-root Raspberry Pi install; a tensor runtime behind an ``import`` in
this file would end it.  The judge, the contract, and the enforcement are
stdlib.  The model lives outside and is passed in.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable, Mapping, Sequence

import model_audit
import neural_gate

SCHEMA = "attestor.advisory/1.0"
VERSION = "4.1.4"

MAX_ADVISORY_CHARS = 2_000
MAX_CODE_LINES = 200
MAX_RANKED = 500
MAX_WINDOW_LINES = 64
# Only used when an artifact omits `window_lines` entirely; a shipped model
# always carries its own.
FALLBACK_WINDOW_LINES = 12

WITHHELD = "withheld"
ISSUED = "issued"
INFERRED = "inferred"


class AdvisoryError(ValueError):
    """The finding, the model, or the generated text is unusable."""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def _field(finding: Mapping[str, Any], name: str, kinds: tuple) -> Any:
    value = finding.get(name)
    if not isinstance(value, kinds) or (isinstance(value, str) and not value.strip()):
        raise AdvisoryError("finding is missing a usable %r" % name)
    return value


def phrase_prompt(finding: Mapping[str, Any], code: str) -> str:
    """Ask for an explanation of a settled defect. Never for a verdict.

    The wording matters more than anything else here.  "Decide whether this
    report is correct" produced rejection of six findings out of six; this
    wording produced a correct explanation from the same weights.
    """
    rule = _field(finding, "rule", (str,))
    line = _field(finding, "line", (int,))
    message = _field(finding, "message", (str,))
    if not isinstance(code, str) or not code.strip():
        raise AdvisoryError("code must be non-empty text")
    lines = code.splitlines()[:MAX_CODE_LINES]
    body = "\n".join("%4d  %s" % (index + 1, text)
                     for index, text in enumerate(lines))
    return (
        "A verified static analysis has established a defect in this code. "
        "It is not in question and you are not being asked to check it.\n\n"
        "Defect: %s\nLocation: line %d\nWhat the analyser determined: %s\n\n"
        "Write at most four sentences for the developer who wrote this, "
        "explaining what happens at runtime and how to correct it. Describe "
        "only the defect above; do not mention other issues.\n\nCode:\n%s"
        % (rule, line, message, body))


def _denies_the_finding(text: str) -> bool:
    """Did the model volunteer that the defect is not real?

    Phrase-only mode never asks, but a model can answer a question it was not
    asked.  This is the check that catches it.
    """
    return model_audit.classify(text) == model_audit.REJECTED


def make_advisory(finding: Mapping[str, Any], code: str,
                  generate: Callable[[str], str], *, model_id: str,
                  audit_report: Mapping[str, Any] | None = None,
                  ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Produce one advisory, or withhold it and say why.

    `generate` is any callable taking a prompt and returning text.  Everything
    about the model except its output and its name stays outside this module.
    """
    if not isinstance(model_id, str) or not model_id.strip():
        raise AdvisoryError("model_id must be a non-empty string")
    if not callable(generate):
        raise AdvisoryError("generate must be callable")

    base = {
        "schema": SCHEMA,
        "version": VERSION,
        "model_id": model_id,
        "rule": _field(finding, "rule", (str,)),
        "line": _field(finding, "line", (int,)),
        "evidence_state": INFERRED,
        "at": int(time.time()),
        "limitations": [
            "written by a language model from a finding the deterministic "
            "rules had already established; it explains that finding and is "
            "not evidence for or against it",
            "outside the verified report digest, so it is not replayable and "
            "carries no weight in adjudication",
        ],
    }

    # Cleared to *explain*, which is a different clearance from being cleared
    # to decide whether a finding is real.  Passing this does not grant that.
    allowed, why = model_audit.may_speak(audit_report,
                                         role=model_audit.ROLE_PHRASE)
    if not allowed:
        return {**base, "status": WITHHELD, "reason": why, "text": ""}

    standing = model_audit.standing(ledger, model_id)
    if not standing["allowed"]:
        return {**base, "status": WITHHELD,
                "reason": "model withdrawn after %d violations"
                          % standing["violations"], "text": ""}

    try:
        text = generate(phrase_prompt(finding, code))
    except Exception as error:                      # a model failure is not ours
        return {**base, "status": WITHHELD,
                "reason": "generation failed: %s" % str(error)[:200], "text": ""}

    if not isinstance(text, str) or not text.strip():
        return {**base, "status": WITHHELD,
                "reason": "model returned nothing", "text": ""}

    if _denies_the_finding(text):
        # It was told the defect was settled and disputed it anyway.  The text
        # is dropped and the model is charged; three of these withdraw it.
        return {**base, "status": WITHHELD,
                "reason": "model disputed a verified finding",
                "violation": "denied %s at line %d" % (base["rule"], base["line"]),
                "text": ""}

    return {**base, "status": ISSUED, "text": text.strip()[:MAX_ADVISORY_CHARS]}


def charge_violations(ledger: Mapping[str, Any] | None,
                      advisories: Sequence[Mapping[str, Any]]
                      ) -> dict[str, Any] | None:
    """Record every advisory that was withheld for disputing a finding."""
    updated = ledger
    for item in advisories:
        if item.get("violation"):
            updated = model_audit.record_violation(
                updated, item["model_id"], item["violation"])
    return updated


def window_for(source: str, line: int, size: int) -> str:
    """The `size` lines around a finding, centred on it.

    The width comes from the model artifact, not from this module.  The gate
    ships trained on twelve-line windows while the corpus builder still
    defaults to four; handing a twelve-line model a four-line window is a
    train/serve mismatch that never raises, it just quietly scores worse.
    Reading the declared value is the only thing that keeps them in step.
    """
    lines = source.splitlines()
    if not lines:
        return ""
    index = max(0, min(line - 1, len(lines) - 1))
    start = max(0, index - size // 2)
    return "\n".join(lines[start:start + size])


def rank(findings: Sequence[Mapping[str, Any]], source: str,
         gate: Mapping[str, Any], *,
         limit: int = MAX_RANKED) -> list[dict[str, Any]]:
    """Score the code around each finding, for review order only.

    This does not decide anything.  The score is `inferred` evidence about
    where a reviewer might look first, it is returned separately from the
    findings rather than written into them, and `attach` keeps it outside the
    digest.  A low score is not a reason to ignore a finding and never becomes
    one -- the deterministic rules already decided that it is real.
    """
    if not isinstance(source, str):
        raise AdvisoryError("source must be text")
    resolved = neural_gate.load_model(gate)
    size = resolved.get("window_lines", FALLBACK_WINDOW_LINES)
    if not isinstance(size, int) or isinstance(size, bool) or \
            not 1 <= size <= MAX_WINDOW_LINES:
        raise AdvisoryError("model declares an unusable window_lines")
    scored: list[dict[str, Any]] = []
    for finding in list(findings)[:limit]:
        rule = _field(finding, "rule", (str,))
        line = _field(finding, "line", (int,))
        result = neural_gate.infer(window_for(source, line, size), gate)
        scored.append({
            "schema": SCHEMA,
            "rule": rule,
            "line": line,
            "score": result["score"],
            "scale": result["scale"],
            "window_lines": size,
            "evidence_state": INFERRED,
            "model_sha256": result["model_sha256"],
        })
    scored.sort(key=lambda row: (-row["score"], row["line"]))
    return scored


def attach(report: Mapping[str, Any],
           advisories: Sequence[Mapping[str, Any]],
           rankings: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Envelope the report with advisories beside it, never inside it.

    The report object is passed through untouched.  That is the whole point:
    `verify_report` must still recompute the same digest over the same bytes
    it would have seen had no model ever run.
    """
    if not isinstance(report, Mapping):
        raise AdvisoryError("report must be a mapping")
    rows = list(advisories)
    for item in rows:
        if item.get("schema") != SCHEMA:
            raise AdvisoryError("not an advisory produced by this module")
    issued = [item for item in rows if item.get("status") == ISSUED]
    return {
        "schema": "attestor.advisory-envelope/1.0",
        "version": VERSION,
        "report": report,
        "report_sha256": _sha(report),
        "advisory": {
            "count": len(rows),
            "issued": len(issued),
            "withheld": len(rows) - len(issued),
            "items": rows,
            "ranking": list(rankings),
        },
        "boundary": [
            "everything under 'advisory' is outside the verified payload",
            "no advisory created, removed, promoted or suppressed a finding",
            "the ranking orders review; it does not weigh whether a finding "
            "is real, and a low score is not a reason to skip one",
        ],
    }


def verify_separation(envelope: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """Prove the advisory text never entered the verified report."""
    problems: list[str] = []
    if not isinstance(envelope, Mapping) or \
            envelope.get("schema") != "attestor.advisory-envelope/1.0":
        return False, ["not an advisory envelope"]
    report = envelope.get("report")
    if not isinstance(report, Mapping):
        return False, ["envelope carries no report"]
    if _sha(report) != envelope.get("report_sha256"):
        problems.append("report digest does not match the report")
    rendered = json.dumps(report, sort_keys=True, default=str)
    for row in envelope.get("advisory", {}).get("ranking", []):
        if row.get("evidence_state") != INFERRED:
            problems.append("a ranking row for %s is not marked inferred"
                            % row.get("rule"))
    for item in envelope.get("advisory", {}).get("items", []):
        text = item.get("text") or ""
        if text and text in rendered:
            problems.append("advisory text for %s appears inside the report"
                            % item.get("rule"))
        if item.get("schema") != SCHEMA:
            problems.append("foreign object under 'advisory'")
    for key in ("advisory", "advisories", "explanation", "model_text",
                "ranking", "gate_score"):
        if key in report:
            problems.append("report carries a %r key" % key)
    return not problems, problems


def render(envelope: Mapping[str, Any]) -> str:
    advisory = envelope.get("advisory", {})
    lines = ["Advisory (outside the verified report): %d issued, %d withheld"
             % (advisory.get("issued", 0), advisory.get("withheld", 0))]
    for item in advisory.get("items", []):
        head = "  %s line %s [%s]" % (item.get("rule"), item.get("line"),
                                      item.get("status"))
        lines.append(head)
        if item.get("status") == ISSUED:
            lines.append("    " + item.get("text", "").replace("\n", "\n    "))
        else:
            lines.append("    withheld: %s" % item.get("reason"))
    lines.extend("  note: " + item for item in envelope.get("boundary", []))
    return "\n".join(lines)
