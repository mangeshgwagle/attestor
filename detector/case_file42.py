#!/usr/bin/env python3
"""The evidence spine: one finding, carried across the research workflow.

Why this exists
---------------
Attestor has strong individual engines -- taint, attack surface, remediation,
truth guard -- and no way to carry a conclusion from one to the next. Each
engine seals its own report and stops. A reviewer who wants to know *why* a
finding was judged reachable, what fix was proposed, and whether the regression
test actually proved anything has to reassemble that by hand.

A case file is that missing spine. It is one finding, plus an append-only,
hash-chained record of what each stage of the workflow established about it.

Three properties are the point, and all three are mechanical:

**The chain is tamper-evident.** Each entry commits to the digest of the entry
before it, so editing or deleting a stage in the middle breaks `verify` at that
entry rather than passing silently. Evidence that can be quietly rewritten is
not evidence.

**Claims are separated from evidence.** Every entry records a `basis`: either
`measured` (a tool produced it) or `hypothesis` (a model proposed it). The two
are never merged. A reader can always tell which conclusions are load-bearing.

**A regression test must fail before the fix.** This is the honesty gate. A
generated test that passes on the unpatched tree proves nothing at all, and it
is the most common way an automated fix pipeline fools itself. `append` refuses
a `regression` entry whose evidence does not record an observed pre-fix
failure -- so the pipeline cannot claim a fix is proven when it isn't.

The module holds no credentials, runs nothing, opens no socket, and reads no
file: it is given values and returns values. Secret-shaped evidence is redacted
on the way in, because a case file is meant to be handed to somebody.
"""
from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import re
from typing import Any, Iterable, Mapping

VERSION = "4.2"
CASE_SCHEMA = "attestor-case-file/4.2"
ENTRY_SCHEMA = "attestor-case-entry/4.2"

#: The workflow stages, in their canonical order.
STAGES = (
    "discovery",
    "validation",
    "severity",
    "exploitability",
    "root_cause",
    "remediation",
    "regression",
    "documentation",
)

#: How a stage knows what it claims.
MEASURED = "measured"
HYPOTHESIS = "hypothesis"
BASES = (MEASURED, HYPOTHESIS)

MAX_TEXT = 4_096
MAX_EVIDENCE_KEYS = 64
MAX_ENTRIES = 512
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
GENESIS = "0" * 64

_SECRET_KEY = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|credential|authorization|private[_-]?key)")
_SECRET_VALUE = re.compile(
    r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})")
REDACTED = "***redacted***"


class CaseFileError(ValueError):
    """A case file was malformed. Raised instead of accepting bad evidence."""


# --------------------------------------------------------------------------- #
# canonical form
# --------------------------------------------------------------------------- #

def canonical_json(value: Any) -> str:
    """One byte-form per value, so digests are comparable across machines."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


# --------------------------------------------------------------------------- #
# validation helpers -- every one fails closed
# --------------------------------------------------------------------------- #

def _text(value: Any, label: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise CaseFileError("%s must be a string" % label)
    stripped = value.strip()
    if not stripped:
        raise CaseFileError("%s must not be empty" % label)
    if len(stripped) > maximum:
        raise CaseFileError("%s exceeds %d characters" % (label, maximum))
    if any(ord(ch) < 32 and ch not in "\t\n" for ch in stripped):
        raise CaseFileError("%s contains control characters" % label)
    return stripped


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label, maximum=128)
    if not ID_PATTERN.fullmatch(text):
        raise CaseFileError("%s is not a valid identifier" % label)
    return text


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
        raise CaseFileError("%s must be a sha256 hex digest" % label)
    return value


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def _redact(value: Any, key_hint: str = "") -> Any:
    """Drop secret-shaped evidence. A case file is meant to be shared."""
    if isinstance(value, Mapping):
        return {str(k): _redact(v, str(k)) for k, v in list(value.items())[:MAX_EVIDENCE_KEYS]}
    if isinstance(value, (list, tuple)):
        return [_redact(v, key_hint) for v in list(value)[:MAX_EVIDENCE_KEYS]]
    if isinstance(value, str):
        if _SECRET_KEY.search(key_hint) or _SECRET_VALUE.search(value):
            return REDACTED
        return value[:MAX_TEXT]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CaseFileError("evidence contains a non-finite number")
        return value
    raise CaseFileError("evidence value of type %s is not storable" % type(value).__name__)


def _evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CaseFileError("evidence must be a mapping")
    if len(value) > MAX_EVIDENCE_KEYS:
        raise CaseFileError("evidence has more than %d keys" % MAX_EVIDENCE_KEYS)
    return {str(k): _redact(v, str(k)) for k, v in value.items()}


# --------------------------------------------------------------------------- #
# the chain
# --------------------------------------------------------------------------- #

def _entry_digest(body: Mapping[str, Any], previous: str) -> str:
    return hashlib.sha256(
        (canonical_json(body) + "|" + previous).encode("ascii")).hexdigest()


def open_case(*, subject_path: str, subject_sha256: str, rule: str,
              summary: str, opened_by: str = "attestor",
              now: str | None = None) -> dict[str, Any]:
    """Start a case file for one finding, bound to the exact bytes it was found in."""
    case = {
        "schema": CASE_SCHEMA,
        "version": VERSION,
        "case_id": digest_json({
            "path": _text(subject_path, "subject_path"),
            "sha256": _digest(subject_sha256, "subject_sha256"),
            "rule": _identifier(rule, "rule"),
        })[:32],
        "subject": {
            "path": _text(subject_path, "subject_path"),
            "sha256": _digest(subject_sha256, "subject_sha256"),
        },
        "rule": _identifier(rule, "rule"),
        "summary": _text(summary, "summary"),
        "opened_by": _identifier(opened_by, "opened_by"),
        "opened_at": now or _utc_now(),
        "entries": [],
    }
    return case


def append(case: Mapping[str, Any], *, stage: str, basis: str, summary: str,
           evidence: Mapping[str, Any] | None = None,
           recorded_by: str = "attestor",
           now: str | None = None) -> dict[str, Any]:
    """Append one stage's finding. Returns a new case; the input is not mutated.

    The regression stage is gated: its evidence must record that the test was
    observed to fail before the fix was applied. A test that passes on the
    unpatched tree demonstrates nothing, and accepting one would let the
    pipeline certify a fix it never proved.
    """
    if not isinstance(case, Mapping) or case.get("schema") != CASE_SCHEMA:
        raise CaseFileError("not a case file")
    if stage not in STAGES:
        raise CaseFileError("unknown stage %r" % (stage,))
    if basis not in BASES:
        raise CaseFileError("basis must be one of %s" % (BASES,))

    entries = list(case.get("entries") or [])
    if len(entries) >= MAX_ENTRIES:
        raise CaseFileError("case file is full")

    payload = _evidence(evidence or {})

    if stage == "regression":
        if payload.get("fails_before_fix") is not True:
            raise CaseFileError(
                "a regression entry must record fails_before_fix=True: a test "
                "that does not fail on the unpatched tree proves nothing")
        if basis != MEASURED:
            raise CaseFileError("a regression entry must be measured, not hypothesised")

    previous = entries[-1]["entry_sha256"] if entries else GENESIS
    body = {
        "schema": ENTRY_SCHEMA,
        "stage": stage,
        "basis": basis,
        "summary": _text(summary, "summary"),
        "evidence": payload,
        "recorded_by": _identifier(recorded_by, "recorded_by"),
        "recorded_at": now or _utc_now(),
        "index": len(entries),
        "prev_sha256": previous,
    }
    entry = dict(body)
    entry["entry_sha256"] = _entry_digest(body, previous)

    updated = {k: v for k, v in case.items() if k != "entries"}
    updated["entries"] = entries + [entry]
    return updated


def verify(case: Any) -> tuple[bool, list[str]]:
    """Re-derive the chain. Returns (ok, problems); never raises on hostile input."""
    problems: list[str] = []
    try:
        if not isinstance(case, Mapping) or case.get("schema") != CASE_SCHEMA:
            return False, ["not a case file"]
        entries = case.get("entries")
        if not isinstance(entries, list):
            return False, ["entries is not a list"]

        previous = GENESIS
        for position, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                problems.append("entry %d is not a mapping" % position)
                break
            if entry.get("index") != position:
                problems.append("entry %d has index %r" % (position, entry.get("index")))
            if entry.get("prev_sha256") != previous:
                problems.append("entry %d does not chain to its predecessor" % position)
            body = {k: v for k, v in entry.items() if k != "entry_sha256"}
            expected = _entry_digest(body, entry.get("prev_sha256", ""))
            if entry.get("entry_sha256") != expected:
                problems.append("entry %d digest does not match its content" % position)
            if entry.get("stage") == "regression" and \
                    (entry.get("evidence") or {}).get("fails_before_fix") is not True:
                problems.append("entry %d is a regression without a pre-fix failure" % position)
            previous = entry.get("entry_sha256", "")
        return (not problems), problems
    except Exception as exc:  # noqa: BLE001 - hostile input must not escape as a crash
        return False, ["verification failed closed (%s)" % type(exc).__name__]


# --------------------------------------------------------------------------- #
# reading a case
# --------------------------------------------------------------------------- #

def stages_completed(case: Mapping[str, Any]) -> tuple[str, ...]:
    seen = [e.get("stage") for e in (case.get("entries") or [])]
    return tuple(s for s in STAGES if s in seen)


def stages_missing(case: Mapping[str, Any]) -> tuple[str, ...]:
    done = set(stages_completed(case))
    return tuple(s for s in STAGES if s not in done)


def measured_only(case: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """The entries a conclusion may rest on. Hypotheses are excluded."""
    return tuple(e for e in (case.get("entries") or [])
                 if e.get("basis") == MEASURED)


def is_proven(case: Mapping[str, Any]) -> bool:
    """True only when a fix exists and a regression test measured it.

    Deliberately strict: remediation without a proven regression test is a
    proposal, not a proof, and this function is what a report should consult
    before it uses the word 'fixed'.
    """
    ok, _ = verify(case)
    if not ok:
        return False
    done = set(stages_completed(case))
    if not {"discovery", "remediation", "regression"} <= done:
        return False
    return any(e.get("stage") == "regression" and e.get("basis") == MEASURED
               for e in (case.get("entries") or []))


def render(case: Mapping[str, Any]) -> str:
    """A short human summary. Unknowns are stated, not hidden."""
    ok, problems = verify(case)
    lines = [
        "case %s  rule=%s" % (case.get("case_id", "?"), case.get("rule", "?")),
        "  subject : %s" % (case.get("subject", {}) or {}).get("path", "?"),
        "  summary : %s" % case.get("summary", ""),
        "  chain   : %s" % ("intact" if ok else "BROKEN -- " + "; ".join(problems)),
        "  proven  : %s" % ("yes" if is_proven(case) else "no"),
    ]
    for entry in case.get("entries") or []:
        lines.append("  [%d] %-14s %-10s %s" % (
            entry.get("index", -1), entry.get("stage", "?"),
            entry.get("basis", "?"), entry.get("summary", "")))
    missing = stages_missing(case)
    if missing:
        lines.append("  not established: " + ", ".join(missing))
    return "\n".join(lines)
