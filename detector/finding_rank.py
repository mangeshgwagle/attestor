#!/usr/bin/env python3
"""Deterministic review ordering for Attestor findings.

A scan can return thousands of observations that adjudication correctly labels
``insufficient``; the reviewer still has to start somewhere.  This module scores
that starting order.  It is a review convenience and nothing else.

What it does not do: it never creates, removes, promotes, suppresses, or
reclassifies a finding, never satisfies an authorization or repair permission,
never inspects a target, never executes code, and never contacts a network.  A
low rank is not evidence that a finding is safe, and ranking does not change the
coverage gaps the scan already reported.

Scores are computed in integer fixed point (0..10000).  Attestor runs on aarch64,
armv7l, and x86-64, and integer arithmetic is the only way the same finding set
orders identically on all of them.  There is no floating-point accumulation
anywhere in the scoring path.

Two regimes are reported and never conflated:

``prior``
    Weights derived from rule metadata that a human assigned.  This orders
    findings; it is not a measured probability and is not presented as one.
``calibrated``
    ``calibration35`` matched an empirical reliability bin built from verified
    labelled outcomes.  Only this regime carries a probability.

The weight table is content-addressed, so a report can record which exact
ordering policy produced it.  See ``MODEL_INTEGRATION_4.1.4.md`` for the
boundary this module is required to respect.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

import confidence

SCHEMA = "attestor.finding-rank/1.0"
VERSION = "4.1.4"
MAX_FINDINGS = 20_000
SCALE = 10_000

PRIOR = "prior"
CALIBRATED = "calibrated"
REGIMES = frozenset({PRIOR, CALIBRATED})

# Every weight is an integer in fixed-point units of 1/10000.  The table is
# hashed as the ordering policy identity, so a changed weight is visible in the
# report rather than silently reordering someone's review queue.
SEVERITY_WEIGHT = {
    "CRITICAL": 4000,
    "HIGH": 3200,
    "MEDIUM": 1800,
    "LOW": 800,
    "INFO": 200,
}
EVIDENCE_WEIGHT = {
    "bound": 1600,
    "observed": 1200,
    "derived": 700,
    "inferred": 200,
}
ADJUDICATION_WEIGHT = {
    "supported": 2000,
    "insufficient": 400,
    "contested": 0,
}
BAND_WEIGHT = {
    "high": 1200,
    "medium": 600,
    "low": 150,
}
# Curated rule sets already maintained in confidence.py.
HIGH_SIGNAL_BONUS = 900
SECURITY_BONUS = 500
LOW_SIGNAL_PENALTY = 700
# exploitability_score is 0..100; contribute at most this much.
EXPLOITABILITY_MAX = 1000


class FindingRankError(ValueError):
    """The supplied findings or calibration input is unusable."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _policy() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "scale": SCALE,
        "severity": SEVERITY_WEIGHT,
        "evidence_state": EVIDENCE_WEIGHT,
        "adjudication": ADJUDICATION_WEIGHT,
        "exploitability_band": BAND_WEIGHT,
        "high_signal_bonus": HIGH_SIGNAL_BONUS,
        "security_bonus": SECURITY_BONUS,
        "low_signal_penalty": LOW_SIGNAL_PENALTY,
        "exploitability_max": EXPLOITABILITY_MAX,
    }


POLICY = _policy()
POLICY_SHA256 = _sha(POLICY)


def _text(value: Any, maximum: int = 160) -> str:
    return value[:maximum] if type(value) is str else ""


def _bounded_int(value: Any, low: int, high: int) -> int:
    """Accept only an exact integer; a float score is not trusted to be stable."""
    if type(value) is not int or isinstance(value, bool):
        return low
    return low if value < low else (high if value > high else value)


def _prior_score(finding: Mapping[str, Any]) -> tuple[int, list[str]]:
    """Integer prior in 0..SCALE, with the reasons that produced it."""
    rule = _text(finding.get("rule"))
    severity = _text(finding.get("severity"), 16).upper()
    reasons: list[str] = []
    total = 0

    weight = SEVERITY_WEIGHT.get(severity)
    if weight is None:
        reasons.append("unknown-severity")
        weight = SEVERITY_WEIGHT["LOW"]
    else:
        reasons.append("severity:" + severity.lower())
    total += weight

    state = _text(finding.get("evidence_state"), 32).lower()
    if state in EVIDENCE_WEIGHT:
        total += EVIDENCE_WEIGHT[state]
        reasons.append("evidence:" + state)
    else:
        total += EVIDENCE_WEIGHT["inferred"]
        reasons.append("evidence:unrecognised-treated-as-inferred")

    label = _text(finding.get("adjudication_classification"), 32).lower()
    if label in ADJUDICATION_WEIGHT:
        total += ADJUDICATION_WEIGHT[label]
        reasons.append("adjudication:" + label)

    band = _text(finding.get("exploitability_band"), 16).lower()
    if band in BAND_WEIGHT:
        total += BAND_WEIGHT[band]
        reasons.append("exploitability-band:" + band)

    # 0..100 -> 0..EXPLOITABILITY_MAX with integer division only.
    exploitability = _bounded_int(finding.get("exploitability_score"), 0, 100)
    if exploitability:
        total += (exploitability * EXPLOITABILITY_MAX) // 100
        reasons.append("exploitability-score")

    if rule in confidence.HIGH_SIGNAL_RULES:
        total += HIGH_SIGNAL_BONUS
        reasons.append("curated:high-signal")
    if rule in confidence.SECURITY_RULES:
        total += SECURITY_BONUS
        reasons.append("curated:security")
    if rule in confidence.LOW_SIGNAL_RULES:
        total -= LOW_SIGNAL_PENALTY
        reasons.append("curated:low-signal")

    if total < 0:
        total = 0
    elif total > SCALE:
        total = SCALE
    return total, sorted(reasons)


def _calibrated_score(finding: Mapping[str, Any]) -> int | None:
    """Empirical probability in fixed point, or None when calibration abstained."""
    evidence = finding.get("confidence_calibration")
    if type(evidence) is not dict or evidence.get("state") != "calibrated":
        return None
    probability = evidence.get("calibrated_probability")
    if type(probability) not in (int, float) or isinstance(probability, bool):
        return None
    if not 0.0 <= float(probability) <= 1.0:
        return None
    # Cross the float boundary exactly once, then stay in integers.
    return int(round(float(probability) * SCALE))


def _identity(finding: Mapping[str, Any], position: int) -> tuple[str, str, int, int]:
    """Stable tie-break: identical scores must order identically everywhere."""
    return (_text(finding.get("fingerprint"), 64),
            _text(finding.get("path"), 320),
            _bounded_int(finding.get("line"), 0, 2_000_000_000),
            position)


def rank(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Score findings for review order without altering any of them.

    Returns a descriptor holding one row per finding.  Input order is preserved
    in ``rows``; ``order`` lists row indexes highest-priority first.
    """
    items = list(findings)
    if len(items) > MAX_FINDINGS:
        raise FindingRankError(
            "finding count exceeds the ranking boundary of %d" % MAX_FINDINGS)
    rows: list[dict[str, Any]] = []
    regimes = {PRIOR: 0, CALIBRATED: 0}
    for position, finding in enumerate(items):
        if not isinstance(finding, Mapping):
            raise FindingRankError("every finding must be a mapping")
        prior, reasons = _prior_score(finding)
        calibrated = _calibrated_score(finding)
        if calibrated is None:
            score, regime = prior, PRIOR
        else:
            score, regime = calibrated, CALIBRATED
            reasons = sorted(reasons + ["calibration:empirical-bin"])
        regimes[regime] += 1
        rows.append({
            "position": position,
            "fingerprint": _text(finding.get("fingerprint"), 64),
            "path": _text(finding.get("path"), 320),
            "line": _bounded_int(finding.get("line"), 0, 2_000_000_000),
            "rule": _text(finding.get("rule")),
            "score": score,
            "scale": SCALE,
            "regime": regime,
            "prior_score": prior,
            "reasons": reasons,
        })
    order = sorted(range(len(rows)),
                  key=lambda index: (-rows[index]["score"],
                                     _identity(items[index], index)))
    for rank_position, index in enumerate(order, start=1):
        rows[index]["review_rank"] = rank_position
    descriptor = {
        "schema": SCHEMA,
        "version": VERSION,
        "policy_sha256": POLICY_SHA256,
        "scale": SCALE,
        "counts": {"findings": len(rows), "prior": regimes[PRIOR],
                   "calibrated": regimes[CALIBRATED]},
        "regime": (CALIBRATED if regimes[PRIOR] == 0 and rows else
                   (PRIOR if regimes[CALIBRATED] == 0 else "mixed")),
        "probability_available": regimes[CALIBRATED] > 0,
        "rows": rows,
        "order": order,
        "limitations": [
            "review ordering only; no finding was added, removed, or reclassified",
            "a low rank is not evidence that a finding is safe",
            "prior-regime scores are ordering weights, not measured probabilities",
        ],
    }
    descriptor["descriptor_sha256"] = _sha(
        {key: value for key, value in descriptor.items()
         if key != "descriptor_sha256"})
    return descriptor


def verify_descriptor(value: Any) -> tuple[bool, list[str]]:
    """Recompute a ranking descriptor's identity and internal consistency."""
    errors: list[str] = []
    if not isinstance(value, Mapping):
        return False, ["descriptor is not a mapping"]
    if value.get("schema") != SCHEMA:
        errors.append("unexpected schema")
    if value.get("policy_sha256") != POLICY_SHA256:
        errors.append("ranking policy identity does not match this build")
    rows = value.get("rows")
    order = value.get("order")
    if type(rows) is not list or type(order) is not list:
        return False, errors + ["rows and order must both be lists"]
    if len(order) != len(rows) or sorted(order) != list(range(len(rows))):
        errors.append("order is not a permutation of rows")
    else:
        previous: int | None = None
        for index in order:
            row = rows[index]
            if type(row) is not dict or type(row.get("score")) is not int:
                errors.append("row score is missing or not an integer")
                break
            if previous is not None and row["score"] > previous:
                errors.append("order is not sorted by descending score")
                break
            previous = row["score"]
    recomputed = _sha({key: item for key, item in value.items()
                       if key != "descriptor_sha256"})
    if value.get("descriptor_sha256") != recomputed:
        errors.append("descriptor digest does not match its content")
    return not errors, errors


__all__ = [
    "SCHEMA", "VERSION", "POLICY", "POLICY_SHA256", "SCALE",
    "PRIOR", "CALIBRATED", "REGIMES", "MAX_FINDINGS",
    "FindingRankError", "rank", "verify_descriptor",
]
