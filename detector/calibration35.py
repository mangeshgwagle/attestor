#!/usr/bin/env python3
"""Evidence-bounded confidence calibration for Attestor 3.5.

Detector scores are useful for ordering findings, but they are not probabilities
until they have been compared with independently labelled outcomes.  This module
builds deterministic reliability profiles from verified observations and applies
them conservatively.  Sparse or unverifiable evidence produces ``unknown``; it
never produces an optimistic replacement score.

The module performs no network access, model calls, imports of target code, or
filesystem writes.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "attestor.calibration/1.0"
VERSION = "3.5.0"
DEFAULT_BINS = 10
DEFAULT_MIN_SAMPLES = 20
MAX_OBSERVATIONS = 200_000
MAX_STRATA = 10_000


class CalibrationError(ValueError):
    """Raised when a calibration profile or argument cannot be trusted."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_text(value: Any, maximum: int = 200) -> str:
    return str(value or "").replace("\x00", "\\0").replace("\r", " ").replace("\n", " ")[:maximum]


def _score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None


def _bin_index(score: float, bins: int) -> int:
    return min(bins - 1, int(score * bins))


def _wilson(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    """Return a bounded Wilson score interval without pretending sparse certainty."""
    if total <= 0:
        return [0.0, 1.0]
    probability = successes / total
    denominator = 1.0 + z * z / total
    centre = probability + z * z / (2.0 * total)
    radius = z * math.sqrt((probability * (1.0 - probability) + z * z / (4.0 * total)) / total)
    return [round(max(0.0, (centre - radius) / denominator), 6),
            round(min(1.0, (centre + radius) / denominator), 6)]


def _normalise_observation(value: Any) -> dict[str, Any] | None:
    if type(value) is not dict or value.get("label_verified") is not True:
        return None
    predicted = _score(value.get("confidence", value.get("predicted")))
    outcome = value.get("outcome", value.get("correct"))
    if predicted is None or type(outcome) is not bool:
        return None
    dataset = _bounded_text(value.get("dataset_id"), 160)
    label_source = _bounded_text(value.get("label_source"), 160)
    if not dataset or not label_source:
        return None
    return {
        "confidence": predicted,
        "outcome": outcome,
        "rule": _bounded_text(value.get("rule"), 160),
        "language": _bounded_text(value.get("language"), 80).lower(),
        "dataset_id": dataset,
        "label_source": label_source,
    }


def _metric_rows(observations: Sequence[Mapping[str, Any]], bins: int,
                 minimum: int) -> dict[str, Any]:
    buckets: list[list[Mapping[str, Any]]] = [[] for _ in range(bins)]
    for row in observations:
        buckets[_bin_index(float(row["confidence"]), bins)].append(row)
    output: list[dict[str, Any]] = []
    weighted_error = 0.0
    brier = 0.0
    for row in observations:
        brier += (float(row["confidence"]) - int(bool(row["outcome"]))) ** 2
    for index, bucket in enumerate(buckets):
        total = len(bucket)
        correct = sum(item["outcome"] is True for item in bucket)
        average = sum(float(item["confidence"]) for item in bucket) / total if total else None
        empirical = correct / total if total else None
        if total:
            weighted_error += total * abs(float(average) - float(empirical))
        output.append({
            "index": index,
            "range": [round(index / bins, 6), round((index + 1) / bins, 6)],
            "samples": total,
            "correct": correct,
            "mean_detector_score": round(average, 6) if average is not None else None,
            "empirical_probability": round(empirical, 6) if total >= minimum else None,
            "interval_95": _wilson(correct, total) if total >= minimum else [0.0, 1.0],
            "state": "calibrated" if total >= minimum else "insufficient-evidence",
        })
    count = len(observations)
    return {
        "samples": count,
        "brier_score": round(brier / count, 6) if count else None,
        "expected_calibration_error": round(weighted_error / count, 6) if count else None,
        "bins": output,
    }


def build_profile(observations: Iterable[Mapping[str, Any]], *, bins: int = DEFAULT_BINS,
                  min_samples: int = DEFAULT_MIN_SAMPLES) -> dict[str, Any]:
    """Build a content-addressed calibration profile from verified labels only."""
    if isinstance(bins, bool) or not 2 <= int(bins) <= 50:
        raise CalibrationError("bins must be between 2 and 50")
    if isinstance(min_samples, bool) or not 5 <= int(min_samples) <= 10_000:
        raise CalibrationError("min_samples must be between 5 and 10000")
    bins = int(bins); min_samples = int(min_samples)
    accepted: list[dict[str, Any]] = []
    observed = 0
    for observed, value in enumerate(observations, start=1):
        if observed > MAX_OBSERVATIONS:
            raise CalibrationError("calibration corpus exceeds the bounded observation limit")
        row = _normalise_observation(value)
        if row is not None:
            accepted.append(row)
    accepted.sort(key=lambda item: (
        item["dataset_id"], item["label_source"], item["rule"], item["language"],
        item["confidence"], item["outcome"]))
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in accepted:
        if row["rule"]:
            groups.setdefault("rule:" + row["rule"], []).append(row)
        if row["rule"] and row["language"]:
            groups.setdefault("rule-language:" + row["rule"] + ":" + row["language"], []).append(row)
        if len(groups) > MAX_STRATA:
            raise CalibrationError("calibration corpus contains too many strata")
    body: dict[str, Any] = {
        "schema": SCHEMA, "version": VERSION,
        "policy": {"bins": bins, "min_samples_per_bin": min_samples,
                   "verified_labels_only": True,
                   "sparse_result": "unknown-no-score-replacement"},
        "corpus": {"observed": observed, "accepted": len(accepted),
                   "rejected": max(0, observed - len(accepted)),
                   "sha256": _sha(accepted),
                   "datasets": sorted({row["dataset_id"] for row in accepted}),
                   "label_sources": sorted({row["label_source"] for row in accepted})},
        "global": _metric_rows(accepted, bins, min_samples),
        "strata": {name: _metric_rows(rows, bins, min_samples)
                   for name, rows in sorted(groups.items())},
    }
    body["profile_sha256"] = _sha(body)
    return body


def verify_profile(profile: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(profile) is not dict or profile.get("schema") != SCHEMA:
        return False, ["calibration profile is absent or uses an unsupported schema"]
    digest = profile.get("profile_sha256")
    unsigned = {key: value for key, value in profile.items() if key != "profile_sha256"}
    if not isinstance(digest, str) or digest != _sha(unsigned):
        errors.append("calibration profile digest mismatch")
    policy = profile.get("policy") if type(profile.get("policy")) is dict else {}
    bins = policy.get("bins")
    minimum = policy.get("min_samples_per_bin")
    if type(bins) is not int or not 2 <= bins <= 50:
        errors.append("calibration bin policy is invalid")
    if type(minimum) is not int or not 5 <= minimum <= 10_000:
        errors.append("calibration sample policy is invalid")
    if policy.get("verified_labels_only") is not True:
        errors.append("calibration profile does not require verified labels")
    return not errors, errors


def calibrate_score(score: Any, profile: Mapping[str, Any] | None, *, rule: str = "",
                    language: str = "") -> dict[str, Any]:
    """Return empirical probability evidence, or explicitly abstain."""
    raw = _score(score)
    if raw is None:
        return {"state": "invalid-detector-score", "detector_score": None,
                "calibrated_probability": None, "interval_95": [0.0, 1.0],
                "samples": 0, "basis": "none"}
    valid, errors = verify_profile(profile) if profile is not None else (False, ["profile unavailable"])
    if not valid:
        return {"state": "uncalibrated", "detector_score": raw,
                "calibrated_probability": None, "interval_95": [0.0, 1.0],
                "samples": 0, "basis": "none", "errors": errors}
    if profile is None:  # defensive type/state guard; the invalid branch above normally returns
        raise CalibrationError("verified calibration profile disappeared")
    policy = profile["policy"]
    index = _bin_index(raw, policy["bins"])
    keys = []
    bounded_rule = _bounded_text(rule, 160)
    bounded_language = _bounded_text(language, 80).lower()
    if bounded_rule and bounded_language:
        keys.append("rule-language:" + bounded_rule + ":" + bounded_language)
    if bounded_rule:
        keys.append("rule:" + bounded_rule)
    candidates = [(key, profile.get("strata", {}).get(key)) for key in keys]
    candidates.append(("global", profile.get("global")))
    for basis, metrics in candidates:
        if type(metrics) is not dict or type(metrics.get("bins")) is not list \
                or index >= len(metrics["bins"]):
            continue
        bucket = metrics["bins"][index]
        if type(bucket) is dict and bucket.get("state") == "calibrated" \
                and _score(bucket.get("empirical_probability")) is not None:
            return {"state": "calibrated", "detector_score": raw,
                    "calibrated_probability": float(bucket["empirical_probability"]),
                    "interval_95": list(bucket["interval_95"]),
                    "samples": int(bucket["samples"]), "basis": basis,
                    "profile_sha256": profile["profile_sha256"]}
    return {"state": "insufficient-evidence", "detector_score": raw,
            "calibrated_probability": None, "interval_95": [0.0, 1.0],
            "samples": 0, "basis": "none", "profile_sha256": profile["profile_sha256"]}


def apply_profile(findings: Sequence[Mapping[str, Any]],
                  profile: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Attach calibration evidence and replace confidence only when supported."""
    output: list[dict[str, Any]] = []
    for value in findings:
        row = dict(value)
        evidence = calibrate_score(row.get("confidence"), profile,
                                   rule=str(row.get("rule", "")),
                                   language=str(row.get("language", "")))
        row["confidence_calibration"] = evidence
        if evidence["state"] == "calibrated":
            row["detector_score"] = row.get("confidence")
            row["confidence"] = evidence["calibrated_probability"]
            row["confidence_basis"] = "empirical-verified-labels"
        else:
            row["confidence_basis"] = "detector-score-not-empirical-probability"
        output.append(row)
    return output
