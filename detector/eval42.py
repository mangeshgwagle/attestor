#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import random
from typing import Any, Mapping, Sequence

VERSION = "4.3"
SCHEMA = "attestor-eval/4.3"

class EvalError(ValueError):
    pass

def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()

def remediation_correctness(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if not results:
        raise EvalError("no remediation results supplied")
    total = len(results)
    correct = 0
    no_regression = 0
    for r in results:
        if not isinstance(r, Mapping):
            raise EvalError("result must be a mapping")
        fixed = r.get("fixed") is True or r.get("rescan_clean") is True or r.get("verified") is True
        regressed = r.get("regression") is True or r.get("new_failures") or r.get("introduced_regression") is True
        if fixed and not regressed:
            correct += 1
        if not regressed:
            no_regression += 1
    rate = correct / total
    return {"total": total, "correct": correct, "no_regression": no_regression, "correctness_rate": rate, "passes_threshold": rate >= 0.80, "threshold": 0.80}

def triage_accuracy(predicted: Sequence[Any], ground_truth: Sequence[Any]) -> dict[str, Any]:
    if len(predicted) != len(ground_truth):
        raise EvalError("predicted and ground_truth must have same length")
    if not predicted:
        raise EvalError("empty triage evaluation")
    correct = sum(1 for p, g in zip(predicted, ground_truth) if p == g)
    accuracy = correct / len(predicted)
    return {"total": len(predicted), "correct": correct, "accuracy": accuracy}

def hallucination_rate(claims: Sequence[Mapping[str, Any]], evidence_report: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(claims, (list, tuple)):
        raise EvalError("claims must be a list")
    total = len(claims)
    if total == 0:
        return {"total": 0, "hallucinated": 0, "rate": 0.0, "passes_threshold": True, "threshold": 0.01}
    hallucinated = 0
    checked = 0
    try:
        import truth_guard as tg  # type: ignore
        has_tg = True
    except Exception:
        has_tg = False
    if has_tg and isinstance(evidence_report, Mapping):
        try:
            index = tg.EvidenceIndex(dict(evidence_report))  # type: ignore
            numeric, lookup = tg._numeric_checks(index)  # type: ignore
            audit_contra, audit = tg._evidence_audit(index, numeric, tg._report_integrity(index))  # type: ignore
            for raw in claims:
                if not isinstance(raw, Mapping):
                    hallucinated += 1
                    checked += 1
                    continue
                verdict = tg._evaluate_claim(dict(raw), index, lookup, audit)  # type: ignore
                checked += 1
                if verdict.get("state") in ("unknown", "refuted"):
                    if raw.get("presented_as_fact") is True or raw.get("kind") in ("statement", "value", "finding"):
                        hallucinated += 1
                    elif verdict.get("state") == "refuted":
                        hallucinated += 1
            rate = hallucinated / checked if checked else 0.0
            return {"total": total, "checked": checked, "hallucinated": hallucinated, "rate": rate, "passes_threshold": rate < 0.01, "threshold": 0.01, "via": "truth_guard"}
        except Exception:
            pass
    for raw in claims:
        if not isinstance(raw, Mapping):
            hallucinated += 1
            continue
        supported = raw.get("supported") is True or raw.get("evidence_refs") or raw.get("grounded") is True
        if not supported:
            if raw.get("state") in ("unknown", "refuted"):
                hallucinated += 1
            elif raw.get("accepted") is False:
                hallucinated += 1
            elif raw.get("kind") == "statement" and not raw.get("evidence_path"):
                hallucinated += 1
    rate = hallucinated / total if total else 0.0
    return {"total": total, "hallucinated": hallucinated, "rate": rate, "passes_threshold": rate < 0.01, "threshold": 0.01, "via": "heuristic"}

def held_out_split(corpus: Sequence[Any], holdout_ratio: float = 0.2, seed: int = 42) -> dict[str, Any]:
    if not 0 < holdout_ratio < 1:
        raise EvalError("holdout_ratio must be between 0 and 1")
    if not corpus:
        raise EvalError("corpus is empty")
    n = len(corpus)
    holdout_n = max(1, int(n * holdout_ratio))
    train_n = n - holdout_n
    rng = random.Random(seed)
    indices = list(range(n))
    rng.shuffle(indices)
    train_idx = set(indices[:train_n])
    holdout_idx = set(indices[train_n:])
    train = [corpus[i] for i in sorted(train_idx)]
    held_out = [corpus[i] for i in sorted(holdout_idx)]
    overlap = set(map(_digest, train)) & set(map(_digest, held_out))
    return {"train": train, "held_out": held_out, "train_size": len(train), "held_out_size": len(held_out), "seed": seed, "overlap": len(overlap), "clean_split": len(overlap) == 0}

def shuffled_label_control(labels: Sequence[Any], predictions: Sequence[Any] | None = None, seed: int = 123) -> dict[str, Any]:
    if not labels:
        raise EvalError("labels is empty")
    n = len(labels)
    if predictions is not None and len(predictions) != n:
        raise EvalError("predictions length must match labels")
    rng = random.Random(seed)
    shuffled = list(labels)
    rng.shuffle(shuffled)
    if predictions is None:
        majority = max(set(labels), key=lambda v: labels.count(v)) if labels else None
        predictions = [majority] * n
    true_acc = sum(1 for p, g in zip(predictions, labels) if p == g) / n if n else 0.0
    shuffled_acc = sum(1 for p, g in zip(predictions, shuffled) if p == g) / n if n else 0.0
    label_values = set(labels)
    chance = 1.0 / len(label_values) if len(label_values) > 1 else 1.0
    leakage = shuffled_acc > chance + 0.1
    return {"n": n, "chance": chance, "true_accuracy": true_acc, "shuffled_accuracy": shuffled_acc, "leakage_detected": leakage, "seed": seed}

def evaluate_suite(*, remediation_results: Sequence[Mapping[str, Any]] | None = None, triage_predicted: Sequence[Any] | None = None, triage_truth: Sequence[Any] | None = None, claims: Sequence[Mapping[str, Any]] | None = None, evidence_report: Mapping[str, Any] | None = None, corpus: Sequence[Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"version": VERSION, "schema": SCHEMA}
    if remediation_results is not None:
        out["remediation"] = remediation_correctness(remediation_results)
    if triage_predicted is not None and triage_truth is not None:
        out["triage"] = triage_accuracy(triage_predicted, triage_truth)
    if claims is not None:
        out["hallucination"] = hallucination_rate(claims, evidence_report)
    if corpus is not None:
        out["held_out"] = held_out_split(corpus)
        labels = [c.get("label") if isinstance(c, Mapping) else c for c in corpus]
        if any(v is not None for v in labels):
            clean_labels = [v for v in labels if v is not None]
            out["shuffled_control"] = shuffled_label_control(clean_labels)
    overall = True
    if "remediation" in out and not out["remediation"]["passes_threshold"]:
        overall = False
    if "hallucination" in out and not out["hallucination"]["passes_threshold"]:
        overall = False
    out["overall_pass"] = overall
    return out
