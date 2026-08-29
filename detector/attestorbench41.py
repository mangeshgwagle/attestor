#!/usr/bin/env python3
"""AttestorBench 4.1 held-out evaluation schema and metric calculator.

This module never manufactures benchmark cases or model answers.  It validates
an operator-supplied held-out corpus and lane records, records source-overlap
hashes, and computes observed metrics for Attestor-only, model-only, and hybrid
lanes.  Stochastic lanes disclose when repeated samples were not supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import statistics
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


VERSION = "4.1.3"
CORPUS_SCHEMA = "attestor.benchmark-corpus/4.1"
RESULT_SCHEMA = "attestor.benchmark-results/4.1"
REPORT_SCHEMA = "attestor.benchmark-report/4.1"
LANES = ("attestor-only", "model-only", "hybrid")
MAX_CASES = 100_000
MAX_RECORDS = 1_000_000
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_REFERENCE_HASHES = 10_000
MAX_EXPECTED_RULES = 10_000
MAX_FINDING_RULES = 20_000
RELEASE_MIN_CASES = 1_000
RECORD_STATUSES = frozenset({"completed", "timeout", "failed", "cancelled", "skipped"})


class AttestorBenchError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _load_json(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size > MAX_MANIFEST_BYTES:
        raise AttestorBenchError("benchmark manifest is missing or exceeds 64 MiB")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AttestorBenchError("benchmark manifest is not valid JSON") from exc


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _real_local_file(base: Path, raw: Any) -> tuple[Path, str]:
    if not isinstance(raw, str) or not raw or len(raw) > 32_768 or "\x00" in raw:
        raise AttestorBenchError("corpus source must be a non-empty bounded path")
    lexical = Path(os.path.abspath(os.fspath(base / raw)))
    try:
        relative = lexical.relative_to(base)
    except ValueError as exc:
        raise AttestorBenchError("corpus source escapes its manifest directory") from exc
    current = base
    for part in relative.parts:
        current = current / part
        if _is_link_or_reparse(current):
            raise AttestorBenchError("corpus source may not traverse a link or reparse point")
    try:
        resolved = lexical.resolve(strict=True)
        portable = resolved.relative_to(base).as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise AttestorBenchError("corpus source must be a regular local file") from exc
    if not resolved.is_file() or _is_link_or_reparse(resolved):
        raise AttestorBenchError("corpus source must be a regular local file")
    return resolved, portable


def load_corpus(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path).expanduser().resolve()
    value = _load_json(manifest_path)
    if not isinstance(value, dict) or value.get("schema") != CORPUS_SCHEMA:
        raise AttestorBenchError("unsupported benchmark corpus schema")
    rows = value.get("cases")
    if not isinstance(rows, list) or not rows or len(rows) > MAX_CASES:
        raise AttestorBenchError("held-out corpus must contain a bounded non-empty case list")
    cases, identities = [], set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            raise AttestorBenchError("corpus case must be an object")
        case_id = raw.get("id")
        if not isinstance(case_id, str) or not case_id or len(case_id) > 300 or case_id in identities:
            raise AttestorBenchError("corpus case ids must be unique and non-empty")
        identities.add(case_id)
        if raw.get("split") != "held-out":
            raise AttestorBenchError("every evaluated corpus case must declare split=held-out")
        source_path, source_label = _real_local_file(manifest_path.parent, raw.get("source"))
        source = source_path.read_bytes()
        if len(source) > MAX_SOURCE_BYTES:
            raise AttestorBenchError("corpus source exceeds 8 MiB")
        label = raw.get("label")
        if type(label) is not bool:
            raise AttestorBenchError("corpus labels must be booleans")
        expected = raw.get("expected_rules", [])
        if (not isinstance(expected, list) or len(expected) > MAX_EXPECTED_RULES or
                any(not isinstance(item, str) or not item or len(item) > 300 for item in expected)):
            raise AttestorBenchError("expected_rules must be at most 10,000 bounded non-empty strings")
        cases.append({"id": case_id, "split": "held-out", "label": label,
                      "source": source_label,
                      "source_sha256": _sha(source), "bytes": len(source),
                      "expected_rules": sorted(set(expected))})
    body = {"schema": CORPUS_SCHEMA, "version": VERSION,
            "name": str(value.get("name", manifest_path.stem))[:300], "cases": cases}
    body["corpus_sha256"] = _sha(body)
    return body


def load_records(path: str | Path) -> list[dict[str, Any]]:
    value = _load_json(Path(path).expanduser().resolve())
    if not isinstance(value, dict) or value.get("schema") != RESULT_SCHEMA:
        raise AttestorBenchError("unsupported benchmark result schema")
    rows = value.get("records")
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise AttestorBenchError("benchmark records must be a bounded list")
    output = []
    seen = set()
    for raw in rows:
        if not isinstance(raw, dict):
            raise AttestorBenchError("benchmark record must be an object")
        case_id, lane = raw.get("case_id"), raw.get("lane")
        sample = raw.get("sample")
        if (not isinstance(case_id, str) or not case_id or len(case_id) > 300 or
                lane not in LANES or type(sample) is not int or sample < 0):
            raise AttestorBenchError("record case, lane, or sample is invalid")
        identity = (case_id, lane, sample)
        if identity in seen:
            raise AttestorBenchError("duplicate case/lane/sample record")
        seen.add(identity)
        probability = raw.get("probability")
        if not isinstance(probability, (int, float)) or isinstance(probability, bool) \
                or not math.isfinite(float(probability)) or not 0 <= float(probability) <= 1:
            raise AttestorBenchError("record probability must be finite and between zero and one")
        predicted = raw.get("predicted_positive")
        if type(predicted) is not bool:
            raise AttestorBenchError("predicted_positive must be boolean")
        numeric = {}
        for name in ("latency_ms", "peak_memory_bytes", "cost_usd"):
            item = raw.get(name, 0)
            if not isinstance(item, (int, float)) or isinstance(item, bool) \
                    or not math.isfinite(float(item)) or float(item) < 0:
                raise AttestorBenchError("%s must be a finite non-negative number" % name)
            numeric[name] = float(item)
        status = str(raw.get("status", "completed"))[:80].lower()
        if status not in RECORD_STATUSES:
            raise AttestorBenchError("record status is unsupported")
        finding_rules = raw.get("finding_rules", [])
        if (not isinstance(finding_rules, list) or len(finding_rules) > MAX_FINDING_RULES or
                any(not isinstance(item, str) or not item or len(item) > 300
                    for item in finding_rules)):
            raise AttestorBenchError("finding_rules must be at most 20,000 bounded non-empty strings")
        output.append({"case_id": case_id, "lane": lane, "sample": sample,
                       "predicted_positive": predicted, "probability": float(probability),
                       "latency_ms": numeric["latency_ms"],
                       "peak_memory_bytes": int(numeric["peak_memory_bytes"]),
                       "cost_usd": numeric["cost_usd"],
                       "status": status,
                       "finding_rules": sorted(set(finding_rules))})
    return output


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def _ece(rows: Sequence[tuple[float, bool]], bins: int = 10) -> float:
    if not rows:
        return 0.0
    total = len(rows)
    error = 0.0
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        bucket = [(probability, label) for probability, label in rows
                  if probability >= low and (probability < high or index == bins - 1)]
        if not bucket:
            continue
        confidence = statistics.fmean(value for value, _label in bucket)
        accuracy = statistics.fmean(1.0 if label else 0.0 for _value, label in bucket)
        error += len(bucket) / total * abs(confidence - accuracy)
    return error


def _lane_metrics(records: Sequence[Mapping[str, Any]], cases: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    # Accuracy and calibration describe completed observations only. Timeouts,
    # failures, cancellations, and skips remain attempt/completion evidence but
    # must not masquerade as model or detector predictions.
    quality_records = [row for row in records if row.get("status") == "completed"]
    tp = fp = fn = tn = 0
    calibration = []
    expected_rule_tp = expected_rule_fp = expected_rule_fn = 0
    for row in quality_records:
        case = cases[row["case_id"]]
        label = bool(case["label"])
        predicted = row["predicted_positive"]
        tp += bool(predicted and label)
        fp += bool(predicted and not label)
        fn += bool(not predicted and label)
        tn += bool(not predicted and not label)
        calibration.append((float(row["probability"]), label))
        expected = set(case.get("expected_rules", []))
        observed = set(row.get("finding_rules", []))
        expected_rule_tp += len(expected & observed)
        expected_rule_fp += len(observed - expected)
        expected_rule_fn += len(expected - observed)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    rule_precision = expected_rule_tp / (expected_rule_tp + expected_rule_fp) \
        if expected_rule_tp + expected_rule_fp else 0.0
    rule_recall = expected_rule_tp / (expected_rule_tp + expected_rule_fn) \
        if expected_rule_tp + expected_rule_fn else 0.0
    rule_f1 = 2 * rule_precision * rule_recall / (rule_precision + rule_recall) \
        if rule_precision + rule_recall else 0.0
    brier = statistics.fmean((probability - (1.0 if label else 0.0)) ** 2
                             for probability, label in calibration) if calibration else 0.0
    latencies = [float(row["latency_ms"]) for row in records]
    memory = [float(row["peak_memory_bytes"]) for row in records]
    costs = [float(row["cost_usd"]) for row in records]
    attempts = {case_id: 0 for case_id in cases}
    samples = {case_id: 0 for case_id in cases}
    for row in records:
        attempts[row["case_id"]] += 1
        if row.get("status") == "completed":
            samples[row["case_id"]] += 1
    per_case_rates = []
    within_case_deviation = []
    repeated_cases = disagreement_cases = 0
    for case_id in sorted(case_id for case_id, count in samples.items() if count):
        predictions = [1.0 if row["predicted_positive"] else 0.0
                       for row in quality_records if row["case_id"] == case_id]
        if predictions:
            per_case_rates.append(statistics.fmean(predictions))
        if len(predictions) >= 2:
            repeated_cases += 1
            within_case_deviation.append(statistics.pstdev(predictions))
            disagreement_cases += len(set(predictions)) > 1
    statuses = [str(row.get("status", "completed")) for row in records]
    return {
        "samples": len(records), "completed_samples": len(quality_records),
        "cases": sum(count > 0 for count in attempts.values()),
        "completed_cases": sum(count > 0 for count in samples.values()),
        "quality_metrics_population": "completed-records-only",
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fpr,
        "rule_metrics": {"tp": expected_rule_tp, "fp": expected_rule_fp,
                         "fn": expected_rule_fn, "precision": rule_precision,
                         "recall": rule_recall, "f1": rule_f1},
        "brier": brier, "ece_10_bin": _ece(calibration),
        "latency_ms": {"median": statistics.median(latencies) if latencies else 0.0,
                       "p95": _percentile(latencies, .95), "max": max(latencies, default=0.0)},
        "peak_memory_bytes": {"median": statistics.median(memory) if memory else 0.0,
                              "p95": _percentile(memory, .95), "max": max(memory, default=0.0)},
        "cost_usd": {"total": sum(costs), "mean_per_sample": statistics.fmean(costs) if costs else 0.0},
        "completion_rate": statuses.count("completed") / len(statuses) if statuses else 0.0,
        "timeout_rate": statuses.count("timeout") / len(statuses) if statuses else 0.0,
        "failure_rate": sum(status in {"failed", "cancelled"} for status in statuses) / len(statuses)
                        if statuses else 0.0,
        "stochastic_case_rate_stddev": statistics.pstdev(per_case_rates)
                                        if len(per_case_rates) > 1 else 0.0,
        "within_case_prediction_stddev_mean": statistics.fmean(within_case_deviation)
                                               if within_case_deviation else 0.0,
        "repeat_disagreement_case_rate": disagreement_cases / repeated_cases
                                         if repeated_cases else 0.0,
        "repeated_completed_cases": repeated_cases,
        "minimum_repeats_per_case": min(samples.values(), default=0),
        "maximum_repeats_per_case": max(samples.values(), default=0),
        "minimum_attempts_per_case": min(attempts.values(), default=0),
        "maximum_attempts_per_case": max(attempts.values(), default=0),
    }


def _reference_hash_set(values: Iterable[str]) -> set[str]:
    if isinstance(values, (str, bytes, bytearray, Mapping)):
        raise AttestorBenchError("reference hashes must be a bounded iterable of SHA-256 strings")
    references: set[str] = set()
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise AttestorBenchError("reference hashes must be iterable") from exc
    for index, value in enumerate(iterator):
        if index >= MAX_REFERENCE_HASHES:
            raise AttestorBenchError("reference hash input exceeds the 10,000-entry boundary")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9A-Fa-f]{64}", value):
            raise AttestorBenchError("reference hashes must be exact hexadecimal SHA-256 values")
        references.add(value.lower())
    return references


def evaluate(corpus: Mapping[str, Any], records: Sequence[Mapping[str, Any]], *,
             reference_hashes: Iterable[str] = ()) -> dict[str, Any]:
    if corpus.get("schema") != CORPUS_SCHEMA or not isinstance(corpus.get("cases"), list):
        raise AttestorBenchError("validated held-out corpus is required")
    cases = {row["id"]: row for row in corpus["cases"] if isinstance(row, Mapping)}
    labels = {case_id: bool(row["label"]) for case_id, row in cases.items()}
    unknown = sorted({str(row.get("case_id")) for row in records} - set(cases))
    if unknown:
        raise AttestorBenchError("results reference unknown corpus cases")
    references = _reference_hash_set(reference_hashes)
    overlaps = sorted(case_id for case_id, row in cases.items()
                      if str(row.get("source_sha256", "")).lower() in references)
    lanes, gaps = {}, []
    for lane in LANES:
        lane_rows = [row for row in records if row.get("lane") == lane]
        metrics = _lane_metrics(lane_rows, cases)
        lanes[lane] = metrics
        missing = sorted(set(cases) - {str(row.get("case_id")) for row in lane_rows})
        if missing:
            gaps.append({"lane": lane, "kind": "missing-cases", "count": len(missing),
                         "case_ids": missing[:100]})
        no_completed = sorted(set(cases) - {
            str(row.get("case_id")) for row in lane_rows
            if row.get("status") == "completed"
        })
        if no_completed:
            gaps.append({"lane": lane, "kind": "no-completed-result",
                         "count": len(no_completed), "case_ids": no_completed[:100]})
        if lane in {"model-only", "hybrid"} and metrics["minimum_repeats_per_case"] < 2:
            gaps.append({"lane": lane, "kind": "stochastic-repeats-insufficient",
                         "message": "At least two observed samples per case are needed to estimate stochastic variance."})
    positive_cases = sum(labels.values())
    negative_cases = len(labels) - positive_cases
    overlap_performed = bool(references)
    complete_lanes = all(lanes[lane]["minimum_repeats_per_case"] >= 1
                         for lane in LANES)
    repeated_stochastic = all(lanes[lane]["minimum_repeats_per_case"] >= 2
                              for lane in ("model-only", "hybrid"))
    release_checks = {
        "minimum_1000_held_out_cases": len(cases) >= RELEASE_MIN_CASES,
        "contains_positive_and_clean_cases": positive_cases > 0 and negative_cases > 0,
        "all_lanes_complete": complete_lanes,
        "stochastic_lanes_repeated": repeated_stochastic,
        "reference_overlap_audited": overlap_performed,
        "no_reference_overlap": overlap_performed and not overlaps,
    }
    body = {
        "schema": REPORT_SCHEMA, "version": VERSION,
        "corpus_sha256": corpus.get("corpus_sha256"), "held_out_cases": len(cases),
        "records": len(records), "lanes": lanes,
        "class_balance": {"positive": positive_cases, "clean": negative_cases},
        "overlap_audit": {"performed": overlap_performed, "reference_hashes": len(references),
                          "overlap_count": len(overlaps), "case_ids": overlaps,
                          "passed": overlap_performed and not overlaps},
        "release_gate": {"passed": all(release_checks.values()), "checks": release_checks},
        "gaps": gaps,
        "claims": {"fabricated_corpus": False, "live_models_invoked": False,
                   "metrics_derived_only_from_supplied_records": True},
    }
    body["report_sha256"] = _sha(body)
    return body


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, help="held-out corpus JSON manifest")
    parser.add_argument("--results", required=True, help="observed lane records JSON")
    parser.add_argument("--reference-hashes", help="optional JSON list of training/reference source hashes")
    args = parser.parse_args(argv)
    try:
        corpus = load_corpus(args.corpus)
        records = load_records(args.results)
        references = _load_json(Path(args.reference_hashes)) if args.reference_hashes else []
        if not isinstance(references, list):
            raise AttestorBenchError("reference hash manifest must be a JSON list")
        report = evaluate(corpus, records, reference_hashes=references)
    except (AttestorBenchError, OSError) as exc:
        print(json.dumps({"schema": REPORT_SCHEMA, "status": "invalid", "error": str(exc)},
                         sort_keys=True))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["release_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
