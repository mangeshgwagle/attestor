#!/usr/bin/env python3
"""Ranking-Gate Trainer 4.2 -- trainable, punishable finding adjudication.

The learned artifact (house style):
  A single linear gate over five bounded finding features,
      keep(x) = 1  iff  w . x >= theta
  trained by perceptron error correction. "Punishment" is the classical
  update rule, applied only on mistakes and always recorded:
      false positive  ->  w <- w - ETA * x      (punish over-prediction)
      false negative  ->  w <- w + ETA * x      (punish under-prediction)
      correct         ->  silence               (no update, by proof)

Determinism contract:
- All arithmetic runs on 1e6-scaled fixed-point integers.
- Every update appends to a SHA-256 hash-chained ledger; `verify-ledger`
  re-walks the chain and names the first broken record.
- Same data + seed => byte-identical model artifact.

Boundaries:
- Offline, stdlib only. This trains a bounded linear ranker; it is not a
  generative model and claims nothing beyond its measured accuracy.
- Exit codes: 0 clean, 1 unresolved findings/gaps, 2 usage, 4 operational.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

RG_SCHEMA = "attestor-rankgate-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

SCALE = 10 ** 6
ETA_SCALED = 50_000          # punishment step size 0.05
MAX_EPOCHS = 200
BIAS_FEATURE = "__bias__"

FEATURE_ORDER = (
    "rule_confidence",
    "reachability",
    "severity",
    "evidence_density",
    "surface_proximity",
)


class RgError(ValueError):
    pass


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _to_scaled(value, name):
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise RgError("%s is not numeric" % name) from exc
    if not 0.0 <= value <= 1.0:
        raise RgError("%s outside [0,1]" % name)
    return int(round(value * SCALE))


def parse_finding(raw, require_label=False):
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(",")]
        values = dict(zip(FEATURE_ORDER, parts))
        label = None
    else:
        values = raw
        label = raw.get("label")
    vector = {}
    for name in FEATURE_ORDER:
        if name not in values:
            raise RgError("finding missing feature %r" % name)
        vector[name] = _to_scaled(values[name], name)
    vector[BIAS_FEATURE] = SCALE
    parsed_label = None
    if require_label:
        if label not in (0, 1, True, False, "0", "1"):
            raise RgError("label must be 0 or 1")
        parsed_label = 1 if str(label) == "1" else 0
    return {"features": vector, "label": parsed_label}


def dot(weights, vector):
    return sum(weights[name] * vector[name] for name in weights)


def predict(weights, theta, vector):
    return 1 if dot(weights, vector) >= theta else 0


# --------------------------------------------------------------- training

def train(dataset, seed=0, eta_scaled=ETA_SCALED, max_epochs=MAX_EPOCHS):
    examples = []
    for index, raw in enumerate(dataset):
        example = parse_finding(raw, require_label=True)
        example["id"] = str(raw.get("id", "example-%d" % index)) \
            if isinstance(raw, dict) else "example-%d" % index
        examples.append(example)

    weights = {name: SCALE // 10 for name in FEATURE_ORDER}
    weights[BIAS_FEATURE] = 0

    ledger = []
    prev_digest = "0" * 64
    theta = SCALE // 2
    epochs_used = 0
    final_errors = 0
    history = []

    for epoch in range(1, max_epochs + 1):
        epochs_used = epoch
        epoch_errors = 0
        for example in examples:
            guess = predict(weights, theta, example["features"])
            truth = example["label"]
            if guess == truth:
                continue
            epoch_errors += 1
            if guess == 1 and truth == 0:
                update_kind = "punish-false-positive"
                sign = -1
            else:
                update_kind = "punish-false-negative"
                sign = 1
            delta = {}
            for name in FEATURE_ORDER:
                shift = sign * eta_scaled * example["features"][name] // SCALE
                weights[name] += shift
                delta[name] = shift
            theta -= sign * eta_scaled * 1 // 4

            record = {
                "step": len(ledger) + 1,
                "epoch": epoch,
                "example_id": example["id"],
                "update": update_kind,
                "delta": delta,
                "prev_digest": prev_digest,
            }
            record["digest"] = sha256_hex(canonical_json(record).encode())
            ledger.append(record)
            prev_digest = record["digest"]

        history.append({"epoch": epoch, "errors": epoch_errors})
        final_errors = epoch_errors
        if epoch_errors == 0:
            break

    accuracy = ((len(examples) * epochs_used
                 - sum(h["errors"] for h in history))
                / max(len(examples) * epochs_used, 1))
    model = {
        "schema": RG_SCHEMA,
        "tool": "rankgate-trainer",
        "feature_order": list(FEATURE_ORDER),
        "weights_scaled": weights,
        "threshold_scaled": theta,
        "scale": SCALE,
        "epochs_used": epochs_used,
        "final_epoch_errors": final_errors,
        "converged": final_errors == 0,
        "examples_seen_total": sum(h["errors"] * 0 + len(examples)
                                   for h in history),
        "updates_total": len(ledger),
        "ledger_tail_digest": prev_digest,
        "error_history": history,
        "seed": seed,
        "note": ("linear gate trained by perceptron error correction; "
                 "'punishment' updates are recorded in the chained ledger"),
    }
    model["model_sha256"] = sha256_hex(
        canonical_json({k: v for k, v in model.items()}).encode())
    return {"model": model, "ledger": ledger}


def load_model(path=None, inline=None):
    if inline is not None:
        model = inline
    elif path:
        with open(path, "r", encoding="utf-8") as handle:
            model = json.load(handle)
    else:
        raise RgError("supply --model FILE")
    if model.get("schema") != RG_SCHEMA:
        raise RgError("not a %s model" % RG_SCHEMA)
    return model


def score_finding(model, raw_finding):
    finding = parse_finding(raw_finding)
    guess = predict(model["weights_scaled"], model["threshold_scaled"],
                    finding["features"])
    margin = dot(model["weights_scaled"], finding["features"]) \
        - model["threshold_scaled"]
    return {
        "schema": RG_SCHEMA,
        "tool": "rankgate-score",
        "prediction": "keep" if guess else "demote",
        "margin_scaled": margin,
        "features": {name: round(finding["features"][name] / SCALE, 6)
                     for name in FEATURE_ORDER},
    }


def evaluate_model(model, dataset):
    correct = 0
    misses = []
    for index, raw in enumerate(dataset):
        example = parse_finding(raw, require_label=True)
        guess = predict(model["weights_scaled"], model["threshold_scaled"],
                        example["features"])
        if guess == example["label"]:
            correct += 1
        else:
            misses.append({
                "example": index,
                "expected": example["label"],
                "predicted": guess,
            })
    total = len(dataset)
    return {
        "schema": RG_SCHEMA,
        "tool": "rankgate-evaluate",
        "total": total,
        "correct": correct,
        "accuracy": round(correct / max(total, 1), 6),
        "misses": misses,
    }


# ----------------------------------------------------------------- ledger

def verify_ledger(ledger):
    prev = "0" * 64
    for position, record in enumerate(ledger):
        expected_fields = {k: v for k, v in record.items() if k != "digest"}
        recomputed = sha256_hex(canonical_json(expected_fields).encode())
        if record.get("prev_digest") != prev:
            return {
                "schema": RG_SCHEMA,
                "tool": "verify-ledger",
                "valid": False,
                "broken_at_step": record.get("step", position + 1),
                "reason": "chain link mismatch",
            }
        if record.get("digest") != recomputed:
            return {
                "schema": RG_SCHEMA,
                "tool": "verify-ledger",
                "valid": False,
                "broken_at_step": record.get("step", position + 1),
                "reason": "record digest mismatch (edited)",
            }
        prev = record["digest"]
    return {
        "schema": RG_SCHEMA,
        "tool": "verify-ledger",
        "valid": True,
        "records_verified": len(ledger),
        "tail_digest": prev,
    }


# ------------------------------------------------------------ demo corpus

DEMO_DATASET = [
    {"id": "sql-tautology", "rule_confidence": 0.92, "reachability": 0.85,
     "severity": 0.95, "evidence_density": 0.8, "surface_proximity": 0.9,
     "label": 1},
    {"id": "jwt-none-route", "rule_confidence": 0.88, "reachability": 0.8,
     "severity": 0.9, "evidence_density": 0.75, "surface_proximity": 0.85,
     "label": 1},
    {"id": "sqli-reachable", "rule_confidence": 0.8, "reachability": 0.9,
     "severity": 0.9, "evidence_density": 0.7, "surface_proximity": 0.95,
     "label": 1},
    {"id": "weak-crypto-path", "rule_confidence": 0.7, "reachability": 0.75,
     "severity": 0.8, "evidence_density": 0.7, "surface_proximity": 0.8,
     "label": 1},
    {"id": "cmdi-unauth", "rule_confidence": 0.9, "reachability": 0.95,
     "severity": 1.0, "evidence_density": 0.85, "surface_proximity": 0.9,
     "label": 1},
    {"id": "comment-noise", "rule_confidence": 0.1, "reachability": 0.05,
     "severity": 0.2, "evidence_density": 0.05, "surface_proximity": 0.05,
     "label": 0},
    {"id": "test-file-secret", "rule_confidence": 0.15, "reachability": 0.0,
     "severity": 0.3, "evidence_density": 0.1, "surface_proximity": 0.0,
     "label": 0},
    {"id": "stale-dependency-note", "rule_confidence": 0.2,
     "reachability": 0.1, "severity": 0.15, "evidence_density": 0.08,
     "surface_proximity": 0.1, "label": 0},
    {"id": "docs-warning", "rule_confidence": 0.05, "reachability": 0.02,
     "severity": 0.1, "evidence_density": 0.03, "surface_proximity": 0.02,
     "label": 0},
    {"id": "generated-code-hint", "rule_confidence": 0.12,
     "reachability": 0.08, "severity": 0.18, "evidence_density": 0.06,
     "surface_proximity": 0.07, "label": 0},
]


def run_demo():
    outcome = train(DEMO_DATASET)
    evaluation = evaluate_model(outcome["model"], DEMO_DATASET)
    ledger_check = verify_ledger(outcome["ledger"])
    punished_fp = sum(1 for r in outcome["ledger"]
                      if r["update"] == "punish-false-positive")
    punished_fn = sum(1 for r in outcome["ledger"]
                      if r["update"] == "punish-false-negative")
    return {
        "schema": RG_SCHEMA,
        "tool": "rankgate-demo",
        "model": outcome["model"],
        "evaluation": evaluation,
        "ledger_check": ledger_check,
        "punishments_false_positive": punished_fp,
        "punishments_false_negative": punished_fn,
    }


def run_selftest():
    checks = []
    outcome = train(DEMO_DATASET)
    model = outcome["model"]
    checks.append(("converges on separable corpus", model["converged"]))
    checks.append(("at least one punishment was dealt",
                   model["updates_total"] >= 1))

    evaluation = evaluate_model(model, DEMO_DATASET)
    checks.append(("post-training accuracy perfect on corpus",
                   evaluation["accuracy"] == 1.0))

    # Punishment direction: an all-max feature vector labeled 0 is a
    # guaranteed initial false positive, so its punishment must push every
    # weight strictly below initialization.
    tricky = [{"id": "trap", "rule_confidence": 1.0, "reachability": 1.0,
               "severity": 1.0, "evidence_density": 1.0,
               "surface_proximity": 1.0, "label": 0}]
    punished = train(tricky, max_epochs=1)
    after = punished["model"]["weights_scaled"]
    checks.append(("false-positive punishment lowers weights",
                   all(after[n] < SCALE // 10 for n in FEATURE_ORDER)))

    ledger_check = verify_ledger(outcome["ledger"])
    checks.append(("training ledger verifies", ledger_check["valid"]))

    tampered = [dict(r) for r in outcome["ledger"]]
    if tampered:
        tampered[0]["delta"] = dict(tampered[0]["delta"])
        key = next(iter(tampered[0]["delta"]))
        tampered[0]["delta"][key] += 1
        bad = verify_ledger(tampered)
        checks.append(("tampered ledger fails closed",
                       bad["valid"] is False and "broken_at_step" in bad))

    import copy
    first = canonical_json(train(DEMO_DATASET)["model"])
    second = canonical_json(train(DEMO_DATASET)["model"])
    checks.append(("retraining is byte-identical", first == second))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": RG_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


# ------------------------------------------------ engagement bridge

KIND_FEATURES = {
    "sql-injection-candidate": (0.9, 0.85, 0.9, 0.8),
    "sql-tautology-candidate": (0.8, 0.8, 0.85, 0.75),
    "command-injection-candidate": (0.95, 0.9, 1.0, 0.85),
    "xss-reflection-candidate": (0.6, 0.5, 0.6, 0.6),
    "path-traversal-candidate": (0.7, 0.65, 0.7, 0.65),
    "missing-security-header": (0.3, 0.2, 0.3, 0.4),
    "bola-candidate-same-content-wrong-principal": (0.95, 0.9, 0.95, 0.9),
    "sql-injection-confirmed": (1.0, 1.0, 1.0, 1.0),
    "command-injection-confirmed": (1.0, 1.0, 1.0, 1.0),
}


def finding_to_example(finding, label=None):
    kind = finding.get("kind", "unknown")
    conf, reach, sev, surf = KIND_FEATURES.get(kind, (0.4, 0.4, 0.4, 0.4))
    triage = finding.get("triage_features") or {}
    if triage:
        reach = float(triage.get("reachability", reach))
        sev = float(triage.get("severity", sev))
    evidence_density = 1.0 if finding.get("evidence_digest") else \
        (0.7 if finding.get("evidence") else 0.3)
    surface = 1.0 if (finding.get("url") or finding.get("endpoint")
                      or finding.get("path")) else surf
    if finding.get("runtime_confirmed") or finding.get(
            "synthetic_confirmed"):
        conf = max(conf, 0.95)
    example = {
        "id": finding.get("finding_id") or finding.get("id")
        or finding.get("probe_id", "finding"),
        "rule_confidence": conf,
        "reachability": reach,
        "severity": sev,
        "evidence_density": evidence_density,
        "surface_proximity": surface,
    }
    if label is not None:
        example["label"] = int(label)
    return example


def engagement_to_dataset(report, labels=None):
    labels = labels or {}
    rows, skipped = [], []
    for finding in report.get("findings", []):
        fid = finding.get("finding_id") or finding.get("probe_id") \
            or finding.get("id")
        auto = 1 if (finding.get("runtime_confirmed")
                     or finding.get("synthetic_confirmed")) else None
        label = labels.get(fid, auto)
        if label is None:
            skipped.append(fid)
            continue
        rows.append(finding_to_example(finding, label=label))
    return rows, skipped

# -------------------------------------------------------------------- cli

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="rankgate_trainer42",
        description="Trainable, punishable linear ranking gate")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("train", help="train on a labeled JSONL dataset")
    p.add_argument("--dataset", help="JSONL file; omit for bundled corpus")
    p.add_argument("--out", help="write the model artifact here")

    p = subs.add_parser("evaluate", help="measure a trained model")
    p.add_argument("--model", required=True)
    p.add_argument("--dataset")

    p = subs.add_parser("score", help="gate one finding")
    p.add_argument("--model", required=True)
    p.add_argument("--finding", required=True,
                   help="'c,r,s,e,p' comma floats in [0,1]")

    p = subs.add_parser("verify-ledger", help="walk a training ledger")
    p.add_argument("--ledger", required=True)

    p = subs.add_parser("from-engagement",
                        help="convert engagement findings to training rows")
    p.add_argument("--engagement", required=True)
    p.add_argument("--labels", help="JSON {finding_id: 0|1}")
    p.add_argument("--out")

    subs.add_parser("demo")
    subs.add_parser("self-test")

    parser.add_argument("--format", choices=["text", "json"], default="json")
    args = parser.parse_args(argv)

    try:
        if args.command == "train":
            dataset = DEMO_DATASET
            if args.dataset:
                dataset = []
                with open(args.dataset, "r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if line:
                            dataset.append(json.loads(line))
            outcome = train(dataset)
            result = outcome["model"]
            result["ledger"] = outcome["ledger"]
            code = EXIT_CLEAN if result["converged"] else EXIT_FINDING
            if args.out:
                with open(args.out, "w", encoding="utf-8") as handle:
                    json.dump(result, handle, indent=2, sort_keys=True)
                result["written_to"] = args.out
        elif args.command == "evaluate":
            model = load_model(path=args.model)
            dataset = DEMO_DATASET
            if args.dataset:
                dataset = []
                with open(args.dataset, "r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if line:
                            dataset.append(json.loads(line))
            result = evaluate_model(model, dataset)
            code = EXIT_CLEAN if not result["misses"] else EXIT_FINDING
        elif args.command == "score":
            model = load_model(path=args.model)
            result = score_finding(model, args.finding)
            code = EXIT_CLEAN
        elif args.command == "verify-ledger":
            with open(args.ledger, "r", encoding="utf-8") as handle:
                ledger = json.load(handle)
            if not isinstance(ledger, list):
                raise RgError("ledger must be a JSON list")
            result = verify_ledger(ledger)
            code = EXIT_CLEAN if result["valid"] else EXIT_OPERATIONAL
        elif args.command == "from-engagement":
            with open(args.engagement, "r", encoding="utf-8") as handle:
                report = json.load(handle)
            labels = None
            if args.labels:
                with open(args.labels, "r", encoding="utf-8") as handle:
                    labels = json.load(handle)
            rows, skipped = engagement_to_dataset(report, labels)
            result = {
                "schema": RG_SCHEMA,
                "tool": "findings-to-jsonl",
                "rows_emitted": len(rows),
                "skipped_unlabeled": len(skipped),
                "rows": rows,
            }
            if args.out:
                with open(args.out, "w", encoding="utf-8") as handle:
                    for row in rows:
                        handle.write(json.dumps(row) + "\n")
                result["written_to"] = args.out
            code = EXIT_CLEAN

        elif args.command == "demo":
            result = run_demo()
            code = EXIT_CLEAN if result["evaluation"]["misses"] == [] \
                else EXIT_FINDING
        elif args.command == "self-test":
            result = run_selftest()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        else:  # pragma: no cover
            parser.error("unknown command")
    except (RgError, OSError, json.JSONDecodeError) as exc:
        print("rankgate_trainer42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
