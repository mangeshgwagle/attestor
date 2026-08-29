#!/usr/bin/env python3
"""Train the gate on Attestor's own mutation corpus, with no external archive.

This is `train_gate.py` with one part replaced.  The split, the featuriser,
the optimiser, the span calibration, the quantiser and the integer
re-verification are imported from that module and run unchanged -- only the
source of labelled windows differs, and it comes from `attestor_corpus`, which
builds pairs by injecting defects into source already in this tree.

Everything that makes the reported number trustworthy is therefore the same
code that produced the shipped artifact, including the two checks that matter:

**The split is grouped, never random.**  `juliet_corpus.group_split` keys on
`Example.pair`, and `attestor_corpus` sets that to the source file, so every
mutation of one file lands on one side of the holdout.  Two mutations of the
same file differ by a line or two; splitting between them would measure
memorisation.

**The control is mandatory.**  The same architecture trained on shuffled
labels must score at chance.  On a corpus this size that is not a formality:
8,883 windows against a 2048x128 model is far more capacity than data, so a
high AUC with a high control AUC would mean the features are carrying file
identity rather than defect structure.  The control is what separates those
two outcomes, and it is why this script fails loudly rather than writing an
artifact when the gap is small.

What a good result here does and does not license
-------------------------------------------------
A high AUC with a chance-level control says the injected patterns are
separable from their own baselines by a bag-of-tokens model.  It does not say
the gate generalises to defects people write rather than defects these sixteen
mutators write, and it does not make the gate a detector -- `neural_gate`
produces evidence for ranking, never a verdict.  The Juliet-trained artifact
remains the shipped one; this path exists so the pipeline can be exercised and
extended without a 146 MB download.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import attestor_corpus  # noqa: E402
import train_gate  # noqa: E402


# Smaller than train_gate's 2048 by default.  That width was chosen against
# 639k Juliet windows; this corpus is two orders of magnitude smaller, and a
# wider hash space on less data buys collisions avoided at the cost of a model
# that can memorise its training set outright.
DEFAULT_DIM = 1024
DEFAULT_HIDDEN = 64
DEFAULT_EPOCHS = 12
DEFAULT_BATCH = 128
DEFAULT_LR = 3e-3
DEFAULT_SEED = 20260806

# The control has to be near chance for the headline number to mean anything.
# 0.60 is deliberately loose: it catches a control that has learned the corpus
# without failing on the sampling noise a few thousand held-out rows carry.
MAX_CONTROL_AUC = 0.60


def featurise(subset, neural_gate, dim: int):
    """Rows to a sparse matrix and a label vector, exactly as `train_gate.load`."""
    labels = np.fromiter((row.label for row in subset),
                         dtype=np.float32, count=len(subset))
    data = train_gate.Sparse.from_stream(
        (neural_gate.sparse_features(row.text, dim) for row in subset),
        len(subset), dim, float(neural_gate.FEATURE_SCALE))
    return data, labels


def main(argv: list[str] | None = None) -> int:
    default_roots = [str(HERE.parent.parent / name)
                     for name in ("detector", "integrations", "experiments",
                                  "services", "realworld")]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--roots", nargs="+", default=default_roots,
                        help="directories of Python source to mutate")
    parser.add_argument("--detector",
                        default=str(HERE.parent.parent / "detector"))
    parser.add_argument("--dim", type=int, default=DEFAULT_DIM)
    parser.add_argument("--hidden", type=int, default=DEFAULT_HIDDEN)
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--window-lines", type=int,
                        default=attestor_corpus.DEFAULT_WINDOW_LINES)
    parser.add_argument("--limit", type=int, default=None,
                        help="stop after N windows")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", default=None,
                        help="where to write the artifact (default: dry run)")
    parser.add_argument(
        "--allow-below-floor", action="store_true",
        help="train on hardware below the recommended accelerator floor; the "
             "run is permitted but unsupported and may exhaust memory and stop")
    args = parser.parse_args(argv)

    # A recommended requirement, not a minimum one. Below the floor the work is
    # attempted when the operator opts in, and the verdict travels into the
    # run record so a result produced on unsupported hardware is not
    # indistinguishable from one produced on supported hardware.
    sys.path.insert(0, args.detector)
    import hardware_tier  # noqa: E402
    try:
        hardware = hardware_tier.require_accelerator(
            allow_below_floor=args.allow_below_floor)
    except hardware_tier.UnsupportedHardware as error:
        print("attestor-train: %s" % error, file=sys.stderr)
        print("attestor-train: pass --allow-below-floor to attempt it anyway.",
              file=sys.stderr)
        return 1
    if hardware.get("ran_below_floor"):
        print("WARNING: %s" % hardware["message"], flush=True)

    juliet_corpus, neural_gate = train_gate._detector(args.detector)
    started = time.time()

    print("building the mutation corpus from %d roots ..." % len(args.roots),
          flush=True)
    try:
        rows = attestor_corpus.build(args.roots, args.detector,
                                 args.window_lines, args.limit)
    except attestor_corpus.CorpusBuildError as error:
        print("corpus-unavailable: %s" % error, file=sys.stderr)
        return 1
    summary = attestor_corpus.stats(rows)
    print("%d windows, %d groups, %d positive / %d negative"
          % (summary["windows"], summary["groups"],
             summary["positive"], summary["negative"]), flush=True)

    train_rows, hold_rows = juliet_corpus.group_split(rows, holdout=0.2)
    if not train_rows or not hold_rows:
        print("split produced an empty side", file=sys.stderr)
        return 1
    train_x, train_y = featurise(train_rows, neural_gate, args.dim)
    hold_x, hold_y = featurise(hold_rows, neural_gate, args.dim)
    print("%d train / %d held-out (grouped by source file)"
          % (len(train_x), len(hold_x)), flush=True)

    print("\ntraining ...", flush=True)
    model = train_gate.train_float(train_x, train_y, args.hidden, args.epochs,
                                   args.batch, args.lr, args.seed)
    hold_logits = train_gate.float_logits(model, hold_x)
    float_auc = train_gate.auc(hold_y, hold_logits)
    accuracy = float(np.mean((hold_logits > 0) == (hold_y == 1)) * 100)
    majority = float(max(hold_y.mean(), 1 - hold_y.mean()) * 100)
    print("held-out: %.2f%% accuracy, AUC %.4f (majority baseline %.2f%%)"
          % (accuracy, float_auc, majority))

    print("\ncontrol (shuffled labels) ...", flush=True)
    rng = np.random.default_rng(args.seed + 1)
    control = train_gate.train_float(train_x, rng.permutation(train_y),
                                     args.hidden, args.epochs, args.batch,
                                     args.lr, args.seed, quiet=True)
    control_logits = train_gate.float_logits(control, hold_x)
    control_auc = train_gate.auc(hold_y, control_logits)
    control_accuracy = float(
        np.mean((control_logits > 0) == (hold_y == 1)) * 100)
    print("control held-out: AUC %.4f (chance 0.5), %.2f%% accuracy"
          % (control_auc, control_accuracy))

    span = train_gate.calibrate_span(hold_logits, neural_gate.WEIGHT_SCALE)
    artifact = train_gate.quantise(model, neural_gate, span)
    print("\nverifying the integer copy ...", flush=True)
    check = train_gate.verify_quantisation(artifact, hold_rows, hold_y,
                                           neural_gate, float_auc)
    print("float AUC %.4f -> integer AUC %.4f (drop %.4f), %.1f%% saturated"
          % (check["float_auc"], check["integer_auc"], check["auc_drop"],
             check["saturated_fraction"] * 100))

    verdict = {
        "schema": "attestor.gate-training-run/1.0",
        "corpus": "attestor-mutation-self-hosted",
        "windows": summary["windows"],
        "groups": summary["groups"],
        "by_cwe": summary["by_cwe"],
        "train_rows": len(train_x),
        "holdout_rows": len(hold_x),
        "held_out_auc": round(float_auc, 4),
        "held_out_accuracy_percent": round(accuracy, 2),
        "held_out_majority_baseline_percent": round(majority, 2),
        "shuffled_label_control_auc": round(control_auc, 4),
        "shuffled_label_control_percent": round(control_accuracy, 2),
        "quantisation": check,
        "hardware": {
            "accelerator_status": hardware["status"],
            "accelerator_floor_gb": hardware["floor_gb"],
            "ran_below_floor": bool(hardware.get("ran_below_floor")),
        },
        "elapsed_seconds": round(time.time() - started, 1),
    }

    # Fail closed.  An artifact whose control also scores high is not a model
    # of defects, and writing it would be the one failure mode that still
    # looks like success everywhere downstream.
    if control_auc > MAX_CONTROL_AUC:
        verdict["status"] = "rejected-control-not-at-chance"
        print("\n" + json.dumps(verdict, indent=2, sort_keys=True))
        print("\nREJECTED: the shuffled-label control reached AUC %.4f "
              "(limit %.2f); the features are carrying corpus structure, not "
              "defects. No artifact was written."
              % (control_auc, MAX_CONTROL_AUC), file=sys.stderr)
        return 1

    verdict["status"] = "accepted"
    if args.out:
        artifact["training_data"] = (
            "Attestor self-hosted mutation corpus: %d windows over %d source files, "
            "defects injected by mutation_gauntlet, grouped split by file."
            % (summary["windows"], summary["groups"]))
        artifact["corpus_limitations"] = [
            "Injected mutator patterns, not the distribution of defects people write.",
            "Grouped by source file; residual similarity between sibling files remains.",
            "Two mutator families supply most rows, so per-family recall is uneven.",
        ]
        artifact["held_out_auc"] = round(float_auc, 4)
        artifact["held_out_accuracy_percent"] = round(accuracy, 2)
        artifact["held_out_majority_baseline_percent"] = round(majority, 2)
        artifact["shuffled_label_control_auc"] = round(control_auc, 4)
        artifact["shuffled_label_control_percent"] = round(control_accuracy, 2)
        artifact["held_out_split"] = "grouped by source file, 80/20"
        artifact["trained_examples"] = int(len(train_x))
        artifact["window_lines"] = int(args.window_lines)
        artifact["logit_span_basis"] = (
            "2x the 99.9th percentile of |logit| on held-out rows")
        artifact["model_sha256"] = neural_gate._sha(artifact)
        pathlib.Path(args.out).write_text(
            json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
        verdict["artifact"] = args.out

    print("\n" + json.dumps(verdict, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
