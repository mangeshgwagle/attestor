#!/usr/bin/env python3
"""Train the neural gate, and prove the integer copy still works.

Where this lives, and why not in `detector/`
--------------------------------------------
`detector/` imports nothing outside the standard library, and that constraint
is worth keeping: it is what lets Attestor run anywhere without a supply chain.
Training is not scanning, though. It happens once, offline, on a machine
somebody chose -- so it may use numpy, and it does, because the alternative is
forty minutes per epoch of pure-Python inner loops.

What ships from here is a JSON artifact of integers. `detector/neural_gate.py`
reads it with no dependency on anything in this directory.

The three things this has to get right
--------------------------------------
**1. The split.** Grouped by testcase, never random. Juliet's flawed and fixed
variants of one testcase are near-identical text; a random split puts them on
opposite sides and the held-out number becomes a memorisation score. That
mistake previously reported 0.943 where the truth was near 0.80.
`juliet_corpus.group_split` already does this and is used unchanged.

**2. The control.** The same architecture trained on *shuffled* labels must
score at chance. If it does not, the features are carrying something about the
corpus's construction rather than about defects, and the real number means
nothing. The shipped artifact records 50.06% against 98.4% -- that gap is what
makes the 98.4% worth believing, and it is recomputed here every run.

**3. The quantisation.** The model is trained in floating point and shipped as
integers, and those are not the same model. A quantised copy that has drifted
is the worst possible failure here, because it still works -- it just works
slightly differently from the thing that was measured. So the artifact is
re-scored through `neural_gate.infer` itself, on held-out data, and the run
fails if the integer AUC falls away from the float AUC.

Why the span is calibrated rather than chosen
---------------------------------------------
`_squash` maps a logit onto 0..10000 through a piecewise-linear curve whose
width travels in the artifact. A span that is too narrow saturates: the first
hardcoded one here was six times too small and pinned 87% of scores at the
maximum, which destroys the ordering the score exists to provide. It is
therefore measured from the held-out logit distribution, not picked.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from array import array
from typing import Any, Sequence

import numpy as np

SCHEMA = "attestor.neural-gate/1.0"
VERSION = "4.1.4"

DEFAULT_DIM = 2048
DEFAULT_HIDDEN = 128
DEFAULT_EPOCHS = 12
DEFAULT_BATCH = 256
DEFAULT_LR = 3e-3
WINDOW_LINES = 12

# The quantised model must track the float one it came from. This is the
# largest AUC drop tolerated before the run is treated as failed rather than
# reported with a caveat -- a caveat nobody reads is not a safeguard.
MAX_QUANTISATION_AUC_DROP = 0.01

# The control is read as AUC, not accuracy, and the difference is not cosmetic.
# Juliet's corrected variant ships two functions where the flawed one ships
# one, so label-0 windows outnumber label-1 and the classes are not balanced.
# A shuffled-label model learns nothing and collapses onto the majority class
# -- which scores the majority fraction, measured here at 71.5%, and looks
# exactly like a feature leak. AUC is invariant to that imbalance: a model
# with no signal ranks at 0.5 however the classes are distributed.
CONTROL_BAND = (0.45, 0.55)


class TrainingError(RuntimeError):
    """The corpus, the split, or the resulting model was unusable."""


class Sparse:
    """The corpus in CSR, materialised one batch at a time.

    Holding it dense is the obvious approach and does not survive contact with
    the real corpus: 400,000 windows at 2,048 float32 is 3.3 GB before the
    optimiser has allocated anything, on a machine with 7 GB free. A twelve-
    line window occupies a few hundred buckets of 2,048, so the dense array is
    almost entirely zeros being paid for in full.

    Stored as (indptr, indices, values) it is roughly 1 GB, and each batch is
    expanded to dense only for as long as the matmul needs it -- 256 x 2048 is
    2 MB. The arithmetic is identical; only the residency changes.
    """

    __slots__ = ("indptr", "indices", "values", "dim")

    def __init__(self, indptr, indices, values, dim: int):
        self.indptr = indptr
        self.indices = indices
        self.values = values
        self.dim = dim

    def __len__(self) -> int:
        return len(self.indptr) - 1

    @property
    def shape(self) -> tuple[int, int]:
        return len(self), self.dim

    @classmethod
    def from_stream(cls, stream, count: int, dim: int,
                    scale: float) -> "Sparse":
        """Consume per-row (index, value) sequences without holding them all.

        Materialising the rows first -- `[sparse_features(t) for t in texts]`
        -- is the natural way to write this and cannot run on the real corpus:
        1.19M windows at a few hundred buckets each is ~300M tuples, and a
        Python list of those costs more than the machine has before any
        training starts.

        `array` rather than a Python list for the same reason: 4 bytes per
        entry against 8 for a pointer plus 28 for the int it points at.
        """
        indptr = np.zeros(count + 1, dtype=np.int64)
        indices = array("i")
        values = array("f")
        position = 0
        for entries in stream:
            for index, value in entries:
                indices.append(index)
                values.append(value / scale)
            position += 1
            indptr[position] = len(indices)
        if position != count:
            raise TrainingError("stream yielded %d rows, expected %d"
                                % (position, count))
        return cls(indptr,
                   np.frombuffer(indices, dtype=np.int32).copy(),
                   np.frombuffer(values, dtype=np.float32).copy(), dim)

    @classmethod
    def from_dense(cls, matrix: np.ndarray) -> "Sparse":
        """For tests and small corpora; not used on the real path."""
        def rows():
            for row in range(matrix.shape[0]):
                yield [(int(index), float(matrix[row, index]))
                       for index in np.nonzero(matrix[row])[0]]
        return cls.from_stream(rows(), matrix.shape[0], matrix.shape[1], 1.0)

    def batch(self, selection: np.ndarray) -> np.ndarray:
        """Dense rows for `selection`, allocated fresh and dropped after use."""
        out = np.zeros((len(selection), self.dim), dtype=np.float32)
        for position, row in enumerate(selection):
            start, end = self.indptr[row], self.indptr[row + 1]
            out[position, self.indices[start:end]] = self.values[start:end]
        return out


def _detector(path: str):
    if path not in sys.path:
        sys.path.insert(0, path)
    import juliet_corpus
    import neural_gate
    return juliet_corpus, neural_gate


def load(archive: str, detector: str, dim: int, limit: int | None,
         max_windows: int | None = None, seed: int = 20260806):
    """Labelled windows, featurised, split by testcase."""
    juliet_corpus, neural_gate = _detector(detector)
    if not pathlib.Path(archive).is_file():
        raise TrainingError("corpus-unavailable: no archive at %s" % archive)

    rows = list(juliet_corpus.iter_archive(archive, WINDOW_LINES, limit))
    if not rows:
        raise TrainingError("corpus-unavailable: no windows in %s" % archive)

    # Subsampled *before* the split, so the split still sees whole testcases
    # and the grouping guarantee is untouched. Uniform over windows rather
    # than over testcases: taking whole testcases would bias toward the
    # families that emit the most windows.
    if max_windows and len(rows) > max_windows:
        selection = np.random.default_rng(seed).choice(
            len(rows), size=max_windows, replace=False)
        rows = [rows[index] for index in sorted(selection)]

    train, holdout = juliet_corpus.group_split(rows, holdout=0.2)
    if not train or not holdout:
        raise TrainingError("split produced an empty side")

    scale = float(neural_gate.FEATURE_SCALE)

    def featurise(subset: Sequence) -> tuple[Sparse, np.ndarray]:
        labels = np.fromiter((row.label for row in subset),
                             dtype=np.float32, count=len(subset))
        data = Sparse.from_stream(
            (neural_gate.sparse_features(row.text, dim) for row in subset),
            len(subset), dim, scale)
        return data, labels

    # The held-out rows travel back with the split they were featurised from.
    # Re-reading the archive to recover them invites the two passes to disagree
    # -- a different `limit`, a different window size, and the verification
    # would be scoring a different corpus than the one that was trained on.
    return featurise(train), featurise(holdout), holdout, len(rows)


def auc(labels: np.ndarray, scores: np.ndarray) -> float:
    """Rank-based AUC. Ties share their averaged rank."""
    order = np.argsort(scores, kind="mergesort")
    ranks = np.empty(len(scores), dtype=np.float64)
    ranks[order] = np.arange(1, len(scores) + 1)
    # Average the ranks of tied scores, or a model that emits one constant
    # value scores 1.0 instead of 0.5.
    sorted_scores = scores[order]
    start = 0
    for index in range(1, len(sorted_scores) + 1):
        if index == len(sorted_scores) or sorted_scores[index] != sorted_scores[start]:
            if index - start > 1:
                ranks[order[start:index]] = ranks[order[start:index]].mean()
            start = index
    positives = labels == 1
    count_positive = int(positives.sum())
    count_negative = len(labels) - count_positive
    if not count_positive or not count_negative:
        return 0.5
    return float((ranks[positives].sum()
                  - count_positive * (count_positive + 1) / 2)
                 / (count_positive * count_negative))


def train_float(features: np.ndarray, labels: np.ndarray, hidden: int,
                epochs: int, batch: int, learning_rate: float,
                seed: int, quiet: bool = False):
    """A dim->hidden->1 ReLU net by Adam on binary cross-entropy."""
    rng = np.random.default_rng(seed)
    dim = features.shape[1]
    # He initialisation: the ReLU halves the variance, so the naive 1/sqrt(dim)
    # starts the hidden layer too quiet to learn from.
    weights_hidden = (rng.standard_normal((dim, hidden)).astype(np.float32)
                      * np.sqrt(2.0 / dim))
    bias_hidden = np.zeros(hidden, dtype=np.float32)
    weights_out = (rng.standard_normal(hidden).astype(np.float32)
                   * np.sqrt(2.0 / hidden))
    bias_out = np.float32(0.0)

    moments = [np.zeros_like(p) for p in
               (weights_hidden, bias_hidden, weights_out)]
    velocities = [np.zeros_like(p) for p in
                  (weights_hidden, bias_hidden, weights_out)]
    moment_out = velocity_out = np.float32(0.0)
    beta1, beta2, epsilon = 0.9, 0.999, 1e-8
    step = 0

    count = len(features)
    for epoch in range(epochs):
        order = rng.permutation(count)
        total_loss = 0.0
        for start in range(0, count, batch):
            index = order[start:start + batch]
            x, y = features.batch(index), labels[index]

            pre = x @ weights_hidden + bias_hidden
            activation = np.maximum(pre, 0.0)
            logit = activation @ weights_out + bias_out
            # Stable sigmoid + BCE: exp() on a large positive logit overflows,
            # and the resulting nan silently poisons every later weight.
            probability = np.where(logit >= 0,
                                   1.0 / (1.0 + np.exp(-np.abs(logit))),
                                   np.exp(-np.abs(logit))
                                   / (1.0 + np.exp(-np.abs(logit))))
            total_loss += float(np.sum(
                np.maximum(logit, 0) - logit * y
                + np.log1p(np.exp(-np.abs(logit)))))

            gradient_logit = (probability - y) / len(index)
            gradient_out = activation.T @ gradient_logit
            gradient_bias_out = gradient_logit.sum()
            gradient_activation = np.outer(gradient_logit, weights_out)
            gradient_pre = gradient_activation * (pre > 0)
            gradient_hidden = x.T @ gradient_pre
            gradient_bias_hidden = gradient_pre.sum(axis=0)

            step += 1
            correction1 = 1 - beta1 ** step
            correction2 = 1 - beta2 ** step
            for slot, (parameter, gradient) in enumerate(
                    ((weights_hidden, gradient_hidden),
                     (bias_hidden, gradient_bias_hidden),
                     (weights_out, gradient_out))):
                moments[slot] = beta1 * moments[slot] + (1 - beta1) * gradient
                velocities[slot] = (beta2 * velocities[slot]
                                    + (1 - beta2) * gradient * gradient)
                parameter -= (learning_rate * (moments[slot] / correction1)
                              / (np.sqrt(velocities[slot] / correction2)
                                 + epsilon))
            moment_out = beta1 * moment_out + (1 - beta1) * gradient_bias_out
            velocity_out = (beta2 * velocity_out
                            + (1 - beta2) * gradient_bias_out ** 2)
            bias_out -= (learning_rate * (moment_out / correction1)
                         / (np.sqrt(velocity_out / correction2) + epsilon))

        if not quiet:
            print("  epoch %2d/%d  loss %.4f"
                  % (epoch + 1, epochs, total_loss / count), flush=True)

    return weights_hidden, bias_hidden, weights_out, float(bias_out)


def float_logits(model, features: Sparse, chunk: int = 4096) -> np.ndarray:
    """Logits for every row, in chunks so no dense copy of the corpus exists."""
    weights_hidden, bias_hidden, weights_out, bias_out = model
    out = np.empty(len(features), dtype=np.float32)
    for start in range(0, len(features), chunk):
        selection = np.arange(start, min(start + chunk, len(features)))
        activation = np.maximum(
            features.batch(selection) @ weights_hidden + bias_hidden, 0.0)
        out[start:start + len(selection)] = activation @ weights_out + bias_out
    return out


def quantise(model, neural_gate, span: int) -> dict[str, Any]:
    """Float parameters to the integer artifact `neural_gate` expects.

    The scales are dictated by that module's arithmetic, not chosen here:
    features arrive divided by FEATURE_SCALE, both layers keep activations at
    WEIGHT_SCALE, and the bias is already at that scale -- which is why only
    the weighted sum is divided down. Getting this wrong does not raise; it
    ships a different model from the one that was measured.
    """
    weights_hidden, bias_hidden, weights_out, bias_out = model
    weight_scale = neural_gate.WEIGHT_SCALE
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "feature_dim": int(weights_hidden.shape[0]),
        "hidden": int(weights_hidden.shape[1]),
        # Row-major by hidden unit, matching `_validate`'s expectation of
        # `hidden` rows each `feature_dim` wide.
        "hidden_weights": np.rint(weights_hidden.T * weight_scale)
                            .astype(np.int64).tolist(),
        "hidden_bias": np.rint(bias_hidden * weight_scale)
                         .astype(np.int64).tolist(),
        "output_weights": np.rint(weights_out * weight_scale)
                            .astype(np.int64).tolist(),
        "output_bias": int(round(bias_out * weight_scale)),
        "logit_span": int(span),
    }


# The span is calibrated on held-out Juliet, but the gate is pointed at real
# code, and a confident model's logits run much wider off its training
# distribution. Measured on a 4096x128 model: |logit| reached 54,849 on Juliet
# and 122,077 on ordinary Python source, so a span fitted to Juliet's 99th
# percentile pinned 4.6% of real scores to an endpoint against the shipped
# model's 0.2%. Saturated scores carry no ordering, which is the one thing the
# score is for.
#
# This multiplier is empirical and deliberately blunt. It is applied to the
# 99.9th percentile rather than the maximum because one outlier would
# otherwise widen the span until typical scores collapse into the middle.
OUT_OF_DISTRIBUTION_HEADROOM = 2.0


def calibrate_span(logits: np.ndarray, weight_scale: int) -> int:
    """A span wide enough that the curve orders instead of saturating."""
    integer_logits = np.abs(logits) * weight_scale
    span = np.percentile(integer_logits, 99.9) * OUT_OF_DISTRIBUTION_HEADROOM
    return max(1, int(span))


def verify_quantisation(artifact: dict, rows: Sequence, labels: np.ndarray,
                        neural_gate, float_auc: float) -> dict[str, Any]:
    """Re-score held-out windows through the shipped integer path."""
    scores = np.array([neural_gate.infer(row.text, artifact)["score"]
                       for row in rows], dtype=np.float64)
    integer_auc = auc(labels, scores)
    saturated = float(np.mean((scores == 0) | (scores == neural_gate.SCORE_SCALE)))
    return {"integer_auc": round(integer_auc, 4),
            "float_auc": round(float_auc, 4),
            "auc_drop": round(float_auc - integer_auc, 4),
            "saturated_fraction": round(saturated, 4)}


def main(argv: list[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", required=True, help="Juliet/SARD zip")
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--dim", type=int, default=DEFAULT_DIM)
    parser.add_argument("--hidden", type=int, default=DEFAULT_HIDDEN)
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    parser.add_argument("--lr", type=float, default=DEFAULT_LR)
    parser.add_argument("--limit", type=int, default=None,
                        help="only read the first N testcases")
    parser.add_argument("--max-windows", type=int, default=400_000,
                        help="cap total windows (memory); 0 for no cap")
    parser.add_argument("--seed", type=int, default=20260806)
    parser.add_argument("--out", default=None,
                        help="where to write the artifact (default: dry run)")
    args = parser.parse_args(argv)

    _, neural_gate = _detector(args.detector)
    started = time.time()
    print("reading %s ..." % args.archive, flush=True)
    try:
        (train_x, train_y), (hold_x, hold_y), hold_rows, total = load(
            args.archive, args.detector, args.dim, args.limit,
            args.max_windows or None, args.seed)
    except TrainingError as error:
        print("%s" % error)
        return 1
    print("%d windows -> %d train / %d held-out (grouped by testcase)"
          % (total, len(train_x), len(hold_x)), flush=True)

    print("\ntraining ...", flush=True)
    model = train_float(train_x, train_y, args.hidden, args.epochs,
                        args.batch, args.lr, args.seed)
    hold_logits = float_logits(model, hold_x)
    float_auc = auc(hold_y, hold_logits)
    accuracy = float(np.mean((hold_logits > 0) == (hold_y == 1)) * 100)
    print("held-out: %.1f%% accuracy, AUC %.4f" % (accuracy, float_auc))

    # The control. Same architecture, same hyperparameters, labels shuffled.
    print("\ncontrol (shuffled labels) ...", flush=True)
    rng = np.random.default_rng(args.seed + 1)
    control = train_float(train_x, rng.permutation(train_y), args.hidden,
                          args.epochs, args.batch, args.lr, args.seed,
                          quiet=True)
    control_logits = float_logits(control, hold_x)
    control_accuracy = float(np.mean((control_logits > 0) == (hold_y == 1)) * 100)
    control_auc = auc(hold_y, control_logits)
    majority = float(max(hold_y.mean(), 1 - hold_y.mean()) * 100)
    print("control held-out: AUC %.4f (chance 0.5); %.2f%% accuracy against a "
          "%.2f%% majority baseline" % (control_auc, control_accuracy, majority))

    span = calibrate_span(hold_logits, neural_gate.WEIGHT_SCALE)
    artifact = quantise(model, neural_gate, span)

    print("\nverifying the integer copy ...", flush=True)
    check = verify_quantisation(artifact, hold_rows, hold_y, neural_gate,
                                float_auc)
    print("float AUC %.4f -> integer AUC %.4f (drop %.4f), %.1f%% saturated"
          % (check["float_auc"], check["integer_auc"], check["auc_drop"],
             check["saturated_fraction"] * 100))

    problems = []
    if check["auc_drop"] > MAX_QUANTISATION_AUC_DROP:
        problems.append("quantisation lost %.4f AUC (limit %.4f)"
                        % (check["auc_drop"], MAX_QUANTISATION_AUC_DROP))
    if not CONTROL_BAND[0] <= control_auc <= CONTROL_BAND[1]:
        problems.append("shuffled-label control AUC %.4f, outside %s -- the "
                        "features carry something other than the defect"
                        % (control_auc, CONTROL_BAND))
    if problems:
        print("\nREFUSED to write an artifact:")
        for problem in problems:
            print("  - %s" % problem)
        return 1

    artifact.update({
        "held_out_accuracy_percent": round(accuracy, 1),
        "held_out_auc": round(float_auc, 4),
        "shuffled_label_control_percent": round(control_accuracy, 2),
        "shuffled_label_control_auc": round(control_auc, 4),
        "held_out_majority_baseline_percent": round(majority, 2),
        "trained_examples": int(len(train_x)),
        "window_lines": WINDOW_LINES,
        "held_out_split": ("grouped by testcase, 80/20; no testcase "
                           "contributes windows to both sides"),
        "training_data": ("NIST Juliet/SARD single-file testcases, with the "
                          "comment, identifier, storage-class and filename "
                          "leaks removed by juliet_corpus"),
        "corpus_limitations": [
            "trained on Juliet, which is synthetic C/C++ whose defects are "
            "cleaner and more uniform than real ones",
            "a twelve-line window sees most of a Juliet function",
            "the label says which variant a window came from, not that the "
            "window is itself the defect",
        ],
    })
    # The digest is computed the way `load_model` computes it, so the artifact
    # verifies itself on load rather than carrying a number nobody checks.
    artifact["model_sha256"] = neural_gate.load_model(
        {k: v for k, v in artifact.items() if k != "model_sha256"}
    )["model_sha256"]

    print("\n%.0fs total" % (time.time() - started))
    if args.out:
        pathlib.Path(args.out).write_text(
            json.dumps(artifact, sort_keys=True), encoding="utf-8")
        print("wrote %s (sha %s)" % (args.out, artifact["model_sha256"][:16]))
    else:
        print("dry run; pass --out to write the artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
