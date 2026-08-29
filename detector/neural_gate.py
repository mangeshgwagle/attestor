#!/usr/bin/env python3
"""A small trained network Attestor can run without leaving his own guarantees.

This is the Phase 1 shape described in ``MODEL_INTEGRATION_4.1.4.md``: a model
may produce evidence, never a verdict, and its output never enters the payload
Truth Guard verifies.  Everything here obeys that.

Why it looks like this
----------------------
Neural inference is normally not bit-reproducible -- kernel choice, thread
count, BLAS backend and floating-point non-associativity all move the result,
and Attestor targets aarch64, armv7l and x86-64.  A report whose digest depends on
which machine produced it would make replay verification meaningless.

So the network is trained offline in floating point, then **quantised to
integers**, and every operation below is integer arithmetic:

* features are integer counts scaled by ``FEATURE_SCALE`` using floor division;
* weights are integers scaled by ``WEIGHT_SCALE``;
* the hidden layer is ReLU, which is exact on integers;
* the output squash is a piecewise-linear integer curve, not a sigmoid.

There is no floating-point value anywhere in the inference path, so the same
source yields the same score on every supported platform, bit for bit.

Token hashing uses FNV-1a rather than ``hash()``: CPython randomises string
hashing per process, which would make the features -- and therefore the score
-- differ between runs of the same binary.

What the score is not
---------------------
It is a *learned opinion* about whether a fragment resembles the defective side
of the corpus the artifact was trained on -- named in the artifact itself, and
reported with every score.  It is not a probability, not a finding, and not
evidence that code is safe.  A high score means "worth a human look", and a low
score means nothing at all.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Iterable, Mapping

SCHEMA = "attestor.neural-gate/1.0"
VERSION = "4.1.4"

# 160 hashed buckets over token unigrams, bigrams and trigrams.  These numbers
# were measured, not chosen: on the same windows with the same seed, held-out
# accuracy was 0.696 for 64 buckets of unigrams+bigrams, 0.799 at 96, and 0.918
# at 160 with trigrams added.  Two variants that looked promising made it
# *worse* -- an AST node histogram (0.706) and doubling the hidden layer
# (0.649, overfitting 966 examples) -- so neither is here.
FEATURE_DIM = 160
TOKEN_BUCKETS = FEATURE_DIM
HIDDEN = 16
FEATURE_SCALE = 1_000
WEIGHT_SCALE = 1_024
SCORE_SCALE = 10_000
MAX_SOURCE_BYTES = 256 * 1024

# The width above is this module's default, not a law.  A model artifact
# carries its own `feature_dim` and `hidden`, and inference reads them from the
# artifact so a larger model can be dropped in without touching the code that
# runs it.
#
# Since inference skips zero features (see `sparse_features`), the cost of a
# fragment is `nnz * hidden`, not `feature_dim * hidden` -- roughly 90 non-zero
# buckets for a four-line window however wide the vector is.  Width is
# therefore close to free and only `hidden` trades against scan time.  The
# ceilings below are what pure Python can still run at scan speed.
#
# Measured on 40,519 Juliet testcase pairs with a testcase-grouped split, held-
# out AUC by size was 0.9604 at 2,593 parameters, 0.9830 at 65,665, 0.9837 at
# 262,401, and 0.9838 at both 786,817 and 983,521.  The curve is flat past
# roughly 65k: capacity is not what limits this model.  So the shipped artifact
# sits at the knee rather than at the ceiling, and raising these numbers will
# not buy accuracy.
#
# Nor was hashing the limit -- collisions are 2.4% at 2,048 buckets and 1.9% at
# 4,096, so widening the vector buys almost nothing.  What limited it was
# *distance*: a four-line window cannot hold a `free()` and the use twelve lines
# below it.  On identical budgets and the same grouped split, held-out AUC by
# window was 0.9814 at four lines, 0.9948 at eight and 0.9979 at twelve, with a
# shuffled-label control of 0.5006 at twelve confirming the gain is not leakage.
# The shipped artifact is trained at twelve lines and `window_lines` travels
# inside it, so callers cut windows to whatever width the model was fitted for.
MAX_FEATURE_DIM = 4_096
MAX_HIDDEN = 512
MAX_PARAMETERS = 1_000_000

INFERRED = "inferred"

_FNV_OFFSET = 0x811C9DC5
_FNV_PRIME = 0x01000193
_MASK32 = 0xFFFFFFFF

_IDENT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
_BRANCH_WORDS = frozenset({"if", "elif", "else", "for", "while", "try",
                           "except", "with", "and", "or", "not"})


class NeuralGateError(ValueError):
    """The model artifact or the supplied source is unusable."""


def _fnv1a(text: str) -> int:
    """Deterministic 32-bit hash. `hash()` is randomised and unusable here."""
    value = _FNV_OFFSET
    for byte in text.encode("utf-8", "replace"):
        value = ((value ^ byte) * _FNV_PRIME) & _MASK32
    return value


# Source code repeats itself: the same identifiers, keywords and punctuation
# recur constantly, and hashing them is a per-byte Python loop.  Memoising is
# safe because FNV-1a is a pure function of the text -- the cache changes how
# long a score takes and cannot change what it is.  Bounded so that scanning a
# large tree cannot turn the cache into the memory problem.
_HASH_CACHE: dict[str, int] = {}
_HASH_CACHE_LIMIT = 200_000


def _hashed(text: str) -> int:
    value = _HASH_CACHE.get(text)
    if value is None:
        value = _fnv1a(text)
        if len(_HASH_CACHE) >= _HASH_CACHE_LIMIT:
            _HASH_CACHE.clear()
        _HASH_CACHE[text] = value
    return value


def tokenize(source: str) -> list[str]:
    """Cheap language-agnostic lexing: identifiers, numbers, and operators."""
    tokens: list[str] = []
    index, length = 0, len(source)
    while index < length:
        char = source[index]
        if char in " \t\r\n":
            index += 1
        elif char in _IDENT:
            start = index
            while index < length and source[index] in _IDENT:
                index += 1
            tokens.append(source[start:index])
        else:
            tokens.append(char)
            index += 1
    return tokens


def features(source: str, dim: int = FEATURE_DIM) -> list[int]:
    """A fixed-width integer feature vector. Deterministic on every platform.

    Trigrams are what make this work.  A defect is usually a short local
    pattern -- ``verify = False``, ``strcpy ( dst`` -- and a unigram bag cannot
    represent adjacency at all.  Adding ordered pairs and triples is what took
    held-out accuracy from 0.696 to 0.918 without touching model size.
    """
    if type(source) is not str:
        raise NeuralGateError("source must be text")
    if type(dim) is not int or isinstance(dim, bool) or \
            not 1 <= dim <= MAX_FEATURE_DIM:
        raise NeuralGateError("feature_dim out of range")
    return _dense(_counted(source, dim), dim)


def _counted(source: str, dim: int) -> tuple[dict[int, int], int]:
    """{bucket: count} and the token total, touching only occupied buckets."""
    tokens = tokenize(source[:MAX_SOURCE_BYTES])
    counts: dict[int, int] = {}
    last = len(tokens) - 1
    for position, token in enumerate(tokens):
        key = _hashed(token) % dim
        counts[key] = counts.get(key, 0) + 1
        if position < last:
            key = _hashed("\x00".join(tokens[position:position + 2])) % dim
            counts[key] = counts.get(key, 0) + 1
        if position + 1 < last:
            key = _hashed("\x01".join(tokens[position:position + 3])) % dim
            counts[key] = counts.get(key, 0) + 1
    return counts, max(1, len(tokens))


def _dense(counted: tuple[dict[int, int], int], dim: int) -> list[int]:
    # Normalise by token count with floor division so a long file and a short
    # one are comparable, and so the result is identical on every platform.
    counts, total = counted
    vector = [0] * dim
    for index, count in counts.items():
        vector[index] = (count * FEATURE_SCALE) // total
    return vector


def sparse_features(source: str, dim: int = FEATURE_DIM) -> list[tuple[int, int]]:
    """The same vector as `features`, as (index, value) for non-zero entries.

    A four-line window has on the order of 90 non-zero buckets however wide the
    vector is, because the count of hashed n-grams depends on the token count
    and not on `dim`.  Skipping the zeros is therefore not an approximation --
    a zero feature contributes exactly `weight * 0` to every hidden unit -- but
    it changes the cost of inference from `dim * hidden` to `nnz * hidden`.

    That is what makes a wide model affordable here.  Widening the vector only
    reduces hash collisions; it no longer costs anything at scan time, so the
    width can be set by accuracy alone and `hidden` is the only dimension that
    trades against speed.
    """
    counts, total = _counted(source, dim)
    # Straight from the occupied buckets: building the dense vector first and
    # then scanning all `dim` entries to drop the zeros costs O(dim) per
    # fragment for an answer that is O(nnz) long.
    return [(index, (count * FEATURE_SCALE) // total)
            for index, count in sorted(counts.items())
            if (count * FEATURE_SCALE) // total]


def _squash(value: int, span: int) -> int:
    """Piecewise-linear integer curve mapping a logit onto 0..SCORE_SCALE.

    A real sigmoid would reintroduce floating point, which is exactly what this
    module exists to avoid.  Monotonicity is all the caller needs -- the score
    orders candidates, it does not claim to be a probability.

    ``span`` is calibrated when the model is trained and travels inside the
    artifact.  A hardcoded span is worse than useless: the first one here was
    six times too narrow and saturated 87% of scores at the maximum, which
    silently destroys the ordering the score exists to provide.
    """
    span = max(1, span)
    half = SCORE_SCALE // 2
    if value <= -span:
        return 0
    if value >= span:
        return SCORE_SCALE
    return half + (value * half) // span


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate(model: Mapping[str, Any]) -> None:
    if not isinstance(model, Mapping):
        raise NeuralGateError("model must be a mapping")
    if model.get("schema") != SCHEMA:
        raise NeuralGateError("unexpected model schema")
    # Shape is whatever the artifact declares, inside fixed ceilings.  Defaults
    # keep the original 160-16 model loadable unchanged.
    dim = model.get("feature_dim", FEATURE_DIM)
    width = model.get("hidden", HIDDEN)
    for name, value, ceiling in (("feature_dim", dim, MAX_FEATURE_DIM),
                                 ("hidden", width, MAX_HIDDEN)):
        if type(value) is not int or isinstance(value, bool) or \
                not 1 <= value <= ceiling:
            raise NeuralGateError(f"{name} must be an integer in 1..{ceiling}")
    if dim * width + 2 * width + 1 > MAX_PARAMETERS:
        raise NeuralGateError("model exceeds the pure-Python inference budget")
    hidden = model.get("hidden_weights")
    if type(hidden) is not list or len(hidden) != width:
        raise NeuralGateError("hidden layer has the wrong shape")
    for row in hidden:
        if type(row) is not list or len(row) != dim or \
                any(type(item) is not int for item in row):
            raise NeuralGateError("hidden weights must be integer rows")
    for name, size in (("hidden_bias", width), ("output_weights", width)):
        row = model.get(name)
        if type(row) is not list or len(row) != size or \
                any(type(item) is not int for item in row):
            raise NeuralGateError(f"{name} must be {size} integers")
    if type(model.get("output_bias")) is not int:
        raise NeuralGateError("output_bias must be an integer")
    span = model.get("logit_span")
    if type(span) is not int or isinstance(span, bool) or span < 1:
        raise NeuralGateError("logit_span must be a positive integer")


# Validation walks every weight and then re-hashes the whole artifact, which is
# the right thing to do once and ruinous to do per fragment: at 160x16 it cost
# little enough to go unnoticed, but at 262,401 parameters it was 98% of the
# time to score a window (78ms, against 1.5ms of actual arithmetic).
#
# The cache is keyed on the *object*, never on the digest the artifact claims.
# Keying on the claimed digest was tried and is unsafe: a tampered artifact
# asserting a digest it does not own hits the entry, is handed back the verified
# weights, and no error is raised -- so the tampering is silently ignored rather
# than refused, which is the opposite of how everything else here behaves.
#
# A strong reference to the mapping is kept alongside the result so its `id`
# cannot be recycled onto a different object.  The residual gap is a caller that
# mutates an already-validated mapping in place; that needs code execution
# inside the process, by which point the digest was never the thing protecting
# anyone.
_RESOLVED: dict[int, tuple[Mapping[str, Any], dict[str, Any]]] = {}
_RESOLVED_LIMIT = 8


def load_model(model: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a model artifact and bind its identity."""
    cached = _RESOLVED.get(id(model))
    if cached is not None and cached[0] is model:
        return cached[1]
    _validate(model)
    body = {key: value for key, value in model.items()
            if key != "model_sha256"}
    resolved = dict(body)
    resolved["model_sha256"] = _sha(body)
    if "model_sha256" in model and model["model_sha256"] != resolved["model_sha256"]:
        raise NeuralGateError("model digest does not match its weights")
    if len(_RESOLVED) >= _RESOLVED_LIMIT:
        _RESOLVED.clear()
    _RESOLVED[id(model)] = (model, resolved)
    return resolved


# Feature-major weights, derived not declared.  They are kept out of the
# resolved model on purpose: `default_model()` hands its result back to callers
# who may load it again, and any key added here would be folded into the digest
# and fail the very integrity check this module exists to pass.
_TRANSPOSED: dict[str, tuple[tuple[int, ...], ...]] = {}


def _by_feature(resolved: Mapping[str, Any]) -> tuple[tuple[int, ...], ...]:
    """Rows indexed by feature. Cached against the digest already verified."""
    digest = resolved["model_sha256"]
    cached = _TRANSPOSED.get(digest)
    if cached is None:
        rows = resolved["hidden_weights"]
        width = resolved.get("feature_dim", FEATURE_DIM)
        cached = tuple(tuple(row[index] for row in rows)
                       for index in range(width))
        if len(_TRANSPOSED) >= _RESOLVED_LIMIT:
            _TRANSPOSED.clear()
        _TRANSPOSED[digest] = cached
    return cached


def infer(source: str, model: Mapping[str, Any]) -> dict[str, Any]:
    """Score one fragment. Integer arithmetic only, start to finish."""
    resolved = load_model(model)
    vector = sparse_features(source, resolved.get("feature_dim", FEATURE_DIM))
    # Both layers keep their activations scaled by WEIGHT_SCALE.  The bias is
    # already at that scale, so only the weighted sum gets divided down --
    # folding the bias into the division would shrink it by FEATURE_SCALE and
    # silently produce a different model from the one that was trained.
    by_feature = _by_feature(resolved)
    sums = [0] * len(resolved["hidden_bias"])
    for index, value in vector:
        row = by_feature[index]
        sums = [total + weight * value for total, weight in zip(sums, row)]
    hidden = []
    for bias, total in zip(resolved["hidden_bias"], sums):
        total = bias + total // FEATURE_SCALE
        hidden.append(total if total > 0 else 0)          # ReLU, exact
    logit = 0
    for weight, activation in zip(resolved["output_weights"], hidden):
        logit += weight * activation
    logit = resolved["output_bias"] + logit // WEIGHT_SCALE
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "score": _squash(logit, resolved["logit_span"]),
        "scale": SCORE_SCALE,
        "logit": logit,
        "model_sha256": resolved["model_sha256"],
        "evidence_state": INFERRED,
        "arithmetic": "integer-only",
        # The first two hold for any model this module will ever load.  The
        # third is a property of the corpus, so it travels in the artifact --
        # leaving it hardcoded meant the caveat kept naming synthetic mutations
        # after the gate had been retrained on Juliet ground truth.
        "limitations": [
            "a learned opinion, not a probability and not a finding",
            "a low score is not evidence that the code is safe",
        ] + list(resolved.get("corpus_limitations", [
            "trained on synthetic mutations; it learns the mutators as much as "
            "it learns defects",
        ])),
    }


def evidence(source: str, model: Mapping[str, Any], *,
             path: str = "", line: int = 0) -> dict[str, Any]:
    """Wrap a score as an ``inferred`` evidence item.

    Deliberately not a finding: adjudication414 will leave an inferred item
    ``insufficient`` until something decisive corroborates it, which is the
    behaviour this module wants.
    """
    result = infer(source, model)
    return {
        "source_engine": "neural-gate/1.0",
        "evidence_state": INFERRED,
        "path": path[:320] if type(path) is str else "",
        "line": line if type(line) is int and not isinstance(line, bool) else 0,
        "score": result["score"],
        "scale": SCORE_SCALE,
        "model_sha256": result["model_sha256"],
        "supports_finding": False,
        "limitations": result["limitations"],
    }


def batch(sources: Iterable[str], model: Mapping[str, Any]) -> list[dict[str, Any]]:
    resolved = load_model(model)
    return [infer(text, resolved) for text in sources]


MODEL_FILENAME = "neural_gate_model.json"
_DEFAULT: dict[str, Any] | None = None


def default_model() -> dict[str, Any]:
    """The shipped artifact, loaded once and identity-checked.

    Kept out of import time on purpose: nothing in Attestor's default coding path
    needs this module, and a scan should not pay for a model it never calls.
    """
    global _DEFAULT
    if _DEFAULT is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            MODEL_FILENAME)
        try:
            with open(path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError) as exc:
            raise NeuralGateError("model artifact is unreadable") from exc
        _DEFAULT = load_model(raw)
    return _DEFAULT


def model_card() -> dict[str, Any]:
    """What this model is, what it scored, and what it must not be used for."""
    resolved = default_model()
    dim = resolved.get("feature_dim", FEATURE_DIM)
    width = resolved.get("hidden", HIDDEN)
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "model_sha256": resolved["model_sha256"],
        "architecture": "%d-%d-1 MLP, ReLU hidden, integer inference"
                        % (dim, width),
        "parameters": dim * width + 2 * width + 1,
        "trained_examples": resolved.get("trained_examples", 0),
        "held_out_accuracy_percent": resolved.get(
            "held_out_accuracy_percent", 0),
        "training_data": resolved.get(
            "training_data",
            "mutation corpus windows: an injected defect and the same window "
            "without it"),
        "intended_use": "ordering candidates for human review",
        "not_for": [
            "creating, promoting or suppressing a finding",
            "satisfying an authorization or repair permission",
            "any claim that unflagged code is safe",
        ],
        "held_out_split": resolved.get("held_out_split", "unrecorded"),
        "shuffled_label_control_percent": resolved.get(
            "shuffled_label_control_percent"),
        "known_weaknesses": [
            "the deterministic rules detect these same defects at 100%; this "
            "model is materially worse and exists to rank, not to detect",
            "balanced training data; scores are not calibrated to any real "
            "base rate",
        ] + list(resolved.get("corpus_limitations", [
            "trained on synthetic single-token mutations, so it partly learns "
            "the mutator catalog rather than defects in general",
        ])),
    }


__all__ = [
    "SCHEMA", "VERSION", "FEATURE_DIM", "HIDDEN", "FEATURE_SCALE",
    "WEIGHT_SCALE", "SCORE_SCALE", "INFERRED", "MODEL_FILENAME",
    "NeuralGateError", "tokenize", "features", "load_model", "infer",
    "evidence", "batch", "default_model", "model_card",
]
