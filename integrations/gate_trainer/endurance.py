#!/usr/bin/env python3
"""Warm starts and checkpoints, so a long training run survives the week.

Two problems, one file
----------------------
**Starting from noise throws away a working model.** The shipped gate is at
AUC 0.9994 on Juliet. Retraining it from scratch means spending hours to
rediscover what is already sitting in `neural_gate_model.json`, and a run that
is interrupted has nothing to show. Warm starting reads the quantised
artifact back into floats and continues from there: the old model teaches the
new one instead of being discarded.

That is only sound because the quantisation is nearly lossless in the first
place -- the trainer refuses to ship an artifact whose integer copy loses more
than 0.01 AUC, so dequantising it recovers weights within that same bound.
`dequantise` is exactly the inverse of `train_gate.quantise`, and there is a
round-trip test to keep it that way.

**A long run cannot depend on nothing going wrong.** The larger training in
this project took 8,673 seconds; a run measured in days will meet a reboot, a
power cut, or somebody closing the laptop. So state is written to disk every
few epochs, atomically, and a resumed run continues from the last checkpoint
rather than the beginning.

What a checkpoint has to contain
--------------------------------
Weights alone are not enough. Adam carries first and second moment estimates
whose scale depends on the step count, and the shuffling depends on the
generator's state. Restoring only the weights restarts the optimiser cold,
which shows up as a visible loss spike at every resume and makes a resumed run
score differently from an uninterrupted one. Everything that moves is saved.

The wall-clock budget
---------------------
`--max-hours` stops cleanly *before* its deadline rather than being killed at
it: the run finishes the epoch it is in, checkpoints, and exits with a status
saying it is resumable. A run stopped by the operating system mid-write would
leave a truncated checkpoint, which is why writes go to a temporary file and
are renamed into place.
"""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
from typing import Any

import numpy as np

SCHEMA = "attestor.gate-endurance/1.0"
VERSION = "4.2"

# Checkpoints are cheap relative to an epoch on a corpus this size, and the
# cost of losing an hour of training is much larger than the cost of writing.
DEFAULT_CHECKPOINT_EVERY = 2

# Leave time to finish the epoch in flight and write the final checkpoint.
SHUTDOWN_MARGIN_SECONDS = 300.0


class EnduranceError(RuntimeError):
    """A checkpoint or a warm start could not be used."""


# ---- warm start ----------------------------------------------------------- #

def dequantise(artifact: dict, weight_scale: int, feature_scale: int):
    """A shipped integer artifact back to the float parameters it came from.

    The exact inverse of `train_gate.quantise`. Getting the scales the wrong
    way round produces weights that are wrong by a factor of a thousand and
    still train -- badly, and without any error to say why -- so the round
    trip is tested rather than reasoned about.
    """
    for key in ("hidden_weights", "hidden_bias", "output_weights",
                "output_bias"):
        if key not in artifact:
            raise EnduranceError("artifact has no %s; it is not a gate" % key)

    hidden_weights = (np.asarray(artifact["hidden_weights"], dtype=np.float64).T
                      / weight_scale).astype(np.float32)
    hidden_bias = (np.asarray(artifact["hidden_bias"], dtype=np.float64)
                   / weight_scale).astype(np.float32)
    output_weights = (np.asarray(artifact["output_weights"], dtype=np.float64)
                      / weight_scale).astype(np.float32)
    output_bias = float(artifact["output_bias"]) / weight_scale
    return hidden_weights, hidden_bias, output_weights, output_bias


def warm_start(path: str, dim: int, hidden: int, weight_scale: int,
               feature_scale: int):
    """Load a teacher artifact, refusing one whose shape does not fit.

    A mismatched shape is refused rather than padded or truncated. Silently
    reshaping a trained model produces something that is neither the old model
    nor a fresh one, and the run would look like it inherited knowledge it did
    not.
    """
    source = pathlib.Path(path)
    if not source.is_file():
        raise EnduranceError("no artifact at %s" % path)
    artifact = json.loads(source.read_text(encoding="utf-8"))
    teacher_dim = int(artifact.get("feature_dim", 0))
    teacher_hidden = int(artifact.get("hidden", 0))
    if (teacher_dim, teacher_hidden) != (dim, hidden):
        raise EnduranceError(
            "teacher is %dx%d but this run is %dx%d; train at the teacher's "
            "shape or start cold" % (teacher_dim, teacher_hidden, dim, hidden))
    model = dequantise(artifact, weight_scale, feature_scale)
    return model, {"teacher": str(source),
                   "teacher_sha256": artifact.get("model_sha256", ""),
                   "teacher_accuracy": artifact.get(
                       "held_out_accuracy_percent")}


# ---- checkpoints ---------------------------------------------------------- #

def _atomic_write(path: pathlib.Path, payload: bytes) -> None:
    """Write via a temporary file in the same directory, then rename.

    A run killed part way through a plain write leaves a truncated file that
    parses as corrupt on resume -- which is precisely when it is needed.
    `os.replace` is atomic on POSIX and on Windows, so a reader sees either
    the old checkpoint or the new one and never half of either.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        dir=str(path.parent), prefix=path.name + ".", suffix=".part",
        delete=False)
    try:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(handle.name, path)
    except BaseException:
        pathlib.Path(handle.name).unlink(missing_ok=True)
        raise


def save_checkpoint(path: str, *, model, moments, velocities, moment_out,
                    velocity_out, step: int, epoch: int, rng: np.random.Generator,
                    settings: dict[str, Any], history: list) -> None:
    """Everything that moves, so a resume is indistinguishable from not stopping."""
    weights_hidden, bias_hidden, weights_out, bias_out = model
    buffer = io_bytes = None
    import io as _io
    buffer = _io.BytesIO()
    np.savez(
        buffer,
        weights_hidden=weights_hidden, bias_hidden=bias_hidden,
        weights_out=weights_out, bias_out=np.float32(bias_out),
        moment_hidden=moments[0], moment_bias=moments[1], moment_out_w=moments[2],
        velocity_hidden=velocities[0], velocity_bias=velocities[1],
        velocity_out_w=velocities[2],
        moment_out=np.float32(moment_out), velocity_out=np.float32(velocity_out),
    )
    payload = {
        "schema": SCHEMA, "version": VERSION,
        "step": int(step), "epoch": int(epoch),
        # The generator's bit state, so the next shuffle is the one the
        # uninterrupted run would have produced.
        "rng_state": _encode_rng(rng),
        "settings": settings,
        "history": history,
        "arrays_npz_b64": _b64(buffer.getvalue()),
        "written": time.time(),
    }
    _atomic_write(pathlib.Path(path),
                  json.dumps(payload).encode("utf-8"))


def load_checkpoint(path: str):
    """A checkpoint back into training state, or a clear refusal."""
    source = pathlib.Path(path)
    if not source.is_file():
        raise EnduranceError("no checkpoint at %s" % path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except ValueError as error:
        raise EnduranceError(
            "checkpoint at %s is not readable JSON (%s); it was probably "
            "written by a run that was killed mid-write, which the atomic "
            "rename is meant to prevent" % (path, error)) from error
    if payload.get("schema") != SCHEMA:
        raise EnduranceError("checkpoint schema is %r, expected %r"
                             % (payload.get("schema"), SCHEMA))

    import io as _io
    arrays = np.load(_io.BytesIO(_unb64(payload["arrays_npz_b64"])))
    model = (arrays["weights_hidden"], arrays["bias_hidden"],
             arrays["weights_out"], float(arrays["bias_out"]))
    moments = [arrays["moment_hidden"], arrays["moment_bias"],
               arrays["moment_out_w"]]
    velocities = [arrays["velocity_hidden"], arrays["velocity_bias"],
                  arrays["velocity_out_w"]]
    rng = np.random.default_rng()
    rng.bit_generator.state = payload["rng_state"]
    return {
        "model": model, "moments": moments, "velocities": velocities,
        "moment_out": float(arrays["moment_out"]),
        "velocity_out": float(arrays["velocity_out"]),
        "step": int(payload["step"]), "epoch": int(payload["epoch"]),
        "rng": rng, "settings": payload.get("settings", {}),
        "history": payload.get("history", []),
    }


def _encode_rng(rng: np.random.Generator) -> dict:
    state = rng.bit_generator.state
    return json.loads(json.dumps(state, default=_jsonable))


def _jsonable(value):
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    raise TypeError("cannot serialise %r into a checkpoint" % type(value))


def _b64(raw: bytes) -> str:
    import base64
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    import base64
    return base64.b64decode(text.encode("ascii"))


# ---- the wall-clock budget ------------------------------------------------ #

class Budget:
    """A deadline that is reached deliberately rather than survived.

    `should_stop` is asked between epochs, and answers yes while there is
    still time to finish the epoch in progress and write a checkpoint. A run
    that instead ran until it was killed would lose that epoch and might lose
    the checkpoint as well.
    """

    def __init__(self, max_hours: float | None,
                 margin: float = SHUTDOWN_MARGIN_SECONDS):
        self.started = time.time()
        self.limit = None if max_hours is None else float(max_hours) * 3600.0
        self.margin = margin

    @property
    def elapsed(self) -> float:
        return time.time() - self.started

    def should_stop(self, epoch_seconds: float = 0.0) -> bool:
        if self.limit is None:
            return False
        # Room for one more epoch *and* the final write, not just the write.
        return self.elapsed + epoch_seconds + self.margin >= self.limit

    def report(self) -> dict:
        return {"elapsed_seconds": round(self.elapsed, 1),
                "limit_seconds": self.limit,
                "remaining_seconds": (None if self.limit is None
                                      else round(self.limit - self.elapsed, 1))}
