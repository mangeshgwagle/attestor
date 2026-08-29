#!/usr/bin/env python3
"""Reasoning for Attestor, in the only shape his design allows.

The constraint
--------------
``MODEL_INTEGRATION_4.1.4.md`` says a model may produce evidence, never a
verdict. That is not a style preference -- it was measured. A local model
asked to *judge* a finding flipped from six rejections to six acceptances on
nothing but a change of prompt wording. Anything built on top of that
judgement inherits its instability.

So "add reasoning" cannot mean "let the model decide". It means: let something
reason, then check the result. `external_gate` already does the checking half
-- disposable copies, rescan against baseline, assurance probes, rollback --
and it never cared where a candidate came from. What was missing is the loop.

What the loop adds
------------------
A single proposal is a guess. A proposal, a *reason it was rejected*, and
another attempt is reasoning: the model is told what Attestor found wrong and
tries again against that. Convergence comes from the feedback, not from the
model being clever, which is why a weak generator is worth running here at
all::

    goal + source ──▶ model ──▶ candidate
                                    │
                        external_gate.review
                                    │
             accepted ◀─────────────┴──────────▶ rejected
                                                     │
                              "you introduced py-eq-none at line 4"
                                                     │
                                                     └──▶ next attempt

Every rejection is specific and comes from a rule, not from an opinion. That
is what the model gets to reason *about*.

The bound that makes it safe to run
-----------------------------------
Attempts are capped. A model that never succeeds costs a fixed, known amount
and then stops -- there is no path here where a confident wrong answer gets
applied because the loop ran out of patience. Rejection is the default and
acceptance is the exception that has to be earned.

What this is not
----------------
It is not a proof. `external_gate`'s own docstring is blunt about this: a
patch that is plausible and wrong in a way no rule catches will pass, and the
probes bound the failure surface rather than eliminating it. Accepted results
are marked as machine-guessed for exactly that reason.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request

SCHEMA = "attestor.reason/1.0"
VERSION = "4.1.4"

DEFAULT_ROUNDS = 4
MAX_SOURCE_BYTES = 64 * 1024

PROMPT = """\
You are rewriting one file to satisfy a goal. Attestor, a static analyser, will
check your answer and reject it if it introduces any defect.

GOAL:
%s

FILE (%s):
```
%s
```
%s
Reply with the complete rewritten file inside one fenced block, and nothing
else. Do not explain.
"""

REJECTION = """
Your previous attempt was REJECTED. Attestor's reasons, which come from rules and
not from opinion:
%s

Fix those specifically. Everything else that already passed must stay passing.
"""


class ReasonError(RuntimeError):
    """The loop could not run."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply_candidate(path: str, report: dict) -> pathlib.Path:
    """Atomically apply a source-bound accepted candidate and retain a backup."""
    if not report.get("solved") or not isinstance(report.get("candidate"), str):
        raise ReasonError("there is no accepted candidate to apply")
    target = pathlib.Path(path)
    try:
        before = target.lstat()
    except OSError as error:
        raise ReasonError("target is unavailable") from error
    attributes = int(getattr(before, "st_file_attributes", 0) or 0)
    if (not stat.S_ISREG(before.st_mode) or target.is_symlink()
            or attributes & 0x400):
        raise ReasonError("target must be a regular non-linked file")

    try:
        original = target.read_bytes()
    except OSError as error:
        raise ReasonError("target could not be read") from error
    expected_original = report.get("original_sha256")
    if not isinstance(expected_original, str) or _sha256(original) != expected_original:
        raise ReasonError("target changed after the candidate was reviewed")

    candidate = report["candidate"].encode("utf-8")
    expected_candidate = report.get("candidate_sha256")
    if not isinstance(expected_candidate, str) or _sha256(candidate) != expected_candidate:
        raise ReasonError("accepted candidate digest does not match its report")

    backup_dir = target.parent / ".attestor-backups"
    if backup_dir.exists() and (backup_dir.is_symlink() or not backup_dir.is_dir()):
        raise ReasonError("backup location is not a regular directory")
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    backup = backup_dir / (target.name + "." + expected_original[:16] + ".bak")
    try:
        descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            if _sha256(backup.read_bytes()) != expected_original:
                raise ReasonError("existing backup does not match the reviewed source")
        except OSError as error:
            raise ReasonError("existing backup could not be verified") from error
    except OSError as error:
        raise ReasonError("backup could not be created") from error
    else:
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(original)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            raise ReasonError("backup could not be persisted") from error

    temp_descriptor, temp_name = tempfile.mkstemp(
        prefix=".attestor-reason-", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(temp_descriptor, "wb", closefd=True) as handle:
            handle.write(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, stat.S_IMODE(before.st_mode))
        current = target.read_bytes()
        current_info = target.lstat()
        if (_sha256(current) != expected_original
                or (current_info.st_dev, current_info.st_ino)
                != (before.st_dev, before.st_ino)):
            raise ReasonError("target changed while the candidate was staged")
        os.replace(temp_name, target)
        temp_name = ""
        if _sha256(target.read_bytes()) != expected_candidate:
            os.replace(backup, target)
            raise ReasonError("applied candidate failed digest verification; restored backup")
    except ReasonError:
        raise
    except OSError as error:
        raise ReasonError("candidate could not be applied atomically") from error
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
    return backup


# ---- model backends ------------------------------------------------------- #

class Backend:
    """Anything that turns a prompt into a candidate file."""

    name = "backend"

    def propose(self, prompt: str) -> str:      # pragma: no cover - interface
        raise NotImplementedError


class LocalBackend(Backend):
    """A llama.cpp server already running, via `attestor_chat`.

    Free and slow. Measured on this project's hardware: about 86 seconds per
    reply for a 9B at Q5. Four rounds is therefore a six-minute operation, and
    the loop's bound matters more than it would with a fast model.
    """

    name = "local"

    def __init__(self, port: int = 8099):
        self._port = port

    def propose(self, prompt: str) -> str:
        here = pathlib.Path(__file__).resolve().parent.parent / "attestor_chat"
        sys.path.insert(0, str(here))
        import attestor_chat

        return attestor_chat.ask(self._port, [
            {"role": "system", "content": "You rewrite files. You reply with "
                                          "one fenced code block and nothing "
                                          "else."},
            {"role": "user", "content": prompt},
        ], max_tokens=2000)


class AnthropicBackend(Backend):
    """The Claude API, over the standard library.

    The key is read from the environment and never from an argument, so it
    cannot end up in a shell history, a process listing, or one of this
    module's own transcripts.
    """

    name = "anthropic"
    ENDPOINT = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: str = "claude-sonnet-5"):
        self._key = os.environ.get("ANTHROPIC_API_KEY")
        if not self._key:
            raise ReasonError(
                "ANTHROPIC_API_KEY is not set; export it yourself rather than "
                "passing it on a command line")
        self._model = model

    def propose(self, prompt: str) -> str:
        body = json.dumps({
            "model": self._model,
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        request = urllib.request.Request(
            self.ENDPOINT, data=body,
            headers={"content-type": "application/json",
                     "x-api-key": self._key,
                     "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(request, timeout=180) as reply:
                payload = json.loads(reply.read().decode())
        except (urllib.error.URLError, ValueError) as error:
            raise ReasonError("the API did not answer: %s" % error) from error
        parts = [block.get("text", "") for block in payload.get("content", [])
                 if block.get("type") == "text"]
        return "\n".join(parts)


def extract_source(reply: str) -> str:
    """The file out of a model reply, or a clear refusal."""
    fence = reply.find("```")
    if fence == -1:
        raise ReasonError("no fenced block in the reply")
    start = reply.find("\n", fence)
    end = reply.find("```", start)
    if start == -1 or end == -1:
        raise ReasonError("unterminated fenced block")
    return reply[start + 1:end]


# ---- the loop ------------------------------------------------------------- #

def solve(path: str, goal: str, backend: Backend, detector: str,
          rounds: int = DEFAULT_ROUNDS) -> dict:
    """Propose, verify, feed the rejection back, repeat -- or give up."""
    sys.path.insert(0, detector)
    import detect
    import external_gate

    target = pathlib.Path(path)
    try:
        original_bytes = target.read_bytes()
        original = original_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ReasonError("target must be a readable UTF-8 source file") from error
    if len(original_bytes) > MAX_SOURCE_BYTES:
        raise ReasonError("%s is %d bytes; too large to round-trip"
                          % (path, len(original_bytes)))

    language = (detect.language_for(str(target))
                if hasattr(detect, "language_for") else "python")
    findings = detect.scan_source(original, str(target), language, deep=True)

    transcript: list[dict] = []
    complaint = ""
    for attempt in range(1, rounds + 1):
        prompt = PROMPT % (goal, target.name, original[:MAX_SOURCE_BYTES],
                           complaint)
        started = time.time()
        try:
            candidate = extract_source(backend.propose(prompt))
        except ReasonError as error:
            transcript.append({"attempt": attempt, "error": str(error)[:200],
                               "seconds": round(time.time() - started)})
            complaint = REJECTION % ("- your reply was unreadable: %s"
                                     % str(error)[:120])
            continue

        review = external_gate.review(str(target), original, candidate,
                                      findings, origin="attestor-reason/%s"
                                                       % backend.name)
        record = {"attempt": attempt,
                  "seconds": round(time.time() - started),
                  "accepted": review.accepted,
                  "resolved": list(review.resolved),
                  "introduced": list(review.introduced),
                  "reasons": list(review.reasons),
                  "candidate_sha256": review.candidate_sha256}
        transcript.append(record)

        if review.accepted:
            return {"schema": SCHEMA, "version": VERSION, "target": str(target),
                    "goal": goal, "backend": backend.name, "solved": True,
                    "attempts": attempt, "transcript": transcript,
                     "unified_diff": review.unified_diff,
                     "candidate": candidate,
                     "original_sha256": _sha256(original_bytes),
                     "candidate_sha256": review.candidate_sha256,
                    # Marked, always: a human reading this should know a
                    # machine guessed and a verifier merely failed to object.
                    "deterministic": False}

        # The whole point of the loop: the next attempt is told exactly what a
        # rule objected to, rather than being asked to try harder.
        complaint = REJECTION % "\n".join(
            "- %s" % reason for reason in review.reasons) or "- rejected"

    return {"schema": SCHEMA, "version": VERSION, "target": str(target),
            "goal": goal, "backend": backend.name, "solved": False,
            "attempts": rounds, "transcript": transcript,
            "deterministic": False}


def main(argv: list[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", help="the file to rewrite")
    parser.add_argument("--goal", required=True, help="what it should achieve")
    parser.add_argument("--backend", choices=("local", "anthropic"),
                        default="local")
    parser.add_argument("--model", default="claude-sonnet-5")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--apply", action="store_true",
                        help="write the accepted result back to the file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        backend = (AnthropicBackend(args.model) if args.backend == "anthropic"
                   else LocalBackend(args.port))
        report = solve(args.path, args.goal, backend, args.detector,
                       args.rounds)
    except ReasonError as error:
        print("attestor-reason: %s" % error, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({k: v for k, v in report.items()
                          if k != "candidate"}, indent=2))
    else:
        print("%s  %s  backend=%s" % (VERSION, report["target"],
                                      report["backend"]))
        for record in report["transcript"]:
            if "error" in record:
                print("  attempt %d: unreadable (%s)"
                      % (record["attempt"], record["error"][:60]))
                continue
            print("  attempt %d: %s in %ds"
                  % (record["attempt"],
                     "ACCEPTED" if record["accepted"] else "rejected",
                     record["seconds"]))
            for reason in record["reasons"][:4]:
                print("      %s" % reason[:88])
        print("\n%s after %d attempt(s)"
              % ("solved" if report["solved"] else "not solved",
                 report["attempts"]))

    if args.apply and report["solved"]:
        try:
            backup = apply_candidate(args.path, report)
        except ReasonError as error:
            print("attestor-reason: apply refused: %s" % error, file=sys.stderr)
            return 2
        print("written to %s; verified backup: %s "
              "(machine-guessed; review the diff)" % (args.path, backup))
    return 0 if report["solved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
