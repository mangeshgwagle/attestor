#!/usr/bin/env python3
"""Let a local model propose detection rules, and let Attestor throw them out.

What this is, and what it is not
--------------------------------
It is not training a model. The weights here are GGUF -- a quantised inference
format -- and nothing in this file adjusts a parameter. What is trained is
*Attestor*, who is a rule engine, and the way to train a rule engine is to add
rules that survive being measured.

So the model does the one thing it is good at and the one thing that does not
require trusting it: it *proposes*. It reads flawed and fixed variants of the
same function and guesses at a pattern that separates them. Attestor then tests
that guess against ground truth the model never saw, and almost always throws
it away.

    flawed / fixed windows ──▶ model ──▶ candidate pattern
                                              │
                              held-out split ─┴─▶ accept or discard

This is the same division `advisory41` draws for single findings and
`external_gate` draws for patches, for the same measured reason: asked to
*judge*, these models flipped from six rejections to six acceptances on nothing
but a change of prompt wording. Asked to *produce something checkable*, they
are useful, because the check is what carries the weight.

Why the held-out split is the whole design
------------------------------------------
Judging a proposed rule by the examples it was proposed from measures nothing
-- the model has seen them, and a regex that memorises four samples is trivial
to write and worthless. Worse, it is not obviously worthless: during this
project three hand-written rules (CWE-369, CWE-252, CWE-253) looked correct on
their training families and scored **zero** on held-out data, because Juliet's
families use different idioms for the same defect. Each one had to be found by
measurement, never by reading.

The split is grouped by testcase, not random. Juliet's two variants of a
testcase are near-identical text; a random split puts them on opposite sides
and the held-out score becomes a memorisation score. `juliet_corpus.group_split`
already does this correctly and is used unchanged.

The acceptance bar
------------------
Zero false positives on held-out data, and a floor on recall. Zero is not
perfectionism -- it is what every rule shipped in this project has met but one,
and a rule that fires on corrected code teaches users to ignore Attestor, which
costs more than the defects it catches.

The honest limit
----------------
A pattern that discriminates on Juliet discriminates on *Juliet*. Its families
are synthetic and narrow, so a surviving candidate is a lead worth a human
reading, not a rule that is finished. Nothing here writes to `detect.py`; the
output is a report, and folding a rule in stays a decision somebody makes.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import re
import subprocess
import sys
import time
from typing import NamedTuple, Sequence

import attestor_chat

SCHEMA = "attestor.rule-forge/1.0"
VERSION = "4.1.4"

# Samples shown to the model per proposal. Enough to see an idiom, few enough
# that the reply is not mostly quoting; the model's context is also the slowest
# part of the loop on CPU.
SAMPLES_PER_SIDE = 6

# The bar a candidate must clear on data it was not proposed from.
MIN_HOLDOUT_RECALL = 0.15
MAX_HOLDOUT_FALSE_POSITIVES = 0

# Bounded so one pathological pattern cannot stall the run.
MAX_TEXT_BYTES = 4096
REGEX_BATCH_SIZE = 512
REGEX_BATCH_TIMEOUT_SECONDS = 2.0

PROPOSE_PROMPT = """\
Below are code windows from flawed and fixed versions of the same C functions.
They differ only in the defect; identifiers and comments have been stripped, \
so you cannot rely on names.

FLAWED (the defect is present):
%s

FIXED (the same code, corrected):
%s

Write ONE Python regular expression that matches the FLAWED windows and does \
NOT match the FIXED ones. Target the structural difference -- a missing check, \
a wrong bound, an absent free -- not incidental formatting.

Reply with only the regex inside a fenced block:
```regex
your pattern here
```
"""


class ForgeError(RuntimeError):
    """The corpus or the model made the run impossible."""


class Candidate(NamedTuple):
    pattern: str
    model: str
    cwe: str


class CompiledCandidate(NamedTuple):
    """A validated regex description with no in-process matching method.

    Returning a raw ``re.Pattern`` would let a later caller accidentally run a
    model-supplied expression in Attestor's long-lived process.  Matching happens
    only in the short-lived worker used by :func:`evaluate`.
    """

    pattern: str
    flags: int


class Score(NamedTuple):
    true_positives: int
    false_positives: int
    flawed_total: int
    fixed_total: int

    @property
    def recall(self) -> float:
        return (self.true_positives / self.flawed_total
                if self.flawed_total else 0.0)

    def as_dict(self) -> dict:
        return {"true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "flawed_total": self.flawed_total,
                "fixed_total": self.fixed_total,
                "recall": round(self.recall, 4)}


_FENCED = re.compile(r"```(?:regex|python|re)?\s*\n(.+?)\n```", re.DOTALL)

# The worker deliberately contains no Attestor imports and receives only bounded
# JSON.  ``subprocess.run(..., timeout=...)`` kills it if CPython's backtracking
# engine stops making progress; Python's ``re`` API itself has no timeout.
_REGEX_WORKER = r"""
import json, re, sys
request = json.load(sys.stdin)
compiled = re.compile(request["pattern"], int(request["flags"]))
tp = fp = flawed = fixed = 0
for text, label in request["rows"]:
    hit = bool(compiled.search(text))
    if label == 1:
        flawed += 1
        tp += int(hit)
    else:
        fixed += 1
        fp += int(hit)
json.dump([tp, fp, flawed, fixed], sys.stdout, separators=(",", ":"))
"""


def _first_tokens(nodes) -> tuple[set[object] | None, bool]:
    """Conservative first-token/nullability summary for a parsed expression."""
    first: set[object] = set()
    nullable = True
    for op, argument in nodes:
        name = str(op)
        if name == "LITERAL":
            return {("literal", argument)}, False
        if name == "NOT_LITERAL":
            return {("not-literal", argument)}, False
        if name == "IN":
            tokens: set[object] = set()
            for inner_op, inner_arg in argument:
                inner_name = str(inner_op)
                if inner_name in {"LITERAL", "CATEGORY"}:
                    tokens.add((inner_name, str(inner_arg)))
                else:
                    return None, False
            return tokens, False
        if name in {"ANY", "GROUPREF"}:
            return None, False
        if name == "SUBPATTERN":
            return _first_tokens(argument[3])
        if name == "BRANCH":
            branch_first: set[object] = set()
            any_nullable = False
            for branch in argument[1]:
                tokens, can_be_empty = _first_tokens(branch)
                if tokens is None:
                    return None, any_nullable or can_be_empty
                branch_first.update(tokens)
                any_nullable |= can_be_empty
            return branch_first, any_nullable
        if name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
            minimum, _maximum, child = argument
            tokens, child_nullable = _first_tokens(child)
            return tokens, minimum == 0 or child_nullable
        if name in {"AT", "ASSERT", "ASSERT_NOT"}:
            continue
        # Conditional groups, locale-dependent categories and future parser
        # opcodes are unknown rather than guessed safe.
        return None, False
    return first, nullable


def _shape_risk(nodes, inside_repeat: bool = False) -> str | None:
    """Find nested repetition and overlapping alternatives in parser output."""
    for op, argument in nodes:
        name = str(op)
        if name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
            if inside_repeat:
                return "nested repetition"
            risk = _shape_risk(argument[2], inside_repeat=True)
            if risk:
                return risk
        elif name == "SUBPATTERN":
            risk = _shape_risk(argument[3], inside_repeat)
            if risk:
                return risk
        elif name == "BRANCH":
            branches = argument[1]
            if inside_repeat:
                seen: set[object] = set()
                for branch in branches:
                    tokens, nullable = _first_tokens(branch)
                    if nullable:
                        return "nullable alternative inside repetition"
                    if tokens is None or seen.intersection(tokens):
                        return "overlapping alternatives inside repetition"
                    seen.update(tokens)
            for branch in branches:
                risk = _shape_risk(branch, inside_repeat)
                if risk:
                    return risk
        elif name in {"ASSERT", "ASSERT_NOT"}:
            risk = _shape_risk(argument[1], inside_repeat)
            if risk:
                return risk
        elif name == "GROUPREF_EXISTS":
            for branch in argument[1:]:
                if branch:
                    risk = _shape_risk(branch, inside_repeat)
                    if risk:
                        return risk
        elif name == "ATOMIC_GROUP":
            risk = _shape_risk(argument, inside_repeat)
            if risk:
                return risk
    return None


def extract_pattern(reply: str) -> str:
    """Pull the regex out of a model reply, or say why it could not be."""
    match = _FENCED.search(reply)
    text = match.group(1) if match else reply
    # A model that ignores the fence usually still puts the pattern alone on a
    # line; take the longest such line rather than the whole reply, which would
    # otherwise compile as a literal and match nothing.
    if not match:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        prose = [line for line in lines
                 if not line.endswith(".") and len(line) > 3]
        if not prose:
            raise ForgeError("no pattern in the reply")
        text = max(prose, key=len)
    text = text.strip().strip("`").strip()
    if text.startswith(("r'", 'r"')):
        text = text[2:-1] if text[-1] in "'\"" else text[2:]
    if not text:
        raise ForgeError("empty pattern")
    return text


def compile_candidate(pattern: str) -> CompiledCandidate:
    """Validate a candidate without exposing an in-process matching method."""
    if not isinstance(pattern, str):
        raise ForgeError("pattern must be text")
    if len(pattern) > 400:
        raise ForgeError("pattern is %d chars; too broad to be a rule"
                         % len(pattern))
    try:
        re.compile(pattern, re.MULTILINE)
        parsed = re._parser.parse(pattern, re.MULTILINE)  # type: ignore[attr-defined]
    except (re.error, OverflowError, ValueError) as error:
        raise ForgeError("will not compile: %s" % error) from error
    risk = _shape_risk(parsed)
    if risk:
        raise ForgeError("%s; refused before isolated evaluation" % risk)
    return CompiledCandidate(pattern, re.MULTILINE)


def evaluate(compiled: CompiledCandidate, rows: Sequence) -> Score:
    """Measure a candidate only in killable, isolated worker processes."""
    true_positives = false_positives = flawed = fixed = 0
    for start in range(0, len(rows), REGEX_BATCH_SIZE):
        batch = rows[start:start + REGEX_BATCH_SIZE]
        request = {
            "pattern": compiled.pattern,
            "flags": compiled.flags,
            "rows": [[row.text[:MAX_TEXT_BYTES], int(row.label)]
                     for row in batch],
        }
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-X", "utf8", "-c",
                 _REGEX_WORKER],
                input=json.dumps(request), capture_output=True, text=True,
                timeout=REGEX_BATCH_TIMEOUT_SECONDS, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ForgeError(
                "regex evaluation exceeded %.1fs; worker terminated"
                % REGEX_BATCH_TIMEOUT_SECONDS) from error
        if completed.returncode != 0:
            detail = completed.stderr.strip().splitlines()[-1:]
            raise ForgeError("isolated regex worker failed%s" %
                             (": " + detail[0][:160] if detail else ""))
        try:
            tp, fp, batch_flawed, batch_fixed = json.loads(completed.stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ForgeError("isolated regex worker returned invalid data") from error
        true_positives += int(tp)
        false_positives += int(fp)
        flawed += int(batch_flawed)
        fixed += int(batch_fixed)
    return Score(true_positives, false_positives, flawed, fixed)


def sample_windows(rows: Sequence, label: int, count: int,
                   rng: random.Random) -> list[str]:
    pool = [row.text for row in rows if row.label == label]
    if not pool:
        raise ForgeError("no windows with label %d" % label)
    rng.shuffle(pool)
    return pool[:count]


def propose(port: int, cwe: str, flawed: Sequence[str],
            fixed: Sequence[str]) -> str:
    """Ask the running model for one candidate pattern."""
    def block(items):
        return "\n---\n".join(item[:600] for item in items)

    reply = attestor_chat.ask(port, [
        {"role": "system",
         "content": "You write precise regular expressions. You reply with a "
                    "regex and nothing else."},
        {"role": "user", "content": PROPOSE_PROMPT % (block(flawed),
                                                      block(fixed))},
    ], max_tokens=300)
    return extract_pattern(reply)


def load_corpus(archive: str, cwe: str, detector: str):
    """Labelled windows for one CWE, split by testcase.

    A missing archive is reported, never worked around. Juliet is ~153 MB of
    separately downloadable NIST material and is deliberately not shipped; a
    run without it must produce `corpus-unavailable`, because the alternative
    -- scoring against something else and calling it ground truth -- is how a
    number stops meaning anything.
    """
    sys.path.insert(0, detector)
    import juliet_corpus

    if not pathlib.Path(archive).is_file():
        raise ForgeError("corpus-unavailable: no archive at %s" % archive)

    rows = [row for row in juliet_corpus.iter_archive(archive)
            if row.cwe == cwe]
    if not rows:
        raise ForgeError("corpus-unavailable: no %s windows in the archive"
                         % cwe)
    train, holdout = juliet_corpus.group_split(rows, holdout=0.2)
    return train, holdout


def forge(archive: str, cwe: str, models: Sequence[str], rounds: int,
          detector: str, port: int, threads: int, seed: int = 20260806) -> dict:
    """Run the propose/measure loop and report what survived."""
    train, holdout = load_corpus(archive, cwe, detector)
    rng = random.Random(seed)
    backend = attestor_chat.find_backend()
    if not backend:
        raise ForgeError("no llama.cpp server under ~/.lmstudio")

    report = {"schema": SCHEMA, "version": VERSION, "cwe": cwe,
              "train_windows": len(train), "holdout_windows": len(holdout),
              "models": [], "accepted": [], "rejected": []}

    for model in models:
        name = pathlib.Path(model).name
        started = time.time()
        try:
            server = attestor_chat.start_server(backend, model, port, threads)
        except attestor_chat.ChatError as error:
            report["models"].append({"model": name, "error": str(error)})
            continue

        attempted = 0
        try:
            for _ in range(rounds):
                attempted += 1
                flawed = sample_windows(train, 1, SAMPLES_PER_SIDE, rng)
                fixed = sample_windows(train, 0, SAMPLES_PER_SIDE, rng)
                try:
                    pattern = propose(port, cwe, flawed, fixed)
                    compiled = compile_candidate(pattern)
                except (ForgeError, attestor_chat.ChatError) as error:
                    report["rejected"].append(
                        {"model": name, "reason": str(error)[:120]})
                    continue

                on_train = evaluate(compiled, train)
                on_holdout = evaluate(compiled, holdout)
                record = {"model": name, "pattern": pattern,
                          "train": on_train.as_dict(),
                          "holdout": on_holdout.as_dict()}

                # Measured on data the proposal never saw. A candidate that
                # looks perfect on `train` and fails here is the normal case,
                # not an anomaly -- see the module docstring.
                if (on_holdout.false_positives <= MAX_HOLDOUT_FALSE_POSITIVES
                        and on_holdout.recall >= MIN_HOLDOUT_RECALL):
                    report["accepted"].append(record)
                else:
                    record["reason"] = (
                        "held-out: %d false positive(s), %.1f%% recall"
                        % (on_holdout.false_positives,
                           on_holdout.recall * 100))
                    report["rejected"].append(record)
        finally:
            server.kill()

        report["models"].append({"model": name, "proposals": attempted,
                                 "seconds": round(time.time() - started)})
    return report


def main(argv: list[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", required=True,
                        help="Juliet/SARD zip (not shipped; supply your own)")
    parser.add_argument("--cwe", required=True, help="e.g. CWE190")
    parser.add_argument("--model", action="append", default=[],
                        help="repeatable; defaults to every model found")
    parser.add_argument("--rounds", type=int, default=4,
                        help="proposals per model")
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--port", type=int, default=8093)
    parser.add_argument("--threads", type=int,
                        default=max(1, (__import__("os").cpu_count() or 4) - 2))
    parser.add_argument("--out", default=None, help="write the report as JSON")
    args = parser.parse_args(argv)

    models = args.model
    if not models:
        root = pathlib.Path.home() / ".lmstudio" / "models"
        models = sorted((str(p) for p in root.rglob("*.gguf")
                         if "mmproj" not in p.name.lower()),
                        key=lambda p: pathlib.Path(p).stat().st_size)
    if not models:
        print("no .gguf models found; pass --model")
        return 2

    try:
        report = forge(args.archive, args.cwe, models, args.rounds,
                       args.detector, args.port, args.threads)
    except ForgeError as error:
        print("%s" % error)
        return 1

    print("\n%s  %s -- %d train / %d held-out windows"
          % (VERSION, report["cwe"], report["train_windows"],
             report["holdout_windows"]))
    for entry in report["models"]:
        if "error" in entry:
            print("  %-34s could not run: %s" % (entry["model"],
                                                 entry["error"][:60]))
        else:
            print("  %-34s %d proposals in %ds"
                  % (entry["model"], entry["proposals"], entry["seconds"]))

    print("\naccepted: %d   rejected: %d"
          % (len(report["accepted"]), len(report["rejected"])))
    for record in report["accepted"]:
        print("  KEEP  %s\n        held-out %.1f%% recall, %d false positive(s)"
              % (record["pattern"][:96],
                 record["holdout"]["recall"] * 100,
                 record["holdout"]["false_positives"]))

    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2),
                                          encoding="utf-8")
        print("\nreport: %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
