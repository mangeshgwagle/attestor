#!/usr/bin/env python3
"""Let something else propose the patch; Attestor still decides.

The problem this solves
-----------------------
`verified_remediation` can only repair what one of its nine AST templates
recognises, because those are the only Python transformations that are
provably semantics-preserving. That bound is correct and this module does not
loosen it. What it does is open the *other* end of the pipeline.

The verification half -- disposable copies, rescan against baseline,
property/mutation/fuzz probes, PatchGuard's atomic backup and rollback -- never
cared where a proposal came from. `run_assurance_probes` takes a `FixProposal`
and asks whether it holds up; it does not ask who wrote it. Until now nothing
could reach that machinery except Attestor's own templates.

So: a model, a script, a colleague, or a coin toss may write the candidate.
Attestor reads it, scans it, runs it, and throws it away if it does not survive.

Why this makes a weak generator useful
--------------------------------------
A generator that is right three times in ten is worthless alone, because you
cannot tell which three. Behind a sound verifier it becomes a slow but reliable
system: propose, check, discard, repeat. That is the whole reason this route
does not need an expensive model -- it needs rejection to be cheap and correct,
and rejection is the part Attestor was already good at.

It also settles a measurement from this codebase's history: a local model asked
to *judge* a finding flipped from six rejections to six acceptances on nothing
but a change of wording. So it is never asked to judge here. It writes; Attestor
adjudicates. That is the same separation `advisory41` enforces for phrasing,
applied to code.

What this is not
----------------
Not a safety proof. A patch that is plausible and wrong in a way no rule
catches will pass, and the probes bound the failure surface rather than
eliminating it. Every accepted proposal is still marked `deterministic=False`,
because a human should know a machine guessed at it.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import difflib
import hashlib
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

import verified_remediation as vr

SCHEMA = "attestor.external-gate/1.0"
VERSION = "4.1.4"

# A candidate is refused above this size rather than scanned: a "patch" that
# replaces the file wholesale is not a repair, and reviewing it as one would
# give a rewrite the credibility of a fix.
MAX_GROWTH_RATIO = 3.0
MIN_RETENTION_RATIO = 0.65
MAX_CANDIDATE_BYTES = 2 * 1024 * 1024


class GateError(RuntimeError):
    """The candidate cannot be reviewed at all."""


@dataclass(frozen=True)
class ExternalReview:
    schema: str
    version: str
    target: str
    origin: str
    accepted: bool
    reasons: tuple[str, ...]
    resolved: tuple[str, ...]
    introduced: tuple[str, ...]
    probes: tuple[dict[str, Any], ...]
    unified_diff: str
    candidate_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rules(source: str, target: str) -> list[str]:
    """Rule names Attestor reports for a source, using the module's own scanner."""
    return list(vr._scan_source(source, target))


def _python_surface(source: str) -> dict[tuple[str, str], str]:
    """Return the module-level callable surface that a repair must preserve."""
    tree = ast.parse(source)
    surface = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "async-function" if isinstance(node, ast.AsyncFunctionDef) else "function"
            signature = ast.dump(node.args, annotate_fields=True,
                                 include_attributes=False)
            surface[(kind, node.name)] = signature
        elif isinstance(node, ast.ClassDef):
            bases = ast.dump(ast.Tuple(elts=node.bases, ctx=ast.Load()),
                             annotate_fields=True, include_attributes=False)
            surface[("class", node.name)] = bases
    return surface


def _changed_line_count(original: str, candidate: str) -> int:
    total = 0
    matcher = difflib.SequenceMatcher(
        None, original.splitlines(), candidate.splitlines(), autojunk=False)
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag != "equal":
            total += max(old_end - old_start, new_end - new_start)
    return total


def _proposal(target: str, original: str, candidate: str,
              findings: Sequence[Any]) -> vr.FixProposal:
    """Wrap someone else's candidate in the shape the verifier expects.

    One `FixEdit` covering the whole file, because an external candidate
    arrives as a finished source rather than as a span: claiming a narrower
    edit than was actually made would misreport the blast radius to anyone
    reading the proposal afterwards.
    """
    diff = "".join(difflib.unified_diff(
        original.splitlines(keepends=True), candidate.splitlines(keepends=True),
        fromfile=target + " (original)", tofile=target + " (candidate)"))
    edits = tuple(
        vr.FixEdit(rule=getattr(f, "rule", None) or f.get("rule", "?"),
                   line=int(getattr(f, "line", None) or f.get("line", 0) or 0),
                   kind="external-candidate",
                   before="", after="",
                   rationale="authored outside Attestor; accepted only on evidence")
        for f in findings) or (
        vr.FixEdit(rule="?", line=0, kind="external-candidate",
                   before="", after="",
                   rationale="authored outside Attestor; accepted only on evidence"),)
    return vr.FixProposal(
        version=vr.ENGINE_VERSION, target=target, language="python",
        original_sha256=_sha(original), candidate_sha256=_sha(candidate),
        improved_source=candidate, unified_diff=diff, edits=edits,
        refusals=(),
        # The one field that must never be True here. A human reading the
        # report has to be able to tell that a machine guessed.
        deterministic=False)


def review(target: str, original: str, candidate: str,
           findings: Iterable[Any] = (), *, origin: str = "external",
           seed: int = vr.DEFAULT_SEED,
           fuzz_cases: int = vr.DEFAULT_FUZZ_CASES) -> ExternalReview:
    """Judge a candidate written by something other than Attestor.

    Four independent ways to fail, and any one of them is fatal:

    * it does not parse;
    * the findings it was meant to fix are still there;
    * it introduced findings that were not there before;
    * a probe failed.

    The third is the one that matters most for a model-authored patch. A
    generator that removes a command injection by introducing a path traversal
    has not helped, and only a rescan across the whole rule set notices.
    """
    findings = list(findings)
    if not candidate.strip():
        raise GateError("the candidate is empty")
    if len(candidate.encode("utf-8")) > MAX_CANDIDATE_BYTES:
        raise GateError("candidate exceeds %d bytes" % MAX_CANDIDATE_BYTES)
    if original and len(candidate) > len(original) * MAX_GROWTH_RATIO:
        raise GateError(
            "candidate is %.1fx the original; that is a rewrite, not a repair"
            % (len(candidate) / max(len(original), 1)))
    if original and len(candidate) < len(original) * MIN_RETENTION_RATIO:
        raise GateError(
            "candidate retains only %.1f%% of the original; that is a "
            "destructive rewrite, not a repair"
            % (100.0 * len(candidate) / max(len(original), 1)))

    reasons: list[str] = []
    proposal = _proposal(target, original, candidate, findings)

    if not proposal.changed:
        reasons.append("the candidate is identical to the original")

    original_lines = max(1, len(original.splitlines()))
    changed_lines = _changed_line_count(original, candidate)
    if changed_lines > max(12, int(original_lines * 0.40)):
        reasons.append(
            "candidate changes %d line(s), exceeding the bounded repair scope"
            % changed_lines)

    probes = vr.run_assurance_probes(proposal, original, seed=seed,
                                     fuzz_cases=fuzz_cases)
    failed = [p.name for p in probes if not p.passed]
    if failed:
        reasons.append("assurance probes failed: " + ", ".join(failed))

    before = _rules(original, target)
    try:
        after = _rules(candidate, target)
    except SyntaxError as error:
        raise GateError("candidate does not parse: %s" % error) from error

    try:
        before_surface = _python_surface(original)
        after_surface = _python_surface(candidate)
    except SyntaxError as error:
        raise GateError("candidate does not parse: %s" % error) from error
    missing_surface = sorted(
        "%s %s" % key for key, signature in before_surface.items()
        if after_surface.get(key) != signature)
    if missing_surface:
        reasons.append("candidate removes or changes the callable surface: "
                       + ", ".join(missing_surface[:8]))

    import collections
    before_counts = collections.Counter(before)
    after_counts = collections.Counter(after)

    # Anything the candidate added. Counted, not just named: turning one
    # injection into three is an increase even though the rule set is the same.
    introduced = sorted(
        (after_counts - before_counts).elements())
    if introduced:
        reasons.append("the candidate introduced: "
                       + ", ".join(sorted(set(introduced))))

    targeted = {getattr(f, "rule", None) or f.get("rule") for f in findings}
    targeted.discard(None)
    # A count decrease is not proof that the selected occurrence was repaired:
    # a model can fix a later duplicate and leave the requested flaw intact.
    # External patches therefore have to eliminate every occurrence of each
    # targeted rule; narrower occurrence-level proof belongs in the deterministic
    # remediation engine, which has source spans and fingerprints.
    resolved = sorted(rule for rule in targeted
                      if before_counts[rule] > 0 and after_counts[rule] == 0)
    unresolved = sorted(targeted - set(resolved))
    if targeted and unresolved:
        reasons.append("still present after the patch: " + ", ".join(unresolved))

    return ExternalReview(
        schema=SCHEMA, version=VERSION, target=target, origin=origin,
        accepted=not reasons, reasons=tuple(dict.fromkeys(reasons)),
        resolved=tuple(resolved), introduced=tuple(sorted(set(introduced))),
        probes=tuple(dataclasses.asdict(p) for p in probes),
        unified_diff=proposal.unified_diff,
        candidate_sha256=proposal.candidate_sha256)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("original", help="the file as it stands")
    parser.add_argument("candidate", help="the proposed replacement")
    parser.add_argument("--origin", default="external",
                        help="who wrote the candidate, for the record")
    parser.add_argument("--rule", action="append", default=[],
                        help="a rule the candidate is meant to resolve")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        with open(args.original, encoding="utf-8") as handle:
            original = handle.read()
        with open(args.candidate, encoding="utf-8") as handle:
            candidate = handle.read()
        result = review(os.path.basename(args.original), original, candidate,
                        [{"rule": r, "line": 0} for r in args.rule],
                        origin=args.origin)
    except (GateError, OSError) as error:
        print("refused: %s" % error)
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0 if result.accepted else 1

    print("%s  origin=%s" % (result.target, result.origin))
    print("verdict : %s" % ("ACCEPTED" if result.accepted else "REJECTED"))
    if result.resolved:
        print("resolved: %s" % ", ".join(result.resolved))
    if result.introduced:
        print("introduced: %s" % ", ".join(result.introduced))
    for reason in result.reasons:
        print("  - %s" % reason)
    print("probes  : %d run, %d failed"
          % (len(result.probes),
             sum(1 for p in result.probes if p["status"] not in
                 {"passed", "skipped"})))
    if result.accepted:
        print("\nAccepted on evidence, not on trust: a machine wrote this and "
              "the proposal is marked non-deterministic. Read the diff.")
    return 0 if result.accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
