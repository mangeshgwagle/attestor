#!/usr/bin/env python3
"""Attestor for a delivery organisation: same findings, professional register.

Two things this is
------------------
**A renderer.** `attestor4kids` proves the point by inversion: it takes exactly the
findings `detect.scan_source` produces and adds an opinion. This does the same
with the opposite register -- a report you can attach to a delivery review
without apologising for it. Neither fork can find a defect the other missed,
and the docstring in each says so.

**A policy layer.** A finding is a fact; whether it *blocks* is an
organisational decision, and organisations differ. A house profile names which
rules are mandatory, which are advisory, and which are waived with a stated
reason. Attestor reports the same defects either way; the profile decides what the
exit status means.

On house standards this module does not have
--------------------------------------------
It ships no organisation's coding standard, and specifically not TCS's --
those documents are internal and this package has never seen one. A profile
that guessed at somebody's standard and called it theirs would be worse than
no profile at all: it would produce a report claiming an authority it does not
have, and a reviewer could reasonably act on it.

So the profile is *supplied*, not assumed. `template_profile()` emits a
commented starting point using rule ids Attestor actually has, for somebody who
holds the real standard to fill in. Every rule id in a loaded profile is
checked against `detect.RULES`, so a typo or a rule from a different Attestor
version is refused rather than silently ignored -- an unenforced mandatory
rule is the failure mode that matters here.

"Improve if necessary"
----------------------
Repair is delegated to `verified_remediation`, which only rewrites what it can
re-verify afterwards, and only for the ten transformations it can prove
semantics-preserving. This module never edits a file itself, and nothing is
written without `--apply`. A tool that silently rewrote a delivery codebase
because a policy said so would be the worst thing in this directory.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

SCHEMA = "attestor.house-profile/1.0"
VERSION = "4.2"

MANDATORY, ADVISORY, WAIVED = "mandatory", "advisory", "waived"
DEFAULT_UNLISTED = ADVISORY

SEVERITIES = ("HIGH", "MEDIUM", "LOW")
MAX_PROFILE_BYTES = 256 * 1024
MAX_FILES = 5000
MAX_FILE_BYTES = 2 * 1024 * 1024


class ProfileError(ValueError):
    """The house profile is unusable."""


@dataclass(frozen=True)
class Profile:
    """One organisation's decision about what each rule means to them."""
    organisation: str = ""
    mandatory: frozenset = frozenset()
    advisory: frozenset = frozenset()
    waived: dict = field(default_factory=dict)      # rule -> stated reason
    severity_overrides: dict = field(default_factory=dict)
    unlisted: str = DEFAULT_UNLISTED

    def disposition(self, rule: str) -> tuple[str, str]:
        """(mandatory|advisory|waived, reason) for one rule id."""
        if rule in self.waived:
            return WAIVED, self.waived[rule]
        if rule in self.mandatory:
            return MANDATORY, ""
        if rule in self.advisory:
            return ADVISORY, ""
        return self.unlisted, "not named by the house profile"

    def severity_of(self, rule: str, reported: str) -> str:
        return self.severity_overrides.get(rule, reported)


def _known_rules(detector: str) -> set[str]:
    if detector not in sys.path:
        sys.path.insert(0, detector)
    import detect
    return {getattr(rule, "rid", "") for rule in detect.RULES} - {""}


def load_profile(path: str, detector: str) -> Profile:
    """Read a house profile, refusing one that names rules Attestor does not have.

    A mandatory rule that does not exist is the dangerous typo: the profile
    reads as strict, the report comes back clean, and nobody learns that the
    check never ran. Unknown ids are refused rather than dropped.
    """
    source = pathlib.Path(path)
    if not source.is_file():
        raise ProfileError("no profile at %s" % path)
    if source.stat().st_size > MAX_PROFILE_BYTES:
        raise ProfileError("profile exceeds %d bytes" % MAX_PROFILE_BYTES)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except ValueError as error:
        raise ProfileError("profile is not valid JSON: %s" % error)
    if not isinstance(raw, dict):
        raise ProfileError("profile must be a JSON object")
    if raw.get("schema") != SCHEMA:
        raise ProfileError("profile schema is %r, expected %r"
                           % (raw.get("schema"), SCHEMA))

    def as_ids(key: str) -> frozenset:
        value = raw.get(key, [])
        if not isinstance(value, list) or \
                any(not isinstance(item, str) for item in value):
            raise ProfileError("%s must be a list of rule ids" % key)
        return frozenset(value)

    waived = raw.get("waived", {})
    if not isinstance(waived, dict) or \
            any(not isinstance(v, str) or not v.strip() for v in waived.values()):
        raise ProfileError(
            "waived must map a rule id to a non-empty reason; a waiver "
            "without a stated reason is not reviewable")

    overrides = raw.get("severity_overrides", {})
    if not isinstance(overrides, dict) or \
            any(v not in SEVERITIES for v in overrides.values()):
        raise ProfileError("severity_overrides must map rule ids to %s"
                           % ", ".join(SEVERITIES))

    unlisted = raw.get("unlisted", DEFAULT_UNLISTED)
    if unlisted not in (MANDATORY, ADVISORY, WAIVED):
        raise ProfileError("unlisted must be mandatory, advisory or waived")

    profile = Profile(
        organisation=str(raw.get("organisation", ""))[:120],
        mandatory=as_ids("mandatory"), advisory=as_ids("advisory"),
        waived=dict(waived), severity_overrides=dict(overrides),
        unlisted=unlisted)

    known = _known_rules(detector)
    named = set(profile.mandatory) | set(profile.advisory) \
        | set(profile.waived) | set(profile.severity_overrides)
    unknown = sorted(named - known)
    if unknown:
        raise ProfileError(
            "profile names %d rule(s) this Attestor does not have: %s -- refusing "
            "rather than ignoring them, because a mandatory rule that does "
            "not exist reads as enforced and never runs"
            % (len(unknown), ", ".join(unknown[:8])))
    return profile


def template_profile(detector: str) -> dict[str, Any]:
    """A starting point using rule ids this Attestor really has.

    Deliberately not filled in with anybody's standard. The severity split
    below is Attestor's own, offered as a default an organisation can accept or
    replace -- not as a claim about what any company requires.
    """
    if detector not in sys.path:
        sys.path.insert(0, detector)
    import detect

    high = sorted(r.rid for r in detect.RULES
                  if getattr(r, "severity", "") == "HIGH")
    return {
        "schema": SCHEMA,
        "organisation": "REPLACE WITH YOUR ORGANISATION",
        "_comment": ("Attestor ships no organisation's coding standard. Fill "
                     "these lists from the standard you actually hold; the "
                     "defaults below are only Attestor's own severities."),
        "mandatory": high,
        "advisory": [],
        "waived": {},
        "severity_overrides": {},
        "unlisted": DEFAULT_UNLISTED,
    }


@dataclass
class ReviewedFinding:
    path: str
    line: int
    rule: str
    severity: str
    message: str
    disposition: str
    reason: str


def review(target: str, profile: Profile, detector: str) -> dict[str, Any]:
    """Scan, then classify every finding through the house profile."""
    if detector not in sys.path:
        sys.path.insert(0, detector)
    import detect

    import language_coverage42 as coverage

    root = pathlib.Path(target)
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*") if p.is_file())
    reviewed: list[ReviewedFinding] = []
    scanned = 0
    unexamined: list[dict[str, Any]] = []
    for path in files[:MAX_FILES]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        language = (detect.language_for(str(path))
                    if hasattr(detect, "language_for") else "text")
        # A file whose language has no rules is recorded as unexamined, not
        # counted as scanned-and-clean. Attestor reads far more file types than
        # he has rules for, and a Java file with a command injection produces
        # zero findings -- the same output a genuinely clean file gives.
        verdict = coverage.assess(path)
        if not verdict["covered"]:
            unexamined.append(verdict)
        try:
            found = detect.scan_source(source, str(path), language, deep=True)
        except Exception:                                # noqa: BLE001
            continue
        scanned += 1
        for item in found:
            rule = getattr(item, "rule", "")
            disposition, reason = profile.disposition(rule)
            reviewed.append(ReviewedFinding(
                path=str(path), line=getattr(item, "line", 0), rule=rule,
                severity=profile.severity_of(
                    rule, getattr(item, "severity", "")),
                message=getattr(item, "message", ""),
                disposition=disposition, reason=reason))

    counts = {MANDATORY: 0, ADVISORY: 0, WAIVED: 0}
    for finding in reviewed:
        counts[finding.disposition] = counts.get(finding.disposition, 0) + 1
    return {
        "schema": SCHEMA, "version": VERSION,
        "organisation": profile.organisation,
        "files_scanned": scanned,
        "files_unexamined": len(unexamined),
        "unexamined_languages": sorted({v["language"] for v in unexamined}),
        "findings": [f.__dict__ for f in reviewed],
        "counts": counts,
        # The only thing that decides pass or fail. Advisory and waived
        # findings are reported in full and do not block, which is what makes
        # a waiver worth writing down instead of deleting the rule.
        "blocking": counts[MANDATORY],
    }


def render(report: dict[str, Any]) -> str:
    """A review a delivery lead can read, in a register they can forward."""
    lines = []
    who = report.get("organisation") or "unnamed organisation"
    lines.append("Attestor code review - %s" % who)
    lines.append("=" * min(72, len(lines[0])))
    lines.append("")
    lines.append("Files scanned : %d" % report["files_scanned"])
    counts = report["counts"]
    lines.append("Findings      : %d mandatory, %d advisory, %d waived"
                 % (counts.get(MANDATORY, 0), counts.get(ADVISORY, 0),
                    counts.get(WAIVED, 0)))
    # Stated at the top, not buried, because it changes what the rest of the
    # report means: a clean section is only clean for languages Attestor reviews.
    if report.get("files_unexamined"):
        lines.append("")
        lines.append("NOT REVIEWED  : %d file(s) in %s"
                     % (report["files_unexamined"],
                        ", ".join(report["unexamined_languages"])))
        lines.append("                Attestor has no rules for those languages. "
                     "Their absence from")
        lines.append("                the findings below means unexamined, "
                     "not clean.")
    lines.append("")

    order = {MANDATORY: 0, ADVISORY: 1, WAIVED: 2}
    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings = sorted(report["findings"],
                      key=lambda f: (order.get(f["disposition"], 3),
                                     rank.get(f["severity"], 3), f["path"],
                                     f["line"]))
    heading = {MANDATORY: "Must be resolved before delivery",
               ADVISORY: "Advisory",
               WAIVED: "Waived by the house profile"}
    current = None
    for finding in findings:
        if finding["disposition"] != current:
            current = finding["disposition"]
            lines.append(heading.get(current, current))
            lines.append("-" * len(lines[-1]))
        lines.append("  %s:%d  [%s]  %s"
                     % (finding["path"], finding["line"], finding["severity"],
                        finding["rule"]))
        lines.append("      %s" % finding["message"])
        # Only a waived finding carries a waiver. An advisory one carries the
        # reason it landed there -- usually "not named by the house profile"
        # -- and labelling that "waiver:" reads as though somebody signed it
        # off, which is the opposite of what it means.
        if finding["reason"]:
            label = "waiver" if finding["disposition"] == WAIVED else "note"
            lines.append("      %s: %s" % (label, finding["reason"]))
    if not findings:
        lines.append("No rule reported a finding.")
        lines.append("")
        lines.append("That is not a statement that the code is correct: Attestor "
                     "reports what its rules match, and a class with no rule "
                     "is unexamined rather than clean.")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?", help="file or directory")
    parser.add_argument("--profile", help="house profile JSON")
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--emit-template", action="store_true",
                        help="print a starting profile and exit")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.emit_template:
            print(json.dumps(template_profile(args.detector), indent=2))
            return 0
        if not args.target:
            parser.error("give a target, or --emit-template")
        profile = (load_profile(args.profile, args.detector) if args.profile
                   else Profile())
        report = review(args.target, profile, args.detector)
    except ProfileError as error:
        print("attestor-pro: %s" % error, file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2) if args.json else render(report),
          end="" if not args.json else "\n")
    # Non-zero only for mandatory findings, so a build can gate on this
    # without advisory noise failing it.
    return 1 if report["blocking"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
