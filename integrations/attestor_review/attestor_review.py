#!/usr/bin/env python3
"""A professional review voice for Attestor, and the TCS route that governs it.

What this is
------------
The plain-language counterpart to `attestor4kids`. That module takes the findings
`detect.scan_source` already produced and adds an opinion about them, in
language nobody should put in front of a client. This one takes the same
findings and writes them the way a reviewer would: what the defect is, what an
attacker gets, what to change, and how confident anyone should be.

Like its noisy twin, **it adds no detection power whatsoever**. Every finding
here comes from `detect.scan_source`, at the same line, under the same rule
name. A renderer cannot find a defect the rules missed, and implying otherwise
would be the same mistake as expecting a wider neural gate to help when the
gate has been flat for two versions. If you want this to report more, write a
rule; that is the only thing that has ever moved the number.

Why TCS files are not just "files"
----------------------------------
`CJP_LOCAL_CONTROL_4.1.4.md` and `cjp_control414` already define how a locally
supplied Tata Consultancy Services copy may be looked at: an explicit request
naming the organization, the issuer, an owner statement, a purpose, a
lifetime of 30 to 900 seconds, and one to twelve exact files. Nothing is
implied and no scope is inferred.

So this module does not open TCS material on its own authority. Pointed at a
TCS root it requires that request, hands it to `cjp_control414.control`, and
reviews only what comes back authorized. Reimplementing the checks here --
even carefully -- would create a second, quieter door into the same material,
and the second door is always the one that is wrong.

Improving files
---------------
"Improve if necessary" means proposing, never rewriting in place. Repairs come
from `verified_remediation`, which only transforms what it can re-verify, and
they are returned as a proposal for a person to accept. The CJP route calls
its editing action `preview-file-edit` for the same reason: a supplier's
source is not something a tool should silently modify.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Iterable, Sequence

SCHEMA = "attestor.review/4.2"
VERSION = "4.2"

# Reviewed one file at a time, and bounded, because a reviewer that stalls on
# a generated blob is a reviewer nobody runs twice.
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_FINDINGS_RENDERED = 200

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# What a reader should do with each severity. Deliberately plain: the register
# is the entire point of this module existing beside `attestor4kids`.
GUIDANCE = {
    "HIGH": "Address before release.",
    "MEDIUM": "Schedule; not a release blocker on its own.",
    "LOW": "Fix opportunistically.",
}


class ReviewError(RuntimeError):
    """The review could not be performed."""


def _detector_on_path(detector: str) -> None:
    if detector not in sys.path:
        sys.path.insert(0, detector)


def _severity(value: Any) -> str:
    text = str(value or "").upper()
    return text if text in SEVERITY_ORDER else "LOW"


def scan_file(path: str, detector: str) -> list[dict[str, Any]]:
    """Findings for one file, as plain dictionaries."""
    _detector_on_path(detector)
    import detect

    source = pathlib.Path(path)
    try:
        if source.stat().st_size > MAX_FILE_BYTES:
            raise ReviewError("%s is larger than %d bytes"
                              % (path, MAX_FILE_BYTES))
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise ReviewError("cannot read %s: %s" % (path, error)) from error

    language = (detect.language_for(str(source))
                if hasattr(detect, "language_for") else "text")
    try:
        found = detect.scan_source(text, str(source), language, deep=True)
    except Exception as error:                               # noqa: BLE001
        raise ReviewError("scan failed for %s: %s" % (path, error)) from error

    return [{"path": str(source), "line": getattr(item, "line", 0),
             "rule": getattr(item, "rule", ""),
             "severity": _severity(getattr(item, "severity", "")),
             "message": getattr(item, "message", ""),
             "fix": getattr(item, "fix", "")}
            for item in found]


def render(findings: Sequence[dict[str, Any]], *,
           limit: int = MAX_FINDINGS_RENDERED) -> str:
    """The findings as a review, in professional register.

    States absence honestly. "No rule fired" is not "this file is safe", and a
    report that blurred the two would be worse than no report -- it is the one
    sentence a reader is most likely to quote back later.
    """
    if not findings:
        return ("No findings. Attestor's rules did not fire on this material.\n"
                "This is not a statement that the code is free of defects: "
                "a class with no rule is unexamined, not clean.")

    ordered = sorted(findings,
                     key=lambda f: (SEVERITY_ORDER.get(f["severity"], 3),
                                    f.get("path", ""), f.get("line", 0)))
    counts: dict[str, int] = {}
    for item in ordered:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1

    lines = ["Review summary: %d finding%s (%s)."
             % (len(ordered), "" if len(ordered) == 1 else "s",
                ", ".join("%d %s" % (counts[key], key.lower())
                          for key in ("HIGH", "MEDIUM", "LOW")
                          if key in counts)),
             ""]
    for item in ordered[:limit]:
        lines.append("%s:%s  [%s]  %s"
                     % (item.get("path", "?"), item.get("line", 0),
                        item["severity"], item.get("rule", "")))
        if item.get("message"):
            lines.append("    %s" % item["message"])
        if item.get("fix"):
            lines.append("    Recommended: %s" % item["fix"])
        lines.append("    %s" % GUIDANCE[item["severity"]])
        lines.append("")
    if len(ordered) > limit:
        lines.append("... %d further findings not shown."
                     % (len(ordered) - limit))
    lines.append("Findings are evidence of defects. The absence of a finding "
                 "is not evidence of their absence.")
    return "\n".join(lines)


def propose_improvements(path: str, findings: Sequence[dict[str, Any]],
                         detector: str) -> dict[str, Any]:
    """A repair proposal for one file, or an explanation of why not.

    Nothing is written. `verified_remediation` only transforms what it can
    re-verify, so most findings return a refusal, and a refusal here is the
    correct answer rather than a shortfall.
    """
    _detector_on_path(detector)
    import verified_remediation as vr

    source = pathlib.Path(path)
    try:
        original = source.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise ReviewError("cannot read %s: %s" % (path, error)) from error

    repairable = [f for f in findings if f.get("rule") in vr.SUPPORTED_RULES]
    if not repairable:
        return {"path": str(source), "proposed": False,
                "reason": ("no finding here matches a transformation that can "
                           "be re-verified; %d rule(s) are repairable in total"
                           % len(vr.SUPPORTED_RULES)),
                "repairable_rules": sorted(vr.SUPPORTED_RULES)}

    # `improve_source` is the in-memory adapter: it builds a disposable
    # one-file project, compiles, rescans and compares, and never touches the
    # real target. That is the whole reason it is used here instead of the
    # applying path -- a supplier's source is not something to rewrite.
    outcome = vr.improve_source(original, str(source), findings=repairable,
                                verify=True)
    accepted = bool(outcome.get("accepted"))
    return {"path": str(source), "proposed": accepted,
            "candidates": len(repairable),
            "reason": ("" if accepted else
                       "; ".join(outcome.get("reasons", ()))
                       or "no candidate survived verification"),
            "report": outcome}


def review_tcs(request_path: str, detector: str,
               *, permission_confirmed: bool = False) -> dict[str, Any]:
    """Review a TCS-supplied copy through the CJP local-control route.

    The authorization decision belongs to `cjp_control414`, which is handed
    the request file unchanged; only the files it authorizes are read, and a
    refusal is returned as a refusal rather than worked around.

    `permission_confirmed` is passed straight through and defaults to False.
    It represents a person having agreed, so this module has no business
    supplying it on their behalf -- the operator sets it, or the session is
    not authorized.
    """
    _detector_on_path(detector)
    import cjp_control414

    request = pathlib.Path(request_path)
    if not request.is_file():
        raise ReviewError("no control request at %s" % request_path)
    try:
        payload = json.loads(request.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReviewError("cannot read the control request: %s"
                          % error) from error

    try:
        decision = cjp_control414.control(
            request, permission_confirmed=permission_confirmed)
    except Exception as error:                               # noqa: BLE001
        # Includes CJPControlError. Its message is the operator's answer.
        return {"schema": SCHEMA, "authorized": False,
                "reason": str(error), "findings": [], "review": ""}

    authorization = decision.get("authorization", {})
    granted = bool(authorization.get("granted", authorization.get("authorized")))
    if not granted:
        return {"schema": SCHEMA, "authorized": False,
                "reason": (authorization.get("reason")
                           or "the control session was not authorized"),
                "control": decision, "findings": [], "review": ""}

    root = pathlib.Path(payload.get("root", "."))
    findings: list[dict[str, Any]] = []
    for relative in payload.get("files", []):
        findings.extend(scan_file(str(root / relative), detector))
    return {"schema": SCHEMA, "version": VERSION, "authorized": True,
            "organization": payload.get("organization", ""),
            "control": decision, "findings": findings,
            "review": render(findings)}


def main(argv: list[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="files to review")
    parser.add_argument("--tcs-request", metavar="JSON",
                        help="a cjp_control414 request file; required for TCS "
                             "material, which is never reviewed on this "
                             "module's own authority")
    parser.add_argument("--permission-confirmed", action="store_true",
                        help="record that the owner has agreed to this exact "
                             "session; without it the control route refuses")
    parser.add_argument("--improve", action="store_true",
                        help="also propose verified repairs (writes nothing)")
    parser.add_argument("--detector",
                        default=str(here.parent.parent.parent / "detector"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.tcs_request:
            result = review_tcs(args.tcs_request, args.detector,
                                permission_confirmed=args.permission_confirmed)
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            elif not result["authorized"]:
                print("Not authorized: %s" % result["reason"])
                return 2
            else:
                print(result["review"])
            return 0 if result["authorized"] else 2

        if not args.paths:
            parser.error("give files to review, or --tcs-request")

        findings: list[dict[str, Any]] = []
        for path in args.paths:
            findings.extend(scan_file(path, args.detector))

        improvements = []
        if args.improve:
            for path in args.paths:
                mine = [f for f in findings if f["path"] == str(
                    pathlib.Path(path))]
                improvements.append(
                    propose_improvements(path, mine, args.detector))

        if args.json:
            print(json.dumps({"schema": SCHEMA, "version": VERSION,
                              "findings": findings,
                              "improvements": improvements},
                             indent=2, sort_keys=True))
        else:
            print(render(findings))
            for item in improvements:
                print()
                if item["proposed"]:
                    print("%s: a verified repair is available for review "
                          "(%d candidate finding(s)). Nothing has been "
                          "written."
                          % (item["path"], item.get("candidates", 0)))
                else:
                    print("%s: no repair proposed -- %s"
                          % (item["path"], item["reason"]))
    except ReviewError as error:
        print("attestor-review: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
