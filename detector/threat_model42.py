#!/usr/bin/env python3
"""Stage 5: threat modelling and incident investigation for Attestor 4.2.

Two distinct planes, kept separate on purpose:

1. **Threat model** -- a STRIDE-style enumeration over a *described* component.
   These are adversary goals and therefore `hypothesis`: they are not measured,
   they are structured assumptions an assessor states up front so they can be
   checked against what the analyzer actually finds. The model never claims a
   threat is present; it claims a threat is *considered*.

2. **Incident investigation** -- findings the analyzer *actually* produced
   (measured) are carried into the case-file spine (case_file42), so an incident
   is a chain of evidence, not a narrative. Measured and hypothesis never merge.

Fail-closed: hostile or empty input resolves to a rejection, never a crash or a
silent pass. Stdlib only; nothing is executed or sent anywhere.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, Mapping, Sequence

VERSION = "4.2"
MODEL_SCHEMA = "attestor.threat-model/4.2"
INCIDENT_SCHEMA = "attestor.incident/4.2"
ID_RE = re.compile(r"[A-Za-z0-9_.:@/+-]{1,256}")

STRIDE = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)
STRIDE_SET = frozenset(STRIDE)

# Which analyzer rule prefixes plausibly bear on which STRIDE category. This is a
# mapping of *interest*, not a verdict: a finding in scope is evidence to weigh,
# not proof a threat is realised.
CATEGORY_HINTS = {
    "spoofing": ("auth", "cred", "token", "signature", "cert"),
    "tampering": ("integrity", "taint", "inject", "deserial", "path"),
    "repudiation": ("audit", "log", "sign"),
    "information_disclosure": ("leak", "secret", "disclosure", "exfil"),
    "denial_of_service": ("dos", "resource", "alloc", "loop",),
    "elevation_of_privilege": ("priv", "exec", "stack-pivot", "execve", "setuid"),
}


class ThreatModelError(ValueError):
    """A threat model or incident was malformed. Rejected fail-closed."""


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ThreatModelError("%s is invalid" % label)
    return value


def _text(value: Any, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str):
        raise ThreatModelError("%s must be a string" % label)
    stripped = value.strip()
    if not stripped:
        raise ThreatModelError("%s must not be empty" % label)
    if len(stripped) > maximum:
        raise ThreatModelError("%s exceeds %d characters" % (label, maximum))
    if any(ord(ch) < 32 and ch not in "\t\n" for ch in stripped):
        raise ThreatModelError("%s contains control characters" % label)
    return stripped


def model_component(*, name: str, description: str, boundaries: Iterable[str],
                    assets: Iterable[str], entry_points: Iterable[str]) -> dict[str, Any]:
    """Describe a component and the threats considered against it (hypothesis)."""
    comp = _id(name, "component name")
    desc = _text(description, "description")
    bounds = sorted({_text(b, "boundary") for b in boundaries})
    if not bounds:
        raise ThreatModelError("at least one trust boundary is required")
    owned = sorted({_text(a, "asset") for a in assets})
    entries = sorted({_text(e, "entry point") for e in entry_points})
    if not entries:
        raise ThreatModelError("at least one entry point is required")
    threats = []
    for category in STRIDE:
        threats.append({
            "category": category,
            "basis": "hypothesis",
            "considered": True,
            "statement": "Threat to %s under %s is considered and must be evidenced or dismissed."
                         % (comp, category.replace("_", " ")),
        })
    return {
        "schema": MODEL_SCHEMA,
        "version": VERSION,
        "component": comp,
        "description": desc,
        "trust_boundaries": bounds,
        "assets": owned,
        "entry_points": entries,
        "threats": threats,
    }


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ThreatModelError("%s must be a sha256 hex digest" % label)
    return value


def map_findings_to_threats(model: Mapping[str, Any],
                            findings: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Bind measured analyzer findings to the threats that were modelled.

    A finding is linked to a category when its rule contains one of that
    category's hint tokens. The link is evidence (`basis: measured`); it does not
    by itself mean the threat is realised, only that there is something to weigh.
    """
    if not isinstance(model, Mapping) or model.get("schema") != MODEL_SCHEMA:
        raise ThreatModelError("expected a threat model")
    categories = {t.get("category") for t in (model.get("threats") or [])}
    links = []
    for f in findings:
        rule = str(f.get("rule", "")).lower()
        for category in STRIDE:
            if category not in categories:
                continue
            for hint in CATEGORY_HINTS[category]:
                if hint in rule:
                    links.append({
                        "category": category,
                        "basis": "measured",
                        "finding_rule": str(f.get("rule", "")),
                        "finding_line": f.get("line"),
                        "severity": f.get("severity"),
                    })
                    break
    return links


def open_incident(*, title: str, component: str,
                  subject_sha256: str, subject_path: str) -> dict[str, Any]:
    """Start an incident investigation bound to the exact analyzed bytes."""
    import case_file42 as cf
    return cf.open_case(
        subject_path=_text(subject_path, "subject_path"),
        subject_sha256=_digest(subject_sha256, "subject_sha256"),
        rule="incident:%s" % _id(component, "component"),
        summary=_text(title, "incident title"),
        opened_by="threat-model-stage5",
    )


def investigate(*, model: Mapping[str, Any], findings: Sequence[Mapping[str, Any]],
                subject_path: str, subject_sha256: str,
                title: str = "incident", now: str | None = None) -> dict[str, Any]:
    """Carry measured findings through the evidence spine as one incident.

    The threat model (hypothesis) and the analyzer findings (measured) are both
    recorded, but never merged: the chain records which is which so a reader can
    tell load-bearing conclusions from assumptions.
    """
    import case_file42 as cf
    subject_sha = _digest(subject_sha256, "subject_sha256")
    case = open_incident(title=title, component=str(model.get("component", "unknown")),
                         subject_sha256=subject_sha, subject_path=subject_path)
    case = cf.append(case, stage="discovery", basis=cf.MEASURED,
                     summary="analyzer produced %d findings on %s" % (len(findings), subject_path),
                     evidence={"finding_count": len(findings),
                               "rules": sorted({str(f.get("rule")) for f in findings})})
    case = cf.append(case, stage="validation", basis=cf.HYPOTHESIS,
                     summary="stride threats modelled for %s" % str(model.get("component")),
                     evidence={"threats_considered": [t.get("category") for t in model.get("threats", [])]})
    links = map_findings_to_threats(model, findings)
    case = cf.append(case, stage="exploitability", basis=cf.MEASURED,
                     summary="%d findings map to modelled threats" % len(links),
                     evidence={"links": links})
    ok, problems = cf.verify(case)
    return {
        "schema": INCIDENT_SCHEMA,
        "version": VERSION,
        "incident_title": title,
        "subject": {"path": subject_path, "sha256": subject_sha},
        "measured_finding_count": len(findings),
        "threat_links": links,
        "chain_intact": ok,
        "chain_problems": problems,
        "case_file": case,
    }


def severity_for_category(links: Sequence[Mapping[str, Any]],
                          severities: Mapping[str, int]) -> dict[str, int]:
    """Aggregate a worst-seen severity per STRIDE category from measured links."""
    ranking = dict(severities)
    out = {c: 0 for c in STRIDE}
    for link in links:
        cat = link.get("category")
        sev = str(link.get("severity", "")).lower()
        if cat in out and sev in ranking:
            out[cat] = max(out[cat], ranking[sev])
    return out
