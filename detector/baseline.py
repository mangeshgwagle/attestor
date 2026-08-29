#!/usr/bin/env python3
"""Finding suppression / baseline system -- allows teams to acknowledge existing
findings and only alert on new ones. Stores baselines as JSON files."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_BASELINE_FILE = ".attestor-baseline.json"


@dataclass
class SuppressedFinding:
    fingerprint: str
    rule_id: str
    path: str
    reason: str = ""
    suppressed_by: str = ""
    suppressed_at: str = ""
    expires: str = ""


@dataclass
class Baseline:
    version: int = 1
    created: str = ""
    updated: str = ""
    suppressions: dict[str, SuppressedFinding] = field(default_factory=dict)


def fingerprint(path: str, line: int, rule_id: str, message: str = "") -> str:
    normalized_path = path.replace("\\", "/")
    content = f"{normalized_path}:{rule_id}:{message[:100]}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def fingerprint_finding(finding: dict) -> str:
    return fingerprint(
        finding.get("path", ""),
        finding.get("line", 0),
        finding.get("rule_id", ""),
        finding.get("message", finding.get("description", "")),
    )


def load_baseline(path: str = DEFAULT_BASELINE_FILE) -> Baseline:
    if not os.path.exists(path):
        return Baseline()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        baseline = Baseline(
            version=data.get("version", 1),
            created=data.get("created", ""),
            updated=data.get("updated", ""),
        )
        for fp, entry in data.get("suppressions", {}).items():
            baseline.suppressions[fp] = SuppressedFinding(
                fingerprint=fp,
                rule_id=entry.get("rule_id", ""),
                path=entry.get("path", ""),
                reason=entry.get("reason", ""),
                suppressed_by=entry.get("suppressed_by", ""),
                suppressed_at=entry.get("suppressed_at", ""),
                expires=entry.get("expires", ""),
            )
        return baseline
    except (json.JSONDecodeError, OSError) as e:
        print(f"warning: could not load baseline {path}: {e}", file=sys.stderr)
        return Baseline()


def save_baseline(baseline: Baseline, path: str = DEFAULT_BASELINE_FILE):
    now = datetime.now(timezone.utc).isoformat()
    if not baseline.created:
        baseline.created = now
    baseline.updated = now
    data = {
        "version": baseline.version,
        "created": baseline.created,
        "updated": baseline.updated,
        "suppressions": {
            fp: {
                "rule_id": s.rule_id,
                "path": s.path,
                "reason": s.reason,
                "suppressed_by": s.suppressed_by,
                "suppressed_at": s.suppressed_at,
                "expires": s.expires,
            }
            for fp, s in baseline.suppressions.items()
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def suppress_finding(
    baseline: Baseline,
    finding: dict,
    reason: str = "",
    suppressed_by: str = "",
    expires: str = "",
) -> str:
    fp = fingerprint_finding(finding)
    now = datetime.now(timezone.utc).isoformat()
    baseline.suppressions[fp] = SuppressedFinding(
        fingerprint=fp,
        rule_id=finding.get("rule_id", ""),
        path=finding.get("path", ""),
        reason=reason,
        suppressed_by=suppressed_by,
        suppressed_at=now,
        expires=expires,
    )
    return fp


def unsuppress_finding(baseline: Baseline, fp: str) -> bool:
    if fp in baseline.suppressions:
        del baseline.suppressions[fp]
        return True
    return False


def _is_expired(suppression: SuppressedFinding) -> bool:
    if not suppression.expires:
        return False
    try:
        expires_dt = datetime.fromisoformat(suppression.expires)
        return datetime.now(timezone.utc) > expires_dt
    except ValueError:
        return False


def filter_findings(
    findings: list[dict],
    baseline: Baseline,
) -> tuple[list[dict], list[dict]]:
    new_findings = []
    suppressed = []
    for finding in findings:
        fp = fingerprint_finding(finding)
        suppression = baseline.suppressions.get(fp)
        if suppression and not _is_expired(suppression):
            suppressed.append(finding)
        else:
            new_findings.append(finding)
    return new_findings, suppressed


def create_baseline_from_findings(
    findings: list[dict],
    reason: str = "initial baseline",
    suppressed_by: str = "",
) -> Baseline:
    baseline = Baseline()
    for finding in findings:
        suppress_finding(baseline, finding, reason=reason, suppressed_by=suppressed_by)
    return baseline


def render_baseline_status(baseline: Baseline) -> str:
    lines = [f"\n  Baseline: {len(baseline.suppressions)} suppressed finding(s)"]
    if baseline.created:
        lines.append(f"  Created:  {baseline.created}")
    if baseline.updated:
        lines.append(f"  Updated:  {baseline.updated}")
    expired = sum(1 for s in baseline.suppressions.values() if _is_expired(s))
    if expired:
        lines.append(f"  Expired:  {expired} (will be re-reported)")
    by_rule = {}
    for s in baseline.suppressions.values():
        by_rule[s.rule_id] = by_rule.get(s.rule_id, 0) + 1
    if by_rule:
        lines.append("  By rule:")
        for rule, count in sorted(by_rule.items(), key=lambda x: -x[1]):
            lines.append(f"    {rule}: {count}")
    return "\n".join(lines)


def render_filter_result(
    new_findings: list[dict],
    suppressed: list[dict],
    total: int,
) -> str:
    lines = []
    lines.append(f"\n  Total findings:      {total}")
    lines.append(f"  Suppressed:          {len(suppressed)}")
    lines.append(f"  New (unsuppressed):  {len(new_findings)}")
    return "\n".join(lines)
