#!/usr/bin/env python3
"""Measured precision / recall / F1 for Attestor -- the number that tells you
whether a change made the engine BETTER or just LOUDER.

`benchmark.py` prints an honest LLM-vs-Attestor scorecard. This goes deeper: it
turns the labelled corpus (detect.EXPECTED over detect.CORPUS) into a real
confusion matrix, per rule and overall, and -- crucially -- measures the
false-positive reduction delivered by vendored-code detection + triage. That is
the metric that fixes the "20,485 findings, 19,795 useless" problem, because now
the reduction is a number you can defend, not a vibe.

    python3 evaluate.py                 # scorecard
    python3 evaluate.py --json          # machine-readable
    python3 evaluate.py --noise ROOT    # measure FP reduction on a real tree
    python3 evaluate.py --calibrate     # rewrite triage weights from precision
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import detect  # existing labelled-corpus scanner + EXPECTED set
import triage
import vendored


@dataclass
class RuleScore:
    rule: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class Scorecard:
    overall_precision: float
    overall_recall: float
    overall_f1: float
    tp: int
    fp: int
    fn: int
    per_rule: dict[str, RuleScore] = field(default_factory=dict)
    sample_counts: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# A small, embedded, labelled CLEAN corpus. Any finding on these is a false
# positive by construction -- this is how we measure precision honestly, since
# the vulnerable corpus alone can only measure recall.
# ---------------------------------------------------------------------------
CLEAN_SAMPLES: dict[str, str] = {
    "clean_config.py": (
        "import os\n"
        "DEBUG = os.environ.get('DEBUG', '0') == '1'\n"
        "DB_URL = os.environ['DATABASE_URL']\n"
        "TIMEOUT = 30\n"
        "def load_settings(path):\n"
        "    with open(path, encoding='utf-8') as f:\n"
        "        return f.read()\n"
    ),
    "clean_math.py": (
        "def mean(xs):\n"
        "    return sum(xs) / len(xs) if xs else 0.0\n"
        "def normalize(xs):\n"
        "    m = mean(xs)\n"
        "    return [x - m for x in xs]\n"
    ),
    "clean_api.js": (
        "async function getUser(id) {\n"
        "  const res = await fetch(`/api/users/${encodeURIComponent(id)}`);\n"
        "  if (!res.ok) throw new Error('request failed');\n"
        "  return res.json();\n"
        "}\n"
        "export default getUser;\n"
    ),
    "clean_util.py": (
        "import hashlib\n"
        "def digest(data: bytes) -> str:\n"
        "    return hashlib.sha256(data).hexdigest()\n"
        "def chunk(seq, n):\n"
        "    return [seq[i:i+n] for i in range(0, len(seq), n)]\n"
    ),
}


def evaluate_recall() -> tuple[dict[str, RuleScore], int, int]:
    """Recall on the vulnerable labelled corpus (detect.EXPECTED)."""
    corpus_dirs = [os.path.join(detect.CORPUS, d)
                   for d in ("c", "cpp", "haskell", "realworld")]
    corpus_dirs = [d for d in corpus_dirs if os.path.isdir(d)]
    files = detect.collect_paths(corpus_dirs) if corpus_dirs else []

    found: set[tuple[str, str]] = set()
    for path in files:
        for f in detect.scan_file(path):
            found.add((os.path.basename(path), f.rule))

    per_rule: dict[str, RuleScore] = {}
    for (fname, rule) in detect.EXPECTED:
        rs = per_rule.setdefault(rule, RuleScore(rule))
        if (fname, rule) in found:
            rs.tp += 1
        else:
            rs.fn += 1

    tp = sum(rs.tp for rs in per_rule.values())
    fn = sum(rs.fn for rs in per_rule.values())
    return per_rule, tp, fn


def evaluate_precision(per_rule: dict[str, RuleScore]) -> int:
    """False positives on the embedded CLEAN corpus (any finding == FP)."""
    fp_total = 0
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for name, content in CLEAN_SAMPLES.items():
            p = os.path.join(tmp, name)
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
            paths.append(p)
        for path in paths:
            for f in detect.scan_file(path):
                rs = per_rule.setdefault(f.rule, RuleScore(f.rule))
                rs.fp += 1
                fp_total += 1
    return fp_total


def build_scorecard() -> Scorecard:
    per_rule, tp, fn = evaluate_recall()
    fp = evaluate_precision(per_rule)

    op = tp / (tp + fp) if (tp + fp) else 0.0
    orr = tp / (tp + fn) if (tp + fn) else 0.0
    of1 = 2 * op * orr / (op + orr) if (op + orr) else 0.0

    sample_counts = {r: rs.tp + rs.fp + rs.fn for r, rs in per_rule.items()}
    return Scorecard(round(op, 3), round(orr, 3), round(of1, 3),
                     tp, fp, fn, per_rule, sample_counts)


# ---------------------------------------------------------------------------
# Noise-reduction measurement: the money metric. Run the aggregate scanners over
# a REAL tree, then show how many findings survive vendored + triage filtering.
# ---------------------------------------------------------------------------
def measure_noise_reduction(root: str) -> dict:
    findings = _collect_aggregate(root)
    before = len(findings)

    kept_fp, suppressed_vendor = vendored.filter_findings(findings, min_weight=0.5)
    triaged = triage.triage_all(findings)
    c = triage.counts(triaged)

    surviving = c["report"] + c["review"]
    return {
        "root": root,
        "raw_findings": before,
        "after_vendored_filter": len(kept_fp),
        "vendored_suppressed": len(suppressed_vendor),
        "triage_report": c["report"],
        "triage_review": c["review"],
        "triage_suppress": c["suppress"],
        "surviving_findings": surviving,
        "noise_removed": before - surviving,
        "noise_removed_pct": round((before - surviving) / before * 100, 1) if before else 0.0,
    }


def _collect_aggregate(root: str) -> list[dict]:
    out: list[dict] = []
    scanners = [
        ("secret_scanner", "scan_directory", "secrets"),
        ("exploit_detector", "scan_directory", None),
        ("iac_scanner", "scan_directory", None),
        ("js_scanner", "scan_directory", None),
    ]
    for modname, fn, cat in scanners:
        try:
            mod = __import__(modname)
            for f in getattr(mod, fn)(root):
                out.append({
                    "path": getattr(f, "path", ""),
                    "line": getattr(f, "line", 0),
                    "rule_id": getattr(f, "rule_id", ""),
                    "severity": getattr(f, "severity", "MEDIUM"),
                    "category": cat or getattr(f, "category", ""),
                })
        except Exception:
            continue
    return out


def calibrate(scorecard: Scorecard, min_samples: int = 3) -> dict[str, float]:
    """Rewrite triage rule confidence from measured precision, persist to disk."""
    updated = {}
    for rule, rs in scorecard.per_rule.items():
        if (rs.tp + rs.fp) < min_samples:
            continue
        new_conf = max(0.05, min(0.99, round(rs.precision, 3)))
        triage.RULE_CONFIDENCE[rule] = new_conf
        updated[rule] = new_conf
    triage.save_overrides()
    return updated


def render(sc: Scorecard) -> str:
    lines = []
    lines.append("\n  Attestor Precision / Recall / F1  (measured on labelled corpus)")
    lines.append("  " + "=" * 62)
    lines.append(f"  Overall:  precision {sc.overall_precision:.1%}   "
                 f"recall {sc.overall_recall:.1%}   F1 {sc.overall_f1:.3f}")
    lines.append(f"  Confusion: TP={sc.tp}  FP={sc.fp}  FN={sc.fn}")
    lines.append("")
    lines.append(f"  {'rule':<32}{'prec':>7}{'rec':>7}{'F1':>7}{'n':>5}")
    lines.append("  " + "-" * 60)
    ranked = sorted(sc.per_rule.values(), key=lambda r: (r.f1, r.recall))
    for rs in ranked:
        n = rs.tp + rs.fp + rs.fn
        lines.append(f"  {rs.rule[:31]:<32}{rs.precision:>7.0%}"
                     f"{rs.recall:>7.0%}{rs.f1:>7.2f}{n:>5}")
    lines.append("")
    weak = [rs for rs in ranked if rs.recall < 0.5 or (rs.tp + rs.fp and rs.precision < 0.5)]
    if weak:
        lines.append("  Weakest rules (fix these first):")
        for rs in weak[:8]:
            why = []
            if rs.recall < 0.5:
                why.append(f"misses {rs.fn}")
            if (rs.tp + rs.fp) and rs.precision < 0.5:
                why.append(f"{rs.fp} false alarms")
            lines.append(f"    - {rs.rule}: {', '.join(why)}")
    return "\n".join(lines)


def render_noise(nr: dict) -> str:
    return (
        f"\n  Noise-reduction on {nr['root']}"
        + "\n  " + "=" * 55
        + f"\n  raw findings:            {nr['raw_findings']}"
        + f"\n  vendored-suppressed:     {nr['vendored_suppressed']}"
        + f"\n  triage suppress:         {nr['triage_suppress']}"
        + f"\n  surviving (report+review): {nr['surviving_findings']}"
        + f"\n  NOISE REMOVED:           {nr['noise_removed']} "
          f"({nr['noise_removed_pct']}%)"
        + "\n  -> this is the fix for the 20k-findings self-scan problem."
    )


def to_dict(sc: Scorecard) -> dict:
    return {
        "overall": {
            "precision": sc.overall_precision,
            "recall": sc.overall_recall,
            "f1": sc.overall_f1,
            "tp": sc.tp, "fp": sc.fp, "fn": sc.fn,
        },
        "per_rule": {
            r: {"precision": round(rs.precision, 3), "recall": round(rs.recall, 3),
                "f1": round(rs.f1, 3), "tp": rs.tp, "fp": rs.fp, "fn": rs.fn}
            for r, rs in sc.per_rule.items()
        },
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--noise", metavar="ROOT", help="measure FP reduction on a real tree")
    ap.add_argument("--calibrate", action="store_true",
                    help="rewrite triage weights from measured precision")
    args = ap.parse_args(argv)

    sc = build_scorecard()

    if args.noise:
        nr = measure_noise_reduction(args.noise)
        if args.json:
            print(json.dumps(nr, indent=2))
        else:
            print(render_noise(nr))
        return 0

    if args.calibrate:
        updated = calibrate(sc)
        print(f"  Calibrated {len(updated)} rule weights from measured precision.")
        print(f"  Saved to {triage._CONFIG_FILE}")
        return 0

    if args.json:
        print(json.dumps(to_dict(sc), indent=2))
    else:
        print(render(sc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
