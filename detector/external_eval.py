#!/usr/bin/env python3
"""Offline CWE-level scorer for Attestor.

Reads `corpus/manifest.jsonl`, runs the appropriate scanners on every sample,
maps findings → CWE via `corpus/rule_cwe_map.json`, and builds a confusion
matrix **per CWE** and **per rule**.  Prints precision/recall/F1 tables and
writes `corpus/scorecard.json`.

Usage:
    python -m detector.external_eval              # scorecard only
    python -m detector.external_eval --json       # machine-readable
    python -m detector.external_eval --calibrate  # write triage weights from precision

Calibration updates `.attestor-triage.json` via `triage.save_overrides()`;
`attestor triage <dir>` then reflects the new weights.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

ROOT = os.path.dirname(_HERE)
MANIFEST = os.path.join(ROOT, "corpus", "manifest.jsonl")
RULE_CWE_MAP = os.path.join(ROOT, "corpus", "rule_cwe_map.json")
SCORECARD = os.path.join(ROOT, "corpus", "scorecard.json")

import detect
import triage

try:
    import js_scanner
    import taint_tracker
    import semantic_similarity
    import nativescan
except Exception:
    js_scanner = taint_tracker = semantic_similarity = nativescan = None


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

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

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn


# ---------------------------------------------------------------------------
# Rule → CWE map loading (harvested sources + JSON overlay)
# ---------------------------------------------------------------------------
def _harvest_map() -> dict[str, list[str]]:
    """Build rule→CWE map from live modules (fallback if JSON missing/incomplete)."""
    m: dict[str, list[str]] = {}

    # detect.py: RULE_CWE (primary) + RULE_CWE_ALSO (extra)
    for rid, cwe in detect.RULE_CWE.items():
        if cwe:
            m[rid] = [cwe]
    for rid, extra in detect.RULE_CWE_ALSO.items():
        lst = m.setdefault(rid, [])
        for e in extra:
            if e not in lst:
                lst.append(e)

    # js_scanner
    if js_scanner:
        for rid, cat, desc, pat, sev, cwe in js_scanner.JS_RULES:
            if cwe:
                m[rid] = [cwe]

    # taint_tracker: synthesize TAINT-<sink_type>
    if taint_tracker:
        for sink, (stype, cwe) in taint_tracker.TAINT_SINKS.items():
            if cwe:
                m[f"TAINT-{stype}"] = [cwe]

    # semantic_similarity: builtin CVE patterns
    if semantic_similarity:
        for p in semantic_similarity.BUILTIN_CVE_PATTERNS:
            if p.get("cwe"):
                m[f"CVE-{p['cve_id']}"] = [p["cwe"]]

    return m


def load_rule_cwe_map() -> dict[str, list[str]]:
    """Load JSON overlay, falling back to harvest; JSON takes precedence."""
    base = _harvest_map()
    if not os.path.exists(RULE_CWE_MAP):
        return base
    try:
        with open(RULE_CWE_MAP, encoding="utf-8") as fh:
            overlay = json.load(fh)
        # overlay wins
        for k, v in overlay.items():
            base[k] = v
    except Exception:
        pass
    return base


def cwes_for(rule_id: str, rule_cwe_map: dict[str, list[str]]) -> list[str]:
    """Longest-prefix match (like triage.rule_confidence)."""
    best = ""
    for prefix in rule_cwe_map:
        if rule_id.startswith(prefix) and len(prefix) > len(best):
            best = prefix
    return rule_cwe_map.get(best, [])


# ---------------------------------------------------------------------------
# Scanner dispatch per language
# ---------------------------------------------------------------------------
def scan_sample(path: str, lang: str, rule_cwe_map: dict) -> list[dict]:
    """Run language-appropriate scanners; return normalized finding dicts."""
    out = []
    if lang in ("c", "cpp"):
        # detect.py rules
        try:
            for f in detect.scan_file(path):
                out.append({
                    "rule": f.rule,
                    "cwe": cwes_for(f.rule, rule_cwe_map),
                    "lang": lang,
                })
        except Exception:
            pass
        # nativescan.py rules (buffer overflows, format string, etc.)
        if nativescan:
            try:
                for f in nativescan.scan_file(path):
                    out.append({
                        "rule": f.rule,
                        "cwe": cwes_for(f.rule, rule_cwe_map),
                        "lang": lang,
                    })
            except Exception:
                pass
    elif lang == "python":
        if taint_tracker:
            try:
                for f in taint_tracker.scan_file(path):
                    out.append({
                        "rule": f"TAINT-{f.sink_type}",
                        "cwe": [f.sink_cwe] if f.sink_cwe else [],
                        "lang": lang,
                    })
            except Exception:
                pass
        if semantic_similarity:
            try:
                for f in semantic_similarity.scan_file(path):
                    out.append({
                        "rule": f"CVE-{f.cve_id}",
                        "cwe": [f.cve_cwe] if f.cve_cwe else [],
                        "lang": lang,
                    })
            except Exception:
                pass
    elif lang in ("javascript", "typescript", "js"):
        if js_scanner:
            try:
                for f in js_scanner.scan_file(path):
                    out.append({
                        "rule": f.rule_id,
                        "cwe": [f.cwe] if f.cwe else [],
                        "lang": lang,
                    })
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def evaluate(manifest_path: str, rule_cwe_map: dict[str, list[str]]) -> tuple[
        dict[str, Confusion], dict[str, Confusion], int, int, int, int]:
    """
    Returns (per_cwe_confusion, per_rule_confusion, total_tp, total_fp, total_fn, total_tn)
    """
    per_cwe: dict[str, Confusion] = defaultdict(Confusion)
    per_rule: dict[str, Confusion] = defaultdict(Confusion)

    total = 0
    with open(manifest_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            sample = json.loads(line)
            total += 1

            cwe = sample["cwe"]
            vulnerable = sample["vulnerable"]
            lang = sample["language"]
            path = os.path.join(ROOT, sample["path"])

            findings = scan_sample(path, lang, rule_cwe_map)

            # For this sample, which CWEs were flagged?
            flagged_cwes: set[str] = set()
            rule_hits: set[str] = set()  # rules that fired on this sample
            for f in findings:
                rule = f["rule"]
                rule_hits.add(rule)
                for c in f.get("cwe", []):
                    flagged_cwes.add(c)

            # Per-CWE confusion
            cwe_conf = per_cwe[cwe]
            if vulnerable:
                if cwe in flagged_cwes:
                    cwe_conf.tp += 1
                else:
                    cwe_conf.fn += 1
            else:
                if cwe in flagged_cwes:
                    cwe_conf.fp += 1
                else:
                    cwe_conf.tn += 1

            # Per-rule confusion (only for rules that map to this CWE)
            for rule in rule_hits:
                rule_cwes = cwes_for(rule, rule_cwe_map)
                if cwe in rule_cwes:
                    rconf = per_rule[rule]
                    if vulnerable:
                        rconf.tp += 1
                    else:
                        rconf.fp += 1
            # Rules that *didn't* fire but map to this CWE: FN for vulnerable, TN for safe
            for rule, cwes in rule_cwe_map.items():
                if cwe in cwes and rule not in rule_hits:
                    rconf = per_rule[rule]
                    if vulnerable:
                        rconf.fn += 1
                    else:
                        rconf.tn += 1

    # Compute totals
    tp = sum(c.tp for c in per_cwe.values())
    fp = sum(c.fp for c in per_cwe.values())
    fn = sum(c.fn for c in per_cwe.values())
    tn = sum(c.tn for c in per_cwe.values())
    return per_cwe, per_rule, tp, fp, fn, tn


def build_scorecard(
    per_cwe: dict[str, Confusion],
    per_rule: dict[str, Confusion],
    tp: int, fp: int, fn: int, tn: int,
) -> dict:
    overall = Confusion(tp, fp, fn, tn)
    return {
        "overall": {
            "precision": round(overall.precision, 3),
            "recall": round(overall.recall, 3),
            "f1": round(overall.f1, 3),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        },
        "per_cwe": {
            cwe: {
                "precision": round(c.precision, 3),
                "recall": round(c.recall, 3),
                "f1": round(c.f1, 3),
                "tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn,
                "total": c.total,
            }
            for cwe, c in per_cwe.items()
        },
        "per_rule": {
            rule: {
                "precision": round(c.precision, 3),
                "recall": round(c.recall, 3),
                "f1": round(c.f1, 3),
                "tp": c.tp, "fp": c.fp, "fn": c.fn, "tn": c.tn,
                "total": c.total,
            }
            for rule, c in per_rule.items() if c.total > 0
        },
    }


def render(scorecard: dict) -> str:
    out = []
    ov = scorecard["overall"]
    out.append("\n  Attestor CWE-level Precision / Recall / F1  (on labeled corpus)")
    out.append("  " + "=" * 68)
    out.append(f"  Overall:  precision {ov['precision']:.1%}   "
               f"recall {ov['recall']:.1%}   F1 {ov['f1']:.3f}")
    out.append(f"  Confusion: TP={ov['tp']}  FP={ov['fp']}  FN={ov['fn']}  TN={ov['tn']}")

    # Per-CWE table
    out.append("")
    out.append("  Per-CWE:")
    out.append(f"  {'CWE':<10}{'prec':>7}{'rec':>7}{'F1':>7}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}")
    out.append("  " + "-" * 56)
    for cwe in sorted(scorecard["per_cwe"],
                       key=lambda k: scorecard["per_cwe"][k]["f1"]):
        v = scorecard["per_cwe"][cwe]
        out.append(f"  {cwe:<10}{v['precision']:>7.0%}{v['recall']:>7.0%}"
                   f"{v['f1']:>7.2f}{v['tp']:>5}{v['fp']:>5}{v['fn']:>5}{v['tn']:>5}")

    # Per-rule table (top 30 by F1 ascending = worst first)
    out.append("")
    out.append("  Per-rule (worst F1 first, top 30):")
    out.append(f"  {'rule':<36}{'prec':>7}{'rec':>7}{'F1':>7}{'n':>5}")
    out.append("  " + "-" * 62)
    ranked = sorted(scorecard["per_rule"].items(),
                    key=lambda kv: (kv[1]["f1"], kv[1]["recall"]))
    for rule, v in ranked[:30]:
        out.append(f"  {rule[:35]:<36}{v['precision']:>7.0%}"
                   f"{v['recall']:>7.0%}{v['f1']:>7.2f}{v['total']:>5}")

    return "\n".join(out)

    # Per-rule table (top 30 by F1 ascending = worst first)
    out.append("")
    out.append("  Per-rule (worst F1 first, top 30):")
    out.append(f"  {'rule':<36}{'prec':>7}{'rec':>7}{'F1':>7}{'n':>5}")
    out.append("  " + "-" * 62)
    ranked = sorted(scorecard["per_rule"].items(),
                    key=lambda kv: (kv[1]["f1"], kv[1]["recall"]))
    for rule, v in ranked[:30]:
        out.append(f"  {rule[:35]:<36}{v['precision']:>7.0%}"
                   f"{v['recall']:>7.0%}{v['f1']:>7.2f}{v['total']:>5}")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------
def calibrate(scorecard: dict, min_samples: int = 5) -> dict[str, float]:
    """Set triage.RULE_CONFIDENCE[rule] = measured precision; persist."""
    updated = {}
    for rule, v in scorecard["per_rule"].items():
        obs = v["tp"] + v["fp"]          # predicted positives
        if obs >= min_samples:
            new_conf = max(0.05, min(0.99, round(v["precision"], 3)))
            triage.RULE_CONFIDENCE[rule] = new_conf
            updated[rule] = new_conf
    triage.save_overrides()
    return updated


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_RULE_CWE_MAP: dict[str, list[str]] = {}

def main(argv=None) -> int:
    global _RULE_CWE_MAP
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--calibrate", action="store_true",
                    help="rewrite triage weights from measured precision")
    ap.add_argument("--min-samples", type=int, default=5,
                    help="min observations for calibration (default 5)")
    args = ap.parse_args(argv)

    _RULE_CWE_MAP = load_rule_cwe_map()

    # If calibrating and scorecard exists, load it instead of re-evaluating
    if args.calibrate and os.path.exists(SCORECARD):
        with open(SCORECARD, encoding="utf-8") as fh:
            sc = json.load(fh)
        updated = calibrate(sc, args.min_samples)
        print(f"  Calibrated {len(updated)} rule weights from measured precision.")
        print(f"  Saved to {triage._CONFIG_FILE}")
        return 0

    if not os.path.exists(MANIFEST):
        print("ERROR: manifest not found at %s" % MANIFEST, file=sys.stderr)
        return 2

    t0 = time.time()
    per_cwe, per_rule, tp, fp, fn, tn = evaluate(MANIFEST, _RULE_CWE_MAP)
    sc = build_scorecard(per_cwe, per_rule, tp, fp, fn, tn)

    if args.calibrate:
        updated = calibrate(sc, args.min_samples)
        if not args.json:
            print(f"  Calibrated {len(updated)} rule weights from measured precision.")
            print(f"  Saved to {triage._CONFIG_FILE}")
        return 0

    # Write scorecard
    with open(SCORECARD, "w", encoding="utf-8") as fh:
        json.dump(sc, fh, indent=2, sort_keys=True)

    if args.json:
        print(json.dumps(sc, indent=2))
    else:
        print(render(sc))
        print(f"\n  elapsed {time.time() - t0:.1f}s  wrote {SCORECARD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())