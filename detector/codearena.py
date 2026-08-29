#!/usr/bin/env python3
"""
codearena.py -- Attestor's benchmark dashboard.

Arena collects the numbers that matter for this project: rule count, planted-bug
recall, false positives, generated-code cleanliness, forge gate success, evolve
improvements, and mutation-gauntlet catch rate.
"""
from __future__ import annotations

import argparse
import json

import benchmark
import advanced_rules
import codebench
import detect
import evolve
import multilang
import mutation_gauntlet
import nativescan
import precision_catalog


ARENA_MUTATION_SEED = """\
import hashlib

DEBUG=False

def token(x):
    if x is None:
        return hashlib.sha256(b'x').hexdigest()
    return x

def fetch(requests, url):
    return requests.get(url, verify=True, timeout=5)
"""


def _evolve_probe() -> dict:
    src = {
        "content": "import requests\nr = requests.get(url, verify=False)\n",
        "repo": "arena/probe",
        "path": "probe.py",
        "url": "",
        "license": "synthetic",
        "ext": ".py",
    }
    result = evolve.evolve_source(src, cycles=3)
    before = result["history"][0]["findings_before"] if result["history"] else 0
    after = len(result["findings"])
    fixes = sum(count for _rid, count, _note in result["applied"])
    return {"findings_before": before, "findings_after": after, "fixes": fixes}


def measure() -> dict:
    b = benchmark.measure()
    cb = codebench.measure()
    mut = mutation_gauntlet.run(ARENA_MUTATION_SEED, "arena_seed.py")
    mutants = len(mut["mutants"])
    caught = sum(1 for m in mut["mutants"] if m["caught"])
    evolve_metrics = _evolve_probe()
    false_positives = b["generated_regex_findings"] + b["generated_ast_findings"]
    rule_sets = {
        "core": {rule.rid for rule in detect.RULES},
        "native": {rule.rid for rule in nativescan.LINE_RULES},
        "extended_languages": {row[0] for rows in multilang.RULES.values() for row in rows},
        "advanced_2_2": {rule.rid for rule in advanced_rules.RULES},
        "precision_flow_2_3": {rule.rid for rule in precision_catalog.RULES},
    }
    all_rules = set().union(*rule_sets.values())
    return {
        "rule_count": len(all_rules),
        "rule_count_by_pack": {name: len(rows) for name, rows in rule_sets.items()},
        "advanced_rule_self_test": not advanced_rules.validate_catalog(),
        "precision_catalog_self_test": not precision_catalog.validate_catalog(),
        "planted_bug_recall_pct": b["bug_recall_pct"],
        "planted_bugs_detected": b["bugs_detected"],
        "planted_bugs_expected": b["bugs_expected"],
        "false_positives_on_generated_code": false_positives,
        "generated_code_clean": false_positives == 0,
        "generated_lines": b["generated_lines"],
        "forge_success_rate_pct": round(
            100 * cb["assisted_gate_solved"] / cb["assisted_gate_total"], 1)
            if cb["assisted_gate_total"] else 0.0,
        "forge_success": cb["assisted_gate_solved"],
        "forge_total": cb["assisted_gate_total"],
        "evolve_findings_before": evolve_metrics["findings_before"],
        "evolve_findings_after": evolve_metrics["findings_after"],
        "evolve_safe_fixes": evolve_metrics["fixes"],
        "mutation_catch_rate_pct": round(100 * caught / mutants, 1) if mutants else 0.0,
        "mutants_caught": caught,
        "mutants_total": mutants,
        "mutation_rule_targets": len(mut["gaps"]),
    }


def render(metrics: dict) -> str:
    lines = [
        "Code Arena",
        "=" * 10,
        "rule count: %d" % metrics["rule_count"],
        "rule packs: " + ", ".join("%s=%d" % item
                                     for item in metrics["rule_count_by_pack"].items()),
        "advanced rule fixtures: %s" % (
            "passing" if metrics["advanced_rule_self_test"] else "FAILED"),
        "15K precision flow catalog: %s" % (
            "passing" if metrics["precision_catalog_self_test"] else "FAILED"),
        "planted-bug recall: %.1f%% (%d/%d)" % (
            metrics["planted_bug_recall_pct"],
            metrics["planted_bugs_detected"],
            metrics["planted_bugs_expected"]),
        "false positives on generated code: %d" % metrics["false_positives_on_generated_code"],
        "generated-code cleanliness: %s (%d lines)" % (
            "clean" if metrics["generated_code_clean"] else "findings present",
            metrics["generated_lines"]),
        "forge success rate: %.1f%% (%d/%d)" % (
            metrics["forge_success_rate_pct"],
            metrics["forge_success"],
            metrics["forge_total"]),
        "evolve improvement probe: %d -> %d findings, %d safe fix(es)" % (
            metrics["evolve_findings_before"],
            metrics["evolve_findings_after"],
            metrics["evolve_safe_fixes"]),
        "mutation gauntlet: %.1f%% caught (%d/%d), %d new rule target(s)" % (
            metrics["mutation_catch_rate_pct"],
            metrics["mutants_caught"],
            metrics["mutants_total"],
            metrics["mutation_rule_targets"]),
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    metrics = measure()
    print(json.dumps(metrics, indent=2) if args.json else render(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
