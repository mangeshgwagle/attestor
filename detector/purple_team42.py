#!/usr/bin/env python3
"""Purple Team Loop 4.2 -- offense-to-detection bridge.

Boundaries (house contract):
- Offline only; standard library; deterministic outputs.
- Attack templates reference the Offensive Lab's own synthetic artifacts.
- Generated Sigma rules are JSON-shaped Sigma (spec-compatible fields);
  every rule ships only after it fires on its attack event and stays silent
  on the bundled negative events.
- The ATT&CK catalog here is a curated subset relevant to Attestor's own
  exercises, not the full enterprise matrix.
- Exit codes follow house convention: 0 clean, 1 finding/gap, 2 usage,
  3 gated, 4 operational.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

PT_SCHEMA = "attestor-purple-team-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PtError(ValueError):
    pass


# ------------------------------------------------------- ATT&CK subset

ATTACK_TECHNIQUES = {
    "T1499.003": {"name": "Application/System Exploitation for DoS",
                  "summary": "application exhaustion floods",
                  "covered_by": ["redos-synthesizer"]},
    "T1552.001": {"name": "Credentials In Files",
                  "summary": "secrets stored in source/config",
                  "covered_by": ["entropy-secrets", "template-context-engine"]},
    "T1552.004": {"name": "Private Keys",
                  "summary": "private key material exposure or recovery",
                  "covered_by": ["ecdsa-recover"]},
    "T1110.002": {"name": "Password Cracking",
                  "summary": "dictionary attacks against authenticators",
                  "covered_by": ["jwt-crack"]},
    "T1190": {"name": "Exploit Public-Facing Application",
              "summary": "exploitation of internet-facing software flaws",
              "covered_by": ["poc-verifier", "template-context-engine",
                             "ssrf-allowlist-reasoner"]},
    "T1210": {"name": "Exploitation of Remote Services",
              "summary": "exploitation of internal services",
              "covered_by": ["poc-verifier"]},
    "T1557": {"name": "Adversary-in-the-Middle",
              "summary": "interception or decryption of traffic",
              "covered_by": ["padding-oracle-simulator"]},
    "T1203": {"name": "Exploitation for Client Execution",
              "summary": "payload-driven code execution",
              "covered_by": ["deserialization-gadget-graph"]},
    "T1059.007": {"name": "JavaScript/JScript",
                  "summary": "script execution including injected script",
                  "covered_by": ["template-context-engine"]},
    "T1595.002": {"name": "Vulnerability Scanning",
                  "summary": "scanning targets for vulnerabilities",
                  "covered_by": ["ssrf-allowlist-reasoner", "poc-verifier"]},
}

FINDING_KIND_TO_TECHNIQUES = {
    "catastrophic-backtracking": ["T1499.003"],
    "jwt-none-alg": ["T1190"],
    "jwt-weak-secret": ["T1110.002"],
    "ecdsa-nonce-reuse": ["T1552.004"],
    "xss-interpolation-point": ["T1190", "T1059.007"],
    "ssti-interpolation-point": ["T1190"],
    "ssrf-bypass-candidate": ["T1190", "T1595.002"],
    "sql-injection-confirmed": ["T1190", "T1210"],
    "command-injection-confirmed": ["T1190", "T1210"],
    "padding-oracle-confirmed": ["T1557"],
    "gadget-chain-found": ["T1203"],
    "secret-candidate": ["T1552.001"],
    "trojan-source-bidi": ["T1190"],
}


def map_finding(finding_kind):
    techniques = FINDING_KIND_TO_TECHNIQUES.get(finding_kind)
    if techniques is None:
        raise PtError("unknown finding kind: %r" % (finding_kind,))
    details = []
    for tid in techniques:
        entry = ATTACK_TECHNIQUES.get(tid)
        if entry:
            details.append({
                "technique_id": tid,
                "name": entry["name"],
                "summary": entry["summary"],
            })
    return {
        "schema": PT_SCHEMA,
        "tool": "attack-mapper",
        "finding_kind": finding_kind,
        "technique_ids": techniques,
        "techniques": details,
        "note": "curated subset mapping for Attestor's own exercise space",
    }


def coverage_report():
    covered = {}
    for tid, entry in ATTACK_TECHNIQUES.items():
        covered[tid] = sorted(entry["covered_by"])
    return {
        "schema": PT_SCHEMA,
        "tool": "attack-mapper",
        "report": "coverage",
        "technique_count": len(ATTACK_TECHNIQUES),
        "techniques": covered,
    }


# ------------------------------------------------------ Sigma emitter

SIGMA_VERSION = "2.0.0"


def _eval_atom(event, field_spec, expected):
    field, _, mods = field_spec.partition("|")
    actual = event.get(field)
    if actual is None:
        return False
    actual = str(actual)
    for mod in mods.split("|"):
        if mod == "contains":
            if expected not in actual:
                return False
        elif mod == "startswith":
            if not actual.startswith(expected):
                return False
        elif mod == "endswith":
            if not actual.endswith(expected):
                return False
        elif mod == "re":
            if not re.search(expected, actual):
                return False
        elif mod == "gt":
            try:
                if not float(actual) > float(expected):
                    return False
            except ValueError:
                return False
        elif mod:
            raise PtError("unsupported modifier: %r" % mod)
        else:
            if actual != expected:
                return False
    return True


def evaluate_rule(rule, event):
    detection = rule.get("detection", {})
    selections = {k: v for k, v in detection.items()
                  if k not in ("condition", " timeframe")}
    condition = detection.get("condition", "")
    results = {}
    for name, criteria in selections.items():
        ok = True
        if isinstance(criteria, dict):
            for field_spec, expected in criteria.items():
                if not _eval_atom(event, field_spec, str(expected)):
                    ok = False
                    break
        else:
            ok = False
        results[name] = ok
    tokens = re.findall(r"[()]|\band\b|\bor\b|\bnot\b|\b\d+\sof\s\S+\*?|\S+",
                        condition.replace("(", " ( ").replace(")", " ) "))
    out = ""
    for tok in tokens:
        if tok.lower() in ("and", "or", "not", "(", ")"):
            out += " " + tok.lower() + " "
        elif tok in results:
            out += " " + ("True" if results[tok] else "False") + " "
        else:
            m = re.fullmatch(r"(\d+) of (\S+)\*?", tok)
            if m:
                count = int(m.group(1))
                prefix = m.group(2).rstrip("*")
                hits = sum(1 for k in results
                           if k.startswith(prefix) and results[k])
                out += " " + ("True" if hits >= count else "False") + " "
            else:
                raise PtError("cannot parse condition token: %r" % tok)
    try:
        return bool(eval(out.strip(), {"__builtins__": {}}, {}))
    except Exception as exc:
        raise PtError("condition evaluation failed (%r) for %r"
                      % (exc, condition)) from None


ATTACK_TEMPLATES = [
    {
        "id": "AT-REDOS-001",
        "title": "ReDoS worst-case probe submitted to a handler",
        "lab_tool": "offensive_lab42.py redos",
        "finding_kind": "catastrophic-backtracking",
        "techniques": ["T1499.003"],
        "positive_event": {
            "process.command_line":
                "attestor redos --pattern (a+)+$ --step-cap 400000",
            "event.duration_ms": "18432",
        },
        "negative_events": [
            {"process.command_line": "attestor redos --pattern ^a+b$",
             "event.duration_ms": "12"},
            {"process.command_line": "pytest -q test_routes.py",
             "event.duration_ms": "900"},
        ],
        "sigma": {
            "title": "Catastrophic regex pattern handed to analysis or "
                     "matching engine",
            "id": "a3f1c2de-0001-4a10-9f01-attestorpt00001",
            "status": "stable",
            "description": "Nested-quantifier regex shapes reaching a "
                           "matching engine indicate ReDoS probing.",
            "logsource": {"category": "process_creation",
                          "product": "any"},
            "detection": {
                "sel_cmd": {
                    "process.command_line|re":
                        r"--pattern\s+\S*(\(\w+\+\)\+|\(\w\|\w\w\)\+)"
                },
                "sel_slow": {"event.duration_ms|gt": "5000"},
                "condition": "sel_cmd and sel_slow",
            },
            "tags": ["attack.t1499_003"],
            "falsepositives": ["long-running legitimate static-analysis runs"],
            "level": "high",
        },
    },
    {
        "id": "AT-JWT-NONE-001",
        "title": "Bearer JWT with empty signature segment presented",
        "lab_tool": "offensive_lab42.py jwt --action none",
        "finding_kind": "jwt-none-alg",
        "techniques": ["T1190"],
        "positive_event": {
            "http.request.auth_header":
                "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZW1vIn0.",
        },
        "negative_events": [
            {"http.request.auth_header":
             "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0."
             "c3VwZXJzZWNyZXRzaWduYXR1cmU"},
            {"http.request.auth_header": ""},
        ],
        "sigma": {
            "title": "JWT bearer token with empty signature (alg=none shape)",
            "id": "a3f1c2de-0002-4a10-9f01-attestorpt00002",
            "status": "stable",
            "description": "Authorization headers carrying a JWT whose "
                           "signature segment is absent.",
            "logsource": {"category": "webserver", "product": "http"},
            "detection": {
                "sel": {
                    "http.request.auth_header|re":
                        r"(?i)bearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?\s*$"
                },
                "condition": "sel",
            },
            "tags": ["attack.t1190"],
            "falsepositives": ["health endpoints that intentionally accept "
                               "unsigned tokens"],
            "level": "critical",
        },
    },
    {
        "id": "AT-SQLI-TAUT-001",
        "title": "Classic boolean-tautology injection in query parameter",
        "lab_tool": "offensive_lab42.py poc-verify (sqli-sqlite)",
        "finding_kind": "sql-injection-confirmed",
        "techniques": ["T1190", "T1210"],
        "positive_event": {
            "url.query": "user=' OR '1'='1",
            "http.response.status_code": "200",
        },
        "negative_events": [
            {"url.query": "user=alice", "http.response.status_code": "200"},
            {"url.query": "user=o'brien", "http.response.status_code": "200"},
        ],
        "sigma": {
            "title": "Boolean tautology pattern in user parameter",
            "id": "a3f1c2de-0003-4a10-9f01-attestorpt00003",
            "status": "stable",
            "description": "Query parameters shaped like classic OR-tautology "
                           "SQL injection probes.",
            "logsource": {"category": "webserver", "product": "http"},
            "detection": {
                "sel": {"url.query|re":
                        r"(?:'|%27)\s*(?:OR|AND)\s+(?:'|%27)?1(?:'|%27)?="
                        r"(?:'|%27)?1"},
                "cond_ok": {"http.response.status_code": "200"},
                "condition": "sel and cond_ok",
            },
            "tags": ["attack.t1190", "attack.t1210"],
            "falsepositives": ["security scanners you run yourself"],
            "level": "high",
        },
    },
    {
        "id": "AT-CMDI-SEMI-001",
        "title": "Command chaining metacharacter inside executed parameter",
        "lab_tool": "offensive_lab42.py poc-verify (cmd-echo)",
        "finding_kind": "command-injection-confirmed",
        "techniques": ["T1190", "T1210"],
        "positive_event": {
            "process.parent.name": "echo-service",
            "process.command_line": "sh -c echo hi; cat /etc/hostname",
        },
        "negative_events": [
            {"process.parent.name": "cron",
             "process.command_line": "sh -c backup.sh --daily"},
            {"process.parent.name": "echo-service",
             "process.command_line": "sh -c echo hello world"},
        ],
        "sigma": {
            "title": "Command chaining in child of echo-like service",
            "id": "a3f1c2de-0004-4a10-9f01-attestorpt00004",
            "status": "stable",
            "description": "Semicolon-chained commands spawned by services "
                           "that should never chain.",
            "logsource": {"category": "process_creation", "product": "any"},
            "detection": {
                "sel_parent": {"process.parent.name": "echo-service"},
                "sel_chain": {"process.command_line|re": r";\s*\S+"},
                "condition": "sel_parent and sel_chain",
            },
            "tags": ["attack.t1059"],
            "falsepositives": [],
            "level": "critical",
        },
    },
    {
        "id": "AT-SSRF-META-001",
        "title": "Request targeting cloud metadata endpoint",
        "lab_tool": "offensive_lab42.py ssrf-check",
        "finding_kind": "ssrf-bypass-candidate",
        "techniques": ["T1190", "T1595.002"],
        "positive_event": {
            "destination.hostname": "169.254.169.254",
            "url.path": "/latest/meta-data/",
        },
        "negative_events": [
            {"destination.hostname": "api.internal.example",
             "url.path": "/v1/status"},
        ],
        "sigma": {
            "title": "Outbound connection to cloud metadata service",
            "id": "a3f1c2de-0005-4a10-9f01-attestorpt00005",
            "status": "stable",
            "description": "Any workload contacting link-local metadata "
                           "addresses outside approved agents.",
            "logsource": {"category": "network_connection", "product": "any"},
            "detection": {
                "sel_ip": {"destination.hostname|contains": "169.254.169.254"},
                "sel_gcp": {"destination.hostname": "metadata.google.internal"},
                "sel_path": {"url.path|contains": "meta-data"},
                "condition": "1 of sel_*",
            },
            "tags": ["attack.t1552.005"],
            "falsepositives": ["cloud agent daemons"],
            "level": "critical",
        },
    },
    {
        "id": "AT-PICKLE-SINK-001",
        "title": "Deserialization sink reached with caller-controlled data",
        "lab_tool": "offensive_lab42.py gadget-chain",
        "finding_kind": "gadget-chain-found",
        "techniques": ["T1203"],
        "positive_event": {
            "service.module": "orders",
            "code.function": "pickle.loads",
            "data.origin": "request.body",
        },
        "negative_events": [
            {"service.module": "orders",
             "code.function": "json.loads",
             "data.origin": "request.body"},
            {"service.module": "cache",
             "code.function": "pickle.loads",
             "data.origin": "local.snapshot"},
        ],
        "sigma": {
            "title": "pickle.loads invoked on request-origin data",
            "id": "a3f1c2de-0006-4a10-9f01-attestorpt00006",
            "status": "stable",
            "description": "Dangerous deserialization sink fed by "
                           "network-originated payloads.",
            "logsource": {"category": "application", "product": "python"},
            "detection": {
                "sel_fn": {"code.function": "pickle.loads"},
                "sel_src": {"data.origin": "request.body"},
                "condition": "sel_fn and sel_src",
            },
            "tags": ["attack.t1203"],
            "falsepositives": [],
            "level": "critical",
        },
    },
]

TEMPLATE_IDS = {template["id"]: template for template in ATTACK_TEMPLATES}

RULE_ID_PREFIX = "SIGMA"


def emit_rules(template_ids=None):
    chosen = ([TEMPLATE_IDS[t] for t in template_ids if t in TEMPLATE_IDS]
              if template_ids else ATTACK_TEMPLATES)
    rules = []
    for template in chosen:
        rule = dict(template["sigma"])
        rule["related"] = [{"id": template["id"], "type": "derived"}]
        rule["schema"] = PT_SCHEMA
        digest = sha256_hex(canonical_json(rule).encode())
        rule["rule_sha256"] = digest
        rules.append({"template_id": template["id"], "rule": rule})
    return {
        "schema": PT_SCHEMA,
        "tool": "sigma-emitter",
        "rules": rules,
        "count": len(rules),
    }


def verify_rules():
    results = []
    for template in ATTACK_TEMPLATES:
        rule = template["sigma"]
        fires_pos = evaluate_rule(rule, template["positive_event"])
        negatives_silent = all(
            not evaluate_rule(rule, event)
            for event in template["negative_events"])
        valid = fires_pos and negatives_silent
        results.append({
            "template_id": template["id"],
            "fires_on_attack_artifact": fires_pos,
            "silent_on_negatives": negatives_silent,
            "valid": valid,
        })
    failed = [r["template_id"] for r in results if not r["valid"]]
    return {
        "schema": PT_SCHEMA,
        "tool": "rule-replay-verifier",
        "results": results,
        "valid_count": sum(1 for r in results if r["valid"]),
        "total": len(results),
        "failed": failed,
        "passed": not failed,
    }


def detection_gaps():
    verification = verify_rules()
    valid_ids = {r["template_id"] for r in verification["results"]
                 if r["valid"]}
    missing = [t["id"] for t in ATTACK_TEMPLATES if t["id"] not in valid_ids]
    total = len(ATTACK_TEMPLATES)
    covered = total - len(missing)
    return {
        "schema": PT_SCHEMA,
        "tool": "detection-gap-scorer",
        "templates_total": total,
        "templates_covered": covered,
        "coverage_ratio": round(covered / max(total, 1), 4),
        "missing_templates": missing,
        "note": ("coverage is over Attestor's own attack-template set, not "
                 "an enterprise threat-model claim"),
    }


def map_tool_to_attack(lab_tool):
    hits = []
    for tid, entry in ATTACK_TECHNIQUES.items():
        if lab_tool in entry["covered_by"]:
            hits.append(tid)
    if not hits:
        raise PtError("tool %r is not mapped in the curated catalog"
                      % (lab_tool,))
    return {"schema": PT_SCHEMA, "tool": "attack-mapper",
            "lab_tool": lab_tool, "technique_ids": sorted(hits)}


def run_selftest():
    checks = []
    mapped = map_finding("jwt-weak-secret")
    checks.append(("mapper resolves jwt-weak-secret",
                   mapped["technique_ids"] == ["T1110.002"]))
    verification = verify_rules()
    checks.append(("all emitted rules validate", verification["passed"]))
    gaps = detection_gaps()
    checks.append(("gap scorer sees full coverage",
                   gaps["missing_templates"] == []))
    emission = emit_rules(["AT-JWT-NONE-001"])
    rule = emission["rules"][0]["rule"]
    checks.append(("emitted rule carries digest",
                   len(rule["rule_sha256"]) == 64))
    try:
        fired_on_empty = evaluate_rule(rule, {})
        checks.append(("empty event does not fire", fired_on_empty is False))
    except Exception:
        checks.append(("empty event does not fire", False))
    failed = [name for name, ok in checks if not ok]
    return {
        "schema": PT_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="purple_team42",
        description="Attestor Purple Team Loop 4.2 (offline)")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("map", help="map a finding kind to ATT&CK techniques")
    p.add_argument("--finding-kind", required=True)

    p = subs.add_parser("tool-map", help="map a lab tool to ATT&CK techniques")
    p.add_argument("--lab-tool", required=True)

    p = subs.add_parser("coverage", help="technique-to-tool coverage")

    p = subs.add_parser("emit", help="emit Sigma (JSON) rules")
    p.add_argument("--templates", help="comma-separated template ids")
    p.add_argument("--out")

    p = subs.add_parser("verify", help="replay-verify every emitted rule")

    p = subs.add_parser("gaps", help="score detection coverage")

    subs.add_parser("self-test")

    parser.add_argument("--format", choices=["text", "json"], default="json")
    args = parser.parse_args(argv)

    try:
        if args.command == "map":
            result = map_finding(args.finding_kind)
            code = EXIT_CLEAN
        elif args.command == "tool-map":
            result = map_tool_to_attack(args.lab_tool)
            code = EXIT_CLEAN
        elif args.command == "coverage":
            result = coverage_report()
            code = EXIT_CLEAN
        elif args.command == "emit":
            ids = args.templates.split(",") if args.templates else None
            result = emit_rules(ids)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as handle:
                    json.dump(result, handle, indent=2, sort_keys=True)
                result["written_to"] = args.out
            code = EXIT_CLEAN
        elif args.command == "verify":
            result = verify_rules()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        elif args.command == "gaps":
            result = detection_gaps()
            code = EXIT_FINDING if result["missing_templates"] else EXIT_CLEAN
        elif args.command == "self-test":
            result = run_selftest()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        else:  # pragma: no cover
            parser.error("unknown command")
    except PtError as exc:
        print("purple_team42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID
    except OSError as exc:
        print("purple_team42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
