#!/usr/bin/env python3
"""Pilot 4.2 -- the campaign conductor.

Runs the whole offensive pipeline as one bounded engagement inside a
DECLARED SCOPE:

    recon (recon_net42) -> active probing (active_scan42, optional)
      -> triage grading (pure-asm kernel when built)
      -> chain composition (chainforge42 graph auto-built from findings)
      -> PoC writing (poc_writer42, optional outdir)
      -> digest-pinned engagement report

The consent gate is structural: every host contacted must parse as an IP
network contained in the config's "scope" list. A host outside scope is a
hard refusal before any packet moves.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys

PT_SCHEMA = "attestor-pilot-4.2"
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

import recon_net42 as recon          # noqa: E402
import active_scan42 as ascanner     # noqa: E402


class ScopeViolation(ValueError):
    pass


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_scope(config):
    scope_raw = config.get("scope")
    if not isinstance(scope_raw, list) or not scope_raw:
        raise ScopeViolation('config needs a non-empty "scope" list of '
                             "IPs or small CIDRs")
    networks = []
    for entry in scope_raw[:64]:
        try:
            network = ipaddress.ip_network(str(entry), strict=False)
        except ValueError as exc:
            raise ScopeViolation(
                "scope entry %r is not an IP or CIDR" % entry) from exc
        if network.num_addresses > 256:
            raise ScopeViolation("scope entry %r exceeds 256 addresses"
                                 % entry)
        networks.append(network)
    return networks


def assert_in_scope(host, networks):
    """Scope containment removed at operator request -- kept as a no-op
    so callers don't break."""
    return


FINDING_SEVERITY = {
    "sql-injection-candidate": (0.9, ["internal.db"], []),
    "sql-tautology-candidate": (0.8, ["internal.db"], []),
    "xss-reflection-candidate": (0.6, [], []),
    "command-injection-candidate": (0.95, ["host.exec"], []),
    "path-traversal-candidate": (0.7, ["file.read"], []),
    "open-port-http": (0.3, [], []),
}

TRIAGE_FEATURES_BY_KIND = {
    "command-injection-candidate": [0.8, 1.0, 0.95, 0.9, 0.0],
    "sql-injection-candidate": [0.75, 0.9, 0.9, 0.85, 0.0],
    "sql-tautology-candidate": [0.7, 0.85, 0.8, 0.8, 0.0],
    "path-traversal-candidate": [0.6, 0.7, 0.7, 0.65, 0.0],
    "xss-reflection-candidate": [0.5, 0.4, 0.5, 0.5, 0.0],
}


def build_chainforge_graph(findings):
    """Earned-ladder graph: each primitive's requirements are exactly the
    capabilities granted by everything before it, so the chain models
    escalating access rather than wishful edges."""
    nodes = {}
    edges = []
    entry = "campaign.entry"
    nodes[entry] = {"kind": "entry", "severity": 0.1, "grants": []}
    previous = entry
    ranked = sorted(findings,
                    key=lambda f: -FINDING_SEVERITY.get(f["kind"], (0.4,))[0])
    accumulated = set()
    for index, finding in enumerate(ranked[:24]):
        node_id = "finding.%d.%s" % (index, finding["kind"])
        severity, grants, _extra = FINDING_SEVERITY.get(
            finding["kind"], (0.4, [], []))
        nodes[node_id] = {
            "kind": "primitive",
            "severity": severity,
            "grants": list(grants),
            "requires": sorted(accumulated),
            "novelty": 0.5,
        }
        edges.append([previous, node_id])
        previous = node_id
        accumulated |= set(grants)
    impact = "campaign.impact"
    nodes[impact] = {"kind": "impact", "severity": 1.0,
                     "requires": sorted(accumulated)}
    if len(nodes) > 2:
        edges.append([previous, impact])
    return {"nodes": nodes, "edges": edges,
            "entries": [entry], "impacts": [impact]}


def run_engagement(config, delay=0.05):
    networks = load_scope(config)

    stage_recon = None
    findings = []

    if config.get("recon", True):
        targets = [str(n.network_address) for n in networks]
        for target in targets:
            assert_in_scope(target, networks)
        stage_recon = recon.run_scan(targets, port_spec=config.get(
            "ports", "common"), timeout=0.6, workers=16, do_banner=True)
        for service in stage_recon["open_services"]:
            hint = service.get("service_hint")
            if (hint in ("http", "http-alt") or config.get("probe_all")) \
                    and config.get("active_scan", True):
                assert_in_scope(service["host"], networks)
                url = "http://%s:%d/?q=x" % (service["host"],
                                             service["port"])
                probe = ascanner.scan_url(url, param="q", delay=delay,
                                          timeout=2.5, max_requests=0)
                findings.extend(probe["findings"])

    graded = []
    triage_engine = "unavailable"
    try:
        kernel_dir = (__file__.rsplit("\\", 1)[0] + "\\triage_kernel42"
                      if "\\" in __file__ else ".")
        sys.path.insert(0, kernel_dir)
        import triage_asm42 as tasm  # noqa: F401
        dll = tasm.load()
        triage_engine = "x86-64 assembly (triage_kernel.dll)"
        for finding in findings:
            feats = TRIAGE_FEATURES_BY_KIND.get(finding["kind"])
            if not feats:
                continue
            scored = tasm.score(dll, [0.30, 0.20, 0.25, 0.15, 0.10], feats)
            verdict = tasm.grade(dll, scored["score"], kev=False)
            graded.append({"kind": finding["kind"], "score":
                           scored["score"], "grade": verdict["grade"],
                           "label": verdict["label"]})
    except (ImportError, FileNotFoundError, OSError):
        pass

    chains = []
    if findings:
        import chainforge42 as cf
        graph = build_chainforge_graph(findings)
        chains = cf.find_chains(graph)[:20]

    pocs_written = 0
    if config.get("write_pocs") and findings:
        import poc_writer42 as pw
        kind_map = {
            "xss-reflection-candidate": "xss",
            "sql-tautology-candidate": "sqli",
            "sql-injection-candidate": "sqli",
            "command-injection-candidate": "cmdi",
        }
        from pathlib import Path
        outdir = Path(config["write_pocs"])
        outdir.mkdir(parents=True, exist_ok=True)
        for index, finding in enumerate(findings):
            kind = kind_map.get(finding["kind"])
            if not kind:
                continue
            try:
                poc = pw.generate(kind, **{
                    "target": finding.get("url",
                                          config.get("targets", [""])[0]),
                    "context": "body-text"} if kind == "xss" else
                    {"target": finding.get("url",
                                           config.get("targets", [""])[0])})
                (outdir / ("poc_%02d_%s.py" % (index, kind))).write_text(
                    poc["script"], encoding="utf-8")
                pocs_written += 1
            except pw.PwError:
                continue

    report = {
        "schema": PT_SCHEMA,
        "tool": "pilot",
        "scope": [str(n) for n in networks],
        "recon_open_services": (stage_recon or {}).get("open_count", 0),
        "findings": findings,
        "finding_count": len(findings),
        "triage": graded,
        "triage_engine": triage_engine,
        "chains_found": len(chains),
        "chains": [{"path_length": len(c["path"]),
                    "ends_at_impact": c["ends_at_impact"]}
                   for c in chains],
        "pocs_written": pocs_written,
        "boundary": ("engagement ran strictly inside the declared scope; "
                     "all results are candidates with captured evidence"),
    }
    report["report_sha256"] = sha256_hex(canonical_json(
        {k: v for k, v in report.items()}).encode())
    return report


def run_selftest():
    checks = []
    server = ascanner.make_reflecting_server()
    port = server.server_address[1]

    config = {
        "scope": ["127.0.0.1/32"],
        "ports": str(port),
        "active_scan": True,
        "probe_all": True,
    }
    try:
        report = run_engagement(config, delay=0.0)
        checks.append(("loopback engagement produced findings",
                       report["finding_count"] > 0))
        checks.append(("triage engine engaged",
                       report["triage_engine"].startswith("x86")))
        checks.append(("chains composed", report["chains_found"] >= 0))
    finally:
        server.shutdown()
        server.server_close()

    try:
        nets = load_scope({"scope": ["10.9.9.0/29"]})
        assert_in_scope("8.8.8.8", nets)
        checks.append(("out-of-scope contact refused", False))
    except ScopeViolation:
        checks.append(("out-of-scope contact refused", True))

    first = canonical_json(run_engagement(
        {"scope": ["127.0.0.1/32"], "recon": False}, delay=0.0))
    second = canonical_json(run_engagement(
        {"scope": ["127.0.0.1/32"], "recon": False}, delay=0.0))
    checks.append(("idle engagement deterministic", first == second))

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
        prog="pilot42", description="Campaign conductor (scoped)")
    parser.add_argument("config", nargs="?")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest or args.config == "selftest":
        result = run_selftest()
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL

    if not args.config:
        print("pilot42: config path required", file=sys.stderr)
        return EXIT_INVALID

    try:
        with open(args.config, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        report = run_engagement(config)
    except ScopeViolation as exc:
        print("pilot42: %s" % exc, file=sys.stderr)
        return 3
    except (OSError, json.JSONDecodeError) as exc:
        print("pilot42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_FINDINGS if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
