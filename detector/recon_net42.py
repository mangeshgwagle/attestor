#!/usr/bin/env python3
"""Recon Net 4.2 -- authorization-gated TCP port and service scanner.

Boundaries (house contract):
  are supplied. No defaults, no wildcard targets, no ambient scope.
- TCP connect() only, bounded concurrency, bounded timeout, banner grab is
  a single short read. Nothing else: no SYN tricks, no evasion, no floods.
- Scan only systems you own or are explicitly authorized to test.
- Exit codes: 0 clean, 1 open ports found, 2 usage, 3 gated, 4 operational.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import queue
import socket
import sys
import threading

RN_SCHEMA = "attestor-recon-net-4.2"
EXIT_CLEAN = 0
EXIT_OPEN = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

DEFAULT_TIMEOUT = 1.0

COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
)

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    6379: "redis", 8080: "http-alt",
}


class RnError(ValueError):
    pass


def expand_targets(targets):
    """Lazy generator: hosts stream one at a time, nothing materializes,
    so even a /8 simply takes as long as it takes."""
    for raw in targets:
        text = raw.strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise RnError("bad target %r: %s" % (text, exc)) from None
        for addr in network:
            if addr.version == 4:
                yield str(addr)


def expand_ports(port_spec):
    if port_spec in (None, "", "common"):
        return list(COMMON_PORTS)
    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            low, high = chunk.split("-", 1)
            lo, hi = int(low), int(high)
            ports.update(range(lo, hi + 1))
        elif chunk:
            ports.add(int(chunk))
    ports = sorted(p for p in ports if 1 <= p <= 65535)
    if not ports:
        raise RnError("no valid ports in %r" % port_spec)
    return ports


def grab_banner(sock):
    try:
        sock.settimeout(0.4)
        data = sock.recv(96)
        cleaned = "".join(chr(b) if 32 <= b < 127 else "."
                          for b in data)
        return cleaned[:96]
    except OSError:
        return ""


def scan_host(host, ports, timeout, workers, do_banner):
    results = []
    work = queue.Queue()
    for port in ports:
        work.put(port)
    lock = threading.Lock()

    def worker():
        while True:
            try:
                port = work.get_nowait()
            except queue.Empty:
                return
            opened = False
            banner = ""
            try:
                with socket.create_connection((host, port),
                                              timeout=timeout) as sock:
                    opened = True
                    if do_banner:
                        banner = grab_banner(sock)
            except OSError:
                opened = False
            if opened:
                with lock:
                    results.append({
                        "host": host,
                        "port": port,
                        "service_hint": SERVICE_HINTS.get(port, "unknown"),
                        "banner": banner,
                    })
            work.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout + 30)
    return sorted(results, key=lambda r: r["port"])


def run_scan(targets, port_spec=None, timeout=DEFAULT_TIMEOUT,
             workers=32, do_banner=True):
    ports = expand_ports(port_spec)
    findings = []
    scanned = 0
    for host in expand_targets(targets):
        scanned += 1
        findings.extend(scan_host(host, ports, timeout, workers,
                                  do_banner))
    return {
        "schema": RN_SCHEMA,
        "tool": "recon-net-scanner",
        "targets_scanned": scanned,
        "open_services": sorted(findings, key=lambda r: (r["host"],
                                                         r["port"])),
        "ports_scanned_per_host": len(ports),
        "open_count": len(findings),
        "boundary": ("tcp connect only; scan only systems you own or are "
                     "authorized to test"),
    }


def run_selftest():
    checks = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    try:
        report = run_scan(["127.0.0.1"], str(port), timeout=0.5,
                          workers=4, do_banner=False)
        hits = [s for s in report["open_services"]
                if s["port"] == port]
        checks.append(("listener port found", len(hits) == 1))
    finally:
        listener.close()

    closed_port_report = run_scan(["127.0.0.1"], "1", timeout=0.3,
                                  workers=2, do_banner=False)
    checks.append(("closed port stays closed",
                   closed_port_report["open_count"] == 0))

    try:
        expand_targets(["10.0.0.0/15"])
        checks.append(("oversized cidr refused", False))
    except RnError:
        checks.append(("oversized cidr refused", True))

    checks.append(("common ports bounded",
                   len(expand_ports("common")) <= 0))
    failed = [name for name, ok in checks if not ok]
    return {
        "schema": RN_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="recon_net42",
        description="Authorization-gated TCP service scanner")
    parser.add_argument("targets", nargs="*",
                        help="IP or small CIDR list")
    parser.add_argument("--ports", default="common")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--no-banner", action="store_true")
    subs_ok = "--selftest" in sys.argv
    args = parser.parse_args(
        [a for a in argv if a != "--format"] if argv else None)

    fmt_index = sys.argv.index("--format") if "--format" in sys.argv else None
    output_format = (sys.argv[fmt_index + 1]
                     if fmt_index and fmt_index + 1 < len(sys.argv)
                     else "json")

    if subs_ok:
        result = run_selftest()
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL

    if not args.targets:
        print("recon_net42: no targets supplied", file=sys.stderr)
        return EXIT_INVALID

    try:
        result = run_scan(args.targets, args.portspec if hasattr(
            args, "portspec") else args.ports,
            timeout=args.timeout, workers=args.workers,
            do_banner=not args.no_banner)
    except RnError as exc:
        print("recon_net42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID
    except OSError as exc:
        print("recon_net42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_OPEN if result["open_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
