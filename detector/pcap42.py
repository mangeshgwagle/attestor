#!/usr/bin/env python3
"""PCAP Analyzer 4.2 -- offline packet-capture inspection.

Detectors (stdlib struct parsing, fully offline):
- cleartext credentials in HTTP POST bodies and FTP USER/PASS commands
- DNS tunneling shape: abnormally long subdomain labels / high-label entropy
- beaconing: repeated same-pair flows at regular intervals

Boundaries: reads only operator-supplied capture files; bounded packets;
never opens a socket itself. Exit 1 when findings exist, else house codes.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys

PC_SCHEMA = "attestor-pcap-analyzer-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

MIN_LABEL_LEN = 30
BEACON_MIN_COUNT = 6


class PcapError(ValueError):
    pass


def shannon(value):
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total)
                for n in counts.values())


def parse_pcap(blob):
    if len(blob) < 24:
        raise PcapError("file too small to be a pcap")
    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise PcapError("unsupported capture magic %r" % magic)
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
        endian + "HHiIII", blob[4:24])
    packets = []
    offset = 24
    while offset + 16 <= len(blob):
        ts_sec, ts_usec, incl_len, _orig = struct.unpack(
            endian + "IIII", blob[offset:offset + 16])
        offset += 16
        frame = blob[offset:offset + incl_len]
        offset += incl_len
        if len(frame) < incl_len:
            break
        packets.append({"ts": ts_sec + ts_usec / 1e6, "frame": frame})
    return linktype, packets


def parse_frame(frame, linktype):
    if linktype == 1:                       # Ethernet
        if len(frame) < 34:
            return None
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0800:
            return None
        ip = frame[14:]
    elif linktype in (101, 228):            # raw IP variants
        ip = frame
    else:
        return None
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    l4 = ip[ihl:]
    if proto == 6 and len(l4) >= 20:        # TCP
        sport, dport = struct.unpack("!HH", l4[0:4])
        payload_off = ((l4[12] >> 4) * 4)
        return {"src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": "tcp", "payload": l4[payload_off:]}
    if proto == 17 and len(l4) >= 8:        # UDP
        sport, dport = struct.unpack("!HH", l4[0:4])
        return {"src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": "udp", "payload": l4[8:]}
    return None


def detect_cleartext_creds(records):
    hits = []
    for rec in records:
        text = rec["payload"][:512].decode("latin-1", errors="replace")
        low = text.lower()
        marker = None
        if "password=" in low or "passwd=" in low or "pass=" in low:
            marker = "http-post-credential"
        elif text.startswith("USER ") or text.startswith("PASS "):
            marker = "ftp-credential"
        if marker:
            hits.append({
                "kind": marker,
                "src": rec["src"], "dst": rec["dst"],
                "port": rec["dport"],
                "preview_redacted": low.split("=")[0] + "=...",
            })
    return hits


def detect_dns_tunneling(records):
    hits = []
    for rec in records:
        if not (rec["proto"] == "udp" and rec["dport"] == 53):
            continue
        payload = rec["payload"]
        if len(payload) < 14:
            continue
        try:
            qdcount = struct.unpack("!H", payload[4:6])[0]
        except struct.error:
            continue
        if qdcount < 1:
            continue
        labels = []
        i = 12
        try:
            while i < len(payload) and payload[i]:
                length = payload[i]
                label = payload[i + 1:i + 1 + length]
                labels.append(label.decode("latin-1",
                                           errors="replace"))
                i += 1 + length
        except IndexError:
            continue
        for label in labels:
            if len(label) >= MIN_LABEL_LEN and shannon(label) > \
                    3.8:
                hits.append({
                    "kind": "dns-tunnel-shape",
                    "src": rec["src"], "dst": rec["dst"],
                    "label_preview": label[:24] + "...",
                    "label_len": len(label),
                    "entropy": round(shannon(label), 2),
                })
                break
    return hits


def detect_beaconing(records):
    flows = {}
    for rec in records:
        key = (rec["src"], rec["dst"], rec["dport"])
        flows.setdefault(key, []).append(rec["ts"])
    hits = []
    for (src, dst, port), stamps in sorted(flows.items()):
        stamps.sort()
        if len(stamps) < BEACON_MIN_COUNT:
            continue
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap <= 0:
            continue
        jitter = sum(abs(g - mean_gap) for g in gaps) / len(gaps)
        if jitter / mean_gap < 0.15:
            hits.append({
                "kind": "regular-beaconing",
                "src": src, "dst": dst, "dst_port": port,
                "occurrences": len(stamps),
                "mean_interval_s": round(mean_gap, 2),
                "jitter_ratio": round(jitter / mean_gap, 3),
            })
    return hits


def analyze_file(path):
    with open(path, "rb") as handle:
        blob = handle.read(64 * 1024 * 1024)
    linktype, packets = parse_pcap(blob)
    records = []
    for packet in packets:
        parsed = parse_frame(packet["frame"], linktype)
        if parsed:
            parsed["ts"] = packet["ts"]
            records.append(parsed)
    creds = detect_cleartext_creds(records)
    tunnels = detect_dns_tunneling(records)[:200]
    beacons = detect_beaconing(records)[:100]
    findings = creds + tunnels + beacons
    return {
        "schema": PC_SCHEMA,
        "tool": "pcap-analyzer",
        "file": path,
        "packets_parsed": len(records),
        "findings": findings,
        "finding_count": len(findings),
        "boundary": ("offline inspection of an operator-supplied capture; "
                     "no network activity was performed"),
    }


def run_selftest():
    checks = []

    def build_pcap(frames, linktype=1):
        out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144,
                          linktype)
        import time as _time
        base_ts = 1700000000
        for index, frame in enumerate(frames):
            out += struct.pack("<IIII", base_ts + index * 10,
                               0, len(frame), len(frame)) + frame
        return out

    def eth_ip_tcp(payload, sport=12345, dport=80, src="10.0.0.5",
                   dst="93.184.216.34"):
        udp_or_tcp_len = 20 + len(payload)
        tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50,
                          0x18, 8192, 0, 0)
        total_len = 20 + udp_or_tcp_len
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0,
                         64, 6, 0,
                         bytes(int(x) for x in src.split(".")),
                         bytes(int(x) for x in dst.split(".")))
        frame = (b"\x00" * 6 + b"\x11" * 6 +
                 struct.pack("!H", 0x0800) + ip + tcp + payload)
        return frame

    http_post = (b"POST /login HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                 b"user=bob&password=hunter2")
    ftp_frame_payload = b"PASS secret123\r\n"

    def eth_ip_tcp_ftp(payload):
        return eth_ip_tcp(payload, dport=21)

    frames = [eth_ip_tcp(http_post),
              eth_ip_tcp_ftp(ftp_frame_payload)]
    blob = build_pcap(frames)
    linktype, packets = parse_pcap(blob)
    checks.append(("synthetic pcap parses", len(packets) == 2))
    records = [dict(parse_frame(p["frame"], linktype), ts=p["ts"])
               for p in packets if parse_frame(p["frame"], linktype)]
    cred_hits = detect_cleartext_creds(records)
    kinds = {h["kind"] for h in cred_hits}
    checks.append(("http post credential detected",
                   "http-post-credential" in kinds))
    checks.append(("ftp credential detected", "ftp-credential" in kinds))

    beacon_frames = []
    for index in range(BEACON_MIN_COUNT + 2):
        beacon_frames.append((eth_ip_tcp(b"x", dport=443,
                                         src="10.0.0.9",
                                         dst="203.0.113.7"),
                              index * 60))
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
    for frame, stamp in beacon_frames:
        out += struct.pack("<IIII", 1700000000 + stamp, 0,
                           len(frame), len(frame)) + frame
    _lt, bpackets = parse_pcap(out)
    brecords = [dict(parse_frame(p["frame"], 1), ts=p["ts"])
               for p in bpackets if parse_frame(p["frame"], 1)]
    beacons = detect_beaconing(brecords)
    checks.append(("regular beaconing flagged", len(beacons) == 1))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": PC_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pcap42", description="Offline PCAP analyzer")
    parser.add_argument("files", nargs="+")
    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    all_findings = []
    per_file = []
    try:
        for path in args.files:
            report = analyze_file(path)
            per_file.append(report)
            all_findings.extend(report["findings"])
    except PcapError as exc:
        print("pcap42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID
    except OSError as exc:
        print("pcap42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    result = {
        "schema": PC_SCHEMA,
        "tool": "pcap-analyzer",
        "files": per_file,
        "total_findings": len(all_findings),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_FINDING if all_findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
