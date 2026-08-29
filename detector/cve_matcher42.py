#!/usr/bin/env python3
"""Offline CVE matcher -- dependencies versus an operator-supplied feed.

Boundaries (house contract):
- Offline only. The feed is either the bundled sample or a JSON file in an
  NVD-like shape that the operator supplies; nothing downloads anything.
- Version comparisons are honest about unknown formats: they return
  "unknown" rather than guessing.
- Matches are review points, not proof of exploitability; reachability stays
  with the analyzer evidence chain.
- Exit codes: 0 clean, 1 matches found, 2 usage, 4 operational failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

CVE_SCHEMA = "attestor-cve-matcher-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

DEP_FEED_ENTRY_CAP = 50_000


class CveError(ValueError):
    pass


BUNDLED_SAMPLE_FEED = {
    "schema": "attestor-cve-sample-feed-4.2",
    "entries": [
        {
            "cve": "CVE-2021-44228",
            "product": "log4j-core",
            "summary": "Apache Log4j2 JNDI features do not protect against "
                       "attacker-controlled LDAP endpoints (Log4Shell).",
            "affected": "<=2.14.1",
            "severity": {"cvss_v31": 10.0},
        },
        {
            "cve": "CVE-2022-22965",
            "product": "spring-beans",
            "summary": "Spring Framework data binding RCE on JDK 9+ "
                       "(Spring4Shell).",
            "affected": ">=5.3.0,<5.3.18",
            "severity": {"cvss_v31": 9.8},
        },
        {
            "cve": "CVE-2023-32681",
            "product": "requests",
            "summary": "Proxy-Authorization header leak on redirect to "
                       "a different origin.",
            "affected": "<2.31.0",
            "severity": {"cvss_v31": 6.1},
        },
        {
            "cve": "CVE-2020-8203",
            "product": "lodash",
            "summary": "Prototype pollution in zipObjectDeep paths.",
            "affected": "<4.17.19",
            "severity": {"cvss_v31": 7.4},
        },
    ],
}


def _version_tokens(version):
    tokens = re.findall(r"\d+|[A-Za-z]+", version.lstrip("vV"))
    out = []
    for token in tokens:
        if token.isdigit():
            out.append((0, int(token), ""))
        else:
            out.append((1, 0, token.lower()))
    return tuple(out) if out else ((2, 0, ""),)


def compare_versions(left, right):
    """Return -1/0/1, or None when the pair is not confidently comparable."""
    try:
        lt = _version_tokens(left)
        rt = _version_tokens(right)
    except Exception:
        return None
    if not lt or not rt:
        return None
    # any alphabetic component makes the comparison inconclusive; guessing
    # an ordering for pre-release tags is exactly the wrong place to be clever
    if any(part[0] != 0 for part in lt + rt):
        return None
    return -1 if lt < rt else (1 if lt > rt else 0)


def _matches_range(version, affected):
    for clause in re.split(r"\|\||,", affected):
        clause = clause.strip()
        if not clause:
            continue
        match = re.fullmatch(r"(<=|>=|<|>|=)\s*([^\s,|]+)", clause)
        if not match:
            return None
        op, bound = match.group(1), match.group(2)
        cmp_result = compare_versions(version, bound)
        if cmp_result is None:
            return None
        ok = {
            "<": cmp_result < 0,
            "<=": cmp_result <= 0,
            ">": cmp_result > 0,
            ">=": cmp_result >= 0,
            "=": cmp_result == 0,
        }[op]
        if not ok:
            return False
    return True


def load_feed(path=None):
    if path is None:
        return dict(BUNDLED_SAMPLE_FEED)
    with open(path, "r", encoding="utf-8") as handle:
        feed = json.load(handle)
    entries = feed.get("entries")
    if not isinstance(entries, list):
        raise CveError('feed must contain an "entries" list')
    if len(entries) > FEED_ENTRY_CAP:
        raise CveError("feed exceeds entry cap %d" % FEED_ENTRY_CAP)
    return feed


def collect_dependencies(directory="."):
    deps = []
    seen = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs
                   if d not in (".git", ".venv", "venv",
                                "__pycache__", "node_modules")]
        for name in files:
            if seen >= DEP_0:
                break
            lower = name.lower()
            path = os.path.join(root, name)
            if lower == "requirements.txt" or lower.startswith("requirements-"):
                seen += 1
                deps.extend(_parse_requirements(path))
            elif lower == "package-lock.json":
                seen += 1
                deps.extend(_parse_package_lock(path))
            elif lower == "package.json":
                seen += 1
                deps.extend(_parse_package_json(path))
    deduped = sorted({(d["name"], d["version"], d["source"])
                      for d in deps})
    return [{"name": n, "version": v, "source": s}
            for n, v, s in deduped]


_REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(?:==|===)\s*([^\s;#]+)")


def _parse_requirements(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = _REQ_LINE.match(line)
                if match:
                    out.append({"name": match.group(1),
                                "version": match.group(2),
                                "source": path})
    except OSError:
        pass
    return out


def _parse_package_lock(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        packages = data.get("packages", {})
        for key, info in packages.items():
            name = key.split("node_modules/")[-1]
            version = info.get("version")
            if name and version and not key.startswith("lockfile"):
                out.append({"name": name, "version": version,
                            "source": path})
    except (OSError, json.JSONDecodeError):
        pass
    return out


def _parse_package_json(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        for section in ("dependencies", "devDependencies"):
            for name, spec in data.get(section, {}).items():
                cleaned = re.sub(r"[^0-9A-Za-z.\-]", "", str(spec))
                if cleaned:
                    out.append({"name": name, "version": cleaned,
                                "source": path})
    except (OSError, json.JSONDecodeError):
        pass
    return out


def match_dependencies(dependencies, feed):
    matches = []
    unknown = []
    for dep in dependencies:
        for entry in feed.get("entries", []):
            if dep["name"].lower() != str(entry.get("product", "")).lower():
                continue
            verdict = _matches_range(dep["version"],
                                     str(entry.get("affected", "")))
            if verdict is None:
                unknown.append({
                    "dependency": dep["name"],
                    "version": dep["version"],
                    "reason": "version comparison inconclusive",
                })
            elif verdict:
                matches.append({
                    "dependency": dep["name"],
                    "version": dep["version"],
                    "source": dep["source"],
                    "cve": entry.get("cve"),
                    "summary": entry.get("summary"),
                    "affected_range": entry.get("affected"),
                    "severity": entry.get("severity"),
                    "boundary": ("inventory-level match only; reachability "
                                 "is not claimed"),
                })
    matches.sort(key=lambda m: (m["dependency"], m["cve"]))
    return {"matches": matches,
            "inconclusive": unknown[:100],
            "match_count": len(matches)}


def scan(directory=".", feed_path=None):
    feed = load_feed(feed_path)
    deps = collect_dependencies(directory)
    outcome = match_dependencies(deps, feed)
    return {
        "schema": CVE_SCHEMA,
        "tool": "offline-cve-matcher",
        "feed_source": feed_path or "bundled-sample",
        "feed_entry_count": len(feed.get("entries", [])),
        "dependencies_scanned": len(deps),
        "matches": outcome["matches"],
        "inconclusive": outcome["inconclusive"],
        "match_count": outcome["match_count"],
    }


def run_selftest():
    checks = []

    feed = load_feed()
    vulnerable = match_dependencies(
        [{"name": "log4j-core", "version": "2.14.1", "source": "t"},
         {"name": "requests", "version": "2.30.0", "source": "t"}], feed)
    checks.append(("bundled feed matches both planted dependencies",
                   vulnerable["match_count"] == 2))

    safe = match_dependencies(
        [{"name": "log4j-core", "version": "2.17.1", "source": "t"}], feed)
    checks.append(("2.17.1 outside range", safe["match_count"] == 0))

    self_cmp = compare_versions("2.17.1", "2.17.1")
    checks.append(("equal versions compare equal", self_cmp == 0))

    weird = compare_versions("abc", "1.2.3")
    checks.append(("non-numeric versions inconclusive", weird is None))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": CVE_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cve_matcher42",
        description="Offline CVE matcher (operator-supplied feed)")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("scan", help="scan a directory's dependency manifests")
    p.add_argument("directory", nargs="?", default=".")
    p.add_argument("--feed", help="path to NVD-style JSON feed")

    subs.add_parser("self-test")

    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            result = scan(args.directory, args.feed)
            code = EXIT_FINDING if result["match_count"] else EXIT_CLEAN
        elif args.command == "self-test":
            result = run_selftest()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        else:  # pragma: no cover
            parser.error("unknown command")
    except (CveError, OSError, json.JSONDecodeError) as exc:
        print("cve_matcher42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
