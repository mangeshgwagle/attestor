#!/usr/bin/env python3
"""Attestor persistent memory -- learns from every scan.

Stores in .attestor/memory/ at the project root:
  - scans.jsonl      : timestamped scan history
  - feedback.json    : user TP/FP verdicts on findings
  - patterns.json    : learned codebase patterns (frameworks, sinks, etc.)
  - stats.json       : aggregate stats (FP rate per rule, hit rate per file)

Memory makes Attestor smarter over time:
  - Suppress known false positives automatically
  - Boost confidence on historically buggy files
  - Track which rules produce real bugs vs noise
  - Remember what frameworks/patterns this codebase uses

    from memory import Memory
    mem = Memory(".")
    mem.record_scan(findings, scan_type="check")
    filtered = mem.filter_findings(findings)
    mem.feedback("abc123", "fp", reason="test helper, not real sink")
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


MEMORY_DIR = ".attestor/memory"
SCANS_FILE = "scans.jsonl"
FEEDBACK_FILE = "feedback.json"
PATTERNS_FILE = "patterns.json"
STATS_FILE = "stats.json"

MAX_SCAN_HISTORY = 1000
MAX_FEEDBACK_ENTRIES = 10000


def _finding_hash(finding: dict) -> str:
    key = f"{finding.get('path', finding.get('file', ''))}:" \
          f"{finding.get('line', 0)}:" \
          f"{finding.get('rule_id', finding.get('rule', finding.get('category', '')))}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _finding_rule_hash(finding: dict) -> str:
    rule = finding.get("rule_id", finding.get("rule", finding.get("category", "")))
    path = finding.get("path", finding.get("file", ""))
    return f"{rule}@{path}"


@dataclass
class ScanRecord:
    timestamp: str
    scan_type: str
    paths: list[str]
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_rule: dict[str, int]
    duration_ms: int = 0
    finding_hashes: list[str] = field(default_factory=list)


class Memory:
    def __init__(self, project_root: str = "."):
        self.root = Path(project_root).resolve()
        self.mem_dir = self.root / MEMORY_DIR
        self._feedback: dict = {}
        self._patterns: dict = {}
        self._stats: dict = {}
        self._loaded = False

    def _ensure_dir(self):
        self.mem_dir.mkdir(parents=True, exist_ok=True)

    def _load(self):
        if self._loaded:
            return
        self._loaded = True

        fb_path = self.mem_dir / FEEDBACK_FILE
        if fb_path.exists():
            try:
                self._feedback = json.loads(fb_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._feedback = {}

        pat_path = self.mem_dir / PATTERNS_FILE
        if pat_path.exists():
            try:
                self._patterns = json.loads(pat_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._patterns = {}

        st_path = self.mem_dir / STATS_FILE
        if st_path.exists():
            try:
                self._stats = json.loads(st_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._stats = {}

    def _save_feedback(self):
        self._ensure_dir()
        path = self.mem_dir / FEEDBACK_FILE
        path.write_text(json.dumps(self._feedback, indent=2, sort_keys=True),
                        encoding="utf-8")

    def _save_patterns(self):
        self._ensure_dir()
        path = self.mem_dir / PATTERNS_FILE
        path.write_text(json.dumps(self._patterns, indent=2, sort_keys=True),
                        encoding="utf-8")

    def _save_stats(self):
        self._ensure_dir()
        path = self.mem_dir / STATS_FILE
        path.write_text(json.dumps(self._stats, indent=2, sort_keys=True),
                        encoding="utf-8")

    def record_scan(self, findings: list[dict], scan_type: str = "scan",
                    paths: list[str] | None = None, duration_ms: int = 0):
        self._load()
        self._ensure_dir()

        sev_counts: dict[str, int] = Counter()
        rule_counts: dict[str, int] = Counter()
        hashes = []

        for f in findings:
            sev = f.get("severity", "MEDIUM")
            rule = f.get("rule_id", f.get("rule", f.get("category", "unknown")))
            sev_counts[sev] += 1
            rule_counts[rule] += 1
            hashes.append(_finding_hash(f))

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": scan_type,
            "paths": paths or [],
            "total_findings": len(findings),
            "findings_by_severity": dict(sev_counts),
            "findings_by_rule": dict(rule_counts),
            "duration_ms": duration_ms,
            "finding_hashes": hashes,
        }

        scans_path = self.mem_dir / SCANS_FILE
        with open(scans_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        self._update_stats(findings)

    def _update_stats(self, findings: list[dict]):
        if "rule_counts" not in self._stats:
            self._stats["rule_counts"] = {}
        if "file_counts" not in self._stats:
            self._stats["file_counts"] = {}
        if "total_scans" not in self._stats:
            self._stats["total_scans"] = 0
        if "total_findings" not in self._stats:
            self._stats["total_findings"] = 0

        self._stats["total_scans"] += 1
        self._stats["total_findings"] += len(findings)
        self._stats["last_scan"] = datetime.now(timezone.utc).isoformat()

        for f in findings:
            rule = f.get("rule_id", f.get("rule", f.get("category", "unknown")))
            path = f.get("path", f.get("file", ""))

            if rule not in self._stats["rule_counts"]:
                self._stats["rule_counts"][rule] = {"total": 0, "tp": 0, "fp": 0}
            self._stats["rule_counts"][rule]["total"] += 1

            if path:
                rel = self._relpath(path)
                if rel not in self._stats["file_counts"]:
                    self._stats["file_counts"][rel] = 0
                self._stats["file_counts"][rel] += 1

        self._save_stats()

    def _relpath(self, path: str) -> str:
        try:
            return str(Path(path).resolve().relative_to(self.root))
        except (ValueError, OSError):
            return path

    def feedback(self, finding_hash: str, verdict: str, reason: str = ""):
        self._load()
        if verdict not in ("tp", "fp", "defer"):
            raise ValueError(f"verdict must be tp, fp, or defer, got {verdict}")

        self._feedback[finding_hash] = {
            "verdict": verdict,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if len(self._feedback) > MAX_FEEDBACK_ENTRIES:
            oldest = sorted(self._feedback.items(),
                           key=lambda x: x[1].get("timestamp", ""))
            for key, _ in oldest[:len(self._feedback) - MAX_FEEDBACK_ENTRIES]:
                del self._feedback[key]

        self._save_feedback()

    def feedback_finding(self, finding: dict, verdict: str, reason: str = ""):
        h = _finding_hash(finding)
        self.feedback(h, verdict, reason)

        rule = finding.get("rule_id", finding.get("rule",
               finding.get("category", "unknown")))
        if rule in self._stats.get("rule_counts", {}):
            if verdict == "tp":
                self._stats["rule_counts"][rule]["tp"] += 1
            elif verdict == "fp":
                self._stats["rule_counts"][rule]["fp"] += 1
            self._save_stats()

    def is_suppressed(self, finding: dict) -> bool:
        self._load()
        h = _finding_hash(finding)
        entry = self._feedback.get(h)
        return entry is not None and entry.get("verdict") == "fp"

    def filter_findings(self, findings: list[dict]) -> list[dict]:
        self._load()
        result = []
        for f in findings:
            if self.is_suppressed(f):
                continue
            f = dict(f)
            h = _finding_hash(f)
            entry = self._feedback.get(h)
            if entry and entry.get("verdict") == "tp":
                f["memory_confirmed"] = True

            rule = f.get("rule_id", f.get("rule", f.get("category", "")))
            rule_stats = self._stats.get("rule_counts", {}).get(rule, {})
            if rule_stats:
                tp = rule_stats.get("tp", 0)
                fp = rule_stats.get("fp", 0)
                total_feedback = tp + fp
                if total_feedback >= 5 and fp / total_feedback > 0.8:
                    f["memory_low_precision"] = True
                elif total_feedback >= 3 and tp / total_feedback > 0.7:
                    f["memory_high_precision"] = True

            path = f.get("path", f.get("file", ""))
            if path:
                rel = self._relpath(path)
                file_count = self._stats.get("file_counts", {}).get(rel, 0)
                if file_count >= 5:
                    f["memory_hotspot"] = True

            result.append(f)
        return result

    def learn_patterns(self, paths: list[str] | None = None):
        self._load()
        scan_root = paths[0] if paths else str(self.root)

        frameworks = set()
        file_types = Counter()
        import_counts = Counter()

        for dirpath, _, filenames in os.walk(scan_root):
            dirname = os.path.basename(dirpath)
            if dirname in (".git", "__pycache__", "node_modules", ".venv",
                           ".attestor"):
                continue
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext:
                    file_types[ext] += 1

                if fn in ("manage.py", "wsgi.py"):
                    frameworks.add("django")
                elif fn == "app.py" and ext == ".py":
                    frameworks.add("flask")
                elif fn == "package.json":
                    frameworks.add("node")
                    try:
                        pkg = json.loads(
                            (Path(dirpath) / fn).read_text(encoding="utf-8"))
                        deps = {**pkg.get("dependencies", {}),
                                **pkg.get("devDependencies", {})}
                        if "react" in deps:
                            frameworks.add("react")
                        if "express" in deps:
                            frameworks.add("express")
                        if "next" in deps:
                            frameworks.add("next")
                    except (json.JSONDecodeError, OSError):
                        pass
                elif fn == "Cargo.toml":
                    frameworks.add("rust")
                elif fn == "go.mod":
                    frameworks.add("go")
                elif fn == "pom.xml" or fn == "build.gradle":
                    frameworks.add("java")
                elif fn == "requirements.txt" or fn == "setup.py" or fn == "pyproject.toml":
                    frameworks.add("python")
                    if fn == "requirements.txt":
                        try:
                            reqs = (Path(dirpath) / fn).read_text(
                                encoding="utf-8", errors="replace")
                            for line in reqs.splitlines():
                                pkg_name = line.strip().split("==")[0].split(
                                    ">=")[0].split("<=")[0].strip()
                                if pkg_name and not pkg_name.startswith("#"):
                                    import_counts[pkg_name] += 1
                        except OSError:
                            pass

                fp = os.path.join(dirpath, fn)
                if ext == ".py" and os.path.getsize(fp) < 500000:
                    try:
                        with open(fp, encoding="utf-8", errors="replace") as f:
                            for line in f:
                                if line.startswith("import ") or \
                                   line.startswith("from "):
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        mod = parts[1].split(".")[0]
                                        import_counts[mod] += 1
                    except OSError:
                        pass

        self._patterns = {
            "frameworks": sorted(frameworks),
            "file_types": dict(file_types.most_common(20)),
            "top_imports": dict(import_counts.most_common(30)),
            "learned_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_patterns()

    def get_patterns(self) -> dict:
        self._load()
        return dict(self._patterns)

    def get_stats(self) -> dict:
        self._load()
        return dict(self._stats)

    def get_feedback_summary(self) -> dict:
        self._load()
        tp = sum(1 for v in self._feedback.values() if v.get("verdict") == "tp")
        fp = sum(1 for v in self._feedback.values() if v.get("verdict") == "fp")
        deferred = sum(1 for v in self._feedback.values()
                      if v.get("verdict") == "defer")
        return {
            "total": len(self._feedback),
            "true_positives": tp,
            "false_positives": fp,
            "deferred": deferred,
            "precision": tp / (tp + fp) if (tp + fp) > 0 else None,
        }

    def get_scan_history(self, limit: int = 20) -> list[dict]:
        scans_path = self.mem_dir / SCANS_FILE
        if not scans_path.exists():
            return []
        records = []
        try:
            with open(scans_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            return []
        return records[-limit:]

    def get_hotspot_files(self, top: int = 10) -> list[tuple[str, int]]:
        self._load()
        fc = self._stats.get("file_counts", {})
        return sorted(fc.items(), key=lambda x: x[1], reverse=True)[:top]

    def get_noisy_rules(self, min_feedback: int = 3) -> list[dict]:
        self._load()
        noisy = []
        for rule, counts in self._stats.get("rule_counts", {}).items():
            tp = counts.get("tp", 0)
            fp = counts.get("fp", 0)
            total_fb = tp + fp
            if total_fb >= min_feedback:
                precision = tp / total_fb if total_fb else 0
                noisy.append({
                    "rule": rule,
                    "total_seen": counts.get("total", 0),
                    "tp": tp, "fp": fp,
                    "precision": round(precision, 3),
                })
        return sorted(noisy, key=lambda x: x["precision"])

    def clear(self):
        for fn in (SCANS_FILE, FEEDBACK_FILE, PATTERNS_FILE, STATS_FILE):
            p = self.mem_dir / fn
            if p.exists():
                p.unlink()
        self._feedback = {}
        self._patterns = {}
        self._stats = {}
        self._loaded = False

    def render(self) -> str:
        self._load()
        lines = [
            "\n  Attestor Memory",
            "  " + "=" * 50,
        ]

        stats = self.get_stats()
        if stats:
            lines.append(f"  Total scans:    {stats.get('total_scans', 0)}")
            lines.append(f"  Total findings: {stats.get('total_findings', 0)}")
            last = stats.get("last_scan", "never")
            lines.append(f"  Last scan:      {last}")

        fb = self.get_feedback_summary()
        if fb["total"] > 0:
            lines.append(f"\n  Feedback:")
            lines.append(f"    True positives:  {fb['true_positives']}")
            lines.append(f"    False positives: {fb['false_positives']}")
            lines.append(f"    Deferred:        {fb['deferred']}")
            if fb["precision"] is not None:
                lines.append(f"    Precision:       {fb['precision']:.1%}")

        patterns = self.get_patterns()
        if patterns:
            fw = patterns.get("frameworks", [])
            if fw:
                lines.append(f"\n  Frameworks: {', '.join(fw)}")
            top_imp = patterns.get("top_imports", {})
            if top_imp:
                top5 = list(top_imp.keys())[:5]
                lines.append(f"  Top imports: {', '.join(top5)}")

        hotspots = self.get_hotspot_files(5)
        if hotspots:
            lines.append(f"\n  Hotspot files:")
            for path, count in hotspots:
                lines.append(f"    {count:3d} findings  {path}")

        noisy = self.get_noisy_rules()
        if noisy:
            lines.append(f"\n  Rule precision (from feedback):")
            for r in noisy[:5]:
                lines.append(f"    {r['rule']:30s}  {r['precision']:.0%}  "
                            f"({r['tp']}tp/{r['fp']}fp)")

        lines.append("  " + "=" * 50)
        return "\n".join(lines)


def to_dict(mem: Memory) -> dict:
    return {
        "stats": mem.get_stats(),
        "feedback": mem.get_feedback_summary(),
        "patterns": mem.get_patterns(),
        "hotspots": [{"file": f, "count": c}
                     for f, c in mem.get_hotspot_files()],
        "noisy_rules": mem.get_noisy_rules(),
        "recent_scans": mem.get_scan_history(10),
    }
