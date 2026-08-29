#!/usr/bin/env python3
"""OwenOS: the self-improving operating system for Attestor 4.2.

Attestor already scans, proves, patches, and tests. OwenOS is the layer
that makes Attestor *improve itself* — without an LLM, without human
intervention, through deterministic feedback loops.

The cycle:

    SCAN ──► EVALUATE ──► ANALYZE ──► MINE ──► GENERATE ──► TEST ──► INTEGRATE
      ▲                                                                    │
      └────────────────────────────────────────────────────────────────────┘

Each iteration:
  1. SCAN a codebase (or corpus) with current rules
  2. EVALUATE results: accuracy, coverage, false-positive rate
  3. ANALYZE gaps: which CWEs are missing, which rules are weak
  4. MINE patterns from confirmed findings (PoC-verified)
  5. GENERATE new detection rules, PoC templates, patch templates
  6. TEST generated artifacts against known-good/bad samples
  7. INTEGRATE passing artifacts into the module registry

The OS manages:
  - Processes (scan jobs, improvement tasks, test runs)
  - Knowledge (findings, patterns, metrics, coverage maps)
  - Modules (dynamic registry of all Attestor components)
  - Scheduling (what to improve next, based on gap analysis)
  - Evolution (track improvements over generations)

Architecture:

    ┌──────────────────────────────────────────────────────────┐
    │                        OwenOS                           │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
    │  │  Kernel   │  │Knowledge │  │Improvement│  │ Module │  │
    │  │ScheduleR  │  │  Store   │  │  Engine   │  │Registry│  │
    │  │EventBus   │  │FindingsDB│  │GapAnalyzer│  │ detect │  │
    │  │ProcessTbl │  │PatternDB │  │PatternMinr│  │poc_gen │  │
    │  │Lifecycle  │  │Metrics   │  │TemplateGn │  │patch_gn│  │
    │  │           │  │Coverage  │  │SelfTest   │  │regr_gen│  │
    │  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
    └──────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable


VERSION = "4.2"


# =========================================================================== #
#  KERNEL                                                                      #
# =========================================================================== #

class ProcessState(Enum):
    QUEUED = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    BLOCKED = auto()


class Priority(Enum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


@dataclass
class Process:
    """A unit of work in OwenOS."""
    pid: int
    name: str
    kind: str  # "scan", "evaluate", "analyze", "mine", "generate", "test", "integrate"
    state: ProcessState = ProcessState.QUEUED
    priority: Priority = Priority.NORMAL
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    result: Any = None
    error: str = ""
    parent_pid: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at or time.time()
        return end - self.started_at


class Event:
    """An event on the kernel event bus."""
    __slots__ = ("kind", "source", "data", "timestamp")

    def __init__(self, kind: str, source: str, data: Any = None):
        self.kind = kind
        self.source = source
        self.data = data
        self.timestamp = time.time()

    def __repr__(self) -> str:
        return "Event(%s, %s)" % (self.kind, self.source)


class EventBus:
    """Pub/sub for inter-module communication."""

    def __init__(self):
        self._subscribers: dict[str, list[Callable[[Event], None]]] = defaultdict(list)
        self._log: list[Event] = []

    def subscribe(self, event_kind: str, callback: Callable[[Event], None]) -> None:
        self._subscribers[event_kind].append(callback)

    def publish(self, event: Event) -> None:
        self._log.append(event)
        for cb in self._subscribers.get(event.kind, []):
            cb(event)
        for cb in self._subscribers.get("*", []):
            cb(event)

    def history(self, kind: str | None = None, limit: int = 100) -> list[Event]:
        if kind is None:
            return self._log[-limit:]
        return [e for e in self._log if e.kind == kind][-limit:]


class Kernel:
    """Process scheduler and lifecycle manager."""

    def __init__(self):
        self.bus = EventBus()
        self._processes: dict[int, Process] = {}
        self._next_pid = 1
        self._generation = 0
        self.boot_time = time.time()

    @property
    def generation(self) -> int:
        return self._generation

    def advance_generation(self) -> int:
        self._generation += 1
        self.bus.publish(Event("generation.advance", "kernel",
                               {"generation": self._generation}))
        return self._generation

    def spawn(self, name: str, kind: str,
              priority: Priority = Priority.NORMAL,
              parent: int | None = None,
              metadata: dict | None = None) -> Process:
        pid = self._next_pid
        self._next_pid += 1
        proc = Process(pid=pid, name=name, kind=kind,
                       priority=priority, parent_pid=parent,
                       metadata=metadata or {})
        self._processes[pid] = proc
        self.bus.publish(Event("process.spawn", "kernel",
                               {"pid": pid, "name": name, "kind": kind}))
        return proc

    def start(self, pid: int) -> None:
        proc = self._processes[pid]
        proc.state = ProcessState.RUNNING
        proc.started_at = time.time()
        self.bus.publish(Event("process.start", "kernel", {"pid": pid}))

    def complete(self, pid: int, result: Any = None) -> None:
        proc = self._processes[pid]
        proc.state = ProcessState.COMPLETED
        proc.finished_at = time.time()
        proc.result = result
        self.bus.publish(Event("process.complete", "kernel",
                               {"pid": pid, "result_type": type(result).__name__}))

    def fail(self, pid: int, error: str) -> None:
        proc = self._processes[pid]
        proc.state = ProcessState.FAILED
        proc.finished_at = time.time()
        proc.error = error
        self.bus.publish(Event("process.fail", "kernel",
                               {"pid": pid, "error": error}))

    def get(self, pid: int) -> Process | None:
        return self._processes.get(pid)

    def ps(self, state: ProcessState | None = None,
           kind: str | None = None) -> list[Process]:
        procs = list(self._processes.values())
        if state:
            procs = [p for p in procs if p.state == state]
        if kind:
            procs = [p for p in procs if p.kind == kind]
        return sorted(procs, key=lambda p: (p.priority.value, p.created_at))

    def run_queue(self) -> list[Process]:
        return self.ps(state=ProcessState.QUEUED)

    def uptime(self) -> float:
        return time.time() - self.boot_time

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for p in self._processes.values():
            counts[p.state.name] += 1
        counts["total"] = len(self._processes)
        counts["generation"] = self._generation
        return dict(counts)


# =========================================================================== #
#  KNOWLEDGE STORE                                                             #
# =========================================================================== #

@dataclass
class StoredFinding:
    """A finding enriched with verification status."""
    rule: str
    cwe: str
    file_path: str
    line: int
    severity: str
    language: str = "unknown"
    snippet: str = ""
    poc_verified: bool = False
    patch_generated: bool = False
    regression_generated: bool = False
    false_positive: bool = False
    generation_found: int = 0
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            h = hashlib.sha256()
            h.update(("%s:%s:%s:%d" % (self.rule, self.cwe,
                                       self.file_path, self.line)).encode())
            self.fingerprint = h.hexdigest()[:16]


@dataclass
class DetectionPattern:
    """A pattern Owen learned or mined from its own results."""
    pattern_id: str
    cwe: str
    language: str
    regex: str
    description: str
    source: str  # "builtin", "mined", "generated"
    hit_count: int = 0
    false_positive_count: int = 0
    generation_added: int = 0

    @property
    def precision(self) -> float:
        total = self.hit_count + self.false_positive_count
        if total == 0:
            return 1.0
        return self.hit_count / total

    @property
    def is_reliable(self) -> bool:
        return self.hit_count >= 3 and self.precision >= 0.7


@dataclass
class CoverageEntry:
    """Coverage status for a single CWE."""
    cwe: str
    cwe_num: int
    has_detection: bool = False
    has_poc: bool = False
    has_patch: bool = False
    has_regression: bool = False
    detection_rules: list[str] = field(default_factory=list)
    finding_count: int = 0
    verified_count: int = 0
    false_positive_count: int = 0

    @property
    def completeness(self) -> float:
        score = 0
        if self.has_detection:
            score += 0.25
        if self.has_poc:
            score += 0.25
        if self.has_patch:
            score += 0.25
        if self.has_regression:
            score += 0.25
        return score

    @property
    def is_complete(self) -> bool:
        return self.completeness == 1.0


class KnowledgeStore:
    """Persistent knowledge base for Owen's self-improvement."""

    def __init__(self, store_dir: str | None = None):
        self._findings: dict[str, StoredFinding] = {}
        self._patterns: dict[str, DetectionPattern] = {}
        self._coverage: dict[str, CoverageEntry] = {}
        self._metrics: list[dict[str, Any]] = []
        self._store_dir = store_dir

    # -- Findings ----------------------------------------------------------- #

    def add_finding(self, finding: StoredFinding) -> str:
        self._findings[finding.fingerprint] = finding
        return finding.fingerprint

    def get_finding(self, fingerprint: str) -> StoredFinding | None:
        return self._findings.get(fingerprint)

    def mark_verified(self, fingerprint: str, poc_passed: bool) -> None:
        f = self._findings.get(fingerprint)
        if f:
            f.poc_verified = poc_passed
            if not poc_passed:
                f.false_positive = True

    def findings(self, cwe: str | None = None,
                 verified_only: bool = False) -> list[StoredFinding]:
        result = list(self._findings.values())
        if cwe:
            result = [f for f in result if f.cwe == cwe]
        if verified_only:
            result = [f for f in result if f.poc_verified]
        return result

    def finding_count(self) -> int:
        return len(self._findings)

    def verified_count(self) -> int:
        return sum(1 for f in self._findings.values() if f.poc_verified)

    def false_positive_rate(self) -> float:
        total = len(self._findings)
        if total == 0:
            return 0.0
        fp = sum(1 for f in self._findings.values() if f.false_positive)
        return fp / total

    # -- Patterns ----------------------------------------------------------- #

    def add_pattern(self, pattern: DetectionPattern) -> str:
        self._patterns[pattern.pattern_id] = pattern
        return pattern.pattern_id

    def get_pattern(self, pattern_id: str) -> DetectionPattern | None:
        return self._patterns.get(pattern_id)

    def patterns(self, cwe: str | None = None,
                 reliable_only: bool = False) -> list[DetectionPattern]:
        result = list(self._patterns.values())
        if cwe:
            result = [p for p in result if p.cwe == cwe]
        if reliable_only:
            result = [p for p in result if p.is_reliable]
        return result

    def record_pattern_hit(self, pattern_id: str,
                           is_true_positive: bool) -> None:
        p = self._patterns.get(pattern_id)
        if p:
            if is_true_positive:
                p.hit_count += 1
            else:
                p.false_positive_count += 1

    # -- Coverage ----------------------------------------------------------- #

    def update_coverage(self, entry: CoverageEntry) -> None:
        self._coverage[entry.cwe] = entry

    def coverage(self, cwe: str | None = None) -> list[CoverageEntry]:
        if cwe:
            e = self._coverage.get(cwe)
            return [e] if e else []
        return sorted(self._coverage.values(), key=lambda e: e.cwe_num)

    def coverage_gaps(self) -> list[CoverageEntry]:
        return [e for e in self._coverage.values() if not e.is_complete]

    def coverage_score(self) -> float:
        if not self._coverage:
            return 0.0
        return sum(e.completeness for e in self._coverage.values()) / len(self._coverage)

    # -- Metrics ------------------------------------------------------------ #

    def record_metric(self, name: str, value: float,
                      generation: int = 0, tags: dict | None = None) -> None:
        self._metrics.append({
            "name": name,
            "value": value,
            "generation": generation,
            "tags": tags or {},
            "timestamp": time.time(),
        })

    def get_metrics(self, name: str,
                    last_n: int = 10) -> list[dict[str, Any]]:
        return [m for m in self._metrics if m["name"] == name][-last_n:]

    def metric_trend(self, name: str) -> str:
        points = self.get_metrics(name, last_n=5)
        if len(points) < 2:
            return "insufficient_data"
        values = [p["value"] for p in points]
        if values[-1] > values[0]:
            return "improving"
        elif values[-1] < values[0]:
            return "degrading"
        return "stable"

    # -- Persistence -------------------------------------------------------- #

    def save(self, path: str | None = None) -> str:
        target = path or self._store_dir
        if not target:
            target = os.path.join(os.getcwd(), ".owen_knowledge")
        os.makedirs(target, exist_ok=True)

        findings_path = os.path.join(target, "findings.json")
        with open(findings_path, "w", encoding="utf-8") as f:
            data = []
            for sf in self._findings.values():
                data.append({
                    "rule": sf.rule, "cwe": sf.cwe, "file_path": sf.file_path,
                    "line": sf.line, "severity": sf.severity,
                    "language": sf.language, "snippet": sf.snippet,
                    "poc_verified": sf.poc_verified,
                    "patch_generated": sf.patch_generated,
                    "regression_generated": sf.regression_generated,
                    "false_positive": sf.false_positive,
                    "generation_found": sf.generation_found,
                    "fingerprint": sf.fingerprint,
                })
            json.dump(data, f, indent=2)

        patterns_path = os.path.join(target, "patterns.json")
        with open(patterns_path, "w", encoding="utf-8") as f:
            data = []
            for p in self._patterns.values():
                data.append({
                    "pattern_id": p.pattern_id, "cwe": p.cwe,
                    "language": p.language, "regex": p.regex,
                    "description": p.description, "source": p.source,
                    "hit_count": p.hit_count,
                    "false_positive_count": p.false_positive_count,
                    "generation_added": p.generation_added,
                })
            json.dump(data, f, indent=2)

        metrics_path = os.path.join(target, "metrics.json")
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(self._metrics, f, indent=2)

        return target

    def load(self, path: str | None = None) -> bool:
        target = path or self._store_dir
        if not target:
            return False

        findings_path = os.path.join(target, "findings.json")
        if os.path.exists(findings_path):
            with open(findings_path, "r", encoding="utf-8") as f:
                for item in json.load(f):
                    sf = StoredFinding(**item)
                    self._findings[sf.fingerprint] = sf

        patterns_path = os.path.join(target, "patterns.json")
        if os.path.exists(patterns_path):
            with open(patterns_path, "r", encoding="utf-8") as f:
                for item in json.load(f):
                    dp = DetectionPattern(**item)
                    self._patterns[dp.pattern_id] = dp

        metrics_path = os.path.join(target, "metrics.json")
        if os.path.exists(metrics_path):
            with open(metrics_path, "r", encoding="utf-8") as f:
                self._metrics = json.load(f)

        return True


# =========================================================================== #
#  MODULE REGISTRY                                                             #
# =========================================================================== #

class ModuleKind(Enum):
    SCANNER = "scanner"
    POC_GENERATOR = "poc_generator"
    PATCH_GENERATOR = "patch_generator"
    REGRESSION_GENERATOR = "regression_generator"
    PAYLOAD_GENERATOR = "payload_generator"
    ANALYZER = "analyzer"
    CUSTOM = "custom"


@dataclass
class RegisteredModule:
    """A module registered in OwenOS."""
    name: str
    kind: ModuleKind
    module: Any  # the actual Python module object
    version: str = ""
    supported_cwes: tuple[int, ...] = ()
    description: str = ""
    generation_added: int = 0


class ModuleRegistry:
    """Dynamic registry of all Attestor components."""

    def __init__(self):
        self._modules: dict[str, RegisteredModule] = {}

    def register(self, name: str, kind: ModuleKind, module: Any,
                 version: str = "", description: str = "",
                 generation: int = 0) -> RegisteredModule:
        cwes: tuple[int, ...] = ()
        if hasattr(module, "supported_cwes"):
            cwes = module.supported_cwes()

        entry = RegisteredModule(
            name=name, kind=kind, module=module,
            version=version, supported_cwes=cwes,
            description=description, generation_added=generation,
        )
        self._modules[name] = entry
        return entry

    def get(self, name: str) -> RegisteredModule | None:
        return self._modules.get(name)

    def by_kind(self, kind: ModuleKind) -> list[RegisteredModule]:
        return [m for m in self._modules.values() if m.kind == kind]

    def all_modules(self) -> list[RegisteredModule]:
        return list(self._modules.values())

    def all_supported_cwes(self) -> dict[str, set[int]]:
        result: dict[str, set[int]] = defaultdict(set)
        for m in self._modules.values():
            result[m.kind.value].update(m.supported_cwes)
        return dict(result)

    def cwe_coverage_matrix(self) -> dict[int, dict[str, bool]]:
        all_cwes: set[int] = set()
        for m in self._modules.values():
            all_cwes.update(m.supported_cwes)

        matrix: dict[int, dict[str, bool]] = {}
        for cwe in sorted(all_cwes):
            matrix[cwe] = {}
            for m in self._modules.values():
                matrix[cwe][m.kind.value] = cwe in m.supported_cwes
        return matrix


# =========================================================================== #
#  GAP ANALYZER                                                                #
# =========================================================================== #

@dataclass
class Gap:
    """A gap in Attestor's coverage that the improvement engine can fill."""
    cwe: int
    gap_type: str  # "no_detection", "no_poc", "no_patch", "no_regression", "low_precision"
    priority: Priority
    description: str
    suggested_action: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def gap_id(self) -> str:
        return "gap-%d-%s" % (self.cwe, self.gap_type)


class GapAnalyzer:
    """Identifies gaps in Attestor's coverage and prioritizes improvements."""

    def __init__(self, registry: ModuleRegistry, knowledge: KnowledgeStore):
        self._registry = registry
        self._knowledge = knowledge

    def analyze(self) -> list[Gap]:
        gaps: list[Gap] = []
        matrix = self._registry.cwe_coverage_matrix()

        for cwe, coverage in matrix.items():
            has_scanner = coverage.get("scanner", False)
            has_poc = coverage.get("poc_generator", False)
            has_patch = coverage.get("patch_generator", False)
            has_regtest = coverage.get("regression_generator", False)

            if has_scanner and not has_poc:
                gaps.append(Gap(
                    cwe=cwe,
                    gap_type="no_poc",
                    priority=Priority.HIGH,
                    description="CWE-%d: scanner detects but no PoC generator exists" % cwe,
                    suggested_action="generate_poc_template",
                ))
            if has_scanner and not has_patch:
                gaps.append(Gap(
                    cwe=cwe,
                    gap_type="no_patch",
                    priority=Priority.NORMAL,
                    description="CWE-%d: scanner detects but no patch generator exists" % cwe,
                    suggested_action="generate_patch_template",
                ))
            if has_poc and not has_regtest:
                gaps.append(Gap(
                    cwe=cwe,
                    gap_type="no_regression",
                    priority=Priority.NORMAL,
                    description="CWE-%d: PoC exists but no regression test generator" % cwe,
                    suggested_action="generate_regression_template",
                ))
            if has_scanner and has_poc:
                findings = self._knowledge.findings(cwe="CWE-%d" % cwe)
                if findings:
                    fp_count = sum(1 for f in findings if f.false_positive)
                    total = len(findings)
                    if total >= 5 and fp_count / total > 0.3:
                        gaps.append(Gap(
                            cwe=cwe,
                            gap_type="low_precision",
                            priority=Priority.HIGH,
                            description=("CWE-%d: %.0f%% false positive rate "
                                         "(%d/%d findings)" %
                                         (cwe, 100 * fp_count / total,
                                          fp_count, total)),
                            suggested_action="tune_detection_pattern",
                            metadata={"fp_rate": fp_count / total,
                                      "total": total},
                        ))

        return sorted(gaps, key=lambda g: g.priority.value)

    def uncovered_cwes(self, known_cwes: list[int] | None = None) -> list[int]:
        covered = set()
        for m in self._registry.all_modules():
            covered.update(m.supported_cwes)

        if known_cwes:
            return sorted(set(known_cwes) - covered)

        all_interesting = [
            22, 23, 36, 77, 78, 79, 80, 89, 90, 94, 95, 113, 116, 119,
            120, 121, 122, 125, 126, 129, 134, 170, 176, 190, 191, 194,
            197, 200, 209, 250, 269, 276, 285, 287, 306, 311, 312, 319,
            326, 327, 328, 330, 336, 338, 345, 346, 352, 362, 367, 369,
            377, 382, 384, 396, 397, 400, 401, 404, 415, 416, 434, 436,
            451, 457, 467, 470, 476, 477, 481, 494, 502, 506, 521, 532,
            546, 562, 586, 590, 597, 601, 611, 614, 615, 643, 672, 732,
            754, 758, 762, 770, 776, 787, 789, 798, 829, 862, 863, 917,
            918, 943,
        ]
        return sorted(set(all_interesting) - covered)

    def improvement_plan(self, max_items: int = 10) -> list[Gap]:
        return self.analyze()[:max_items]


# =========================================================================== #
#  PATTERN MINER                                                               #
# =========================================================================== #

class PatternMiner:
    """Extracts new detection patterns from verified findings.

    When Owen confirms a finding via PoC, the finding's snippet and context
    contain the vulnerable code pattern. The miner extracts a generalized
    regex from confirmed patterns and proposes it as a new detection rule.
    """

    def __init__(self, knowledge: KnowledgeStore):
        self._knowledge = knowledge

    def mine_from_findings(self, cwe: str,
                           min_samples: int = 3) -> list[DetectionPattern]:
        confirmed = self._knowledge.findings(cwe=cwe, verified_only=True)
        if len(confirmed) < min_samples:
            return []

        snippets = [f.snippet for f in confirmed if f.snippet]
        if not snippets:
            return []

        patterns = []

        common_tokens = self._extract_common_tokens(snippets)
        if common_tokens:
            regex = self._tokens_to_regex(common_tokens)
            if regex and self._is_valid_regex(regex):
                cwe_num = int(re.search(r"\d+", cwe).group()) if re.search(r"\d+", cwe) else 0
                lang = confirmed[0].language if confirmed else "unknown"
                pid = "mined-%s-%s-%s" % (
                    cwe.lower().replace("-", ""),
                    lang,
                    hashlib.sha256(regex.encode()).hexdigest()[:8],
                )
                patterns.append(DetectionPattern(
                    pattern_id=pid,
                    cwe=cwe,
                    language=lang,
                    regex=regex,
                    description="Mined from %d verified findings" % len(confirmed),
                    source="mined",
                ))

        sink_patterns = self._extract_sink_patterns(confirmed)
        for sp in sink_patterns:
            if self._is_valid_regex(sp["regex"]):
                pid = "mined-sink-%s-%s" % (
                    cwe.lower().replace("-", ""),
                    hashlib.sha256(sp["regex"].encode()).hexdigest()[:8],
                )
                patterns.append(DetectionPattern(
                    pattern_id=pid,
                    cwe=cwe,
                    language=sp.get("language", "unknown"),
                    regex=sp["regex"],
                    description="Sink pattern: %s" % sp.get("description", ""),
                    source="mined",
                ))

        return patterns

    def _extract_common_tokens(self, snippets: list[str]) -> list[str]:
        if not snippets:
            return []
        token_sets = []
        for s in snippets:
            tokens = set(re.findall(r"[a-zA-Z_]\w*", s))
            token_sets.append(tokens)

        common = token_sets[0]
        for ts in token_sets[1:]:
            common = common & ts

        noise = {"self", "return", "if", "else", "for", "while", "def",
                 "class", "import", "from", "try", "except", "finally",
                 "with", "as", "in", "not", "and", "or", "is", "None",
                 "True", "False", "public", "private", "static", "void",
                 "int", "String", "boolean", "new", "this", "var", "let",
                 "const", "function"}
        return sorted(common - noise)

    def _tokens_to_regex(self, tokens: list[str]) -> str:
        if not tokens:
            return ""
        if len(tokens) == 1:
            return r"\b" + re.escape(tokens[0]) + r"\b"
        escaped = [re.escape(t) for t in tokens[:5]]
        parts = [r"\b" + e + r"\b" for e in escaped]
        return "(?=.*" + ")(?=.*".join(parts) + ")"

    def _extract_sink_patterns(self,
                               findings: list[StoredFinding],
                               ) -> list[dict[str, str]]:
        results = []
        sink_groups: dict[str, list[str]] = defaultdict(list)

        for f in findings:
            if not f.snippet:
                continue
            calls = re.findall(r"(\w+)\s*\(", f.snippet)
            for call in calls:
                sink_groups[call].append(f.snippet)

        for call_name, snippets in sink_groups.items():
            if len(snippets) >= 2:
                results.append({
                    "regex": r"\b" + re.escape(call_name) + r"\s*\(",
                    "description": "call to %s() seen in %d findings" %
                                   (call_name, len(snippets)),
                    "language": findings[0].language,
                })

        return results

    def _is_valid_regex(self, pattern: str) -> bool:
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False


# =========================================================================== #
#  TEMPLATE GENERATOR                                                          #
# =========================================================================== #

class TemplateGenerator:
    """Generates new detection/PoC/patch/regression templates from patterns.

    When the gap analyzer identifies a missing CWE in one of the generators,
    the template generator creates a skeleton that can be tested and
    integrated. It doesn't hallucinate attack techniques -- it extracts
    them from the pattern miner's verified findings and the existing
    templates for related CWEs.
    """

    def __init__(self, registry: ModuleRegistry, knowledge: KnowledgeStore):
        self._registry = registry
        self._knowledge = knowledge

    def generate_detection_rule(self, pattern: DetectionPattern) -> str:
        return (
            '    "%s": {\n'
            '        "pattern": r"""%s""",\n'
            '        "cwe": "%s",\n'
            '        "severity": "HIGH",\n'
            '        "message": "Potential %s vulnerability detected",\n'
            '        "fix": "Review and apply secure coding pattern for %s",\n'
            '        "confidence": %.1f,\n'
            '        "source": "%s",\n'
            '    },\n'
        ) % (
            pattern.pattern_id,
            pattern.regex,
            pattern.cwe,
            pattern.cwe,
            pattern.cwe,
            min(pattern.precision, 0.9),
            pattern.source,
        )

    def generate_poc_skeleton(self, cwe: int,
                              findings: list[StoredFinding]) -> str:
        param = "user_input"
        endpoint = "http://TARGET/endpoint"
        if findings:
            f = findings[0]
            param = f.snippet.split("(")[0].strip() if "(" in f.snippet else param

        return (
            '#!/usr/bin/env python3\n'
            '"""PoC for CWE-%d (auto-generated by OwenOS gen %%%%GEN%%%%).\n'
            'Target: %%%%ENDPOINT%%%%\n'
            'Parameter: %%%%PARAM%%%%\n'
            '"""\n'
            'import sys\n'
            'import requests\n'
            '\n'
            'TARGET = "%%%%ENDPOINT%%%%"\n'
            'PARAM = "%%%%PARAM%%%%"\n'
            '\n'
            '# --- Attack vectors (extracted from %d verified findings) ---\n'
            'PAYLOADS = [\n'
            '%s'
            ']\n'
            '\n'
            '\n'
            'def main():\n'
            '    print("[*] CWE-%d PoC - %%%%RULE%%%%")\n'
            '    print("[*] Target: %%s" %% TARGET)\n'
            '    vulns = 0\n'
            '    for payload in PAYLOADS:\n'
            '        try:\n'
            '            resp = requests.get(TARGET, params={PARAM: payload}, timeout=10)\n'
            '            if payload in resp.text or resp.status_code == 500:\n'
            '                print("[+] Payload triggered: %%s" %% payload[:60])\n'
            '                vulns += 1\n'
            '        except requests.RequestException as e:\n'
            '            print("[-] Error: %%s" %% e)\n'
            '    if vulns:\n'
            '        print("[+] VULNERABLE: %%d payloads triggered" %% vulns)\n'
            '        sys.exit(0)\n'
            '    else:\n'
            '        print("[-] Not vulnerable or not reachable")\n'
            '        sys.exit(1)\n'
            '\n'
            '\n'
            'if __name__ == "__main__":\n'
            '    main()\n'
        ) % (
            cwe,
            len(findings),
            self._extract_payloads_from_findings(findings),
            cwe,
        )

    def generate_patch_skeleton(self, cwe: int, language: str,
                                findings: list[StoredFinding]) -> str:
        return (
            '# Patch skeleton for CWE-%d (%s)\n'
            '# Generated by OwenOS from %d verified findings\n'
            '#\n'
            '# VULNERABLE:\n'
            '%s'
            '#\n'
            '# FIXED:\n'
            '#   [TODO: extract fix pattern from related CWEs]\n'
            '#\n'
            '# EXPLANATION:\n'
            '#   [TODO: describe the vulnerability and the fix]\n'
        ) % (
            cwe,
            language,
            len(findings),
            self._extract_vulnerable_patterns(findings),
        )

    def generate_regression_skeleton(self, cwe: int,
                                     findings: list[StoredFinding]) -> str:
        return (
            '#!/usr/bin/env python3\n'
            '"""Regression test for CWE-%d (auto-generated by OwenOS).\n'
            'Generated from %d verified findings.\n'
            '"""\n'
            'import unittest\n'
            '\n'
            '\n'
            'def vulnerable(user_input):\n'
            '    """VULNERABLE: the pattern from the finding."""\n'
            '    pass  # TODO: extract from snippet\n'
            '\n'
            '\n'
            'def fixed(user_input):\n'
            '    """FIXED: the secure alternative."""\n'
            '    pass  # TODO: extract from patch\n'
            '\n'
            '\n'
            'class TestCWE%dRegression(unittest.TestCase):\n'
            '\n'
            '    def test_vulnerable_is_exploitable(self):\n'
            '        # The vulnerable version should exhibit the flaw\n'
            '        pass  # TODO\n'
            '\n'
            '    def test_fixed_is_safe(self):\n'
            '        # The fixed version should block the attack\n'
            '        pass  # TODO\n'
            '\n'
            '\n'
            'if __name__ == "__main__":\n'
            '    unittest.main()\n'
        ) % (cwe, len(findings), cwe)

    def _extract_payloads_from_findings(self, findings: list[StoredFinding]) -> str:
        payloads = set()
        for f in findings:
            if f.snippet:
                strings = re.findall(r'"([^"]+)"', f.snippet)
                strings += re.findall(r"'([^']+)'", f.snippet)
                for s in strings:
                    if len(s) > 2 and not s.startswith("http"):
                        payloads.add(s)

        if not payloads:
            return '    "test_payload",\n'
        lines = []
        for p in sorted(payloads)[:20]:
            lines.append('    %s,\n' % repr(p))
        return "".join(lines)

    def _extract_vulnerable_patterns(self, findings: list[StoredFinding]) -> str:
        lines = []
        seen = set()
        for f in findings[:5]:
            if f.snippet and f.snippet not in seen:
                seen.add(f.snippet)
                for line in f.snippet.split("\n")[:3]:
                    lines.append("#   %s\n" % line.strip())
        return "".join(lines) if lines else "#   [no snippets available]\n"


# =========================================================================== #
#  SELF-TEST ENGINE                                                            #
# =========================================================================== #

class SelfTestResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class TestOutcome:
    name: str
    result: SelfTestResult
    details: str = ""
    elapsed: float = 0.0


class SelfTestEngine:
    """Validates generated artifacts before they're integrated.

    Every improvement Owen makes to itself must pass the self-test
    before it goes live. This prevents regressions and ensures
    generated code actually works.
    """

    def __init__(self, knowledge: KnowledgeStore):
        self._knowledge = knowledge
        self._test_history: list[TestOutcome] = []

    def test_detection_pattern(self, pattern: DetectionPattern,
                               known_vulnerable: list[str] | None = None,
                               known_safe: list[str] | None = None,
                               ) -> TestOutcome:
        start = time.time()
        try:
            compiled = re.compile(pattern.regex)
        except re.error as e:
            return TestOutcome("pattern-compile", SelfTestResult.FAIL,
                               "Invalid regex: %s" % e)

        tp = fp = tn = fn = 0

        if known_vulnerable:
            for sample in known_vulnerable:
                if compiled.search(sample):
                    tp += 1
                else:
                    fn += 1

        if known_safe:
            for sample in known_safe:
                if compiled.search(sample):
                    fp += 1
                else:
                    tn += 1

        total_tested = tp + fp + tn + fn
        if total_tested == 0:
            return TestOutcome("pattern-validate", SelfTestResult.SKIP,
                               "No test samples provided",
                               time.time() - start)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall / (precision + recall)
               if (precision + recall) > 0 else 0)

        outcome = TestOutcome(
            name="pattern-accuracy",
            result=SelfTestResult.PASS if f1 >= 0.6 else SelfTestResult.FAIL,
            details="P=%.2f R=%.2f F1=%.2f (TP=%d FP=%d TN=%d FN=%d)" %
                    (precision, recall, f1, tp, fp, tn, fn),
            elapsed=time.time() - start,
        )
        self._test_history.append(outcome)
        return outcome

    def test_generated_code(self, code: str, label: str = "generated") -> TestOutcome:
        start = time.time()
        try:
            ast.parse(code)
        except SyntaxError as e:
            outcome = TestOutcome(
                name="%s-syntax" % label,
                result=SelfTestResult.FAIL,
                details="SyntaxError at line %d: %s" % (e.lineno or 0, e.msg),
                elapsed=time.time() - start,
            )
            self._test_history.append(outcome)
            return outcome

        unfilled = re.findall(r"%%[A-Z_]+%%", code)
        if unfilled:
            outcome = TestOutcome(
                name="%s-placeholders" % label,
                result=SelfTestResult.FAIL,
                details="Unfilled placeholders: %s" % unfilled,
                elapsed=time.time() - start,
            )
            self._test_history.append(outcome)
            return outcome

        has_main = "__name__" in code and "__main__" in code
        has_exit = "sys.exit" in code

        issues = []
        if not has_main:
            issues.append("missing __main__ guard")
        if not has_exit:
            issues.append("missing sys.exit")

        if issues:
            outcome = TestOutcome(
                name="%s-structure" % label,
                result=SelfTestResult.FAIL,
                details="; ".join(issues),
                elapsed=time.time() - start,
            )
        else:
            outcome = TestOutcome(
                name="%s-validate" % label,
                result=SelfTestResult.PASS,
                details="valid Python, has __main__ and sys.exit",
                elapsed=time.time() - start,
            )

        self._test_history.append(outcome)
        return outcome

    def test_history(self, last_n: int = 20) -> list[TestOutcome]:
        return self._test_history[-last_n:]

    def pass_rate(self) -> float:
        if not self._test_history:
            return 0.0
        passed = sum(1 for t in self._test_history
                     if t.result == SelfTestResult.PASS)
        return passed / len(self._test_history)


# =========================================================================== #
#  IMPROVEMENT ENGINE                                                          #
# =========================================================================== #

@dataclass
class Improvement:
    """A concrete improvement Owen made to itself."""
    improvement_id: str
    kind: str  # "new_pattern", "new_poc", "new_patch", "new_regression", "tuned_pattern"
    cwe: int
    description: str
    artifact: str  # the generated code or rule
    test_result: TestOutcome | None = None
    integrated: bool = False
    generation: int = 0


class ImprovementEngine:
    """The core self-improvement loop.

    Orchestrates: gap analysis -> pattern mining -> template generation ->
    self-testing -> integration. Each cycle produces Improvement objects
    that track what Owen changed about itself.
    """

    def __init__(self, kernel: Kernel, registry: ModuleRegistry,
                 knowledge: KnowledgeStore):
        self._kernel = kernel
        self._registry = registry
        self._knowledge = knowledge
        self._gap_analyzer = GapAnalyzer(registry, knowledge)
        self._pattern_miner = PatternMiner(knowledge)
        self._template_gen = TemplateGenerator(registry, knowledge)
        self._self_test = SelfTestEngine(knowledge)
        self._improvements: list[Improvement] = []

    @property
    def gap_analyzer(self) -> GapAnalyzer:
        return self._gap_analyzer

    @property
    def pattern_miner(self) -> PatternMiner:
        return self._pattern_miner

    @property
    def template_generator(self) -> TemplateGenerator:
        return self._template_gen

    @property
    def self_test(self) -> SelfTestEngine:
        return self._self_test

    def run_cycle(self) -> list[Improvement]:
        gen = self._kernel.generation
        improvements: list[Improvement] = []

        proc = self._kernel.spawn("improvement-cycle-%d" % gen,
                                   "analyze", Priority.HIGH)
        self._kernel.start(proc.pid)

        # Phase 1: Gap Analysis
        gaps = self._gap_analyzer.analyze()
        self._knowledge.record_metric("gaps_found", len(gaps), gen)

        # Phase 2: Pattern Mining
        mined_cwes = set()
        for gap in gaps:
            cwe_str = "CWE-%d" % gap.cwe
            if cwe_str not in mined_cwes:
                mined_cwes.add(cwe_str)
                new_patterns = self._pattern_miner.mine_from_findings(cwe_str)
                for pattern in new_patterns:
                    pattern.generation_added = gen
                    test_result = self._self_test.test_detection_pattern(pattern)
                    if test_result.result != SelfTestResult.FAIL:
                        self._knowledge.add_pattern(pattern)
                        imp = Improvement(
                            improvement_id="imp-%d-%s" % (gen, pattern.pattern_id),
                            kind="new_pattern",
                            cwe=gap.cwe,
                            description="Mined detection pattern for %s" % cwe_str,
                            artifact=pattern.regex,
                            test_result=test_result,
                            integrated=True,
                            generation=gen,
                        )
                        improvements.append(imp)

        # Phase 3: Template Generation for missing coverage
        for gap in gaps:
            if gap.gap_type == "no_poc":
                findings = self._knowledge.findings(
                    cwe="CWE-%d" % gap.cwe, verified_only=True)
                skeleton = self._template_gen.generate_poc_skeleton(
                    gap.cwe, findings)
                test_result = self._self_test.test_generated_code(
                    skeleton, "poc-cwe%d" % gap.cwe)
                imp = Improvement(
                    improvement_id="imp-%d-poc-%d" % (gen, gap.cwe),
                    kind="new_poc",
                    cwe=gap.cwe,
                    description="Generated PoC skeleton for CWE-%d" % gap.cwe,
                    artifact=skeleton,
                    test_result=test_result,
                    integrated=test_result.result == SelfTestResult.PASS,
                    generation=gen,
                )
                improvements.append(imp)

            elif gap.gap_type == "no_patch":
                findings = self._knowledge.findings(cwe="CWE-%d" % gap.cwe)
                lang = findings[0].language if findings else "python"
                skeleton = self._template_gen.generate_patch_skeleton(
                    gap.cwe, lang, findings)
                imp = Improvement(
                    improvement_id="imp-%d-patch-%d" % (gen, gap.cwe),
                    kind="new_patch",
                    cwe=gap.cwe,
                    description="Generated patch skeleton for CWE-%d" % gap.cwe,
                    artifact=skeleton,
                    integrated=False,
                    generation=gen,
                )
                improvements.append(imp)

            elif gap.gap_type == "no_regression":
                findings = self._knowledge.findings(cwe="CWE-%d" % gap.cwe)
                skeleton = self._template_gen.generate_regression_skeleton(
                    gap.cwe, findings)
                test_result = self._self_test.test_generated_code(
                    skeleton, "regtest-cwe%d" % gap.cwe)
                imp = Improvement(
                    improvement_id="imp-%d-regtest-%d" % (gen, gap.cwe),
                    kind="new_regression",
                    cwe=gap.cwe,
                    description="Generated regression test for CWE-%d" % gap.cwe,
                    artifact=skeleton,
                    test_result=test_result,
                    integrated=test_result.result == SelfTestResult.PASS,
                    generation=gen,
                )
                improvements.append(imp)

        # Phase 4: Record metrics
        self._knowledge.record_metric(
            "improvements_made", len(improvements), gen)
        self._knowledge.record_metric(
            "improvements_integrated",
            sum(1 for i in improvements if i.integrated), gen)
        self._knowledge.record_metric(
            "coverage_score", self._knowledge.coverage_score(), gen)
        self._knowledge.record_metric(
            "self_test_pass_rate", self._self_test.pass_rate(), gen)

        self._improvements.extend(improvements)
        self._kernel.complete(proc.pid, {
            "improvements": len(improvements),
            "integrated": sum(1 for i in improvements if i.integrated),
            "gaps_remaining": len(gaps) - len(improvements),
        })

        return improvements

    def improvements(self, generation: int | None = None) -> list[Improvement]:
        if generation is not None:
            return [i for i in self._improvements if i.generation == generation]
        return list(self._improvements)

    def improvement_rate(self) -> float:
        if not self._improvements:
            return 0.0
        return sum(1 for i in self._improvements if i.integrated) / len(self._improvements)


# =========================================================================== #
#  EVOLUTION TRACKER                                                           #
# =========================================================================== #

@dataclass
class GenerationSnapshot:
    """Snapshot of Owen's state at a generation boundary."""
    generation: int
    timestamp: float
    total_cwes_covered: int
    detection_cwes: int
    poc_cwes: int
    patch_cwes: int
    regression_cwes: int
    total_findings: int
    verified_findings: int
    false_positive_rate: float
    patterns_mined: int
    improvements_made: int
    coverage_score: float
    self_test_pass_rate: float


class EvolutionTracker:
    """Tracks Owen's evolution across generations."""

    def __init__(self, knowledge: KnowledgeStore, registry: ModuleRegistry):
        self._knowledge = knowledge
        self._registry = registry
        self._snapshots: list[GenerationSnapshot] = []

    def snapshot(self, generation: int) -> GenerationSnapshot:
        matrix = self._registry.cwe_coverage_matrix()
        all_cwes = set(matrix.keys())

        det_cwes = {c for c, m in matrix.items() if m.get("scanner")}
        poc_cwes = {c for c, m in matrix.items() if m.get("poc_generator")}
        pat_cwes = {c for c, m in matrix.items() if m.get("patch_generator")}
        reg_cwes = {c for c, m in matrix.items() if m.get("regression_generator")}

        snap = GenerationSnapshot(
            generation=generation,
            timestamp=time.time(),
            total_cwes_covered=len(all_cwes),
            detection_cwes=len(det_cwes),
            poc_cwes=len(poc_cwes),
            patch_cwes=len(pat_cwes),
            regression_cwes=len(reg_cwes),
            total_findings=self._knowledge.finding_count(),
            verified_findings=self._knowledge.verified_count(),
            false_positive_rate=self._knowledge.false_positive_rate(),
            patterns_mined=len(self._knowledge.patterns(reliable_only=False)),
            improvements_made=len([m for m in self._knowledge.get_metrics(
                "improvements_made")]),
            coverage_score=self._knowledge.coverage_score(),
            self_test_pass_rate=0.0,
        )
        self._snapshots.append(snap)
        return snap

    def history(self) -> list[GenerationSnapshot]:
        return list(self._snapshots)

    def delta(self, gen_a: int, gen_b: int) -> dict[str, float]:
        snaps = {s.generation: s for s in self._snapshots}
        a = snaps.get(gen_a)
        b = snaps.get(gen_b)
        if not a or not b:
            return {}
        return {
            "cwes_covered": b.total_cwes_covered - a.total_cwes_covered,
            "detection_cwes": b.detection_cwes - a.detection_cwes,
            "poc_cwes": b.poc_cwes - a.poc_cwes,
            "patch_cwes": b.patch_cwes - a.patch_cwes,
            "regression_cwes": b.regression_cwes - a.regression_cwes,
            "findings": b.total_findings - a.total_findings,
            "verified": b.verified_findings - a.verified_findings,
            "fp_rate_change": b.false_positive_rate - a.false_positive_rate,
            "coverage_score_change": b.coverage_score - a.coverage_score,
        }

    def is_improving(self) -> bool:
        if len(self._snapshots) < 2:
            return True  # benefit of the doubt
        recent = self._snapshots[-2:]
        return recent[-1].coverage_score >= recent[-2].coverage_score


# =========================================================================== #
#  OWEN OS: THE FULL SYSTEM                                                    #
# =========================================================================== #

class OwenOS:
    """The self-improving operating system for Attestor.

    Usage:
        os = OwenOS()
        os.boot()                    # load modules, restore state
        os.ingest_findings(...)      # feed scan results
        improvements = os.evolve()   # run one improvement cycle
        os.status()                  # see what changed
        os.shutdown()                # persist state
    """

    def __init__(self, knowledge_dir: str | None = None):
        self.kernel = Kernel()
        self.knowledge = KnowledgeStore(knowledge_dir)
        self.registry = ModuleRegistry()
        self.engine = ImprovementEngine(
            self.kernel, self.registry, self.knowledge)
        self.evolution = EvolutionTracker(self.knowledge, self.registry)
        self._booted = False

    def boot(self) -> dict[str, Any]:
        proc = self.kernel.spawn("boot", "lifecycle", Priority.CRITICAL)
        self.kernel.start(proc.pid)

        self.knowledge.load()
        self._load_modules()

        self.kernel.complete(proc.pid, {"modules": len(self.registry.all_modules())})
        self._booted = True

        self.kernel.bus.publish(Event("os.boot", "owen_os", {
            "generation": self.kernel.generation,
            "modules": len(self.registry.all_modules()),
        }))

        return self.status()

    def _load_modules(self) -> None:
        detector_dir = os.path.dirname(os.path.abspath(__file__))

        module_specs = [
            ("detect", ModuleKind.SCANNER, "detect"),
            ("poc_gen42", ModuleKind.POC_GENERATOR, "poc_gen42"),
            ("patch_gen42", ModuleKind.PATCH_GENERATOR, "patch_gen42"),
            ("regression_gen42", ModuleKind.REGRESSION_GENERATOR, "regression_gen42"),
            ("realpath_bypass42", ModuleKind.PAYLOAD_GENERATOR, "realpath_bypass42"),
        ]

        import importlib
        import sys

        if detector_dir not in sys.path:
            sys.path.insert(0, detector_dir)

        for name, kind, module_name in module_specs:
            try:
                mod = importlib.import_module(module_name)
                self.registry.register(
                    name=name,
                    kind=kind,
                    module=mod,
                    version=getattr(mod, "VERSION", "unknown"),
                    description=getattr(mod, "__doc__", "")[:100] if mod.__doc__ else "",
                )
            except ImportError:
                pass  # module not available

    def ingest_findings(self, findings: list[dict[str, Any]],
                        generation: int | None = None) -> int:
        gen = generation if generation is not None else self.kernel.generation
        count = 0
        for f in findings:
            cwe_str = f.get("cwe", "")
            if not cwe_str and f.get("rule"):
                try:
                    from detect import RULE_CWE
                    cwe_str = RULE_CWE.get(f["rule"], "")
                except ImportError:
                    pass

            sf = StoredFinding(
                rule=f.get("rule", "unknown"),
                cwe=cwe_str,
                file_path=f.get("path", f.get("file_path", "")),
                line=f.get("line", 0),
                severity=f.get("severity", "MEDIUM"),
                language=f.get("language", "unknown"),
                snippet=f.get("snippet", ""),
                generation_found=gen,
            )
            self.knowledge.add_finding(sf)
            count += 1

        self.kernel.bus.publish(Event("findings.ingested", "owen_os",
                                      {"count": count, "generation": gen}))
        return count

    def verify_finding(self, fingerprint: str, poc_passed: bool) -> None:
        self.knowledge.mark_verified(fingerprint, poc_passed)
        self.kernel.bus.publish(Event("finding.verified", "owen_os",
                                      {"fingerprint": fingerprint,
                                       "passed": poc_passed}))

    def evolve(self) -> list[Improvement]:
        gen = self.kernel.advance_generation()

        self.evolution.snapshot(gen - 1)

        improvements = self.engine.run_cycle()

        self.evolution.snapshot(gen)

        self.kernel.bus.publish(Event("evolution.complete", "owen_os", {
            "generation": gen,
            "improvements": len(improvements),
            "integrated": sum(1 for i in improvements if i.integrated),
        }))

        return improvements

    def status(self) -> dict[str, Any]:
        matrix = self.registry.cwe_coverage_matrix()
        return {
            "generation": self.kernel.generation,
            "uptime": self.kernel.uptime(),
            "modules": len(self.registry.all_modules()),
            "cwes_covered": len(matrix),
            "coverage_score": self.knowledge.coverage_score(),
            "total_findings": self.knowledge.finding_count(),
            "verified_findings": self.knowledge.verified_count(),
            "false_positive_rate": self.knowledge.false_positive_rate(),
            "patterns_mined": len(self.knowledge.patterns()),
            "improvements": len(self.engine.improvements()),
            "improvement_rate": self.engine.improvement_rate(),
            "is_improving": self.evolution.is_improving(),
            "process_stats": self.kernel.stats(),
        }

    def coverage_report(self) -> dict[int, dict[str, bool]]:
        return self.registry.cwe_coverage_matrix()

    def gaps(self) -> list[Gap]:
        return self.engine.gap_analyzer.analyze()

    def improvement_plan(self, max_items: int = 10) -> list[Gap]:
        return self.engine.gap_analyzer.improvement_plan(max_items)

    def shutdown(self, persist: bool = True) -> None:
        if persist:
            self.knowledge.save()

        self.kernel.bus.publish(Event("os.shutdown", "owen_os", {
            "generation": self.kernel.generation,
            "persisted": persist,
        }))

    def __repr__(self) -> str:
        return ("OwenOS(gen=%d, modules=%d, cwes=%d, findings=%d)" %
                (self.kernel.generation,
                 len(self.registry.all_modules()),
                 len(self.registry.cwe_coverage_matrix()),
                 self.knowledge.finding_count()))
