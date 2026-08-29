#!/usr/bin/env python3
"""Runtime behavior correlation -- combines static analysis findings with
runtime signals to dramatically reduce false positives. Ingests runtime data
from logs, traces, coverage reports, and dynamic analysis tools, then
correlates with static findings to assign reachability and exploitability."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class RuntimeSignal:
    source: str
    signal_type: str
    file: str
    line: int = 0
    function: str = ""
    details: str = ""
    confidence: float = 1.0


@dataclass
class CorrelatedFinding:
    static_finding: dict
    runtime_signals: list[RuntimeSignal] = field(default_factory=list)
    reachability: str = "unknown"
    exploitability: str = "unknown"
    false_positive_probability: float = 0.5
    adjusted_severity: str = ""
    reasoning: str = ""


REACHABILITY_LABELS = {
    "confirmed": "Code is confirmed reachable at runtime (observed in traces/logs)",
    "likely": "Code is likely reachable based on coverage data",
    "possible": "Code may be reachable but no runtime evidence found",
    "unreachable": "Code is confirmed unreachable (dead code / never executed)",
}

EXPLOITABILITY_LABELS = {
    "confirmed": "Vulnerability confirmed exploitable with runtime evidence",
    "likely": "Vulnerability likely exploitable based on data flow",
    "possible": "Vulnerability may be exploitable but needs investigation",
    "unlikely": "Vulnerability unlikely exploitable due to runtime controls",
    "mitigated": "Vulnerability mitigated by runtime protections (WAF, sanitizers)",
}


def parse_coverage_report(coverage_path: str) -> dict[str, set[int]]:
    covered_lines: dict[str, set[int]] = {}

    if coverage_path.endswith(".json"):
        try:
            with open(coverage_path, encoding="utf-8") as f:
                data = json.load(f)
            if "files" in data:
                for fpath, fdata in data["files"].items():
                    executed = set()
                    if "executed_lines" in fdata:
                        executed = set(fdata["executed_lines"])
                    elif "lines" in fdata:
                        for line_num, count in fdata["lines"].items():
                            if count > 0:
                                executed.add(int(line_num))
                    covered_lines[fpath] = executed
            elif "coverage" in data:
                for fpath, line_data in data["coverage"].items():
                    executed = {int(ln) for ln, ct in line_data.items() if ct and ct > 0}
                    covered_lines[fpath] = executed
        except (OSError, json.JSONDecodeError, KeyError):
            pass

    elif coverage_path.endswith(".xml"):
        try:
            with open(coverage_path, encoding="utf-8") as f:
                content = f.read()
            for match in re.finditer(
                r'<class[^>]*filename="([^"]*)"[^>]*>(.*?)</class>',
                content, re.DOTALL
            ):
                fpath = match.group(1)
                lines_section = match.group(2)
                executed = set()
                for line_match in re.finditer(r'<line\s+number="(\d+)"\s+hits="(\d+)"', lines_section):
                    if int(line_match.group(2)) > 0:
                        executed.add(int(line_match.group(1)))
                covered_lines[fpath] = executed
        except OSError:
            pass

    return covered_lines


def parse_runtime_logs(log_path: str) -> list[RuntimeSignal]:
    signals = []
    error_pattern = re.compile(
        r"(?:ERROR|CRITICAL|EXCEPTION|Traceback|Warning).*?(?:File\s+['\"]([^'\"]+)['\"],\s+line\s+(\d+))?",
        re.I
    )
    request_pattern = re.compile(
        r"(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s]*)",
        re.I
    )

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = error_pattern.search(line)
                if m:
                    signals.append(RuntimeSignal(
                        source="log",
                        signal_type="error",
                        file=m.group(1) or "",
                        line=int(m.group(2)) if m.group(2) else 0,
                        details=line.strip()[:200],
                    ))

                m = request_pattern.search(line)
                if m:
                    signals.append(RuntimeSignal(
                        source="log",
                        signal_type="request",
                        file="",
                        line=0,
                        details=m.group(0)[:200],
                    ))

    except OSError:
        pass
    return signals


def parse_trace_data(trace_path: str) -> list[RuntimeSignal]:
    signals = []
    try:
        with open(trace_path, encoding="utf-8") as f:
            data = json.load(f)

        traces = data if isinstance(data, list) else data.get("traces", data.get("spans", []))
        for trace in traces:
            signals.append(RuntimeSignal(
                source="trace",
                signal_type="execution",
                file=trace.get("file", trace.get("source", "")),
                line=trace.get("line", 0),
                function=trace.get("function", trace.get("operation", "")),
                details=json.dumps(trace.get("attributes", {}))[:200],
                confidence=0.9,
            ))
    except (OSError, json.JSONDecodeError):
        pass
    return signals


def correlate(
    static_findings: list[dict],
    coverage: dict[str, set[int]] | None = None,
    runtime_signals: list[RuntimeSignal] | None = None,
) -> list[CorrelatedFinding]:
    coverage = coverage or {}
    runtime_signals = runtime_signals or []

    signal_by_file: dict[str, list[RuntimeSignal]] = {}
    for sig in runtime_signals:
        if sig.file:
            signal_by_file.setdefault(sig.file, []).append(sig)

    results = []
    for finding in static_findings:
        fpath = finding.get("path", finding.get("file", finding.get("source_file", "")))
        fline = finding.get("line", finding.get("line_start", finding.get("source_line", 0)))
        severity = finding.get("severity", "MEDIUM")

        corr = CorrelatedFinding(static_finding=finding, adjusted_severity=severity)

        if coverage:
            fpath_norm = fpath.replace("\\", "/")
            matched_coverage = None
            for cov_path, cov_lines in coverage.items():
                cov_norm = cov_path.replace("\\", "/")
                if fpath_norm.endswith(cov_norm) or cov_norm.endswith(fpath_norm):
                    matched_coverage = cov_lines
                    break

            if matched_coverage is not None:
                if fline in matched_coverage:
                    corr.reachability = "confirmed"
                    corr.false_positive_probability *= 0.3
                    corr.reasoning += "Line executed in coverage data. "
                elif any(abs(fline - l) <= 3 for l in matched_coverage):
                    corr.reachability = "likely"
                    corr.false_positive_probability *= 0.5
                    corr.reasoning += "Nearby lines executed in coverage. "
                else:
                    corr.reachability = "unreachable"
                    corr.false_positive_probability *= 2.0
                    corr.reasoning += "Line never executed in coverage. "
            else:
                corr.reachability = "possible"

        file_signals = []
        for sig_path, sigs in signal_by_file.items():
            if fpath.replace("\\", "/").endswith(sig_path.replace("\\", "/")):
                file_signals.extend(sigs)

        corr.runtime_signals = file_signals

        if file_signals:
            error_signals = [s for s in file_signals if s.signal_type == "error"]
            exec_signals = [s for s in file_signals if s.signal_type == "execution"]

            if any(s.line == fline for s in error_signals):
                corr.exploitability = "confirmed"
                corr.false_positive_probability *= 0.1
                corr.reasoning += "Runtime error at exact finding location. "
            elif exec_signals:
                corr.exploitability = "likely"
                corr.false_positive_probability *= 0.4
                corr.reasoning += "Code executed at runtime. "
            else:
                corr.exploitability = "possible"
        else:
            corr.exploitability = "possible"

        fp_prob = min(1.0, max(0.0, corr.false_positive_probability))
        corr.false_positive_probability = round(fp_prob, 2)

        sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_idx = sev_order.index(severity) if severity in sev_order else 1
        if corr.reachability == "unreachable":
            sev_idx = max(0, sev_idx - 2)
            corr.reasoning += "Severity lowered: unreachable code. "
        elif corr.exploitability == "confirmed":
            sev_idx = min(3, sev_idx + 1)
            corr.reasoning += "Severity raised: confirmed exploitable. "
        elif corr.reachability == "confirmed" and corr.exploitability == "likely":
            sev_idx = min(3, sev_idx + 1)
            corr.reasoning += "Severity raised: reachable and likely exploitable. "
        corr.adjusted_severity = sev_order[sev_idx]

        results.append(corr)

    results.sort(key=lambda r: (
        -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r.adjusted_severity, 0),
        r.false_positive_probability,
    ))

    return results


def render(results: list[CorrelatedFinding]) -> str:
    if not results:
        return "  No findings to correlate."
    lines = []
    lines.append(f"\n  Runtime Correlation ({len(results)} finding{'s' if len(results) != 1 else ''})")
    lines.append(f"  {'='*55}")

    confirmed = sum(1 for r in results if r.reachability == "confirmed")
    unreachable = sum(1 for r in results if r.reachability == "unreachable")
    confirmed_exploit = sum(1 for r in results if r.exploitability == "confirmed")

    lines.append(f"  Reachable: {confirmed}  |  Unreachable: {unreachable}  |  Confirmed exploitable: {confirmed_exploit}")
    lines.append(f"  FP reduction: {unreachable} findings deprioritized as unreachable\n")

    for r in results[:30]:
        f = r.static_finding
        path = f.get("path", f.get("file", "?"))
        fline = f.get("line", f.get("line_start", "?"))
        rule = f.get("rule_id", f.get("cwe", "?"))
        orig_sev = f.get("severity", "?")

        sev_change = ""
        if r.adjusted_severity != orig_sev:
            sev_change = f" (was {orig_sev})"

        lines.append(f"  [{r.adjusted_severity}{sev_change}] {path}:{fline}  {rule}")
        lines.append(f"    Reachability: {r.reachability}  |  Exploitability: {r.exploitability}")
        lines.append(f"    FP probability: {r.false_positive_probability:.0%}")
        if r.reasoning:
            lines.append(f"    Reasoning: {r.reasoning.strip()}")
        lines.append("")

    if len(results) > 30:
        lines.append(f"  ... and {len(results) - 30} more findings")

    return "\n".join(lines)


def to_dict(results: list[CorrelatedFinding]) -> list[dict]:
    return [
        {
            "static_finding": r.static_finding,
            "reachability": r.reachability,
            "exploitability": r.exploitability,
            "false_positive_probability": r.false_positive_probability,
            "adjusted_severity": r.adjusted_severity,
            "reasoning": r.reasoning,
            "runtime_signal_count": len(r.runtime_signals),
        }
        for r in results
    ]
