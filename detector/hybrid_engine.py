#!/usr/bin/env python3
"""Hybrid analysis engine -- static analysis + trained model judgment.

Static engines find candidate vulnerabilities with high recall.
Owen-coder (fine-tuned) judges each candidate with semantic understanding.
Memory provides historical context to boost precision.

This is what makes Attestor competitive with frontier models:
  - Static analysis gives us dataflow/taint/reachability that LLMs can't do
  - Owen-coder gives us intent understanding that rules can't do
  - Memory gives us codebase-specific learning that neither can do alone

    from hybrid_engine import HybridAnalyzer
    analyzer = HybridAnalyzer(".")
    results = analyzer.analyze(effort="high")
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


JUDGE_SYSTEM = (
    "You are a vulnerability judge. You receive findings from static analysis "
    "and the source code context. For each finding, determine if it is a real "
    "exploitable vulnerability or a false positive. Be precise. Output JSON."
)

JUDGE_PROMPT = """Static analysis found this potential vulnerability:

Rule: {rule_id}
Severity: {severity}
File: {path}
Line: {line}
Description: {description}
{cwe_line}
{memory_context}

Source code around the finding:
```
{code_context}
```

Analyze this finding. Output valid JSON:
{{
  "verdict": "EXPLOITABLE" | "FALSE_POSITIVE" | "UNCERTAIN",
  "confidence": 0.0-1.0,
  "reasoning": "why this verdict",
  "actual_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "exploit_scenario": "how an attacker would exploit this (if exploitable)",
  "fix": "concrete fix suggestion"
}}"""

BATCH_PROMPT = """You are judging {count} static analysis findings. For each, determine if it's a real vulnerability or false positive.

Findings:
{findings_block}

Output a JSON array with one verdict per finding, in order:
[
  {{"id": 0, "verdict": "EXPLOITABLE|FALSE_POSITIVE|UNCERTAIN", "confidence": 0.0-1.0, "reasoning": "...", "actual_severity": "...", "fix": "..."}},
  ...
]"""


@dataclass
class JudgedFinding:
    finding: dict
    verdict: str = "UNCERTAIN"
    confidence: float = 0.0
    reasoning: str = ""
    actual_severity: str = ""
    exploit_scenario: str = ""
    fix: str = ""
    static_severity: str = ""
    memory_tags: list[str] = field(default_factory=list)
    judge_model: str = ""
    latency_ms: int = 0


class HybridAnalyzer:
    def __init__(self, project_root: str = ".", model: str | None = None):
        self.root = Path(project_root).resolve()
        self.model = model
        self._mem = None
        self._ai = None

    def _get_memory(self):
        if self._mem is None:
            try:
                import memory
                self._mem = memory.Memory(str(self.root))
            except ImportError:
                pass
        return self._mem

    def _get_ai(self):
        if self._ai is None:
            import ai_engine
            self._ai = ai_engine
        return self._ai

    def _read_context(self, path: str, line: int, window: int = 15) -> str:
        full_path = self.root / path if not os.path.isabs(path) else Path(path)
        if not full_path.exists():
            return ""
        try:
            with open(full_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return ""
        start = max(0, line - window - 1)
        end = min(len(lines), line + window)
        numbered = []
        for i in range(start, end):
            marker = " >> " if i == line - 1 else "    "
            numbered.append(f"{i+1:4d}{marker}{lines[i].rstrip()}")
        return "\n".join(numbered)

    def _memory_context(self, finding: dict) -> str:
        mem = self._get_memory()
        if mem is None:
            return ""
        parts = []
        if finding.get("memory_confirmed"):
            parts.append("MEMORY: Previously confirmed as true positive")
        if finding.get("memory_low_precision"):
            parts.append("MEMORY: This rule has >80% false positive rate historically")
        if finding.get("memory_high_precision"):
            parts.append("MEMORY: This rule has >70% true positive rate historically")
        if finding.get("memory_hotspot"):
            parts.append("MEMORY: This file is a known vulnerability hotspot")
        return "\n".join(parts)

    def judge_finding(self, finding: dict) -> JudgedFinding:
        ai = self._get_ai()
        path = finding.get("path", finding.get("file", ""))
        line = finding.get("line", 0)
        code_context = self._read_context(path, line)
        mem_ctx = self._memory_context(finding)
        cwe = finding.get("cwe", "")
        cwe_line = f"CWE: {cwe}" if cwe else ""

        prompt = JUDGE_PROMPT.format(
            rule_id=finding.get("rule_id", finding.get("rule", "unknown")),
            severity=finding.get("severity", "MEDIUM"),
            path=path,
            line=line,
            description=finding.get("description", ""),
            cwe_line=cwe_line,
            memory_context=mem_ctx,
            code_context=code_context or "(source not available)",
        )

        t0 = time.time()
        try:
            response = ai.chat(
                [{"role": "user", "content": prompt}],
                model=self.model, task="review",
                stream=False, temperature=0.1,
            )
            model_used = ai.resolve_model("review", override=self.model)
        except Exception as e:
            return JudgedFinding(
                finding=finding,
                verdict="UNCERTAIN",
                confidence=0.0,
                reasoning=f"Model unavailable: {e}",
                static_severity=finding.get("severity", "MEDIUM"),
            )
        latency = int((time.time() - t0) * 1000)

        parsed = _parse_verdict(response)
        tags = []
        if finding.get("memory_confirmed"):
            tags.append("confirmed")
        if finding.get("memory_hotspot"):
            tags.append("hotspot")
        if finding.get("memory_low_precision"):
            tags.append("noisy_rule")

        return JudgedFinding(
            finding=finding,
            verdict=parsed.get("verdict", "UNCERTAIN"),
            confidence=parsed.get("confidence", 0.0),
            reasoning=parsed.get("reasoning", ""),
            actual_severity=parsed.get("actual_severity",
                                       finding.get("severity", "MEDIUM")),
            exploit_scenario=parsed.get("exploit_scenario", ""),
            fix=parsed.get("fix", ""),
            static_severity=finding.get("severity", "MEDIUM"),
            memory_tags=tags,
            judge_model=model_used,
            latency_ms=latency,
        )

    def judge_batch(self, findings: list[dict],
                    batch_size: int = 5) -> list[JudgedFinding]:
        results = []
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            batch_results = self._judge_batch_chunk(batch, start_idx=i)
            results.extend(batch_results)
        return results

    def _judge_batch_chunk(self, findings: list[dict],
                           start_idx: int = 0) -> list[JudgedFinding]:
        if not findings:
            return []
        if len(findings) == 1:
            return [self.judge_finding(findings[0])]

        ai = self._get_ai()
        blocks = []
        for j, f in enumerate(findings):
            path = f.get("path", f.get("file", ""))
            line = f.get("line", 0)
            code = self._read_context(path, line, window=8)
            mem_ctx = self._memory_context(f)
            block = (
                f"--- Finding {j} ---\n"
                f"Rule: {f.get('rule_id', f.get('rule', ''))}\n"
                f"Severity: {f.get('severity', 'MEDIUM')}\n"
                f"File: {path}:{line}\n"
                f"Description: {f.get('description', '')}\n"
                f"{mem_ctx}\n"
                f"Code:\n```\n{code}\n```\n"
            )
            blocks.append(block)

        prompt = BATCH_PROMPT.format(
            count=len(findings),
            findings_block="\n".join(blocks),
        )

        t0 = time.time()
        try:
            response = ai.chat(
                [{"role": "user", "content": prompt}],
                model=self.model, task="review",
                stream=False, temperature=0.1,
            )
            model_used = ai.resolve_model("review", override=self.model)
        except Exception as e:
            return [
                JudgedFinding(
                    finding=f, verdict="UNCERTAIN", confidence=0.0,
                    reasoning=f"Model unavailable: {e}",
                    static_severity=f.get("severity", "MEDIUM"),
                )
                for f in findings
            ]
        latency = int((time.time() - t0) * 1000)

        verdicts = _parse_batch_verdicts(response, len(findings))
        results = []
        for j, f in enumerate(findings):
            v = verdicts[j] if j < len(verdicts) else {}
            tags = []
            if f.get("memory_confirmed"):
                tags.append("confirmed")
            if f.get("memory_hotspot"):
                tags.append("hotspot")
            results.append(JudgedFinding(
                finding=f,
                verdict=v.get("verdict", "UNCERTAIN"),
                confidence=v.get("confidence", 0.0),
                reasoning=v.get("reasoning", ""),
                actual_severity=v.get("actual_severity",
                                     f.get("severity", "MEDIUM")),
                fix=v.get("fix", ""),
                static_severity=f.get("severity", "MEDIUM"),
                memory_tags=tags,
                judge_model=model_used,
                latency_ms=latency // max(len(findings), 1),
            ))
        return results

    def analyze(self, effort: str = "high",
                batch: bool = True) -> list[JudgedFinding]:
        from cli import _run_effort
        mem = self._get_memory()

        findings = _run_effort(str(self.root), effort)

        if mem:
            findings = mem.filter_findings(findings)

        if not findings:
            return []

        if batch:
            results = self.judge_batch(findings)
        else:
            results = [self.judge_finding(f) for f in findings]

        if mem:
            t = int(time.time() * 1000)
            mem.record_scan(
                [r.finding for r in results],
                scan_type="hybrid",
                paths=[str(self.root)],
                duration_ms=t,
            )

        return results

    def analyze_file(self, path: str) -> list[JudgedFinding]:
        full = self.root / path if not os.path.isabs(path) else Path(path)
        if not full.exists():
            return []

        try:
            src = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        ext = full.suffix.lower()
        findings = []

        if ext == ".py":
            try:
                import detect
                for f in detect.scan_file(str(full)):
                    findings.append({
                        "path": str(full), "line": getattr(f, "line", 0),
                        "rule_id": getattr(f, "rule", ""),
                        "severity": getattr(f, "severity", "MEDIUM"),
                        "description": getattr(f, "message", ""),
                    })
            except Exception:
                pass

        mem = self._get_memory()
        if mem:
            findings = mem.filter_findings(findings)

        if not findings:
            return []

        return [self.judge_finding(f) for f in findings]


def _parse_verdict(response: str) -> dict:
    try:
        m = re.search(r'\{[^{}]*"verdict"[^{}]*\}', response, re.DOTALL)
        if m:
            return json.loads(m.group())
    except (json.JSONDecodeError, AttributeError):
        pass

    verdict = "UNCERTAIN"
    if "EXPLOITABLE" in response.upper() and "NOT_EXPLOITABLE" not in response.upper():
        verdict = "EXPLOITABLE"
    elif "FALSE_POSITIVE" in response.upper() or "NOT_EXPLOITABLE" in response.upper():
        verdict = "FALSE_POSITIVE"

    return {"verdict": verdict, "confidence": 0.5, "reasoning": response[:500]}


def _parse_batch_verdicts(response: str, expected: int) -> list[dict]:
    try:
        m = re.search(r'\[.*\]', response, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            if isinstance(parsed, list):
                while len(parsed) < expected:
                    parsed.append({"verdict": "UNCERTAIN", "confidence": 0.0})
                return parsed[:expected]
    except (json.JSONDecodeError, AttributeError):
        pass

    verdicts = []
    for block in re.split(r'(?:---\s*Finding\s+\d+|"id"\s*:\s*\d+)', response):
        v = _parse_verdict(block)
        if v.get("verdict") != "UNCERTAIN" or len(verdicts) < expected:
            verdicts.append(v)
    while len(verdicts) < expected:
        verdicts.append({"verdict": "UNCERTAIN", "confidence": 0.0})
    return verdicts[:expected]


def render_results(results: list[JudgedFinding]) -> str:
    lines = [
        "\n  Hybrid Analysis Results",
        "  " + "=" * 55,
    ]

    exploitable = [r for r in results if r.verdict == "EXPLOITABLE"]
    uncertain = [r for r in results if r.verdict == "UNCERTAIN"]
    fps = [r for r in results if r.verdict == "FALSE_POSITIVE"]

    lines.append(f"  {len(results)} findings analyzed by {results[0].judge_model if results else 'model'}")
    lines.append(f"  {len(exploitable)} EXPLOITABLE  |  {len(uncertain)} UNCERTAIN  |  {len(fps)} FALSE POSITIVE")
    lines.append("")

    for r in sorted(exploitable, key=lambda x: _sev_rank(x.actual_severity)):
        f = r.finding
        tags = " ".join(f"[{t}]" for t in r.memory_tags) if r.memory_tags else ""
        lines.append(f"  !! {r.actual_severity:8s} {f.get('rule_id', '?'):20s} "
                     f"{f.get('path', '?')}:{f.get('line', '?')} {tags}")
        lines.append(f"     confidence: {r.confidence:.0%}  |  {r.reasoning[:80]}")
        if r.exploit_scenario:
            lines.append(f"     exploit: {r.exploit_scenario[:80]}")
        if r.fix:
            lines.append(f"     fix: {r.fix[:80]}")
        lines.append("")

    if uncertain:
        lines.append(f"  -- {len(uncertain)} uncertain (manual review recommended) --")
        for r in uncertain[:5]:
            f = r.finding
            lines.append(f"     {f.get('severity', '?'):8s} {f.get('rule_id', '?'):20s} "
                         f"{f.get('path', '?')}:{f.get('line', '?')}")

    if fps:
        lines.append(f"\n  -- {len(fps)} false positives filtered --")

    avg_lat = sum(r.latency_ms for r in results) / max(len(results), 1)
    lines.append(f"\n  avg latency: {avg_lat:.0f}ms per finding")
    lines.append("  " + "=" * 55)
    return "\n".join(lines)


def to_dict(results: list[JudgedFinding]) -> list[dict]:
    return [
        {
            "finding": r.finding,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "reasoning": r.reasoning,
            "actual_severity": r.actual_severity,
            "exploit_scenario": r.exploit_scenario,
            "fix": r.fix,
            "static_severity": r.static_severity,
            "memory_tags": r.memory_tags,
            "judge_model": r.judge_model,
            "latency_ms": r.latency_ms,
        }
        for r in results
    ]


def _sev_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)
