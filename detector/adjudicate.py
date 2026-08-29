#!/usr/bin/env python3
"""Grounded LLM adjudication -- the hybrid that beats a standalone model.

Pillar 2 of the SOTA push. The dataflow engine (Pillar 1) FINDS candidates and,
crucially, GROUNDS each one with an evidence trace (source -> hops -> sink). This
module hands that grounded candidate to Owen Coder and asks the one question a
model is actually good at: given this exact data-flow path, is it exploitable,
and how do you fix it?

Why this beats a raw LLM on the security task:
  - The model never scans blind or hallucinates locations -- it only judges a
    concrete, pre-localized path with the code in front of it.
  - Static analysis does the finding (cheap, whole-repo, deterministic); the LLM
    does the judgement + explanation + fix (its strength). Neither alone is SOTA.

Degrades gracefully: if Owen Coder is offline, findings keep their static verdict
so the pipeline still works -- the model only ever *improves* the result."""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import dataflow


@dataclass
class Adjudication:
    finding: dataflow.Finding
    verdict: str            # EXPLOITABLE | NOT_EXPLOITABLE | UNCERTAIN
    confidence: float       # 0..1
    explanation: str
    suggested_fix: str
    model: str = ""
    grounded: bool = False  # True when the LLM actually judged it


def build_prompt(f: dataflow.Finding) -> str:
    trace_lines = []
    for i, s in enumerate(f.trace, 1):
        base = s.file.replace("\\", "/").split("/")[-1]
        code = f"    {s.code}" if s.code else ""
        trace_lines.append(f"  {i}. {base}:{s.line}  [{s.note}]{code}")
    trace = "\n".join(trace_lines)
    kind = "across function boundaries" if f.interprocedural else "within one function"
    return (
        "You are a precise security auditor. A static dataflow analysis found a "
        "potential vulnerability and traced how untrusted data reaches a dangerous "
        "sink. Judge whether it is ACTUALLY exploitable given this exact path.\n\n"
        f"Vulnerability: {f.sink_type} ({f.cwe})\n"
        f"Data flows {kind} from an untrusted source ({f.source_type}) to the sink:\n"
        f"  sink -> {f.sink_code}\n\n"
        f"Evidence trace (source to sink):\n{trace}\n\n"
        "Answer in EXACTLY this format, nothing else:\n"
        "VERDICT: <EXPLOITABLE|NOT_EXPLOITABLE|UNCERTAIN>\n"
        "CONFIDENCE: <integer 0-100>\n"
        "WHY: <one sentence>\n"
        "FIX: <one concrete code-level fix>"
    )


_VERDICTS = {"EXPLOITABLE", "NOT_EXPLOITABLE", "UNCERTAIN"}


def _parse(text: str) -> tuple[str, float, str, str]:
    verdict, conf, why, fix = "UNCERTAIN", 0.5, "", ""
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"VERDICT:\s*([A-Z_]+)", line, re.I)
        if m and m.group(1).upper() in _VERDICTS:
            verdict = m.group(1).upper()
        m = re.match(r"CONFIDENCE:\s*(\d+)", line, re.I)
        if m:
            conf = max(0.0, min(1.0, int(m.group(1)) / 100.0))
        m = re.match(r"WHY:\s*(.+)", line, re.I)
        if m:
            why = m.group(1).strip()
        m = re.match(r"FIX:\s*(.+)", line, re.I)
        if m:
            fix = m.group(1).strip()
    return verdict, conf, why, fix


def _static_verdict(f: dataflow.Finding) -> Adjudication:
    """Fallback when the model is offline: trust the static analysis."""
    conf = {"CRITICAL": 0.85, "HIGH": 0.75, "MEDIUM": 0.6, "LOW": 0.5}.get(f.severity, 0.6)
    if f.interprocedural:
        conf = min(0.95, conf + 0.05)  # cross-function flows are hard to spot by eye
    return Adjudication(
        finding=f, verdict="EXPLOITABLE" if f.severity in ("CRITICAL", "HIGH") else "UNCERTAIN",
        confidence=conf,
        explanation=f"Static dataflow: untrusted {f.source_type} reaches {f.sink_type} "
                    f"({'cross-function' if f.interprocedural else 'same-function'} path).",
        suggested_fix="", model="(static only -- Owen Coder offline)", grounded=False)


def adjudicate(findings: list[dataflow.Finding], model: str | None = None,
               limit: int = 100) -> list[Adjudication]:
    try:
        import ai_engine
        online = ai_engine.is_available() and bool(ai_engine.list_models())
    except Exception:
        ai_engine = None
        online = False

    results = []
    for f in findings[:limit]:
        if not online:
            results.append(_static_verdict(f))
            continue
        try:
            prompt = build_prompt(f)
            text = ai_engine.generate(prompt, model=model, task="review",
                                      stream=False, temperature=0.1)
            verdict, conf, why, fix = _parse(text or "")
            used = model or ai_engine.resolve_model("review")
            results.append(Adjudication(
                finding=f, verdict=verdict, confidence=conf,
                explanation=why or "(no explanation returned)",
                suggested_fix=fix, model=used, grounded=True))
        except Exception as exc:
            adj = _static_verdict(f)
            adj.explanation += f"  [LLM error: {str(exc)[:60]}]"
            results.append(adj)

    # rank: exploitable + high confidence first
    vorder = {"EXPLOITABLE": 0, "UNCERTAIN": 1, "NOT_EXPLOITABLE": 2}
    results.sort(key=lambda a: (vorder.get(a.verdict, 1), -a.confidence))
    return results


def render(adjs: list[Adjudication]) -> str:
    if not adjs:
        return "  No dataflow findings to adjudicate."
    grounded = any(a.grounded for a in adjs)
    header = "Owen Coder + dataflow (hybrid)" if grounded else "dataflow (static only -- model offline)"
    lines = [f"\n  Grounded Adjudication -- {header}",
             "  " + "=" * 62]
    exploitable = sum(1 for a in adjs if a.verdict == "EXPLOITABLE")
    dismissed = sum(1 for a in adjs if a.verdict == "NOT_EXPLOITABLE")
    lines.append(f"  {len(adjs)} candidate(s): {exploitable} exploitable, "
                 f"{dismissed} dismissed, {len(adjs)-exploitable-dismissed} uncertain")
    if grounded:
        lines.append(f"  (Owen Coder dismissed {dismissed} as non-exploitable -> fewer false alarms)")
    for a in adjs:
        f = a.finding
        base = f.sink_file.replace("\\", "/").split("/")[-1]
        tag = {"EXPLOITABLE": "EXPLOIT", "NOT_EXPLOITABLE": "dismiss",
               "UNCERTAIN": "review"}.get(a.verdict, "review")
        lines.append(f"\n  [{tag}] {f.sink_type} ({f.cwe})  conf={a.confidence:.0%}  "
                     f"{base}:{f.sink_line}")
        if a.explanation:
            lines.append(f"    why: {a.explanation}")
        if a.suggested_fix:
            lines.append(f"    fix: {a.suggested_fix}")
        hops = len(f.trace)
        lines.append(f"    evidence: {hops}-step trace "
                     f"({'cross-function' if f.interprocedural else 'same-function'})")
    if not grounded:
        lines.append("\n  Start Owen Coder (ollama serve + model) to get grounded, "
                     "model-judged verdicts and fixes.")
    return "\n".join(lines)


def to_dict(adjs: list[Adjudication]) -> list[dict]:
    return [
        {
            "cwe": a.finding.cwe, "sink_type": a.finding.sink_type,
            "sink_file": a.finding.sink_file, "sink_line": a.finding.sink_line,
            "verdict": a.verdict, "confidence": a.confidence,
            "explanation": a.explanation, "suggested_fix": a.suggested_fix,
            "model": a.model, "grounded": a.grounded,
            "interprocedural": a.finding.interprocedural,
            "trace": [{"file": s.file, "line": s.line, "note": s.note} for s in a.finding.trace],
        }
        for a in adjs
    ]
