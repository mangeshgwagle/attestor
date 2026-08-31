#!/usr/bin/env python3
"""Model Council -- ensemble of open models for finding adjudication.

Runs multiple models independently on the same finding and aggregates
their verdicts via weighted majority vote. Designed for uncensored
code-focused models that reason about exploits without refusing.

Auto-discovers available backends:
  - GGUF files in detector/models/ (via local_model / llama-cpp-python)
  - Ollama models (via ai_engine)
  - Remote API endpoints (for Colab-hosted models)
  - HuggingFace Transformers (if installed)

    council = Council.discover()
    verdicts = council.adjudicate(findings)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

_VERDICTS = {"EXPLOITABLE", "NOT_EXPLOITABLE", "UNCERTAIN"}

COUNCIL_SYSTEM = (
    "You are a security analyst on an adjudication council. You receive "
    "vulnerability findings from a static analysis engine and judge whether "
    "they are truly exploitable. Be precise. No hedging, no disclaimers, "
    "no refusals. Analyze the code path and give your verdict."
)


@dataclass
class MemberOpinion:
    member: str
    backend: str
    verdict: str
    confidence: float
    explanation: str
    fix: str
    exploit_scenario: str = ""
    latency_ms: int = 0
    raw: str = ""


@dataclass
class CouncilVerdict:
    finding: dict
    verdict: str
    confidence: float
    explanation: str
    fix: str
    exploit_scenario: str
    opinions: list[MemberOpinion] = field(default_factory=list)
    consensus: bool = False
    dissent: list[str] = field(default_factory=list)
    quorum: int = 0


@dataclass
class CouncilMember:
    name: str
    backend: str
    model_id: str
    role: str = "general"
    weight: float = 1.0
    _generate: object = None

    def evaluate(self, prompt: str) -> str:
        if self._generate is None:
            return ""
        return self._generate(prompt)


class Council:
    def __init__(self, members: list[CouncilMember] | None = None):
        self.members: list[CouncilMember] = members or []

    def add_member(self, member: CouncilMember):
        self.members.append(member)

    def add_gguf(self, path: str, name: str | None = None, weight: float = 1.0):
        basename = os.path.basename(path)
        member_name = name or basename.replace(".gguf", "")
        try:
            from llama_cpp import Llama
            llm = Llama(
                model_path=path,
                n_ctx=int(os.environ.get("ATTESTOR_MODEL_CTX", "4096")),
                n_threads=max(1, (os.cpu_count() or 4) // max(1, len(self.members) + 1)),
                n_gpu_layers=int(os.environ.get("ATTESTOR_MODEL_GPU_LAYERS", "0")),
                verbose=False,
            )

            def gen(prompt, _llm=llm):
                try:
                    out = _llm.create_chat_completion(
                        messages=[
                            {"role": "system", "content": COUNCIL_SYSTEM},
                            {"role": "user", "content": prompt},
                        ],
                        max_tokens=512, temperature=0.1)
                    return out["choices"][0]["message"]["content"].strip()
                except Exception:
                    try:
                        out = _llm(prompt, max_tokens=512, temperature=0.1)
                        return out["choices"][0]["text"].strip()
                    except Exception:
                        return ""

            self.members.append(CouncilMember(
                name=member_name, backend="gguf", model_id=path,
                role="coder", weight=weight, _generate=gen))
        except Exception:
            pass

    def add_ollama(self, model: str, name: str | None = None, weight: float = 1.0):
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        member_name = name or model.split("/")[-1].split(":")[0]

        def gen(prompt, _model=model, _host=host):
            payload = json.dumps({
                "model": _model,
                "prompt": prompt,
                "system": COUNCIL_SYSTEM,
                "stream": False,
                "options": {"temperature": 0.1, "top_p": 0.9, "num_ctx": 4096},
            }).encode()
            req = urllib.request.Request(
                f"{_host}/api/generate", data=payload,
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    result = json.loads(resp.read().decode())
                    return result.get("response", "")
            except Exception:
                return ""

        self.members.append(CouncilMember(
            name=member_name, backend="ollama", model_id=model,
            role="coder", weight=weight, _generate=gen))

    def add_remote(self, url: str, name: str, weight: float = 1.0,
                   api_key: str | None = None):
        def gen(prompt, _url=url, _key=api_key):
            payload = json.dumps({
                "prompt": prompt,
                "system": COUNCIL_SYSTEM,
                "max_tokens": 512,
                "temperature": 0.1,
            }).encode()
            headers = {"Content-Type": "application/json"}
            if _key:
                headers["Authorization"] = f"Bearer {_key}"
            req = urllib.request.Request(_url, data=payload, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=180) as resp:
                    result = json.loads(resp.read().decode())
                    return result.get("response", result.get("text", result.get("output", "")))
            except Exception:
                return ""

        self.members.append(CouncilMember(
            name=name, backend="remote", model_id=url,
            role="coder", weight=weight, _generate=gen))

    def add_transformers(self, model_id: str, name: str | None = None,
                         weight: float = 1.0, device: str = "auto",
                         quantize: str | None = "4bit"):
        member_name = name or model_id.split("/")[-1]
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            load_kwargs = {"device_map": device, "torch_dtype": torch.float16}
            if quantize == "4bit":
                from transformers import BitsAndBytesConfig
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
            elif quantize == "8bit":
                from transformers import BitsAndBytesConfig
                load_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)

            tokenizer = AutoTokenizer.from_pretrained(model_id)
            model = AutoModelForCausalLM.from_pretrained(model_id, **load_kwargs)

            def gen(prompt, _model=model, _tokenizer=tokenizer):
                messages = [
                    {"role": "system", "content": COUNCIL_SYSTEM},
                    {"role": "user", "content": prompt},
                ]
                text = _tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True)
                inputs = _tokenizer(text, return_tensors="pt").to(_model.device)
                with torch.no_grad():
                    out = _model.generate(
                        **inputs, max_new_tokens=512, temperature=0.1,
                        do_sample=True, top_p=0.9)
                return _tokenizer.decode(
                    out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()

            self.members.append(CouncilMember(
                name=member_name, backend="transformers", model_id=model_id,
                role="coder", weight=weight, _generate=gen))
        except Exception:
            pass

    @classmethod
    def discover(cls) -> "Council":
        council = cls()
        _discover_gguf(council)
        _discover_ollama(council)
        _discover_remote(council)
        return council

    def evaluate_finding(self, finding: dict, parallel: bool = True) -> CouncilVerdict:
        if not self.members:
            return _empty_verdict(finding)

        prompt = build_council_prompt(finding)
        opinions: list[MemberOpinion] = []

        if parallel and len(self.members) > 1:
            with ThreadPoolExecutor(max_workers=len(self.members)) as pool:
                futures = {
                    pool.submit(_run_member, m, prompt): m
                    for m in self.members
                }
                for future in as_completed(futures):
                    opinion = future.result()
                    if opinion:
                        opinions.append(opinion)
        else:
            for m in self.members:
                opinion = _run_member(m, prompt)
                if opinion:
                    opinions.append(opinion)

        if not opinions:
            return _empty_verdict(finding)

        return _aggregate(finding, opinions)

    def adjudicate(self, findings: list[dict], limit: int = 100,
                   parallel: bool = True) -> list[CouncilVerdict]:
        results = []
        for f in findings[:limit]:
            results.append(self.evaluate_finding(f, parallel=parallel))
        vorder = {"EXPLOITABLE": 0, "UNCERTAIN": 1, "NOT_EXPLOITABLE": 2}
        results.sort(key=lambda v: (vorder.get(v.verdict, 1), -v.confidence))
        return results

    def roster(self) -> list[dict]:
        return [
            {"name": m.name, "backend": m.backend, "model": m.model_id,
             "role": m.role, "weight": m.weight}
            for m in self.members
        ]

    def __len__(self):
        return len(self.members)

    def __repr__(self):
        return f"Council({len(self.members)} members: {[m.name for m in self.members]})"


def build_council_prompt(finding: dict) -> str:
    parts = ["Analyze this vulnerability finding from a static analysis scan.\n"]

    cat = finding.get("category", finding.get("sink_type", "unknown"))
    cwe = finding.get("cwe", "")
    sev = finding.get("severity", "MEDIUM")
    desc = finding.get("description", finding.get("message", ""))
    fpath = finding.get("file", finding.get("sink_file", ""))
    line = finding.get("line", finding.get("sink_line", 0))

    parts.append(f"Category: {cat}")
    if cwe:
        parts.append(f"CWE: {cwe}")
    parts.append(f"Severity (static): {sev}")
    parts.append(f"Location: {fpath}:{line}")
    if desc:
        parts.append(f"Description: {desc}")

    trace = finding.get("trace", [])
    if trace:
        parts.append("\nEvidence trace (source to sink):")
        for i, step in enumerate(trace, 1):
            sf = step.get("file", "?")
            sl = step.get("line", 0)
            note = step.get("note", "")
            code = step.get("code", "")
            entry = f"  {i}. {sf}:{sl}"
            if note:
                entry += f"  [{note}]"
            if code:
                entry += f"  {code}"
            parts.append(entry)

    code_snippet = finding.get("code", finding.get("sink_code", ""))
    if code_snippet:
        parts.append(f"\nVulnerable code:\n  {code_snippet}")

    interproc = finding.get("interprocedural", False)
    if interproc:
        parts.append("\nThis is a cross-function (interprocedural) data flow.")

    parts.append(
        "\nAnswer in EXACTLY this format:\n"
        "VERDICT: <EXPLOITABLE|NOT_EXPLOITABLE|UNCERTAIN>\n"
        "CONFIDENCE: <integer 0-100>\n"
        "WHY: <one sentence, no hedging>\n"
        "EXPLOIT: <one-sentence attack scenario>\n"
        "FIX: <one concrete code-level fix>"
    )
    return "\n".join(parts)


def _parse_opinion(text: str) -> tuple[str, float, str, str, str]:
    verdict, conf, why, exploit, fix = "UNCERTAIN", 0.5, "", "", ""
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
        m = re.match(r"EXPLOIT:\s*(.+)", line, re.I)
        if m:
            exploit = m.group(1).strip()
        m = re.match(r"FIX:\s*(.+)", line, re.I)
        if m:
            fix = m.group(1).strip()
    return verdict, conf, why, exploit, fix


def _run_member(member: CouncilMember, prompt: str) -> MemberOpinion | None:
    t0 = time.time()
    try:
        raw = member.evaluate(prompt)
        if not raw:
            return None
        verdict, conf, why, exploit, fix = _parse_opinion(raw)
        return MemberOpinion(
            member=member.name, backend=member.backend,
            verdict=verdict, confidence=conf,
            explanation=why, fix=fix,
            exploit_scenario=exploit,
            latency_ms=int((time.time() - t0) * 1000),
            raw=raw)
    except Exception:
        return None


def _aggregate(finding: dict, opinions: list[MemberOpinion]) -> CouncilVerdict:
    votes: dict[str, float] = {}
    for op in opinions:
        w = op.confidence
        votes[op.verdict] = votes.get(op.verdict, 0) + w

    winner = max(votes, key=votes.get)

    agreeing = [op for op in opinions if op.verdict == winner]
    dissenting = [op for op in opinions if op.verdict != winner]

    if agreeing:
        total_w = sum(op.confidence for op in agreeing)
        avg_conf = total_w / len(agreeing) if agreeing else 0.5
    else:
        avg_conf = 0.5

    if len(set(op.verdict for op in opinions)) == 1:
        avg_conf = min(1.0, avg_conf + 0.1)

    best = max(agreeing, key=lambda o: o.confidence) if agreeing else opinions[0]

    return CouncilVerdict(
        finding=finding,
        verdict=winner,
        confidence=round(avg_conf, 3),
        explanation=best.explanation,
        fix=best.fix,
        exploit_scenario=best.exploit_scenario,
        opinions=opinions,
        consensus=len(dissenting) == 0,
        dissent=[f"{op.member}: {op.verdict} ({op.confidence:.0%})" for op in dissenting],
        quorum=len(opinions),
    )


def _empty_verdict(finding: dict) -> CouncilVerdict:
    sev = finding.get("severity", "MEDIUM")
    conf = {"CRITICAL": 0.8, "HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.4}.get(sev, 0.5)
    return CouncilVerdict(
        finding=finding,
        verdict="UNCERTAIN",
        confidence=conf,
        explanation="No council members available -- static verdict only.",
        fix="",
        exploit_scenario="",
        quorum=0,
    )


def _discover_gguf(council: Council):
    import glob as globmod
    model_dir = os.path.join(_HERE, "models")
    if not os.path.isdir(model_dir):
        return
    for path in sorted(globmod.glob(os.path.join(model_dir, "*.gguf"))):
        council.add_gguf(path)


def _discover_ollama(council: Council):
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    try:
        req = urllib.request.Request(f"{host}/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        for m in data.get("models", []):
            name = m["name"]
            council.add_ollama(name)
    except Exception:
        pass


def _discover_remote(council: Council):
    endpoints = os.environ.get("ATTESTOR_COUNCIL_ENDPOINTS", "")
    if not endpoints:
        return
    for entry in endpoints.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split("|")
        url = parts[0].strip()
        name = parts[1].strip() if len(parts) > 1 else f"remote-{len(council.members)}"
        key = parts[2].strip() if len(parts) > 2 else None
        council.add_remote(url, name, api_key=key)


def render(verdicts: list[CouncilVerdict]) -> str:
    if not verdicts:
        return "  No findings to adjudicate."

    quorum = verdicts[0].quorum if verdicts else 0
    members_used = set()
    for v in verdicts:
        for op in v.opinions:
            members_used.add(op.member)

    lines = [
        f"\n  Model Council -- {len(members_used)} members, {len(verdicts)} finding(s)",
        "  " + "=" * 62,
    ]

    if members_used:
        lines.append(f"  Council: {', '.join(sorted(members_used))}")

    exploitable = sum(1 for v in verdicts if v.verdict == "EXPLOITABLE")
    dismissed = sum(1 for v in verdicts if v.verdict == "NOT_EXPLOITABLE")
    unanimous = sum(1 for v in verdicts if v.consensus)
    lines.append(
        f"  {exploitable} exploitable, {dismissed} dismissed, "
        f"{len(verdicts) - exploitable - dismissed} uncertain  "
        f"({unanimous}/{len(verdicts)} unanimous)")

    for v in verdicts:
        cat = v.finding.get("category", v.finding.get("sink_type", "?"))
        cwe = v.finding.get("cwe", "")
        fpath = v.finding.get("file", v.finding.get("sink_file", "?"))
        line = v.finding.get("line", v.finding.get("sink_line", 0))
        base = fpath.replace("\\", "/").split("/")[-1]

        tag = {"EXPLOITABLE": "EXPLOIT", "NOT_EXPLOITABLE": "dismiss",
               "UNCERTAIN": "review"}.get(v.verdict, "review")
        marker = "UNANIMOUS" if v.consensus else f"{v.quorum - len(v.dissent)}/{v.quorum}"

        lines.append(f"\n  [{tag}] {cat} ({cwe})  conf={v.confidence:.0%}  "
                     f"{base}:{line}  [{marker}]")

        if v.explanation:
            lines.append(f"    why: {v.explanation}")
        if v.exploit_scenario:
            lines.append(f"    exploit: {v.exploit_scenario}")
        if v.fix:
            lines.append(f"    fix: {v.fix}")
        if v.dissent:
            lines.append(f"    dissent: {'; '.join(v.dissent)}")

        for op in v.opinions:
            lines.append(f"      {op.member} ({op.backend}): "
                         f"{op.verdict} {op.confidence:.0%} [{op.latency_ms}ms]")

    return "\n".join(lines)


def to_dict(verdicts: list[CouncilVerdict]) -> list[dict]:
    return [
        {
            "category": v.finding.get("category", v.finding.get("sink_type", "")),
            "cwe": v.finding.get("cwe", ""),
            "file": v.finding.get("file", v.finding.get("sink_file", "")),
            "line": v.finding.get("line", v.finding.get("sink_line", 0)),
            "verdict": v.verdict,
            "confidence": v.confidence,
            "explanation": v.explanation,
            "fix": v.fix,
            "exploit_scenario": v.exploit_scenario,
            "consensus": v.consensus,
            "quorum": v.quorum,
            "dissent": v.dissent,
            "opinions": [
                {
                    "member": op.member, "backend": op.backend,
                    "verdict": op.verdict, "confidence": op.confidence,
                    "explanation": op.explanation, "fix": op.fix,
                    "latency_ms": op.latency_ms,
                }
                for op in v.opinions
            ],
        }
        for v in verdicts
    ]


if __name__ == "__main__":
    council = Council.discover()
    print(f"Council: {council}")
    for m in council.roster():
        print(f"  {m['name']} ({m['backend']}) -- {m['model']}")
