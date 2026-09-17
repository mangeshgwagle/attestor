#!/usr/bin/env python3
"""Attestor Agent Loop 4.3 -- the ReAct core.

The operator's prompt selects the mode. The model's knowledge -- trained on
offensive (theZoo, reverse shell cheatsheets, cybersec handbooks) and defensive
(CWE detection, taint analysis, hardening) data -- powers both sides.

Architecture (inspired by PentAGI + Xalgorix):

    Operator prompt
        |
    Agent Loop (ReAct: reason -> act -> observe -> repeat)
        |
    Tool Registry (Attestor modules as callable tools)
        |
    Verifier Agent (independent re-exploitation / confirmation)
        |
    Attestation (confirmed + proof, or inconclusive)

The agent loop is ~50 lines of core logic. Everything else is tool wiring.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

VERSION = "4.3"
MAX_ITERATIONS = 50
VERIFIER_MAX_ITERATIONS = 15

# ---------------------------------------------------------------------------
# Tool registry -- each Attestor module registers as a callable tool
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    func: Callable[..., str]


class ToolRegistry:
    """Holds all tools the agent can call."""

    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, name: str, description: str,
                 parameters: dict[str, Any], func: Callable[..., str]):
        self._tools[name] = Tool(name, description, parameters, func)

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in self._tools.values()
        ]

    def execute(self, name: str, arguments: dict[str, Any]) -> str:
        tool = self._tools.get(name)
        if not tool:
            return json.dumps({"error": f"Unknown tool: {name}"})
        try:
            result = tool.func(**arguments)
            if not isinstance(result, str):
                result = json.dumps(result, default=str)
            return result
        except Exception as exc:
            return json.dumps({"error": str(exc), "traceback": traceback.format_exc()})

    @property
    def names(self) -> list[str]:
        return list(self._tools.keys())


# ---------------------------------------------------------------------------
# Agent step -- one iteration of the ReAct loop
# ---------------------------------------------------------------------------

@dataclass
class AgentStep:
    iteration: int
    thought: str
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    observation: str | None = None
    is_final: bool = False
    final_answer: str | None = None


@dataclass
class AgentResult:
    steps: list[AgentStep] = field(default_factory=list)
    final_answer: str = ""
    total_iterations: int = 0
    tool_calls_made: int = 0
    elapsed_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Model interface -- talks to Ollama or any OpenAI-compatible endpoint
# ---------------------------------------------------------------------------

class AgentModel:
    """Wraps model_loader43 for the agent loop with tool-calling support."""

    def __init__(self, backend=None, system_prompt: str = ""):
        self._backend = backend
        self.system_prompt = system_prompt

    @classmethod
    def from_loader(cls, prefer: str | None = None,
                    system_prompt: str = "") -> "AgentModel":
        loader_path = Path(__file__).resolve().parent / "model_loader43.py"
        if loader_path.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "model_loader43", loader_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            backend = mod.get_model(prefer=prefer)
            return cls(backend=backend,
                       system_prompt=system_prompt or mod.SYSTEM_PROMPT)
        raise RuntimeError("model_loader43.py not found")

    def chat(self, messages: list[dict[str, str]], tools: list[dict] | None = None,
             **kwargs) -> dict[str, Any]:
        """Call the model and parse tool calls from the response.

        Since local models (Ollama/llama-cpp) may not support native tool
        calling, we use a structured prompt format that instructs the model
        to output tool calls as JSON blocks.
        """
        if tools:
            tool_instruction = self._build_tool_instruction(tools)
            augmented = list(messages)
            if augmented and augmented[0]["role"] == "system":
                augmented[0] = {
                    "role": "system",
                    "content": augmented[0]["content"] + "\n\n" + tool_instruction,
                }
            else:
                augmented.insert(0, {
                    "role": "system",
                    "content": self.system_prompt + "\n\n" + tool_instruction,
                })
        else:
            augmented = messages

        # Call Ollama API directly so our system prompt (with tool instructions)
        # actually reaches the model, instead of being replaced by the backend's
        # hardcoded SYSTEM_PROMPT.
        raw = self._call_ollama(augmented, **kwargs)
        return self._parse_response(raw)

    def _call_ollama(self, messages: list[dict[str, str]], **kwargs) -> str:
        """Direct Ollama /api/chat call that preserves our system prompt."""
        import urllib.request
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        model_id = ""
        if self._backend:
            model_id = getattr(self._backend, "model_id", "")
        if not model_id:
            model_id = "qwen2.5-coder:3b-instruct-q4_K_M"

        payload = {
            "model": model_id,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", 0.3),
                "top_p": 0.9,
                "num_predict": kwargs.get("max_tokens", 2048),
                "num_ctx": 4096,
            },
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{host}/api/chat", data=data,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read().decode())
        return result.get("message", {}).get("content", "")

    def _build_tool_instruction(self, tools: list[dict]) -> str:
        tool_descs = []
        for t in tools:
            f = t.get("function", t)
            params = f.get("parameters", {})
            required = params.get("required", [])
            tool_descs.append(f"- {f['name']}({', '.join(required)}): {f['description']}")
        return (
            "Tools:\n" + "\n".join(tool_descs) + "\n\n"
            "Use a tool:\n"
            '```tool_call\n{"tool": "<name>", "arguments": {<args>}}\n```\n\n'
            "Final answer:\n"
            '```final_answer\n<answer>\n```'
        )

    def _parse_response(self, raw: str) -> dict[str, Any]:
        result: dict[str, Any] = {"content": raw, "tool_calls": [], "is_final": False}

        if "```tool_call" in raw:
            blocks = raw.split("```tool_call")
            for block in blocks[1:]:
                end = block.find("```")
                if end == -1:
                    json_str = block.strip()
                else:
                    json_str = block[:end].strip()
                try:
                    call = json.loads(json_str)
                    result["tool_calls"].append({
                        "name": call.get("tool", call.get("name", "")),
                        "arguments": call.get("arguments", call.get("args", {})),
                    })
                except json.JSONDecodeError:
                    pass

        if "```final_answer" in raw:
            start = raw.find("```final_answer") + len("```final_answer")
            end = raw.find("```", start)
            if end == -1:
                result["final_answer"] = raw[start:].strip()
            else:
                result["final_answer"] = raw[start:end].strip()
            result["is_final"] = True

        if not result["tool_calls"] and not result["is_final"]:
            if not any(kw in raw.lower() for kw in ["```tool_call", "```final_answer"]):
                result["is_final"] = True
                result["final_answer"] = raw

        return result


# ---------------------------------------------------------------------------
# The agent loop -- the core ReAct cycle
# ---------------------------------------------------------------------------

class AttestorAgent:
    """ReAct agent that uses Attestor modules as tools."""

    def __init__(self, model: AgentModel, registry: ToolRegistry,
                 max_iterations: int = MAX_ITERATIONS,
                 verbose: bool = False):
        self.model = model
        self.registry = registry
        self.max_iterations = max_iterations
        self.verbose = verbose

    def run(self, task: str, context: str = "") -> AgentResult:
        """Execute the full agent loop for a given task."""
        start = time.time()
        result = AgentResult()
        messages: list[dict[str, str]] = []

        if context:
            messages.append({"role": "user", "content": f"Context:\n{context}\n\nTask: {task}"})
        else:
            messages.append({"role": "user", "content": task})

        tools_spec = self.registry.list_tools()

        for i in range(self.max_iterations):
            if self.verbose:
                print(f"\n--- Iteration {i + 1}/{self.max_iterations} ---")

            response = self.model.chat(messages, tools=tools_spec if tools_spec else None)

            step = AgentStep(
                iteration=i + 1,
                thought=response.get("content", ""),
            )

            if response.get("is_final"):
                step.is_final = True
                step.final_answer = response.get("final_answer", "")
                result.steps.append(step)
                result.final_answer = step.final_answer
                break

            if response.get("tool_calls"):
                call = response["tool_calls"][0]
                step.tool_name = call["name"]
                step.tool_args = call["arguments"]

                if self.verbose:
                    print(f"  Tool: {step.tool_name}({json.dumps(step.tool_args)[:200]})")

                observation = self.registry.execute(step.tool_name, step.tool_args)
                step.observation = observation
                result.tool_calls_made += 1

                if self.verbose:
                    print(f"  Result: {observation[:300]}...")

                messages.append({"role": "assistant", "content": response["content"]})
                messages.append({"role": "user",
                                 "content": f"Tool '{step.tool_name}' returned:\n{observation}"})
            else:
                step.is_final = True
                step.final_answer = response.get("content", "")
                result.steps.append(step)
                result.final_answer = step.final_answer
                break

            result.steps.append(step)

            if i >= self.max_iterations - 3:
                messages.append({
                    "role": "user",
                    "content": (
                        f"You have {self.max_iterations - i - 1} iterations remaining. "
                        "Wrap up your analysis and provide a final answer."
                    ),
                })

        result.total_iterations = len(result.steps)
        result.elapsed_seconds = time.time() - start
        return result


# ---------------------------------------------------------------------------
# Verifier agent -- independent re-exploitation (Xalgorix pattern)
# ---------------------------------------------------------------------------

class VerifierAgent:
    """Independently verifies findings from the primary agent.

    Takes each finding and attempts to reproduce it using a fresh agent
    with a different system prompt. If the verifier confirms, the finding
    is ATTESTED. If not, it's marked INCONCLUSIVE.
    """

    VERIFIER_PROMPT = (
        "You are the Attestor Verifier -- an independent security verification agent. "
        "You receive vulnerability findings from a primary analysis agent. Your job is "
        "to independently verify each finding by:\n"
        "1. Understanding the claimed vulnerability\n"
        "2. Attempting to reproduce it using the available tools\n"
        "3. Determining if the finding is CONFIRMED (exploitable) or INCONCLUSIVE\n\n"
        "You must be skeptical. Do not accept claims at face value. Prove it yourself. "
        "Your verification is the attestation -- if you can't reproduce it, it's not confirmed."
    )

    def __init__(self, model: AgentModel, registry: ToolRegistry,
                 verbose: bool = False):
        self.verbose = verbose
        self.model = AgentModel(
            backend=model._backend,
            system_prompt=self.VERIFIER_PROMPT,
        )
        self.agent = AttestorAgent(
            self.model, registry,
            max_iterations=VERIFIER_MAX_ITERATIONS,
            verbose=verbose,
        )

    def verify(self, finding: dict[str, Any], source_code: str = "") -> dict[str, Any]:
        """Verify a single finding. Returns attestation result."""
        task = (
            f"Verify this vulnerability finding independently:\n\n"
            f"Finding: {json.dumps(finding, indent=2)}\n\n"
        )
        if source_code:
            task += f"Source code:\n```\n{source_code}\n```\n\n"
        task += (
            "Attempt to confirm this vulnerability using the available tools. "
            "Respond with your verdict: CONFIRMED (with proof) or INCONCLUSIVE (with reason)."
        )

        result = self.agent.run(task)

        verdict = "INCONCLUSIVE"
        answer = result.final_answer.upper()
        if "CONFIRMED" in answer and "INCONCLUSIVE" not in answer:
            verdict = "CONFIRMED"

        return {
            "original_finding": finding,
            "verdict": verdict,
            "verifier_analysis": result.final_answer,
            "verifier_steps": len(result.steps),
            "verifier_tool_calls": result.tool_calls_made,
        }

    def verify_all(self, findings: list[dict[str, Any]],
                   source_code: str = "") -> list[dict[str, Any]]:
        """Verify a batch of findings. Returns attestation results."""
        return [self.verify(f, source_code) for f in findings]


# ---------------------------------------------------------------------------
# Built-in tools -- wire Attestor modules into the registry
# ---------------------------------------------------------------------------

def build_default_registry() -> ToolRegistry:
    """Register all available Attestor modules as agent tools."""
    registry = ToolRegistry()
    detector_dir = Path(__file__).resolve().parent

    # -- detect: static vulnerability scanner --
    def tool_detect(file_path: str, language: str = "auto") -> str:
        try:
            sys.path.insert(0, str(detector_dir))
            import detect
            findings = detect.scan_file(file_path)
            return json.dumps([
                {"rule": f.rule, "line": f.line, "severity": f.severity,
                 "message": f.message, "cwe": getattr(f, "cwe", "")}
                for f in findings
            ], indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    registry.register("detect", "Scan a file for security vulnerabilities using static analysis. "
                       "Returns findings with CWE IDs, severity, and line numbers.",
                       {"type": "object", "properties": {
                           "file_path": {"type": "string", "description": "Path to the file to scan"},
                           "language": {"type": "string", "description": "Programming language (auto-detected if omitted)"},
                       }, "required": ["file_path"]}, tool_detect)

    # -- exploit_detect: find offensive patterns (shells, backdoors, C2) --
    def tool_exploit_detect(file_path: str) -> str:
        try:
            sys.path.insert(0, str(detector_dir))
            import exploit_detector
            findings = list(exploit_detector.scan_file(file_path))
            return json.dumps([
                {"rule_id": f.rule_id, "category": f.category, "line": f.line,
                 "severity": f.severity, "description": f.description,
                 "mitre_id": f.mitre_id}
                for f in findings
            ], indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    registry.register("exploit_detect",
                       "Detect offensive patterns in code: reverse shells, webshells, "
                       "backdoors, C2 beacons, keyloggers, data exfiltration, crypto miners.",
                       {"type": "object", "properties": {
                           "file_path": {"type": "string", "description": "Path to scan for exploits"},
                       }, "required": ["file_path"]}, tool_exploit_detect)

    # -- payload_decode: decode obfuscated payloads --
    def tool_payload_decode(file_path: str) -> str:
        try:
            sys.path.insert(0, str(detector_dir))
            import payload_decoder
            results = payload_decoder.scan_file(file_path)
            return json.dumps([
                {"line": r.line, "encoding": r.encoding, "decoded": r.decoded[:500],
                 "severity": r.severity, "is_suspicious": r.is_suspicious}
                for r in results
            ], indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    registry.register("payload_decode",
                       "Decode obfuscated payloads in source code. Supports base64, hex, "
                       "ROT13, XOR, URL encoding, PowerShell encoded commands, gzip/zlib.",
                       {"type": "object", "properties": {
                           "file_path": {"type": "string", "description": "Path to scan for encoded payloads"},
                       }, "required": ["file_path"]}, tool_payload_decode)

    # -- poc_generate: generate proof-of-concept exploit --
    def tool_poc_generate(cwe: int, rule: str, file_path: str,
                          line: int, language: str = "python",
                          snippet: str = "") -> str:
        try:
            sys.path.insert(0, str(detector_dir))
            import poc_gen42
            finding = poc_gen42.PocFinding(
                cwe=cwe, rule=rule, file_path=file_path,
                line=line, language=language, snippet=snippet)
            poc = poc_gen42.generate_poc(finding)
            if poc:
                return json.dumps({
                    "code": poc.code, "verification": poc.verification,
                    "vectors": poc.vectors,
                })
            return json.dumps({"error": "No PoC generator for this CWE"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    registry.register("poc_generate",
                       "Generate a proof-of-concept exploit for a vulnerability finding. "
                       "Produces runnable code that proves the vulnerability is exploitable.",
                       {"type": "object", "properties": {
                           "cwe": {"type": "integer", "description": "CWE number (e.g. 89 for SQLi)"},
                           "rule": {"type": "string", "description": "Rule ID from the scanner"},
                           "file_path": {"type": "string", "description": "Vulnerable file path"},
                           "line": {"type": "integer", "description": "Vulnerable line number"},
                           "language": {"type": "string", "description": "Target language"},
                           "snippet": {"type": "string", "description": "Code snippet around the vuln"},
                       }, "required": ["cwe", "rule", "file_path", "line"]}, tool_poc_generate)

    # -- read_file: read source code for analysis --
    def tool_read_file(file_path: str, max_lines: int = 200) -> str:
        try:
            p = Path(file_path)
            if not p.exists():
                return json.dumps({"error": f"File not found: {file_path}"})
            if p.stat().st_size > 1_000_000:
                return json.dumps({"error": "File too large (>1MB)"})
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) > max_lines:
                lines = lines[:max_lines]
            numbered = [f"{i+1}: {line}" for i, line in enumerate(lines)]
            return "\n".join(numbered)
        except Exception as e:
            return json.dumps({"error": str(e)})

    registry.register("read_file", "Read source code from a file for analysis.",
                       {"type": "object", "properties": {
                           "file_path": {"type": "string", "description": "Path to the file"},
                           "max_lines": {"type": "integer", "description": "Max lines to read (default 200)"},
                       }, "required": ["file_path"]}, tool_read_file)

    # -- list_files: list files in a directory --
    def tool_list_files(directory: str, pattern: str = "*") -> str:
        try:
            p = Path(directory)
            if not p.is_dir():
                return json.dumps({"error": f"Not a directory: {directory}"})
            files = sorted(p.glob(pattern))[:100]
            return json.dumps([str(f.relative_to(p)) for f in files])
        except Exception as e:
            return json.dumps({"error": str(e)})

    registry.register("list_files", "List files in a directory.",
                       {"type": "object", "properties": {
                           "directory": {"type": "string", "description": "Directory path"},
                           "pattern": {"type": "string", "description": "Glob pattern (default: *)"},
                       }, "required": ["directory"]}, tool_list_files)

    # -- ask_model: direct question to the security model (no tool) --
    def tool_ask_model(question: str) -> str:
        return f"[This question should be answered by the agent directly: {question}]"

    registry.register("ask_model",
                       "Ask the security model a direct question about vulnerabilities, "
                       "exploits, malware, MITRE ATT&CK, CWEs, or security concepts.",
                       {"type": "object", "properties": {
                           "question": {"type": "string", "description": "Security question"},
                       }, "required": ["question"]}, tool_ask_model)

    # -- finish: signal task completion with verdict --
    def tool_finish(verdict: str, summary: str, findings: str = "[]",
                    confidence: str = "medium") -> str:
        return json.dumps({
            "status": "complete",
            "verdict": verdict,
            "summary": summary,
            "findings": findings,
            "confidence": confidence,
        })

    registry.register("finish",
                       "Signal that the analysis is complete. Provide a verdict "
                       "(secure/vulnerable/inconclusive), summary, and any findings.",
                       {"type": "object", "properties": {
                           "verdict": {"type": "string", "enum": ["secure", "vulnerable", "inconclusive"],
                                       "description": "Overall security verdict"},
                           "summary": {"type": "string", "description": "Summary of findings"},
                           "findings": {"type": "string", "description": "JSON array of findings"},
                           "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                       }, "required": ["verdict", "summary"]}, tool_finish)

    return registry


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------

def run_agent(task: str, context: str = "", verbose: bool = False,
              prefer_model: str | None = None,
              verify: bool = True) -> dict[str, Any]:
    """Run the full Attestor agent pipeline: analyze, then verify."""
    model = AgentModel.from_loader(prefer=prefer_model)
    registry = build_default_registry()

    # Phase 1: Primary analysis
    agent = AttestorAgent(model, registry, verbose=verbose)
    primary = agent.run(task, context=context)

    output = {
        "task": task,
        "primary_analysis": primary.final_answer,
        "steps": len(primary.steps),
        "tool_calls": primary.tool_calls_made,
        "elapsed": primary.elapsed_seconds,
        "attestation": [],
    }

    # Phase 2: Independent verification (if enabled and findings exist)
    if verify and primary.final_answer:
        try:
            findings = _extract_findings(primary)
            if findings:
                verifier = VerifierAgent(model, registry, verbose=verbose)
                attestations = verifier.verify_all(findings, source_code=context)
                output["attestation"] = attestations
                confirmed = sum(1 for a in attestations if a["verdict"] == "CONFIRMED")
                output["confirmed_count"] = confirmed
                output["total_findings"] = len(findings)
        except Exception:
            output["attestation_error"] = traceback.format_exc()

    return output


def _extract_findings(result: AgentResult) -> list[dict[str, Any]]:
    """Extract structured findings from agent output."""
    findings = []
    for step in result.steps:
        if step.observation:
            try:
                data = json.loads(step.observation)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and ("rule" in item or "rule_id" in item):
                            findings.append(item)
            except (json.JSONDecodeError, TypeError):
                pass
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Attestor Agent Loop -- autonomous security analysis with verification")
    parser.add_argument("task", help="Security task or question")
    parser.add_argument("--context", "-c", default="",
                        help="File path to use as context (source code to analyze)")
    parser.add_argument("--model", "-m", default=None,
                        help="Preferred model name")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip independent verification pass")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output raw JSON")
    args = parser.parse_args()

    context = ""
    if args.context:
        p = Path(args.context)
        if p.is_file():
            context = p.read_text(encoding="utf-8", errors="replace")
        elif p.is_dir():
            context = f"[Directory: {args.context}]"

    result = run_agent(
        task=args.task,
        context=context,
        verbose=args.verbose,
        prefer_model=args.model,
        verify=not args.no_verify,
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"\n{'='*60}")
        print(f"ATTESTOR AGENT REPORT")
        print(f"{'='*60}")
        print(f"Task: {result['task']}")
        print(f"Steps: {result['steps']} | Tool calls: {result['tool_calls']} | "
              f"Time: {result['elapsed']:.1f}s")
        print(f"\n--- Analysis ---\n{result['primary_analysis']}")

        if result.get("attestation"):
            print(f"\n--- Attestation ({result.get('confirmed_count', 0)}/"
                  f"{result.get('total_findings', 0)} confirmed) ---")
            for att in result["attestation"]:
                v = att["verdict"]
                marker = "[+]" if v == "CONFIRMED" else "[?]"
                finding = att["original_finding"]
                label = finding.get("rule", finding.get("rule_id", "unknown"))
                print(f"  {marker} {label}: {v}")
                if att.get("verifier_analysis"):
                    preview = att["verifier_analysis"][:200]
                    print(f"      {preview}")

        print(f"\n{'='*60}")


if __name__ == "__main__":
    main()
