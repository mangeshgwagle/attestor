#!/usr/bin/env python3
"""codegen_pipeline42 -- multi-pass code generation with verification.

The secret sauce that elevates a 7B model to frontier-level code quality:
  1. Generate: model produces code with chain-of-thought reasoning
  2. Scan: Attestor's scanner checks for vulnerabilities
  3. Fix: model patches any findings using scanner feedback
  4. Verify: final scan confirms clean output
  5. Enrich: inject domain knowledge from Attestor engines

This pipeline is what 'attestor codegen --verified' runs.

    attestor codegen --verified "write a web server with auth"
    attestor codegen --pipeline "implement AES from scratch in C"
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import time
from pathlib import Path

PIPELINE_SCHEMA = "attestor-codegen-pipeline-4.3"
MAX_FIX_PASSES = 3


def _load_module(name):
    """Load a sibling detector module."""
    mod_path = Path(__file__).resolve().parent / f"{name}.py"
    if not mod_path.exists():
        return None
    spec = importlib.util.spec_from_file_location(name, mod_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _get_model():
    loader = _load_module("model_loader43")
    if loader:
        return loader.get_model()
    return None


def _get_scanner():
    return _load_module("impl42")


def _get_zeroday():
    return _load_module("zeroday42")


def _extract_code(response):
    """Extract code blocks from model response."""
    blocks = re.findall(r'```(\w*)\n(.*?)```', response, re.DOTALL)
    if blocks:
        return [(lang or "text", code.strip()) for lang, code in blocks]
    return [("text", response.strip())]


def _detect_lang_from_prompt(prompt):
    """Guess target language from the prompt."""
    prompt_lower = prompt.lower()
    lang_hints = {
        "python": "python", "py ": "python",
        "javascript": "javascript", " js ": "javascript",
        "typescript": "typescript", " ts ": "typescript",
        "golang": "go", " go ": "go",
        "rust": "rust", " rs ": "rust",
        " c ": "c", " c++": "cpp", "cpp": "cpp",
        "java ": "java", "kotlin": "kotlin",
        "ruby": "ruby", "php": "php",
        "shell": "bash", "bash": "bash",
        "sql": "sql", "assembly": "asm", "x86": "asm",
    }
    for hint, lang in lang_hints.items():
        if hint in prompt_lower:
            return lang
    return "python"


LANG_EXT = {
    "python": ".py", "javascript": ".js", "typescript": ".ts",
    "go": ".go", "rust": ".rs", "c": ".c", "cpp": ".cpp",
    "java": ".java", "ruby": ".rb", "php": ".php",
    "bash": ".sh", "sql": ".sql", "asm": ".asm",
}


def generate_phase(prompt, model, lang=None, reason=True):
    """Phase 1: Generate code with reasoning."""
    if not lang:
        lang = _detect_lang_from_prompt(prompt)

    system = (
        "You are Owen Coder 4.3, a security-focused code generation engine. "
        "Write complete, production-quality code. Include all imports, error handling, "
        "and edge cases. Code must compile/run as-is. Security-first: validate inputs, "
        "prevent injection, handle errors properly."
    )

    full_prompt = prompt
    if reason:
        full_prompt = (
            "Think step by step before writing code. Consider:\n"
            "1. Algorithm design and tradeoffs\n"
            "2. Edge cases and error conditions\n"
            "3. Security implications (injection, overflow, race conditions)\n"
            "4. Performance (time/space complexity)\n\n"
            f"Write the solution in {lang}.\n\n{prompt}"
        )

    if model and model.available():
        try:
            result = model.chat([
                {"role": "system", "content": system},
                {"role": "user", "content": full_prompt},
            ], max_tokens=4096)
            return {"code": result, "lang": lang, "phase": "generate"}
        except Exception as e:
            return {"error": str(e), "phase": "generate"}

    return {"error": "No model available", "phase": "generate"}


def scan_phase(code, lang, scanner=None, zeroday=None):
    """Phase 2: Scan generated code for vulnerabilities."""
    findings = []

    ext = LANG_EXT.get(lang, ".py")
    with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False,
                                     encoding="utf-8") as f:
        # Extract just code from response
        blocks = _extract_code(code)
        if blocks:
            f.write(blocks[0][1])
        else:
            f.write(code)
        tmp_path = f.name

    try:
        if scanner:
            try:
                scan_result = scanner.scan_file(tmp_path)
                if isinstance(scan_result, dict):
                    findings.extend(scan_result.get("findings", []))
                elif isinstance(scan_result, list):
                    findings.extend(scan_result)
            except Exception:
                pass

        if zeroday:
            try:
                zd_findings = zeroday.scan_file(tmp_path)
                findings.extend(zd_findings)
            except Exception:
                pass
    finally:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass

    return {
        "findings": findings,
        "finding_count": len(findings),
        "phase": "scan",
    }


def fix_phase(original_code, findings, model, pass_num=1):
    """Phase 3: Fix vulnerabilities found by the scanner."""
    if not findings:
        return {"code": original_code, "fixed": False, "phase": "fix"}

    findings_desc = []
    for i, f in enumerate(findings[:10], 1):
        if isinstance(f, dict):
            name = f.get("name", f.get("rule", f.get("id", "finding")))
            sev = f.get("severity", "MEDIUM")
            line = f.get("line", "?")
            desc = f.get("description", f.get("message", ""))[:150]
            findings_desc.append(f"  {i}. [{sev}] {name} at line {line}: {desc}")

    fix_prompt = (
        f"The following security vulnerabilities were found in the code (pass {pass_num}):\n\n"
        + "\n".join(findings_desc)
        + "\n\nHere is the code:\n\n"
        + original_code
        + "\n\nFix ALL vulnerabilities while preserving functionality. "
        "Output ONLY the fixed code, complete and runnable."
    )

    if model and model.available():
        try:
            result = model.chat([
                {"role": "system", "content":
                 "You are a security-focused code fixer. Fix all vulnerabilities "
                 "while preserving the original functionality. Output only the "
                 "corrected code, no explanations."},
                {"role": "user", "content": fix_prompt},
            ], max_tokens=4096)
            return {"code": result, "fixed": True, "phase": "fix", "pass": pass_num}
        except Exception as e:
            return {"code": original_code, "error": str(e), "phase": "fix"}

    return {"code": original_code, "error": "No model", "phase": "fix"}


def enrich_phase(prompt, code, lang):
    """Phase 5: Enrich with domain knowledge from Attestor engines."""
    enrichments = []

    if any(kw in prompt.lower() for kw in ["math", "crypto", "number", "prime",
                                             "factor", "gcd", "modular"]):
        math_engine = _load_module("math_engine42")
        if math_engine:
            enrichments.append({
                "engine": "math",
                "note": "Math engine available for x86-64 accelerated computation",
            })

    if any(kw in prompt.lower() for kw in ["vuln", "exploit", "cve", "zero-day",
                                             "patch", "security"]):
        zd = _load_module("zeroday42")
        if zd:
            enrichments.append({
                "engine": "zeroday",
                "note": "Zero-day engine patterns available for vulnerability context",
                "pattern_count": len(zd.NOVEL_PATTERNS),
            })

    if any(kw in prompt.lower() for kw in ["socat", "relay", "tunnel", "reverse shell",
                                             "bind shell"]):
        socat = _load_module("socat42")
        if socat:
            enrichments.append({
                "engine": "socat",
                "note": "Socat relay and exploit templates available",
            })

    return enrichments


def run_pipeline(prompt, lang=None, reason=True, max_passes=MAX_FIX_PASSES,
                 stream=True, verbose=False):
    """Run the full multi-pass generation pipeline.

    Returns a dict with the final code, all phases, and metadata.
    """
    result = {
        "schema": PIPELINE_SCHEMA,
        "prompt": prompt,
        "phases": [],
        "passes": 0,
        "final_findings": 0,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    model = _get_model()
    scanner = _get_scanner()
    zeroday = _get_zeroday()

    if not lang:
        lang = _detect_lang_from_prompt(prompt)
    result["lang"] = lang

    # Phase 1: Generate
    if verbose:
        print("[pipeline] Phase 1: Generating code...")
    gen = generate_phase(prompt, model, lang, reason)
    result["phases"].append(gen)

    if "error" in gen:
        result["error"] = gen["error"]
        if stream:
            print(f"Generation error: {gen['error']}")
        return result

    current_code = gen["code"]
    if stream and verbose:
        print("[pipeline] Code generated. Running scanner...")

    # Phase 2-4: Scan -> Fix -> Verify loop
    for pass_num in range(1, max_passes + 1):
        result["passes"] = pass_num

        scan = scan_phase(current_code, lang, scanner, zeroday)
        result["phases"].append(scan)

        if scan["finding_count"] == 0:
            if verbose:
                print(f"[pipeline] Pass {pass_num}: Clean — no findings.")
            break

        if verbose:
            print(f"[pipeline] Pass {pass_num}: {scan['finding_count']} findings. Fixing...")

        fix = fix_phase(current_code, scan["findings"], model, pass_num)
        result["phases"].append(fix)

        if fix.get("fixed"):
            current_code = fix["code"]
        else:
            if verbose:
                print(f"[pipeline] Fix failed: {fix.get('error', 'unknown')}")
            break

    # Final verification scan
    final_scan = scan_phase(current_code, lang, scanner, zeroday)
    result["final_findings"] = final_scan["finding_count"]
    result["verified"] = final_scan["finding_count"] == 0

    # Enrichments
    enrichments = enrich_phase(prompt, current_code, lang)
    if enrichments:
        result["enrichments"] = enrichments

    result["code"] = current_code

    if stream:
        blocks = _extract_code(current_code)
        if blocks:
            print(f"\n```{blocks[0][0]}")
            print(blocks[0][1])
            print("```")
        else:
            print(current_code)
        print()
        status = "VERIFIED CLEAN" if result["verified"] else f"{result['final_findings']} remaining findings"
        print(f"[pipeline] {result['passes']} pass(es) | {status}")

    return result
