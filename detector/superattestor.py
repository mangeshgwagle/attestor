#!/usr/bin/env python3
"""
superattestor.py -- every one of Attestor's powers behind ONE door.

Give it anything -- a file, a directory, a GitHub link, or plain English -- and it
decides which power fits and runs it:

  a directory / repo folder     -> AUDIT: both engines over the whole tree, an
                                   aggregated report (summary, top files, findings)
  a single file / GitHub URL    -> COMPREHEND: the multi-pass deep read (both
                                   engines: regex + AST), the structural picture,
                                   the safe fixes
  --evolve GitHub/query         -> EVOLVE: harvest GitHub code, reread/fix/re-scan
                                   in cycles, then write improved copies
  --ruleforge GitHub/query      -> RULE FORGE: mine code for candidate detector
                                   rules, prove them, emit rule/test snippets
  --patchforge file             -> PATCH FORGE: ask API models for patches, then
                                   force them through Attestor/crucible/test gates
  --patchguard target           -> PATCH GUARD: isolate, diff, scan, compile,
                                   test when authorized, back up, apply/rollback
  --workspace dir               -> WORKSPACE ENGINE: cached parallel analysis
                                   across modern source/config languages
  --attestor414 dir                 -> ATTESTOR 4.1.4 CURRENT MAXIMUM: sealed analysis
                                   variants, bounded evidence, and verified repair
  --attestor413/--attestor41 dir        -> ATTESTOR 4.1.3 MAXIMUM: immutable semantic/correctness,
                                   source-bound findings, supply-chain/secret lifecycle,
                                   proof-gated repair, and Truth Guard 3
  --computer-scan              -> COMPUTER SCAN: permission-gated, bounded,
                                   read-only project discovery without a supplied path
  --cjp-control request.json   -> COCKROACH LOCAL CONTROL: exact local files,
                                   read-only database understanding, preview,
                                   and separately confirmed transactional edits
  --escape-lab                -> PRIVATE ESCAPE LAB: a bounded, data-only
                                   policy-graph simulation; never a real escape
  --blind-escape-arena        -> BLIND ESCAPE ARENA: autonomous bounded
                                   opaque-policy exploration with replay proof
  --research question --online -> DEEP RESEARCH: bounded public-web search for
                                   non-coding questions with citations and conflicts
  --attestor40 dir                  -> ATTESTOR 4.0 COMPATIBILITY: evidence-backed engineering plans,
                                   defensive Security Fabric, bounded repairs,
                                   and Truth Guard 2.1 evidence
  --attestor3 dir                   -> ATTESTOR 3.0 COMPATIBILITY MAXIMUM: whole-program semantics,
                                   security, supply chain, attack paths, memory,
                                   and verified complete improved results
  --attestor35 dir                  -> ATTESTOR 3.5 MAXIMUM: adds bounded symbolic paths,
                                   polyglot IR, Git impact, exact dependency
                                   graphs, calibration, and Truth Guard 2
  --improve file/dir            -> VERIFIED IMPROVEMENT: find supported errors,
                                   prove the candidate, return full safer source
  --semantic dir                -> SEMANTIC ENGINE: import/call/CFG/data-flow and
                                   interprocedural source-to-sink evidence
  --supply-chain dir            -> SUPPLY-CHAIN CENTER: inventory, risk, SBOM,
                                   VEX, and provenance evidence without installs
  --repository-memory dir       -> PRIVATE MEMORY: source-free hashes and
                                   architecture summaries
  --quality-gate dir            -> QUALITY GATE: enforce grade/severity/test policy
  --cybermayhem dir             -> CYBERSECURITY MAYHEM: CWE/OWASP, attack surface,
                                   secrets, supply chain, SBOM, prioritized fixes
  --mayhem dir                  -> CODING MAYHEM: every deterministic engineering
                                   gate fused into one maximum-strength report
  --sieve request/file          -> SIEVE: write/load code, review, improve,
                                   review again, repeat, then print code
  --codemax request/file/dir    -> CODE MAX: grade, API map, call graph,
                                   safe-refine, test skeleton, or Sieve prompt
  --codepower request/file/dir  -> CODE POWER: architecture, tests, types,
                                   performance, docs, contracts, patch ranking
  --securitymax dir/file        -> SECURITY MAX: defensive cyber, SARIF, OWASP,
                                   threat model, safe repro and patch guidance
  --attestor2 request/file/dir      -> ATTESTOR 2 MAX: Code Power + Security Max together
  --rarebugs dir/file           -> RARE ERROR ORACLE: Python traps that survive
                                   ordinary review
  --reproduce file              -> BUG REPRODUCER: emit a tiny runnable file/test
                                   proving a finding exists
  --projectbrain dir            -> PROJECT BRAIN: imports, call graph, routes,
                                   env/config, DB queries, dead code, flows
  --cyber dir/file              -> CYBER SENTINEL: secrets, auth/session,
                                   taint flows, crypto, web/API, deps, config
  --polyglot dir/file           -> POLYGLOT TINY BUGS: C, C++, Haskell, and
                                   Assembly microscope for rare low-level bugs
  --gauntlet file               -> MUTATION GAUNTLET: inject subtle bugs and
                                   see what Attestor/test gates catch
  --arena                       -> CODE ARENA: rule count, recall, false
                                   positives, forge/evolve/mutation dashboard
  --darwin search QUERY         -> DARWIN: bundled security payload search,
                                   category browser, export, and local web UI
  a live website URL            -> WEBSCAN: fetch its public front-end, explain how
                                   the page is built, find the JavaScript bugs, and
                                   (with a brain) hand back corrected code
  "make an api for Book ..."    -> SCAFFOLD: the deterministic generator
                                   (clean-by-construction service, tests included)
  "review <file>"               -> the same deep read
  anything novel, brain awake   -> FORGE: the multiplication -- the LLM writes,
                                   Attestor's two engines verify, the leftovers go
                                   back to the model to repair, loop until clean
  anything novel, no brain      -> the curated snippet library if it matches,
                                   else an honest refusal (never a faked answer)

The brain is the sibling chain -- Groq (Qwen/Llama), OpenRouter, Mistral,
Gemini, OpenAI, and local Ollama when configured. Set any of GROQ_API_KEY /
OPENROUTER_API_KEY / MISTRAL_API_KEY / GEMINI_API_KEY / OPENAI_API_KEY, or
OLLAMA_MODEL.

Honesty, as always: "super-intelligent" is the marketing name. What is real is
one dispatcher over a deterministic analysis/generation toolkit plus (optionally)
a real LLM, each half covering the other's weakness. No key -> everything offline
still works; nothing is ever faked.

    python3 superattestor.py detect.py                       # deep-read a file
    python3 superattestor.py "make an api for Book with fields title, year (int)" --out ./svc
    python3 superattestor.py "write a red-black tree" --rounds 4 --out rbt.py
    python3 superattestor.py https://github.com/o/r/blob/main/app.py
"""
from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import os
import signal
import stat
import sys
import threading
from dataclasses import asdict
from pathlib import Path

# Root launchers deliberately use Python isolated mode so the working
# directory, user site, and PYTHONPATH cannot shadow Attestor's modules.  Isolated
# script execution also removes the script directory from sys.path, so add
# back only this resolved, trusted detector directory before local imports.
_TRUSTED_MODULE_DIR = Path(__file__).resolve().parent
if str(_TRUSTED_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_TRUSTED_MODULE_DIR))

import brain
import blind_escape_arena414
import codepower
import codemax
import comprehend
import computer_scan41
import cjp_control414
import codearena
import cyber
import darwin
import evolve
import escape_lab414
import fixmemory
import forge
import grade
import harvest
import massgen
import mayhem
import mutation_gauntlet
import nativegrade
import nl
import attestor
import attestor2
import attestor3
import attestor35
import attestor40
import attestor41
import patchforge
import patchguard
import personalities as P
import polyglot
import projectbrain
import rarebugs
import refine
import response41
import response_engine
import repository_memory
import research_engine41
import reproducer
import ruleforge
import scanengine
import secmax
import semantic_engine
import security_posture
import sieve
import supply_chain_center
import truth_guard
import truth_guard41
import variant414
import webscan
import qualitygate

# Use every configured provider by default; Attestor's verification is the multiplier.
EXCLUDED = ()
HERE = os.path.dirname(os.path.abspath(__file__))
_MACHINE_OUTPUT_FORMATS = frozenset({
    "json", "sarif", "sbom", "cyclonedx", "spdx", "spdx-2.3", "vex",
})
_ESCAPE_LAB_REQUESTS = frozenset({
    "escape lab", "sandbox escape lab", "sandbox escape",
})
_BLIND_ESCAPE_ACTION = "blindescapearena414"


def _attestor414_module():
    """Load the current orchestrator only when its mode is selected."""
    return importlib.import_module("attestor414")


def _output_notice(text: str, message: str, output_format: str) -> str:
    """Keep machine-readable stdout parseable; send operational notes to stderr."""
    if output_format in _MACHINE_OUTPUT_FORMATS:
        print(message, file=sys.stderr)
        return text
    return text + "\n" + message


def _attestor414_failure(error: BaseException, output_format: str) -> str:
    """Keep JSON callers parseable when the current engine fails closed."""
    error_type = type(error).__name__[:120]
    if output_format == "json":
        return json.dumps({
            "schema": "attestor-dispatch-failure/4.1.4",
            "version": "4.1.4",
            "status": "failed",
            "result_available": False,
            "findings": [],
            "summary": {"findings": 0, "component_errors": 1},
            "coverage": {
                "complete": False,
                "absence_proven": False,
                "gaps": [
                    "analysis failed closed before a verified result was "
                    "available"
                ],
            },
            "error": {
                "code": "ATTESTOR414-FAILED-CLOSED",
                "type": error_type,
                "details_disclosed": False,
                "traceback_disclosed": False,
            },
        }, indent=2, sort_keys=True, ensure_ascii=False)
    return "Attestor 4.1.4 failed safely: %s" % error_type


def _blind_escape_checkpoint_path() -> Path:
    """Return the controller-owned checkpoint path without exposing it to the arena."""
    root = Path.home() / ".attestor"
    if not root.exists():
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise blind_escape_arena414.BlindEscapeArenaError(
            "controller state directory is unavailable") from exc
    reparse = bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    junction = getattr(root, "is_junction", None)
    if (root.is_symlink() or reparse or (callable(junction) and junction())
            or not root.is_dir()):
        raise blind_escape_arena414.BlindEscapeArenaError(
            "controller state directory must be a regular private directory")
    try:
        root.chmod(0o700)
    except OSError:
        pass
    checkpoint = root / "blind-escape-arena-4.1.4.json"
    if checkpoint.exists():
        metadata = checkpoint.lstat()
        reparse = bool(
            getattr(metadata, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        junction = getattr(checkpoint, "is_junction", None)
        if (checkpoint.is_symlink() or reparse
                or (callable(junction) and junction())
                or not checkpoint.is_file()):
            raise blind_escape_arena414.BlindEscapeArenaError(
                "controller checkpoint must be a regular non-link file")
    return checkpoint


def _blind_escape_validate_output_path(out, checkpoint: Path) -> None:
    """Keep the controller report output separate from its private checkpoint."""
    if not out:
        return
    try:
        output_path = Path(out).expanduser()
        resolved_output = output_path.resolve(strict=False)
        resolved_checkpoint = checkpoint.expanduser().resolve(strict=False)
        if resolved_output == resolved_checkpoint:
            raise blind_escape_arena414.BlindEscapeArenaError(
                "report output must not overwrite the controller checkpoint")
        if output_path.exists() and checkpoint.exists() and os.path.samefile(
                output_path, checkpoint):
            raise blind_escape_arena414.BlindEscapeArenaError(
                "report output must not alias the controller checkpoint")
    except blind_escape_arena414.BlindEscapeArenaError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise blind_escape_arena414.BlindEscapeArenaError(
            "report output path could not be validated safely") from exc


def _blind_escape_dispatch(status: str, output_format: str,
                           error: BaseException | None = None) -> str:
    """Render a machine-safe non-result without claiming a verified escape."""
    error_type = type(error).__name__[:120] if error is not None else ""
    if output_format == "json":
        return json.dumps({
            "schema": "attestor.blind-escape-arena/dispatch/4.1.4",
            "version": "4.1.4",
            "objective": blind_escape_arena414.OBJECTIVE,
            "status": status,
            "terminal": False,
            "escaped": False,
            "result_verified": False,
            "error_type": error_type,
            "simulation_controls": {
                "arbitrary_payloads_accepted": False,
                "commands_executed": False,
                "network_accessed": False,
                "processes_started": False,
                "real_escape_attempted": False,
            },
        }, indent=2, sort_keys=True, ensure_ascii=False)
    if status == "cancelled":
        return (
            "Attestor 4.1.4 blind escape arena cancelled safely; "
            "no verified escape is claimed.")
    return "Attestor 4.1.4 blind escape arena failed safely: " + error_type


@contextlib.contextmanager
def _blind_escape_cancellation():
    """Translate Ctrl+C into a checkpointable cancelled arena episode."""
    requested = threading.Event()
    previous = None
    installed = False
    if threading.current_thread() is threading.main_thread():
        try:
            previous = signal.getsignal(signal.SIGINT)

            def request_cancel(_signum, _frame):
                if requested.is_set():
                    raise KeyboardInterrupt
                requested.set()

            signal.signal(signal.SIGINT, request_cancel)
            installed = True
        except (AttributeError, OSError, ValueError):
            pass
    try:
        yield requested
    finally:
        if installed:
            signal.signal(signal.SIGINT, previous)


def build_brain(model: str = "", mode: str = "fallback"):
    return brain.from_env(model=model, mode=mode, exclude=EXCLUDED)


def _local_path(target: str) -> str:
    """Resolve direct paths from cwd first, then from the detector folder."""
    if os.path.exists(target):
        return target
    detector_relative = os.path.join(HERE, target)
    if os.path.exists(detector_relative):
        return detector_relative
    return ""


def _link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _prepare_candidate_export(output: str, selected: str) -> Path:
    """Create an empty review directory that cannot overlap the analyzed tree."""
    supplied = Path(output).expanduser()
    if _link_or_reparse(supplied):
        raise ValueError("repair candidate export cannot be a link or reparse point")
    destination = supplied.resolve()
    target = Path(selected).expanduser().resolve(strict=True)
    workspace = target if target.is_dir() else target.parent
    if destination == workspace or workspace in destination.parents:
        raise ValueError("repair candidate export must be outside the analyzed workspace")
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            raise ValueError("repair candidate export directory must be empty")
    else:
        destination.mkdir(parents=True, exist_ok=False)
    if _link_or_reparse(destination):
        raise ValueError("repair candidate export cannot be a link or reparse point")
    return destination


def _write_verified_improvements(report: dict, output: str, selected: str) -> list[str]:
    """Export only complete improvements whose inherited proof gates accepted them."""
    rows = [row for row in report.get("improvements", [])
            if isinstance(row, dict) and row.get("accepted") is True and
            row.get("complete") is True and isinstance(row.get("improved_source"), str) and
            row.get("improved_source")]
    if not rows:
        return []
    destination = _prepare_candidate_export(output, selected)
    written: list[str] = []
    for row in rows:
        relative = Path(str(row.get("target", "")))
        if (relative.is_absolute() or not relative.parts or
                any(part in {"", ".", ".."} for part in relative.parts)):
            raise ValueError("verified improvement output path is unsafe")
        target = (destination / relative).resolve()
        try:
            target.relative_to(destination)
        except ValueError as exc:
            raise ValueError("verified improvement output escapes destination") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(row["improved_source"], encoding="utf-8", newline="")
        written.append(str(target))
    return written


def _patchguard_decision(payload: str) -> dict:
    """Parse `target :: candidate` or `project :: target :: candidate`."""
    parts = [part.strip() for part in payload.split("::")]
    if len(parts) == 2 and all(parts):
        return {"action": "patchguard", "project": ".", "target": parts[0],
                "candidate": parts[1]}
    if len(parts) == 3 and all(parts):
        return {"action": "patchguard", "project": parts[0], "target": parts[1],
                "candidate": parts[2]}
    return {"action": "patchguard", "project": ".", "target": "", "candidate": ""}


def decide(request: str, bus=None) -> dict:
    """Map anything the user typed to the power that fits it."""
    low = request.lower().strip()
    if low in _ESCAPE_LAB_REQUESTS:
        return {
            "action": "escapelab414",
            "scenario": escape_lab414.ALL_SCENARIOS,
        }
    computer_requests = (
        "scan my computer", "scan computer", "computer scan",
        "check my computer", "find files on my computer",
    )
    if low in computer_requests or any(
            low.startswith(phrase + " ") for phrase in computer_requests):
        return {"action": "computer41"}
    for prefix in ("attestor413 ", "attestor 4.1.3 ", "attestor 4 1 3 ",
                   "maximum 4.1.3 "):
        if low.startswith(prefix):
            return {"action": "attestor41", "path": request[len(prefix):].strip() or "."}
    for prefix in ("attestor414 ", "attestor 4.1.4 ", "attestor 4 1 4 ",
                   "maximum 4.1.4 ", "attestor41 ", "attestor 4.1 ", "attestor 4 1 ",
                   "maximum 4.1 ", "maximum attestor ", "maximum review ",
                   "maximum analysis "):
        if low.startswith(prefix):
            return {"action": "attestor414", "path": request[len(prefix):].strip() or "."}
    for prefix in ("deep research ", "web research ", "research "):
        if low.startswith(prefix):
            return {"action": "research41", "question": request[len(prefix):].strip()}
    for prefix in ("attestor40 ", "attestor 4.0 ", "attestor 4 ", "attestor 4 0 ", "maximum 4.0 "):
        if low.startswith(prefix):
            return {"action": "attestor40", "path": request[len(prefix):].strip() or "."}
    for prefix in ("attestor35 ", "attestor 3.5 ", "attestor 3 5 ", "maximum 3.5 "):
        if low.startswith(prefix):
            return {"action": "attestor35", "path": request[len(prefix):].strip() or "."}
    for prefix in ("attestor3 ", "attestor 3.0 ", "attestor 3 "):
        if low.startswith(prefix):
            return {"action": "attestor3", "path": request[len(prefix):].strip() or "."}
    for prefix in ("improve result ", "verified improve ", "find and improve ",
                   "find errors and improve ", "fix safely "):
        if low.startswith(prefix):
            return {"action": "improve", "path": request[len(prefix):].strip() or "."}
    for prefix in ("semantic scan ", "whole program ", "whole-program ",
                   "data flow ", "call graph "):
        if low.startswith(prefix):
            return {"action": "semantic", "path": request[len(prefix):].strip() or "."}
    for prefix in ("supply chain ", "supply-chain ", "dependency center ", "sbom scan "):
        if low.startswith(prefix):
            return {"action": "supplychain", "path": request[len(prefix):].strip() or "."}
    for prefix in ("repository memory ", "repo memory ", "architecture memory "):
        if low.startswith(prefix):
            return {"action": "repositorymemory", "path": request[len(prefix):].strip() or "."}
    for prefix in ("mayhem ", "coding mayhem ", "hard mayhem ", "maximum coding "):
        if low.startswith(prefix):
            return {"action": "mayhem", "path": request[len(prefix):].strip() or "."}
    for prefix in ("cybermayhem ", "cyber mayhem ", "security posture ", "maximum security "):
        if low.startswith(prefix):
            return {"action": "cybermayhem", "path": request[len(prefix):].strip() or "."}
    for prefix in ("quality gate ", "qualitygate ", "release gate "):
        if low.startswith(prefix):
            return {"action": "qualitygate", "path": request[len(prefix):].strip() or "."}
    for prefix in ("patchguard ", "patch guard ", "verify patch "):
        if low.startswith(prefix):
            return _patchguard_decision(request[len(prefix):].strip())
    for prefix in ("workspace scan ", "scan workspace ", "full project scan ", "engine22 "):
        if low.startswith(prefix):
            return {"action": "workspace", "path": request[len(prefix):].strip() or "."}
    for prefix in ("self improve ", "self-improve ", "evolve ", "harvest and improve " ):
        if low.startswith(prefix):
            return {"action": "evolve", "target": request[len(prefix):].strip()}
    for prefix in ("ruleforge ", "rule forge ", "forge rules ", "make rules from " ):
        if low.startswith(prefix):
            return {"action": "ruleforge", "target": request[len(prefix):].strip()}
    for prefix in ("patchforge ", "patch forge ", "forge patch ", "patch this "):
        if low.startswith(prefix):
            return {"action": "patchforge", "target": request[len(prefix):].strip()}
    for prefix in ("sieve ", "code sieve ", "write and refine ", "generate and refine "):
        if low.startswith(prefix):
            return {"action": "sieve", "target": request[len(prefix):].strip()}
    for prefix in ("codemax ", "code max ", "max code ", "maximum coding "):
        if low.startswith(prefix):
            return {"action": "codemax", "target": request[len(prefix):].strip()}
    for prefix in ("codepower ", "code power ", "architect ", "test smith ",
                   "review duel ", "excellent coding "):
        if low.startswith(prefix):
            return {"action": "codepower", "target": request[len(prefix):].strip()}
    for prefix in ("securitymax ", "security max ", "secrets hunter ", "owasp ",
                   "threat model "):
        if low.startswith(prefix):
            return {"action": "securitymax", "path": request[len(prefix):].strip()}
    for prefix in ("attestor2 ", "attestor 2 ", "max everything ", "maximum everything "):
        if low.startswith(prefix):
            return {"action": "attestor2", "target": request[len(prefix):].strip()}
    for prefix in ("rarebugs ", "rare bugs ", "rare errors ", "mythic errors ",
                   "super rare errors "):
        if low.startswith(prefix):
            return {"action": "rarebugs", "path": request[len(prefix):].strip()}
    for prefix in ("reproduce ", "bug reproducer ", "make reproducer "):
        if low.startswith(prefix):
            return {"action": "reproduce", "target": request[len(prefix):].strip()}
    for prefix in ("projectbrain ", "project brain ", "brain project "):
        if low.startswith(prefix):
            return {"action": "projectbrain", "path": request[len(prefix):].strip()}
    for prefix in ("cyber sentinel ", "security audit ", "security scan ", "cyber "):
        if low.startswith(prefix):
            return {"action": "cyber", "path": request[len(prefix):].strip()}
    for prefix in ("polyglot ", "tiny bugs ", "low level scan ", "asm scan "):
        if low.startswith(prefix):
            return {"action": "polyglot", "path": request[len(prefix):].strip()}
    for prefix in ("mutation gauntlet ", "gauntlet ", "mutate "):
        if low.startswith(prefix):
            return {"action": "gauntlet", "target": request[len(prefix):].strip()}
    if low in ("code arena", "arena", "dashboard", "benchmark dashboard"):
        return {"action": "arena"}
    if low in ("fix memory", "fixmemory", "repair memory"):
        return {"action": "fixmemory"}
    if low == "darwin" or low == "darwin stats":
        return {"action": "darwin", "cmd": "stats", "query": ""}
    for prefix in ("darwin search ", "payload search ", "search payloads "):
        if low.startswith(prefix):
            return {"action": "darwin", "cmd": "search", "query": request[len(prefix):].strip()}
    for prefix in ("darwin show ", "payload category "):
        if low.startswith(prefix):
            return {"action": "darwin", "cmd": "show", "query": request[len(prefix):].strip()}
    if low in ("darwin list", "payload list", "list payloads"):
        return {"action": "darwin", "cmd": "list", "query": ""}
    local = _local_path(request)
    if local and os.path.isdir(local):
        return {"action": "audit", "path": local}       # a whole tree -> full review
    if local or harvest.parse_github_url(request):
        return {"action": "comprehend", "target": local or request}
    if request.startswith(("http" + "://", "https://")):
        # a live website (not a GitHub file) -> read its public front-end
        return {"action": "webscan", "url": request}
    intent = nl.interpret(request)
    if intent["intent"] == "scaffold":
        return {"action": "scaffold", "intent": intent}
    if intent["intent"] == "review":
        local = _local_path(intent["path"])
        return {"action": "comprehend", "target": local or intent["path"]}
    brain_awake = bus is not None and bus.available()
    if intent["intent"] == "snippet":
        # with a real model awake, forging beats a canned snippet; offline, the
        # curated library is the honest best
        if brain_awake:
            return {"action": "forge", "request": request}
        return {"action": "snippet", "intent": intent}
    if brain_awake:
        return {"action": "forge", "request": request}
    return {"action": "unknown"}


def perform(decision: dict, out=None, rounds: int | None = None, bus=None, curry_mode: bool = False,
            evolve_lang=None, evolve_limit: int = 1, evolve_cycles: int = 5,
            ruleforge_pick: int = 0, request: str = "", execute_generated: bool = False,
            external_tools: bool = False, use_cache: bool = True,
            output_format: str = "text", min_grade: str = "B", max_high: int = 0,
            mutation_limit: int = 12, run_tests: bool = False,
            test_command=None, response_style: str = "professional",
            apply_patch_authorized: bool = False, backup_root: str = "",
            max_improvement_files: int = 3, improved_out: str = "",
             memory_out: str = "", rule_packs=(), rule_pack_key: bytes | None = None,
             semantic_rule_packs=(), require_signed_packs: bool = False,
             truth_key: bytes | None = None, truth_key_id: str = "",
             research_online: bool = False, research_fetch_pages: bool = False,
             research_max_queries: int = 6, research_max_sources: int = 30,
             research_country: str = "US", research_language: str = "en",
             research_freshness: str = "", computer_authorized: bool = False,
             computer_scope: str = "home", computer_max_projects: int = 3,
             computer_review_improvements: bool = False,
             cjp_permission_confirmed: bool = False,
             cjp_apply: bool = False,
             cjp_apply_confirmed: bool = False,
             cjp_preview_evidence_sha256: str = "",
             variant_profile=None):
    """Run the chosen power. Returns (text, exit_code)."""
    action = decision["action"]
    if variant_profile is not None and action not in {"attestor414", "improve"}:
        return "Attestor 4.1.4 variant failed safely: invalid mode boundary", 2
    if action == _BLIND_ESCAPE_ACTION:
        try:
            if output_format not in {"text", "json"}:
                raise blind_escape_arena414.BlindEscapeArenaError(
                    "blind escape arena supports text or json only")
            if (type(decision) is not dict
                    or set(decision) - {"action", "single_episode"}
                    or type(decision.get("single_episode", False)) is not bool
                    or request):
                raise blind_escape_arena414.BlindEscapeArenaError(
                    "blind escape arena accepts no request or arena payload")
            checkpoint = _blind_escape_checkpoint_path()
            _blind_escape_validate_output_path(out, checkpoint)
            with _blind_escape_cancellation() as cancellation:
                state = blind_escape_arena414.open_or_create(
                    checkpoint, objective=blind_escape_arena414.OBJECTIVE)
                if decision.get("single_episode", False):
                    report = blind_escape_arena414.run_episode(
                        state, cancel=cancellation,
                        checkpoint_path=checkpoint)
                else:
                    report = blind_escape_arena414.run_until_terminal(
                        state, episode_budget=None, cancel=cancellation,
                        checkpoint_path=checkpoint)
            state_valid, _state_errors = blind_escape_arena414.verify_state(
                state)
            report_valid, _report_errors = blind_escape_arena414.verify_report(
                report, state)
            if not state_valid or not report_valid:
                raise blind_escape_arena414.BlindEscapeArenaError(
                    "arena result did not pass deterministic replay")
            if output_format == "json":
                text = json.dumps(
                    report, indent=2, sort_keys=True, ensure_ascii=False)
            else:
                text = blind_escape_arena414.render_text(report, state)
            if out:
                _blind_escape_validate_output_path(out, checkpoint)
                Path(out).write_text(
                    text + ("" if text.endswith("\n") else "\n"),
                    encoding="utf-8")
                text = _output_notice(
                    text,
                    "wrote replay-verified Attestor 4.1.4 blind-arena report",
                    output_format,
                )
            status = report["status"]
            if status == "escaped":
                return text, 0
            if status == "cancelled":
                return text, 130
            return text, 2 if status == "explorer-refused" else 1
        except KeyboardInterrupt:
            return _blind_escape_dispatch("cancelled", output_format), 130
        except (blind_escape_arena414.BlindEscapeArenaError, OSError,
                RuntimeError, TypeError, ValueError) as exc:
            return _blind_escape_dispatch("failed", output_format, exc), 2
    if action == "escapelab414":
        try:
            if output_format not in {"text", "json"}:
                raise escape_lab414.EscapeLabError(
                    "escape lab supports text or json only")
            report = escape_lab414.run(
                decision.get("scenario", escape_lab414.ALL_SCENARIOS),
                simulation_confirmed=True,
            )
            valid, _errors = escape_lab414.verify_report(report)
            if not valid:
                return (
                    "Attestor 4.1.4 private escape lab failed safely: "
                    "report verification failed",
                    2,
                )
            if output_format == "json":
                text = json.dumps(
                    report, indent=2, sort_keys=True, ensure_ascii=False)
            else:
                text = escape_lab414.render_text(report)
            if out:
                Path(out).write_text(
                    text + ("" if text.endswith("\n") else "\n"),
                    encoding="utf-8")
                text = _output_notice(
                    text,
                    "wrote Attestor 4.1.4 simulated escape-lab report -> "
                    + str(out),
                    output_format,
                )
            summary = report.get("summary", {})
            return text, 1 if summary.get("simulated_escapes", 0) else 0
        except (escape_lab414.EscapeLabError, variant414.VariantError,
                OSError, RuntimeError, TypeError, ValueError) as exc:
            return (
                "Attestor 4.1.4 private escape lab failed safely: %s"
                % type(exc).__name__,
                2,
            )
    if action == "cjpcontrol414":
        try:
            report = cjp_control414.control(
                decision.get("request_file", ""),
                permission_confirmed=cjp_permission_confirmed,
                apply=cjp_apply,
                apply_confirmed=cjp_apply_confirmed,
                preview_evidence_sha256=cjp_preview_evidence_sha256,
            )
            if output_format == "json":
                text = json.dumps(
                    report, indent=2, sort_keys=True, ensure_ascii=False)
            else:
                text = cjp_control414.render_text(report)
            if out:
                Path(out).write_text(
                    text + ("" if text.endswith("\n") else "\n"),
                    encoding="utf-8")
                text = _output_notice(
                    text,
                    "wrote Cockroach local-control session report -> " +
                    str(out),
                    output_format)
            status = report.get("status")
            if status in {
                    "authorization-required", "failed", "rolled-back"}:
                return text, 2
            transaction = report.get("transaction")
            if (isinstance(transaction, dict)
                    and transaction.get("cleanup_complete") is False):
                return text, 1
            return text, 1 if status == "apply-refused" else 0
        except (OSError, PermissionError, RuntimeError, TypeError,
                ValueError) as exc:
            return (
                "Attestor 4.1.4 Cockroach local control failed safely: %s"
                % type(exc).__name__,
                2,
            )
    if action == "computer41":
        try:
            report = computer_scan41.scan_computer(
                authorized=computer_authorized,
                scope=computer_scope,
                max_projects=computer_max_projects,
                review_improvements=computer_review_improvements)
            if output_format == "json":
                text = json.dumps(report, indent=2, sort_keys=True,
                                  ensure_ascii=False)
            else:
                text = computer_scan41.render_text(report)
            if out:
                Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
                text = _output_notice(
                    text, "wrote Attestor 4.1.3 computer scan report -> " + str(out),
                    output_format)
            status = report.get("status")
            return text, 2 if status in {
                "authorization-required", "failed", "inconsistent"
            } else (
                1 if status == "partial" else 0)
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "Attestor 4.1.3 Computer Scan failed safely: %s" % type(exc).__name__, 2
    if action in {"attestor414", "improve"}:
        try:
            if memory_out:
                raise ValueError(
                    "Attestor 4.1.4 uses the explicit evidence-history API, "
                    "not --memory-out")
            selected = decision.get("path") or "."
            profile = variant414.DEFAULT_PROFILE if variant_profile is None else (
                variant414.require_compiled_profile(variant_profile)
                if type(variant_profile) is variant414.VariantProfile else
                variant414.profile_for_slug(variant_profile))
            current = _attestor414_module()
            report = current.maximum(
                selected, improve=True,
                include_candidate_source=True,
                max_improvement_files=min(
                    max_improvement_files, profile.max_improvement_files),
                compiler_checks=external_tools, use_cache=use_cache,
                test_command=test_command if run_tests else None,
                authorize_tests=run_tests,
                legacy_rule_packs=tuple(rule_packs or ()),
                semantic_rule_packs=tuple(semantic_rule_packs or ()),
                rule_pack_key=rule_pack_key,
                require_signed_packs=require_signed_packs,
                truth_key=truth_key, truth_key_id=truth_key_id,
                variant=profile)
            public = current.safe_public_report(
                report, root=selected, truth_key=truth_key)
            if output_format == "json":
                text = json.dumps(
                    public, indent=2, sort_keys=True, ensure_ascii=False)
            elif output_format == "sarif":
                text = json.dumps(current.to_sarif(
                    report, root=selected, truth_key=truth_key),
                    indent=2, sort_keys=True)
            elif output_format in {"sbom", "cyclonedx"}:
                text = json.dumps(public.get("supply_chain", {}).get(
                    "sbom", {}).get("cyclonedx", {}),
                    indent=2, sort_keys=True)
            elif output_format == "spdx":
                text = json.dumps(public.get("supply_chain", {}).get(
                    "sbom", {}).get("spdx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx-2.3":
                text = json.dumps(public.get("supply_chain", {}).get(
                    "sbom", {}).get("spdx_2_3_legacy", {}),
                    indent=2, sort_keys=True)
            elif output_format == "vex":
                text = json.dumps(
                    public.get("supply_chain", {}).get("vex", {}),
                    indent=2, sort_keys=True)
            else:
                text = current.render(
                    report, response_style, root=selected,
                    truth_key=truth_key)
                candidate = public.get("repair_director_41", {}).get(
                    "selected_candidate_output")
                if action == "improve" and isinstance(candidate, dict):
                    text += "\n\nSelected repair result\n----------------------\n"
                    text += json.dumps(
                        candidate, indent=2, sort_keys=True,
                        ensure_ascii=False)
            if out:
                Path(out).write_text(
                    text + ("" if text.endswith("\n") else "\n"),
                    encoding="utf-8")
                text = _output_notice(
                    text, "wrote Attestor 4.1.4 report -> " + str(out),
                    output_format)
            if improved_out:
                written = _write_verified_improvements(
                    public, improved_out, selected)
                if written:
                    text = _output_notice(
                        text,
                        "wrote %d complete verified improvement file(s) -> %s" %
                        (len(written), improved_out),
                        output_format)
                else:
                    text = _output_notice(
                        text,
                        "no complete verified improvement was available; "
                        "any Repair Director candidate remains an unverified "
                        "review artifact in the report",
                        output_format)
            return text, 2 if public.get("status") in {
                "failed", "inconsistent"
            } else (
                1 if public.get("summary", {}).get("findings", 0)
                or public.get("status") == "no-findings-with-gaps" else 0)
        except (ImportError, OSError, PermissionError, RuntimeError,
                TypeError, ValueError) as exc:
            return _attestor414_failure(exc, output_format), 2
    if action == "attestor41":
        try:
            if memory_out:
                raise ValueError("Attestor 4.1.3 uses the explicit evidence-history API, not --memory-out")
            selected = decision.get("path") or "."
            report = attestor41.maximum(
                selected, improve=True,
                include_candidate_source=action == "improve",
                max_improvement_files=max_improvement_files,
                compiler_checks=external_tools, use_cache=use_cache,
                test_command=test_command if run_tests else None,
                authorize_tests=run_tests,
                legacy_rule_packs=tuple(rule_packs or ()),
                semantic_rule_packs=tuple(semantic_rule_packs or ()),
                rule_pack_key=rule_pack_key,
                require_signed_packs=require_signed_packs,
                truth_key=truth_key, truth_key_id=truth_key_id)
            public = attestor41.safe_public_report(report, root=selected,
                                               truth_key=truth_key)
            if output_format == "json":
                text = truth_guard41.deterministic_json(public)
            elif output_format == "sarif":
                text = json.dumps(attestor41.to_sarif(
                    report, root=selected, truth_key=truth_key),
                    indent=2, sort_keys=True)
            elif output_format in {"sbom", "cyclonedx"}:
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "cyclonedx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx-2.3":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx_2_3_legacy", {}), indent=2, sort_keys=True)
            elif output_format == "vex":
                text = json.dumps(public.get("supply_chain", {}).get("vex", {}),
                                  indent=2, sort_keys=True)
            else:
                text = attestor41.render(report, response_style, root=selected,
                                     truth_key=truth_key)
                candidate = public.get("repair_director_41", {}).get(
                    "selected_candidate_output")
                if action == "improve" and isinstance(candidate, dict):
                    text += "\n\nSelected repair result\n----------------------\n"
                    text += json.dumps(candidate, indent=2, sort_keys=True,
                                       ensure_ascii=False)
            if out:
                Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
                text = _output_notice(
                    text, "wrote Attestor 4.1.3 report -> " + str(out), output_format)
            if improved_out:
                written = _write_verified_improvements(public, improved_out, selected)
                if written:
                    text += "\nwrote %d complete verified improvement file(s) -> %s" % (
                        len(written), improved_out)
                else:
                    text += ("\nno complete verified improvement was available; "
                             "any Repair Director candidate remains an unverified review artifact in the report")
            return text, 2 if public.get("status") in {"failed", "inconsistent"} else (
                1 if public.get("summary", {}).get("findings", 0)
                or public.get("status") == "no-findings-with-gaps" else 0)
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "Attestor 4.1.3 failed safely: %s" % type(exc).__name__, 2
    if action == "research41":
        try:
            policy = research_engine41.ResearchPolicy(
                allow_network=research_online,
                max_queries=research_max_queries,
                max_sources=research_max_sources,
                fetch_pages=research_fetch_pages,
                country=research_country, language=research_language,
                freshness=research_freshness)
            report = research_engine41.research(
                decision.get("question") or request, policy=policy)
            valid, _errors = research_engine41.verify_report(report)
            text = json.dumps(report, indent=2, sort_keys=True,
                              ensure_ascii=False) if output_format == "json" else \
                research_engine41.render(report)
            if out:
                network_used = bool(report.get("execution", {}).get("network_accessed"))
                retention_allowed = report.get("retention", {}).get(
                    "provider_declared_retention_allowed") is True
                if network_used and not retention_allowed:
                    text = _output_notice(
                        text, "research report was not persisted: the active provider plan "
                        "did not declare result retention as allowed", output_format)
                else:
                    Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                         encoding="utf-8")
                    text = _output_notice(
                        text, "wrote Attestor 4.1.3 research report -> " + str(out),
                        output_format)
            return text, 2 if not valid or report.get("status") == "no-evidence" else 0
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "Attestor 4.1.3 Research failed safely: %s" % type(exc).__name__, 2
    if action == "attestor40":
        try:
            report = attestor40.maximum(
                decision.get("path") or ".", improve=True,
                max_improvement_files=max_improvement_files,
                compiler_checks=external_tools, use_cache=use_cache,
                test_command=test_command if run_tests else None,
                authorize_tests=run_tests, rule_packs=tuple(rule_packs or ()),
                rule_pack_key=rule_pack_key,
                require_signed_packs=require_signed_packs,
                truth_key=truth_key, truth_key_id=truth_key_id)
            public = attestor40.safe_public_report(report, truth_key=truth_key)
            if output_format == "json":
                text = attestor40.truth_guard40.deterministic_json(public)
            elif output_format == "sarif":
                text = json.dumps(attestor40.to_sarif(report, truth_key=truth_key),
                                  indent=2, sort_keys=True)
            elif output_format in {"sbom", "cyclonedx"}:
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "cyclonedx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx-2.3":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx_2_3_legacy", {}), indent=2, sort_keys=True)
            elif output_format == "vex":
                text = json.dumps(public.get("supply_chain", {}).get("vex", {}),
                                  indent=2, sort_keys=True)
            else:
                text = attestor40.render(report, response_style, truth_key=truth_key)
            if out:
                Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
                text += "\nwrote Attestor 4.0 report -> " + str(out)
            if improved_out:
                written = attestor40._write_improvements(
                    report, improved_out, truth_key=truth_key)
                text += "\nwrote %d verified improved source file(s) -> %s" % (
                    len(written), improved_out)
            if memory_out:
                memory = public.get("incremental_semantics_35", {}).get("database", {})
                Path(memory_out).write_text(
                    json.dumps(memory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                text += "\nwrote source-free Attestor 4.0 semantic database -> " + memory_out
            return text, 2 if public["status"] in {"failed", "inconsistent", "no-evidence"} else (
                1 if public.get("summary", {}).get("findings", 0)
                or public["status"] == "no-findings-with-gaps" else 0)
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "Attestor 4.0 failed safely: %s" % type(exc).__name__, 2
    if action == "attestor35":
        try:
            report = attestor35.maximum(
                decision.get("path") or ".", improve=True,
                max_improvement_files=max_improvement_files,
                compiler_checks=external_tools, use_cache=use_cache,
                test_command=test_command if run_tests else None,
                authorize_tests=run_tests, rule_packs=tuple(rule_packs or ()),
                rule_pack_key=rule_pack_key,
                require_signed_packs=require_signed_packs,
                truth_key=truth_key, truth_key_id=truth_key_id)
            public = attestor35.safe_public_report(report, truth_key=truth_key)
            if output_format == "json":
                text = attestor35.truth_guard35.deterministic_json(public)
            elif output_format == "sarif":
                text = json.dumps(attestor35.to_sarif(report, truth_key=truth_key),
                                  indent=2, sort_keys=True)
            elif output_format in {"sbom", "cyclonedx"}:
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "cyclonedx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx-2.3":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx_2_3_legacy", {}), indent=2, sort_keys=True)
            elif output_format == "vex":
                text = json.dumps(public.get("supply_chain", {}).get("vex", {}),
                                  indent=2, sort_keys=True)
            else:
                text = attestor35.render(report, response_style, truth_key=truth_key)
            if out:
                Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
                text += "\nwrote Attestor 3.5 report -> " + str(out)
            if improved_out:
                written = attestor35._write_improvements(
                    report, improved_out, truth_key=truth_key)
                text += "\nwrote %d verified improved source file(s) -> %s" % (
                    len(written), improved_out)
            if memory_out:
                memory = public.get("incremental_semantics_35", {}).get("database", {})
                Path(memory_out).write_text(
                    json.dumps(memory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                text += "\nwrote source-free Attestor 3.5 semantic database -> " + memory_out
            return text, 2 if public["status"] in {"failed", "inconsistent", "no-evidence"} else (
                1 if public.get("summary", {}).get("findings", 0)
                or public["status"] == "no-findings-with-gaps" else 0)
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "Attestor 3.5 failed safely: %s" % type(exc).__name__, 2
    if action == "attestor3":
        try:
            report = attestor3.maximum(
                decision.get("path") or ".", improve=True,
                max_improvement_files=max_improvement_files,
                compiler_checks=external_tools, use_cache=use_cache,
                test_command=test_command if run_tests else None,
                authorize_tests=run_tests, rule_packs=tuple(rule_packs or ()),
                rule_pack_key=rule_pack_key,
                require_signed_packs=require_signed_packs)
            public = attestor3.safe_public_report(report)
            if output_format == "json":
                text = truth_guard.deterministic_json(public)
            elif output_format == "sarif":
                text = json.dumps(attestor3.to_sarif(report), indent=2, sort_keys=True)
            elif output_format in {"sbom", "cyclonedx"}:
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "cyclonedx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx", {}), indent=2, sort_keys=True)
            elif output_format == "spdx-2.3":
                text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get(
                    "spdx_2_3_legacy", {}), indent=2, sort_keys=True)
            elif output_format == "vex":
                text = json.dumps(public.get("supply_chain", {}).get("vex", {}),
                                  indent=2, sort_keys=True)
            else:
                text = attestor3.render(report, response_style)
            if out:
                Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
                text += "\nwrote Attestor 3.0 report -> " + str(out)
            if improved_out:
                written = attestor3._write_improvements(report, improved_out)
                text += "\nwrote %d verified improved source file(s) -> %s" % (
                    len(written), improved_out)
            if memory_out:
                Path(memory_out).write_text(
                    json.dumps(report["_memory_snapshot"], indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
                text += "\nwrote privacy-preserving repository memory -> " + memory_out
            return text, 2 if public["status"] in {"failed", "inconsistent", "no-evidence"} else (
                1 if public.get("summary", {}).get("findings", 0)
                or public["status"] == "no-findings-with-gaps" else 0)
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "Attestor 3.0 failed safely: %s" % type(exc).__name__, 2
    if action == "semantic":
        try:
            report = semantic_engine.analyze_repository(
                decision.get("path") or ".", compiler_checks=external_tools)
            text = (json.dumps(report, indent=2, sort_keys=True)
                    if output_format == "json" else semantic_engine.render(report))
            if out:
                Path(out).write_text(text + ("" if text.endswith("\n") else "\n"),
                                     encoding="utf-8")
                text += "\nwrote semantic report -> " + str(out)
            return text, 2 if report.get("status") == "error" else (
                1 if report.get("findings") else 0)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return "Semantic analysis failed safely: %s" % type(exc).__name__, 2
    if action == "supplychain":
        try:
            report = supply_chain_center.analyze_workspace(decision.get("path") or ".")
            if output_format in {"sbom", "cyclonedx"}:
                value = report["sbom"]["cyclonedx"]
            elif output_format == "spdx":
                value = report["sbom"]["spdx"]
            elif output_format == "spdx-2.3":
                value = report["sbom"]["spdx_2_3_legacy"]
            elif output_format == "vex":
                value = report["vex"]
            else:
                value = report
            text = json.dumps(value, indent=2, sort_keys=True)
            if out:
                Path(out).write_text(text + "\n", encoding="utf-8")
                text += "\nwrote supply-chain report -> " + str(out)
            errors = report.get("inventory", {}).get("errors", [])
            risks = report.get("risk_findings", [])
            return text, 2 if errors else (1 if risks else 0)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return "Supply-chain analysis failed safely: %s" % type(exc).__name__, 2
    if action == "repositorymemory":
        try:
            report = repository_memory.snapshot(decision.get("path") or ".")
            text = json.dumps(report, indent=2, sort_keys=True)
            if out:
                Path(out).write_text(text + "\n", encoding="utf-8")
                text += "\nwrote repository memory -> " + str(out)
            return text, 0
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return "Repository memory failed safely: %s" % type(exc).__name__, 2
    if action == "mayhem":
        report = mayhem.run(
            decision.get("path") or ".", min_grade=min_grade, max_high=max_high,
            external_tools=external_tools, use_cache=use_cache,
            mutation_limit=mutation_limit, execute_mutants=execute_generated,
            run_tests=run_tests, test_command=test_command)
        if output_format == "json":
            text = json.dumps(report, indent=2, sort_keys=True)
        elif output_format == "sarif":
            text = json.dumps(security_posture.to_sarif(report.get("security", {})), indent=2)
        elif output_format == "sbom":
            text = json.dumps(report.get("security", {}).get("sbom", {}), indent=2, sort_keys=True)
        else:
            text = response_engine.structured(report, response_style)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Coding Mayhem report -> " + out
        return text, 2 if report["status"] == "failed" else (
            0 if report["status"] in {"ready", "ready-with-notes"} else 1)
    if action == "cybermayhem":
        report = security_posture.assess(
            decision.get("path") or ".", external_tools=external_tools,
            use_cache=use_cache)
        if output_format == "json":
            text = json.dumps(report, indent=2, sort_keys=True)
        elif output_format == "sarif":
            text = json.dumps(security_posture.to_sarif(report), indent=2)
        elif output_format == "sbom":
            text = json.dumps(report.get("sbom", {}), indent=2, sort_keys=True)
        else:
            text = response_engine.structured(report, response_style)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Cybersecurity Mayhem report -> " + out
        if report.get("status") == "failed":
            return text, 2
        return text, 1 if report.get("summary", {}).get("findings", 0) else 0
    if action == "qualitygate":
        report = qualitygate.evaluate(
            decision.get("path") or ".", min_grade=min_grade, max_high=max_high,
            run_tests=run_tests, test_command=test_command,
            external_tools=external_tools, use_cache=use_cache)
        if output_format == "json":
            text = qualitygate.render_json(report)
        elif output_format == "sbom":
            text = json.dumps(report.sbom, indent=2, sort_keys=True)
        else:
            text = qualitygate.render_markdown(report)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote quality-gate report -> " + out
        return text, 0 if report.passed else 1
    if action == "patchguard":
        try:
            candidate_source = decision.get("candidate_source")
            if candidate_source is None:
                candidate_source = Path(decision["candidate"]).read_text(encoding="utf-8")
            report = patchguard.verify_candidate(
                decision.get("project") or ".", decision["target"], candidate_source,
                name=decision.get("name") or "candidate",
                test_command=test_command if run_tests else None,
                authorize_tests=run_tests, deep=True)
            text = (json.dumps(patchguard.report_dict(report), indent=2)
                    if output_format == "json" else patchguard.render(report))
            if apply_patch_authorized and report.accepted:
                applied = patchguard.apply_candidate(
                    report, candidate_source, authorized=True,
                    backup_root=backup_root or None)
                text += "\nApplied transactionally: %s\nBackup: %s" % (
                    applied.target, applied.backup)
            elif report.accepted:
                text += "\nDRY RUN: accepted but not applied. Use --apply-patch explicitly."
            return text, 0 if report.accepted else 1
        except (KeyError, OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return "PatchGuard failed safely: %s" % type(exc).__name__, 2
    if action == "workspace":
        result = scanengine.scan([decision.get("path") or "."], tools=external_tools,
                                 use_cache=use_cache, deep=True)
        if output_format == "json":
            text = json.dumps(asdict(result), indent=2)
        elif output_format == "sarif":
            text = json.dumps(scanengine.to_sarif(result), indent=2)
        elif output_format == "html":
            text = scanengine.render_html(result)
        else:
            text = scanengine.render_markdown(result)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote workspace report -> " + out
        code = 2 if result.status in {"failed", "unsupported"} else (1 if result.issues else 0)
        return text, code
    if action == "comprehend":
        source, path = comprehend._load(decision["target"])
        if source is None:
            return "", 2
        report = comprehend.comprehend(source, path)
        text = comprehend.render(report)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(report["improved"])
            text += "\nwrote improved copy -> " + out
        return text, 0
    if action == "audit":
        import audit
        result = audit.audit([decision["path"]])
        text = audit.report_text(result, decision["path"])
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(audit.report_markdown(result, decision["path"]))
            text += "\nwrote markdown report -> " + out
        return text, 1 if result["findings"] else 0
    if action == "evolve":
        run = evolve.evolve(decision["target"], lang=evolve_lang, limit=evolve_limit,
                            cycles=evolve_cycles)
        text = evolve.render(run)
        if run["results"]:
            memory = fixmemory.learn_from_evolve_run(run)
            text += "\nupdated Fix Memory -> %s (%d pattern(s))" % (
                fixmemory.DEFAULT_MEMORY, len(memory.get("patterns", {})))
        if out and run["results"]:
            written = evolve.write_results(run, out)
            text += "\nwrote improved file(s):\n" + "\n".join("  " + p for p in written)
        return text, 0 if run["results"] else 1
    if action == "ruleforge":
        run = ruleforge.forge(decision["target"], lang=evolve_lang,
                              pick=ruleforge_pick, limit=evolve_limit)
        text = ruleforge.render(run)
        if out:
            written = ruleforge.write_results(run, out)
            text += "\nwrote candidate artifact(s):\n" + "\n".join("  " + p for p in written)
        return text, 0 if run["candidates"] else 1
    if action == "patchforge":
        result = patchforge.patch_file(decision["target"], bus, request=request,
                                       rounds=rounds or 3, execute=execute_generated)
        text = patchforge.render(result, decision["target"])
        if out and result["ok"]:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(result["code"])
            text += "\nwrote %s candidate -> %s" % (
                result.get("evidence_level", "scan_clean"), out)
        return text, 0 if result["ok"] else 2
    if action == "sieve":
        passes = sieve.DEFAULT_PASSES if rounds is None else rounds
        text, code = sieve.run(decision["target"], bus=bus, rounds=passes)
        if out and code == 0:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote sieve output -> " + out
        return text, code
    if action == "codemax":
        passes = codemax.DEFAULT_PASSES if rounds is None else rounds
        text, code = codemax.run(decision["target"], bus=bus, rounds=passes)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Code Max report -> " + out
        return text, code
    if action == "codepower":
        passes = sieve.DEFAULT_PASSES if rounds is None else rounds
        text, code = codepower.run(decision["target"], bus=bus, rounds=passes)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Code Power report -> " + out
        return text, code
    if action == "securitymax":
        report = secmax.scan([decision["path"] or "."])
        text = secmax.render(report)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Security Max report -> " + out
        return text, 1 if report["findings"] else 0
    if action == "attestor2":
        passes = sieve.DEFAULT_PASSES if rounds is None else rounds
        text, code = attestor2.run(decision["target"], bus=bus, rounds=passes)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Attestor 2 Max report -> " + out
        return text, code
    if action == "rarebugs":
        findings = rarebugs.collect([decision["path"] or "."])
        text = rarebugs.render(findings)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote Rare Error Oracle report -> " + out
        return text, 1 if findings else 0
    if action == "reproduce":
        repro = reproducer.first_for_file(decision["target"])
        text = reproducer.render(repro)
        if out and repro:
            written = reproducer.write(repro, out)
            text += "\nwrote reproducer:\n" + "\n".join("  " + p for p in written)
        return text, 0 if repro else 1
    if action == "projectbrain":
        report = projectbrain.analyze(decision["path"])
        text = projectbrain.render(report)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote project brain report -> " + out
        return text, 0
    if action == "cyber":
        report = cyber.scan([decision["path"] or "."])
        text = cyber.render(report)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote cyber sentinel report -> " + out
        return text, 1 if report["findings"] else 0
    if action == "polyglot":
        report = polyglot.scan([decision["path"] or "."])
        text = polyglot.render(report)
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote polyglot tiny-error report -> " + out
        return text, 1 if report["findings"] else 0
    if action == "grade":
        graded = grade.collect([decision["path"] or "."])
        text = grade.render(graded, "C")
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote code grade report -> " + out
        return text, 1 if grade.failures(graded, "C") else 0
    if action == "nativegrade":
        graded = nativegrade.collect([decision["path"] or "."], jobs=0)
        text = nativegrade.render(graded, "C")
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote native grade report -> " + out
        return text, 1 if nativegrade.failures(graded, "C") else 0
    if action == "factory":
        try:
            count = min(64, max(1, int(str(decision["count"]).split()[0])))
        except (ValueError, IndexError):
            count = 20
        totals = massgen.factory(count, resources=20, jobs=0)
        return massgen.render(totals), 1 if totals["defects"] else 0
    if action == "refine":
        text, remaining = refine.report(decision["target"])
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(text)
            text += "\nwrote refined code -> " + out
        return text, remaining
    if action == "gauntlet":
        with open(decision["target"], encoding="utf-8", errors="replace") as fh:
            result = mutation_gauntlet.run(
                fh.read(), decision["target"], request=request,
                execute=execute_generated)
        return mutation_gauntlet.render(result), 1 if result["gaps"] else 0
    if action == "arena":
        return codearena.render(codearena.measure()), 0
    if action == "fixmemory":
        return fixmemory.render(fixmemory.load()), 0
    if action == "darwin":
        data = darwin.load()
        cmd = decision.get("cmd", "stats")
        query = decision.get("query", "")
        if cmd == "stats":
            return darwin.render_stats(data), 0
        if cmd == "list":
            return darwin.render_categories(data), 0
        if cmd == "show":
            return darwin.render_category(query, data=data), 0
        if cmd == "search":
            results = darwin.search(query, limit=evolve_limit, data=data)
            return darwin.render_search(results, query), 0 if results else 1
    if action == "webscan":
        try:
            html = webscan.fetch(decision["url"])
        except Exception as exc:                 # noqa: BLE001 -- report and bail
            return f"could not reach {decision['url']}: {type(exc).__name__} {exc}", 2
        report = webscan.analyze(html, decision["url"], [])
        text = webscan.render(report)
        if bus is not None and bus.available() and report["findings"]:
            text += "\n\n" + webscan.correct(report, bus)
        return text, 1 if report["findings"] else 0
    if action in ("scaffold", "snippet"):
        return nl.run(decision["intent"], out=out), 0
    if action == "forge":
        if curry_mode and len(bus.providers()) > 1:
            import curry
            dishes = curry.cook(decision["request"], bus.providers())
            winner = curry.pick(dishes)
            text = curry.render(decision["request"], dishes, winner)
            if out and winner is not None:
                with open(out, "w", encoding="utf-8") as fh:
                    fh.write(winner["code"])
                text += "\nwrote the winning dish -> " + out
            return text, 0 if winner is not None else 2
        result = forge.forge(decision["request"], bus, rounds=rounds or 3,
                             execute=execute_generated)
        text = forge.render(result, decision["request"])
        if out and result["ok"] and result["code"]:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(result["code"])
            text += "\nwrote -> " + out
        return text, 0 if result["ok"] else 2
    return nl._help_unknown(), 1


def _blind_escape_cli(argv) -> int:
    """Parse the blind arena's exact, deliberately tiny CLI surface."""
    ap = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description=(
            "Run Attestor's bounded blind escape arena without loading any other "
            "CLI mode or caller-controlled arena input."),
        add_help=False,
        allow_abbrev=False,
    )
    ap.add_argument("--blind-escape-arena", action="store_true")
    ap.add_argument("--blind-escape-single-episode", action="store_true")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--out", default="")

    tokens = list(argv)
    option_counts = {
        "--blind-escape-arena": tokens.count("--blind-escape-arena"),
        "--blind-escape-single-episode": tokens.count(
            "--blind-escape-single-episode"),
        "--format": sum(
            token == "--format" or token.startswith("--format=")
            for token in tokens),
        "--out": sum(
            token == "--out" or token.startswith("--out=")
            for token in tokens),
    }
    if option_counts["--blind-escape-arena"] != 1:
        ap.error("--blind-escape-arena must be supplied exactly once")
    duplicates = [
        option for option, count in option_counts.items() if count > 1
    ]
    if duplicates:
        ap.error("duplicate option: " + ", ".join(duplicates))

    args = ap.parse_args(tokens)
    text, code = perform(
        {
            "action": _BLIND_ESCAPE_ACTION,
            "single_episode": args.blind_escape_single_episode,
        },
        out=args.out or None,
        request="",
        output_format=args.format,
    )
    if text:
        print(text)
    return code


def main(argv=None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if any(token.startswith("--blind-escape") for token in raw_argv):
        return _blind_escape_cli(raw_argv)
    argv = raw_argv
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False)
    ap.add_argument("request", nargs="*",
                    help="a file, a directory, a GitHub URL, or plain English")
    ap.add_argument("--out", help="write the result (improved file / service / code) here")
    ap.add_argument("--rounds", type=int, default=None,
                    help="max generate/repair passes (mode-specific default when omitted)")
    ap.add_argument("--model", default="",
                    help="pin the LLM model on every provider (e.g. qwen/qwen3-32b)")
    ap.add_argument("--sfw", action="store_true", help="bleep the profanity")
    ap.add_argument("--seed", type=int, default=None, help="pin the persona (CI)")
    ap.add_argument("--curry", action="store_true",
                    help="the thick curry: every provider cooks, Attestor serves the best")
    ap.add_argument("--evolve", action="store_true",
                    help="treat the request as a GitHub file/query to harvest, reread, fix, and rescan")
    ap.add_argument("--ruleforge", action="store_true",
                    help="treat the request as code to mine for candidate detector rules")
    ap.add_argument("--patchforge", action="store_true",
                    help="ask API models for patches, then gate them through Attestor/crucible/tests")
    ap.add_argument("--patchguard", action="store_true",
                    help="verify a candidate replacement transactionally (dry by default)")
    ap.add_argument("--candidate-file", default="",
                    help="with --patchguard, replacement source file")
    ap.add_argument("--project-root", default=".",
                    help="with --patchguard, project root containing the target")
    ap.add_argument("--candidate-name", default="candidate")
    ap.add_argument("--apply-patch", action="store_true",
                    help="explicitly apply a PatchGuard-accepted candidate with backup")
    ap.add_argument("--backup-root", default="")
    ap.add_argument("--execute-generated", action="store_true",
                    help="explicitly allow generated code/tests to run in the restricted runner")
    ap.add_argument("--workspace", action="store_true",
                    help="incremental parallel multi-language workspace scan")
    ap.add_argument("--attestor414", action="store_true",
                    help="Attestor 4.1.4 current maximum with a sealed analysis variant")
    ap.add_argument("--attestor413", "--attestor41", dest="attestor41", action="store_true",
                    help="Attestor 4.1.3 maximum (the --attestor41 spelling remains compatible): shared semantic graph, deep correctness, defensive-security posture, supply-chain/secret lifecycle, repair director, and Truth Guard 3")
    ap.add_argument("--variant", default=None,
                    help="4.1.4 CLI variant alias (default: south-park)")
    ap.add_argument("--computer-scan", action="store_true",
                    help="discover and analyze local projects without a path; permission is denied unless explicitly authorized")
                    help="grant read-only local discovery and analysis permission for this run only")
    ap.add_argument("--computer-scope", choices=("home", "fixed-drives"),
                    default="home",
                    help="bounded discovery scope for --computer-scan (default: home)")
    ap.add_argument("--computer-max-projects", type=int, default=3,
                    help="maximum discovered projects to analyze (1-12; default: 3)")
    ap.add_argument("--computer-improve", action="store_true",
                    help="produce review-only improvement summaries; never apply or write discovered source")
    ap.add_argument("--cjp-control", action="store_true",
                    help="run Cockroach-only exact local-file control from a strict request JSON document")
    ap.add_argument("--confirm-cjp-permission", action="store_true",
                    help="confirm asserted owner/custodian permission for this one local-control run")
    ap.add_argument("--apply-cjp-edit", action="store_true",
                    help="after an authorized preview, request its exact candidate be applied transactionally")
    ap.add_argument("--confirm-cjp-apply", action="store_true",
                    help="separately confirm applying the exact previewed candidate")
    ap.add_argument("--cjp-preview-evidence-sha256", default="",
                    help="exact preview_evidence_sha256 from a prior preview-only CJP run")
    ap.add_argument("--escape-lab", action="store_true",
                    help="run the private in-memory policy-graph escape simulation; never attempts a real escape")
    ap.add_argument(
        "--escape-scenario",
        choices=(escape_lab414.ALL_SCENARIOS, *escape_lab414.SCENARIO_IDS),
        default=None,
        help="compiled simulation scenario for --escape-lab (default: all)",
    )
    ap.add_argument("--attestor40", action="store_true",
                    help="Attestor 4.0 compatibility maximum")
    ap.add_argument("--research", action="store_true",
                    help="deep research for a non-coding question (offline until --online is supplied)")
    ap.add_argument("--online", action="store_true",
                    help="explicitly authorize public-web network access for --research")
    ap.add_argument("--fetch-pages", action="store_true",
                    help="with --research --online, retrieve bounded public pages after search")
    ap.add_argument("--research-max-queries", type=int, default=6)
    ap.add_argument("--research-max-sources", type=int, default=30)
    ap.add_argument("--research-country", default="US")
    ap.add_argument("--research-language", default="en")
    ap.add_argument("--research-freshness", choices=("", "pd", "pw", "pm", "py"), default="")
    ap.add_argument("--attestor3", action="store_true",
                    help="Attestor 3.0 compatibility maximum: semantic, security, supply chain, attack paths, and verified improvements")
    ap.add_argument("--attestor35", action="store_true",
                    help="Attestor 3.5 compatibility maximum: symbolic paths, polyglot IR, Git impact, exact dependency graphs, calibration, and Truth Guard 2")
    ap.add_argument("--improve", action="store_true",
                    help="find errors and return complete verified improved source without applying it")
    ap.add_argument("--semantic", action="store_true",
                    help="whole-program semantic, call-graph, CFG, and interprocedural data-flow analysis")
    ap.add_argument("--supply-chain", action="store_true",
                    help="offline dependency inventory, risks, SBOM, VEX, and provenance evidence")
    ap.add_argument("--repository-memory", action="store_true",
                    help="emit a source-free hashed architecture snapshot")
    ap.add_argument("--max-improvement-files", type=int, default=None,
                    help="repair-file ceiling (4.1.4 variant default; legacy default: 3)")
    ap.add_argument("--improved-out", default="",
                    help="write only complete proof-gate-verified improvements to a separate empty directory; unverified Attestor 4.1.3 review candidates stay in the report")
    ap.add_argument("--memory-out", default="",
                    help="write Attestor 3's privacy-preserving repository snapshot")
    ap.add_argument("--rule-pack", action="append", default=[],
                    help="load a declarative Attestor 3 rule SDK pack")
    ap.add_argument("--semantic-rule-pack", action="append", default=[],
                    help="load an Attestor 4.1.3 declarative semantic rule SDK pack")
    ap.add_argument("--rule-key-file", default="",
                    help="HMAC verification key for rule packs")
    ap.add_argument("--require-signed-packs", action="store_true")
    ap.add_argument("--truth-key-file", default="",
                    help="HMAC-SHA256 key used to authenticate Attestor 4.0/3.5 reports")
    ap.add_argument("--truth-key-id", default="",
                    help="bounded identifier recorded with an authenticated Attestor 4.0/3.5 report")
    ap.add_argument("--mayhem", action="store_true",
                    help="maximum coding gate: quality + security + graph + mutation")
    ap.add_argument("--cybermayhem", action="store_true",
                    help="maximum defensive security posture, SBOM, CWE/OWASP, and attack surface")
    ap.add_argument("--quality-gate", action="store_true",
                    help="enforce grade, severity, scan, repository, and optional test policy")
    ap.add_argument("--min-grade", choices=("A", "B", "C", "D", "F"), default="B")
    ap.add_argument("--max-high", type=int, default=0)
    ap.add_argument("--mutation-limit", type=int, default=12)
    ap.add_argument("--run-tests", action="store_true",
                    help="explicitly execute the bounded --test-command-json argv")
    ap.add_argument("--test-command-json", default="")
    ap.add_argument("--response-style", choices=tuple(dict.fromkeys(
                        response_engine.STYLES + response41.STYLES)),
                    default="professional")
    ap.add_argument("--tools", action="store_true",
                    help="with --workspace, run available safe syntax/compiler adapters")
    ap.add_argument("--no-cache", action="store_true",
                    help="with --workspace, disable content-hash result caching")
    ap.add_argument("--format", choices=("text", "json", "sarif", "html", "markdown", "sbom",
                                          "cyclonedx", "spdx", "spdx-2.3", "vex"), default="text",
                    help="workspace report format")
    ap.add_argument("--sieve", action="store_true",
                    help="write/load code, review, improve, review again, repeat, then print")
    ap.add_argument("--codemax", action="store_true",
                    help="maximum coding pass: grade, map, refine, test skeleton, or prompt sieve")
    ap.add_argument("--codepower", action="store_true",
                    help="Attestor 2 coding suite: architect, tests, types, performance, docs, contracts")
    ap.add_argument("--securitymax", action="store_true",
                    help="Attestor 2 defensive security suite: OWASP, SARIF, threat model, patch guidance")
    ap.add_argument("--attestor2", action="store_true",
                    help="Attestor 2 maximum review: Code Power + Security Max together")
    ap.add_argument("--rarebugs", action="store_true",
                    help="scan Python for rare correctness traps that ordinary review misses")
    ap.add_argument("--reproduce", action="store_true",
                    help="generate a tiny runnable reproducer for the first finding in a file")
    ap.add_argument("--projectbrain", action="store_true",
                    help="analyze a project tree: imports, calls, routes, env, DB, dead code, flows")
    ap.add_argument("--cyber", action="store_true",
                    help="defensive security scan: secrets, auth, taint, crypto, deps, config")
    ap.add_argument("--polyglot", action="store_true",
                    help="scan C, C++, Haskell, and Assembly for tiny low-level bugs")
    ap.add_argument("--grade", action="store_true",
                    help="grade Python files A-F: fuses detect+deepscan+metrics into one score")
    ap.add_argument("--refine", action="store_true",
                    help="improve a Python file to a fixed point: examine, fix, repeat, print")
    ap.add_argument("--nativegrade", action="store_true",
                    help="grade C/C++/Assembly files A-F: fuses nativescan+polyglot+nativemetrics")
    ap.add_argument("--factory", action="store_true",
                    help="the code factory: generate N services and verify every file is grade A")
    ap.add_argument("--gauntlet", action="store_true",
                    help="mutate a Python file and report whether Attestor/test gates catch the bugs")
    ap.add_argument("--arena", action="store_true",
                    help="print the Code Arena benchmark dashboard")
    ap.add_argument("--fixmemory", action="store_true",
                    help="print Attestor's recorded repeated repair patterns")
    ap.add_argument("--darwin", action="store_true",
                    help="use Darwin payloads: stats, list, search QUERY, or show CATEGORY")
    ap.add_argument("--lang", help="with --evolve/--ruleforge, restrict GitHub search by language")
    ap.add_argument("--limit", type=int, default=1,
                    help="with --evolve/--ruleforge, number of GitHub search results to process")
    ap.add_argument("--pick", type=int, default=0,
                    help="with --ruleforge, first GitHub search result index")
    ap.add_argument("--cycles", type=int, default=5,
                    help="with --evolve, max review/fix/reread cycles per file")
    args = ap.parse_args(argv)

    explicit_modes = [
        name for name, enabled in (
            ("--attestor414", args.attestor414),
            ("--attestor413/--attestor41", args.attestor41),
            ("--computer-scan", args.computer_scan),
            ("--cjp-control", args.cjp_control),
            ("--escape-lab", args.escape_lab),
            ("--research", args.research),
            ("--attestor40", args.attestor40),
            ("--attestor35", args.attestor35),
            ("--attestor3", args.attestor3),
            ("--improve", args.improve),
            ("--semantic", args.semantic),
            ("--supply-chain", args.supply_chain),
            ("--repository-memory", args.repository_memory),
            ("--mayhem", args.mayhem),
            ("--cybermayhem", args.cybermayhem),
            ("--quality-gate", args.quality_gate),
            ("--patchguard", args.patchguard),
            ("--workspace", args.workspace),
            ("--arena", args.arena),
            ("--fixmemory", args.fixmemory),
            ("--darwin", args.darwin),
            ("--patchforge", args.patchforge),
            ("--sieve", args.sieve),
            ("--codemax", args.codemax),
            ("--codepower", args.codepower),
            ("--securitymax", args.securitymax),
            ("--attestor2", args.attestor2),
            ("--rarebugs", args.rarebugs),
            ("--reproduce", args.reproduce),
            ("--projectbrain", args.projectbrain),
            ("--cyber", args.cyber),
            ("--polyglot", args.polyglot),
            ("--grade", args.grade),
            ("--nativegrade", args.nativegrade),
            ("--factory", args.factory),
            ("--refine", args.refine),
            ("--gauntlet", args.gauntlet),
            ("--ruleforge", args.ruleforge),
            ("--evolve", args.evolve),
        ) if enabled
    ]
    if len(explicit_modes) > 1:
        ap.error(
            "conflicting top-level modes: " + ", ".join(explicit_modes))
    if args.max_high < 0:
        ap.error("--max-high cannot be negative")
    if not 0 <= args.mutation_limit <= 64:
        ap.error("--mutation-limit must be between 0 and 64")
    if (args.max_improvement_files is not None and
            not 0 <= args.max_improvement_files <=
            variant414.COCKROACH_JANTA_PARTY.max_improvement_files):
        ap.error("--max-improvement-files must be between 0 and 12")
    if not 1 <= args.computer_max_projects <= computer_scan41.MAX_PROJECTS:
        ap.error("--computer-max-projects must be between 1 and 12")
    test_command = None
    if args.test_command_json:
        try:
            test_command = json.loads(args.test_command_json)
            qualitygate._validate_command(test_command)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            ap.error("--test-command-json must be a bounded JSON argv list: %s" % exc)
    if args.run_tests and not test_command:
        ap.error("--run-tests requires --test-command-json")
    if args.apply_patch and not args.patchguard:
        ap.error("--apply-patch is only valid with --patchguard")
    if args.confirm_cjp_apply and not args.apply_cjp_edit:
        ap.error("--confirm-cjp-apply requires --apply-cjp-edit")
    if args.cjp_preview_evidence_sha256 and not args.apply_cjp_edit:
        ap.error(
            "--cjp-preview-evidence-sha256 requires --apply-cjp-edit")
    if args.escape_scenario is not None and not args.escape_lab:
        ap.error("--escape-scenario is only valid with --escape-lab")
    if args.apply_cjp_edit and cjp_control414.SHA256_RE.fullmatch(
            args.cjp_preview_evidence_sha256) is None:
        ap.error(
            "--apply-cjp-edit requires the exact lowercase "
            "--cjp-preview-evidence-sha256 from a prior preview-only run")
    if args.patchguard and not args.candidate_file:
        ap.error("--patchguard requires --candidate-file")
    if args.require_signed_packs and not args.rule_key_file:
        ap.error("--require-signed-packs requires --rule-key-file")
    try:
        rule_pack_key = Path(args.rule_key_file).read_bytes() if args.rule_key_file else None
    except OSError as exc:
        ap.error("--rule-key-file cannot be read: %s" % type(exc).__name__)
    try:
        truth_key = Path(args.truth_key_file).read_bytes() if args.truth_key_file else None
    except OSError as exc:
        ap.error("--truth-key-file cannot be read: %s" % type(exc).__name__)
    if truth_key is not None and not args.truth_key_id:
        ap.error("--truth-key-file requires --truth-key-id")
    if args.truth_key_id and truth_key is None:
        ap.error("--truth-key-id requires --truth-key-file")

    request = " ".join(args.request).strip()
    if not request and not (args.arena or args.fixmemory or args.darwin
                            or args.cyber or args.polyglot or args.grade
                            or args.securitymax or args.rarebugs
                            or args.nativegrade or args.factory or args.workspace
                             or args.attestor414 or args.attestor41 or args.computer_scan
                            or args.escape_lab
                            or args.attestor40 or args.attestor35 or args.attestor3
                            or args.improve or args.semantic
                            or args.supply_chain or args.repository_memory
                            or args.mayhem or args.cybermayhem or args.quality_gate):
        ap.error("request is required unless --arena, --fixmemory, --darwin, "
                 "--cyber, --polyglot, --grade, --securitymax, --rarebugs, "
                  "--nativegrade, --factory, --workspace, --attestor414, "
                  "--attestor413/--attestor41, --computer-scan, --attestor40, "
                  "--escape-lab, "
                  "--attestor35, --attestor3, --improve, "
                  "--semantic, --supply-chain, --repository-memory, --mayhem, --cybermayhem, "
                  "or --quality-gate is used")
    low_request = request.lower()
    compare_mode = args.patchforge or low_request.startswith(
        ("patchforge ", "patch forge ", "forge patch ", "patch this "))
    bus = build_brain(args.model, mode="compare" if compare_mode else "fallback")
    persona, rng = attestor.pick_persona(args.seed)
    research_requested = args.research or low_request.startswith(
        ("deep research ", "web research ", "research "))
    computer_requested = args.computer_scan or decide(request).get("action") == "computer41"
    escape_requested = args.escape_lab or low_request in _ESCAPE_LAB_REQUESTS
    machine_output = (args.workspace or args.attestor414 or args.attestor41
                      or args.cjp_control
                      or escape_requested
                      or computer_requested or args.attestor40 or args.attestor35
                      or args.attestor3 or args.improve or args.semantic
                      or research_requested
                      or args.supply_chain or args.repository_memory or args.mayhem
                      or args.cybermayhem or args.quality_gate) \
        and args.format in {"json", "sarif", "html", "sbom", "cyclonedx", "spdx",
                            "spdx-2.3", "vex"}
    if not machine_output and args.response_style == "classic":
        print(P.censor(rng.choice(persona.wake), args.sfw))
        siblings = ", ".join(bus.provider_names()) if bus.available() else \
            "none awake (offline powers only; set GROQ_API_KEY or a sibling)"
        print(f"   [brain] {siblings}  [provider candidates x deterministic evidence gates]")
        print()

    if args.attestor414:
        decision = {"action": "attestor414", "path": request or "."}
    elif args.attestor41:
        decision = {"action": "attestor41", "path": request or "."}
    elif args.cjp_control:
        decision = {
            "action": "cjpcontrol414",
            "request_file": request,
        }
    elif args.escape_lab:
        decision = {
            "action": "escapelab414",
            "scenario": (
                args.escape_scenario or escape_lab414.ALL_SCENARIOS),
        }
    elif args.computer_scan:
        decision = {"action": "computer41"}
    elif args.research:
        decision = {"action": "research41", "question": request}
    elif args.attestor40:
        decision = {"action": "attestor40", "path": request or "."}
    elif args.attestor35:
        decision = {"action": "attestor35", "path": request or "."}
    elif args.attestor3:
        decision = {"action": "attestor3", "path": request or "."}
    elif args.improve:
        decision = {"action": "improve", "path": request or "."}
    elif args.semantic:
        decision = {"action": "semantic", "path": request or "."}
    elif args.supply_chain:
        decision = {"action": "supplychain", "path": request or "."}
    elif args.repository_memory:
        decision = {"action": "repositorymemory", "path": request or "."}
    elif args.mayhem:
        decision = {"action": "mayhem", "path": request or "."}
    elif args.cybermayhem:
        decision = {"action": "cybermayhem", "path": request or "."}
    elif args.quality_gate:
        decision = {"action": "qualitygate", "path": request or "."}
    elif args.patchguard:
        decision = {"action": "patchguard", "project": args.project_root,
                    "target": request, "candidate": args.candidate_file,
                    "name": args.candidate_name}
    elif args.workspace:
        decision = {"action": "workspace", "path": request or "."}
    elif args.arena:
        decision = {"action": "arena"}
    elif args.fixmemory:
        decision = {"action": "fixmemory"}
    elif args.darwin:
        parts = request.split(maxsplit=1)
        cmd = parts[0].lower() if parts else "stats"
        query = parts[1] if len(parts) > 1 else ""
        if cmd not in ("stats", "list", "search", "show"):
            cmd, query = "search", request
        decision = {"action": "darwin", "cmd": cmd, "query": query}
    elif args.patchforge:
        decision = {"action": "patchforge", "target": request}
    elif args.sieve:
        decision = {"action": "sieve", "target": request}
    elif args.codemax:
        decision = {"action": "codemax", "target": request}
    elif args.codepower:
        decision = {"action": "codepower", "target": request}
    elif args.securitymax:
        decision = {"action": "securitymax", "path": request or "."}
    elif args.attestor2:
        decision = {"action": "attestor2", "target": request}
    elif args.rarebugs:
        decision = {"action": "rarebugs", "path": request or "."}
    elif args.reproduce:
        decision = {"action": "reproduce", "target": request}
    elif args.projectbrain:
        decision = {"action": "projectbrain", "path": request}
    elif args.cyber:
        decision = {"action": "cyber", "path": request or "."}
    elif args.polyglot:
        decision = {"action": "polyglot", "path": request or "."}
    elif args.grade:
        decision = {"action": "grade", "path": request or "."}
    elif args.nativegrade:
        decision = {"action": "nativegrade", "path": request or "."}
    elif args.factory:
        decision = {"action": "factory", "count": request or "20"}
    elif args.refine:
        decision = {"action": "refine", "target": request}
    elif args.gauntlet:
        decision = {"action": "gauntlet", "target": request}
    elif args.ruleforge:
        decision = {"action": "ruleforge", "target": request}
    elif args.evolve:
        decision = {"action": "evolve", "target": request}
    else:
        decision = decide(request, bus)
    variant_profile = None
    if args.variant is not None:
        if decision.get("action") not in {"attestor414", "improve"}:
            ap.error(
                "--variant is only valid with Attestor 4.1.4 or improvement mode")
        try:
            variant_profile = variant414.parse_profile(args.variant)
        except variant414.VariantError as exc:
            ap.error("--variant is invalid: %s" % exc)
    elif decision.get("action") in {"attestor414", "improve"}:
        variant_profile = variant414.DEFAULT_PROFILE
    effective_max_improvement_files = (
        variant_profile.max_improvement_files
        if args.max_improvement_files is None and variant_profile is not None
        else 3 if args.max_improvement_files is None
        else args.max_improvement_files
    )
    if (args.rule_pack or args.semantic_rule_pack or args.rule_key_file or args.require_signed_packs) and \
            decision.get("action") not in {
                "attestor414", "attestor41", "attestor40", "attestor35", "attestor3", "improve"}:
        ap.error(
            "rule-pack options are only valid with Attestor "
            "4.1.4/4.1.3/4.0/3.5/3.0/improve")
    if args.semantic_rule_pack and decision.get("action") not in {
            "attestor414", "attestor41", "improve"}:
        ap.error(
            "--semantic-rule-pack is only valid with Attestor 4.1.4/4.1.3/improve")
    if (args.truth_key_file or args.truth_key_id) and \
            decision.get("action") not in {
                "attestor414", "attestor41", "attestor40", "attestor35", "improve"}:
        ap.error(
            "truth-key options are only valid with Attestor "
            "4.1.4/4.1.3/4.0/3.5/improve")
    if args.improved_out and decision.get("action") not in {
            "attestor414", "attestor41", "attestor40", "attestor35", "attestor3", "improve"}:
        ap.error(
            "--improved-out is only valid with Attestor "
            "4.1.4/4.1.3/4.0/3.5/3.0/improve")
    if args.memory_out and decision.get("action") not in {"attestor40", "attestor35", "attestor3"}:
        ap.error("--memory-out is only valid with Attestor 4.0/3.5/3.0 compatibility modes")
    if args.response_style == "technical" and decision.get("action") not in {
            "attestor414", "attestor41", "improve"}:
        ap.error(
            "--response-style technical is only valid with Attestor "
            "4.1.4/4.1.3/improve")
    if (args.online or args.fetch_pages) and decision.get("action") != "research41":
        ap.error("--online and --fetch-pages are only valid with Attestor 4.1.3 research")
    if args.fetch_pages and not args.online:
        ap.error("--fetch-pages requires --online")
    if decision.get("action") == "research41" and not str(
            decision.get("question", "")).strip():
        ap.error("Attestor research requires a non-empty question")
    if decision.get("action") == "research41" and args.format not in {"text", "json"}:
        ap.error("Attestor research supports --format text or json")
    if (args.authorize_computer_scan or args.computer_improve or
            args.computer_scope != "home" or args.computer_max_projects != 3) and \
            decision.get("action") != "computer41":
        ap.error("computer-scan options are only valid with --computer-scan or a computer-scan request")
    if decision.get("action") == "computer41" and args.format not in {"text", "json"}:
        ap.error("Attestor computer scan supports --format text or json")
    if (args.confirm_cjp_permission or args.apply_cjp_edit or
            args.confirm_cjp_apply or args.cjp_preview_evidence_sha256) and \
            decision.get("action") != "cjpcontrol414":
        ap.error(
            "Cockroach local-control confirmations are valid only with "
            "--cjp-control")
    if decision.get("action") == "cjpcontrol414":
        if not request:
            ap.error("--cjp-control requires a request JSON path")
        if args.format not in {"text", "json"}:
            ap.error("Cockroach local control supports --format text or json")
    if decision.get("action") == "escapelab414" and args.format not in {
            "text", "json"}:
        ap.error("Attestor private escape lab supports --format text or json")
    if not 1 <= args.research_max_queries <= research_engine41.MAX_QUERIES:
        ap.error("--research-max-queries is outside the bounded policy")
    if not 1 <= args.research_max_sources <= research_engine41.MAX_RESULTS:
        ap.error("--research-max-sources is outside the bounded policy")
    text, code = perform(decision, out=args.out, rounds=args.rounds, bus=bus,
                         curry_mode=args.curry, evolve_lang=args.lang,
                         evolve_limit=args.limit, evolve_cycles=args.cycles,
                         ruleforge_pick=args.pick, request=request,
                         execute_generated=args.execute_generated,
                         external_tools=args.tools, use_cache=not args.no_cache,
                         output_format=args.format, min_grade=args.min_grade,
                         max_high=args.max_high, mutation_limit=args.mutation_limit,
                         run_tests=args.run_tests, test_command=test_command,
                         response_style=args.response_style,
                         apply_patch_authorized=args.apply_patch,
                         backup_root=args.backup_root,
                         max_improvement_files=effective_max_improvement_files,
                         improved_out=args.improved_out, memory_out=args.memory_out,
                          rule_packs=args.rule_pack,
                          semantic_rule_packs=args.semantic_rule_pack,
                          rule_pack_key=rule_pack_key,
                          require_signed_packs=args.require_signed_packs,
                          truth_key=truth_key, truth_key_id=args.truth_key_id,
                          research_online=args.online,
                          research_fetch_pages=args.fetch_pages,
                          research_max_queries=args.research_max_queries,
                          research_max_sources=args.research_max_sources,
                          research_country=args.research_country,
                          research_language=args.research_language,
                          research_freshness=args.research_freshness,
                          computer_authorized=args.authorize_computer_scan,
                          computer_scope=args.computer_scope,
                          computer_max_projects=args.computer_max_projects,
                          computer_review_improvements=args.computer_improve,
                          cjp_permission_confirmed=args.confirm_cjp_permission,
                          cjp_apply=args.apply_cjp_edit,
                          cjp_apply_confirmed=args.confirm_cjp_apply,
                          cjp_preview_evidence_sha256=(
                              args.cjp_preview_evidence_sha256),
                          variant_profile=variant_profile)
    if (text and args.format == "text" and args.response_style != "classic"
            and decision.get("action") not in {
                "attestor414", "attestor41", "computer41", "cjpcontrol414",
                "escapelab414", _BLIND_ESCAPE_ACTION,
                "attestor40", "attestor35",
                "attestor3", "improve", "research41", "semantic",
                                                "supplychain", "repositorymemory",
                                                "mayhem", "cybermayhem"}):
        text = response_engine.wrap_text(
            text, code, decision.get("action", "request"), args.response_style,
            model_assisted=decision.get("action") in {
                "forge", "patchforge", "sieve", "webscan",
            })
    if text:
        print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
