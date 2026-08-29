#!/usr/bin/env python3
"""Secure local web interface for the Attestor 4.2 distribution.

The distribution serves the Attestor 4.1.4 engineering and security analysis
engine/protocol. The server is loopback-only. Browser requests require a
per-launch token, JSON content type, a valid Host, and a same-origin Origin.
Expensive work runs as bounded, cancellable jobs instead of occupying an
unbounded request thread.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import ipaddress
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
# The launcher uses Python isolated mode. Add only Attestor's resolved, trusted
# detector directory so this server can read its own catalog metadata without
# restoring the working directory or environment-controlled import paths.
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import precision_catalog
import secret_guard
import truth_guard41
import attestor414
import cjp_authorization414
import variant414
import blind_escape_arena414
from evidence_store41 import EvidenceStore, EvidenceStoreError, default_history_path
UI_DIR = HERE / "ui"
INDEX = UI_DIR / "index.html"
UI_SCRIPT = UI_DIR / "ui23.js"
UI_STYLES = UI_DIR / "ui23.css"
DEFAULT_TIMEOUT = 120
MAX_BODY_BYTES = 128 * 1024
# Historical and non-variant modes retain the established 4 MiB capture
# boundary. Attestor 4.1.4 variant runs derive their stdout boundary from the
# immutable compiled profile instead.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_LIMIT = 100
MIN_TIMEOUT = 1
MAX_TIMEOUT = 600
# The selected worker limit is not an end-to-end orchestrator limit.  A current
# run first executes inherited compatibility analysis and then verifies the
# bounded workers/report.  Give that complete process a separately named,
# deterministic outer boundary so the UI cannot kill a worker at the exact
# instant its own profile budget expires.
VARIANT_PROCESS_TIMEOUT_MULTIPLIER = 3
MAX_ACTIVE_JOBS = 2
MAX_JOB_HISTORY = 100
MAX_PENDING_JOBS = 32
MAX_CONNECTIONS = 12
VERSION_LABELS = (
    "Attestor 1.0", "Attestor 1.1", "Attestor 1.25", "Attestor 1.3", "Attestor 1.4",
    "Attestor 1.5", "Attestor 1.65", "Attestor 1.9", "Attestor 2", "Attestor 2.1", "Attestor 2.2",
    "Attestor 2.3", "Attestor 3.0", "Attestor 3.5", "Attestor 4.0", "Attestor 4.1", "Attestor 4.1.2",
    "Attestor 4.1.3", "Attestor 4.1.4",
)
CURRENT_VERSION = "Attestor 4.1.4"
UI_VERSION = "4.1.4"
DISTRIBUTION_VERSION = "Attestor 4.2"
VARIANT_MODES = frozenset({"attestor41", "improve", "cjpcontrol"})
DEFAULT_VARIANT = variant414.DEFAULT_PROFILE.slug
RESPONSE_STYLES = {"professional", "concise", "mentor", "direct", "executive", "classic"}
REPORT_MODES = {
    "workspace", "mayhem", "cybermayhem", "qualitygate", "patchguard",
    "cyber", "polyglot", "grade", "nativegrade", "securitymax", "rarebugs",
    "gauntlet", "factory", "darwin", "reproduce",
    "attestor41", "attestor40", "attestor35", "attestor3", "improve", "semantic", "supplychain", "repositorymemory",
    "research", "computer41", "cjpcontrol", "escapelab",
}

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; style-src 'self'; script-src 'self'; "
    "img-src 'self' data:; media-src 'none'; connect-src 'self'; "
    "object-src 'none'; worker-src 'none'; frame-ancestors 'none'; "
    "form-action 'none'; base-uri 'none'"
)

STATIC_ASSETS = {
    "/ui23.js": (UI_SCRIPT, "text/javascript; charset=utf-8"),
    "/ui23.css": (UI_STYLES, "text/css; charset=utf-8"),
    # Old bookmarks remain harmless and receive the current, secured client.
    "/ui22.js": (UI_SCRIPT, "text/javascript; charset=utf-8"),
}

MODE_FLAGS = {
    "chat": "",
    "arena": "--arena",
    "fixmemory": "--fixmemory",
    "darwin": "--darwin",
    "project": "--projectbrain",
    "workspace": "--workspace",
    "research": "--research",
    "computer41": "--computer-scan",
    "cjpcontrol": "--cjp-control",
    "escapelab": "--escape-lab",
    "attestor41": "--attestor41",
    "attestor40": "--attestor40",
    "attestor35": "--attestor35",
    "attestor3": "--attestor3",
    # The current maximum orchestrator retains verified improvement generation.
    "improve": "--attestor41",
    "semantic": "--semantic",
    "supplychain": "--supply-chain",
    "repositorymemory": "--repository-memory",
    "mayhem": "--mayhem",
    "cybermayhem": "--cybermayhem",
    "qualitygate": "--quality-gate",
    "patchguard": "--patchguard",
    "cyber": "--cyber",
    "polyglot": "--polyglot",
    "grade": "--grade",
    "nativegrade": "--nativegrade",
    "factory": "--factory",
    "refine": "--refine",
    "sieve": "--sieve",
    "codemax": "--codemax",
    "codepower": "--codepower",
    "securitymax": "--securitymax",
    "attestor2": "--attestor2",
    "rarebugs": "--rarebugs",
    "patch": "--patchforge",
    "reproduce": "--reproduce",
    "gauntlet": "--gauntlet",
}


def _version_root(label: str) -> Path:
    return Path(os.environ.get("ATTESTOR_VERSION_ROOT", "D:/")) / label


def _detector_for_version(label: str) -> Path | None:
    if label is None or label == "":
        label = CURRENT_VERSION
    if not isinstance(label, str):
        return None
    label = label.strip()
    if label not in VERSION_LABELS:
        return None
    if label == CURRENT_VERSION:
        return HERE
    root = _version_root(label)
    candidates = [
        root / "AttestorVonLuneberg_Darwin_Merged" / "detector",
        root / "AttestorVonLuneberg" / "detector",
        root / "AttestorVonLuneberg2" / "detector",
        root / label / "detector",
        root / "detector",
    ]
    for detector in candidates:
        if (detector / "superattestor.py").is_file():
            return detector.resolve()
    if root.exists():
        try:
            for found in root.rglob("superattestor.py"):
                return found.resolve().parent
        except OSError:
            return None
    return None


def _capabilities(detector: Path | None) -> list[str]:
    if detector is None:
        return []
    if detector.resolve() == HERE:
        return sorted(MODE_FLAGS)
    try:
        source = (detector / "superattestor.py").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ["chat"]
    modes = ["chat"]
    for mode, flag in MODE_FLAGS.items():
        if mode != "chat" and flag and flag in source:
            modes.append(mode)
    return sorted(set(modes))


def _variant_descriptor(
        profile: variant414.VariantProfile) -> dict[str, object]:
    """Return the bounded, non-authority profile metadata exposed to the UI."""
    selected = variant414.require_compiled_profile(profile)
    return {
        "slug": selected.slug,
        "display_name": selected.display_name,
        "mode": selected.mode,
        "response_language":
            variant414.response_language_metadata(selected),
        "profile_sha256": variant414.profile_identity(selected),
        "timeout_seconds": _variant_process_timeout(selected),
        "worker_timeout_seconds": selected.max_worker_seconds,
        "max_output_bytes": selected.max_ui_output_bytes,
    }


def _variant_process_timeout(
        profile: variant414.VariantProfile) -> int:
    """Return the immutable outer UI budget for one profile-bound run."""
    selected = variant414.require_compiled_profile(profile)
    return min(
        MAX_TIMEOUT,
        max(DEFAULT_TIMEOUT,
            selected.max_worker_seconds * VARIANT_PROCESS_TIMEOUT_MULTIPLIER),
    )


def available_variants() -> list[dict[str, object]]:
    return [_variant_descriptor(profile)
            for profile in variant414.COMPILED_PROFILES]


def available_versions() -> dict:
    out = {}
    for label in VERSION_LABELS:
        detector = _detector_for_version(label)
        out[label] = {
            "available": detector is not None,
            "detector": str(detector) if detector else "",
            "modes": _capabilities(detector),
            "variants": (
                [profile.slug for profile in variant414.COMPILED_PROFILES]
                if label == CURRENT_VERSION else []
            ),
        }
    return out


def _safe_env() -> dict:
    env = os.environ.copy()
    for key in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"):
        env.pop(key, None)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _bounded_int(value, default: int, min_value: int, max_value: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_value, min(number, max_value))


def _variant_profile_for_request(
        mode: str, version: object, value: object = None,
) -> variant414.VariantProfile | None:
    """Resolve only exact HTTP/UI slugs for the current variant-capable modes."""
    if type(mode) is not str or type(version) is not str:
        raise ValueError("Attestor mode and version must be text.")
    normalized_mode = mode.strip().lower()
    if normalized_mode == "cjpcontrol":
        if version != CURRENT_VERSION:
            raise ValueError(
                "Cockroach local control is available only in Attestor 4.1.4.")
        try:
            selected = (
                variant414.COCKROACH_JANTA_PARTY
                if value is None else variant414.profile_for_slug(value))
            selected = variant414.require_compiled_profile(selected)
        except variant414.VariantError as exc:
            raise ValueError(
                "Cockroach local control requires its exact canonical slug."
            ) from exc
        if selected is not variant414.COCKROACH_JANTA_PARTY:
            raise ValueError(
                "Cockroach local control cannot use South Park or Gruppe Sechs.")
        return selected
    applicable = version == CURRENT_VERSION and normalized_mode in VARIANT_MODES
    if not applicable:
        if value is not None:
            raise ValueError(
                "Attestor variants are only valid for current 4.1.4 maximum modes.")
        return None
    if value is None:
        return variant414.DEFAULT_PROFILE
    try:
        return variant414.profile_for_slug(value)
    except variant414.VariantError as exc:
        raise ValueError(
            "Variant must be one exact Attestor 4.1.4 canonical slug.") from exc


def _base_args(
        mode: str, response_style: str = "professional", *,
        current_variant_mode: bool = False,
) -> list[str]:
    flag = MODE_FLAGS.get(mode)
    if flag is None:
        raise ValueError("Unknown Attestor mode: %s" % mode)
    if response_style not in RESPONSE_STYLES:
        raise ValueError("Unknown Attestor response style.")
    args = ["--sfw", "--seed", "1", "--response-style", response_style]
    if current_variant_mode and mode != "cjpcontrol":
        flag = "--attestor414"
    if flag:
        args.append(flag)
    if mode in {"attestor41", "attestor40", "attestor35", "attestor3", "improve", "semantic", "supplychain", "repositorymemory", "research", "computer41", "cjpcontrol", "escapelab"}:
        args.extend(["--format", "json"])
    return args


def build_args(mode: str, prompt: str, limit: int = 8,
               response_style: str = "professional", *,
               version: object = CURRENT_VERSION,
               variant: object = None,
               research_online: bool = False,
               research_fetch_pages: bool = False,
               computer_authorized: bool = False,
               computer_scope: str = "home",
               computer_max_projects: int = 3,
               computer_improve: bool = False,
               cjp_permission_confirmed: bool = False,
               cjp_apply: bool = False,
               cjp_apply_confirmed: bool = False,
               cjp_preview_evidence_sha256: str = "") -> list[str]:
    """Translate UI modes to CLI args without allowing option injection."""
    if prompt is None:
        prompt = ""
    if mode is None:
        mode = "chat"
    if not isinstance(prompt, str) or not isinstance(mode, str):
        raise ValueError("Attestor mode and prompt must be text.")
    prompt = prompt.strip()
    mode = mode.strip().lower()
    profile = _variant_profile_for_request(mode, version, variant)
    if mode == "escapelab" and version != CURRENT_VERSION:
        raise ValueError(
            "The private escape lab is available only in Attestor 4.1.4.")
    # Network authorization is fail-closed: JSON strings, numbers, and other
    # truthy values never become permission to access the public web.
    research_online = research_online is True
    research_fetch_pages = research_fetch_pages is True
    # Local discovery authorization is equally fail-closed. In particular, JSON
    # strings such as "true" must never authorize reading beyond a supplied path.
    computer_authorized = computer_authorized is True
    computer_improve = computer_improve is True
    cjp_permission_confirmed = cjp_permission_confirmed is True
    cjp_apply = cjp_apply is True
    cjp_apply_confirmed = cjp_apply_confirmed is True
    if type(cjp_preview_evidence_sha256) is not str:
        raise ValueError("CJP preview evidence must be a text SHA-256.")
    if mode != "research" and (research_online or research_fetch_pages):
        raise ValueError("Online research controls are only valid in Research mode.")
    if mode != "computer41" and (
            computer_authorized or computer_improve or
            computer_scope != "home" or computer_max_projects != 3):
        raise ValueError("Computer scan controls are only valid in Computer Scan mode.")
    if mode != "cjpcontrol" and (
            cjp_permission_confirmed or cjp_apply or cjp_apply_confirmed
            or cjp_preview_evidence_sha256):
        raise ValueError(
            "Cockroach local-control permissions are valid only in that mode.")
    limit = _bounded_int(limit, 8, 1, MAX_LIMIT)
    args = _base_args(
        mode, response_style, current_variant_mode=profile is not None)
    if profile is not None and mode != "cjpcontrol":
        # Every option is placed before the terminator; target text remains
        # data and can never inject or replace the compiled variant.
        args.extend(["--variant", profile.slug])
    if mode == "cjpcontrol":
        if not prompt:
            raise ValueError(
                "Cockroach local control needs a strict request JSON path.")
        if profile is not variant414.COCKROACH_JANTA_PARTY:
            raise ValueError(
                "Cockroach local control requires its exact compiled profile.")
        if cjp_apply and not cjp_permission_confirmed:
            raise ValueError(
                "Applying an edit requires owner-permission confirmation.")
        if cjp_apply_confirmed and not cjp_apply:
            raise ValueError(
                "Separate apply confirmation requires an apply request.")
        if cjp_preview_evidence_sha256 and not cjp_apply:
            raise ValueError(
                "Preview evidence is valid only for a separate apply request.")
        if cjp_apply and cjp_authorization414.SHA256_RE.fullmatch(
                cjp_preview_evidence_sha256) is None:
            raise ValueError(
                "Applying requires the exact preview evidence SHA-256 from "
                "a prior preview-only run.")
        if cjp_permission_confirmed:
            args.append("--confirm-cjp-permission")
        if cjp_apply:
            args.append("--apply-cjp-edit")
        if cjp_apply_confirmed:
            args.append("--confirm-cjp-apply")
        if cjp_preview_evidence_sha256:
            args.extend([
                "--cjp-preview-evidence-sha256",
                cjp_preview_evidence_sha256,
            ])
        args.extend(["--", prompt])
        return args
    if mode == "escapelab":
        if prompt:
            raise ValueError(
                "The private escape lab does not accept a prompt or path.")
        # Selecting this explicit UI mode requests only Attestor's compiled,
        # deterministic in-memory policy simulation. No caller-controlled
        # target is forwarded to the CLI.
        return args
    if mode == "research":
        if not prompt:
            raise ValueError("Research needs a non-coding question.")
        if research_fetch_pages and not research_online:
            raise ValueError("Page fetching requires explicit online research authorization.")
        if research_online:
            args.append("--online")
        if research_fetch_pages:
            args.append("--fetch-pages")
        args.extend(["--", prompt])
        return args
    if mode == "computer41":
        if not isinstance(computer_scope, str):
            raise ValueError("Computer scan scope must be text.")
        computer_scope = computer_scope.strip().lower()
        if computer_scope not in {"home", "fixed-drives"}:
            raise ValueError("Computer scan scope must be 'home' or 'fixed-drives'.")
        if type(computer_max_projects) is not int:
            raise ValueError("Computer scan project limit must be between 1 and 12.")
        project_limit = computer_max_projects
        if not 1 <= project_limit <= 12:
            raise ValueError("Computer scan project limit must be between 1 and 12.")
        if computer_improve and not computer_authorized:
            raise ValueError("Review-only computer improvements require computer scan authorization.")
        if computer_authorized:
            args.append("-computer-scan")
        args.extend(["--computer-scope", computer_scope,
                     "--computer-max-projects", str(project_limit)])
        if computer_improve:
            args.append("--computer-improve")
        # This mode discovers eligible local projects itself. Never append a UI
        # prompt as a path or positional argument.
        return args
    if mode in ("arena", "fixmemory"):
        return args
    if mode == "darwin":
        args.extend(["--limit", str(limit), "--", "search", prompt or "graphql"])
        return args
    if mode == "factory":
        try:
            count = int(prompt or "20")
        except ValueError as exc:
            raise ValueError("Code Factory needs a service count between 1 and 64.") from exc
        if not 1 <= count <= 64:
            raise ValueError("Code Factory needs a service count between 1 and 64.")
        args.extend(["--", str(count)])
        return args
    if mode == "patchguard":
        parts = [part.strip() for part in prompt.split("::")]
        if len(parts) == 2 and all(parts):
            project, target, candidate = ".", parts[0], parts[1]
        elif len(parts) == 3 and all(parts):
            project, target, candidate = parts
        else:
            raise ValueError(
                "Patch Guard needs 'target :: candidate-file' or "
                "'project :: target :: candidate-file'.")
        args.extend(["--project-root=" + project, "--candidate-file=" + candidate,
                     "--", target])
        return args
    defaults = {
        "project": ".", "workspace": ".", "grade": ".", "nativegrade": ".",
        "securitymax": ".", "rarebugs": ".", "mayhem": ".",
        "cybermayhem": ".", "qualitygate": ".",
        "attestor41": ".", "attestor40": ".", "attestor35": ".", "attestor3": ".", "improve": ".", "semantic": ".", "supplychain": ".",
        "repositorymemory": ".",
    }
    required = {
        "cyber": "Cyber Sentinel needs a file or folder path.",
        "polyglot": "Polyglot Tiny Bugs needs a C/C++/Haskell/Assembly path.",
        "refine": "Refine needs a Python file path.",
        "sieve": "Sieve needs a file path or coding request.",
        "codemax": "Code Max needs a Python file, folder, or coding request.",
        "codepower": "Code Power needs a Python file, folder, or coding request.",
        "attestor2": "Attestor 2 Max needs a file, folder, or coding request.",
        "patch": "Patch Forge needs a file path.",
        "reproduce": "Bug Reproducer needs a file path.",
        "gauntlet": "Mutation Gauntlet needs a Python file path.",
        "chat": "Type something for Attestor to do.",
    }
    if not prompt and mode in required:
        raise ValueError(required[mode])
    args.extend(["--", prompt or defaults.get(mode, ".")])
    return args


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True, timeout=5, check=False,
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        with contextlib.suppress(OSError):
            proc.kill()


def _read_bounded(handle, limit: int) -> tuple[bytes, bool]:
    handle.flush()
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    truncated = size > limit
    handle.seek(max(0, size - limit))
    return handle.read(limit), truncated


def _process_output(mode: str, out: bytes, err: bytes, *,
                    out_truncated: bool = False,
                    err_truncated: bool = False,
                    output_limit: int = MAX_OUTPUT_BYTES,
                    diagnostics_limit: int = MAX_OUTPUT_BYTES) -> tuple[str, str]:
    """Keep machine-readable stdout separate from human diagnostics."""
    stdout = out.decode("utf-8", "replace")
    stderr = err.decode("utf-8", "replace")
    if stderr and secret_guard.scan_text(
            stderr, "attestor-ui-stderr.txt", max_findings=1):
        stderr = "[diagnostics withheld: credential-like material detected]"
    if mode in REPORT_MODES and stdout.strip():
        output = stdout
        diagnostics = stderr
        if out_truncated:
            output = "[stdout truncated to the final %d bytes]\n%s" % (
                output_limit, output)
        if err_truncated and diagnostics:
            diagnostics = "[stderr truncated to the final %d bytes]\n%s" % (
                diagnostics_limit, diagnostics)
        return output.strip(), diagnostics.strip()
    output = stdout + (("\n" if stdout and stderr else "") + stderr if stderr else "")
    if out_truncated or err_truncated:
        output = "[output truncated to the final %d bytes]\n%s" % (
            max(output_limit, diagnostics_limit), output)
    return output.strip(), ""


def _verified_report_variant(
        report: object,
) -> dict[str, object] | None:
    """Return a variant only after the complete 4.1.4 report replay verifies."""
    if type(report) is not dict:
        return None
    try:
        valid_report, _errors = attestor414.verify_report(
            report, root=report.get("root"))
        if not valid_report:
            return None
        config = report.get("analysis_config")
        analyzer = report.get("analyzer")
        selection = report.get("variant_414")
        config_selection = (
            config.get("variant_414") if type(config) is dict else None)
        if (type(analyzer) is not dict or type(selection) is not dict or
                type(config_selection) is not dict or
                config_selection != selection):
            return None
        valid_selection, _selection_errors = variant414.verify_report(selection)
        if not valid_selection:
            return None
        profile = variant414.load_profile_dict(selection["selected_profile"])
    except (KeyError, OSError, RuntimeError, TypeError, ValueError,
            attestor414.Attestor414Error, variant414.VariantError):
        return None
    identity = variant414.profile_identity(profile)
    if (analyzer.get("variant_slug") != profile.slug or
            analyzer.get("variant_profile_sha256") != identity):
        return None
    return _variant_descriptor(profile)


def _verified_output_variant(output: str) -> dict[str, object] | None:
    if not isinstance(output, str) or not output.lstrip().startswith("{"):
        return None
    try:
        report = json.loads(output)
    except (json.JSONDecodeError, UnicodeError, ValueError):
        return None
    return _verified_report_variant(report)


def _verified_cjp_output_variant(
        output: str) -> dict[str, object] | None:
    """Verify CJP authority/profile evidence without treating it as a scan."""
    if not isinstance(output, str) or not output.lstrip().startswith("{"):
        return None
    try:
        report = json.loads(output)
    except (json.JSONDecodeError, UnicodeError, ValueError):
        return None
    if (type(report) is not dict or
            report.get("schema") != "attestor-cjp-local-control/4.1.4" or
            report.get("version") != "4.1.4" or
            report.get("profile") != "cockroach-janta-party"):
        return None
    expected = variant414.COCKROACH_JANTA_PARTY
    identity = variant414.profile_identity(expected)
    expected_language = {
        **variant414.response_language_metadata(expected),
        "profile_sha256": identity,
        "verified": True,
    }
    if report.get("response_language") != expected_language:
        return None
    status = report.get("status")
    audit = report.get("authorization")
    if status == "authorization-required":
        try:
            if audit != cjp_authorization414.denied_status():
                return None
        except (PermissionError, TypeError, ValueError):
            return None
    else:
        valid, _errors = cjp_authorization414.verify_audit(audit)
        if not valid or type(audit) is not dict:
            return None
        profile = audit.get("profile")
        if (type(profile) is not dict or
                profile.get("slug") != expected.slug or
                profile.get("profile_sha256") != identity or
                audit.get("operation_sha256") !=
                report.get("operation_sha256")):
            return None
    apply_audit = report.get("apply_authorization")
    if apply_audit is not None:
        valid, _errors = cjp_authorization414.verify_audit(apply_audit)
        if (not valid or type(apply_audit) is not dict or
                apply_audit.get("authorization_kind") != "apply" or
                apply_audit.get("authorized_actions") !=
                ["apply-file-edit"] or
                apply_audit.get("operation_sha256") !=
                report.get("operation_sha256")):
            return None
    return _variant_descriptor(expected)


def _history_verification(report: dict) -> dict:
    """Freshly replay stored Truth Guard evidence without rewriting history."""
    # This endpoint can replay only Truth Guard 3. Older ledgers remain valid
    # historical artifacts, but must not be misrouted through the 4.1 verifier.
    applicable = isinstance(report.get("truth_guard3"), dict)
    if not applicable:
        return {"applicable": False, "checked": False, "verified": False,
                "fresh": None, "status": "not-applicable", "error_count": 0}
    try:
        verification = truth_guard41.verify_guarded(report, require_fresh=True)
    except (OSError, RuntimeError, TypeError, ValueError,
            truth_guard41.TruthGuard41Error):
        return {"applicable": True, "checked": False, "verified": False,
                "fresh": None, "status": "verification-error", "error_count": 1}
    fresh_value = verification.get("fresh")
    fresh = fresh_value if type(fresh_value) is bool else None
    verified = verification.get("ok") is True and fresh is True
    raw_status = str(verification.get("status", "invalid")).casefold()
    status = "fresh-verified" if verified else (
        "stale" if raw_status == "stale" else "invalid")
    errors = verification.get("errors")
    return {"applicable": True, "checked": True, "verified": verified,
            "fresh": fresh, "status": status,
            "error_count": min(len(errors), 2_000) if isinstance(errors, list) else 0}


def _completed_returncode(mode: str, code: int) -> bool:
    """Finding/policy exits are completed reports, not subprocess failures."""
    return code in (0, 1)


def run_attestor(
    mode: str,
    prompt: str,
    limit: int = 8,
    timeout: int = DEFAULT_TIMEOUT,
    version: str = CURRENT_VERSION,
    variant: object = None,
    response_style: str = "professional",
    cancel_event: threading.Event | None = None,
    research_online: bool = False,
    research_fetch_pages: bool = False,
    computer_authorized: bool = False,
    computer_scope: str = "home",
    computer_max_projects: int = 3,
    computer_improve: bool = False,
    cjp_permission_confirmed: bool = False,
    cjp_apply: bool = False,
    cjp_apply_confirmed: bool = False,
    cjp_preview_evidence_sha256: str = "",
) -> dict:
    started = time.perf_counter()
    limit = _bounded_int(limit, 8, 1, MAX_LIMIT)
    detector = _detector_for_version(version)
    if detector is None:
        return {"ok": False, "code": 2,
                "output": "That Attestor version is not available as an extracted detector folder.",
                "elapsed_ms": 0}
    try:
        normalized_mode = mode.strip().lower() if isinstance(mode, str) else mode
        profile = _variant_profile_for_request(
            normalized_mode, version, variant)
        if profile is not None:
            effective_timeout = _variant_process_timeout(profile)
            output_limit = profile.max_ui_output_bytes
        else:
            effective_timeout = _bounded_int(
                timeout, DEFAULT_TIMEOUT, MIN_TIMEOUT, MAX_TIMEOUT)
            output_limit = MAX_OUTPUT_BYTES
        diagnostics_limit = MAX_OUTPUT_BYTES
        args = build_args(
            mode, prompt, limit=limit, response_style=response_style,
            version=version, variant=variant,
            research_online=research_online,
            research_fetch_pages=research_fetch_pages,
            computer_authorized=computer_authorized,
            computer_scope=computer_scope,
            computer_max_projects=computer_max_projects,
            computer_improve=computer_improve,
            cjp_permission_confirmed=cjp_permission_confirmed,
            cjp_apply=cjp_apply,
            cjp_apply_confirmed=cjp_apply_confirmed,
            cjp_preview_evidence_sha256=cjp_preview_evidence_sha256,
        )
    except ValueError as exc:
        return {"ok": False, "code": 2, "output": str(exc), "elapsed_ms": 0}

    script = str(detector / "superattestor.py")
    bootstrap = (
        "import runpy,sys; root,script,*rest=sys.argv[1:]; "
        "sys.path.insert(0,root); sys.argv=[script,*rest]; "
        "runpy.run_path(script,run_name='__main__')"
    )
    cmd = [sys.executable, "-I", "-B", "-X", "utf8", "-c",
           bootstrap, str(detector), script, *args]
    creationflags = 0
    popen_kwargs = {}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(detector), stdout=stdout_file, stderr=stderr_file,
                env=_safe_env(), creationflags=creationflags, **popen_kwargs,
            )
        except OSError as exc:
            return {"ok": False, "code": 127, "output": str(exc), "elapsed_ms": 0}
        deadline = time.monotonic() + effective_timeout
        cancelled = False
        timed_out = False
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                _terminate_process_tree(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_process_tree(proc)
                break
            time.sleep(0.05)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        out, out_truncated = _read_bounded(stdout_file, output_limit)
        err, err_truncated = _read_bounded(stderr_file, diagnostics_limit)

    elapsed = int((time.perf_counter() - started) * 1000)
    if cancelled:
        return {"ok": False, "code": 130, "output": "Attestor job cancelled.",
                "elapsed_ms": elapsed, "cancelled": True,
                "execution_limits": {
                    "source": "compiled-variant" if profile is not None else "legacy-ui",
                    "timeout_seconds": effective_timeout,
                    "stdout_bytes": output_limit,
                }}
    if timed_out:
        return {"ok": False, "code": 124,
                "output": "Attestor timed out after %ds." % effective_timeout,
                "elapsed_ms": elapsed,
                "execution_limits": {
                    "source": "compiled-variant" if profile is not None else "legacy-ui",
                    "timeout_seconds": effective_timeout,
                    "stdout_bytes": output_limit,
                }}
    if out_truncated and mode in REPORT_MODES:
        # A tail fragment is not a machine report. Reject it before JSON
        # parsing, history persistence, or a misleading zero-finding view.
        _, diagnostics = _process_output(
            mode, b"{}", err, err_truncated=err_truncated,
            output_limit=output_limit, diagnostics_limit=diagnostics_limit)
        return {
            "ok": False, "code": 125,
            "output": "Attestor's machine report exceeded the %d-byte stdout boundary. " %
                      output_limit +
                      "The partial JSON was rejected; no findings were accepted or archived.",
            "diagnostics": diagnostics, "elapsed_ms": elapsed,
            "truncated": True, "partial": True,
            "stdout_truncated": True,
            "stderr_truncated": bool(err_truncated),
            "outcome": "output-boundary-exceeded",
            "output_boundary": {"status": "failed",
                                "maximum_bytes": output_limit,
                                "machine_report_accepted": False},
            "execution_limits": {
                "source": "compiled-variant" if profile is not None else "legacy-ui",
                "timeout_seconds": effective_timeout,
                "stdout_bytes": output_limit,
            },
        }
    output, diagnostics = _process_output(
        mode, out, err, out_truncated=out_truncated,
        err_truncated=err_truncated, output_limit=output_limit,
        diagnostics_limit=diagnostics_limit)
    completed = _completed_returncode(mode, proc.returncode)
    result = {"ok": completed, "code": proc.returncode,
            "output": output, "diagnostics": diagnostics,
            "elapsed_ms": elapsed,
            "truncated": bool(out_truncated or err_truncated),
            "stdout_truncated": bool(out_truncated),
            "stderr_truncated": bool(err_truncated),
            "outcome": "action-required" if completed and proc.returncode else (
                "completed" if completed else "failed"),
            "execution_limits": {
                "source": "compiled-variant" if profile is not None else "legacy-ui",
                "timeout_seconds": effective_timeout,
                "stdout_bytes": output_limit,
            }}
    if profile is not None:
        verified_variant = (
            _verified_cjp_output_variant(output)
            if normalized_mode == "cjpcontrol"
            else _verified_output_variant(output))
        if verified_variant is not None:
            result["verified_variant"] = verified_variant
            result["variant_consistent"] = (
                verified_variant["slug"] == profile.slug)
        else:
            result["variant_consistent"] = False
            result["variant_verification"] = "unavailable"
    return result


class JobManager:
    def __init__(self, workers: int = MAX_ACTIVE_JOBS,
                 max_pending: int = MAX_PENDING_JOBS,
                 evidence_store: EvidenceStore | None = None):
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, workers), thread_name_prefix="attestor-job")
        self._max_pending = max(1, max_pending)
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()
        self.evidence_store = evidence_store

    def _archive_result(self, result: dict, *, mode: str = "",
                        research_online: bool = False) -> None:
        """Persist only a complete machine-readable server result."""
        if self.evidence_store is None or not result.get("ok"):
            return
        output = result.get("output")
        if not isinstance(output, str) or not output.lstrip().startswith("{"):
            return
        try:
            report = json.loads(output)
            if not isinstance(report, dict):
                return
            execution = report.get("execution")
            execution = execution if isinstance(execution, dict) else {}
            retention = report.get("retention")
            retention = retention if isinstance(retention, dict) else {}
            online_research = mode == "research" and (
                research_online is True or execution.get("network_accessed") is True)
            if (online_research and
                    retention.get("provider_declared_retention_allowed") is not True):
                result["history_skipped"] = (
                    "online research is session-only because provider retention "
                    "was not explicitly allowed")
                return
            result["history"] = self.evidence_store.store_report(report)
        except (EvidenceStoreError, UnicodeError, json.JSONDecodeError, OSError, ValueError):
            # History is auxiliary. A scan result remains valid when local
            # persistence is unavailable, but the client must not invent a run.
            result["history_unavailable"] = True

    def submit(self, data: dict) -> dict | None:
        job_id = uuid.uuid4().hex
        event = threading.Event()
        job = {
            "id": job_id, "status": "queued", "created": time.time(),
            "started": None, "finished": None, "result": None,
            "cancel_event": event, "future": None,
        }
        with self._lock:
            pending = sum(1 for item in self._jobs.values()
                          if item["status"] in ("queued", "running"))
            if pending >= self._max_pending:
                return None
            completed = sorted(
                (j for j in self._jobs.values() if j["status"] in ("done", "failed", "cancelled")),
                key=lambda item: item["created"],
            )
            while len(self._jobs) >= MAX_JOB_HISTORY and completed:
                old = completed.pop(0)
                self._jobs.pop(old["id"], None)
            self._jobs[job_id] = job
            job["future"] = self._executor.submit(self._execute, job_id, dict(data))
        return self.get(job_id) or {"id": job_id, "status": "queued"}

    def _execute(self, job_id: str, data: dict) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            if job["cancel_event"].is_set():
                job["status"] = "cancelled"
                job["finished"] = time.time()
                return
            job["status"] = "running"
            job["started"] = time.time()
            event = job["cancel_event"]
        try:
            result = run_attestor(
                data.get("mode", "chat"), data.get("prompt", ""),
                limit=_bounded_int(data.get("limit", 8), 8, 1, MAX_LIMIT),
                timeout=data.get("timeout", DEFAULT_TIMEOUT),
                version=data.get("version", CURRENT_VERSION),
                variant=data.get("variant") if "variant" in data else None,
                response_style=data.get("response_style", "professional"),
                cancel_event=event,
                research_online=data.get("research_online") is True,
                research_fetch_pages=data.get("research_fetch_pages") is True,
                computer_authorized=data.get("computer_authorized") is True,
                computer_scope=data.get("computer_scope", "home"),
                computer_max_projects=data.get("computer_max_projects", 3),
                computer_improve=data.get("computer_improve") is True,
                cjp_permission_confirmed=(
                    data.get("cjp_permission_confirmed") is True),
                cjp_apply=data.get("cjp_apply") is True,
                cjp_apply_confirmed=(
                    data.get("cjp_apply_confirmed") is True),
                cjp_preview_evidence_sha256=data.get(
                    "cjp_preview_evidence_sha256", ""),
            )
        except Exception as exc:  # keep malformed jobs observable and terminal
            result = {"ok": False, "code": 2,
                      "output": "Attestor job failed safely: %s" % type(exc).__name__,
                      "elapsed_ms": 0}
        # A pathless scan can enumerate project and source-file paths across a
        # broad local scope.  Per-run read consent must not silently become
        # durable path retention in the shared workbench history.  The CLI can
        # still persist a report when the operator explicitly supplies --out.
        if data.get("mode") in {"computer41", "cjpcontrol", "escapelab"}:
            result["history_skipped"] = (
                "permissioned local-control and private escape-lab reports "
                "are session-only")
        else:
            self._archive_result(
                result, mode=data.get("mode", ""),
                research_online=data.get("research_online") is True)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["result"] = result
            job["finished"] = time.time()
            job["status"] = "cancelled" if result.get("cancelled") else (
                "done" if result.get("ok") else "failed")

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            now = time.time()
            started = job["started"] or job["created"]
            return {
                "id": job["id"], "status": job["status"],
                "created": job["created"], "started": job["started"],
                "finished": job["finished"], "elapsed_ms": int(
                    ((job["finished"] or now) - started) * 1000),
                "result": job["result"],
            }

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job["status"] in ("done", "failed", "cancelled"):
                return False
            job["cancel_event"].set()
            future = job.get("future")
            if future is not None and future.cancel():
                job["status"] = "cancelled"
                job["finished"] = time.time()
            return True

    def shutdown(self) -> None:
        """Cancel active subprocesses and join worker threads on server exit."""
        with self._lock:
            for job in self._jobs.values():
                if job["status"] in ("queued", "running"):
                    job["cancel_event"].set()
        self._executor.shutdown(wait=True, cancel_futures=True)


class BlindArenaConflictError(RuntimeError):
    """A blind-arena lifecycle request conflicts with its current state."""


class BlindArenaManager:
    """Own the UI's fixed, abstract arena and its private checkpoint.

    This manager deliberately does not use ``JobManager`` or ``run_attestor``.
    Each background episode is bounded by the arena core, while the sequence of
    resumable episodes has no wall-clock or total-episode deadline.  The API
    exposes only verified counters and booleans, never the hidden token, trace,
    graph, checkpoint path, or arbitrary explorer input.
    """

    def __init__(self, checkpoint_path: str | os.PathLike[str], *,
                 episode_steps: int = blind_escape_arena414.DEFAULT_EPISODE_STEPS):
        self._checkpoint_path = self._validated_checkpoint_path(checkpoint_path)
        self._episode_steps = episode_steps
        self._lock = threading.RLock()
        self._state: dict | None = None
        self._thread: threading.Thread | None = None
        self._cancel_event: threading.Event | None = None
        self._running = False
        self._checkpoint_error = ""
        self._runtime_error = ""
        if self._checkpoint_path.exists():
            try:
                self._state = blind_escape_arena414.load_checkpoint(
                    self._checkpoint_path)
            except (blind_escape_arena414.BlindEscapeArenaError, OSError):
                # Never silently replace unverifiable durable evidence.  The
                # operator can explicitly choose Reset/new through the API.
                self._checkpoint_error = (
                    "The saved arena checkpoint failed closed. Use Reset/new "
                    "to replace it explicitly.")

    @staticmethod
    def _validated_checkpoint_path(
            checkpoint_path: str | os.PathLike[str]) -> Path:
        if not isinstance(checkpoint_path, (str, os.PathLike)):
            raise blind_escape_arena414.BlindEscapeArenaError(
                "controller checkpoint path must be path-like")
        target = Path(checkpoint_path).expanduser()
        parent = target.parent if str(target.parent) else Path(".")
        try:
            parent_stat = os.lstat(parent)
        except OSError as exc:
            raise blind_escape_arena414.BlindEscapeArenaError(
                "controller checkpoint parent could not be inspected") from exc
        attributes = getattr(parent_stat, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(parent_stat.st_mode) or attributes & reparse_flag:
            raise blind_escape_arena414.BlindEscapeArenaError(
                "controller checkpoint parent must not be a link or reparse point")
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise blind_escape_arena414.BlindEscapeArenaError(
                "controller checkpoint parent must be a directory")
        return target

    def _checked_checkpoint_path(self) -> Path:
        # Re-check immediately before every controller-owned filesystem action
        # so a replaced parent fails closed instead of redirecting state.
        return self._validated_checkpoint_path(self._checkpoint_path)

    @staticmethod
    def _empty_status(*, reason: str = "The arena has not been started.") -> dict:
        return {
            "ok": True,
            "schema": blind_escape_arena414.STATUS_SCHEMA,
            "version": blind_escape_arena414.VERSION,
            "objective": blind_escape_arena414.OBJECTIVE,
            "status": "not-started",
            "last_episode_status": "not-started",
            "running": False,
            "cancel_requested": False,
            "terminal": False,
            "incomplete": False,
            "verified_escape": False,
            "episode_count": 0,
            "total_steps": 0,
            "observations_known": 0,
            "actions_known": 0,
            "frontier": {"state": "unopened", "observations_known": 0,
                         "actions_known": 0},
            "reason": reason,
            "verification": {"report": False, "hidden_token": False,
                             "trace": False},
            "simulation_controls": {
                "abstract_only": True,
                "arbitrary_payloads_accepted": False,
                "commands_executed": False,
                "simulation_core_file_access": False,
                "controller_checkpoint_may_read_write": True,
                "network_accessed": False,
                "processes_started": False,
                "real_escape_attempted": False,
            },
        }

    def _status_locked(self) -> dict:
        if self._state is None:
            reason = self._checkpoint_error or self._runtime_error or (
                "The arena has not been started.")
            result = self._empty_status(reason=reason)
            if self._checkpoint_error or self._runtime_error:
                result.update({"status": "checkpoint-error", "incomplete": True})
            return result

        view = blind_escape_arena414.status_view(self._state)
        last = self._state["progress"].get("last_report")
        report_verified = False
        proof_verified = False
        if last is not None:
            report_verified, _errors = blind_escape_arena414.verify_report(
                last, self._state)
            proof_verified = bool(
                report_verified and last.get("status") == "escaped"
                and isinstance(last.get("escape_proof"), dict)
                and last["escape_proof"].get("hidden_token")
                and last["escape_proof"].get("trace_sha256")
                and isinstance(last.get("trace"), list) and last["trace"])

        last_status = view["last_episode_status"]
        display_status = view["status"]
        cancel_requested = bool(
            self._running and self._cancel_event is not None
            and self._cancel_event.is_set())
        if self._running:
            display_status = "cancelling" if cancel_requested else "running"
        elif not view["terminal"] and last_status in {
                "cancelled", "episode-exhausted", "explorer-refused"}:
            display_status = last_status
        elif view["episode_count"] == 0:
            display_status = "ready"

        if proof_verified:
            frontier_state = "verified-synthetic-boundary"
            reason = view["escape_reason"]
        elif display_status == "contained":
            frontier_state = "exhausted-contained-reference"
            reason = "Every compiled opaque action in the contained reference was explored."
        elif self._runtime_error:
            frontier_state = "checkpointed-incomplete"
            reason = self._runtime_error
            display_status = "incomplete"
        elif display_status == "cancelled":
            frontier_state = "checkpointed-incomplete"
            reason = "Cancelled safely at a bounded episode step; learned knowledge remains resumable."
        elif display_status == "cancelling":
            frontier_state = "cancellation-pending"
            reason = "Cancellation was requested and will be observed at a bounded step boundary."
        elif display_status == "explorer-refused":
            frontier_state = "checkpointed-incomplete"
            reason = "The explorer refused an available opaque action; the arena remains incomplete."
        elif display_status == "episode-exhausted":
            frontier_state = "checkpointed-incomplete"
            reason = "The episode step boundary was reached; resume from the persistent checkpoint."
        elif self._running:
            frontier_state = "expanding"
            reason = "Running bounded abstract episodes in the background."
        else:
            frontier_state = "ready-to-resume" if view["episode_count"] else "unopened"
            reason = "Persistent black-box knowledge is ready to resume."

        verified_escape = bool(
            proof_verified and view["status"] == "escaped"
            and view["terminal"] is True)
        if view["status"] == "escaped" and not verified_escape:
            # This should already fail state verification, but retain a second
            # UI-specific fail-closed gate: no proof means no success label.
            display_status = "verification-failed"
            frontier_state = "checkpointed-incomplete"
            reason = "Escape evidence did not pass token and trace replay verification."

        return {
            "ok": True,
            "schema": view["schema"],
            "version": view["version"],
            "objective": view["objective"],
            "status": display_status,
            "last_episode_status": last_status,
            "running": self._running,
            "cancel_requested": cancel_requested,
            "terminal": bool(view["terminal"] and (
                view["status"] != "escaped" or verified_escape)),
            "incomplete": bool(not view["terminal"] and (
                self._running or view["episode_count"] > 0)),
            "verified_escape": verified_escape,
            "episode_count": view["episode_count"],
            "total_steps": view["total_steps"],
            "observations_known": view["observations_known"],
            "actions_known": view["actions_known"],
            "frontier": {
                "state": frontier_state,
                "observations_known": view["observations_known"],
                "actions_known": view["actions_known"],
            },
            "reason": reason,
            "verification": {
                "report": report_verified,
                "hidden_token": proof_verified,
                "trace": proof_verified,
            },
            "simulation_controls": view["simulation_controls"],
        }

    def status(self) -> dict:
        with self._lock:
            try:
                return self._status_locked()
            except blind_escape_arena414.BlindEscapeArenaError:
                result = self._empty_status(
                    reason="Arena evidence failed closed during status verification.")
                result.update({"status": "verification-failed", "incomplete": True})
                return result

    def start_or_resume(self) -> dict:
        with self._lock:
            if self._running:
                raise BlindArenaConflictError("The blind arena is already running.")
            if self._checkpoint_error:
                raise BlindArenaConflictError(self._checkpoint_error)
            if self._state is None:
                checkpoint_path = self._checked_checkpoint_path()
                self._state = blind_escape_arena414.open_or_create(
                    checkpoint_path,
                    objective=blind_escape_arena414.OBJECTIVE,
                    arena_kind=blind_escape_arena414.GENERATED_ESCAPABLE)
            view = blind_escape_arena414.status_view(self._state)
            if view["terminal"]:
                raise BlindArenaConflictError(
                    "The arena is terminal. Use explicitly confirmed Reset/new for another arena.")
            self._runtime_error = ""
            self._cancel_event = threading.Event()
            self._running = True
            self._thread = threading.Thread(
                target=self._run_background,
                args=(self._cancel_event,),
                name="attestor-blind-arena", daemon=True)
            self._thread.start()
            return self._status_locked()

    def _run_background(self, cancel_event: threading.Event) -> None:
        try:
            while True:
                with self._lock:
                    if self._state is None:
                        raise blind_escape_arena414.BlindEscapeArenaError(
                            "arena state disappeared")
                    report = blind_escape_arena414.run_episode(
                        self._state,
                        max_steps=self._episode_steps,
                        cancel=cancel_event,
                        checkpoint_path=self._checked_checkpoint_path())
                    verified, _errors = blind_escape_arena414.verify_report(
                        report, self._state)
                    if not verified:
                        raise blind_escape_arena414.BlindEscapeArenaError(
                            "episode evidence failed replay verification")
                    status = report["status"]
                if status in {"escaped", "contained", "cancelled",
                              "explorer-refused"}:
                    break
                # No total episode count or overall wall-clock deadline is
                # imposed.  The checkpoint is durable after every episode.
        except (blind_escape_arena414.BlindEscapeArenaError, OSError):
            with self._lock:
                self._runtime_error = (
                    "The latest bounded episode failed closed; the last "
                    "verified checkpoint remains incomplete.")
                try:
                    self._state = blind_escape_arena414.load_checkpoint(
                        self._checked_checkpoint_path())
                except (blind_escape_arena414.BlindEscapeArenaError, OSError):
                    self._state = None
                    self._checkpoint_error = (
                        "The saved arena checkpoint failed closed. Use Reset/new "
                        "to replace it explicitly.")
        finally:
            with self._lock:
                self._running = False

    def cancel(self) -> bool:
        # Do not take the state lock here: a bounded episode owns that lock
        # while it mutates and verifies state, and cancellation must be able to
        # signal the episode's independent Event immediately.
        event = self._cancel_event
        if not self._running or event is None:
            return False
        event.set()
        return True

    def reset(self) -> dict:
        with self._lock:
            if self._running:
                raise BlindArenaConflictError(
                    "Cancel the active arena before Reset/new.")
            checkpoint_path = self._checked_checkpoint_path()
            state = blind_escape_arena414.open_or_create(
                objective=blind_escape_arena414.OBJECTIVE,
                arena_kind=blind_escape_arena414.GENERATED_ESCAPABLE)
            blind_escape_arena414.save_checkpoint(state, checkpoint_path)
            self._state = state
            self._checkpoint_error = ""
            self._runtime_error = ""
            self._cancel_event = None
            return self._status_locked()

    def shutdown(self) -> None:
        # Like cancel(), shutdown signals without waiting for the state lock.
        event = self._cancel_event if self._running else None
        thread = self._thread
        if event is not None:
            event.set()
        if thread is not None and thread.is_alive():
            # The core explorer is local and each episode has a strict step
            # boundary, so shutdown does not need a process-kill capability.
            thread.join(timeout=5)


def _security_headers(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Cross-Origin-Resource-Policy", "same-origin")


def _json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    _security_headers(handler)
    handler.end_headers()
    _write_response_body(handler, body)


def _write_response_body(handler: BaseHTTPRequestHandler, body: bytes) -> bool:
    """Finish a response quietly when a local client has already disconnected."""
    try:
        handler.wfile.write(body)
        return True
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
        return False


def _binary(handler: BaseHTTPRequestHandler, status: int, body: bytes,
            content_type: str, filename: str = "") -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    if filename:
        safe_name = "".join(character for character in filename
                            if character.isalnum() or character in "._-")[:160]
        handler.send_header("Content-Disposition", 'attachment; filename="%s"' % safe_name)
    _security_headers(handler)
    handler.end_headers()
    _write_response_body(handler, body)


def _strict_request_pairs(pairs: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("request contains duplicate JSON object keys")
        value[key] = item
    return value


def _reject_request_constant(value: str) -> None:
    raise ValueError("request contains a non-finite JSON constant: " + value)


def _file(handler: BaseHTTPRequestHandler, path: Path, content_type: str) -> None:
    if not path.exists() or not path.is_file():
        handler.send_error(404)
        return
    body = path.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    _security_headers(handler)
    handler.end_headers()
    _write_response_body(handler, body)


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, max_connections: int = MAX_CONNECTIONS, **kwargs):
        super().__init__(*args, **kwargs)
        self._maximum_connections = max(1, int(max_connections))
        self._active_connections = 0
        self._connection_lock = threading.Lock()

    def _take_connection_slot(self) -> bool:
        with self._connection_lock:
            if self._active_connections >= self._maximum_connections:
                return False
            self._active_connections += 1
            return True

    def _return_connection_slot(self) -> None:
        with self._connection_lock:
            if self._active_connections <= 0:
                raise RuntimeError("connection slot ownership is inconsistent")
            self._active_connections -= 1

    def process_request(self, request, client_address):
        if not self._take_connection_slot():
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._return_connection_slot()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._return_connection_slot()


class Handler(BaseHTTPRequestHandler):
    server_version = "AttestorUI/4.1.4"

    def log_message(self, fmt, *args):
        try:
            sys.stderr.write("[attestor-ui] " + fmt % args + "\n")
        except (OSError, ValueError):
            # A detached Windows launcher can close inherited standard handles.
            # Request handling must never fail merely because access logging is
            # unavailable.
            pass

    def _request_host_ok(self) -> bool:
        host = self.headers.get("Host", "").lower()
        return host in self.server.allowed_hosts

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        try:
            parsed = urlparse(origin)
        except ValueError:
            return False
        return parsed.scheme == "http" and parsed.netloc.lower() in self.server.allowed_hosts

    def _api_authorized(self) -> bool:
        token = self.headers.get("X-Attestor-Token", "")
        return secrets.compare_digest(token, self.server.session_token)

    def _authorized_get(self) -> bool:
        if not self._request_host_ok() or not self._origin_ok() or not self._api_authorized():
            _json(self, 403, {"ok": False, "output": "Unauthorized."})
            return False
        return True

    def _reject_ambiguous_framing(self, *, body_expected: bool) -> bool:
        """Reject framing that different HTTP parsers could interpret differently."""
        transfer_encodings = self.headers.get_all("Transfer-Encoding") or []
        content_lengths = self.headers.get_all("Content-Length") or []
        invalid = bool(transfer_encodings) or len(content_lengths) > 1
        if body_expected:
            invalid = invalid or len(content_lengths) != 1
            if len(content_lengths) == 1:
                value = content_lengths[0]
                invalid = invalid or not value.isascii() or not value.isdecimal()
        elif content_lengths:
            invalid = invalid or content_lengths[0] not in {"", "0"}
        if not invalid:
            return False
        # Never leave a rejected request body available for interpretation as a
        # second request, even if the server protocol changes in the future.
        self.close_connection = True
        # Draining first is what makes that close orderly. Closing a socket
        # while unread bytes sit in the receive buffer makes Windows send RST
        # rather than FIN, and the client then raises ConnectionAbortedError
        # instead of reading this 400 -- a race that failed about one run in
        # five. The body is read purely to discard it, and bounded so an
        # oversized one cannot make the server work on the sender's behalf.
        self._discard_body()
        _json(self, 400, {
            "ok": False,
            "output": "Ambiguous or unsupported HTTP request framing was rejected.",
        })
        return True

    def _discard_body(self) -> None:
        """Consume a rejected request body so the connection can close cleanly."""
        try:
            declared = 0
            for value in self.headers.get_all("Content-Length") or []:
                text = value.strip()
                if text.isascii() and text.isdecimal():
                    declared = max(declared, int(text))
            remaining = min(declared, MAX_BODY_BYTES)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 8192))
                if not chunk:
                    break
                remaining -= len(chunk)
        except (OSError, ValueError):
            return                  # the peer has gone; the close is moot now

    def _parse_json(self, *, reject_duplicate_keys: bool = False) -> dict | None:
        if not self._request_host_ok() or not self._origin_ok():
            _json(self, 403, {"ok": False, "output": "Host/origin rejected."})
            return None
        if not self._api_authorized():
            _json(self, 403, {"ok": False, "output": "Missing or invalid Attestor session token."})
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            _json(self, 415, {"ok": False, "output": "Content-Type must be application/json."})
            return None
        if self._reject_ambiguous_framing(body_expected=True):
            return None
        try:
            length = int((self.headers.get_all("Content-Length") or [""])[0])
            if length > MAX_BODY_BYTES:
                _json(self, 413, {"ok": False, "output": "Request body is too large."})
                return None
            raw = self.rfile.read(length)
            object_pairs_hook = _strict_request_pairs if reject_duplicate_keys else None
            data = json.loads(
                raw.decode("utf-8"), object_pairs_hook=object_pairs_hook,
                parse_constant=_reject_request_constant)
            if not isinstance(data, dict):
                raise ValueError("request body must be a JSON object")
            return data
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            _json(self, 400, {"ok": False, "output": "Bad JSON: %s" % exc})
            return None

    def do_GET(self):
        parsed_request = urlparse(self.path)
        path = unquote(parsed_request.path)
        query = parse_qs(parsed_request.query, keep_blank_values=False)
        if path in ("/", "/index.html"):
            if not self._request_host_ok():
                self.send_error(403)
                return
            _file(self, INDEX, "text/html; charset=utf-8")
            return
        if path in STATIC_ASSETS:
            if not self._request_host_ok():
                self.send_error(403)
                return
            asset, content_type = STATIC_ASSETS[path]
            _file(self, asset, content_type)
            return
        if path == "/health":
            if not self._request_host_ok():
                _json(self, 403, {"ok": False})
                return
            _json(self, 200, {
                "ok": True, "version": CURRENT_VERSION, "detector": str(HERE),
                "distribution_version": DISTRIBUTION_VERSION,
                "has_superattestor": (HERE / "superattestor.py").exists(),
                "has_darwin": (HERE / "darwin.py").exists(),
                "versions": available_versions(), "token": self.server.session_token,
                "max_active_jobs": self.server.max_active_jobs,
                "ui_version": UI_VERSION,
                "default_mode": "attestor41",
                "default_variant": DEFAULT_VARIANT,
                "variants": available_variants(),
                "compatibility_versions": ["Attestor 4.0", "Attestor 3.5", "Attestor 3.0"],
                "precision_rules": len(precision_catalog.RULES),
                "durable_history": getattr(self.server, "evidence_store", None) is not None,
            })
            return
        if path == "/api/history":
            if not self._authorized_get():
                return
            try:
                limit = _bounded_int(query.get("limit", [50])[0], 50, 1, 200)
                rows = self.server.evidence_store.list_runs(limit=limit)
                _json(self, 200, {"ok": True, "schema": "attestor.history-index/4.1", "runs": rows})
            except (AttributeError, EvidenceStoreError, OSError, ValueError):
                _json(self, 503, {"ok": False, "output": "Durable history is unavailable."})
            return
        if path == "/api/history/compare":
            if not self._authorized_get():
                return
            try:
                baseline = query.get("baseline", [""])[0]
                current = query.get("current", [""])[0]
                _json(self, 200, {"ok": True, "delta": self.server.evidence_store.compare(baseline, current)})
            except (AttributeError, EvidenceStoreError, OSError, ValueError) as exc:
                _json(self, 400, {"ok": False, "output": str(exc)})
            return
        if path == "/api/suppressions":
            if not self._authorized_get():
                return
            try:
                _json(self, 200, {"ok": True,
                    "suppressions": self.server.evidence_store.active_suppressions()})
            except (AttributeError, EvidenceStoreError, OSError, ValueError):
                _json(self, 503, {"ok": False, "output": "Suppression state is unavailable."})
            return
        if path == "/api/blind-arena/status":
            if not self._authorized_get():
                return
            if self._reject_ambiguous_framing(body_expected=False):
                return
            if parsed_request.query:
                _json(self, 400, {"ok": False,
                                  "output": "Blind arena status accepts no query or body input."})
                return
            _json(self, 200, self.server.blind_arena.status())
            return
        if path.startswith("/api/history/"):
            if not self._authorized_get():
                return
            parts = [part for part in path.split("/") if part]
            try:
                if len(parts) == 5 and parts[3] == "export":
                    run_id, format_name = parts[2], parts[4]
                    content_type, body = self.server.evidence_store.canonical_export(run_id, format_name)
                    _binary(self, 200, body, content_type,
                            "%s.%s%s" % (run_id, format_name, ".json" if format_name == "sarif" else ""))
                elif len(parts) == 4 and parts[3] == "annotations":
                    _json(self, 200, {"ok": True,
                        "annotations": self.server.evidence_store.annotations(parts[2])})
                elif len(parts) == 3:
                    report = self.server.evidence_store.get_report(parts[2])
                    _json(self, 200, {"ok": True, "run_id": parts[2], "report": report,
                                     "verification": _history_verification(report),
                                     "verified_variant": _verified_report_variant(report),
                                     "annotations": self.server.evidence_store.annotations(parts[2])})
                else:
                    _json(self, 404, {"ok": False, "output": "Unknown history route."})
            except (AttributeError, EvidenceStoreError, OSError, ValueError) as exc:
                _json(self, 409, {"ok": False, "output": str(exc)})
            return
        if path.startswith("/api/jobs/"):
            if not self._authorized_get():
                return
            job = self.server.jobs.get(path.rsplit("/", 1)[-1])
            _json(self, 200 if job else 404, job or {"ok": False, "output": "Unknown job."})
            return
        self.send_error(404)

    def do_POST(self):
        parsed_request = urlparse(self.path)
        path = parsed_request.path
        if path not in ("/api/run", "/api/jobs", "/api/triage", "/api/suppressions",
                        "/api/blind-arena/start", "/api/blind-arena/reset"):
            self.send_error(404)
            return
        data = self._parse_json(
            reject_duplicate_keys=path.startswith("/api/blind-arena/"))
        if data is None:
            return
        if path.startswith("/api/blind-arena/"):
            if parsed_request.query:
                _json(self, 400, {"ok": False,
                                  "output": "Blind arena actions accept no query input."})
                return
            if path == "/api/blind-arena/start":
                if data:
                    _json(self, 400, {"ok": False, "output": (
                        "Blind arena start/resume accepts an empty JSON object only; "
                        "the objective is fixed to Escape.")})
                    return
                try:
                    _json(self, 202, self.server.blind_arena.start_or_resume())
                except BlindArenaConflictError as exc:
                    _json(self, 409, {"ok": False, "output": str(exc)})
                except (blind_escape_arena414.BlindEscapeArenaError, OSError):
                    _json(self, 503, {"ok": False,
                                      "output": "Blind arena failed closed before starting."})
                return
            if set(data) != {"confirmed"} or data.get("confirmed") is not True:
                _json(self, 400, {"ok": False, "output": (
                    "Reset/new requires the exact explicit confirmation object "
                    "{\"confirmed\": true}.")})
                return
            try:
                _json(self, 200, self.server.blind_arena.reset())
            except BlindArenaConflictError as exc:
                _json(self, 409, {"ok": False, "output": str(exc)})
            except (blind_escape_arena414.BlindEscapeArenaError, OSError):
                _json(self, 503, {"ok": False,
                                  "output": "Blind arena reset failed closed."})
            return
        if path == "/api/triage":
            try:
                value = self.server.evidence_store.set_triage(
                    data.get("fingerprint", ""), data.get("state", ""),
                    owner=data.get("owner", ""), reason=data.get("reason", ""))
                _json(self, 200, {"ok": True, "triage": value})
            except (AttributeError, EvidenceStoreError, OSError, TypeError, ValueError) as exc:
                _json(self, 400, {"ok": False, "output": str(exc)})
            return
        if path == "/api/suppressions":
            try:
                value = self.server.evidence_store.suppress(
                    data.get("fingerprint", ""), owner=data.get("owner", ""),
                    reason=data.get("reason", ""), expires_at=data.get("expires_at", ""))
                _json(self, 200, {"ok": True, "suppression": value})
            except (AttributeError, EvidenceStoreError, OSError, TypeError, ValueError) as exc:
                _json(self, 400, {"ok": False, "output": str(exc)})
            return
        if path == "/api/jobs":
            try:
                _variant_profile_for_request(
                    data.get("mode", "chat"),
                    data.get("version", CURRENT_VERSION),
                    data.get("variant") if "variant" in data else None)
            except ValueError as exc:
                _json(self, 400, {"ok": False, "output": str(exc)})
                return
            submitted = self.server.jobs.submit(data)
            if submitted is None:
                _json(self, 429, {"ok": False, "output": "Attestor's bounded job queue is full."})
            else:
                _json(self, 202, submitted)
            return
        # Backward-compatible synchronous endpoint, routed through the same
        # bounded worker queue as the cancellable API.
        try:
            _variant_profile_for_request(
                data.get("mode", "chat"),
                data.get("version", CURRENT_VERSION),
                data.get("variant") if "variant" in data else None)
        except ValueError as exc:
            _json(self, 400, {"ok": False, "output": str(exc)})
            return
        submitted = self.server.jobs.submit(data)
        if submitted is None:
            _json(self, 429, {"ok": False, "output": "Attestor's bounded job queue is full."})
            return
        while True:
            job = self.server.jobs.get(submitted["id"])
            if job is None:
                _json(self, 500, {"ok": False, "output": "Attestor job disappeared."})
                return
            if job["status"] in ("done", "failed", "cancelled"):
                _json(self, 200, job["result"] or {
                    "ok": False, "code": 130, "output": "Attestor job cancelled.",
                    "elapsed_ms": job["elapsed_ms"]})
                return
            time.sleep(0.05)

    def do_DELETE(self):
        parsed_request = urlparse(self.path)
        path = unquote(parsed_request.path)
        if path == "/api/blind-arena":
            if not self._authorized_get():
                return
            if self._reject_ambiguous_framing(body_expected=False):
                return
            if parsed_request.query:
                _json(self, 400, {"ok": False,
                                  "output": "Blind arena cancellation accepts no query or body input."})
                return
            ok = self.server.blind_arena.cancel()
            _json(self, 202 if ok else 409, {
                "ok": ok,
                "status": "cancelling" if ok else "not-running",
            })
            return
        if path == "/api/history":
            if not self._authorized_get():
                return
            try:
                deleted = self.server.evidence_store.clear()
                _json(self, 200, {"ok": True, "deleted": deleted})
            except (AttributeError, EvidenceStoreError, OSError, ValueError):
                _json(self, 503, {"ok": False, "output": "Durable history is unavailable."})
            return
        if path.startswith("/api/suppressions/"):
            if not self._authorized_get():
                return
            try:
                fingerprint = path.split("/", 3)[-1]
                ok = self.server.evidence_store.unsuppress(fingerprint)
                _json(self, 200 if ok else 404, {"ok": ok, "fingerprint": fingerprint})
            except (AttributeError, EvidenceStoreError, OSError, ValueError) as exc:
                _json(self, 400, {"ok": False, "output": str(exc)})
            return
        if not path.startswith("/api/jobs/"):
            self.send_error(404)
            return
        if not self._request_host_ok() or not self._origin_ok() or not self._api_authorized():
            _json(self, 403, {"ok": False, "output": "Unauthorized."})
            return
        job_id = path.rsplit("/", 1)[-1]
        ok = self.server.jobs.cancel(job_id)
        _json(self, 202 if ok else 409, {"ok": ok, "id": job_id,
                                        "status": "cancelling" if ok else "not-cancellable"})


def _loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--jobs", type=int, default=MAX_ACTIVE_JOBS,
                    help="maximum concurrent Attestor subprocess jobs")
    ap.add_argument("--history", default=str(default_history_path()),
                    help="bounded local SQLite evidence-history path")
    args = ap.parse_args(argv)

    missing_assets = [path for path in (INDEX, UI_SCRIPT, UI_STYLES) if not path.is_file()]
    if missing_assets:
        print("missing UI file(s): " + ", ".join(map(str, missing_assets)), file=sys.stderr)
        return 2
    if not _loopback_host(args.host):
        print("refusing non-loopback bind; use an authenticated tunnel to the local UI", file=sys.stderr)
        return 2

    server = LimitedThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.evidence_store = EvidenceStore(args.history)
        history_path = Path(args.history).expanduser()
        server.blind_arena = BlindArenaManager(
            history_path.with_name("blind-escape-arena-4.1.4.checkpoint.json"))
    except (EvidenceStoreError, blind_escape_arena414.BlindEscapeArenaError,
            OSError, ValueError) as exc:
        print("local state initialization failed safely: %s" % exc, file=sys.stderr)
        server.server_close()
        return 2
    server.session_token = secrets.token_urlsafe(32)
    server.jobs = JobManager(_bounded_int(args.jobs, MAX_ACTIVE_JOBS, 1, 8),
                             evidence_store=server.evidence_store)
    server.max_active_jobs = _bounded_int(args.jobs, MAX_ACTIVE_JOBS, 1, 8)
    port = server.server_address[1]
    server.allowed_hosts = {
        "%s:%d" % (args.host.lower(), port), "127.0.0.1:%d" % port,
        "localhost:%d" % port, "[::1]:%d" % port,
    }
    print(
        "%s distribution (%s analysis engine/protocol) running at "
        % (DISTRIBUTION_VERSION, UI_VERSION)
        + "http" + "://%s:%d" % (args.host, port))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping Attestor UI")
    finally:
        server.server_close()
        server.blind_arena.shutdown()
        server.jobs.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
