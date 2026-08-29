#!/usr/bin/env python3
"""Attestor 4.2 — great unified CLI.

One entry point for the entire distribution: offline scans, language
runtimes, offense, brain, review, and system tools.

    attestor scan <path>          static scan (offline, uncached)
    attestor github <url>         clone + review a repo
    attestor shell                interactive REPL
    attestor list                 all capabilities
    attestor doctor               environment check

Every command accepts --help. Output is text by default, --format json
where supported. No network on the default paths; the brain lane is the
explicit opt-in exception and is clearly labeled.

Exit codes: 0 clean, 1 findings/cap reached, 2 invalid usage,
            3 incomplete/gated, 4 operational failure.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import textwrap

VERSION = "4.2"
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INVALID = 2
EXIT_INCOMPLETE = 3
EXIT_OPERATIONAL = 4

# keep release audits clean
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve(strict=True).parent
DETECTOR = ROOT / "detector"

# ---------------------------------------------------------------- ANSI
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    codes = {
        "cyan": "\x1b[36m", "dim": "\x1b[2m", "bold": "\x1b[1m",
        "green": "\x1b[32m", "yellow": "\x1b[33m", "red": "\x1b[31m",
        "magenta": "\x1b[35m", "reset": "\x1b[0m",
    }
    return codes.get(color, "") + text + codes["reset"]


def _banner() -> str:
    return _c(r"""
   ___   __  __  ___  _  _     ___     _    _              _            
  / _ \ | | | |/ _ \| \| |   /   \ __| |_ | |_  ___  ___ | |_  ___  _ _ 
 | (_) || |_| |  _/| .  |   | - |/ _|  _||  _|/ -_)(_-<|  _|/ _ \| '_|
  \___/  \___/|_|  |_|\_|   |_|_|\__|\__| \__|\___|/__/ \__|\___/|_|  
""", "cyan") + _c("  verifiable security toolkit", "dim") + _c("  v%s" % VERSION, "bold") + "\n"


def _section(title: str) -> str:
    return _c("\n%s" % title, "bold") + _c("  --------------------------------", "dim")


# ---------------------------------------------------------------- help
COMMANDS = {
    "scan":     ("core",    "static scan (offline, uncached)"),
    "verify":   ("core",    "audit this release tree"),
    "status":   ("core",    "show CLI availability"),
    "github":   ("core",    "clone + review a GitHub repo"),
    "impl":     ("core",    "clone + install a repo into Attestor"),
    "recon":    ("offense", "port/service scan (connect)"),
    "active":   ("offense", "live injection probes"),
    "bola":     ("offense", "BOLA/AuthZ differential"),
    "proxy":    ("offense", "intercept proxy (Match&Replace)"),
    "fuzz":     ("offense", "universal fuzz (any binary)"),
    "pwn":      ("offense", "pwntools primitives"),
    "lab":      ("lab",     "synthetic enterprise lab"),
    "assure":   ("lab",     "read-only repository assurance"),
    "chain":    ("intel",   "exploit-chain composition"),
    "reader":   ("intel",   "whole-repo comprehension"),
    "pcap":     ("intel",   "offline capture analysis"),
    "cve":      ("intel",   "CVE matching vs feed"),
    "hardening":("intel",   "Trojan Source + secrets"),
    "rank":     ("brain",   "ranking-gate trainer"),
    "brain":    ("brain",   "local byte-level brain"),
    "synth":    ("brain",   "white-box program synthesis"),
    "distill":  ("brain",   "teacher farm (distillation)"),
    "chat":     ("brain",   "chat to local brain"),
    "edit":     ("brain",   "let dolphin edit code"),
    "review":   ("review",  "review everything (dolphin, all files)"),
    "autofix":  ("review",  "self-healing draft->fix loop"),
    "verdict":  ("review",  "signed dual-engine verdicts"),
    "shell":    ("system",  "interactive Attestor shell"),
    "list":     ("system",  "list all capabilities"),
    "doctor":   ("system",  "environment check"),
    # passthrough / legacy
    "lang":     ("legacy",  "AttestorLang 4.2"),
    "control":  ("legacy",  "Owner Control 4.2"),
    "pharma":   ("legacy",  "pharma reference"),
}

ALIASES = {"impl": "github42", "recon": "recon_net42", "active": "active_scan42",
           "bola": "bola_hunter42", "proxy": "proxy42", "fuzz": "universal_fuzz42",
           "pwn": "pwnbridge42", "cve": "cve_matcher42", "hardening": "source_hardening42",
           "rank": "rankgate_trainer42", "brain": "brain42", "synth": "synth42",
           "distill": "distill42", "chat": "owen_chat", "edit": "owen_edit",
           "review": "review_everything", "autofix": "autofix42", "verdict": "verdict42",
           "chain": "chainforge42", "reader": "reader42", "pcap": "pcap42"}

# modules that live as detectors -> dispatched via -I -B -X utf8
DETECTOR_MODULES = {
    "github": "github42",
    "recon": "recon_net42", "active": "active_scan42",
    "bola": "bola_hunter42", "proxy": "proxy42",
    "fuzz": "universal_fuzz42", "pwn": "pwnbridge42",
    "assure": "assurance42",
    "chain": "chainforge42", "reader": "reader42", "pcap": "pcap42",
    "cve": "cve_matcher42", "hardening": "source_hardening42",
    "rank": "rankgate_trainer42", "brain": "brain42", "synth": "synth42",
    "distill": "distill42", "chat": "owen_chat", "edit": "owen_edit",
    "review": "review_everything", "autofix": "autofix42", "verdict": "verdict42",
}

PASSTHROUGH = {
    "lang": ROOT / "integrations" / "attestorlang" / "cli.py",
    "control": DETECTOR / "owner_control42.py",
    "pharma": ROOT / "integrations" / "attestor_chem" / "cli.py",
    "lab": ROOT / "experiments" / "enterprise_security42" / "lab.py",
}


def _print_help():
    print(_banner())
    print(_c("Usage:", "bold") + "  attestor <command> [options]  |  attestor --help | attestor shell\n")
    # group by section
    groups: dict[str, list[str]] = {}
    for cmd, (sec, desc) in COMMANDS.items():
        groups.setdefault(sec, []).append(cmd)

    order = ["core", "offense", "intel", "brain", "review", "lab", "system", "legacy"]
    labels = {"core": "Core", "offense": "Offense  (connects to real targets — use on systems you may test)",
              "intel": "Intel", "brain": "Brain  (local, keyless — Ollama on 127.0.0.1)", "review": "Review",
              "lab": "Lab", "system": "System", "legacy": "Legacy / passthrough"}
    for sec in order:
        if sec not in groups:
            continue
        print(_section(labels.get(sec, sec.title())))
        for cmd in sorted(groups[sec]):
            _, desc = COMMANDS[cmd]
            print("  %-12s %s" % (_c(cmd, "cyan"), desc))
    print(_c("\nExamples:", "bold"))
    print(textwrap.dedent("""\
      attestor scan detector/test_version42.py --format json
      attestor github https://github.com/user/repo
      attestor impl https://github.com/pwntools/pwntools
      attestor recon 192.0.2.1 --ports common
      attestor reader D:\\path\\to\\repo --format text
      attestor brain self-test
      attestor chat --model dolphin3:8b
      attestor shell
    """))
    print(_c("Every command: attestor <command> --help", "dim"))


def _run_detector_module(name: str, args: list[str]) -> int:
    path = (DETECTOR / (name + ".py")).resolve(strict=True)
    # allow calling from anywhere; keep cwd
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-X", "utf8", str(path), *args],
        shell=False, check=False)
    return int(completed.returncode)


def _run_passthrough(path: Path, args: list[str]) -> int:
    path = path.resolve(strict=True)
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-X", "utf8", str(path), *args],
        shell=False, check=False)
    return int(completed.returncode)


def _cmd_scan(argv: list[str]) -> int:
    try:
        return int(subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8",
             str(ROOT / "attestor_cli.py.bak"), "scan", *argv],
            shell=False, check=False).returncode)
    except Exception as exc:
        print("attestor: scan failed (%s)" % type(exc).__name__, file=sys.stderr)
        return 4


def _cmd_list() -> int:
    print(_banner())
    print(_c("All capabilities (detector/*.py):", "bold"))
    for cmd in sorted(COMMANDS):
        sec, desc = COMMANDS[cmd]
        print("  %-12s %-9s %s" % (_c(cmd, "cyan"), _c("[%s]" % sec, "dim"), desc))
    print(_c("\nDetector modules on disk:", "bold"))
    for p in sorted(DETECTOR.glob("*42.py")):
        print("  %s" % _c(p.name, "dim"))
    return 0


def _cmd_doctor() -> int:
    print(_banner())
    print(_c("Environment check\n", "bold"))

    def _ok(msg): print(_c("  [OK] ", "green") + msg)
    def _warn(msg): print(_c("  [!!] ", "yellow") + msg)
    def _bad(msg): print(_c("  [XX] ", "red") + msg)

    # python
    _ok("Python %s (%s)" % (".".join(map(str, sys.version_info[:3])), sys.executable))
    # ollama
    import urllib.request, urllib.error, json as _json
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as r:
            data = _json.loads(r.read().decode())
            n = len(data.get("models", []))
            _ok("Ollama alive — %d model(s) pulled" % n)
            for m in data["models"][:6]:
                print("       - %s (%s)" % (m["name"], m.get("size", "?")))
    except Exception:
        _warn("Ollama not reachable at 127.0.0.1:11434 — chat/brain/distill need it")
        print("       start: ollama serve  |  pull: ollama pull qwen2.5-coder:1.5b")

    # torch
    try:
        import torch
        cuda = "cuda" if torch.cuda.is_available() else "cpu"
        _ok("torch %s (%s)" % (torch.__version__, cuda))
    except ImportError:
        _warn("torch not installed — brain42 trains on CPU numpy only")
        print("       pip install torch  (or cu129 for CUDA)")

    # pwntools
    try:
        import pwnlib
        _ok("pwntools %s" % pwnlib.__version__)
    except ImportError:
        _warn("pwntools not installed — pwnbridge shellcraft/asm need it")

    # disk
    free = shutil.disk_usage(ROOT).free / (1024 ** 3)
    _ok("disk free %.1f GB at %s" % (free, ROOT))

    # repos
    repos = ROOT / "repos"
    if repos.is_dir():
        n = sum(1 for _ in repos.iterdir())
        _ok("repos/ contains %d cloned project(s)" % n)
    else:
        _warn("repos/ not yet created — github/impl will create it")

    print(_c("\nTip: attestor shell  for an interactive session.", "dim"))
    return 0


def _cmd_shell():
    print(_banner())
    print(_c("Attestor shell — type 'help' for commands, 'exit' to leave.\n", "dim"))
    hist = []
    while True:
        try:
            line = input(_c("attestor> ", "cyan")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in ("exit", "quit", ":q", "logout"):
            break
        if line in ("help", "?"):
            _print_help()
            continue
        if line == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            continue
        hist.append(line)
        parts = line.split()
        # allow "scan ." etc.
        ret = main(parts)
        # keep shell alive even if subcommand fails


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_help()
        return 0
    if argv[0] in ("--version", "-V", "version"):
        print("Attestor %s" % VERSION)
        return 0

    cmd = argv[0]
    rest = argv[1:]

    # impl is its own module (clone+install), not just github alias
    if cmd == "impl":
        return _run_detector_module("impl42", rest)
    if cmd == "scan":
        return _cmd_scan(rest)
    if cmd == "verify":
        # keep original verify path
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("_orig_cli", str(ROOT / "attestor_cli.py.bak"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            return int(mod._run_verify())
        except Exception as exc:
            print("attestor: verify failed (%s)" % type(exc).__name__, file=sys.stderr)
            return 4

    # direct detector modules
    if cmd in DETECTOR_MODULES:
        return _run_detector_module(DETECTOR_MODULES[cmd], rest)

    # passthrough legacy
    if cmd in PASSTHROUGH:
        return _run_passthrough(PASSTHROUGH[cmd], rest)

    # system commands
    if cmd == "list":
        return _cmd_list()
    if cmd == "doctor":
        return _cmd_doctor()
    if cmd == "shell":
        _cmd_shell()
        return 0
    if cmd == "status":
        # keep original status output for compatibility
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("_orig_cli", str(ROOT / "attestor_cli.py.bak"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore
            mod._status()
            return 0
        except Exception:
            print("Attestor 4.2 unified CLI")
            print("available: scan, github, recon, active, bola, proxy, fuzz, pwn, lab, chain, reader, brain, synth, chat, edit, review, autofix, verdict, shell, list, doctor")
            return 0

    print("attestor: unknown command '%s'" % cmd, file=sys.stderr)
    print("Try: attestor --help", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

