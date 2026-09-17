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
import difflib
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import textwrap

VERSION = "4.3"
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
    "security": ("core",   "preview an assessment, run checks, export evidence"),
    "ui":       ("core",   "open the local assessment interface"),
    "check":    ("core",   "scan local code and prioritize findings"),
    "report":   ("core",   "export an HTML report for local code"),
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
    "codegen":  ("brain",   "code generation with reasoning"),
    "math":     ("brain",   "x86-64 accelerated math engine"),
    "edit":     ("brain",   "let dolphin edit code"),
    "review":   ("review",  "review everything (dolphin, all files)"),
    "socat":    ("offense", "socat detection, relay & exploit"),
    "zeroday":  ("offense", "zero-day discovery & patch engine"),
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
           "codegen": "codegen42", "math": "math_engine42", "socat": "socat42", "zeroday": "zeroday42",
           "review": "review_everything", "autofix": "autofix42", "verdict": "verdict42",
           "chain": "chainforge42", "reader": "reader42", "pcap": "pcap42"}

# modules that live as detectors -> dispatched via -I -B -X utf8
DETECTOR_MODULES = {
    "security": "security_assessment", "ui": "attestor_ui",
    "github": "github42",
    "recon": "recon_net42", "active": "active_scan42",
    "bola": "bola_hunter42", "proxy": "proxy42",
    "fuzz": "universal_fuzz42", "pwn": "pwnbridge42",
    "assure": "assurance42",
    "chain": "chainforge42", "reader": "reader42", "pcap": "pcap42",
    "cve": "cve_matcher42", "hardening": "source_hardening42",
    "rank": "rankgate_trainer42", "brain": "brain42", "synth": "synth42",
    "distill": "distill42", "chat": "owen_chat", "edit": "owen_edit",
    "codegen": "codegen42", "math": "math_engine42", "socat": "socat42",
    "zeroday": "zeroday42",
    "review": "review_everything", "autofix": "autofix42", "verdict": "verdict42",
}

PASSTHROUGH = {
    "lang": ROOT / "integrations" / "attestorlang" / "cli.py",
    "control": DETECTOR / "owner_control42.py",
    "pharma": ROOT / "integrations" / "attestor_chem" / "cli.py",
    "lab": ROOT / "experiments" / "enterprise_security42" / "lab.py",
}


def _print_help(full: bool = False):
    if not full:
        print(_c("Attestor %s" % VERSION, "bold") + " | security assessments and code review")
        print("\nUsage: attestor <command> [options]")
        print("\nStart here:")
        for command in ("ui", "security", "check", "scan", "report", "status", "doctor"):
            print("  %-12s %s" % (command, COMMANDS[command][1]))
        print("\nExamples:")
        print("  attestor ui")
        print("  attestor security plan --target https://example.test --out plan.json")
        print('  attestor check "D:\\path to\\project" --json')
        print("  attestor status --json")
        print("\nMore: attestor list [search] | attestor help <command> | attestor shell")
        print("Options: --version | --no-color | --help-all")
        return
    print(_c("Attestor %s - all commands" % VERSION, "bold"))
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
    return _run_release_command("scan", argv)


def _json_requested(argv: list[str]) -> bool:
    return "--json" in argv or "--format=json" in argv or any(
        a == "--format" and i + 1 < len(argv) and argv[i + 1] == "json"
        for i, a in enumerate(argv))


def _error(message: str, code: int, argv: list[str]) -> int:
    if _json_requested(argv):
        print(json.dumps({"ok": False, "error": message, "exit_code": code}))
    else:
        print("attestor: " + message, file=sys.stderr)
    return code


class CliUsageError(ValueError):
    pass


class CliParser(argparse.ArgumentParser):
    def error(self, message):
        raise CliUsageError(message)


def _release_entrypoint() -> Path:
    path = ROOT / "attestor_cli.py.bak"
    pin = ROOT / "attestor_cli.py.bak.sha256"
    if not path.is_file() or not pin.is_file():
        raise FileNotFoundError("release scan engine or its integrity pin is missing")
    pinned = pin.read_text(encoding="utf-8").strip().split()
    if not pinned or hashlib.sha256(path.read_bytes()).hexdigest() != pinned[0]:
        raise ValueError("integrity check failed for attestor_cli.py.bak")
    return path


def _run_release_command(command: str, argv: list[str]) -> int:
    """Execute the pinned .bak as Python; importlib does not infer its loader."""
    path = _release_entrypoint()
    arguments = list(argv)
    if command == "scan" and "--json" in arguments:
        arguments.remove("--json")
        arguments += ["--format", "json"]
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-X", "utf8", str(path), command, *arguments],
        shell=False, check=False, capture_output=_json_requested(argv),
        text=True, encoding="utf-8", errors="replace")
    if _json_requested(argv):
        if completed.stdout.strip():
            print(completed.stdout, end="")
            if completed.stderr:
                print(completed.stderr, file=sys.stderr, end="")
        else:
            return _error(completed.stderr.strip() or "command returned no result",
                          int(completed.returncode) or EXIT_OPERATIONAL, argv)
    return int(completed.returncode)


def _command_inventory() -> list[dict]:
    rows = []
    for name, (group, description) in COMMANDS.items():
        path = None
        if name in DETECTOR_MODULES:
            path = DETECTOR / (DETECTOR_MODULES[name] + ".py")
        elif name in PASSTHROUGH:
            path = PASSTHROUGH[name]
        elif name in ("scan", "verify"):
            path = ROOT / "attestor_cli.py.bak"
        elif name in ("check", "report"):
            path = DETECTOR / "cli.py"
        elif name == "impl":
            path = DETECTOR / "impl42.py"
        rows.append({"command": name, "group": group, "description": description,
                     "available": path is None or path.is_file()})
    return rows


def _system_parser(command: str, search: bool = False) -> argparse.ArgumentParser:
    parser = CliParser(prog="attestor " + command,
                       description=COMMANDS[command][1])
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    if search:
        parser.add_argument("search", nargs="?", default="", help="filter names and descriptions")
    return parser


def _cmd_list(argv: list[str]) -> int:
    args = _system_parser("list", search=True).parse_args(argv)
    rows = [r for r in _command_inventory() if args.search.casefold() in
            (r["command"] + " " + r["description"] + " " + r["group"]).casefold()]
    if args.json or args.format == "json":
        print(json.dumps({"version": VERSION, "commands": rows}, indent=2))
        return 0
    print("Attestor %s - %d commands%s" % (
        VERSION, len(rows), " matching '" + args.search + "'" if args.search else ""))
    for row in rows:
        print("  %-12s %-9s %s%s" % (row["command"], row["group"], row["description"],
                                      " [missing]" if not row["available"] else ""))
    print("\nDetails: attestor help <command>")
    return 0


def _cmd_status(argv: list[str], doctor: bool = False) -> int:
    args = _system_parser("doctor" if doctor else "status").parse_args(argv)
    rows = _command_inventory()
    checks = [{"name": "Python", "ok": sys.version_info >= (3, 10),
               "detail": sys.version.split()[0]}]
    for command in ("security", "ui", "check", "scan"):
        row = next(r for r in rows if r["command"] == command)
        checks.append({"name": command, "ok": row["available"],
                       "detail": "entrypoint present" if row["available"] else "entrypoint missing"})
    try:
        _release_entrypoint()
        checks.append({"name": "Release engine", "ok": True, "detail": "integrity pin matches"})
    except (OSError, ValueError) as exc:
        checks.append({"name": "Release engine", "ok": False, "detail": str(exc)})
    report = {"version": VERSION, "ok": all(c["ok"] for c in checks),
              "root": str(ROOT), "python": sys.executable, "checks": checks,
              "commands": rows, "note": "Availability checks do not execute scanners or verify the whole release."}
    if doctor:
        report["disk_free_gb"] = round(shutil.disk_usage(ROOT).free / (1024 ** 3), 1)
        report["optional"] = {name: importlib.util.find_spec(name) is not None
                              for name in ("torch", "numpy")}
        report["optional"]["ollama"] = shutil.which("ollama") is not None
    if args.json or args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print("Attestor %s - %s" % (VERSION, "environment check" if doctor else "status"))
        print("Location: " + str(ROOT))
        for check in checks:
            print("  [%-7s] %-16s %s" % ("OK" if check["ok"] else "MISSING", check["name"], check["detail"]))
        if doctor:
            print("  Disk free: %.1f GB" % report["disk_free_gb"])
            print("  Optional: " + ", ".join(name + (" found" if found else " not installed")
                                            for name, found in report["optional"].items()))
        print("\n" + report["note"])
        print("Next: attestor ui | attestor security --help | attestor list")
    return EXIT_OPERATIONAL if doctor and not report["ok"] else EXIT_CLEAN


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
        import shlex
        try:
            # POSIX parsing consumes backslashes in Windows paths.
            parts = shlex.split(line, posix=os.name != "nt")
            if os.name == "nt":
                parts = [part[1:-1] if len(part) >= 2 and part[0] == part[-1]
                         and part[0] in ('"', "'") else part for part in parts]
        except ValueError as exc:
            print("attestor: " + str(exc), file=sys.stderr)
            continue
        if parts and parts[0] == "shell":
            print("attestor: already in shell", file=sys.stderr)
            continue
        ret = main(parts)
        # keep shell alive even if subcommand fails


def _main(argv: list[str]) -> int:
    global USE_COLOR
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--no-color" in argv:
        USE_COLOR = False
        argv.remove("--no-color")
        os.environ["NO_COLOR"] = "1"

    if argv and argv[0] == "help" and len(argv) > 1:
        argv = [*argv[1:], "--help"]
    if argv == ["--help-all"]:
        _print_help(full=True)
        return 0

    if not argv or argv[0] in ("-h", "--help", "help"):
        _print_help()
        return 0
    if argv[0] in ("--version", "-V", "version"):
        if _json_requested(argv):
            print(json.dumps({"version": VERSION, "python": sys.version.split()[0]}))
        else:
            print("Attestor %s" % VERSION)
        return 0

    cmd = argv[0]
    rest = argv[1:]

    # impl is its own module (clone+install), not just github alias
    if cmd == "impl":
        return _run_detector_module("impl42", rest)
    if cmd == "scan":
        return _cmd_scan(rest)
    if cmd in ("check", "report"):
        return _run_detector_module("cli", [cmd, *rest])
    if cmd == "verify":
        if rest in (["--json"], ["--format", "json"], ["--format=json"]):
            rest = []
        return _run_release_command("verify", rest)

    # direct detector modules
    if cmd in DETECTOR_MODULES:
        return _run_detector_module(DETECTOR_MODULES[cmd], rest)

    # passthrough legacy
    if cmd in PASSTHROUGH:
        return _run_passthrough(PASSTHROUGH[cmd], rest)

    # system commands
    if cmd == "list":
        return _cmd_list(rest)
    if cmd == "doctor":
        return _cmd_status(rest, doctor=True)
    if cmd == "shell":
        CliParser(prog="attestor shell", description="Interactive Attestor shell. Type help or exit.").parse_args(rest)
        _cmd_shell()
        return 0
    if cmd == "status":
        return _cmd_status(rest)

    close = difflib.get_close_matches(cmd, COMMANDS, n=1, cutoff=0.6)
    message = "unknown command '%s'. " % cmd
    message += "Did you mean '%s'?" % close[0] if close else "Try: attestor --help"
    return _error(message, EXIT_INVALID, argv)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        return _main(arguments)
    except KeyboardInterrupt:
        return _error("interrupted", 130, arguments)
    except CliUsageError as exc:
        return _error(str(exc), EXIT_INVALID, arguments)
    except (OSError, ValueError) as exc:
        return _error(str(exc), EXIT_OPERATIONAL, arguments)
    except Exception as exc:
        return _error("%s: %s" % (type(exc).__name__, exc), EXIT_OPERATIONAL, arguments)


if __name__ == "__main__":
    raise SystemExit(main())
