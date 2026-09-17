#!/usr/bin/env python3
"""Attestor unified CLI -- one command to rule them all.

    attestor check .                # THE command: scan + triage + what matters
    attestor check . --effort max   # deepest analysis (all scanners)
    attestor fix src/ --apply       # auto-fix safe findings (verified by re-scan)
    attestor fix src/ --pr          # auto-fix + open a pull request
    attestor scan src/              # grade Python files A-F
    attestor native src/            # grade C/C++/Assembly
    attestor review old.py new.py   # diff review (Python)
    attestor review app.py --git    # review against git HEAD
    attestor full .                 # full project analysis (4.1.4 engine)
    attestor secrets .              # scan for hardcoded secrets
    attestor exploits .             # detect backdoors, shells, C2
    attestor payloads .             # decode obfuscated payloads
    attestor sca .                  # check dependencies for vulns
    attestor iac .                  # scan IaC (Docker, K8s, Terraform)
    attestor js src/                # scan JavaScript/TypeScript
    attestor ioc .                  # threat intelligence IOC scan
    attestor surface .              # map attack surface
    attestor taint src/             # interprocedural taint tracking
    attestor binary .               # analyze .pyc/.class/.wasm binaries
    attestor supply-chain .         # typosquatting + dependency confusion
    attestor similarity src/        # CVE pattern similarity matching
    attestor git-history .          # scan git history for leaks
    attestor cicd .                 # CI/CD pipeline security
    attestor poc .                  # generate proof-of-concept exploits
    attestor compliance .           # OWASP/NIST/SOC2/PCI-DSS reports
    attestor chain .                # vulnerability chaining analysis
    attestor fix-verify .           # generate fix verification tests
    attestor correlate .            # runtime behavior correlation
    attestor report .               # generate HTML security report
    attestor baseline create        # create finding suppression baseline
    attestor hooks install          # install git pre-commit hook
    attestor watch .                # watch mode (auto-rescan)
    attestor sym-solve .             # symbolic path feasibility
    attestor abstract .              # abstract interpretation (value ranges)
    attestor clones .                # semantic clone detection
    attestor taint-dsl . --policy p  # custom taint policy (YAML)
    attestor api-scan spec.json      # OpenAPI/Swagger security scan
    attestor threat-model .          # auto-STRIDE threat model
    attestor sbom . --format spdx    # SBOM generation (CycloneDX/SPDX)
    attestor hybrid .                # static + model hybrid analysis
    attestor hybrid . --effort max   # deep hybrid with all scanners
    attestor memory show             # show memory (learned from past scans)
    attestor memory feedback tp --file f --line n  # mark finding as TP/FP
    attestor memory learn            # learn codebase patterns
    attestor retrain                 # retrain owen-coder from feedback
    attestor retrain --colab         # export Colab notebook for GPU training
    attestor novel .                 # detect structurally unusual code patterns
    attestor explain .               # explain findings in natural language
    attestor serve                   # start REST API server (enterprise)
    attestor serve --port 9000       # custom port
    attestor control policy          # show Owner Control policy
    attestor version                 # version info
"""
from __future__ import annotations

import argparse
import difflib
import importlib
import importlib.util
import json
import os
import sys
from pathlib import Path

_DETECTOR = Path(__file__).resolve().parent
if os.fspath(_DETECTOR) not in sys.path:
    sys.path.insert(0, os.fspath(_DETECTOR))

VERSION = "4.3"
_MACHINE_OUTPUT = False
BANNER = r"""
   _   _   _            _
  / \ | |_| |_ ___  ___| |_ ___  _ __
 / _ \| __| __/ _ \/ __| __/ _ \| '__|
/ ___ \ |_| ||  __/\__ \ || (_) | |
/_/  \_\__|\__\___||___/\__\___/|_|  v%s
""" % VERSION


def _banner():
    if not _MACHINE_OUTPUT and sys.stderr.isatty():
        sys.stderr.write("Attestor %s\n" % VERSION)
        sys.stderr.flush()


def _progress(message: str) -> None:
    """Keep diagnostics away from machine-readable stdout."""
    if not _MACHINE_OUTPUT:
        print(message)


class CliUsageError(ValueError):
    pass


class CliParser(argparse.ArgumentParser):
    def error(self, message):
        raise CliUsageError(message)


def _quick_help() -> None:
    print("Attestor %s | security assessments and code review" % VERSION)
    print("\nUsage: attestor <command> [options]")
    print("\nStart here:")
    for command, description in (
            ("ui", "open the local assessment interface"),
            ("security", "preview an assessment, run checks, export evidence"),
            ("check", "scan local code and prioritize findings"),
            ("scan", "grade Python files A-F"),
            ("report", "export an HTML report for local code"),
            ("status", "show installed command availability"),
            ("list", "search all commands")):
        print("  %-12s %s" % (command, description))
    print("\nExamples:")
    print("  attestor ui")
    print("  attestor security plan --target https://example.test --out plan.json")
    print('  attestor check "path to project" --json')
    print("  attestor list taint")
    print("\nMore: attestor help <command> | attestor --help-all")
    print("Options: --version | --no-color")


def _command_parsers(parser):
    return next(action.choices for action in parser._actions
                if isinstance(action, argparse._SubParsersAction))


def cmd_list(args):
    parser = build_parser()
    action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    rows = [{"command": choice.dest, "description": choice.help}
            for choice in action._choices_actions
            if args.search.casefold() in (choice.dest + " " + choice.help).casefold()]
    if args.json:
        print(json.dumps({"version": VERSION, "commands": rows}, indent=2))
    else:
        print("Attestor %s - %d commands" % (VERSION, len(rows)))
        for row in rows:
            print("  %-24s %s" % (row["command"], row["description"]))
        print("\nDetails: attestor help <command>")
    return 0


def cmd_status(args):
    modules = {"security": "security_assessment", "ui": "attestor_ui",
               "check": "detect", "scan": "grade", "report": "html_report"}
    checks = [{"command": name, "available": importlib.util.find_spec(module) is not None}
              for name, module in modules.items()]
    report = {"version": VERSION, "python": sys.executable, "location": str(_DETECTOR),
              "ok": all(check["available"] for check in checks), "commands": checks,
              "note": "Availability checks do not execute scanners or verify the whole release."}
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Attestor %s - status" % VERSION)
        print("Location: " + str(_DETECTOR))
        for check in checks:
            print("  [%-7s] %s" % ("OK" if check["available"] else "MISSING", check["command"]))
        print("\n" + report["note"])
        print("Next: attestor ui | attestor security --help")
    return 4 if args.command == "doctor" and not report["ok"] else 0


class C:
    """Minimal ANSI colorizer. Off when piped, when NO_COLOR is set, or --no-color."""
    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    _CODES = {"red": 91, "green": 92, "yellow": 93, "blue": 94, "magenta": 95,
              "cyan": 96, "grey": 90, "bold": 1, "dim": 2}

    @classmethod
    def paint(cls, s, *styles):
        if not cls.enabled:
            return s
        codes = ";".join(str(cls._CODES[s2]) for s2 in styles if s2 in cls._CODES)
        return f"\033[{codes}m{s}\033[0m" if codes else s


_SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def _sev(severity: str) -> str:
    return C.paint(f"{severity:8s}", _SEV_COLOR.get(severity, "grey"), "bold")


# Effort ladder: which scanners run. Higher effort = deeper + slower.
EFFORT_LEVELS = ("low", "medium", "high", "max")
EFFORT_SCANNERS = {
    "low":    ["core"],
    "medium": ["core", "secrets", "exploits", "iac", "js"],
    "high":   ["core", "secrets", "exploits", "iac", "js", "taint", "supply", "cicd", "git"],
    "max":    ["core", "secrets", "exploits", "iac", "js", "taint", "supply", "cicd",
               "git", "similarity", "binary", "novel", "phantom"],
}


_scan_errors: list[str] = []


def _run_effort(root: str, effort: str) -> list[dict]:
    """Run the scanner set for the given effort level and return unified findings."""
    wanted = set(EFFORT_SCANNERS.get(effort, EFFORT_SCANNERS["medium"]))
    findings: list[dict] = []
    _scan_errors.clear()

    def _add(objs, cat=None, cwe_attr=None):
        for f in objs:
            findings.append({
                "path": getattr(f, "path", getattr(f, "file", "")),
                "line": getattr(f, "line", getattr(f, "line_start", 0)),
                "rule_id": getattr(f, "rule_id", getattr(f, "rule", "")),
                "severity": getattr(f, "severity", "MEDIUM"),
                "description": getattr(f, "description", getattr(f, "message", "")),
                "category": cat or getattr(f, "category", ""),
                "cwe": getattr(f, cwe_attr, "") if cwe_attr else getattr(f, "cwe", ""),
            })

    def _try_scanner(name: str, fn):
        try:
            fn()
        except Exception as exc:
            _scan_errors.append(f"{name}: {exc}")

    def _core():
        import detect
        for p in detect.collect_paths([root]):
            for f in detect.scan_file(p):
                findings.append({
                    "path": getattr(f, "path", p), "line": getattr(f, "line", 0),
                    "rule_id": getattr(f, "rule", ""),
                    "severity": getattr(f, "severity", "MEDIUM"),
                    "description": getattr(f, "message", ""), "category": "core",
                })

    if "core" in wanted:
        _try_scanner("core", _core)

    scanner_map = {
        "secrets": ("secret_scanner", "secrets"), "exploits": ("exploit_detector", None),
        "iac": ("iac_scanner", None), "js": ("js_scanner", None),
        "supply": ("supply_chain", None), "cicd": ("cicd_scanner", None),
        "binary": ("binary_analyzer", None),
    }
    for key, (modname, cat) in scanner_map.items():
        if key not in wanted:
            continue

        def _run_mapped(mn=modname, c=cat):
            mod = __import__(mn)
            fn = getattr(mod, "scan_directory", None) or getattr(mod, "scan", None)
            if fn is None:
                raise AttributeError(f"{mn} has no scan_directory or scan function")
            _add(fn(root), c)

        _try_scanner(key, _run_mapped)

    if "taint" in wanted:
        def _taint():
            import taint_tracker
            for fl in taint_tracker.scan_directory(root):
                findings.append({"path": fl.sink_file, "line": fl.sink_line,
                                 "rule_id": f"TAINT-{fl.sink_type}", "severity": "HIGH",
                                 "description": f"{fl.source_type} -> {fl.sink_type}",
                                 "category": "taint", "cwe": fl.sink_cwe})
        _try_scanner("taint", _taint)

    if "git" in wanted:
        def _git():
            import git_history
            _add(git_history.scan(root), None)
        _try_scanner("git", _git)

    if "similarity" in wanted:
        def _sim():
            import semantic_similarity
            for m in semantic_similarity.scan_directory(root):
                findings.append({"path": m.path, "line": m.line_start,
                                 "rule_id": m.cve_id, "severity": m.cve_severity,
                                 "description": m.cve_description, "category": "similarity",
                                 "cwe": m.cve_cwe})
        _try_scanner("similarity", _sim)

    if "novel" in wanted:
        def _novel():
            import novel_detector
            nd = novel_detector.NovelDetector()
            for f in nd.scan_directory(root):
                findings.append({
                    "path": f.path, "line": f.line,
                    "rule_id": f"NOVEL-{f.category.upper()}",
                    "severity": f.severity,
                    "description": f.description,
                    "category": f.category,
                })
        _try_scanner("novel", _novel)

    return findings


def cmd_check(args):
    """The one-command experience: scan -> triage -> show what matters -> offer fix."""
    import triage
    import autofix
    import memory as mem_mod
    if args.no_color:
        C.enabled = False
    _banner()
    root = args.root
    effort = args.effort
    if not Path(root).exists():
        raise CliUsageError("target does not exist: " + root)
    _progress(f"\n  {C.paint('attestor check', 'bold', 'cyan')}  "
          f"{root}   effort={C.paint(effort, 'bold')}\n")

    mem = mem_mod.Memory(root)
    import time as _time
    _t0 = int(_time.time() * 1000)

    triage.load_overrides()
    findings = _run_effort(root, effort)

    pre_filter = len(findings)
    findings = mem.filter_findings(findings)
    mem_suppressed = pre_filter - len(findings)

    triaged = triage.triage_all(findings)
    counts = triage.counts(triaged)

    actionable = [t for t in triaged if t.action != "suppress"]
    autofixable = sum(1 for t in actionable
                      if t.finding.get("rule_id", "") in autofix.SAFE_FIXERS)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in actionable:
        s = t.finding.get("severity", "MEDIUM")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    total_raw = len(findings)
    suppressed = counts["suppress"]
    elapsed = int(_time.time() * 1000) - _t0
    mem.record_scan([t.finding for t in triaged], scan_type="check",
                    paths=[root], duration_ms=elapsed)
    exit_code = 3 if _scan_errors else (1 if actionable else 0)
    if args.json:
        print(json.dumps({
            "schema": "attestor-check/1", "root": root, "effort": effort,
            "status": "incomplete" if _scan_errors else "findings" if actionable else "clean",
            "findings": triage.to_dict(triaged), "counts": counts,
            "severity_counts": sev_counts, "scanner_errors": list(_scan_errors),
            "memory_suppressed": mem_suppressed, "duration_ms": elapsed,
            "exit_code": exit_code,
        }, indent=2))
        return exit_code
    print(f"  scanned with {len(EFFORT_SCANNERS[effort])} scanner group(s)")
    print(f"  {C.paint(str(total_raw), 'bold')} raw findings  ->  "
          f"{C.paint(str(len(actionable)), 'bold', 'green')} actionable  "
          f"({C.paint(str(suppressed), 'dim')} noise suppressed)")
    print(f"  {_sev('CRITICAL')}{C.paint(str(sev_counts['CRITICAL']),'red','bold')}   "
          f"{_sev('HIGH')}{sev_counts['HIGH']}   "
          f"{_sev('MEDIUM')}{sev_counts['MEDIUM']}   "
          f"{_sev('LOW')}{sev_counts['LOW']}")

    print(f"\n  {C.paint('Top findings:', 'bold')}")
    for t in actionable[:args.top]:
        f = t.finding
        p = f.get("path", "?")
        ln = f.get("line", "?")
        fixable = C.paint(" [autofixable]", "green") if f.get("rule_id") in autofix.SAFE_FIXERS else ""
        print(f"    {_sev(f.get('severity','?'))} {f.get('rule_id','?'):24s} "
              f"{p}:{ln}{fixable}")
        desc = (f.get("description") or "").strip().replace("\n", " ")
        if desc:
            print(f"      {C.paint(desc[:90], 'dim')}")
    if len(actionable) > args.top:
        print(f"    {C.paint(f'... and {len(actionable)-args.top} more', 'dim')}")

    if autofixable:
        print(f"\n  {C.paint('->', 'green', 'bold')} "
              f"{autofixable} finding(s) can be auto-fixed: "
              f"{C.paint(f'attestor fix {root} --apply', 'bold', 'cyan')}")
    if mem_suppressed:
        print(f"  {C.paint(f'  {mem_suppressed} suppressed by memory (known FPs)', 'dim')}")
    if _scan_errors:
        print(f"\n  {C.paint(f'Scanner errors ({len(_scan_errors)}):', 'yellow', 'bold')}")
        for err in _scan_errors:
            print(f"    {C.paint('!', 'yellow')} {err}")

    return exit_code


def cmd_scan(args):
    import grade
    import metrics
    errors = []
    graded = grade.collect(args.paths, top=args.top, errors=errors)
    if not graded and not errors:
        errors.append("no Python source files found")
    for msg in errors:
        print(f"error: {msg}", file=sys.stderr)
    if args.json:
        from dataclasses import asdict
        print(json.dumps(
            [{**asdict(fg), "fix_first": tips} for fg, tips in graded],
            indent=2))
    else:
        print(grade.render(graded, args.passing))
    return 2 if errors else min(len(grade.failures(graded, args.passing)), 250)


def cmd_native(args):
    import nativegrade
    errors = []
    graded = nativegrade.collect(args.paths, errors=errors)
    if not graded and not errors:
        errors.append("no C/C++/Assembly source files found")
    for msg in errors:
        print(f"error: {msg}", file=sys.stderr)
    if args.json:
        from dataclasses import asdict
        print(json.dumps(
            [{**asdict(fg), "fix_first": tips} for fg, tips in graded],
            indent=2))
    else:
        print(nativegrade.render(graded, args.passing))
    return 2 if errors else 0


def cmd_review(args):
    import review
    if args.git:
        result = review.review_git(args.paths[0], ref=args.ref or "HEAD")
    elif len(args.paths) == 2:
        result = review.review_files(args.paths[0], args.paths[1])
    else:
        print("error: provide two files or one file with --git", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(review.render(result, args.paths[-1]))
    return min(len(result.get("introduced", [])), 250)


def cmd_native_review(args):
    import nativereview
    result = nativereview.review(args.old, args.new)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(nativereview.render(result, args.new))
    return min(len(result.get("introduced", [])), 250)


def cmd_full(args):
    import attestor414
    return attestor414.main([
        args.root,
        "--variant", args.variant,
        "--format", args.format,
    ] + (["--out", args.out] if args.out else [])
      + (["--no-cache"] if args.no_cache else []))


def _read_source(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


class _Finding:
    __slots__ = ("line", "rule", "severity", "message", "path")
    def __init__(self, line, rule, severity, message, path=""):
        self.line = line
        self.rule = rule
        self.severity = severity
        self.message = message
        self.path = path


def _get_findings(path: str):
    src = _read_source(path)
    ext = Path(path).suffix.lower()
    if ext in (".c", ".h", ".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".s", ".asm"):
        import nativegrade
        raw = nativegrade._findings(path)
        findings = [_Finding(ln, rule, sev, msg, path)
                    for ln, rule, sev, msg in raw]
        return src, findings
    else:
        import grade
        import metrics
        _fg, findings, _funcs = grade.grade_source(src, path, metrics.DEFAULT_LIMITS)
        return src, findings


def cmd_ai_models(_args):
    import ai_engine
    _check_ai_soft()
    status = ai_engine.roster_status()
    print("\n  Model Roster:\n")
    for entry in status:
        icon = "+" if entry["loaded"] else "-"
        state = "loaded" if entry["loaded"] else "not installed"
        print(f"  [{icon}] {entry['model']}")
        print(f"      {entry['desc']}  ({state})")
    available = ai_engine.list_models()
    extra = [m for m in available
             if not any(m.startswith(r["model"]) for r in status)]
    if extra:
        print("\n  Other models in Ollama:")
        for m in extra:
            print(f"  [+] {m}")
    print(f"\n  Task routing:")
    for task, candidates in ai_engine.TASK_ROUTING.items():
        chosen = ai_engine.resolve_model(task)
        print(f"    {task:10s} -> {chosen}")
    print()
    return 0


def _check_ai():
    import ai_engine
    if not ai_engine.is_available():
        print(
            "error: Ollama is not running. Start it with:\n"
            "  ollama serve\n",
            file=sys.stderr)
        sys.exit(2)
    available = ai_engine.list_models()
    if not available:
        print(
            "error: no models loaded in Ollama.\n"
            "  Pull a model: ollama pull qwen2.5-coder:3b-instruct-q4_K_M\n"
            "  Or create owen-coder: ollama create owen-coder -f Modelfile\n",
            file=sys.stderr)
        sys.exit(2)


def _check_ai_soft():
    import ai_engine
    if not ai_engine.is_available():
        print("Ollama is not running.", file=sys.stderr)
        sys.exit(2)


def cmd_hybrid(args):
    """Hybrid analysis: static engines + owen-coder model judgment."""
    import hybrid_engine
    if getattr(args, "no_color", False):
        C.enabled = False
    _banner()
    _check_ai()
    root = args.root
    effort = getattr(args, "effort", "high")
    print(f"\n  {C.paint('attestor hybrid', 'bold', 'cyan')}  "
          f"{root}   effort={C.paint(effort, 'bold')}\n")

    analyzer = hybrid_engine.HybridAnalyzer(
        root, model=getattr(args, "model", None))
    results = analyzer.analyze(effort=effort,
                               batch=not getattr(args, "no_batch", False))

    if not results:
        print("  No findings.")
        return 0

    if args.json:
        print(json.dumps(hybrid_engine.to_dict(results), indent=2, default=str))
    else:
        print(hybrid_engine.render_results(results))

    exploitable = sum(1 for r in results if r.verdict == "EXPLOITABLE")
    return min(exploitable, 250)


def cmd_retrain(args):
    """Generate feedback training data and optionally retrain."""
    _banner()
    import subprocess
    training_dir = str(Path(__file__).resolve().parent.parent / "training")

    projects = args.projects or ["."]
    print(f"\n  {C.paint('attestor retrain', 'bold', 'cyan')}\n")

    print("  Step 1: Extract feedback from memory...")
    fb_script = os.path.join(training_dir, "feedback_to_training.py")
    subprocess.run(
        [sys.executable, fb_script] + projects,
        cwd=training_dir)

    print("\n  Step 2: Merge all training data...")
    merge_script = os.path.join(training_dir, "merge_training_data.py")
    subprocess.run([sys.executable, merge_script], cwd=training_dir)

    if getattr(args, "colab", False):
        print("\n  Step 3: Export Colab notebook...")
        colab_script = os.path.join(training_dir, "export_colab.py")
        model_size = getattr(args, "model", "14b")
        subprocess.run(
            [sys.executable, colab_script, "--model", model_size],
            cwd=training_dir)
        print(f"\n  Upload the .ipynb to Colab and run all cells.")
    elif getattr(args, "train", False):
        print("\n  Step 3: Training locally...")
        train_script = os.path.join(training_dir, "train_attestor.py")
        model_size = getattr(args, "model", "3b")
        subprocess.run(
            [sys.executable, train_script, "--model", model_size, "--skip-fetch"],
            cwd=training_dir)
    else:
        print("\n  Data ready. Next steps:")
        print(f"    Train locally:  attestor retrain --train --model 3b")
        print(f"    Train on Colab: attestor retrain --colab --model 14b")

    return 0


def cmd_control(args):
    import owner_control42
    argv = [args.control_command]
    if args.control_command == "policy":
        argv += ["--format", args.format]
    elif args.control_command == "run":
        argv += [args.plan_file]
        if args.permission:
            argv += ["--permission"]
        if args.confirm_plan_sha256:
            argv += ["--confirm-plan-sha256", args.confirm_plan_sha256]
        argv += ["--format", args.format]
    return owner_control42.main(argv)


def cmd_secrets(args):
    import secret_scanner
    _banner()
    _progress(f"\n  Secret Scanner -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(secret_scanner.scan_directory(p, entropy=not args.no_entropy))
        else:
            findings.extend(secret_scanner.scan_file(p, entropy=not args.no_entropy))
    if args.json:
        print(json.dumps(secret_scanner.to_dict(findings), indent=2))
    else:
        print(secret_scanner.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_exploits(args):
    import exploit_detector
    _banner()
    _progress(f"\n  Exploit Detector -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(exploit_detector.scan_directory(p))
        else:
            findings.extend(exploit_detector.scan_file(p))
    if args.json:
        print(json.dumps(exploit_detector.to_dict(findings), indent=2))
    else:
        print(exploit_detector.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_payloads(args):
    import payload_decoder
    _banner()
    _progress(f"\n  Payload Decoder -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(payload_decoder.scan_directory(p))
        else:
            findings.extend(payload_decoder.scan_file(p))
    if args.json:
        print(json.dumps(payload_decoder.to_dict(findings), indent=2))
    else:
        print(payload_decoder.render(findings))
    suspicious = [f for f in findings if f.is_suspicious]
    return min(len(suspicious), 250)


def cmd_sca(args):
    import sca_scanner
    _banner()
    root = args.root
    _progress(f"\n  SCA Scanner -- checking dependencies in {root}\n")
    deps, findings = sca_scanner.scan(root, offline=args.offline)
    if args.json:
        print(json.dumps(sca_scanner.to_dict(deps, findings), indent=2))
    else:
        print(sca_scanner.render(deps, findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_iac(args):
    import iac_scanner
    _banner()
    _progress(f"\n  IaC Scanner -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(iac_scanner.scan_directory(p))
        else:
            findings.extend(iac_scanner.scan_file(p))
    if args.json:
        print(json.dumps(iac_scanner.to_dict(findings), indent=2))
    else:
        print(iac_scanner.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_js(args):
    import js_scanner
    _banner()
    _progress(f"\n  JS/TS Scanner -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(js_scanner.scan_directory(p))
        else:
            findings.extend(js_scanner.scan_file(p))
    if args.json:
        print(json.dumps(js_scanner.to_dict(findings), indent=2))
    else:
        print(js_scanner.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_ioc(args):
    import threat_intel
    _banner()
    _progress(f"\n  Threat Intel IOC Scanner -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(threat_intel.scan_directory(p))
        else:
            findings.extend(threat_intel.scan_file(p))
    if args.json:
        print(json.dumps(threat_intel.to_dict(findings), indent=2))
    else:
        print(threat_intel.render(findings))
    return min(len(findings), 250) if findings else 0


def cmd_surface(args):
    import attack_surface
    _banner()
    _progress(f"\n  Attack Surface Mapper -- scanning {', '.join(args.paths)}\n")
    entries = []
    for p in args.paths:
        if os.path.isdir(p):
            entries.extend(attack_surface.scan_directory(p))
        else:
            entries.extend(attack_surface.scan_file(p))
    if args.json:
        print(json.dumps(attack_surface.to_dict(entries), indent=2))
    else:
        print(attack_surface.render(entries))
    return 0


def cmd_taint(args):
    import taint_tracker
    _banner()
    print(f"\n  Taint Tracker -- analyzing data flows in {', '.join(args.paths)}\n")
    flows = []
    for p in args.paths:
        if os.path.isdir(p):
            flows.extend(taint_tracker.scan_directory(p))
        else:
            flows.extend(taint_tracker.scan_file(p))
    if args.json:
        print(json.dumps(taint_tracker.to_dict(flows), indent=2))
    else:
        print(taint_tracker.render(flows))
    return min(len(flows), 250) if flows else 0


def cmd_dataflow(args):
    import dataflow
    _banner()
    print(f"\n  Dataflow Engine -- interprocedural taint with evidence traces\n")
    findings = dataflow.scan_paths(args.paths)
    if args.json:
        print(json.dumps(dataflow.to_dict(findings), indent=2))
    else:
        print(dataflow.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_confirm(args):
    import confirm
    _banner()
    print(f"\n  Dynamic Confirmation -- proving flows fire (without detonation)\n")
    results = confirm.confirm_paths(args.paths, timeout=args.timeout)
    if args.json:
        print(json.dumps(confirm.to_dict(results), indent=2))
    else:
        print(confirm.render(results))
    return min(sum(1 for r in results if r.status == "CONFIRMED"), 250)


def cmd_council(args):
    import model_council
    _banner()
    council = model_council.Council.discover()
    if args.add_remote:
        for entry in args.add_remote:
            parts = entry.split("|")
            url = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else f"remote-{len(council)}"
            key = parts[2].strip() if len(parts) > 2 else None
            council.add_remote(url, name, api_key=key)
    if not council.members:
        print("  No council members found.\n"
              "  Install models:\n"
              "    - Drop .gguf files in detector/models/\n"
              "    - Run Ollama (ollama serve) with models pulled\n"
              "    - Set ATTESTOR_COUNCIL_ENDPOINTS for remote models\n"
              "    - Use --add-remote URL|name to add a Colab endpoint")
        return 1
    print(f"\n  Model Council -- {len(council)} members\n")
    for m in council.roster():
        print(f"    {m['name']:20s} ({m['backend']:12s}) {m['model']}")
    if args.roster:
        return 0
    findings = _collect_findings(args.paths)
    if not findings:
        print("\n  No findings to adjudicate.")
        return 0
    verdicts = council.adjudicate(findings, parallel=not args.sequential)
    if args.json:
        print(json.dumps(model_council.to_dict(verdicts), indent=2))
    else:
        print(model_council.render(verdicts))
    return min(sum(1 for v in verdicts if v.verdict == "EXPLOITABLE"), 250)


def _collect_findings(paths):
    try:
        import killchain
        return killchain._collect_findings(paths)
    except Exception:
        pass
    try:
        import dataflow
        flows = dataflow.scan_paths(paths)
        return [
            {"category": f.sink_type, "cwe": f.cwe, "severity": f.severity,
             "file": f.sink_file, "line": f.sink_line,
             "description": f"taint flow: {f.source_type} -> {f.sink_type}",
             "interprocedural": f.interprocedural,
             "trace": [{"file": s.file, "line": s.line, "note": s.note} for s in f.trace]}
            for f in flows
        ]
    except Exception:
        pass
    try:
        import detect
        findings = []
        for p in paths:
            if os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for fn in files:
                        if fn.endswith((".py", ".js", ".ts", ".java", ".go", ".c", ".cpp")):
                            fp = os.path.join(root, fn)
                            try:
                                with open(fp, encoding="utf-8", errors="replace") as f:
                                    src = f.read()
                                findings.extend(detect.scan(src, fp))
                            except Exception:
                                pass
            elif os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as f:
                    src = f.read()
                findings.extend(detect.scan(src, p))
        return [
            {"category": getattr(f, "rule", ""), "severity": getattr(f, "severity", "MEDIUM"),
             "cwe": getattr(f, "cwe", ""), "file": getattr(f, "file", p),
             "line": getattr(f, "line", 0), "description": getattr(f, "message", "")}
            for f in findings
        ]
    except Exception:
        return []


def cmd_audit(args):
    import dataflow, adjudicate
    _banner()
    print(f"\n  Attestor Audit -- dataflow + adjudication\n")
    findings = dataflow.scan_paths(args.paths)
    if not findings:
        print("  No taint flows found.")
        return 0
    adjs = adjudicate.adjudicate(findings, model=getattr(args, "model", None))
    if args.json:
        print(json.dumps(adjudicate.to_dict(adjs), indent=2))
    else:
        print(adjudicate.render(adjs))
    return min(sum(1 for a in adjs if a.verdict == "EXPLOITABLE"), 250)


def cmd_reachability(args):
    import reachability
    _banner()
    print(f"\n  Reachability -- which findings can an attacker actually trigger?\n")
    ann = reachability.scan(args.paths)
    if args.json:
        print(json.dumps(reachability.to_dict(ann), indent=2))
    else:
        print(reachability.render(ann))
    return min(sum(1 for _f, r in ann if r.reachable), 250)


def cmd_binary(args):
    import binary_analyzer
    _banner()
    print(f"\n  Binary Analyzer -- scanning {', '.join(args.paths)}\n")
    findings = []
    for p in args.paths:
        if os.path.isdir(p):
            findings.extend(binary_analyzer.scan_directory(p))
        else:
            findings.extend(binary_analyzer.scan_file(p))
    if args.json:
        print(json.dumps(binary_analyzer.to_dict(findings), indent=2))
    else:
        print(binary_analyzer.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_supply_chain(args):
    import supply_chain
    _banner()
    root = args.root
    print(f"\n  Supply Chain Analyzer -- scanning {root}\n")
    findings = supply_chain.scan(root, internal_scope=args.internal_scope or "")
    if args.json:
        print(json.dumps(supply_chain.to_dict(findings), indent=2))
    else:
        print(supply_chain.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_similarity(args):
    import semantic_similarity
    _banner()
    print(f"\n  Semantic Similarity -- CVE pattern matching in {', '.join(args.paths)}\n")
    matches = []
    for p in args.paths:
        if os.path.isdir(p):
            matches.extend(semantic_similarity.scan_directory(p, threshold=args.threshold))
        else:
            matches.extend(semantic_similarity.scan_file(p, threshold=args.threshold))
    if args.json:
        print(json.dumps(semantic_similarity.to_dict(matches), indent=2))
    else:
        print(semantic_similarity.render(matches))
    return min(len(matches), 250) if matches else 0


def cmd_git_history(args):
    import git_history
    _banner()
    root = args.root
    print(f"\n  Git History Analyzer -- scanning {root}\n")
    findings = git_history.scan(root, max_commits=args.max_commits)
    if args.json:
        print(json.dumps(git_history.to_dict(findings), indent=2))
    else:
        print(git_history.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_cicd(args):
    import cicd_scanner
    _banner()
    root = args.root
    print(f"\n  CI/CD Pipeline Scanner -- scanning {root}\n")
    findings = cicd_scanner.scan_directory(root)
    if args.json:
        print(json.dumps(cicd_scanner.to_dict(findings), indent=2))
    else:
        print(cicd_scanner.render(findings))
    return min(sum(1 for f in findings if f.severity == "CRITICAL"), 250) if findings else 0


def cmd_poc(args):
    import poc_generator
    _banner()
    root = args.root
    print(f"\n  PoC Generator -- generating exploits for findings in {root}\n")
    all_findings = _collect_all_findings(root)
    pocs = poc_generator.generate_pocs_from_findings(all_findings)
    if args.json:
        print(json.dumps(poc_generator.to_dict(pocs), indent=2))
    else:
        print(poc_generator.render(pocs))
    return 0


def cmd_compliance(args):
    import compliance
    _banner()
    root = args.root
    framework = args.framework
    print(f"\n  Compliance Report -- {framework.upper()} for {root}\n")
    all_findings = _collect_all_findings(root)
    if framework == "all":
        output = compliance.render_all(all_findings, project_name=root)
        print(output)
    else:
        report = compliance.generate_report(all_findings, framework)
        if args.json:
            print(json.dumps(compliance.to_dict(report), indent=2))
        else:
            print(compliance.render(report))
    return 0


def cmd_chain(args):
    import vuln_chain
    _banner()
    root = args.root
    print(f"\n  Vulnerability Chaining -- analyzing {root}\n")
    all_findings = _collect_all_findings(root)
    chains = vuln_chain.analyze(all_findings)
    if args.json:
        print(json.dumps(vuln_chain.to_dict(chains), indent=2))
    else:
        print(vuln_chain.render(chains))
    return min(sum(1 for c in chains if c.severity == "CRITICAL"), 250) if chains else 0


def cmd_fix_verify(args):
    import fix_verifier
    _banner()
    root = args.root
    print(f"\n  Fix Verifier -- generating tests for {root}\n")
    all_findings = _collect_all_findings(root)
    tests = fix_verifier.generate_tests_from_findings(all_findings)
    if args.output:
        fix_verifier.write_test_file(tests, args.output)
        print(f"  Tests written to: {args.output}")
    if args.json:
        print(json.dumps(fix_verifier.to_dict(tests), indent=2))
    else:
        print(fix_verifier.render(tests))
    return 0


def cmd_correlate(args):
    import runtime_correlator
    _banner()
    root = args.root
    print(f"\n  Runtime Correlator -- correlating findings in {root}\n")
    all_findings = _collect_all_findings(root)
    coverage = {}
    if args.coverage:
        coverage = runtime_correlator.parse_coverage_report(args.coverage)
    signals = []
    if args.logs:
        signals.extend(runtime_correlator.parse_runtime_logs(args.logs))
    if args.traces:
        signals.extend(runtime_correlator.parse_trace_data(args.traces))
    results = runtime_correlator.correlate(all_findings, coverage, signals)
    if args.json:
        print(json.dumps(runtime_correlator.to_dict(results), indent=2))
    else:
        print(runtime_correlator.render(results))
    return 0


def cmd_bench(args):
    import bench_compare
    _banner()
    print(f"\n  Benchmark -- dataflow engine vs baselines\n")
    scores = bench_compare.run()
    if args.json:
        print(json.dumps(bench_compare.to_dict(scores), indent=2))
    else:
        print(bench_compare.render(scores))
    return 0


def cmd_swe_bench(args):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
    import swe_bench
    _banner()
    swe_bench.run_benchmark(
        limit=args.limit,
        filter_mode=args.filter,
        use_council=args.council,
        output_json=args.json)
    return 0


def cmd_evaluate(args):
    import evaluate
    _banner()
    if args.noise:
        nr = evaluate.measure_noise_reduction(args.noise)
        if args.json:
            print(json.dumps(nr, indent=2))
        else:
            print(evaluate.render_noise(nr))
        return 0
    sc = evaluate.build_scorecard()
    if args.calibrate:
        updated = evaluate.calibrate(sc)
        print(f"\n  Calibrated {len(updated)} rule weights from measured precision.")
        return 0
    if args.json:
        print(json.dumps(evaluate.to_dict(sc), indent=2))
    else:
        print(evaluate.render(sc))
    return 0


def cmd_triage(args):
    import triage
    _banner()
    root = args.root
    print(f"\n  Triage -- prioritizing findings in {root}\n")
    triage.load_overrides()
    all_findings = _collect_all_findings(root)
    triaged = triage.triage_all(all_findings)
    if args.json:
        print(json.dumps(triage.to_dict(triaged), indent=2))
    else:
        print(triage.render(triaged))
    return 0


def cmd_exploit(args):
    """Scan root, map findings to Metasploit modules, emit an .rc script."""
    import metasploit_bridge
    _banner()
    root = args.root
    print(f"\n  Exploit -- scanning {root} and building Metasploit resource script\n")
    raw = _collect_all_findings(root)
    # Normalize: bridge expects a cwe LIST; scanners emit a bare string or none
    findings = []
    for f in raw:
        cwe = f.get("cwe") or ""
        findings.append({**f, "cwe": [cwe] if isinstance(cwe, str) and cwe
                                     else list(cwe) if cwe else []})
    metasploit_bridge.write_rc(findings, args.out,
                               rhosts=args.rhosts, lhost=args.lhost,
                               lport=args.lport, payload_override=args.payload)
    if args.run:
        import subprocess as _sp
        msf = os.environ.get("ATT_MSFCONSOLE",
                             r"C:\metasploit-framework\bin\msfconsole.bat")
        print(f"\n  Launching: {msf} -r {args.out}")
        subprocess_rc = _sp.call([msf, "-r", os.path.abspath(args.out)])
        return subprocess_rc
    print(f"  Run it:  msfconsole -r {args.out}")
    return 0


def cmd_sym_solve(args):
    import sym_solve
    import dataflow
    _banner()
    print(f"\n  Symbolic Path Feasibility -- analyzing {', '.join(args.paths)}\n")
    flows = dataflow.to_dict(dataflow.scan_paths(args.paths))
    results = sym_solve.analyze_findings(flows, args.paths)
    if args.json:
        print(json.dumps(sym_solve.to_dict(results), indent=2))
    else:
        print(sym_solve.render(results))
    return 0


def cmd_abstract_interp(args):
    import abstract_interp
    _banner()
    print(f"\n  Abstract Interpretation -- analyzing {', '.join(args.paths)}\n")
    findings = abstract_interp.scan_paths(args.paths)
    if args.json:
        print(json.dumps(abstract_interp.to_dict(findings), indent=2))
    else:
        print(abstract_interp.render(findings))
    return 0


def cmd_clone_detect(args):
    import clone_detect
    _banner()
    print(f"\n  Semantic Clone Detection -- scanning {', '.join(args.paths)}\n")
    clones, nears = clone_detect.scan_paths(args.paths, near_threshold=args.threshold)
    if args.json:
        print(json.dumps(clone_detect.to_dict(clones, nears), indent=2))
    else:
        print(clone_detect.render(clones, nears))
    return 0


def cmd_taint_dsl(args):
    import taint_dsl
    _banner()
    policy = taint_dsl.load_policy_file(args.policy)
    print(f"\n  Taint Policy DSL -- policy '{policy.name}' on {', '.join(args.paths)}\n")
    findings = taint_dsl.scan_with_policy(args.paths, policy)
    if args.json:
        print(json.dumps(taint_dsl.to_dict(findings), indent=2))
    else:
        print(taint_dsl.render(findings))
    return 0


def cmd_api_scan(args):
    import api_scan
    _banner()
    print(f"\n  API Security Scan -- analyzing {', '.join(args.paths)}\n")
    findings = api_scan.scan_paths(args.paths)
    if args.json:
        print(json.dumps(api_scan.to_dict(findings), indent=2))
    else:
        print(api_scan.render(findings))
    return 0


def cmd_threat_model(args):
    import threat_model
    _banner()
    print(f"\n  Threat Model Generator -- analyzing {', '.join(args.paths)}\n")
    comps, bounds, threats = threat_model.scan_paths(args.paths)
    if args.json:
        print(json.dumps(threat_model.to_dict(threats), indent=2))
    else:
        print(threat_model.render(comps, bounds, threats))
    return 0


def cmd_sbom(args):
    import sbom_gen
    _banner()
    print(f"\n  SBOM Generator -- collecting from {', '.join(args.paths)}\n")
    deps = sbom_gen.collect_deps(args.paths)
    if args.format == "cyclonedx":
        print(json.dumps(sbom_gen.to_cyclonedx(deps, args.project), indent=2))
    elif args.format == "spdx":
        print(json.dumps(sbom_gen.to_spdx(deps, args.project), indent=2))
    else:
        print(sbom_gen.render(deps))
    return 0


def cmd_fix(args):
    import autofix
    _banner()
    apply = args.apply or args.pr or args.test    # --pr/--test imply --apply
    mode = "applying" if apply else "previewing"
    print(f"\n  Autofix -- {mode} safe fixes in {', '.join(args.paths)}\n")

    test_report = None
    if args.test:
        results, test_report = autofix.apply_with_test_gate(
            args.paths, aggressive=args.aggressive, test_cmd=args.test_cmd)
    else:
        results = autofix.fix_paths(args.paths, apply=apply, aggressive=args.aggressive)

    if args.json:
        out = {"results": autofix.to_dict(results)}
        if test_report:
            out["tests"] = {"ran": test_report.ran, "passed": test_report.passed,
                            "summary": test_report.summary}
        if args.pr:
            out["pr"] = autofix.create_pr(results, base=args.base)
        print(json.dumps(out, indent=2))
    else:
        print(autofix.render(results, apply=apply))
        if test_report:
            if not test_report.ran:
                print(f"\n  Tests: not run ({test_report.summary})")
            elif test_report.passed:
                print(f"\n  Tests: {C.paint('PASSED', 'green', 'bold')} -- fixes are non-breaking.")
            else:
                print(f"\n  Tests: {C.paint('FAILED', 'red', 'bold')} -- all fixes reverted.")
                print(f"    {test_report.summary}")
        if args.pr:
            info = autofix.create_pr(results, base=args.base)
            print(autofix.render_pr(info))
    return 0


def cmd_interproc(args):
    import interprocedural
    _banner()
    print(f"\n  Inter-procedural Analysis -- indexing {', '.join(args.paths)}\n")
    index = interprocedural.build_index(args.paths)
    graph = interprocedural.build_call_graph(index)
    findings = interprocedural.analyze(index, graph, max_depth=args.depth)
    if args.json:
        print(json.dumps(interprocedural.to_dict(findings), indent=2))
    else:
        print(interprocedural.render(findings, index))
    return 0


def cmd_killchain(args):
    import killchain
    _banner()
    print(f"\n  Kill Chain Synthesis -- analyzing {', '.join(args.paths)}\n")
    if args.full:
        chains = killchain.synthesize_from_engines(args.paths)
    else:
        import interprocedural
        import detect
        all_findings = []
        for p in args.paths:
            if os.path.isfile(p):
                for f in detect.scan_file(p):
                    d = {}
                    for attr in ("rule", "line", "severity", "file", "sink_type",
                                 "sink_line", "cwe", "category"):
                        val = getattr(f, attr, None)
                        if val is not None:
                            d[attr] = val
                    all_findings.append(d)
        try:
            inter = interprocedural.scan_paths(args.paths)
            all_findings.extend(interprocedural.to_dict(inter))
        except Exception:
            pass
        chains = killchain.synthesize(all_findings)
    if args.graph:
        import attack_graph_viz
        out = args.output or "attack-graph.html"
        attack_graph_viz.write_html(killchain.to_dict(chains), out)
        print(f"  attack graph written to: {os.path.abspath(out)}")
    elif args.json:
        print(json.dumps(killchain.to_dict(chains), indent=2))
    else:
        print(killchain.render(chains))
    return 0


def cmd_attack_graph(args):
    import killchain
    import attack_graph_viz
    _banner()
    print(f"\n  Attack Graph -- visualizing {', '.join(args.paths)}\n")
    chains = killchain.synthesize_from_engines(args.paths)
    dicts = killchain.to_dict(chains)
    out = args.output or "attack-graph.html"
    attack_graph_viz.write_html(dicts, out)
    print(f"  {len(chains)} chain(s) rendered to: {os.path.abspath(out)}")
    print(f"  open it in a browser to explore the interactive graph.")
    return 0


def cmd_plan_fix(args):
    import fixengine
    _banner()
    print(f"\n  Fix Engine -- planning fixes for {', '.join(args.paths)}\n")

    all_plans = []
    all_results = []
    for p in args.paths:
        if os.path.isfile(p):
            files = [p]
        elif os.path.isdir(p):
            files = []
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules"}]
                for n in fn:
                    if n.endswith((".py", ".js", ".ts")):
                        files.append(os.path.join(dp, n))
        else:
            continue
        for filepath in files:
            plans = fixengine.plan_file(filepath)
            all_plans.extend(plans)
            if args.apply and plans:
                try:
                    with open(filepath, encoding="utf-8", errors="replace") as f:
                        source = f.read()
                    fixed, results = fixengine.apply_fixes(plans, source)
                    all_results.extend(results)
                    if any(r.applied for r in results):
                        with open(filepath, "w", encoding="utf-8", newline="") as f:
                            f.write(fixed)
                except OSError:
                    pass

    if args.json:
        out = {"plans": fixengine.to_dict(all_plans)}
        if all_results:
            out["applied"] = sum(1 for r in all_results if r.applied)
        print(json.dumps(out, indent=2))
    else:
        print(fixengine.render(all_plans, all_results or None))
    return 0


def _collect_all_findings(root: str) -> list[dict]:
    """Collect findings from all scanners for aggregate analysis."""
    all_findings = []
    try:
        import secret_scanner
        for f in secret_scanner.scan_directory(root):
            all_findings.append({
                "path": f.path, "line": f.line, "rule_id": f.rule_id,
                "description": f.description, "severity": f.severity,
                "category": "secrets",
            })
    except Exception:
        pass
    try:
        import exploit_detector
        for f in exploit_detector.scan_directory(root):
            all_findings.append({
                "path": f.path, "line": f.line, "rule_id": f.rule_id,
                "description": f.description, "severity": f.severity,
                "category": f.category, "mitre_id": f.mitre_id,
            })
    except Exception:
        pass
    try:
        import iac_scanner
        for f in iac_scanner.scan_directory(root):
            all_findings.append({
                "path": f.path, "line": f.line, "rule_id": f.rule_id,
                "description": f.description, "severity": f.severity,
                "category": f.category, "remediation": f.remediation,
            })
    except Exception:
        pass
    try:
        import js_scanner
        for f in js_scanner.scan_directory(root):
            all_findings.append({
                "path": f.path, "line": f.line, "rule_id": f.rule_id,
                "description": f.description, "severity": f.severity,
                "category": f.category, "cwe": f.cwe,
            })
    except Exception:
        pass
    return all_findings


def cmd_report(args):
    import html_report
    _banner()
    root = args.root
    print(f"\n  Generating security report for {root}...\n")
    all_findings = []

    import secret_scanner
    for f in secret_scanner.scan_directory(root):
        all_findings.append({
            "path": f.path, "line": f.line, "rule_id": f.rule_id,
            "description": f.description, "severity": f.severity,
            "category": "secrets",
        })

    import exploit_detector
    for f in exploit_detector.scan_directory(root):
        all_findings.append({
            "path": f.path, "line": f.line, "rule_id": f.rule_id,
            "description": f.description, "severity": f.severity,
            "category": f.category, "mitre_id": f.mitre_id,
        })

    import iac_scanner
    for f in iac_scanner.scan_directory(root):
        all_findings.append({
            "path": f.path, "line": f.line, "rule_id": f.rule_id,
            "description": f.description, "severity": f.severity,
            "category": f.category, "remediation": f.remediation,
        })

    import js_scanner
    for f in js_scanner.scan_directory(root):
        all_findings.append({
            "path": f.path, "line": f.line, "rule_id": f.rule_id,
            "description": f.description, "severity": f.severity,
            "category": f.category, "cwe": f.cwe,
        })

    output = args.output or "attestor-report.html"
    project = args.project or os.path.basename(os.path.abspath(root))
    html_report.write_report(all_findings, output, project_name=project, root=root)
    print(f"  Report written to: {output}")
    print(f"  Total findings: {len(all_findings)}")
    return 0


def cmd_baseline(args):
    import baseline as bl
    if args.baseline_command == "create":
        _banner()
        root = args.root
        print(f"\n  Creating baseline from current findings in {root}...\n")
        all_findings = []
        import secret_scanner
        for f in secret_scanner.scan_directory(root):
            all_findings.append({"path": f.path, "line": f.line, "rule_id": f.rule_id,
                                 "description": f.description})
        import exploit_detector
        for f in exploit_detector.scan_directory(root):
            all_findings.append({"path": f.path, "line": f.line, "rule_id": f.rule_id,
                                 "description": f.description})
        baseline_obj = bl.create_baseline_from_findings(
            all_findings, reason=args.reason or "initial baseline")
        out = args.output or bl.DEFAULT_BASELINE_FILE
        bl.save_baseline(baseline_obj, out)
        print(f"  Baseline created: {out}")
        print(f"  Suppressed: {len(baseline_obj.suppressions)} findings")
        return 0
    elif args.baseline_command == "status":
        baseline_obj = bl.load_baseline(args.file or bl.DEFAULT_BASELINE_FILE)
        print(bl.render_baseline_status(baseline_obj))
        return 0
    elif args.baseline_command == "clear":
        out = args.file or bl.DEFAULT_BASELINE_FILE
        if os.path.exists(out):
            os.remove(out)
            print(f"  Baseline removed: {out}")
        else:
            print(f"  No baseline file at: {out}")
        return 0
    return 0


def cmd_sales(args):
    import sales_engine
    _banner()
    sa = sales_engine.SalesAnalyzer(args.data_dir)
    subcmd = getattr(args, "sales_command", None)

    if subcmd == "ingest":
        for csv_path in args.files:
            result = sa.ingest(csv_path, source=getattr(args, "source", ""))
            status = result["status"]
            if status == "imported":
                print(f"  Imported {result['rows']} rows from {csv_path}")
            elif status == "skipped":
                print(f"  Skipped {csv_path} (already imported)")
            else:
                print(f"  Error: {result.get('reason', 'unknown')}")
        return 0

    if subcmd == "analyze":
        report = sa.analyze(days=args.days)
        if args.json:
            print(json.dumps(sales_engine.to_dict(report), indent=2, default=str))
        else:
            print(sa.render(report))
        return 0

    if subcmd == "clear":
        sa.clear()
        print("  Sales data cleared.")
        return 0

    print("  Usage: attestor sales {ingest|analyze|clear}")
    return 0


def cmd_inventory(args):
    import inventory_engine
    _banner()
    mon = inventory_engine.InventoryMonitor(args.data_dir)
    subcmd = getattr(args, "inv_command", None)

    if subcmd == "load":
        result = mon.load_stock(args.file)
        print(f"  Loaded {result['items']} items")
        return 0

    if subcmd == "check":
        if args.stock:
            mon.load_stock(args.stock)
        if not mon._stock:
            print("  No stock loaded. Use: attestor inventory load stock.csv")
            return 1
        if not mon._thresholds:
            mon.set_default_threshold(
                min_qty=args.min_qty, reorder_qty=args.reorder_qty)
        alerts = mon.check_thresholds()
        if args.json:
            print(json.dumps(inventory_engine.alerts_to_dict(alerts), indent=2))
        else:
            print(mon.render_alerts(alerts))
        if args.slack and alerts:
            ok = mon.send_slack_alert(args.slack, alerts)
            print(f"  Slack: {'sent' if ok else 'failed'}")
        if args.po and alerts:
            po = mon.generate_po(alerts, vendor=args.vendor or "")
            if po:
                print(f"  PO draft: {po.po_number} (${po.total:,.2f})")
        return 0

    if subcmd == "threshold":
        mon.set_threshold(args.sku, min_qty=args.min_qty,
                          reorder_qty=args.reorder_qty)
        print(f"  Threshold set for {args.sku}: min={args.min_qty}, "
              f"reorder={args.reorder_qty}")
        return 0

    print("  Usage: attestor inventory {load|check|threshold}")
    return 0


def cmd_schedule(args):
    import scheduler_engine
    _banner()
    s = scheduler_engine.Scheduler()
    subcmd = getattr(args, "sched_command", None)

    if subcmd == "solve":
        if args.employees:
            s.load_employees_csv(args.employees)
        if args.shifts:
            s.load_shifts_csv(args.shifts)
        if args.labour_cap:
            s.set_labour_cap(args.labour_cap)
        schedule = s.solve(week_start=args.week or "")
        if args.json:
            print(json.dumps(scheduler_engine.to_dict(schedule), indent=2))
        elif args.gcal:
            events = scheduler_engine.to_gcal_events(schedule)
            out = args.output or "schedule_events.json"
            with open(out, "w") as f:
                json.dump(events, f, indent=2)
            print(f"  {len(events)} events exported to {out}")
            print(f"  Import via Google Calendar API or gcalcli")
        else:
            print(s.render(schedule))
        return 0

    print("  Usage: attestor schedule solve --employees staff.csv --shifts shifts.csv")
    return 0


def cmd_novel(args):
    """Detect structurally unusual code -- catches what rules miss."""
    import novel_detector
    if getattr(args, "no_color", False):
        C.enabled = False
    _banner()
    root = args.root
    _progress(f"\n  {C.paint('attestor novel', 'bold', 'cyan')}  {root}\n")

    nd = novel_detector.NovelDetector(
        z_threshold=getattr(args, "threshold", 2.0))

    if os.path.isdir(root):
        findings = nd.scan_directory(root)
    else:
        findings = nd.scan_file(root)

    if args.json:
        print(json.dumps(novel_detector.to_dict(findings), indent=2))
    else:
        print(novel_detector.render(findings))

    return min(sum(1 for f in findings if f.severity == "HIGH"), 250)


def cmd_explain(args):
    """Explain findings in natural language."""
    import explainer
    if getattr(args, "no_color", False):
        C.enabled = False
    _banner()
    root = args.root
    effort = getattr(args, "effort", "medium")
    _progress(f"\n  {C.paint('attestor explain', 'bold', 'cyan')}  "
          f"{root}   effort={C.paint(effort, 'bold')}\n")

    findings = _run_effort(root, effort)

    if not findings:
        if args.json:
            print(json.dumps({"findings": [], "scanner_errors": list(_scan_errors)}))
        else:
            print("  No findings to explain.")
            for error in _scan_errors:
                print("  Scanner error: " + error, file=sys.stderr)
        return 3 if _scan_errors else 0

    top_n = getattr(args, "top", 10)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 4))
    findings = findings[:top_n]

    exp = explainer.Explainer(
        context_lines=getattr(args, "context", 5))
    explanations = exp.explain_batch(findings)

    if args.json:
        print(json.dumps(explainer.to_dict(explanations), indent=2))
    else:
        print(explainer.render(explanations))

    return 0


def cmd_phantom(args):
    """Phantom Analysis -- autonomous exploit verification (4.3)."""
    import phantom43
    _banner()
    return phantom43.main([
        args.root,
        *(["--finding", args.finding] if args.finding else []),
        *(["--severity", args.severity] if args.severity else []),
        *(["--output", args.output] if args.output else []),
        *(["--exploit"] if args.exploit else []),
        *(["--effort", args.effort] if hasattr(args, "effort") else []),
        *(["--json"] if args.json else []),
        *(["--no-color"] if getattr(args, "no_color", False) else []),
    ])


def cmd_model_status(args):
    """Show AI model status and availability (4.3)."""
    import model_loader43
    _banner()
    info = model_loader43.status()
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(f"\n  {C.paint('Model Status', 'bold', 'cyan')}\n")
    print(f"  Active backend:  {C.paint(info['active_backend'], 'bold')}")
    print(f"  Active model:    {C.paint(info['active_model'], 'bold', 'green')}")
    print(f"  LoRA adapter:    {info['adapter_found'] or C.paint('not found', 'dim')}")
    print(f"  GGUF file:       {info['gguf_found'] or C.paint('not found', 'dim')}")
    print(f"  Ollama (43):     {'yes' if info['ollama_finetuned'] else 'no'}")
    print(f"  llama-cpp:       {'installed' if info['llama_cpp_available'] else 'not installed'}")
    print()
    return 0


def cmd_serve(args):
    """Start REST API server for enterprise/CI/CD integration."""
    import api_server
    _banner()
    print(f"\n  {C.paint('attestor serve', 'bold', 'cyan')}  "
          f"{args.host}:{args.port}\n")
    api_server.serve(host=args.host, port=args.port)
    return 0


def cmd_hooks(args):
    import git_hooks
    if args.hooks_command == "install":
        result = git_hooks.install_hook(
            hook_type=args.hook_type or "pre-commit",
            pass_grade=args.grade or "C",
            block_on_fail=args.block,
        )
        print(f"  {result}")
        return 0
    elif args.hooks_command == "uninstall":
        result = git_hooks.uninstall_hook(hook_type=args.hook_type or "pre-commit")
        print(f"  {result}")
        return 0
    elif args.hooks_command == "status":
        print(git_hooks.status())
        return 0
    return 0


def cmd_watch(args):
    import watch_mode
    modes = args.modes.split(",") if args.modes else ["secrets", "exploits"]
    callback = watch_mode.scan_callback_factory(modes)
    watch_mode.watch(
        args.root,
        callback=callback,
        interval=args.interval,
    )
    return 0


def cmd_memory(args):
    import memory as mem_mod
    mem = mem_mod.Memory(getattr(args, "root", "."))
    subcmd = getattr(args, "memory_command", None)

    if subcmd == "show":
        if args.json:
            print(json.dumps(mem_mod.to_dict(mem), indent=2, default=str))
        else:
            print(mem.render())
        return 0

    if subcmd == "feedback":
        finding = {
            "path": args.file or "", "line": args.line or 0,
            "rule_id": args.rule or "",
        }
        mem.feedback_finding(finding, args.verdict, reason=args.reason or "")
        print(f"  Recorded {args.verdict} for {args.rule or 'finding'}"
              f" at {args.file}:{args.line}")
        return 0

    if subcmd == "learn":
        mem.learn_patterns([args.root])
        patterns = mem.get_patterns()
        fw = patterns.get("frameworks", [])
        print(f"  Learned codebase patterns")
        if fw:
            print(f"  Frameworks: {', '.join(fw)}")
        imports = list(patterns.get("top_imports", {}).keys())[:10]
        if imports:
            print(f"  Top imports: {', '.join(imports)}")
        return 0

    if subcmd == "stats":
        stats = mem.get_stats()
        if not stats:
            print("  No scan history yet.")
            return 0
        print(f"  Total scans:    {stats.get('total_scans', 0)}")
        print(f"  Total findings: {stats.get('total_findings', 0)}")
        print(f"  Last scan:      {stats.get('last_scan', 'never')}")
        hotspots = mem.get_hotspot_files(5)
        if hotspots:
            print(f"\n  Hotspot files:")
            for path, count in hotspots:
                print(f"    {count:3d} findings  {path}")
        noisy = mem.get_noisy_rules()
        if noisy:
            print(f"\n  Rule precision:")
            for r in noisy[:5]:
                print(f"    {r['rule']:30s}  {r['precision']:.0%}  "
                      f"({r['tp']}tp/{r['fp']}fp)")
        return 0

    if subcmd == "clear":
        mem.clear()
        print("  Memory cleared.")
        return 0

    print("  Usage: attestor memory {show|feedback|learn|stats|clear}")
    return 0


def cmd_version(args):
    if getattr(args, "json", False):
        print(json.dumps({"version": VERSION, "python": sys.version.split()[0]}))
        return 0
    _banner()
    print(f"  Attestor {VERSION}")
    print(f"  Python   {sys.version.split()[0]}")
    print(f"  engines  dataflow, taint, sym-solve, abstract-interp, clone-detect,")
    print(f"           api-scan, threat-model, sbom, iac, ci, dep-scan, reachability")
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = CliParser(
        prog="attestor",
        description="Attestor %s - security assessments and code review" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Start with attestor ui or attestor security --help. Use attestor help <command> for details.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.add_parser("security", help="preview an assessment, run checks, export evidence")
    sub.add_parser("ui", help="open the local assessment interface")
    p_list = sub.add_parser("list", help="search all commands")
    p_list.add_argument("search", nargs="?", default="")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)
    for command in ("status", "doctor"):
        p_status = sub.add_parser(command, help="show installed command availability")
        p_status.add_argument("--json", action="store_true")
        p_status.set_defaults(func=cmd_status)

    # --- scan (Python grading) ---
    p_scan = sub.add_parser("scan", help="grade Python files A-F",
                            aliases=["grade"])
    p_scan.add_argument("paths", nargs="+", help="files or directories")
    p_scan.add_argument("--pass", dest="passing", default="C",
                        choices=["A", "B", "C", "D", "F"])
    p_scan.add_argument("--top", type=int, default=6)
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    # --- native (C/C++/Assembly grading) ---
    p_nat = sub.add_parser("native", help="grade C/C++/Assembly files",
                           aliases=["nscan"])
    p_nat.add_argument("paths", nargs="+")
    p_nat.add_argument("--pass", dest="passing", default="C",
                       choices=["A", "B", "C", "D", "F"])
    p_nat.add_argument("--json", action="store_true")
    p_nat.set_defaults(func=cmd_native)

    # --- review (Python diff review) ---
    p_rev = sub.add_parser("review", help="review Python code changes",
                           aliases=["diff"])
    p_rev.add_argument("paths", nargs="+", help="old new | file --git")
    p_rev.add_argument("--git", action="store_true",
                       help="compare against git HEAD")
    p_rev.add_argument("--ref", help="git ref to compare against")
    p_rev.add_argument("--json", action="store_true")
    p_rev.set_defaults(func=cmd_review)

    # --- native-review ---
    p_nrev = sub.add_parser("native-review", help="review C/C++ changes",
                            aliases=["ndiff"])
    p_nrev.add_argument("old")
    p_nrev.add_argument("new")
    p_nrev.add_argument("--json", action="store_true")
    p_nrev.set_defaults(func=cmd_native_review)

    # --- full (4.1.4 orchestrator) ---
    p_full = sub.add_parser("full", help="full project analysis (4.1.4 engine)",
                            aliases=["analyze"])
    p_full.add_argument("root", nargs="?", default=".")
    p_full.add_argument("--variant", default="cockroach-janta-party")
    p_full.add_argument("--format", choices=("text", "json", "sarif"),
                        default="text")
    p_full.add_argument("--out")
    p_full.add_argument("--no-cache", action="store_true")
    p_full.set_defaults(func=cmd_full)

    # --- secrets ---
    p_sec = sub.add_parser("secrets", help="scan for hardcoded secrets & credentials")
    p_sec.add_argument("paths", nargs="+", help="files or directories")
    p_sec.add_argument("--json", action="store_true")
    p_sec.add_argument("--no-entropy", action="store_true",
                       help="disable entropy-based detection")
    p_sec.set_defaults(func=cmd_secrets)

    # --- exploits ---
    p_exp = sub.add_parser("exploits", help="detect backdoors, shells, C2, malware",
                           aliases=["malware"])
    p_exp.add_argument("paths", nargs="+", help="files or directories")
    p_exp.add_argument("--json", action="store_true")
    p_exp.set_defaults(func=cmd_exploits)

    # --- payloads ---
    p_pay = sub.add_parser("payloads", help="decode obfuscated payloads",
                           aliases=["decode"])
    p_pay.add_argument("paths", nargs="+", help="files or directories")
    p_pay.add_argument("--json", action="store_true")
    p_pay.set_defaults(func=cmd_payloads)

    # --- sca ---
    p_sca = sub.add_parser("sca", help="check dependencies for known vulns",
                           aliases=["deps"])
    p_sca.add_argument("root", nargs="?", default=".")
    p_sca.add_argument("--json", action="store_true")
    p_sca.add_argument("--offline", action="store_true",
                       help="skip OSV API queries")
    p_sca.set_defaults(func=cmd_sca)

    # --- iac ---
    p_iac = sub.add_parser("iac", help="scan IaC files (Docker, K8s, Terraform, GHA)",
                           aliases=["infra"])
    p_iac.add_argument("paths", nargs="+", help="files or directories")
    p_iac.add_argument("--json", action="store_true")
    p_iac.set_defaults(func=cmd_iac)

    # --- js ---
    p_js = sub.add_parser("js", help="scan JavaScript/TypeScript for security issues",
                          aliases=["ts"])
    p_js.add_argument("paths", nargs="+", help="files or directories")
    p_js.add_argument("--json", action="store_true")
    p_js.set_defaults(func=cmd_js)

    # --- ioc (threat intel) ---
    p_ioc = sub.add_parser("ioc", help="threat intelligence IOC scanner",
                           aliases=["threat"])
    p_ioc.add_argument("paths", nargs="+", help="files or directories")
    p_ioc.add_argument("--json", action="store_true")
    p_ioc.set_defaults(func=cmd_ioc)

    # --- surface (attack surface mapper) ---
    p_surf = sub.add_parser("surface", help="map attack surface (endpoints, inputs, auth)",
                            aliases=["attack-surface"])
    p_surf.add_argument("paths", nargs="+", help="files or directories")
    p_surf.add_argument("--json", action="store_true")
    p_surf.set_defaults(func=cmd_surface)

    # --- taint (interprocedural taint tracking) ---
    p_taint = sub.add_parser("taint", help="taint tracking (pattern-based, legacy)")
    p_taint.add_argument("paths", nargs="+", help="files or directories")
    p_taint.add_argument("--json", action="store_true")
    p_taint.set_defaults(func=cmd_taint)

    # --- dataflow (interprocedural taint with evidence traces -- SOTA core) ---
    p_df = sub.add_parser("dataflow", help="interprocedural taint with evidence traces",
                          aliases=["flow"])
    p_df.add_argument("paths", nargs="+", help="files or directories")
    p_df.add_argument("--json", action="store_true")
    p_df.set_defaults(func=cmd_dataflow)

    # --- reachability (whole-program: which findings are triggerable) ---
    p_reach = sub.add_parser("reachability", help="whole-program reachability of findings",
                             aliases=["reach"])
    p_reach.add_argument("paths", nargs="+", help="files or directories")
    p_reach.add_argument("--json", action="store_true")
    p_reach.set_defaults(func=cmd_reachability)

    # --- confirm (dynamic confirmation without detonation) ---
    p_conf = sub.add_parser("confirm", help="dynamically prove flows fire (no detonation)")
    p_conf.add_argument("paths", nargs="+", help="files or directories")
    p_conf.add_argument("--timeout", type=int, default=15, help="per-file harness timeout (s)")
    p_conf.add_argument("--json", action="store_true")
    p_conf.set_defaults(func=cmd_confirm)

    # --- audit (flagship hybrid: dataflow + adjudication) ---
    p_audit = sub.add_parser("audit", help="HYBRID: dataflow + adjudication")
    p_audit.add_argument("paths", nargs="+", help="files or directories")
    p_audit.add_argument("--model", help="override adjudication model")
    p_audit.add_argument("--json", action="store_true")
    p_audit.set_defaults(func=cmd_audit)

    # --- binary (bytecode/binary analysis) ---
    p_bin = sub.add_parser("binary", help="analyze .pyc/.class/.wasm binaries",
                           aliases=["bin"])
    p_bin.add_argument("paths", nargs="+", help="files or directories")
    p_bin.add_argument("--json", action="store_true")
    p_bin.set_defaults(func=cmd_binary)

    # --- supply-chain (typosquatting, dependency confusion) ---
    p_sc = sub.add_parser("supply-chain", help="supply chain deep analysis",
                          aliases=["supplychain"])
    p_sc.add_argument("root", nargs="?", default=".")
    p_sc.add_argument("--json", action="store_true")
    p_sc.add_argument("--internal-scope",
                      help="internal package prefix (e.g. @company/)")
    p_sc.set_defaults(func=cmd_supply_chain)

    # --- similarity (CVE pattern matching) ---
    p_sim = sub.add_parser("similarity", help="semantic CVE pattern matching",
                           aliases=["cve-match"])
    p_sim.add_argument("paths", nargs="+", help="files or directories")
    p_sim.add_argument("--json", action="store_true")
    p_sim.add_argument("--threshold", type=float, default=0.35,
                       help="similarity threshold (0.0-1.0, default: 0.35)")
    p_sim.set_defaults(func=cmd_similarity)

    # --- git-history (historical vulnerability scan) ---
    p_gh = sub.add_parser("git-history", help="scan git history for secret leaks",
                          aliases=["history"])
    p_gh.add_argument("root", nargs="?", default=".")
    p_gh.add_argument("--json", action="store_true")
    p_gh.add_argument("--max-commits", type=int, default=200)
    p_gh.set_defaults(func=cmd_git_history)

    # --- cicd (CI/CD pipeline security) ---
    p_cicd = sub.add_parser("cicd", help="scan CI/CD pipelines for security issues",
                            aliases=["pipeline"])
    p_cicd.add_argument("root", nargs="?", default=".")
    p_cicd.add_argument("--json", action="store_true")
    p_cicd.set_defaults(func=cmd_cicd)

    # --- poc (proof-of-concept generation) ---
    p_poc = sub.add_parser("poc", help="generate PoC exploits for findings",
                           aliases=["exploit"])
    p_poc.add_argument("root", nargs="?", default=".")
    p_poc.add_argument("--json", action="store_true")
    p_poc.set_defaults(func=cmd_poc)

    # --- compliance (framework mapping) ---
    p_comp = sub.add_parser("compliance", help="compliance framework reports",
                            aliases=["comply"])
    p_comp.add_argument("root", nargs="?", default=".")
    p_comp.add_argument("--framework", "-f",
                        choices=["owasp", "nist", "soc2", "pci-dss", "all"],
                        default="all")
    p_comp.add_argument("--json", action="store_true")
    p_comp.set_defaults(func=cmd_compliance)

    # --- chain (vulnerability chaining) ---
    p_chain = sub.add_parser("chain", help="vulnerability chaining analysis",
                             aliases=["exploit-chain"])
    p_chain.add_argument("root", nargs="?", default=".")
    p_chain.add_argument("--json", action="store_true")
    p_chain.set_defaults(func=cmd_chain)

    # --- fix-verify (test generation) ---
    p_fix = sub.add_parser("fix-verify", help="generate fix verification tests",
                           aliases=["verify"])
    p_fix.add_argument("root", nargs="?", default=".")
    p_fix.add_argument("--json", action="store_true")
    p_fix.add_argument("--output", "-o", help="output test file path")
    p_fix.set_defaults(func=cmd_fix_verify)

    # --- correlate (runtime behavior correlation) ---
    p_corr = sub.add_parser("correlate", help="correlate static findings with runtime data",
                            aliases=["runtime"])
    p_corr.add_argument("root", nargs="?", default=".")
    p_corr.add_argument("--json", action="store_true")
    p_corr.add_argument("--coverage", help="path to coverage report (JSON/XML)")
    p_corr.add_argument("--logs", help="path to runtime logs")
    p_corr.add_argument("--traces", help="path to trace data (JSON)")
    p_corr.set_defaults(func=cmd_correlate)

    # --- check (the unified, effort-aware, one-command experience) ---
    p_chk = sub.add_parser("check", help="ONE command: scan + triage + what matters",
                           aliases=["c"])
    p_chk.add_argument("root", nargs="?", default=".")
    p_chk.add_argument("--effort", "-e", choices=EFFORT_LEVELS, default="medium",
                       help="analysis depth: low|medium|high|max (default: medium)")
    p_chk.add_argument("--top", type=int, default=15, help="how many findings to show")
    p_chk.add_argument("--no-color", action="store_true")
    p_chk.add_argument("--json", action="store_true")
    p_chk.set_defaults(func=cmd_check)

    # --- fix (autofix with verify loop) ---
    p_fix = sub.add_parser("fix", help="auto-fix safe findings (verified by re-scan)",
                           aliases=["autofix"])
    p_fix.add_argument("paths", nargs="+", help="files or directories")
    p_fix.add_argument("--apply", action="store_true",
                       help="write fixes (default: dry-run preview)")
    p_fix.add_argument("--pr", action="store_true",
                       help="apply verified fixes on a branch and open a PR")
    p_fix.add_argument("--base", help="base branch for the PR (default: current)")
    p_fix.add_argument("--aggressive", action="store_true",
                       help="also propose semantic-changing fixes")
    p_fix.add_argument("--test", action="store_true",
                       help="run the test suite after fixing; revert all if it fails")
    p_fix.add_argument("--test-cmd", help="custom test command (default: pytest)")
    p_fix.add_argument("--json", action="store_true")
    p_fix.set_defaults(func=cmd_fix)

    # --- plan-fix (AST-aware fix planning with reasoning) ---
    p_planfix = sub.add_parser("plan-fix",
                               help="plan AST-aware security fixes with reasoning")
    p_planfix.add_argument("paths", nargs="+", help="files or directories")
    p_planfix.add_argument("--apply", action="store_true",
                           help="apply planned fixes")
    p_planfix.add_argument("--json", action="store_true")
    p_planfix.set_defaults(func=cmd_plan_fix)

    # --- interproc (cross-function taint analysis) ---
    p_inter = sub.add_parser("interproc",
                             help="inter-procedural dataflow -- cross-function taint",
                             aliases=["xfunc"])
    p_inter.add_argument("paths", nargs="+", help="files or directories")
    p_inter.add_argument("--depth", type=int, default=8,
                         help="max call chain depth (default: 8)")
    p_inter.add_argument("--json", action="store_true")
    p_inter.set_defaults(func=cmd_interproc)

    # --- killchain (attack chain synthesis) ---
    p_kc = sub.add_parser("killchain",
                          help="synthesize multi-step attack chains from findings",
                          aliases=["kc", "attack"])
    p_kc.add_argument("paths", nargs="+", help="files or directories")
    p_kc.add_argument("--full", action="store_true",
                      help="run ALL engines (detect, interproc, api, iac, threat-model)")
    p_kc.add_argument("--graph", action="store_true",
                      help="output interactive HTML attack graph")
    p_kc.add_argument("--output", "-o",
                      help="output file for --graph (default: attack-graph.html)")
    p_kc.add_argument("--json", action="store_true")
    p_kc.set_defaults(func=cmd_killchain)

    # --- attack-graph (standalone interactive visualization) ---
    p_ag = sub.add_parser("attack-graph",
                          help="interactive HTML attack graph from all engines",
                          aliases=["graph", "viz"])
    p_ag.add_argument("paths", nargs="+", help="files or directories")
    p_ag.add_argument("--output", "-o", default="attack-graph.html",
                      help="output HTML file (default: attack-graph.html)")
    p_ag.set_defaults(func=cmd_attack_graph)

    # --- council (multi-model ensemble adjudication) ---
    p_council = sub.add_parser("council",
                               help="multi-model ensemble adjudication (model council)",
                               aliases=["ensemble", "jury"])
    p_council.add_argument("paths", nargs="*", default=["."],
                           help="files or directories to scan")
    p_council.add_argument("--roster", action="store_true",
                           help="list available council members and exit")
    p_council.add_argument("--add-remote", action="append", metavar="URL|NAME",
                           help="add remote model endpoint (URL|name|key)")
    p_council.add_argument("--sequential", action="store_true",
                           help="run models sequentially (default: parallel)")
    p_council.add_argument("--json", action="store_true")
    p_council.set_defaults(func=cmd_council)

    # --- hybrid (static + model judgment) ---
    p_hybrid = sub.add_parser("hybrid",
                              help="hybrid analysis: static engines + owen-coder judgment",
                              aliases=["judge"])
    p_hybrid.add_argument("root", nargs="?", default=".")
    p_hybrid.add_argument("--effort", "-e", choices=EFFORT_LEVELS, default="high")
    p_hybrid.add_argument("--model", help="override model (default: auto-select)")
    p_hybrid.add_argument("--no-batch", action="store_true",
                          help="judge findings one at a time (slower, more detailed)")
    p_hybrid.add_argument("--no-color", action="store_true")
    p_hybrid.add_argument("--json", action="store_true")
    p_hybrid.set_defaults(func=cmd_hybrid)

    # --- retrain (feedback loop) ---
    p_retrain = sub.add_parser("retrain",
                               help="retrain owen-coder from scan feedback",
                               aliases=["learn"])
    p_retrain.add_argument("projects", nargs="*",
                           help="project dirs to extract feedback from (default: .)")
    p_retrain.add_argument("--colab", action="store_true",
                           help="export Colab notebook for GPU training")
    p_retrain.add_argument("--train", action="store_true",
                           help="train locally (requires GPU)")
    p_retrain.add_argument("--model", choices=["3b", "14b"], default="14b")
    p_retrain.set_defaults(func=cmd_retrain)

    # --- bench (dataflow engine vs baselines) ---
    p_bench = sub.add_parser("bench", help="benchmark dataflow engine vs legacy/Bandit")
    p_bench.add_argument("--json", action="store_true")
    p_bench.set_defaults(func=cmd_bench)

    p_swebench = sub.add_parser("swe-bench",
                                help="benchmark on SWE-bench Verified",
                                aliases=["swebench"])
    p_swebench.add_argument("--limit", type=int, default=50,
                            help="max instances (default: 50)")
    p_swebench.add_argument("--filter", choices=["all", "security", "python"],
                            default="python")
    p_swebench.add_argument("--council", action="store_true",
                            help="also run model council on findings")
    p_swebench.add_argument("--json", action="store_true")
    p_swebench.set_defaults(func=cmd_swe_bench)

    # --- evaluate (precision/recall/F1 + noise reduction) ---
    p_eval = sub.add_parser("evaluate", help="measure precision/recall/F1 + FP reduction",
                            aliases=["eval", "score"])
    p_eval.add_argument("--json", action="store_true")
    p_eval.add_argument("--noise", metavar="ROOT",
                        help="measure false-positive reduction on a real tree")
    p_eval.add_argument("--calibrate", action="store_true",
                        help="rewrite triage weights from measured precision")
    p_eval.set_defaults(func=cmd_evaluate)

    # --- triage (rule confidence x vendored -> report/review/suppress) ---
    p_tri = sub.add_parser("triage", help="prioritize findings, suppress vendored noise")
    p_tri.add_argument("root", nargs="?", default=".")
    p_tri.add_argument("--json", action="store_true")
    p_tri.set_defaults(func=cmd_triage)

    # --- msf (findings -> Metasploit resource script) ---
    p_xpl = sub.add_parser("msf",
                           help="export findings as a Metasploit .rc resource script")
    p_xpl.add_argument("root", nargs="?", default=".")
    p_xpl.add_argument("--rhosts", required=True,
                       help="target IP/range (comma-separated or CIDR)")
    p_xpl.add_argument("--lhost", help="local IP for reverse shells")
    p_xpl.add_argument("--lport", type=int, default=4444)
    p_xpl.add_argument("--payload",
                       help="override payload for all exploit modules "
                            "(default: platform-matched)")
    p_xpl.add_argument("--out", "-o", default="attestor_findings.rc",
                       help="output .rc file (default: attestor_findings.rc)")
    p_xpl.add_argument("--run", action="store_true",
                       help="launch msfconsole -r on the generated .rc")
    p_xpl.set_defaults(func=cmd_exploit)

    # --- report (HTML) ---
    p_rep = sub.add_parser("report", help="generate HTML security report dashboard")
    p_rep.add_argument("root", nargs="?", default=".")
    p_rep.add_argument("--output", "-o", help="output file (default: attestor-report.html)")
    p_rep.add_argument("--project", help="project name for report header")
    p_rep.set_defaults(func=cmd_report)

    # --- baseline ---
    p_base = sub.add_parser("baseline", help="finding suppression baseline")
    base_sub = p_base.add_subparsers(dest="baseline_command")

    p_base_create = base_sub.add_parser("create", help="create baseline from current findings")
    p_base_create.add_argument("root", nargs="?", default=".")
    p_base_create.add_argument("--output", "-o")
    p_base_create.add_argument("--reason", default="initial baseline")
    p_base_create.set_defaults(func=cmd_baseline)

    p_base_status = base_sub.add_parser("status", help="show baseline status")
    p_base_status.add_argument("--file", help="baseline file path")
    p_base_status.set_defaults(func=cmd_baseline)

    p_base_clear = base_sub.add_parser("clear", help="remove baseline")
    p_base_clear.add_argument("--file", help="baseline file path")
    p_base_clear.set_defaults(func=cmd_baseline)

    # --- hooks ---
    p_hooks = sub.add_parser("hooks", help="manage git hooks for Attestor")
    hooks_sub = p_hooks.add_subparsers(dest="hooks_command")

    p_hooks_install = hooks_sub.add_parser("install", help="install git hook")
    p_hooks_install.add_argument("--hook-type", choices=["pre-commit", "pre-push"],
                                 default="pre-commit")
    p_hooks_install.add_argument("--grade", default="C",
                                 help="passing grade (default: C)")
    p_hooks_install.add_argument("--block", action="store_true",
                                 help="block commits on findings")
    p_hooks_install.set_defaults(func=cmd_hooks)

    p_hooks_uninstall = hooks_sub.add_parser("uninstall", help="remove git hook")
    p_hooks_uninstall.add_argument("--hook-type", choices=["pre-commit", "pre-push"],
                                   default="pre-commit")
    p_hooks_uninstall.set_defaults(func=cmd_hooks)

    p_hooks_status = hooks_sub.add_parser("status", help="show hook status")
    p_hooks_status.set_defaults(func=cmd_hooks)

    # --- watch ---
    p_watch = sub.add_parser("watch", help="watch mode (auto-rescan on changes)")
    p_watch.add_argument("root", nargs="?", default=".")
    p_watch.add_argument("--interval", type=float, default=1.0,
                         help="poll interval in seconds")
    p_watch.add_argument("--modes", default="secrets,exploits",
                         help="comma-separated scan modes (secrets,exploits,js,iac,payloads)")
    p_watch.set_defaults(func=cmd_watch)

    # --- control (Owner Control) ---
    p_ctrl = sub.add_parser("control", help="Owner Control 4.2")
    ctrl_sub = p_ctrl.add_subparsers(dest="control_command")

    p_ctrl_pol = ctrl_sub.add_parser("policy", help="show policy")
    p_ctrl_pol.add_argument("--format", choices=("text", "json"), default="json")
    p_ctrl_pol.set_defaults(func=cmd_control)

    p_ctrl_run = ctrl_sub.add_parser("run", help="run a control plan")
    p_ctrl_run.add_argument("plan_file")
    p_ctrl_run.add_argument("--permission", action="store_true")
    p_ctrl_run.add_argument("--confirm-plan-sha256", default="")
    p_ctrl_run.add_argument("--format", choices=("text", "json"), default="json")
    p_ctrl_run.set_defaults(func=cmd_control)

    # --- symbolic path feasibility ---
    p_sym = sub.add_parser("sym-solve", help="symbolic path feasibility analysis")
    p_sym.add_argument("paths", nargs="+")
    p_sym.add_argument("--json", action="store_true")
    p_sym.set_defaults(func=cmd_sym_solve)

    # --- abstract interpretation ---
    p_ai2 = sub.add_parser("abstract", help="abstract interpretation (value ranges)")
    p_ai2.add_argument("paths", nargs="+")
    p_ai2.add_argument("--json", action="store_true")
    p_ai2.set_defaults(func=cmd_abstract_interp)

    # --- semantic clone detection ---
    p_clone = sub.add_parser("clones", help="semantic clone detection")
    p_clone.add_argument("paths", nargs="+")
    p_clone.add_argument("--threshold", type=float, default=0.75)
    p_clone.add_argument("--json", action="store_true")
    p_clone.set_defaults(func=cmd_clone_detect)

    # --- taint policy DSL ---
    p_dsl = sub.add_parser("taint-dsl", help="custom taint policy (YAML)")
    p_dsl.add_argument("paths", nargs="+")
    p_dsl.add_argument("--policy", required=True, help="path to policy YAML")
    p_dsl.add_argument("--json", action="store_true")
    p_dsl.set_defaults(func=cmd_taint_dsl)

    # --- API security scan ---
    p_api = sub.add_parser("api-scan", help="OpenAPI/Swagger security scan")
    p_api.add_argument("paths", nargs="+")
    p_api.add_argument("--json", action="store_true")
    p_api.set_defaults(func=cmd_api_scan)

    # --- threat model ---
    p_tm = sub.add_parser("threat-model", help="auto-STRIDE threat model")
    p_tm.add_argument("paths", nargs="+")
    p_tm.add_argument("--json", action="store_true")
    p_tm.set_defaults(func=cmd_threat_model)

    # --- SBOM ---
    p_sbom = sub.add_parser("sbom", help="generate SBOM (CycloneDX/SPDX)")
    p_sbom.add_argument("paths", nargs="+")
    p_sbom.add_argument("--format", choices=["cyclonedx", "spdx", "summary"],
                        default="summary")
    p_sbom.add_argument("--project", default="attestor-project")
    p_sbom.add_argument("--json", action="store_true")
    p_sbom.set_defaults(func=cmd_sbom)

    # --- sales ---
    p_sales = sub.add_parser("sales", help="sales data analysis (ingest, trend, forecast)")
    sales_sub = p_sales.add_subparsers(dest="sales_command")

    p_sales_in = sales_sub.add_parser("ingest", help="import CSV sales data")
    p_sales_in.add_argument("files", nargs="+", help="CSV files to import")
    p_sales_in.add_argument("--data-dir", default=".", help="data directory")
    p_sales_in.add_argument("--source", help="data source label")
    p_sales_in.set_defaults(func=cmd_sales)

    p_sales_an = sales_sub.add_parser("analyze", help="analyze sales trends")
    p_sales_an.add_argument("--data-dir", default=".", help="data directory")
    p_sales_an.add_argument("--days", type=int, default=90)
    p_sales_an.add_argument("--json", action="store_true")
    p_sales_an.set_defaults(func=cmd_sales)

    p_sales_cl = sales_sub.add_parser("clear", help="clear all sales data")
    p_sales_cl.add_argument("--data-dir", default=".")
    p_sales_cl.set_defaults(func=cmd_sales)
    p_sales.set_defaults(func=cmd_sales)

    # --- inventory ---
    p_inv = sub.add_parser("inventory", help="inventory monitoring and alerts")
    inv_sub = p_inv.add_subparsers(dest="inv_command")

    p_inv_load = inv_sub.add_parser("load", help="load stock CSV")
    p_inv_load.add_argument("file", help="stock CSV file")
    p_inv_load.add_argument("--data-dir", default=".")
    p_inv_load.set_defaults(func=cmd_inventory)

    p_inv_check = inv_sub.add_parser("check", help="check thresholds and alert")
    p_inv_check.add_argument("--data-dir", default=".")
    p_inv_check.add_argument("--stock", help="stock CSV to load first")
    p_inv_check.add_argument("--min-qty", type=int, default=10)
    p_inv_check.add_argument("--reorder-qty", type=int, default=50)
    p_inv_check.add_argument("--slack", help="Slack webhook URL for alerts")
    p_inv_check.add_argument("--po", action="store_true", help="generate PO draft")
    p_inv_check.add_argument("--vendor", help="vendor name for PO")
    p_inv_check.add_argument("--json", action="store_true")
    p_inv_check.set_defaults(func=cmd_inventory)

    p_inv_th = inv_sub.add_parser("threshold", help="set item threshold")
    p_inv_th.add_argument("sku", help="SKU to set threshold for")
    p_inv_th.add_argument("--min-qty", type=int, required=True)
    p_inv_th.add_argument("--reorder-qty", type=int, required=True)
    p_inv_th.add_argument("--data-dir", default=".")
    p_inv_th.set_defaults(func=cmd_inventory)
    p_inv.set_defaults(func=cmd_inventory)

    # --- schedule ---
    p_sched = sub.add_parser("schedule", help="employee shift scheduling")
    sched_sub = p_sched.add_subparsers(dest="sched_command")

    p_sched_solve = sched_sub.add_parser("solve", help="generate schedule")
    p_sched_solve.add_argument("--employees", required=True,
                               help="employees CSV")
    p_sched_solve.add_argument("--shifts", required=True,
                               help="shifts CSV")
    p_sched_solve.add_argument("--week", help="week start date (YYYY-MM-DD)")
    p_sched_solve.add_argument("--labour-cap", type=float,
                               help="weekly labour cost cap")
    p_sched_solve.add_argument("--gcal", action="store_true",
                               help="export Google Calendar events JSON")
    p_sched_solve.add_argument("--output", "-o", help="output file for --gcal")
    p_sched_solve.add_argument("--json", action="store_true")
    p_sched_solve.set_defaults(func=cmd_schedule)
    p_sched.set_defaults(func=cmd_schedule)

    # --- memory ---
    p_mem = sub.add_parser("memory", help="persistent memory (learns across scans)")
    mem_sub = p_mem.add_subparsers(dest="memory_command")

    p_mem_show = mem_sub.add_parser("show", help="show memory summary")
    p_mem_show.add_argument("root", nargs="?", default=".")
    p_mem_show.add_argument("--json", action="store_true")
    p_mem_show.set_defaults(func=cmd_memory)

    p_mem_fb = mem_sub.add_parser("feedback",
                                  help="mark a finding as tp/fp")
    p_mem_fb.add_argument("verdict", choices=["tp", "fp", "defer"])
    p_mem_fb.add_argument("--file", required=True, help="file path")
    p_mem_fb.add_argument("--line", type=int, required=True)
    p_mem_fb.add_argument("--rule", help="rule ID")
    p_mem_fb.add_argument("--reason", help="why this verdict")
    p_mem_fb.add_argument("root", nargs="?", default=".")
    p_mem_fb.set_defaults(func=cmd_memory)

    p_mem_learn = mem_sub.add_parser("learn",
                                     help="learn codebase patterns")
    p_mem_learn.add_argument("root", nargs="?", default=".")
    p_mem_learn.set_defaults(func=cmd_memory)

    p_mem_stats = mem_sub.add_parser("stats", help="show scan statistics")
    p_mem_stats.add_argument("root", nargs="?", default=".")
    p_mem_stats.set_defaults(func=cmd_memory)

    p_mem_clear = mem_sub.add_parser("clear", help="wipe all memory")
    p_mem_clear.add_argument("root", nargs="?", default=".")
    p_mem_clear.set_defaults(func=cmd_memory)

    p_mem.set_defaults(func=cmd_memory)

    # --- novel (anomalous code detection) ---
    p_novel = sub.add_parser("novel",
                             help="detect structurally unusual code patterns")
    p_novel.add_argument("root", nargs="?", default=".")
    p_novel.add_argument("--threshold", type=float, default=2.0,
                         help="z-score threshold for outlier detection (default 2.0)")
    p_novel.add_argument("--json", action="store_true")
    p_novel.add_argument("--no-color", action="store_true")
    p_novel.set_defaults(func=cmd_novel)

    # --- explain (natural language explanations) ---
    p_explain = sub.add_parser("explain",
                               help="explain findings in natural language")
    p_explain.add_argument("root", nargs="?", default=".")
    p_explain.add_argument("--effort", default="medium",
                           choices=EFFORT_LEVELS)
    p_explain.add_argument("--top", type=int, default=10,
                           help="number of findings to explain")
    p_explain.add_argument("--context", type=int, default=5,
                           help="lines of code context around finding")
    p_explain.add_argument("--json", action="store_true")
    p_explain.add_argument("--no-color", action="store_true")
    p_explain.set_defaults(func=cmd_explain)

    # --- phantom (autonomous exploit verification -- 4.3 flagship) ---
    p_phantom = sub.add_parser("phantom",
                               help="autonomous exploit verification (4.3)",
                               aliases=["verify-exploits", "prove"])
    p_phantom.add_argument("root", nargs="?", default=".")
    p_phantom.add_argument("--finding", help="filter by rule_id substring")
    p_phantom.add_argument("--severity",
                           choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                           help="minimum severity to verify")
    p_phantom.add_argument("--output", "-o", help="write JSON report to file")
    p_phantom.add_argument("--exploit", action="store_true",
                           help="generate standalone exploit scripts")
    p_phantom.add_argument("--effort", default="medium",
                           choices=EFFORT_LEVELS)
    p_phantom.add_argument("--json", action="store_true")
    p_phantom.add_argument("--no-color", action="store_true")
    p_phantom.set_defaults(func=cmd_phantom)

    # --- model (AI model status -- 4.3) ---
    p_model = sub.add_parser("model",
                             help="show AI model status and availability (4.3)",
                             aliases=["ai"])
    p_model.add_argument("--json", action="store_true")
    p_model.set_defaults(func=cmd_model_status)

    # --- serve (REST API) ---
    p_serve = sub.add_parser("serve",
                             help="start REST API server (enterprise deployment)")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8844)
    p_serve.set_defaults(func=cmd_serve)

    # --- version ---
    p_ver = sub.add_parser("version", help="show version information")
    p_ver.add_argument("--json", action="store_true")
    p_ver.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    global _MACHINE_OUTPUT
    arguments = list(sys.argv[1:] if argv is None else argv)
    _MACHINE_OUTPUT = "--json" in arguments or "--format=json" in arguments or any(
        value == "--format" and i + 1 < len(arguments) and arguments[i + 1] == "json"
        for i, value in enumerate(arguments))
    C.enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and not _MACHINE_OUTPUT
    if "--no-color" in arguments:
        C.enabled = False
        arguments.remove("--no-color")
    if arguments and arguments[0] == "help" and len(arguments) > 1:
        arguments = [*arguments[1:], "--help"]
    if not arguments or arguments in (["--help"], ["-h"], ["help"]):
        _quick_help()
        return 0
    if arguments[0] in ("--version", "-V"):
        arguments[0] = "version"
    parser = build_parser()
    if arguments == ["--help-all"]:
        parser.print_help()
        return 0
    try:
        if arguments[0] in ("security", "ui"):
            module = importlib.import_module("security_assessment" if arguments[0] == "security" else "attestor_ui")
            return int(module.main(arguments[1:]) or 0)
        commands = _command_parsers(parser)
        if not arguments[0].startswith("-") and arguments[0] not in commands:
            close = difflib.get_close_matches(arguments[0], commands, n=1, cutoff=0.6)
            hint = " Did you mean '%s'?" % close[0] if close else " Try: attestor --help"
            raise CliUsageError("unknown command '%s'.%s" % (arguments[0], hint))
        args = parser.parse_args(arguments)
        if not hasattr(args, "func"):
            commands[args.command].print_help()
            return 0
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        code, message = 130, "interrupted"
    except CliUsageError as exc:
        code, message = 2, str(exc)
    except Exception as exc:
        code, message = 4, "%s: %s" % (type(exc).__name__, exc)
    if _MACHINE_OUTPUT:
        print(json.dumps({"ok": False, "error": message, "exit_code": code}))
    else:
        print("attestor: " + message, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
