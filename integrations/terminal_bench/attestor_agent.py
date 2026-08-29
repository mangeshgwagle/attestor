"""A Terminal-Bench agent that runs Attestor.

Read this before reading the score
----------------------------------
Terminal-Bench measures whether an *agent* can finish a terminal task: plan,
run commands, read the output, iterate, and leave the container in a state that
passes a test. Attestor is not an agent. He reads source and reports defects; he
does not plan and he does not iterate, and by the placement rules in
``MODEL_INTEGRATION_4.1.4.md`` no learned component of his is permitted to
decide anything.

So this adapter will score near zero on the suite as a whole, and that number
is not a verdict on Attestor any more than a chess rating is a verdict on a
spell-checker. What it *is* good for:

* a floor -- how many tasks a static analyser plus verified autofix can close
  with no reasoning at all;
* a baseline for the comparison actually worth running, which is the same
  LLM agent with and without Attestor available as a tool. The delta there is
  Attestor's real contribution, and it is the only number here that answers a
  question anyone should care about.

Two modes
---------
``scan``    -- run the detector over the task directory and leave a JSON report
               at ``/tmp/attestor-findings.json``. Changes nothing, so it closes
               only tasks that ask for a report.
``repair``  -- scan, then hand the findings to ``verified_remediation.py
               --apply``, which rewrites only what it can re-verify and keeps a
               backup. This is the mode that can actually pass a test.

``repair`` is not the default. An agent that edits a repository it was only
asked to look at is the wrong default for a security tool.

Usage
-----
    tb run --agent-import-path attestor_agent:AttestorAgent \\
           --agent-kwarg attestor_path=/path/to/Attestor \\
           --agent-kwarg mode=repair \\
           --task-id <task>

Requires Terminal-Bench (Python >= 3.12) and a running Docker daemon.
"""
from __future__ import annotations

import os
import shlex
import shutil
import tempfile
from pathlib import Path

from terminal_bench.agents.base_agent import AgentResult, BaseAgent
from terminal_bench.agents.failure_mode import FailureMode
from terminal_bench.terminal.tmux_session import TmuxSession

CONTAINER_ROOT = "/attestor"
FINDINGS_PATH = "/tmp/attestor-findings.json"
REPAIR_LOG = "/tmp/attestor-repair.json"
# Copied in beside the detector rather than typed as a `-c` script; see
# `_script` for why that distinction cost a whole benchmark run.
REPORT_SCRIPT = "tb_report.py"
# The whole workflow, written here and copied in, so exactly one short line
# ever has to survive being typed into a terminal.
RUNNER = "attestor_run.sh"
DEFAULT_TARGET = "/app"


class AttestorAgent(BaseAgent):
    """Runs the Attestor detector, and optionally its verified remediation."""

    @staticmethod
    def name() -> str:
        return "attestor"

    def __init__(self, attestor_path: str | None = None, mode: str = "scan",
                 target: str = DEFAULT_TARGET, scan_timeout_sec: float = 600.0,
                 severity: str = "LOW", report_path: str | None = None,
                 report_cwe: str | None = None, **kwargs):
        super().__init__(**kwargs)
        root = attestor_path or os.environ.get("ATTESTOR_PATH")
        if not root:
            raise ValueError(
                "AttestorAgent needs attestor_path (or the ATTESTOR_PATH environment "
                "variable) pointing at an Attestor 4.1.4 checkout")
        self._detector = Path(root).expanduser().resolve() / "detector"
        if not (self._detector / "detect.py").is_file():
            raise ValueError("no detector/detect.py under %s" % root)
        if mode not in ("scan", "repair"):
            raise ValueError("mode must be 'scan' or 'repair'")
        self._mode = mode
        self._target = target
        self._scan_timeout = float(scan_timeout_sec)
        self._severity = severity
        # A task that asks for a report in a stated shape is asking the agent
        # to write that shape; producing it is doing the task, not gaming it.
        # The translation below is deliberately faithful -- it drops no finding
        # and moves no line number -- so a false positive fails the task
        # instead of being quietly filtered out on the way to the file.
        self._report_path = report_path
        self._report_cwe = report_cwe

    # -- helpers ---------------------------------------------------------- #
    def _run(self, session: TmuxSession, command: str, timeout: float) -> None:
        session.send_keys([command, "Enter"], block=True,
                          max_timeout_sec=timeout)

    def _script(self) -> str:
        """The entire workflow, as one shell script copied into the container.

        Why a script and not a sequence of typed commands
        -------------------------------------------------
        Every failure this adapter has had was a *delivery* failure, and they
        all came from the same place: commands reach the container by being
        typed into a tmux session. A `python -c` with newlines split into
        fragments, because a newline is an Enter keypress. Rewritten onto one
        physical line it still failed, on wrapping and quoting. Splitting the
        scan and the report into two commands raced, because the harness
        decides when the previous one has finished and on a deep scan it
        decided too early -- so the report read a findings file still being
        written and emitted an empty array.

        A file has none of those failure modes. The workflow is written here
        in full, copied in, and started with one short line that contains no
        quoting, no newlines, and nothing to race against. The detector was
        correct in every one of those runs; only the typing was not.

        The exit code, which is the one that actually cost the benchmark
        ----------------------------------------------------------------
        ``detect.py`` exits **2** when it finds something and 0 when the tree
        is clean -- correct behaviour for a scanner, and fatal to the previous
        arrangement. The scan and the report were joined by ``&&``, so *every
        run in which Attestor found a defect* short-circuited before the report
        was written. The only way to reach the report step was to find
        nothing, which fails the task too. That is a complete account of 0/5
        on its own, and it was invisible because the trailing ``|| true``
        swallowed the status.

        So the steps are sequenced, never conditioned on each other, and each
        records its own status.

        `|| true` is deliberately gone
        ------------------------------
        It used to sit on the end of the scan so a crash could not abort the
        sequence. What it actually did was turn "no such file" into an empty
        findings list, which is indistinguishable from a clean scan -- two
        benchmark runs scored zero with the detector working perfectly. Here
        each step records its exit status and the script always reaches the
        summary, so a failure is reported rather than smoothed over.
        """
        target = shlex.quote(self._target)
        detector = CONTAINER_ROOT
        lines = [
            "#!/bin/sh",
            "# Generated by AttestorAgent; not part of the task under test.",
            "set -u",
            "",
            "# Attestor imports no third-party package, so any CPython will run",
            "# him; images differ on whether that is python3 or python.",
            "PY=python3",
            "command -v python3 >/dev/null 2>&1 || PY=python",
            'echo "attestor: interpreter $PY"',
            "",
            'echo "attestor: scanning %s"' % self._target,
            '"$PY" -B %s/detect.py --deep --json --no-color --severity %s %s '
            '> %s 2>/tmp/attestor-scan.err' % (
                detector, shlex.quote(self._severity), target, FINDINGS_PATH),
            "SCAN=$?",
            'echo "attestor: scan exit $SCAN"',
        ]
        if self._report_path:
            lines += [
                "",
                "# Sequenced by the script, so it cannot start before the",
                "# findings file is closed.",
                '"$PY" -B %s/%s %s %s %s %s' % (
                    detector, REPORT_SCRIPT, shlex.quote(detector),
                    shlex.quote(FINDINGS_PATH),
                    shlex.quote(self._report_path),
                    shlex.quote(self._report_cwe or "")),
                "REPORT=$?",
                'echo "attestor: report exit $REPORT"',
            ]
        if self._mode == "repair":
            lines += [
                "",
                "# Only rewrites what it can re-verify, and keeps a backup: a",
                "# security tool that silently edits a tree it cannot check",
                "# afterwards is worse than one that reports and stops.",
                '"$PY" -B %s/verified_remediation.py --findings %s --apply '
                '--json %s %s > %s 2>/tmp/attestor-repair.err' % (
                    detector, FINDINGS_PATH, target, target, REPAIR_LOG),
                'echo "attestor: repair exit $?"',
            ]
        lines += [
            "",
            "# The evidence, in the container, where it happened. Without",
            "# this the harness captures only the pane and every diagnosis",
            "# ends up in a file nobody reads.",
            'echo "--- attestor: detector present? ---"',
            "ls %s/detect.py 2>&1 | head -2" % detector,
            'echo "--- attestor: target present? ---"',
            "ls -d %s 2>&1 | head -2" % target,
            'echo "--- attestor: scan stderr ---"',
            "head -c 600 /tmp/attestor-scan.err 2>/dev/null",
            'echo "--- attestor: findings ---"',
            "head -c 2000 %s 2>/dev/null" % FINDINGS_PATH,
            'echo ""',
            'echo "attestor: done"',
        ]
        return "\n".join(lines) + "\n"

    # -- the agent interface ---------------------------------------------- #
    def perform_task(self, instruction: str, session: TmuxSession,
                     logging_dir: Path | None = None) -> AgentResult:
        markers: list[tuple[float, str]] = []

        def mark(text: str) -> None:
            try:
                markers.append((session.get_asciinema_timestamp(), text))
            except Exception:          # markers are diagnostics, never the run
                pass

        staging = Path(tempfile.mkdtemp(prefix="attestor-tb-"))
        try:
            payload = [self._detector]
            if self._report_path:
                script = Path(__file__).resolve().parent / REPORT_SCRIPT
                if script.is_file():
                    payload.append(script)
            runner = staging / RUNNER
            runner.write_text(self._script(), encoding="utf-8", newline="\n")
            payload.append(runner)
            session.copy_to_container(payload, container_dir=CONTAINER_ROOT)
            # `copy_to_container` flattens a directory: it archives each entry
            # as `item.relative_to(path)`, so `detector/detect.py` arrives as
            # `/attestor/detect.py` and `/attestor/detector/` never exists. `docker cp`
            # keeps the directory name, which is why this worked by hand and
            # failed in the harness for two days -- the `|| true` on the scan
            # turned "no such file" into an empty findings list that looked
            # exactly like a clean scan.
            mark("attestor detector and runner copied into the container")

            # One short line. No newlines to become Enter keypresses, no
            # quoting to survive a terminal, and nothing that can begin before
            # the step before it has finished.
            self._run(session, "sh %s/%s" % (CONTAINER_ROOT, RUNNER),
                      self._scan_timeout)
            mark("attestor run finished")

            if self._report_path:
                mark("report written to " + self._report_path)
            return AgentResult(failure_mode=FailureMode.NONE,
                               timestamped_markers=markers)
        except Exception as error:                       # noqa: BLE001
            mark("attestor failed: %s" % str(error)[:160])
            return AgentResult(failure_mode=FailureMode.UNKNOWN_AGENT_ERROR,
                               timestamped_markers=markers)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
