"""Attestor, left running, still telling the truth.

Two things were asked for and they are one system. *Endurance* is surviving
a long unattended run -- crashes, reboots, being killed mid-cycle.
*Accuracy over time* is the claims still being true at hour 900. Neither is
worth anything alone: a process that runs for a month and reports stale
numbers is worse than one that dies honestly.

What this actually does
-----------------------
It re-runs Attestor's own invariants on a loop and compares each result to a
recorded baseline. Not the unit tests -- those check that code does what it
did. These check the *claims*: that a rule still separates flawed from
fixed, that four backends still agree, that a synthesized program still
computes its examples.

Every cycle is checkpointed before it is reported, so a kill at any point
loses at most one cycle and never corrupts the record.

Why a baseline and not a threshold
----------------------------------
A threshold ("detection above 60%") passes silently while a number slides
from 94% to 61%. A baseline notices the slide. Every probe records the
value it first measured, and any later disagreement is drift -- reported
with both numbers, not swallowed.

Drift is not failure. A rule improving is drift too, and it should be
announced, because an unexplained improvement is as much a reason to look
as an unexplained regression. This session produced exactly one of those:
CWE-89 went from 93.3% to 100% and it took a deliberate check to find out
why.

What it will not do
-------------------
It does not decide that drift is acceptable. It records, it reports, it
keeps going. A monitor that suppresses its own alarms is a monitor with an
opinion, and the point of leaving this running for a thousand hours is that
nobody is there to have one.
"""

from __future__ import annotations

import json
import os
import platform
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Probe", "Result", "Ledger", "PROBES", "run_cycle", "endure",
           "SCHEMA"]

SCHEMA = "attestor.endure/1"


@dataclass(frozen=True)
class Probe:
    """One checkable claim.

    `measure` returns a value that must stay equal to the baseline. It is a
    value rather than a boolean on purpose: `True/False` tells you something
    broke, a number tells you by how much and in which direction.
    """

    name: str
    measure: object
    detail: str = ""

    def run(self):
        started = time.perf_counter()
        try:
            value = self.measure()
            return Result(self.name, value, time.perf_counter() - started)
        except Exception as failed:                     # noqa: BLE001
            # A probe that raises is a result, not a crash. The whole point
            # is to still be running tomorrow.
            return Result(self.name, None, time.perf_counter() - started,
                          error="%s: %s" % (type(failed).__name__, failed),
                          trace=traceback.format_exc(limit=3))


@dataclass
class Result:
    name: str
    value: object
    seconds: float
    error: str = ""
    trace: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class Ledger:
    """The record on disk: baselines, cycle count, and every drift seen.

    Written atomically -- to a temporary file, then renamed -- because the
    failure this has to survive is being killed. A half-written ledger is
    indistinguishable from a corrupted one, and a monitor that loses its own
    history is not a monitor.
    """

    path: Path
    baseline: dict = field(default_factory=dict)
    cycles: int = 0
    started: float = field(default_factory=time.time)
    drifts: list = field(default_factory=list)
    failures: int = 0

    @classmethod
    def load(cls, path) -> "Ledger":
        path = Path(path)
        if not path.is_file():
            return cls(path=path)
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A ledger that will not parse is worse than none: it would be
            # silently treated as an empty baseline and every probe would
            # look like a first run. Say so and refuse.
            raise RuntimeError(
                "%s exists but is not a readable ledger; move it aside "
                "rather than letting a fresh baseline be recorded over a "
                "run in progress" % path)
        if body.get("schema") != SCHEMA:
            raise RuntimeError("%s is not an %s ledger" % (path, SCHEMA))
        return cls(path=path, baseline=body.get("baseline", {}),
                   cycles=body.get("cycles", 0),
                   started=body.get("started", time.time()),
                   drifts=body.get("drifts", []),
                   failures=body.get("failures", 0))

    def save(self) -> None:
        body = {
            "schema": SCHEMA,
            "baseline": self.baseline,
            "cycles": self.cycles,
            "started": self.started,
            "drifts": self.drifts[-200:],       # bounded: this runs for weeks
            "failures": self.failures,
            "host": platform.node(),
            "updated": time.time(),
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(body, indent=1) + "\n",
                             encoding="utf-8")
        os.replace(temporary, self.path)        # atomic on every platform

    @property
    def hours(self) -> float:
        return (time.time() - self.started) / 3600.0


def run_cycle(probes, ledger: Ledger) -> dict:
    """One pass over every probe, compared against the baseline."""
    ledger.cycles += 1
    fresh, drifted, broken = [], [], []
    for probe in probes:
        result = probe.run()
        if not result.ok:
            broken.append(result)
            ledger.failures += 1
            continue
        recorded = ledger.baseline.get(probe.name)
        if recorded is None:
            ledger.baseline[probe.name] = result.value
            fresh.append(result)
        elif recorded != result.value:
            drifted.append((probe, recorded, result.value))
            ledger.drifts.append({
                "cycle": ledger.cycles,
                "at": time.time(),
                "probe": probe.name,
                "was": recorded,
                "now": result.value,
            })
    ledger.save()
    return {"cycle": ledger.cycles, "new": fresh, "drift": drifted,
            "broken": broken}


def describe(report, ledger: Ledger) -> str:
    lines = ["cycle %d, hour %.1f" % (report["cycle"], ledger.hours)]
    for result in report["new"]:
        lines.append("  baseline  %-28s %s" % (result.name, result.value))
    for probe, was, now in report["drift"]:
        lines.append("  DRIFT     %-28s %s -> %s" % (probe.name, was, now))
        if probe.detail:
            lines.append("            %s" % probe.detail)
    for result in report["broken"]:
        lines.append("  ERROR     %-28s %s" % (result.name, result.error))
    if not (report["new"] or report["drift"] or report["broken"]):
        lines.append("  %d probe(s) unchanged" % len(ledger.baseline))
    return "\n".join(lines)


def endure(probes, ledger_path, hours: float = 0.0, interval: float = 300.0,
           cycles: int = 0, on_report=print) -> Ledger:
    """Run until the time or cycle budget is spent.

    Resumes from whatever the ledger already holds, so being restarted after
    a crash continues the same run rather than starting a new one with a
    fresh baseline -- which would quietly erase the very drift it exists to
    catch.
    """
    ledger = Ledger.load(ledger_path)
    deadline = time.time() + hours * 3600 if hours else None
    done = 0
    while True:
        report = run_cycle(probes, ledger)
        on_report(describe(report, ledger))
        done += 1
        if cycles and done >= cycles:
            break
        if deadline and time.time() >= deadline:
            break
        if deadline is None and not cycles:
            break                                # one pass when unbounded
        time.sleep(min(interval, max(0.0, deadline - time.time()))
                   if deadline else interval)
    return ledger
