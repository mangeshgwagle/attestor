"""What kind of machine is Attestor running on, and does it get billed?

Attestor charges for the machines that can actually use what it costs to run:
a workstation with the cores and memory to hold a 46,000-file corpus in
flight. A laptop with 8 GB is not a smaller customer, it is not a customer
-- it runs the same Attestor, free, forever, and is never asked for a card.

The classification is deliberately coarse. Three classes, two thresholds,
no scoring function nobody can predict the output of. A person should be
able to read their own machine off the table:

    class   cores       memory          billed
    low     any         under 8 GB      never
    mid     >= 4        8 GB or more    never
    high    >= 8        16 GB or more   yes

Memory is stated as the machine is *sold*, not as the OS reports it -- see
the thresholds below for why those are not the same number.

Both conditions have to hold to move up a class, so 32 GiB behind two cores
is `low` -- the memory is useless without something to run on it.

WHAT THIS IS NOT: this is not a licence check and it will not survive
someone who wants to lie to it. The probe runs on the user's own machine and
reports its own answer; anyone who wants to claim `low` can claim `low`.
That is a deliberate trade. The alternative is remote attestation against a
TPM, which would mean Attestor refusing to start on hardware it disapproves of,
and Attestor is not going to do that to somebody. What stops abuse is that the
entitlement is signed server-side and checked server-side; the machine class
decides only whether Attestor *asks* for money. Treat a claimed class as a
statement of intent, not as a fact you can rely on.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import subprocess
from dataclasses import asdict, dataclass

LOGGER = logging.getLogger(__name__)

__all__ = [
    "MachineProfile",
    "BILLED_CLASSES",
    "GIB",
    "HIGH_END_CORES",
    "HIGH_END_MEMORY",
    "MID_RANGE_CORES",
    "MID_RANGE_MEMORY",
    "classify",
    "probe",
    "total_memory_bytes",
    "logical_cores",
]

GIB = 1024 ** 3

# The thresholds are set a little under the round number they are named for,
# and that margin is not fudge -- it is the difference between what a machine
# is sold as and what the OS can see. A 16 GB stick reports 15.6 GiB on the
# Windows box this was written on: the firmware and the integrated GPU take
# their cut before the OS counts what is left. Asking for a full 16 GiB would
# have put every machine marketed as 16 GB on the free tier, which is exactly
# backwards. 15.5 clears a real 16 GB machine and still excludes a 12 GB one
# (11.x GiB), which is the only distinction the threshold has to make.
HIGH_END_CORES = 8
HIGH_END_MEMORY = int(15.5 * GIB)
MID_RANGE_CORES = 4
MID_RANGE_MEMORY = int(7.5 * GIB)

#: The only class Attestor ever bills. Everything else runs free.
BILLED_CLASSES = frozenset({"high"})


@dataclass(frozen=True)
class MachineProfile:
    """A machine, as coarsely as Attestor is willing to describe one."""

    machine_class: str
    cores: int
    memory_bytes: int
    system: str
    probe_confidence: str

    @property
    def billed(self) -> bool:
        return self.machine_class in BILLED_CLASSES

    @property
    def memory_gib(self) -> float:
        return round(self.memory_bytes / GIB, 1)

    def as_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["billed"] = self.billed
        payload["memory_gib"] = self.memory_gib
        return payload

    def explain(self) -> str:
        """Why this machine landed in this class, in one line."""
        if self.machine_class == "high":
            return (
                "%d cores and %.1f GiB -- at or above the %d-core / 16 GB "
                "line, so Attestor bills this one."
                % (self.cores, self.memory_gib, HIGH_END_CORES)
            )
        reason = []
        if self.cores < (MID_RANGE_CORES if self.machine_class == "low"
                         else HIGH_END_CORES):
            reason.append("%d cores" % self.cores)
        if self.memory_bytes < (MID_RANGE_MEMORY if self.machine_class == "low"
                                else HIGH_END_MEMORY):
            reason.append("%.1f GiB" % self.memory_gib)
        return "%s -- %s, so Attestor runs here for free." % (
            self.machine_class, " and ".join(reason) or "below the line")


def logical_cores() -> int:
    """Logical processors, or 0 if the platform will not say.

    `os.cpu_count()` returns None on platforms that cannot determine it, and
    `sched_getaffinity` is the more honest number where it exists because a
    container pinned to two cores has two cores no matter what the host has.
    """
    if hasattr(os, "sched_getaffinity"):
        try:
            return len(os.sched_getaffinity(0))
        except OSError as unavailable:
            # Not silence: the affinity mask is unavailable on this platform
            # and cpu_count below is the answer. Attestor flagged the bare `pass`
            # that used to be here and was right to -- a reader could not
            # tell whether the fallthrough was intended or forgotten.
            LOGGER.debug("sched_getaffinity unavailable (%s); "
                         "falling back to cpu_count", unavailable)
    return os.cpu_count() or 0


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _windows_memory() -> int:
    status = _MemoryStatusEx()
    status.dwLength = ctypes.sizeof(_MemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return 0
    return int(status.ullTotalPhys)


def _linux_memory() -> int:
    try:
        with open("/proc/meminfo", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _bsd_memory() -> int:
    for key in ("hw.memsize", "hw.physmem"):
        try:
            output = subprocess.run(
                ["sysctl", "-n", key], capture_output=True, text=True,
                timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            return 0
        value = output.stdout.strip()
        if value.isdigit():
            return int(value)
    return 0


def total_memory_bytes() -> int:
    """Physical RAM in bytes, or 0 when the platform will not say.

    Zero is a real answer here and callers must treat it as one: an unknown
    machine is classified `low` and therefore never billed. Guessing high on
    a machine we failed to measure would mean charging someone because a
    syscall failed.
    """
    system = platform.system()
    try:
        if system == "Windows":
            return _windows_memory()
        if system == "Linux":
            return _linux_memory()
        if system in {"Darwin", "FreeBSD", "OpenBSD", "NetBSD"}:
            return _bsd_memory()
    except Exception:            # pragma: no cover - platform specific
        return 0
    # Anything else: try the POSIX sysconf pair before giving up.
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, ValueError, OSError):
        return 0


def classify(cores: int, memory_bytes: int) -> str:
    """Place a machine in one of three classes.

    Both the core count and the memory have to clear a line to move up, and
    a machine we could not measure (0 of either) lands in `low` -- the class
    that is never charged. Failing towards free is the only safe direction
    for a measurement that decides whether to ask someone for money.
    """
    if cores <= 0 or memory_bytes <= 0:
        return "low"
    if cores >= HIGH_END_CORES and memory_bytes >= HIGH_END_MEMORY:
        return "high"
    if cores >= MID_RANGE_CORES and memory_bytes >= MID_RANGE_MEMORY:
        return "mid"
    return "low"


def probe() -> MachineProfile:
    """Measure this machine and classify it."""
    cores = logical_cores()
    memory = total_memory_bytes()
    confidence = "measured" if cores > 0 and memory > 0 else "unmeasured"
    return MachineProfile(
        machine_class=classify(cores, memory),
        cores=cores,
        memory_bytes=memory,
        system=platform.system() or "unknown",
        probe_confidence=confidence,
    )


def main(argv: list[str] | None = None) -> int:
    profile = probe()
    print("Attestor machine class: %s" % profile.machine_class)
    print("  cores    : %d" % profile.cores)
    print("  memory   : %.1f GiB" % profile.memory_gib)
    print("  system   : %s" % profile.system)
    print("  confidence: %s" % profile.probe_confidence)
    print("  %s" % profile.explain())
    return 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
