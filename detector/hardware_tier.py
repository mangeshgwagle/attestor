#!/usr/bin/env python3
"""Classify this machine into a pricing tier, locally.

Why the classification happens here
-----------------------------------
The obvious implementation collects a hardware inventory and posts it to a
server, which then decides the tier. That builds a device-fingerprinting
database as a side effect of billing -- core counts, memory sizes and GPU
model strings are exactly what a fingerprint is made of, and once collected
they are a liability whether or not anyone meant to use them that way.

So the machine classifies itself and reports one word. The server learns
"high" or "standard" and cannot reconstruct anything else. Same billing
decision, none of the inventory.

Honest about enforcement
------------------------
A client that reports its own tier can lie, and this one is a Python file the
customer can read and edit. That is not a flaw to be patched -- any
client-side measurement has it, and the alternatives (signed attestation,
kernel agents) cost more trust than the revenue is worth. This is a stated
pricing basis that honest customers follow, not a lock.

Stdlib only, like everything else in `detector/`.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

SCHEMA = "attestor.hardware-tier/1.0"
VERSION = "4.1.5"

# A machine is "high" when it is comfortably a workstation rather than a
# laptop somebody was issued. Both conditions must hold, so a many-core server
# with little memory and a memory-heavy machine with few cores both stay in
# the free tier -- the target is people who bought power, not people whose
# hardware is lopsided.
HIGH_END_CORES = 12
HIGH_END_MEMORY_GB = 32

STANDARD, HIGH = "standard", "high"
LOW, MID = "low", "mid"
LOW_MAX_CORES = 4
LOW_MAX_MEMORY_GB = 8
SUBSCRIPTION_FREE_CLASSES = frozenset({LOW, MID})

# Accelerator memory, measured separately from the CPU/RAM decision above.
#
# The floor is aggregate rather than per-device: 64 GB is reached as one 80 GB
# card, two 32 GB cards or four 24 GB cards, and a workload sized to the total
# does not care which. Summing is also the reading that cannot be gamed by
# owning more small cards than the check expected.
#
# What this class does *not* mean: Attestor's analysis path has no GPU code at all,
# and `neural_gate` is deliberately integer-only CPU arithmetic so a report's
# digest does not depend on which machine produced it. This measurement exists
# to gate capabilities that would genuinely need the memory -- local model
# work -- not to make scanning faster, because scanning would not use it.
ACCELERATOR_MEMORY_GB = 64
ACCELERATED = "accelerated"


def _physical_memory_bytes() -> int | None:
    """Total RAM, or None when the platform will not say without a dependency."""
    # POSIX: the arithmetic is exact and needs nothing installed.
    if hasattr(os, "sysconf"):
        try:
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if pages > 0 and page_size > 0:
                return pages * page_size
        except (OSError, ValueError):
            pass
    if sys.platform == "win32":
        try:
            import ctypes

            class _Status(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = _Status()
            status.dwLength = ctypes.sizeof(_Status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        except Exception:                                    # noqa: BLE001
            pass
    return None


def _discrete_gpu() -> bool:
    """True when a discrete accelerator is present.

    Only asks tools that are already installed and reports nothing about which
    card it is. `nvidia-smi` existing at all is close enough -- it ships with
    the driver, and the driver ships with the card.
    """
    if shutil.which("nvidia-smi"):
        try:
            done = subprocess.run(
                ["nvidia-smi", "--query-gpu=count", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=8, check=False)
            if done.returncode == 0 and done.stdout.strip():
                return True
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("rocm-smi"):
        return True
    return False


def _accelerator_memory_bytes() -> int | None:
    """Total accelerator memory across all devices, or None if it cannot be read.

    Asks the same already-installed tools `_discrete_gpu` uses and keeps the
    same discipline: the total is a number this process holds, and what leaves
    `classify` is a boolean. A VRAM figure is far closer to a fingerprint than
    "high" or "standard" is -- 81,559 MiB names a specific card -- so it stays
    local, exactly like the core count and the RAM size already do.

    None means "could not be read", which is not the same as zero and must not
    be rounded into it. A machine that cannot answer has not been shown to be
    below the floor any more than it has been shown to be above it.
    """
    if shutil.which("nvidia-smi"):
        try:
            done = subprocess.run(
                ["nvidia-smi", "--query-gpu=memory.total",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=8, check=False)
            if done.returncode == 0 and done.stdout.strip():
                total_mib = 0
                for line in done.stdout.splitlines():
                    entry = line.strip()
                    if not entry:
                        continue
                    if not entry.isdigit():
                        # One unparseable row makes the total wrong rather than
                        # merely incomplete, so the whole reading is discarded.
                        return None
                    total_mib += int(entry)
                if total_mib > 0:
                    return total_mib * 1024 * 1024
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    if shutil.which("rocm-smi"):
        try:
            done = subprocess.run(
                ["rocm-smi", "--showmeminfo", "vram", "--csv"],
                capture_output=True, text=True, timeout=8, check=False)
            if done.returncode == 0 and done.stdout.strip():
                total = 0
                for line in done.stdout.splitlines():
                    for field in line.split(","):
                        value = field.strip()
                        # rocm-smi reports VRAM in bytes; take the widest
                        # plausible integer on each row and ignore the rest.
                        if value.isdigit() and int(value) > 1024 ** 3:
                            total = max(total, int(value))
                if total > 0:
                    return total
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    return None


def meets_accelerator_floor(vram_bytes: int | None,
                            floor_gb: int = ACCELERATOR_MEMORY_GB) -> bool:
    """Whether measured accelerator memory clears the floor.

    Unreadable memory is False. That direction is the opposite of the billing
    decision above -- there, an unproven machine is not charged; here, an
    unproven machine does not get a capability it may be unable to run. Both
    rules fail toward not taking something from the customer.
    """
    if vram_bytes is None:
        return False
    return vram_bytes >= floor_gb * (1024 ** 3)


SUPPORTED, DEGRADED, UNKNOWN = "supported", "degraded", "unknown"


def preflight(vram_bytes: int | None = None, probe: bool = True,
              floor_gb: int = ACCELERATOR_MEMORY_GB) -> dict:
    """Whether a memory-hungry capability is *supported* here, not whether it may run.

    The floor is a recommended requirement, not a minimum one. Below it the
    work is still attempted when the caller opts in, because a smaller job on
    a smaller card often completes and refusing outright would be a lock
    dressed up as a system requirement. What the caller does not get below the
    floor is a promise: the run may exhaust device memory and die part-way,
    and that outcome is reported as expected rather than as a bug.

    `unknown` is grouped with `degraded` deliberately. A machine that will not
    say how much memory it has has not been shown to have enough, and telling
    somebody their run is supported when that could not be established is the
    one answer that would be dishonest in both directions.

    This says nothing about scanning. Attestor's analysis path is CPU-only and
    bounded, and no amount of accelerator memory changes what it does.
    """
    if vram_bytes is None and probe:
        vram_bytes = _accelerator_memory_bytes()
    if vram_bytes is None:
        status = UNKNOWN
        message = ("accelerator memory could not be read, so a %d GB floor could "
                   "not be confirmed; the run may exhaust memory and stop"
                   % floor_gb)
    elif meets_accelerator_floor(vram_bytes, floor_gb):
        status = SUPPORTED
        message = "accelerator memory clears the %d GB floor" % floor_gb
    else:
        status = DEGRADED
        message = ("accelerator memory is below the %d GB floor; the run is "
                   "permitted but unsupported and may exhaust memory and stop"
                   % floor_gb)
    return {
        "schema": SCHEMA,
        "status": status,
        "supported": status == SUPPORTED,
        # Not a prediction that it *will* fail -- a statement that failing is
        # an expected outcome here rather than a defect worth reporting.
        "may_exhaust_memory": status != SUPPORTED,
        "floor_gb": floor_gb,
        "message": message,
    }


class UnsupportedHardware(RuntimeError):
    """The floor was not met and the caller did not opt in to running anyway."""


def require_accelerator(allow_below_floor: bool = False,
                        vram_bytes: int | None = None, probe: bool = True,
                        floor_gb: int = ACCELERATOR_MEMORY_GB) -> dict:
    """Return the preflight, or raise unless the caller accepted the risk.

    The opt-in is a parameter rather than an environment variable so that
    choosing to run unsupported is visible at the call site and in the command
    line that produced a result -- a run that may have died for lack of memory
    should not look identical to one that could not.
    """
    verdict = preflight(vram_bytes=vram_bytes, probe=probe, floor_gb=floor_gb)
    if not verdict["supported"] and not allow_below_floor:
        raise UnsupportedHardware(verdict["message"])
    verdict["ran_below_floor"] = not verdict["supported"]
    return verdict


def classify(cores: int | None = None, memory_bytes: int | None = None,
             gpu: bool | None = None, vram_bytes: int | None = None,
             probe_vram: bool = True) -> dict:
    """The tier, and the reason for it.

    Arguments exist so the decision can be tested without owning four
    machines; production passes nothing.
    """
    cores = cores if cores is not None else (os.cpu_count() or 1)
    memory_bytes = (memory_bytes if memory_bytes is not None
                    else _physical_memory_bytes())
    gpu = gpu if gpu is not None else _discrete_gpu()
    memory_gb = round(memory_bytes / (1024 ** 3), 1) if memory_bytes else None

    powerful = (cores >= HIGH_END_CORES
                and memory_gb is not None and memory_gb >= HIGH_END_MEMORY_GB)
    # A discrete GPU alone does not make an otherwise modest or old PC a
    # high-tier workstation. CPU and RAM must both clear the threshold.
    tier = HIGH if powerful else STANDARD

    if tier == HIGH:
        hardware_class = HIGH
    elif memory_gb is None:
        # Unknown hardware is never used as a reason to demand payment.
        hardware_class = LOW
    elif cores <= LOW_MAX_CORES or memory_gb <= LOW_MAX_MEMORY_GB:
        hardware_class = LOW
    else:
        hardware_class = MID

    if tier == STANDARD:
        reason = ("below the workstation threshold (%d cores, %s GB)"
                  % (cores, memory_gb if memory_gb is not None else "unknown"))
    else:
        reason = ("%d cores and %s GB clears the workstation threshold "
                  "(%d cores, %d GB)"
                  % (cores, memory_gb, HIGH_END_CORES, HIGH_END_MEMORY_GB))

    # Memory unavailable means the machine could not be shown to be high-end.
    # An unproven machine is classified down rather than up, so a failed
    # measurement never becomes a reason to claim more capability than was
    # demonstrated.
    if memory_bytes is None:
        tier, hardware_class, reason = (
            STANDARD,
            LOW,
            "physical memory could not be read on this platform; an unproven "
            "machine is classified down",
        )

    if vram_bytes is None and probe_vram:
        vram_bytes = _accelerator_memory_bytes()
    accelerated = meets_accelerator_floor(vram_bytes)

    return {
        "schema": SCHEMA,
        "version": VERSION,
        "tier": tier,
        "hardware_class": hardware_class,
        # A boolean, never the measured size. Which threshold was applied is
        # already public in this file, so publishing the answer reveals a bit;
        # publishing the megabytes would name the card.
        "accelerator_class": ACCELERATED if accelerated else STANDARD,
        "meets_accelerator_floor": accelerated,
        "accelerator_floor_gb": ACCELERATOR_MEMORY_GB,
        "reason": reason,
        # Deliberately coarse. `platform.system()` distinguishes three
        # operating systems and identifies nobody.
        "platform": platform.system(),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--show-inputs", action="store_true",
                        help="print the measurements behind the decision; "
                             "they are never transmitted")
    args = parser.parse_args(argv)

    verdict = classify()
    if args.show_inputs:
        memory = _physical_memory_bytes()
        vram = _accelerator_memory_bytes()
        verdict["_inputs_local_only"] = {
            "cores": os.cpu_count(),
            "memory_gb": round(memory / (1024 ** 3), 1) if memory else None,
            "discrete_gpu": _discrete_gpu(),
            "accelerator_memory_gb": (
                round(vram / (1024 ** 3), 1) if vram else None),
        }

    if args.json:
        print(json.dumps(verdict, indent=2, sort_keys=True))
    else:
        print("class        : %s" % verdict["hardware_class"])
        print("capability tier: %s" % verdict["tier"])
        print("because      : %s" % verdict["reason"])
        print("accelerator  : %s (floor %d GB aggregate VRAM)" % (
            "meets the floor" if verdict["meets_accelerator_floor"]
            else "below the floor or unreadable",
            verdict["accelerator_floor_gb"]))
        print("sent         : nothing; this module decides locally")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
