#!/usr/bin/env python3
"""Decide what an account may do, from what it actually does.

The problem with asking the machine
-----------------------------------
`hardware_tier` runs on the customer's computer and makes a coarse local
low/mid/high decision. Low and mid map to the subscription-free `standard`
tier. A customer who edits that file can change the answer. That is not a bug
to be patched: any measurement taken on hardware the other party controls can
be forged, and the fixes -- signed attestation, kernel agents -- cost more
trust than the subscription is worth.

So the hardware answer is a *default*, not an enforcement. What actually
decides entitlement is usage, which the server measures itself and the client
cannot touch.

Why this catches the right people anyway
----------------------------------------
The lie buys nothing. Somebody on a 64-core workstation who claims the free
tier still runs into the free tier's ceiling, because a big machine is bought
in order to do more work and doing more work is the thing being counted. The
free allowance is sized for a laptop's worth of scanning; exceeding it is
revealed preference, not a self-report.

That also makes the pricing fairer than the hardware test was. Someone with an
expensive machine who scans one small repo a month costs nothing to serve and
pays nothing. Someone on a modest laptop driving a CI pipeline across forty
repositories is the expensive customer, whatever their CPU says.
"""
from __future__ import annotations

import time

SCHEMA = "attestor.tier-policy/1.0"
VERSION = "4.1.5"

FREE, PAID = "standard", "high"
PERIOD_SECONDS = 30 * 24 * 60 * 60

# Sized for one developer scanning their own work. A laptop doing normal
# review will not approach it; a CI pipeline across many repositories will
# pass it in days, which is the distinction being priced.
FREE_MONTHLY_BYTES = 512 * 1024 * 1024

# A workstation's advantage is parallelism, so that is what the free tier
# limits. Unlike the hardware claim, this is enforced on the server and no
# edit to a client file changes it.
CONCURRENCY = {FREE: 1, PAID: 8}

# Sustained use well under the hard ceiling still says "this is a workstation
# workload". Crossing it does not cut anyone off; it marks the account so the
# upgrade prompt is honest rather than a surprise at the ceiling.
WORKSTATION_PATTERN_BYTES = int(FREE_MONTHLY_BYTES * 0.6)

# Scans a workstation account may run before subscribing. This is an
# evaluation period, not an allowance -- the free tier already exists for
# people who should never pay, and this exists so the people who should can
# find out whether it is worth it first.
#
# Counting scans is the wrong basis for *billing* (a scan can be one file or a
# monorepo, so it rewards whoever batches hardest) and that is exactly why
# bytes are metered elsewhere. As a trial it is the right basis, because what
# is being offered is a number of looks, not a quantity of work -- and the
# per-request size cap keeps the total bounded regardless of how it is spent.
TRIAL_SCANS = 5


def period_expired(record: dict, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return (now - record.get("period_started", now)) >= PERIOD_SECONDS


def roll_period(record: dict, now: float | None = None) -> dict:
    """Start a fresh allowance. Callers persist the result."""
    record["bytes_this_period"] = 0
    record["period_started"] = int(time.time() if now is None else now)
    return record


def looks_like_a_workstation(record: dict) -> bool:
    """Usage consistent with a machine bought to do a lot of this."""
    return record.get("bytes_this_period", 0) >= WORKSTATION_PATTERN_BYTES


def decide(record: dict, active_scans: int = 0,
           now: float | None = None) -> dict:
    """May this account scan, and what should it be told.

    Returns a verdict rather than raising, because "no, and here is the
    reason, and here is what it would cost" is a better answer to a paying
    customer than an error code.
    """
    tier = record.get("tier", FREE)
    entitled = bool(record.get("entitled"))
    used = int(record.get("bytes_this_period", 0))

    if period_expired(record, now):
        # Reported, not applied: mutating a record inside a read-only decision
        # would make the caller's persistence accidental.
        return {"allowed": True, "reason": "", "period_stale": True,
                "tier": tier, "used_bytes": used}

    limit = CONCURRENCY.get(tier, 1)
    if active_scans >= limit:
        return {"allowed": False, "period_stale": False, "tier": tier,
                "used_bytes": used, "denial": "concurrency",
                "reason": ("the %s tier runs %d scan%s at a time and %d %s "
                           "already running"
                           % (tier, limit, "" if limit == 1 else "s",
                              active_scans,
                              "is" if active_scans == 1 else "are")),
                "remedy": "wait, or upgrade for %d concurrent scans"
                          % CONCURRENCY[PAID]}

    if tier == PAID and not entitled:
        used_trials = int(record.get("trial_scans_used", 0))
        remaining = TRIAL_SCANS - used_trials
        if remaining > 0:
            return {"allowed": True, "period_stale": False, "tier": tier,
                    "used_bytes": used, "trial": True,
                    "trial_remaining": remaining - 1,
                    "reason": "",
                    "notice": ("trial scan %d of %d; after that the "
                               "workstation tier needs a subscription"
                               % (used_trials + 1, TRIAL_SCANS))}
        return {"allowed": False, "period_stale": False, "tier": tier,
                "used_bytes": used, "trial": False, "trial_remaining": 0,
                "denial": "subscription",
                "reason": ("all %d trial scans are used and the workstation "
                           "tier is not settled" % TRIAL_SCANS),
                "remedy": "complete the subscription"}

    if tier == FREE and used >= FREE_MONTHLY_BYTES:
        return {"allowed": False, "period_stale": False, "tier": tier,
                "used_bytes": used, "denial": "quota",
                "reason": ("the free allowance of %d MB is used up for this "
                           "period" % (FREE_MONTHLY_BYTES // (1024 * 1024))),
                "remedy": ("upgrade, or wait %d day(s) for the period to roll"
                           % max(1, int((PERIOD_SECONDS - (
                               (time.time() if now is None else now)
                               - record.get("period_started", 0)))
                               // 86400)))}

    verdict = {"allowed": True, "reason": "", "period_stale": False,
               "tier": tier, "used_bytes": used}
    if tier == FREE and looks_like_a_workstation(record):
        # Advisory only. Cutting someone off at 60% because of a guess about
        # their hardware would be exactly the arbitrariness this module exists
        # to remove.
        verdict["notice"] = (
            "usage this period is %d MB, which is workstation-shaped; the "
            "free ceiling is %d MB"
            % (used // (1024 * 1024), FREE_MONTHLY_BYTES // (1024 * 1024)))
    return verdict
