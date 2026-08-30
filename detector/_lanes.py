"""Lane manifest -- the machine-readable dual-use split.

Drives the distribution boundary between the public-safe `attestor` (defensive)
package and the deliberate-release `attestor-redteam` package. A build script or
packager consults REDTEAM to exclude offensive modules from the default wheel;
runtime code can use is_redteam() to gate offensive capability.

See DUAL_USE_AUDIT.md for the evidence behind each classification.
"""
from __future__ import annotations

# Offensive / red-team lane: standalone scripts, never wired into the `attestor`
# CLI. Each requires deliberate, direct invocation on authorized targets.
REDTEAM: frozenset[str] = frozenset({
    # live-network (send traffic to an explicit target)
    "active_scan42", "msf_lite42", "recon_net42",
    # local code execution (fuzzers / labs)
    "crashforge42", "offensive_lab42", "offensive_fuzz42", "mayhem",
    "escape_lab414", "purple_team42", "pwnbridge42",
    # payload / PoC generation (writes attack code, does not run it)
    "poc_generator", "poc_gen42", "poc_writer42", "payload_decoder",
    # offline credential auditing
    "password_audit",
    # metasploit bridge (if present)
    "msf_bridge", "sliver_bridge",
})


def is_redteam(module: str) -> bool:
    """True if `module` (bare name, no .py) belongs to the red-team lane."""
    return module in REDTEAM
