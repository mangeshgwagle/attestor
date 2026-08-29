# TCS Pilot Evidence Bundle

This folder is **evidence**, not a deployment request.

It contains reproducible, offline static-analysis results produced by
Attestor 4.2 (analyzer identity 4.1.4) on **owned and synthetic** fixtures
only. No client, production, or TCS system was scanned or executed.

## What it shows
- `case_tcs.*` -- one finding carried through the evidence spine
  (case_file42.py). The tamper-evident hash chain is intact, the honesty
  gate refused an unproven fix, and the result is marked proven only
  because a regression test was observed to fail before the fix.
- `asm_tcs.*` -- a deliberately weak x86-64 fixture tripping the dangerous
  pattern rules (execve / stack-pivot / NOP-sled / W^X), while a 10,000-line
  clean multi-function program produced **zero** findings.

## How to verify
    cd ..\.owen42_codex_final\Attestor 4.2\detector
    python -I -B -X utf8 demo_tcs_case.py
    python -I -B -X utf8 demo_asm_tcs.py

## Authorization note
Any scan of a TCS held-out repository requires explicit InfoSec
authorization and a sponsored lab. See bench_tcs42.py (auth-gated).
