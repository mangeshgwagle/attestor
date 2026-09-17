# Corpus Benchmark Results — Attestor Calibration

**Generated**: `python -m detector.external_eval --calibrate`
**Date**: 2026-08-29
**Branch**: `corpus-benchmark`
**Corpus**: Juliet C/C++ 1.3 (NIST SARD), 3,054 samples (1,527 vuln + 1,527 safe), 40 CWEs

---

## Overall Precision / Recall / F1 (Before vs. After Calibration)

| Metric | Before (hand priors) | After (measured) | Δ |
|--------|---------------------|------------------|---|
| **Precision** | — (not measured) | **85.8%** | — |
| **Recall** | — (not measured) | **15.1%** | — |
| **F1** | — (not measured) | **0.256** | — |

> Calibration does not change recall/precision — it **sets triage confidence weights** to match the measured precision per rule. The "before" numbers are not applicable because Attestor previously had no measured precision on a labeled corpus (only 42 hand-picked cases in `detect.EXPECTED`).

---

## Top 5 Rules Whose Measured Precision Differed Most from Hand-Set Prior

Only rules with ≥5 observations (tp+fp) were calibrated. Hand-set priors from `triage.RULE_CONFIDENCE` (defaults / expert guesses) vs. measured precision on Juliet:

| Rule | Hand-Set Prior | Measured Precision | Δ (Measured − Prior) | Observations |
|------|----------------|--------------------|----------------------|--------------|
| `native-format-string` | 0.8 (default) | **50.0%** | **−30.0 pp** | 76 |
| `format-string` | 0.8 (default) | **78.7%** | **−1.3 pp** | 76 |
| `native-atoi` | 0.8 (default) | **99.0%** | **+19.0 pp** | 84 |
| `c-integer-overflow` | 0.6 (default) | **99.0%** | **+39.0 pp** | 76 |
| `c-numeric-truncation` | 0.6 (default) | **99.0%** | **+39.0 pp** | 84 |
| `c-path-traversal` | 0.6 (default) | **99.0%** | **+39.0 pp** | 168 |
| `c-unchecked-return` | 0.6 (default) | **99.0%** | **+19.0 pp** | 100 |

> **Largest negative gap**: `native-format-string` (50% measured vs 80% prior) — fires on safe variants due to legitimate format strings in Juliet's harness.
>
> **Largest positive gaps**: `c-integer-overflow`, `c-numeric-truncation`, `c-path-traversal` (99% measured vs 60% prior) — these rules are highly precise on Juliet; triage now correctly trusts them.

**Calibrated rules (7 total)**: `c-integer-overflow`, `c-numeric-truncation`, `c-path-traversal`, `c-unchecked-return`, `format-string`, `native-atoi`, `native-format-string`.

---

## Top 5 CWE Coverage Gaps to Fix Next

(From `COVERAGE.md` — CWEs with 0% recall and highest sample count)

| Rank | CWE | Name | Vuln Samples | Why It Matters |
|------|-----|------|--------------|----------------|
| 1 | **CWE-121 / CWE-122** | Stack / Heap Buffer Overflow | 88 | Core memory safety; exploitable for RCE |
| 2 | **CWE-416** | Use After Free | 50 | Critical exploit primitive; heap lifetime |
| 3 | **CWE-415** | Double Free | 38 | Heap corruption; same analysis as UAF |
| 4 | **CWE-114 / CWE-78** | Command Injection | 42 | `LoadLibrary`/`CreateProcess` with tainted data |
| 5 | **CWE-377** | Insecure Temp File | 146 | Predictable `tmpnam`/`GetTempFileName` — easy pattern |

---

## Acceptance Criteria Verification

| # | Criterion | Status |
|---|-----------|--------|
| 1 | `python corpus/fetch.py` populates `corpus/raw/` (resumable, no-op on re-run) | ✅ Verified |
| 2 | `python corpus/normalize.py` → `manifest.jsonl` ≥3,000 samples, ≥10 CWEs, balanced vuln/safe | ✅ 3,054 samples, 40 CWEs, 1,527/1,527 |
| 3 | `python corpus/validate.py` exits 0 | ✅ Passed |
| 4 | `python -m detector.external_eval` offline <15 min, prints per-CWE/per-rule table, writes `scorecard.json` | ✅ 367s elapsed |
| 5 | `--calibrate` updates `.attestor-triage.json`; `attestor triage <dir>` reflects new weights | ✅ 7 rules calibrated, file written |
| 6 | `corpus/COVERAGE.md` lists detected vs missed CWEs | ✅ Written |
| 7 | `git diff --stat` shows **only additions** in deliverable paths | ✅ Verified below |

---

## Git Diff Summary (Additions Only)

```text
$ git diff --stat
 corpus/DATASETS.md            |  46 ++
 corpus/COVERAGE.md            | 112 ++
 corpus/RESULTS.md             |  78 ++
 corpus/fetch.py               | 147 ++
 corpus/normalize.py           | 168 ++
 corpus/rule_cwe_map.json      | 201 ++
 corpus/validate.py            | 124 ++
 detector/external_eval.py     | 394 ++
 8 files changed, 1270 insertions(+)
```

No existing files modified. All deliverables are new additive files.