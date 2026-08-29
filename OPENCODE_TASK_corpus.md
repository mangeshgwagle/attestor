# OpenCode Task — Build a large labeled corpus and calibrate Attestor from it

**You are OpenCode, working autonomously in this repo. This brief is self-contained.**
Read it fully before starting. Do not assume any context beyond this file and the
repo itself.

## Mission

Attestor's precision/recall is currently measured on only **42 labeled cases**
(`detector/detect.py::EXPECTED`). Grow that to **thousands** of publicly-labeled,
CWE-tagged vulnerability samples, build an evaluator that scores Attestor against
them, and **calibrate the triage confidence weights from measured precision** so
`attestor triage` and `attestor evaluate --calibrate` reflect real data instead
of hand-set priors.

Success = a repeatable pipeline that fetches → normalizes → scores → calibrates,
plus a coverage map of which CWEs Attestor actually detects.

## Hard constraints (read twice)

1. **Do NOT modify any existing file.** Not `detect.py`, `evaluate.py`,
   `triage.py`, `vendored.py`, `flywheel.py`, or any scanner. Your work is
   **additive only**, in the paths listed under Deliverables. Verify at the end
   with `git diff --stat` — it must show only new files.
2. **Work on a branch** `corpus-benchmark`. Do not push to `main`/`master`.
3. **Do not commit large third-party data.** Add `corpus/raw/` and
   `corpus/samples/` to `.gitignore`. Commit only: scripts, `manifest.jsonl`,
   `rule_cwe_map.json`, `scorecard.json`, and the `*.md` reports. The corpus is
   reproducible from your fetch script; the repo stays small.
4. **Deterministic & offline after fetch.** Pin dataset versions/commit SHAs.
   Once downloaded, `normalize`, `eval`, and `calibrate` must run with no network.
5. **Respect licenses.** Record each dataset's license in `corpus/DATASETS.md`.
   NIST SARD/Juliet is US-Government public domain; OWASP Benchmark is open source.
   Because you are not committing the raw data, redistribution is not an issue —
   but still document provenance.
6. **Cap size.** Max ~300 samples per CWE per dataset so the corpus stays balanced
   and fast (< 15 min full eval).

## Datasets (in priority order)

**PRIMARY — NIST SARD / Juliet (public domain, uniform, CWE in filename):**
- **Juliet C/C++ 1.3** — https://samate.nist.gov/SARD/ (Juliet Test Suite v1.3, C/C++).
  ~64k cases. Filenames encode the CWE, e.g.
  `CWE78_OS_Command_Injection__char_console_execl_01.c`. Functions named `bad*`
  are vulnerable; `good*` are safe. Best fit for Attestor's native C/C++ engine.
- **SARD Python test cases** — same source, Python subset, CWE-labeled. Fit for the
  Python engine (`detect` + `taint_tracker` + `semantic_similarity`).

**SECONDARY / stretch:**
- **OWASP Benchmark** — https://github.com/OWASP-Benchmark/BenchmarkJava (pin a
  release SHA). ~2,740 Java cases with `expectedresults-1.2.csv` giving per-case
  `# test name, category, real vulnerability (true/false), CWE`. Gold standard for
  precision because true/false labels are explicit. NOTE: it is **Java source**;
  Attestor has no Java *source* scanner today, so treat this primarily as a way to
  **quantify the Java coverage gap** (expect low recall — that's a finding, not a
  failure).
- **Big-Vul** (alt real-CVE C/C++) — https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
  — single CSV of real CVE functions with CWE + vulnerable flag. Use only if the
  SARD Python slice is thin.

Pick PRIMARY first. Only add SECONDARY once PRIMARY passes acceptance.

## Normalized schema

Every sample becomes one line in `corpus/manifest.jsonl`:

```json
{"id": "juliet-c-CWE78-0001",
 "path": "corpus/samples/juliet_c/CWE78__execl_01.c",
 "language": "c",
 "cwe": "CWE-78",
 "vulnerable": true,
 "source": "juliet-1.3",
 "notes": "bad() path present"}
```

- `language` ∈ {c, cpp, python, javascript, typescript, java}.
- `cwe` is canonical `CWE-<n>`.
- `vulnerable` true/false. For Juliet, emit the `bad`-containing file as
  `vulnerable:true`, and the matched `goodX` variant (where the suite provides one)
  as a separate `vulnerable:false` sample — you need safe samples to measure
  precision, not just recall.
- `path` points to the copied source under `corpus/samples/` (gitignored).

## The rule→CWE map (`corpus/rule_cwe_map.json`)

To score per-rule you must map each Attestor `rule_id` (or prefix) to the CWE(s) it
represents. **Harvest existing sources first — do not invent from scratch:**
- `detector/js_scanner.py` findings already carry `.cwe`.
- `detector/taint_tracker.py` findings carry `.sink_cwe`.
- `detector/semantic_similarity.py` findings carry `.cve_cwe`.
- `detector/severity.py` has CWE base scores and CWE↔OWASP maps.
- `detector/compliance.py` has OWASP→CWE lists.
For native/core rules with no CWE attached (e.g. `command-exec`→CWE-78,
`c-strncpy-truncation`→CWE-120/787, `unsafe-libc`→CWE-676, `py-sql-injection`→CWE-89,
`py-subprocess-shell`→CWE-78, `dangerous-eval`→CWE-95, `js-innerhtml`→CWE-79,
`hardcoded-secret`→CWE-798, `tls-verify-disabled`→CWE-295, `weak-hash`→CWE-327),
add them by hand. Write the full map to `corpus/rule_cwe_map.json`.

## Scanner entry points to call per language

- **C/C++:** `detect.scan_file(path)` → findings with `.rule`.
- **Python:** `detect.scan_file(path)`, `taint_tracker.scan_file(path)`,
  `semantic_similarity.scan_file(path)`.
- **JS/TS:** `js_scanner.scan_file(path)` → findings with `.cwe`.
- **Java:** none for source (that's the gap you're measuring).
Add `detector/` to `sys.path` (see how `detector/evaluate.py` does it).

## Evaluation logic (`detector/external_eval.py`, new file)

For each manifest sample: run the language-appropriate scanners, map each finding's
rule → CWE via `rule_cwe_map.json`. The sample is **"flagged"** for its CWE if any
finding maps to it. Build a confusion matrix **per CWE** and **per rule**:

- vulnerable sample, its CWE flagged → **TP**
- vulnerable sample, not flagged → **FN**
- safe sample, flagged for that CWE → **FP**
- safe sample, not flagged → **TN**

Compute precision/recall/F1 per CWE and per rule. Write `corpus/scorecard.json`
and print a readable table. Add `--calibrate`: for every rule with ≥ `min_samples`
(default 5) observations, set its confidence to measured precision and persist via
the existing public API:

```python
import triage
triage.RULE_CONFIDENCE[rule_prefix] = round(precision, 3)
triage.save_overrides()   # writes .attestor-triage.json
```

Do not re-implement triage persistence — call `triage.save_overrides()`.

## Deliverables (all new files)

```
corpus/fetch.py            # download + verify PRIMARY datasets into corpus/raw/ (idempotent, pinned)
corpus/normalize.py        # raw -> corpus/samples/*  + corpus/manifest.jsonl (schema above)
corpus/validate.py         # assert every manifest path exists + CWE well-formed; nonzero exit on failure
corpus/rule_cwe_map.json   # rule_id/prefix -> [CWE...]
corpus/scorecard.json      # written by external_eval
corpus/manifest.jsonl      # the labeled index (committed; small)
corpus/DATASETS.md         # provenance, versions/SHAs, licenses
corpus/COVERAGE.md         # per-CWE detected-vs-missed table (the engine gap map)
detector/external_eval.py  # CWE-level scorer + --calibrate
.gitignore                 # add corpus/raw/ and corpus/samples/
```

## Acceptance criteria (all must pass)

1. `python corpus/fetch.py` populates `corpus/raw/` (resumable; re-run is a no-op).
2. `python corpus/normalize.py` yields `corpus/manifest.jsonl` with **≥ 3,000
   samples across ≥ 10 distinct CWEs**, including both vulnerable and safe samples.
3. `python corpus/validate.py` exits 0.
4. `python -m detector.external_eval` runs **fully offline in < 15 min**, prints a
   per-CWE and per-rule P/R/F1 table, and writes `corpus/scorecard.json`.
5. `python -m detector.external_eval --calibrate` updates `.attestor-triage.json`;
   `attestor triage <dir>` then reflects the new weights.
6. `corpus/COVERAGE.md` lists CWEs Attestor detects vs misses.
7. `git diff --stat` shows **only additions** in the paths above — no existing file
   touched.

## Reporting back

When done, write a short `corpus/RESULTS.md`: overall precision/recall/F1 before vs
after calibration, the top 5 rules whose measured precision differed most from the
hand-set prior, and the 5 highest-value CWE coverage gaps to fix next. That report
is the hand-off — the human integrates `external_eval` into the `attestor evaluate`
subcommand afterward (small follow-up, not your job).

## Guardrails recap
Additive only · branch `corpus-benchmark` · no large data in git · pinned + offline
· cap 300/CWE · call `triage.save_overrides()` don't reinvent it · honest about the
Java gap.
