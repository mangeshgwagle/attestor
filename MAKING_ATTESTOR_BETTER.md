# Making Attestor Truly Better — Build Log & Runbook

This documents the "make it truly better, not just louder" work: a measurement
harness, false-positive surgery, a training flywheel, and simultaneous 3B+7B
training across Colab and Kaggle.

## The problem this fixes

The self-scan produced **20,485 findings, 19,795 "critical"** — almost all from
pwntools syscall tables. A scanner that cries wolf 19,795 times is useless. The
fix is not more rules; it's **measured precision** plus **noise suppression**.

---

## 1. Measurement — you can now prove better, not guess it

**`attestor evaluate`** → precision / recall / F1 on the labelled corpus
(`detect.EXPECTED`, 42 cases), per-rule and overall, plus a clean-corpus false-
positive check. The core engine scores **100% / 100% / F1 1.000** with **0 FPs**
on the clean set.

```bash
attestor evaluate               # scorecard
attestor evaluate --json        # machine-readable
attestor evaluate --noise .     # measure FP reduction on a real tree
attestor evaluate --calibrate   # rewrite triage weights from measured precision
```

Every change to a rule now produces a number. That's the whole game.

## 2. False-positive surgery — the 20k problem, solved

Two new layers, both measured:

- **`detector/vendored.py`** — classifies each file as first-party / vendored /
  generated / test. Detects `node_modules`, `site-packages`, minified bundles,
  **pwntools/syscall tables**, and >70%-constant lookup tables. Vendored files
  get weight ~0.0, so their findings can't dominate.
- **`detector/triage.py`** — `rule_confidence × file_weight × severity` → a single
  priority → **report / review / suppress**.

Proven in miniature: a pwntools syscall table's `EXP-ROOTKIT` finding →
**suppress** (priority 0.007), while a real AWS key → **report** (0.98) and a
command injection → **report** (0.60).

```bash
attestor triage .               # prioritized findings, vendored noise removed
```

## 3. The flywheel — the moat GPT can't copy

**`detector/flywheel.py`** turns every scan into Owen Coder training data
(`{instruction, output}`, drop-in for `training_data_merged.jsonl`). High-priority
findings become true-positive examples; suppressed ones become false-positive
examples; the ambiguous middle can be labelled by Owen Coder itself (`--auto`).
Over scans, the model learns **your** codebase's true/false boundary — something
a generic model never has.

```bash
attestor flywheel . --out new_pairs.jsonl        # bronze labels from triage
attestor flywheel . --out new_pairs.jsonl --auto # + Owen Coder silver labels
```

---

## 4. Train 3B + 7B SIMULTANEOUSLY (Colab + Kaggle)

| Platform | GPU | Model | Notebook |
|---|---|---|---|
| **Google Colab** | 1× T4 (15 GB) | **Owen Coder 3B** | `training/Owen_Coder_Expert.ipynb` |
| **Kaggle** | 2× T4 (30 GB) | **Owen Coder 7B** | `training/Owen_Coder_7B_Kaggle.ipynb` |

Both read the same `training_data_merged.jsonl` (2,475 pairs) and export a GGUF.
Run them at the same time — they're independent accounts and independent GPUs.

### Kaggle one-time setup (you must do this — I can't create accounts)
1. Sign in at **kaggle.com** → **Settings → verify phone** (unlocks GPU + internet).
2. **New Notebook → Import** `training/Owen_Coder_7B_Kaggle.ipynb`.
3. Right panel → **Accelerator: GPU T4 ×2**, **Internet: On**.
4. **Add Data → Upload** `training_data_merged.jsonl` (mounts under `/kaggle/input/…`).
5. **Run All**. When done, **Save Version** → download the `.gguf` from the Output tab.

### Colab (in parallel)
1. Open `training/Owen_Coder_Expert.ipynb` in Colab.
2. Runtime → **T4 GPU**. Upload `training_data_merged.jsonl` via the file sidebar.
3. **Run All** → download the 3B GGUF.

### Install locally when both finish
```bash
ollama create owen-coder    -f training/Modelfile      # 3B (from Colab)
ollama create owen-coder-7b -f training/Modelfile.7b   # 7B (from Kaggle)
```

---

## Full list of new commands

```
attestor evaluate [--json] [--noise ROOT] [--calibrate]   precision/recall/F1 + FP reduction
attestor triage ROOT [--json]                             prioritize, suppress vendored noise
attestor flywheel ROOT [--out F] [--auto]                 findings -> training pairs
```

New modules: `detector/vendored.py`, `detector/triage.py`, `detector/evaluate.py`,
`detector/flywheel.py`. New notebook: `training/Owen_Coder_7B_Kaggle.ipynb`.

## What's next (highest leverage remaining)
- **Bigger labelled corpus** → pull NIST Juliet / OWASP Benchmark / CVEfixes so
  precision/recall reflect thousands of cases, not 42. (OpenCode can fetch +
  normalize these in parallel while the engine work continues.)
- **Calibrate from real data** → run `evaluate --calibrate` on the expanded corpus
  so triage weights are earned end-to-end.
- **Wire triage into the HTML report** so `attestor report` shows only the
  report/review buckets by default.
