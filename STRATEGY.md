# Attestor: Differentiation, Training, and Evaluation Strategy

This document sets out where Attestor can be **measurably** better than
comparable AI coding systems, and how to train and evaluate it toward clearly
defined, bounded capabilities. It is deliberately not a plan for a "perfect" or
general-purpose coding model. It is a plan for a robust system with stated
limits and quality targets that can be checked against external ground truth.

The single most important framing, established by measurement rather than
ambition:

> Attestor does not compete on **code generation**. It competes on
> **verification**: reproducible, hallucination-free, offline evidence about
> code. Where a frontier model *proposes*, Attestor *proves*.

Everything below follows from that.

---

## Part 1 — Where Attestor can be measurably better

General coding models (Copilot, Qwen-Coder, Claude, etc.) win decisively on
open-ended generation and natural-language reasoning, and Attestor never will —
its core is a deterministic analyzer with hand-written rules, not a learned
generator. Chasing HumanEval or SWE-bench would be a losing race. The
differentiators below are the axes where a deterministic, evidence-bound tool
*structurally* beats a generative model, each with a metric.

### 1. Reproducible, re-verifiable findings (the core moat)

Every finding is bound to a SHA-256 of the exact source bytes and can be
re-verified by re-reading the tree. No commercial SAST tool and no LLM offers
this. A report is evidence, not an opinion.

- **Metric:** byte-identical report for identical input, across machines and
  runs. **Target: 100%.** (The integer-only gate and content-addressed schemas
  exist precisely to hold this.)

### 2. Zero hallucination on findings

A deterministic rule cannot invent a vulnerability that is not there. An LLM
vulnerability-finder can, and must be independently checked.

- **Metric:** false-positive rate, measured as findings the tool raises on the
  *fixed* variant of a NIST Juliet pair (which by construction has no planted
  flaw). **Current: 5.5% (Java). Target: below 5%, trending down.**

### 3. Offline / air-gapped operation

The analysis path makes no network calls and starts no target process. This is
the only mode acceptable for sensitive, proprietary, or already-compromised
code — a market segment cloud LLMs cannot serve at all.

- **Metric:** network syscalls and spawned processes on the analysis path.
  **Target: 0.** Enforced by the machine-checked execution contract in every
  report (`network_accessed: false`, `target_code_executed: false`).

### 4. Cross-file / repository-level taint

Most real injection bugs span files (source in a controller, sink in a DAO). A
per-file scanner and a fixed-context LLM both miss these. Attestor now follows
taint across files in the scan path.

- **Metric:** detection on NIST Juliet's multi-file flow variants (~25k Java,
  ~50k C/C++ cases) — a corpus segment built specifically for cross-file flow.
  **Baseline: to be measured with multi_file enabled.**

### 5. Coverage of underserved languages

Attestor analyzes x86-64 assembly and **IBM High Level Assembler** (System/360
and z/Architecture). Mainframe assembler is load-bearing in banking, insurance,
and government and is essentially unserved by modern tooling.

- **Metric:** rule count and per-CWE detection per language; HLASM is a
  category with **no mainstream competitor.**

### 6. Build-divergence detection

Comparing source against its compiled assembly to flag capabilities the binary
has that the source never requested — the XZ-utils / SolarWinds class, which
source review cannot catch by construction.

- **Metric:** on a held-out set of clean-vs-tampered build pairs, true-positive
  rate on injected syscall/exec/network primitives with zero false positives on
  honest builds. (14 unit cases pass today; needs a larger corpus.)

### Priority order (value x measurability x cost)

1. **Wire and measure cross-file taint** (wiring done; measure on multi-file
   Juliet). Highest leverage; external ground truth already on disk.
2. **Drive down the false-positive rate** — attributable to four named rules
   today; each is checkable against the corpus.
3. **Grow per-CWE coverage** — 64 uncovered Java classes, ranked by corpus
   weight, each validated on accept.
4. **OWASP Benchmark scoring** (needs the corpus) — yields a number *comparable
   to published commercial-tool scores*, the strongest external signal.

---

## Part 2 — Train vs. tool vs. architecture

The most consequential decisions are about **what not to train**. Training is
the right tool for exactly one component; everything else is better served by
rules, retrieval, or system design.

| Capability | Mechanism | Why not training |
|---|---|---|
| **Detecting a new vulnerability class** | Write a **rule**, validate on Juliet | Deterministic, inspectable, no data or GPU needed; a rule's behavior is provable, a learned detector's is not |
| **Ranking / prioritizing findings** | **Train the neural gate** | This *is* the one learned component — see below |
| **Generating code from a prompt** | **Local model** (Qwen via `forge`) + the deterministic **synthesizer** | Training a competitive generator from scratch is infeasible on the target hardware and adds nothing over an existing open model |
| **Repository understanding** | **Semantic graph + snapshot** (architecture) | A parsed call/data-flow graph is exact; a model's "understanding" is not verifiable |
| **Context management** | **Content-addressed snapshot + retrieval** | Deterministic selection beats a learned context window for a verification tool |
| **Hallucination reduction** | **Verification wrapper** (`forge` re-scans its own output) | The fix is architectural: never certify unverified output. Training only reduces, never eliminates |
| **Secure code generation** | **Evidence gate** in `forge` | Generated code is scanned by Attestor's own rules and cannot earn a clean level if it trips them |

### The one thing to train: the ranking gate

`neural_gate` is a small, integer-only classifier that orders findings. It is
the only learned component, and it is trainable on CPU in ~80 seconds.

- **Data:** NIST Juliet (external ground truth) plus a self-generated mutation
  corpus (`mutation_gauntlet` injects labeled defects into in-repo source).
- **Quality controls, already implemented:** grouped train/test split (no
  near-duplicate leakage across the boundary) and a **shuffled-label control**
  that must score at chance — if it does not, the features are memorizing the
  corpus and the headline number is meaningless.
- **Scope honesty:** the gate *ranks*; it does not *detect*. It can surface a
  finding a human would deprioritize, but it cannot find a class no rule covers.

### Fine-tuning a generator (aspirational, hardware-gated)

Turning the local model into a specialized secure-code writer would use QLoRA
on an open code model (e.g. Qwen-Coder) over a corpus of
`(vulnerable code -> fixed code)` pairs, with the fix labeled by CVE or by
Attestor's own before/after scan. Preference optimization (DPO) would use a
real signal: *the developer accepted or rejected the suggested fix.*

**Honest constraint:** fine-tuning a model of this size needs GPU memory the
target machine does not have (no GPU, ~15 GB RAM). On the current hardware this
is out of reach; it belongs on a rented GPU, and the local model should be
*used* (inference) rather than *trained* until then.

---

## Part 3 — Data, licensing, and quality

- **Training data for the gate:** NIST Juliet (US Government, **public domain**
  — safe to train on and cite) and the self-hosted mutation corpus (derived
  from first-party source — clean provenance).
- **Licensing discipline:** do **not** train on and redistribute weights
  derived from copyleft (GPL) source. Advisory metadata (OSV, GHSA, RustSec) is
  CC-BY — usable for detection and measurement with attribution; the *code* each
  advisory points at keeps its own license and must be treated accordingly.
- **Data quality gates:** grouped splits, the shuffled-label control, and
  external labels only. Self-graded corpora (the mutation gauntlet scoring
  itself) are for regression, never for headline capability claims.

---

## Part 4 — Evaluation, regression, and continuous measurement

### Benchmarks (detection)

| Benchmark | Status | What it measures |
|---|---|---|
| **NIST Juliet (Java)** | On disk, wired | Per-CWE detection on the languages Attestor claims |
| **NIST Juliet (C/C++)** | On disk, wired | Memory-safety ceiling (not Attestor's claimed strength) |
| **OWASP Benchmark (Java)** | Needs download | Score **comparable to published commercial SAST tools**; true FP rate |
| **RustSec / real-CVE (Vul4J, CVEfixes)** | Needs download | Detection on real, non-synthetic vulnerabilities |

Explicitly **not** a target: HumanEval, MBPP, SWE-bench, LiveCodeBench — those
measure generation, which is not Attestor's lane. For the generation path, the
right metric is *"does generated code pass Attestor's own security review,"*
which the `forge` evidence level already reports.

### Regression testing

- The full suite (~2,478 tests) plus the planted-bug corpus (**42/42 must be
  detected**) gate every change.
- **Pin the Juliet number in CI** as a floor test (e.g. "Java exact-CWE must not
  fall below 30%"), so a rule edit that quietly costs detections fails the
  build.
- Any change to `detect.py` cascades the content-addressed identities; the
  published-identity test enforces that docs and code agree.

### Hallucination and secure-generation

- **Findings** cannot hallucinate (deterministic); this is verified by the
  fixed-variant false-positive metric, not asserted.
- **Generated code** is held to the same bar as any other code: `forge` scans
  its output and refuses to *certify* (assign a clean evidence level) anything
  that trips Attestor's own rules. It does not silently suppress the code — it
  withholds the certification and warns — which is the correct behavior for a
  tool a security reviewer uses.

### Continuous evaluation

The improvement loop that keeps the tool honest over time:

```
  local model proposes a candidate rule (or vuln/safe code pairs)
        |
  Attestor scores it against NIST Juliet ground truth
        |
  keep it only if exact-CWE rises and fixed-variant noise does not
        |
  it becomes a permanent, externally-verified rule
```

The **ground truth is the teacher, not the model.** The model's output is a
hypothesis; the benchmark is the grader. Nothing enters the ruleset on a
model's say-so.

---

## Quality targets (bounded, not "perfect")

| Property | Current | Target |
|---|---|---|
| Report reproducibility | 100% | 100% (hard invariant) |
| Java Juliet exact-CWE (overall) | 35.4% | grow via coverage, class-by-class |
| Java Juliet exact-CWE (covered classes) | ~90-100% on 12 classes | 90%+ on every covered class |
| False-positive rate (Java, fixed-variant) | 5.5% | below 5% |
| Regression suite | 2,478 pass, 42/42 planted | 0 failures, 42/42 (hard gate) |
| Analysis-path network calls / processes | 0 | 0 (hard invariant) |

### Stated limitations (kept visible on purpose)

- Finds novel *instances* of *modeled* vulnerability classes; not novel
  *classes* (that needs reasoning) and not memory-safety zero-days (that needs
  fuzzing / execution, which is refused by design).
- Detection quality is exactly as good as rule coverage; uncovered classes are
  reported as gaps, never as "clean."
- The generation path depends on an external model and is a separate,
  non-deterministic capability plane — outside the reproducibility guarantees
  of the analyzer.
