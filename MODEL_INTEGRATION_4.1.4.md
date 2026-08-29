# Attestor model integration boundary

Status: **Phase 1 implemented, Phase 2 evaluated and closed.**

- Phase 1 (a stdlib-only learned ranker) ships as `neural_gate.py` with
  `neural_gate_model.json`. It obeys every placement rule below.
- Phase 2 (adopting a pretrained code model) was measured and **declined**. The
  reasoning is recorded under "Phase 2" so the decision is auditable rather
  than re-litigated.

Detection behaviour is unchanged by both. The planted corpus is still 42/42 and
no learned component is why any of them is found.

This record fixes where learned components may and may not sit inside Attestor. It
exists because "add a model" is the single change most likely to quietly destroy
what the rest of the system spends 99,000 lines establishing.

## The constraint that decides everything

Attestor's claims rest on recomputation. `verify_report` re-derives a canonical
SHA-256 over the report and fails closed on a mismatch; profile identity, the
evidence store, the CJP preview/apply digest chain, and every Truth Guard
generation depend on the same property. A component that cannot be replayed
bit-for-bit cannot sit inside that envelope without making the envelope a
decoration.

Neural inference is not bit-reproducible in the general case. Pinning weights is
not sufficient: kernel selection, thread count, BLAS backend, hardware
generation, and floating-point non-associativity all move results. On the
Raspberry Pi targets the backend differs from the desktop targets outright.

Therefore:

> A model may **produce evidence**. A model may **not produce a verdict**, and
> its output may **not enter the payload that Truth Guard verifies**.

## What this permits

The finding schema already carries `evidence_state`, and `inferred` is already a
value it takes. `adjudication414.py` already labels a finding `insufficient`
when no decisive evidence is linked, and already refuses to guess from
natural-language message text.

So a learned component is not a new concept in the architecture. It is another
source engine that emits `inferred` evidence, which adjudication then declines to
promote until something decisive corroborates it. No new trust vocabulary is
required, and a model that is wrong degrades to noise rather than to a false
clean bill of health.

## Identity binding

Any model-backed component binds its identity the way compiled profiles do. The
report records, for each model used:

- `model_sha256` over the exact weight/parameter artifact bytes;
- `runtime_sha256` or a pinned runtime version identifier;
- `input_manifest_sha256` over the exact inputs the model saw;
- the execution settings that affect determinism (thread count, provider).

A mismatch fails identity check exactly as a mutated profile does. This makes
tampering detectable even where the output itself is not replayable.

## Placement rules

1. Model output lands in an `advisory` section that is explicitly outside the
   verified digest, or as an `inferred` evidence item bound as above.
2. No model output may create, delete, promote, or suppress a finding.
3. No model output may satisfy a repair permission, an authorization gate, or a
   CJP local-control confirmation.
4. Detection rules stay deterministic. The planted-bug corpus (42/42) and the
   per-rule fixtures remain the acceptance gate for detection; a learned
   component is never allowed to be the reason a planted bug is found.
5. The default coding path stays offline. Remote providers require explicit
   per-request authorization, following the `research_engine41.py` pattern: one
   pinned HTTPS origin, byte-bounded responses, no silent cache writes.

## Dependency posture

Attestor 4.1.4's core detector imported no third-party package in its 262 modules
and shipped no runtime requirements file. That historical property remains
load-bearing for the default detector path: the Raspberry Pi installer calls
no `sudo`, `apt`, `curl`, or network bootstrap. Attestor 4.1.5 adds explicitly
optional dependencies for entitlement verification and for its separately
deployed billing sandbox; those packages are not imported by the core scanner.

A learned component that requires `numpy`, `onnxruntime`, or a tensor runtime is
therefore not a small addition. It is the largest supply-chain change in the
project's history, it breaks the no-root Pi install, and it enlarges the attack
surface of a security tool. Such a component is out of scope here and requires
its own decision record.

Learned components in scope are those expressible in the standard library:
linear and tree models with integer/float arithmetic, binned calibration,
locality-sensitive hashing. These are deterministic on every target board.

## Cold start -- resolved

This section previously said a supervised ranker could not be fitted, because
the only labels available were Attestor's own rule metadata and the 42-finding
planted corpus. That was true of internal data and stopped being the whole
picture once an external corpus was used.

NIST Juliet/SARD supplies 40,519 single-file testcases that each ship a flawed
and a corrected variant of the same function, labelled by someone other than
Attestor. `juliet_corpus.py` turns those into 1,057,949 labelled windows.

The first attempt at this scored well for the wrong reasons, which is worth
recording because every one of these is invisible in the accuracy number:

1. the comments state the answer (`/* POTENTIAL FLAW: ... */`);
2. so do the identifiers (`..._bad`, `goodG2B`, `badSink`);
3. so does the storage class -- Juliet exports every flawed function and makes
   every corrected one `static`, a perfect correlation;
4. so does the filename, which is why the testcase is a grouping key and never
   a feature.

With all four stripped, the artifact shipped in this tree declares a
4096-128-1 integer MLP (524,545 parameters including biases), held-out AUC
0.9994 and accuracy 98.7%. Those values are artifact metadata, not an
independent reproduction claim. Any future retraining must update the artifact,
this record, and a separately reproducible evaluation report together.

`calibration35.py` remains the path for real triage outcomes as they
accumulate, and a prior-only score still must not be presented as a measured
probability.

## Phase 2: pretrained code models -- evaluated, declined

Two independent reasons, either of which is sufficient.

**They did not win.** Compared against the same hashed-n-gram representation on
the corpus available at the time (the mutation corpus, before Juliet was
introduced): CodeBERT at 125M parameters lost to the hashed features by 13
points, and GraphCodeBERT scored 0.728 against 0.777. A distilgpt2 comparison
was void -- fed raw activations without standardisation, it returned a
degenerate 0.500 on every seed -- and is not counted as evidence either way.
These comparisons have **not** been repeated on the Juliet corpus, so the fair
statement is that pretrained code models were not better on the corpus tested,
not that they cannot be.

**They cost the property that makes the rest credible.** The 4.1.4 core scanner
imports no third-party package. The Raspberry Pi installer calls no `sudo`,
`apt`, `curl`, or network bootstrap. Attestor 4.1.5's optional entitlement verifier
and separately deployed billing service have isolated, pinned requirements;
they do not turn the detector into a transformer runtime.
Adopting a transformer means `torch` or `onnxruntime`, which is the largest
supply-chain change in the project's history, in a security tool, to gain
ranking quality that was not demonstrated. Pure-Python inference also caps out
near a million parameters; a 12B model would need roughly two hours per forward
pass, so "just run it in stdlib" is not an escape.

Training dependencies remain outside the runtime detector path: the gate was
fitted offline and inference uses the JSON integer artifact. The optional
training utility is shipped under `integrations/gate_trainer/` and imports
NumPy; nothing in `detector/` imports NumPy or PyTorch at runtime.

**What would reopen this.** A measured win on Juliet large enough to matter,
achieved by a model expressible in the standard library at inference time --
or a decision, taken explicitly and recorded, that the zero-dependency property
is worth trading. Neither condition is met today.

## Phase 3: a local generative model -- audited, and refused

Two routes were built and measured. No key and no network were used: both ran
entirely on the local machine.

**Route A, train one from scratch.** A 1,063,680-parameter transformer was
trained on correct code only, to test whether defective code is more surprising
to it. Held-out AUC **0.4534** -- below chance, and backwards: the flawed
variant was *less* surprising in 62% of pairs, because Juliet's fixes add guard
code and longer text is harder to predict. The corpus also carries only 237
distinct tokens once declassified, so there is little for a language model to
learn from it. Route A is dead.

**Route B, use a local instruct model.** Two were tested against the battery in
`model_audit.py`, which mixes findings that are genuinely present with findings
invented for code that is correct:

| model | verdict | correct | genuine accepted | fabrications caught |
|---|---|---|---|---|
| Qwen2.5-3B-Instruct (leading prompt) | refused | 2 of 6 | 0 of 2 | 3 of 3 |
| Qwen2.5-3B-Instruct (neutral prompt) | refused | 3 of 6 | 3 of 3 | 0 of 3 |
| Qwen2.5-Coder-1.5B-Instruct | refused | 3 of 6 | 0 of 3 | 3 of 3 |

A note on running these at all: quantising to int8 is worth doing before any
of it. On Qwen's architecture -- 197 `nn.Linear` modules -- dynamic int8 gave
1.65x the throughput at a sixth of the weight memory (5.84 tok/s against 3.54,
934 MB against 6,175 MB on the 1.5B), and took the 3B from 0.15 tok/s in
emulated bfloat16 to 0.97. An earlier measurement claiming int8 bought nothing
was taken on GPT-2, which is `Conv1D`-based, so dynamic quantisation of
`nn.Linear` never applied to it; that conclusion did not transfer and was
wrong for this family.

Both answered "the report is incorrect" to **every** probe under the first
wording. Asked about a real use-after-free, the 3B replied that the report was
wrong while describing the defect accurately in the next sentence, and the 1.5B
claimed a 100-byte source buffer "has a size of 10" and that
`free(p); printLine(p);` frees the pointer *after* printing it.

Then the prompt was made neutral -- "begin with exactly one word, CONFIRMED or
REJECTED" instead of wording that invited a rejection -- and the 3B was re-run
on the same six probes. It **accepted all six**, including all three
fabrications:

| run | prompt | verdict on every probe | genuine | fabricated |
|---|---|---|---|---|
| first | invited rejection | REJECTED | 0 of 2 | 3 of 3 |
| second | neutral | ACCEPTED | 3 of 3 | 0 of 3 |

Same weights, same probes, opposite constant answer. The model is not judging
the code at all; its verdict follows the framing it is handed. That is
acquiescence, and it is disqualifying for a component whose entire job would be
to disagree when a report is wrong.

It is also why the verdict here cannot rest on one half of the battery. A
fabrication-only metric scores the first run 3 of 3; a "does it catch real
defects" metric scores the second run 3 of 3. The same `always_one_answer`
flag refused both.

Note what a fabrication-only metric would have said: both models caught 3 of 3
invented findings, a perfect score on that half. A model with one opinion
passes any test that only looks at one side, so the audit requires the model to
**separate** true from false, and reports `always_one_answer` explicitly.

**Consequence.** No model output reaches a user until `model_audit.may_speak`
returns true for the role being asked of it, and it fails closed on a missing,
tampered, foreign-battery, or wrong-role report. `record_violation` withdraws a
model that contradicts a verified finding at runtime. On today's evidence both
local models are refused **for adjudication**, permanently as far as this
release is concerned.

### Phrase-only, which is enabled

Adjudication is not the only role, and gating explanation on the adjudication
battery would refuse a model for failing a task it is never given. So there is
a second battery and a second clearance. `ROLE_PHRASE` scores faithfulness on
findings the model is *told* are settled: it must locate the defect, describe
the right mechanism, not wander onto other defects, and not dispute what it was
handed. The two clearances do not authorise each other, and a test asserts it.

Measured on the phrasing battery:

| model | phrasing verdict | faithful |
|---|---|---|
| Qwen2.5-Coder-1.5B-Instruct | **trusted** | 3 of 3 |
| Qwythos-9B (Q4_K_M, llama.cpp) | **trusted** | 3 of 3 |

### Adjudication does scale with size -- an earlier claim corrected

This record previously said the adjudication failure was "not a tuning
problem", inferred from two models of 1.5B and 3B that each answered with one
constant verdict. A 9B run through llama.cpp shows that inference was wrong:

| model | correct | genuine accepted | fabrications caught | one constant answer? |
|---|---|---|---|---|
| Qwen2.5-Coder-1.5B | 3 of 6 | 0 of 3 | 3 of 3 | yes |
| Qwen2.5-3B (neutral prompt) | 3 of 6 | 3 of 3 | 0 of 3 | yes |
| **Qwythos-9B** | **4 of 6** | **3 of 3** | **1 of 3** | **no** |

The 9B is the first model to vary its verdict with the code rather than with
the framing, and the first to catch a fabricated finding on the merits --
"the `c-use-after-free` warning is a false positive" on code that frees after
its last use. It still fails the bar, which requires all six, and the bar
stays where it is for a component that would be talking to people about
security defects. But the direction is real and the earlier claim overstated
what two small models could establish.

One of its two misses is worth recording precisely, because it is not a
comprehension failure: on the initialised-pointer probe it answered CONFIRMED
while writing "`d` is assigned the address of `t` on line 6, so it is never
null when dereferenced". The reasoning is correct and the label contradicts
it, which suggests the CONFIRMED/REJECTED convention was read as agreeing with
the analysis rather than with the report. That is a prompt-clarity problem on
our side as much as a model failure.

### Generation, which is the one thing these models are actually good for

Adjudication is the wrong job for them. Writing code to a specification is not.
CWE-862 and CWE-306 are ranks 4 and 21 of the CWE Top 25 and Juliet contains no
case for either -- it is C/C++ memory safety and never covers web
authorisation -- so there was nothing to write rules against.

Twenty-four flawed/fixed pairs were generated by the local 9B across Flask,
FastAPI and Django shapes. The model was told what the flaw was; it was never
asked whether anything was a defect. Every pair parsed.

The corpus is **not ground truth and is not used as a benchmark**. Reading the
first five made the reason plain: three of the five "fixed" variants did not
fix anything. CWE-770's fix checked the body size *after* reading the whole
body; CWE-434's allow-list compared `txt` against `{'.txt'}` so nothing could
ever be saved; CWE-862's check compared a record id against a user id. What the
pairs are reliably good for is *shape* -- every fix adds an identity check and
a 401/403, and every flaw has neither -- and that is the only thing taken from
them.

The two rules were then written by hand and are measured on their negatives,
which is where an absence-based rule actually lives or dies: they stay silent
on `@login_required`, on a session ownership check, on FastAPI `Depends`, on
the login route itself, on unprivileged public routes, on a handler that
already returns 403, and across all 299 Python files in this tree. Recall
against the generated shapes is 58% and 67%, and that number is reported as
what it is -- performance against model-authored examples, not against ground
truth.

Rules built this way carry the provenance in their comment block, and the
generated corpus lives outside the repository.

### A harness bug that nearly produced a false refusal

The first 9B run scored **0 of 6 on both batteries**, every answer blank. The
model was not refusing: it is a reasoning model, it spent the entire token
budget in `reasoning_content`, and `content` came back empty with
`finish_reason: length`. The harness read `content`, got nothing, and graded
silence.

Two changes followed, and both matter beyond this model. Thinking is disabled
via `chat_template_kwargs`, and an empty answer now raises instead of being
scored -- a model is never recorded as having failed a battery it was never
allowed to answer.

The same model that is refused as a judge is trustworthy as a writer, which is
the entire point of separating the roles. End to end, offline and keyless: the
deterministic rules found `c-stack-buffer-overflow` in fresh code, the model
explained it correctly, `verify_separation` confirmed the text never entered the
report digest.

`advisory41.py` enforces the boundary at three points -- a prompt that states
the defect as settled and asks only for explanation; a post-generation check
that discards the text and charges a violation if the model disputes the finding
anyway; and an envelope that carries advisories *beside* the report so
`verify_report` still recomputes the same digest over the same bytes.

One correction worth recording. The phrasing scorer first reported 0 of 3 and
would have withheld three correct explanations: it read "crashes or *incorrect*
results" as the model disputing the report, and demanded a literal line number
from a model that had named the offending call instead. The model was right and
the scorer was wrong. Nothing is charged against a model for a defect in the
thing judging it, so both were fixed before any verdict was recorded.

## What is explicitly not claimed

- No learned component improves detection recall in this design.
- Ranking order is a review convenience. A low rank is not evidence of safety,
  and the coverage-gap reporting is unchanged.
- Model identity digests detect modification. They are not publisher signatures
  and do not attest training data, licensing, or fitness.
