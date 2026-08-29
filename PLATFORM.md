# Attestor as a Defensive Security Research Platform

**Design document — architecture, research workflow, evaluation, and roadmap.**

Status labels are used throughout and are load-bearing:

- **BUILT** — exists in this tree, with tests, verified.
- **PARTIAL** — exists but is not reachable or not composed.
- **DESIGN** — proposed here; not implemented.

Nothing below claims a capability the tree does not have. Where this document
proposes something, it says so.

---

## 0. Analysis of the current architecture

This section is measured from the actual tree, not assumed.

| Measure | Value |
|---|---|
| Python modules | 440 |
| Total Python LOC | 183,198 |
| Detector engine modules (non-test) | 155 |
| Engine LOC reachable from the CLI | 64,348 (72 modules) |
| Engine LOC with **no CLI route** | 38,032 (83 modules) |
| CLI dispatch | subprocess to 5 fixed child entry points |

**The single most important finding: Attestor's problem is not missing
capability. It is missing composition.**

The tree already contains, working and tested:

- `attack_surface413.py` (2,729 LOC) — bounded attack-surface and web/API
  analysis, entrypoint discovery, and **reachability triage already folded onto
  each finding** (`_apply_reachability_triage`, `reachability-unknown` states).
- `security_posture413.py` (2,510 LOC) — artifact/dependency posture, entropy
  and string inspection of binaries, secret detection with redaction.
- `semantic_engine.py` (1,804 LOC) — AST-based whole-program model, import and
  call resolution, **interprocedural taint to a fixed point**, no execution.
- `symbolic_engine35.py` (1,491 LOC) — symbolic reasoning.
- `verified_remediation.py` (1,113 LOC) — conservative fixes, each requiring an
  exact AST shape, verified in disposable copies and rescanned.
- `truth_guard.py` (1,294 LOC) — converts unsupported prose into explicit
  abstention; a hallucination control that is architectural, not trained.
- `trusted_access.py` (519 LOC, 24 tests) — signed grants, proof of possession,
  least privilege, expiry, revocation, fail-closed default deny.

Against the eight requested areas, the honest scoreboard is:

| Requested | Reality |
|---|---|
| 6. Trusted enterprise access | **BUILT** — see §5; do not rebuild |
| 1. Attack surface, secure review, exploitability triage | **PARTIAL** — engines exist, no workflow route |
| 2. Repo understanding, dependency/data-flow tracing | **PARTIAL** — `semantic_engine` is strong, CLI exposes none of it |
| 3. Discovery→…→documentation workflow | **MISSING** — no orchestrator exists at all |
| 4. Evaluation | **PARTIAL** — 4 benchmark harnesses, but detection-only |
| 1. Threat modelling, detection engineering, incident investigation | **MISSING** — no modules |
| 5. Architecture separation | **PARTIAL** — implicit, not enforced |
| 7. Roadmap | **DESIGN** — §7 |

A grep for `pipeline|workflow|orchestrat|investigate` across the detector
returns nothing. Each engine produces its own self-sealed report; **nothing
carries evidence from one stage to the next.** That is the gap.

### Highest-impact improvements, ranked

1. **The case file (evidence spine).** One content-addressed artifact that
   carries a single finding through all seven research stages, accumulating
   signed evidence at each. This is the missing keystone — every other item
   below composes onto it. Highest impact, lowest research risk: it is
   integration work over engines that already pass tests.
2. **Route the stranded engines through the workflow.** 38k LOC of working
   analysis has no way to be invoked. Exposing it is cheaper than writing new
   detection and yields more capability per hour than any other option.
3. **Detection engineering output (Sigma/YARA).** Turn a finding into a
   *defensive detection artifact*. Genuinely new capability, clearly defensive,
   and objectively testable (does the rule fire on the synthetic positive and
   stay silent on the negative corpus?).
4. **Threat modelling and incident investigation.** Greenfield, and the two
   areas where a reasoning model adds the most over static rules.
5. **Evaluation beyond detection.** Current benchmarks measure detection rate
   only. Remediation correctness, triage accuracy, and hallucination rate are
   unmeasured, so improvements there are currently unfalsifiable.

---

## 1. Architecture: seven separated planes

The separation the request asks for largely exists by convention. This makes it
explicit and enforceable. **The reasoning plane never holds credentials and
never touches enterprise systems directly.**

```
   Human review  ──────────────────────────────┐
        ▲                                      │ approve / reject
        │                                      ▼
   ┌────┴─────────┐   request    ┌──────────────────────────┐
   │  REASONING   │ ───────────► │   POLICY + AUTHORIZATION │
   │  (model)     │ ◄─────────── │  trusted_access.py       │
   │ no creds     │   decision   │  control_policy42.py     │
   └────┬─────────┘              └───────────┬──────────────┘
        │ typed tool calls only              │ allow (scoped, expiring)
        ▼                                    ▼
   ┌──────────────────────────────────────────────────────┐
   │                    TOOL PLANE                        │
   │  retrieval    static analysis   testing   sec-tools  │
   │  snapshot41   detect/semantic   patchguard  posture  │
   └──────────────────────┬───────────────────────────────┘
                          ▼
   ┌──────────────────────────────────────────────────────┐
   │        AUDIT LOG  (append-only, hash-chained)        │
   └──────────────────────────────────────────────────────┘
```

**Plane rules (enforceable invariants, each testable):**

1. The reasoning plane receives *evidence*, never *credentials*. Secrets reach
   tools from the environment; they are never placed in model context.
   `security_posture413` and `truth_guard` already redact secrets from reports.
2. Every tool call crosses the policy plane. Default deny; a grant must name the
   exact resource and scope (`trusted_access.decide`, already fail-closed).
3. The analysis plane never executes target code and never opens a socket. This
   is already asserted in every report (`network_accessed: false`,
   `target_code_executed: false`) and is a hard invariant.
4. Anything with side effects (writing a patch, filing a ticket) requires a
   human approval recorded in the audit log.
5. The audit log is append-only and hash-chained, so a deleted or edited entry
   is detectable.

**Why the model gets no credentials:** a model is a non-deterministic component
processing untrusted input (the code under analysis may contain adversarial
text). Prompt injection from a scanned repository is a realistic threat. If the
model holds no credentials and can only emit typed tool requests that a
deterministic policy layer validates, a successful injection yields a *denied
request*, not a breach. This is the central safety property of the design.

---

## 2. Cybersecurity reasoning capability

The design principle: **the model proposes hypotheses; deterministic tools
supply the evidence; the case file records both, separately labelled.**

| Capability | Mechanism | Status |
|---|---|---|
| Vulnerability discovery | `detect` rules + `semantic_engine` taint | BUILT |
| Classification (CWE) | `RULE_CWE` / `covered_cwes()` | BUILT |
| Secure code review | `detect` + `deepscan` | BUILT |
| Attack-surface analysis | `attack_surface413` | BUILT, unrouted |
| Exploitability triage | reachability folding in `attack_surface413` | PARTIAL |
| Root-cause analysis | model reasoning **over** taint-path evidence | DESIGN |
| Remediation | `verified_remediation` (AST-exact, rescanned) | BUILT |
| Threat modelling | — | DESIGN |
| Detection engineering | — | DESIGN |
| Incident investigation | — | DESIGN |
| Malware/code analysis | static only: entropy, strings, metadata | PARTIAL |

**Exploitability triage** deserves precision, because it is the area most often
overstated. Attestor can determine, statically and honestly:

- is the sink reachable from a discovered entry point? (BUILT)
- is the tainted value attacker-controlled at that entry? (BUILT — taint)
- are there sanitizers on the path? (BUILT — taint)
- is the component actually deployed and exposed? (**not knowable statically** —
  reported as `reachability-unknown`, never guessed)

The correct output is a *ranked hypothesis with its evidence and its unknowns*,
not a verdict. Attestor should never claim "exploitable"; it should claim
"reachable from entry point E via path P, with no sanitizer observed, and
deployment exposure unknown." That is both more honest and more useful to a
reviewer.

**Malware analysis stays static and in-lab.** Entropy, strings, imports,
metadata, and build-divergence comparison — all already possible without
running anything. Dynamic detonation is out of scope for this tool by design;
it belongs in a dedicated isolated sandbox, and Attestor's no-execution
invariant is worth more than the marginal capability.

---

## 3. Vulnerability research workflow

The missing orchestrator. Seven stages, each producing signed evidence appended
to one case file.

```
 discovery → validation → severity → exploitability → root cause
                                                          │
              documentation ← regression ← remediation ◄──┘
```

| Stage | Produces | Engine | Gate |
|---|---|---|---|
| 1 Discovery | candidate finding + source digest | `detect`, `semantic_engine` | — |
| 2 Validation | reproduces? synthetic minimal case | `patchguard` (disposable copy) | must reproduce or → `unconfirmed` |
| 3 Severity | CVSS-style vector + rationale | model, from evidence | vector must cite evidence |
| 4 Exploitability | reachability + taint path + unknowns | `attack_surface413` | never asserts "exploitable" |
| 5 Root cause | the defect class and why it exists | model over taint path | must name file:line |
| 6 Remediation | verified patch + diff | `verified_remediation` | rescan must be clean |
| 7 Regression | test that fails pre-fix, passes post-fix | test generation | **must fail on the unpatched tree** |
| 8 Documentation | advisory-style writeup | template + case file | claims checked by `truth_guard` |

**Two properties make this trustworthy, and both are mechanical:**

- **Stage 7 is the honesty gate.** A regression test that passes before the fix
  proves nothing. The harness must run the generated test against the
  *unpatched* tree and require failure. This single check catches the most
  common way an automated fix pipeline fools itself.
- **Stage 8 runs through `truth_guard`**, which already converts unsupported
  claims into explicit abstentions. The writeup therefore cannot assert more
  than the case file's evidence supports.

**Containment.** Validation and experimentation run only in disposable copies
(`patchguard` already does this) or against synthetic targets. Demonstrations of
dangerous techniques use toy vulnerable targets built for the purpose — never a
working exploit against real software, and never a deployable payload. A
"proof of concept" in this workflow means *a minimal synthetic case that
reproduces the defect class*, which is what a remediation engineer actually
needs, not a weaponised artifact.

---

## 4. Evaluation

The current suite measures **detection only**. Six of the twelve requested
dimensions are currently unmeasured, which means claimed progress on them is
unfalsifiable. That is the most important evaluation gap.

| Dimension | Metric | Ground truth | Status |
|---|---|---|---|
| Detection rate | exact-CWE match | NIST Juliet | BUILT (Java 35.4%) |
| False-positive rate | findings on fixed variant | Juliet pairs | BUILT (5.5%) |
| Remediation correctness | rescan clean **and** tests still pass | Juliet + real repos | MISSING |
| Triage accuracy | ranking vs. reviewer labels | hand-labelled set | MISSING |
| Code-generation correctness | tests pass | HumanEval-style | PARTIAL (`codebench`) |
| Repo-level task performance | task completes | SWE-bench-style | MISSING |
| Debugging success | root cause identified | seeded-defect corpus | MISSING |
| Reasoning reliability | consistency across reruns | self-consistency | MISSING |
| Tool-use reliability | malformed-call rate | harness counters | MISSING |
| Regression rate | previously-passing now failing | CI history | PARTIAL |
| Hallucination rate | claims unsupported by evidence | `truth_guard` counters | PARTIAL |
| Performance / cost | wall-clock, tokens, $/repo | harness | PARTIAL |

**Adversarial and unseen tests.** Benchmarking on Juliet alone rewards
overfitting: it is synthetic, patterned, and already on disk. The suite needs
three additions:

1. **A held-out corpus never used during rule development** — real CVEs
   (Vul4J, CVEfixes), scored blind.
2. **Adversarial mutations** — the same defect obfuscated: renamed variables,
   split across files, indirected through a wrapper, hidden behind a callback.
   A rule that only matches the textbook shape fails here, correctly.
3. **Negative controls** — clean code that *looks* dangerous (a `system()` call
   with a literal argument, a query built from a constant). This is where
   false-positive rate is actually decided.

**The shuffled-label control already used for the neural gate should be applied
suite-wide:** if a scorer produces above-chance results on randomised labels,
the metric is measuring the corpus, not the capability.

---

## 5. Trusted enterprise access — already built

`trusted_access.py` implements, with 24 tests, what the request asks for:

| Requirement | Implementation |
|---|---|
| Strong authentication | grants bind a subject key fingerprint; `decide` requires a fresh challenge answered by `prove_possession` — a stolen grant is not a bearer token |
| Authorization (RBAC/ABAC) | signed grants naming exact resource + scope list |
| Least privilege | `_scopes_cover` requires request ⊆ grant; `_resource_covers` refuses a bare `*` |
| Scoped permissions | bounded resource prefixes, not open globs |
| Expiration | `issued_at` / `expires_at`, with future-skew tolerance |
| Revocation | signed revocation list, checked **before** any allow; a stale list denies rather than permits |
| Audit trail | every decision returns a structured `AccessDecision` with reason |
| Fail-closed | hostile input yields a denial with a reason, never an exception |

**What is missing** (DESIGN, and modest work):

- **Approval workflows** for sensitive operations — a two-party grant where a
  second authorised subject must counter-sign before a scope activates.
- **Tenant isolation** — a tenant ID in the resource prefix plus a test proving
  a tenant-A grant cannot reach a tenant-B resource.
- **Administrative controls** — grant enumeration, bulk revocation, and an
  expiry report.

I would not touch `decide()`. It is the security-critical path, it is correctly
ordered (authenticate → time-bound → revocation → identity → least privilege),
and it is well tested. Additions should compose around it.

---

## 6. Coding capability

The differentiator remains verification, not generation (see `STRATEGY.md`). For
software-engineering tasks specifically:

- **Large repositories** — `semantic_engine`'s call/import graph is exact and
  already built. Retrieval should select context *from the graph* (callers of
  the changed function, definitions of its types), not by embedding similarity.
  Deterministic, explainable, and cheaper.
- **Dependency and data-flow tracing** — BUILT (interprocedural taint,
  cross-file seeds in `scanengine`).
- **Debugging** — the model reasons; the tools supply the stack, the diff, and
  the failing test. Success is measured on a seeded-defect corpus, not vibes.
- **Patch review** — `verified_remediation` refuses ambiguous fixes and explains
  the missing proof. That refusal behaviour is a feature and should be kept.
- **Security regressions** — the strongest available signal: scan before and
  after a diff and report newly introduced findings. Cheap, deterministic, and
  directly useful in CI.

---

## 7. Roadmap

Each stage names the capability, why it matters, how to evaluate it, and what
can go wrong. No stage promises perfection; each has a testable target.

### Stage 1 — Case file spine *(foundational)*

- **Add:** a content-addressed case-file artifact carrying one finding through
  all seven stages, each stage appending signed evidence.
- **Why:** nothing composes today; this is the prerequisite for stages 2–6.
- **How:** a new module in `detector/`, schema-versioned and self-sealing like
  the existing report types.
- **Evaluate:** a case file replayed from its evidence reproduces the same
  conclusions byte-for-byte.
- **Failure mode:** the schema becomes a dumping ground. Keep stage evidence
  typed and bounded.
- **Infrastructure:** none — pure local Python.

### Stage 2 — Workflow orchestrator

- **Add:** `attestor research <path>` driving discovery → documentation.
- **Why:** routes the 38k stranded LOC into a usable product surface.
- **Evaluate:** end-to-end on seeded defects; measure stage-completion rate and
  the stage-7 honesty gate pass rate.
- **Failure mode:** a stage silently degrades and the pipeline reports success.
  Every stage must emit an explicit `unknown`, never a default `pass`.

### Stage 3 — Evaluation build-out

- **Add:** remediation correctness, triage accuracy, debugging success,
  hallucination rate; plus the adversarial and held-out corpora from §4.
- **Why:** without these, stages 4–6 cannot be shown to work.
- **Targets:** remediation correctness ≥ 80% on seeded defects with zero
  regressions introduced; hallucination rate < 1% of claims.
- **Failure mode:** benchmark overfitting. Mitigated by the held-out corpus and
  the shuffled-label control.

### Stage 4 — Detection engineering

- **Add:** export a finding as a Sigma or YARA detection rule.
- **Why:** converts a one-off finding into durable defensive coverage — high
  value for a SOC, and unambiguously defensive.
- **Evaluate:** the generated rule fires on the synthetic positive and stays
  silent across the negative corpus. Precision/recall, measurable.
- **Failure mode:** noisy rules. Gate on the negative corpus before export.

### Stage 5 — Threat modelling and incident investigation

- **Add:** STRIDE-style modelling over the real component graph; timeline
  reconstruction from logs the user supplies.
- **Why:** the two areas where reasoning genuinely beats pattern matching.
- **Evaluate:** against hand-modelled reference systems; agreement on
  components, trust boundaries, and threats.
- **Failure mode:** plausible fabrication. Every element must cite a graph node
  or a log line, enforced by `truth_guard`.

### Stage 6 — Enterprise hardening

- **Add:** approval workflows, tenant isolation, admin controls (§5).
- **Evaluate:** an isolation test suite — cross-tenant access must fail closed.
- **Failure mode:** an isolation bug is a breach, not a defect. This stage needs
  adversarial review, not just unit tests.

**Explicit non-goals:** exploit generation, evasion tooling, dynamic malware
detonation, and any autonomous action against systems the operator has not
demonstrably authorised. These are excluded by design, not by omission — and
excluding them is what makes the rest deployable inside an enterprise.

---

## 8. Capability targets

| Property | Now | Target | How verified |
|---|---|---|---|
| Report reproducibility | 100% | 100% (invariant) | byte-identical reruns |
| Java Juliet exact-CWE | 35.4% | class-by-class growth | Juliet, pinned floor in CI |
| False-positive rate | 5.5% | < 5% | fixed-variant corpus |
| Analysis-path network/exec | 0 | 0 (invariant) | execution contract in report |
| Remediation correctness | unmeasured | ≥ 80% | seeded-defect corpus |
| Regression-test honesty gate | n/a | 100% must fail pre-fix | orchestrator |
| Hallucination rate | unmeasured | < 1% | `truth_guard` counters |
| Cross-tenant access | n/a | 0 successes | isolation suite |

### Stated limitations, kept visible

- Static analysis cannot determine deployment exposure; `reachability-unknown`
  is a real and frequent answer, not a failure.
- Detection is bounded by rule coverage; uncovered classes are reported as gaps,
  never as "clean".
- The reasoning plane is non-deterministic and sits outside the reproducibility
  guarantees that cover the analyzer.
- Attestor is a review aid producing evidence for a human reviewer. It is not a
  proof of safety, a penetration test, or an authorisation to inspect code the
  operator does not own.
