# Introduction email — Attestor

Draft for a first introduction to someone who has not encountered the project
before. Adapt the greeting and sign-off to how you actually write; the goal is
that a reader with a technical background but no prior context understands what
Attestor is, what it does, and why it exists, in one read.

**Before sending, please note:**

- Send it from your own account. It should come from you, in your voice.
- The honest-status paragraph is deliberate. Attestor has a large automated test
  suite, but it has not yet been measured against an external benchmark corpus,
  so the draft claims capability and design, never performance numbers.
- Ownership and licensing are worth settling before any company evaluates it.
  That is the first question a procurement or security team asks.

---

**Subject:** Introducing Attestor — an offline code security analysis tool

Hi [Name],

I wanted to introduce you properly to something I have been building, since I
have mentioned it in passing but never actually explained it.

**What it is**

Attestor is a code security analysis tool. You point it at a codebase and it
reports security and correctness defects — injection flaws, weak cryptography,
hardcoded credentials, unsafe deserialization, insecure configuration — across
Java, Python, C and C++, JavaScript and TypeScript, C#, Go, and Rust.

**What makes it different**

Two design decisions set it apart from a conventional scanner.

First, it never executes the code it analyses, and it makes no network
connections while analysing. Everything runs locally and deterministically. That
matters more than it sounds: it means Attestor is safe to point at sensitive
code, at proprietary code that cannot leave a network, and at code you already
suspect has been compromised.

Second, every finding is tied to a cryptographic hash of the exact source bytes
it came from, and each report can be independently re-verified afterwards. Most
tools hand you a report you have to trust. Attestor hands you evidence you can
check. Building on that, it can take a cryptographically signed "known-good"
snapshot of a codebase and later prove whether anything has been altered —
verified on a separate clean machine, so the proof does not depend on trusting
the machine under investigation.

**Why it exists**

Two gaps, from watching how security tooling actually gets used.

Scanners produce far more findings than anyone can review, with no reliable way
to tell which ones matter. Attestor grades each finding by whether an attacker
can actually reach the vulnerable code from an external entry point, so the
review queue starts with what is genuinely exposed rather than with whatever
happened to score highest. Importantly, when it cannot determine reachability it
says so, rather than quietly marking the finding low priority — an honest
"unknown" is more useful than a confident guess.

And when an organisation is compromised, the pressing questions are forensic:
what changed, what credentials were exposed, is this dependency affected. Those
need evidence that holds up under scrutiny, produced without trusting the
compromised system. That is the problem the signing and verification layer is
built for.

**Where it could fit in an organisation**

Pre-merge security review in a CI pipeline; software supply-chain and SBOM
inventory (it emits both CycloneDX and SPDX); and incident response, where the
tamper-evident baseline is the distinctive capability. It also has a Trusted
Access layer for controlling who may reach a given resource, built on explicit
authorization, verified identity, least-privilege scopes, revocation, and
tamper-evident audit logging.

**Honest current status**

It is a working tool with a substantial automated test suite, and I use it on
real code. It is also still a personal project. It has not yet been benchmarked
against an industry-standard vulnerability corpus, which is the next thing I
want to do, because until then I can describe what it does but not how it
compares. If it were ever to be evaluated somewhere formally, ownership and
licensing would need to be worked out first.

I am not asking for anything specific — mainly I wanted you to actually know
what it is. If it sounds relevant to anything you see day to day, I would
genuinely value your read on it, and I am happy to walk you or a colleague
through it in more detail.

Thanks for reading this far.

[Your name]

---

## Shorter variant

If the full version feels long for a first message, this keeps the essentials:

**Subject:** Introducing Attestor — an offline code security analysis tool

Hi [Name],

I wanted to explain properly what I have been building, since I have only
mentioned it in passing.

Attestor is a code security analysis tool. It reads source code and reports
security defects — injection flaws, weak cryptography, hardcoded credentials,
insecure configuration — across Java, Python, C/C++, JavaScript, C#, Go, and
Rust.

Two things make it unusual. It never runs the code it analyses and never goes
online, so it is safe to point at sensitive or already-compromised code. And
every finding is tied to a cryptographic hash of the exact source it came from,
so reports can be independently verified rather than simply trusted.

It also grades findings by whether an attacker could actually reach the
vulnerable code, which helps when a scan returns hundreds of results — and it
reports "unknown" honestly when it cannot tell, instead of guessing.

Status: it works, it has a large automated test suite, and I use it on real
code. It is still a personal project, has not yet been benchmarked against an
industry-standard corpus, and would need ownership and licensing settled before
any formal evaluation.

No specific ask — I mostly wanted you to know what it is. Happy to show you
properly if it sounds useful.

Thanks,
[Your name]
