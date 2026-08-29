# Running Attestor under Terminal-Bench

## Read this before you read a score

Terminal-Bench measures whether an **agent** can finish a terminal task: plan,
run commands, read output, iterate, and leave the container in a state that
passes a test.

Attestor is not an agent. He reads source and reports defects. He does not plan, he
does not iterate, and by the placement rules in `MODEL_INTEGRATION_4.1.4.md`
no learned component of his is permitted to decide anything.

**So this adapter will score near zero on the suite, and that number is not a
verdict on Attestor.** A chess rating is not a verdict on a spell-checker.

Two things it *is* good for:

1. **A floor** — how many tasks a static analyser plus verified autofix closes
   with no reasoning at all.
2. **A baseline for the comparison actually worth running** — the same LLM
   agent, once with Attestor exposed as a tool and once without. That delta is
   Attestor's real contribution and the only number here worth quoting.

## Requirements

| | |
|---|---|
| Python | **≥ 3.12** |
| terminal-bench | `pip install terminal-bench` (in a venv: Debian/Ubuntu mark the system Python `EXTERNALLY-MANAGED`) |
| Docker | daemon **running**, and reachable from wherever `tb` runs |

Install `tb` on the same side of the machine as the daemon it should use. On a
Windows host with WSL that is usually inside the distro — `tb` installed on the
Windows side will reach for Docker Desktop, which may not be the daemon you
intend it to use.

## Modes

| mode | what it does | changes files? |
|---|---|---|
| `scan` (default) | runs `detect.py --deep --json` over the task directory, leaves `/tmp/attestor-findings.json` | no |
| `repair` | scan, then `verified_remediation.py --apply`, which rewrites only what it can re-verify and keeps a backup | yes |

`repair` is deliberately **not** the default. A security tool that edits a
repository it was only asked to inspect is the wrong default.

## Running it

```bash
tb run --agent-import-path attestor_agent:AttestorAgent \
       --agent-kwarg attestor_path=/path/to/Attestor-4.1.4 \
       --agent-kwarg mode=repair \
       --task-id hello-world
```

Run from this directory so `attestor_agent` is importable, or add it to
`PYTHONPATH`. `attestor_path` may also be supplied as the `ATTESTOR_PATH` environment
variable.

Other kwargs: `target` (default `/app`), `severity` (default `LOW`),
`scan_timeout_sec` (default 600).

## What the adapter does inside the container

1. Copies `detector/` and a generated `attestor_run.sh` to `/attestor` — Attestor imports
   no third-party package, so any CPython with a standard library runs him,
   and the image needs no setup.
2. Runs `sh /attestor/attestor_run.sh` — **one** short command. The script picks the
   interpreter, scans to `/tmp/attestor-findings.json`, writes the report, applies
   verified remediations in `repair` mode, and echoes its own diagnostics.
3. Returns timestamped markers for each stage.

Failures are returned as `FailureMode.UNKNOWN_AGENT_ERROR` rather than raised,
so one broken task never voids a run.

### Why a script and not a sequence of commands

Every failure this adapter had was a delivery failure. Commands reach the
container by being *typed into a tmux session*, so a `python -c` with newlines
split into fragments, a long one-liner broke on wrapping and quoting, and
splitting the scan from the report raced — the harness decides when the
previous command finished, and on a deep scan it decided too early.

The one that actually cost the benchmark was subtler. **`detect.py` exits 2
when it finds something** and 0 when the tree is clean. Scan and report were
joined by `&&`, so every run in which Attestor found a defect short-circuited
before the report was written; the only way to reach the report step was to
find nothing, which fails the task too. A trailing `|| true` hid the status.

The script has none of those failure modes: it is written here, copied in, and
started by one line with nothing to quote and nothing to race.

## The comparison worth running

Attestor alone is the floor. To measure whether he *helps*, run an LLM agent twice
over the defect-related task subset — once with Attestor available as a tool, once
without — and compare. Everything needed for that is here; only the driving
agent differs.
