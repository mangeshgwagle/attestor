# Attestor 4.1.4 private escape lab

The private escape lab is a defensive, deterministic policy-reasoning
simulation for Cockroach Janta Party. Attestor starts at an `attestor-inside` node,
searches a compiled in-memory graph for a route to `simulated-outside`, and
reports the planted policy defect used by any route it finds.

This is **not** a real operating-system, process, browser, Python, VM, container,
or kernel escape attempt. The lab has no command, code, file, path, URL, payload,
plugin, process, network, target-execution, or deletion input. It neither grants
nor tests authority over the computer running Attestor.

## Run the lab

Run every compiled case:

```sh
python3 detector/superattestor.py --escape-lab --format text
python3 detector/superattestor.py --escape-lab --format json
```

Run one exact compiled case:

```sh
python3 detector/superattestor.py --escape-lab --escape-scenario stale-capability-recheck --format json
```

Selecting `--escape-lab` confirms only this data-only simulation. It is not an
authorization for a real escape, execution, network request, filesystem access,
or permission change. Variant selection is invalid because this is a sealed,
session-only CJP exercise rather than a general analysis profile.

## Compiled cases

| Scenario | Synthetic defect | Expected result |
|---|---|---|
| `stale-capability-recheck` | use-time state is not atomically rechecked | simulated escape |
| `path-alias-rebinding` | an alias is trusted after its identity changes | simulated escape |
| `helper-permission-inheritance` | a helper inherits a non-delegable capability | simulated escape |
| `broker-confused-deputy` | a broker authorizes itself instead of its requester | simulated escape |
| `proxy-boundary-misclassification` | a proxy mislabels a synthetic outside destination | simulated escape |
| `contained-reference` | the final boundary remains default-deny | contained |

Each simulated escape includes the deterministic abstract edge path, one
compiled reason, and one defensive mitigation. The intended-policy traversal
must remain contained; a malformed case or a path without a planted defect fails
closed.

## Integrity and replay

`escape_lab414.py` bounds graph size, traversal work, path length, and report
bytes. Equal inputs produce byte-identical JSON. Scenario, result, profile, and
report SHA-256 values identify the exact evidence, and `verify_report()` rebuilds
the complete result rather than trusting a caller-recomputed digest. SHA-256 is
an integrity identifier, not authorization or proof that a real product is
secure.

The report's controls apply to the escape-simulation core. A CLI/UI wrapper may
separately launch Attestor or save a caller-requested report; neither operation is an
escape action. Within the simulation core, the lab is pure in-memory and offline
and performs none of the following:

- host file reads or writes;
- deletion;
- process or shell launch;
- network access;
- target-code execution;
- real sandbox, container, VM, or kernel escape;
- persistence or permission changes.

## Deletion posture

The lab deletes nothing. Earlier builds carried a presentation-layer joke about
Cockroach Janta Party "accidentally" deleting an important file; that line and
the `cjp_satire` report block holding it have been removed. No factual claim was
lost with them: `controls.files_deleted` and `controls.host_files_written` state
the same thing directly, and the rendered report prints it in plain text.

This does not change Attestor's separate exact-file, two-phase local-control
authorization contract, which never granted deletion either.

## Scope of the result

A successful result proves only that Attestor traversed the compiled abstract graph
and identified its planted policy inconsistency. It does not demonstrate a real
escape, real exploitability, isolation strength, host security, or permission to
test another system.
