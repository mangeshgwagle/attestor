# Attestor 4.2 Owner Control MVP

Owner Control 4.2 is a permission-first, local, read-only computer-inspection
subsystem for the canonical **Cockroach Janta Party** profile. It is not an
autonomous “take over the PC” feature. It provides bounded observations and an
inert format for reviewing possible future changes. Attestor 4.2 contains **no
mutation executor**.

Every report states `mutation_executed: false`. No Owner Control action grants
authority to run commands, start processes, access the network or credential
stores, create persistence, elevate privilege, disable security controls, or
modify files, services, settings, or accounts.

## Authoritative entry point and launchers

From the Attestor 4.2 directory, the supported wrappers are:

```powershell
.\Run_Owner_Control_4.2.bat --help
```

```sh
./Run_Owner_Control_4.2.sh --help
```

They change only to the release directory and invoke the authoritative
standalone CLI in isolated mode. They forward the operator's arguments exactly
and never add `--permission` automatically. The direct entry point is:

```powershell
python -I -B -X utf8 detector/owner_control42.py --help
```

`-I` starts Python in isolated mode; `-B` keeps bytecode caches out of the
audited release tree. The entry point resolves and seeds only its own
`detector` directory, so a module planted in the caller's working directory
cannot replace an Owner Control module.

Owner Control is not wired into `superattestor.py` or the desktop/web UI in this
MVP. Integrators should call a supplied launcher, the CLI, or the documented
Python coordinator, `detector/owner_control42.py`, and must preserve the
permission and digest confirmation flow.

## Permission flow

The CLI has three exact subcommands. Abbreviated subcommands/actions and
duplicate options are rejected.

```text
policy
plan {system-inventory,find-files,computer-project-scan,plan-future-mutations}
run PLAN_FILE
```

1. `policy` prints the compiled policy and its SHA-256 identity.
2. `plan` validates an exact JSON request and creates a non-probing plan bound
   to the session, CJP profile identity, policy, action, and request.
3. The operator reviews the plan and its `plan_sha256`.
4. `run` denies by default. It will not open the named plan file or probe the
   computer unless both `--permission` and the exact reviewed
   `--confirm-plan-sha256` are supplied.
5. An authorized invocation creates and consumes a one-use, short-lived,
   in-memory capability before the observation begins.

Example using a 32-character lowercase hexadecimal session ID:

```powershell
python -I -B -X utf8 detector/owner_control42.py policy --format json

python -I -B -X utf8 detector/owner_control42.py plan system-inventory `
  --session-id 0123456789abcdef0123456789abcdef `
  --request-json '{"storage_roots":[]}' `
  --format json

# Denied by default; the missing file is deliberately not opened.
python -I -B -X utf8 detector/owner_control42.py run missing-plan.json --format json

# After saving and reviewing the generated UTF-8 JSON plan:
python -I -B -X utf8 detector/owner_control42.py run .\owner-plan.json `
  --permission `
  --confirm-plan-sha256 <the-exact-64-character-plan-sha256> `
  --format json
```

The CLI writes plans and reports to standard output. If PowerShell is used to
save a plan, save it as UTF-8 **without a byte-order mark**. Do not edit the
plan after recording its digest; any change invalidates the digest.

Exit status `0` means success, `1` means the authorized observation returned
partial or inconsistent coverage, and `2` means permission was not supplied
or the request failed closed.

### Capability contract

The live capability is authenticated with a fresh ephemeral HMAC key and is
bound to all of the following:

- live registry identity;
- 32-character session ID;
- exact compiled CJP profile identity;
- exact compiled policy digest;
- exact plan digest;
- exact action and authorization kind;
- issue and expiry times; and
- a unique nonce and one-use state.

The lifetime is 1–300 seconds (180 seconds by default). A capability cannot be
reused, copied to another live registry, moved to another session or plan, or
used after expiry. Concurrent consumption permits at most one winner.
Permission and capabilities are not persisted.

This is application-level containment, not operating-system identity proof.
`--permission` is an explicit per-run owner attestation; any process already
able to invoke Attestor as the same OS user could supply that flag. A future
privileged product would need a separately authenticated OS broker and a fresh
human confirmation UI. Copied JSON audit evidence proves its own digest, but
only the original live registry can establish that a capability was issued and
unused.

## Allowed actions and exact requests

Unknown fields are rejected. JSON is bounded to 4 MiB, 16,384 nodes, and depth
32. Paths must be absolute local paths. UNC/network, removable, traversal,
linked/reparse, protected, and unsafe roots fail closed or are reported as
coverage gaps, depending on the action.

### `system-inventory`

Request:

```json
{"storage_roots": []}
```

`storage_roots` may contain zero to eight explicitly selected local fixed-drive
directories. The action returns bounded OS family/version, process architecture
width, logical CPU count, physical-memory size when available, and storage
capacity for accepted roots. It does not emit the hostname, username, network
identifiers, or root paths. Root identities are represented by SHA-256 values.

### `find-files`

Request:

```json
{
  "extensions": [".py", ".txt"],
  "hash_files": false,
  "max_depth": 4,
  "max_directories": 1000,
  "max_files": 10000,
  "max_results": 100,
  "name_contains": "",
  "roots": ["C:\\Users\\owner\\Documents\\approved-project"]
}
```

The action returns relative paths, byte sizes, modification times, suffixes,
and optionally SHA-256 digests. It never emits file contents or absolute root
paths. `extensions` must be sorted, unique, lowercase, and may be empty. The
hard limits are eight roots, depth 16, 20,000 directories, 200,000 files, and
1,000 returned rows. Each directory is capped at 10,000 examined entries.

Optional hashing reads only eligible single-link regular files. It is capped at
16 MiB per file and 128 MiB total, verifies file identity before and after the
read, and returns only the digest. SHA-256 here is an integrity fingerprint,
not a malware verdict or proof that a file is safe.

### `computer-project-scan`

Request:

```json
{
  "max_projects": 4,
  "review_improvements": true,
  "scope": "home"
}
```

`scope` is exactly `home` or `fixed-drives`; `max_projects` is 1–12. This wraps
Attestor's established 4.1 permissioned static project scanner and rejects a report
that claims target-code execution, network access, target-file writes,
improvement application, privilege elevation, or access-control bypass.

Unlike `system-inventory` and the root identity section of `find-files`, the
established project-scan report can contain local project and finding paths.
Treat its output as local/session-sensitive. Static analysis can read selected
project source; it does not import or execute target code, run tests or compiler
hooks, or apply suggested improvements.

### `plan-future-mutations`

Request:

```json
{
  "executor": "unavailable",
  "operations": [
    {
      "after_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "before_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "estimated_bytes": 12,
      "kind": "replace-existing-files",
      "operation_id": "replace-one",
      "root_identity_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "target_identity_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ]
}
```

This action accepts 1–12 review records, with a total estimated size no greater
than 32 MiB. The only recognized future kinds are:

- `create-directory`
- `quarantine-files`
- `replace-existing-files`
- `restore-quarantined-files`

These names do not create authority. The action does not probe the computer and
cannot dispatch through the observation layer. Its result is always
`planned-only`, `executor: unavailable`, `mutation_authorized: false`, and
`mutation_executed: false`.

## Filesystem and information boundaries

Owner Control refuses or skips sensitive and structurally unsafe locations.
The compiled denylist includes OS directories, browser and mail profiles,
application-data locations, cloud/CLI credentials, SSH/GPG/Kubernetes areas,
Codex/OpenAI configuration, and common secret, key, certificate, token, wallet,
and credential filenames. The policy is intentionally conservative and can
produce omissions.

Directory symlinks, Windows reparse points, cross-filesystem entries, and
multi-link files are not followed or hashed. Files that change during hashing
fail closed. Traversal limits, unreadable entries, unsafe roots, hash limits,
and exclusions are represented as explicit coverage gaps or counters.

The denylist is defense in depth, not a complete secret-classification system.
An innocently named file can still contain confidential data. Use narrowly
scoped roots, keep `hash_files` disabled unless needed, review outputs locally,
and do not upload reports without checking them.

## Audit and integrity

Plans, policy documents, capability-consumption evidence, and final reports use
deterministic SHA-256 identities. The coordinator verifies the exact plan before
issuing a capability and verifies the report it builds. Each final report binds
the profile, policy, plan, action, authorization evidence, result, coverage,
side-effect assertions, and authority boundaries.

These digests detect accidental or unauthorized modification of a retained
artifact when the expected digest is trusted. Plain SHA-256 report/plan digests
are not digital signatures and do not establish who created an offline JSON
file. The capability HMAC remains only in the ephemeral live registry.

There is no rollback subsystem in 4.2 because there is no mutation executor and
nothing in Owner Control can change. Future mutation work must add a separate,
authenticated, least-privilege executor, precondition checks, backup/quarantine
journaling, atomic rollback, and new tests; the 4.2 plan format alone must never
be treated as permission.

## Known limitations

- CJP is the only supported Owner Control profile in this MVP.
- There is no durable permission, background agent, service, elevation broker,
  remote control, shell, process launcher, network client, or mutation API.
- The supplied `.bat` and `.sh` launchers expose the standalone CLI, but Owner
  Control is not yet connected to Attestor's main UI or `superattestor.py` command
  routing.
- Inventory completeness depends on OS APIs, permissions, filesystem behavior,
  configured limits, and the conservative exclusions. Check `coverage` and
  `status`; do not interpret a clean or complete-looking subset as proof that
  the entire computer is safe.
- Project scanning inherits the established static scanner's discovery limits
  and local-path output.
- Time expiry uses the process clock; the implementation fails closed on
  detected rollback but does not use trusted hardware time.

## Verification

The focused regression suite is:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -B -X utf8 -m unittest discover `
  -s detector -p 'test_*control*42.py' -v
```

It covers strict schemas and bounds, policy/plan tampering, protected and
sensitive exclusions, metadata-only search, optional hashing, one-use and
expiring capabilities, concurrent consumption, wrong-session/cross-registry
denial, side-effect report rejection, inert future plans, denial before plan
access or probing, and isolated CLI behavior.
