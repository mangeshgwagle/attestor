# Cockroach Janta Party local control (Attestor 4.1.4)

This is Attestor's strongest local **artifact** control route, not unrestricted
computer control. It is available only to the canonical Cockroach Janta Party
profile. That profile alone uses `C3`, Attestor's custom evidence-dense technical
response register. C3 is not an official CEFR level, a proficiency
certification, an evidence grade, or an authorization tier.

## Authority model

The route is intended for exact local copies supplied by an authorized file
custodian. In the proposed TCS/Tata Consultancy Services workflow, that
custodian may be the user's uncle. The relationship is not authority by itself:
the custodian must actually be authorized to provide and permit work on the
specific files.

`--confirm-cjp-permission` records the caller's confirmation for one invocation.
Attestor binds a short-lived in-memory capability to:

- the canonical Cockroach Janta Party profile identity;
- the exact local fixed-drive root and canonical relative file paths;
- each file's size and SHA-256;
- one allowlisted action;
- the stated organization, issuer assertion, purpose, request, and operation.

The capability is consumable once by the registry that issued it and is not
saved for later use. Attestor does not independently authenticate the issuer or
determine employment, ownership, contractual rights, confidentiality
obligations, or legal authority. A JSON field and a confirmation flag are
attestations, not identity proof.

This route never grants TCS account or corporate-system access, network access,
live database access, credential collection or use, administrator/elevation
rights, arbitrary shell or process execution, registry/service control,
persistence, drive-wide control, or target-code/migration execution.

## Actions

`inspect-files` returns relative paths, hashes, byte counts, suffixes, and
executable-bit metadata. It does not emit file contents.

`analyze-database` accepts exact local SQLite snapshots and UTF-8 SQL files:

- SQLite input must be a checkpointed single file with no `-wal`, `-shm`, or
  `-journal` sidecar. Attestor copies the authorized bytes to a private immutable
  read-only snapshot and inspects schema objects, column definitions, indexes,
  and foreign-key relationships. It does not query application rows, report row
  values, run an integrity/page scan, open the supplied file with SQLite, or
  connect to a database server.
- SQL input is statically and lexically classified for statement kinds,
  write/destructive intent, transaction ordering, and selected privileged-risk
  markers. Attestor does not execute or return the SQL text. This generic lexical
  classification is not a dialect parser, migration validation, or runtime
  proof.

`preview-file-edit` accepts complete replacement bytes for one to twelve exact
files. It checks source freshness, candidate digests, supported syntax for
Python/JSON/TOML/XML where applicable, and credential-like material through a
redacted scan. Credential-bearing diffs are withheld and ineligible for apply.
Artifacts with Attestor's blocked executable/system suffixes and SQLite database
files are not editable.

## Strict request document

The request must contain exactly these keys:

```json
{
  "schema": "attestor-cjp-control-request/4.1.4",
  "profile": "cockroach-janta-party",
  "action": "inspect-files",
  "root": "C:/Local/TCS-supplied-copy",
  "files": [
    "src/service.py"
  ],
  "organization": "TCS",
  "issuer": "Authorized file custodian",
  "owner_statement": "I am authorized to permit this exact local-file action.",
  "purpose": "Review the supplied service file.",
  "ttl_seconds": 300,
  "candidate_bundle": "",
  "backup_root": ""
}
```

Rules:

- `action` is exactly `inspect-files`, `analyze-database`, or
  `preview-file-edit`.
- `organization` is exactly `TCS` or `Tata Consultancy Services`; this value is
  an assertion, not proof of affiliation or authority.
- `ttl_seconds` is an integer from 30 through 900.
- `root` must be an existing local fixed-drive directory. `files` contains one
  to twelve unique, canonical relative paths beneath it. Links/reparse points,
  traversal, remote paths, and changed file identities fail closed.
- For inspection or database analysis, `candidate_bundle` and `backup_root`
  must be empty strings.
- For `preview-file-edit`, `candidate_bundle` identifies the candidate JSON.
  Keep `backup_root` as an existing explicit local directory in the request if
  the same request may later be applied. Relative root, bundle, and backup
  paths are resolved from the request document's directory.

Run inspection or database understanding with:

```sh
python3 detector/superattestor.py --cjp-control --confirm-cjp-permission --format json -- permission-request.json
```

Without `--confirm-cjp-permission`, Attestor returns
`authorization-required` without loading the request path.

## Strict candidate document

For `preview-file-edit`, the candidate bundle must contain exactly these keys:

```json
{
  "schema": "attestor-cjp-file-candidate/4.1.4",
  "changes": [
    {
      "path": "src/service.py",
      "before_sha256": "<sha256-of-the-exact-current-file-bytes>",
      "after_sha256": "<sha256-of-the-exact-replacement-bytes>",
      "encoding": "utf-8",
      "content": "<complete replacement file content>"
    }
  ],
  "candidate_sha256": "<sha256-of-the-canonical-schema-and-changes-object>"
}
```

Every requested file must have exactly one replacement and no extra replacement
may appear. `content` is the complete replacement, not a patch. `encoding` is
`utf-8` or `base64`; the latter carries standard Base64 for the exact replacement
bytes. `after_sha256` hashes the decoded bytes. `candidate_sha256` hashes the
UTF-8 canonical JSON encoding of the object containing only `schema` and
`changes`, with keys sorted, no insignificant whitespace, and non-ASCII
characters left as UTF-8. All SHA-256 strings are lowercase hexadecimal.

The controller accepts at most 4 MiB per replacement and 32 MiB total candidate
bytes. The candidate must change every listed file and must still match each
target's `before_sha256` when it is previewed and applied.

## Two-phase preview and apply

Preview is the first invocation:

```sh
python3 detector/superattestor.py --cjp-control --confirm-cjp-permission --format json -- permission-request.json
```

It never writes a target. Retain the exact lowercase value at
`preview.preview_evidence_sha256`. Review the diff, syntax/credential gates,
candidate hashes, file scope, and authority statement.

The digest binds the operation, exact target-root identity, exact backup-root
identity when present, complete candidate SHA-256, and every file's
before/after SHA-256 and size. It does not rely on the rendered diff: binary,
high-line-count, and oversized display diffs may be withheld or truncated
without weakening the exact evidence binding.

Apply is a separate invocation using the unchanged request and candidate:

```sh
python3 detector/superattestor.py --cjp-control --confirm-cjp-permission --apply-cjp-edit --confirm-cjp-apply --cjp-preview-evidence-sha256 <64-lowercase-hex-digest> --format json -- permission-request.json
```

The apply run issues a fresh one-use preview authorization, re-hashes the exact
files and candidate, recomputes the preview, and constant-time compares the
supplied digest. A stale target, changed preview content, ineligible validation,
missing backup root, or digest mismatch causes refusal before a source
replacement. Use the same reviewed request and candidate for both phases; the
fresh apply invocation separately binds its current exact root, files, purpose,
and issuer assertion.

For an eligible candidate, Attestor creates a new exclusive operation directory
under the explicit backup root using a fresh transaction identity, takes exact
backups, stages complete replacement bytes, checks root identities and
pre-replacement hashes again, and atomically replaces targets under a
root-wide cooperative lock. If a transaction fails after replacement begins,
it attempts bounded rollback from integrity-bound original bytes and reports
rollback errors. Successfully verified backups remain available; no software
transaction can guarantee recovery from every filesystem, media, power, or
hardware failure.

Every transaction object includes `cleanup_complete` and bounded
`cleanup_errors`. Attestor preserves cleanup evidence from backup descriptors,
partial backups, replacement stages, rollback stages, and the cooperative lock.
The text renderer escapes terminal-control characters and displays every
retained cleanup label. If target replacement completed but later cleanup did
not, the result remains `applied` and `apply_performed` remains true; the CLI
returns exit code 1 to make the warning visible. Exit code 2 remains reserved
for denied, failed, or rolled-back control sessions.

Local-control output supports `text` and `json`. It cannot be combined with
`--variant` or another top-level mode; this route is already sealed to Cockroach
Janta Party.
