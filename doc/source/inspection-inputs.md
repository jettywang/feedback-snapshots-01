# Inspection Inputs

Inspections are commands that `in-toto-verify` executes on the verifier's
machine. Their results are only meaningful if the files they read are the ones
that the authenticated part of the supply chain produced. Artifact rules alone
do not establish that: a `MATCH` rule compares hashes between Link files, but
the inspection process reads the local filesystem. A replaced file with the
same name can pass every Link-to-Link rule and still be consumed by the
inspection.

Inspection inputs make that link explicit. They declare which local files the
inspection is allowed to treat as authenticated inputs, and they bind each one
to a step Link that already passed signature and threshold verification.

## Declaring inputs

Every inspection accepts an optional `inputs` list. Each entry can be a
compact string:

```
[<step>:]<path>[@<materials|products>]
```

or a dictionary with explicit fields:

```json
{
  "name": "build/foo.tar.gz",
  "from_step": "package",
  "from_type": "products",
  "link_path": "dist/foo.tar.gz",
  "record_method": "file"
}
```

| Field | Meaning |
| --- | --- |
| `name` | Path the inspection reads, relative to the verification directory, with POSIX separators. Absolute paths, `..`, `.` segments, repeated slashes, trailing slashes and backslashes are rejected. |
| `from_step` | Name of the step whose authenticated Link supplies the evidence. Required. |
| `from_type` | `products` (default) or `materials`. |
| `link_path` | Artifact name exactly as reported by the Link. Defaults to `name`. Use it when the producer and consumer use different path prefixes, analogous to `MATCH ... IN ...`. |
| `record_method` | How the Link must have recorded the artifact. Only `file` is supported. Link artifact names with a `dir:` or `ostree:` prefix are rejected. |

Example layout fragment:

```json
"inspect": [
  {
    "name": "untar",
    "run": ["tar", "xfz", "foo.tar.gz"],
    "inputs": ["package:foo.tar.gz"],
    "expected_materials": [
      ["MATCH", "foo.tar.gz", "WITH", "PRODUCTS", "FROM", "package"]
    ]
  }
]
```

## What is checked before execution

For each declared input, verification fails before the inspection command is
started if any of the following is true:

- The source step has no Link that passed signature and threshold verification.
- The Link does not report the exact `link_path` in the declared artifact type.
  No implicit path normalization is performed.
- The Link artifact was not recorded as a regular file.
- The file is missing, is a symlink, or is not a regular file.
- Any digest reported by the Link does not match the bytes on disk.
- The file's stat metadata changes while it is being hashed.
- The declared inputs are re-hashed immediately before process start, and that
  recheck fails. The recheck also rejects a file whose inode, size or mtime
  changed between the two checks, even when the content still matches.

When the bindings succeed, the inspection's Link records the authenticated Link
digests as materials. Files that were not declared are not treated as
authenticated inputs just because they are in the working directory.

## What the binding does not guarantee

The binding is a preflight check, not a sandbox:

- It does not restrict which files the inspection process may open. An
  inspection program can still read undeclared files or the environment.
- It does not prove what the inspection actually read while it ran.
- It does not verify Link signatures itself. `in-toto-verify` passes only Links
  that already passed signature and threshold verification, but direct API
  callers must uphold that contract.
- It does not cover concurrency. Hashing and process execution are separate
  operations, and no locks or snapshots are held. A writer that can modify the
  verification directory can replace a file after the preflight check and
  before or during inspection execution. A change that happens between the
  recheck and the inspection's `open()` is not detectable by in-toto.

Callers that need a stronger guarantee must provide isolation, for example:

- run verification against a read-only or immutable snapshot of the artifacts,
- hold exclusive write locks from the preflight check through the end of the
  inspection, or
- execute the inspection inside a sandbox that mounts the same snapshot that
  was checked.

## Report

`in-toto-verify --inspection-input-report <path>` writes a JSON report for every
inspection, including rejected ones. It contains, per input:

- the inspection view path and declared Link path,
- the source step, artifact type and Link filenames,
- the step name, the Link's own `name` field, and the keyid(s) of the verified
  Link selected for this step, plus the corresponding Link filename,
- a SHA-256 digest of the Link's signed payload, so different Link identities
  with the same step name remain distinguishable,
- the digests declared by the Link and observed on disk,
- the resolved path, size, inode and mtime observed during preflight hashing,
- a separate `recheck` record with the digest and stat identity observed
  immediately before process start,
- the policy, including what is checked, what is not guaranteed, concurrency
  limits and caller requirements.

The API exposes the same evidence as
`in_toto.inspection_binding.InspectionInputReport`. The report is intended as a
record of what was checked; it is not a proof that the inspection consumed
exactly those bytes.

## Strict mode

Declared inputs are always enforced. Passing
`--require-inspection-inputs` additionally fails verification before execution
for any inspection that declares no inputs at all, so a verifier cannot
silently fall back to the legacy behavior of observing the whole working
directory. Inspections without declarations are still executed by default for
backward compatibility, and their reports say explicitly that no input binding
was performed.
