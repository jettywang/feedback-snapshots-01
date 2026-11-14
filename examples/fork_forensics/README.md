# Offline Fork Forensics Example

Two update nodes can independently observe metadata for the same role and
version that contain different content. This example shows how the
`tuf.forensics` package decides, fully offline and starting from an explicit
trust anchor, whether that proves the publisher signed conflicting content.

## What counts as a fork

The analyzer never trusts an observation package without verifying it. Each
package must independently pass identity and authorization checks against the
supplied root chain and delegation material:

- traditional `Metadata` is verified over its canonical JSON signed bytes;
- a DSSE `SimpleEnvelope` is verified over its pre-auth encoding (PAE);
- root metadata is checked against both the previous root and itself;
- delegated targets are checked hop by hop along the delegation path.

Only when both packages authenticate, target the same role and version, and
contain different canonical payload content is a fork **proven**. The
following are deliberately not forks:

- JSON whitespace or signature-order differences,
- additional valid signatures on otherwise identical content,
- different versions (a same-version conflict cannot span versions),
- a different role.

A package that fails verification (for example one tampered with by a third
party) makes the result **inconclusive**, never evidence of publisher
misbehavior. Inconclusive evidence and a genuine refutation are reported as
distinct statuses.

## Usage

```console
python examples/fork_forensics/demo.py
```

The demo builds fully signed repositories with freshly generated ed25519 keys
and runs five scenarios under both signature semantics
(`METADATA` and `SIMPLE`):

1. two valid conflicting same-version packages (`proven`),
2. identical content with different formatting and an extra signature
   (`refuted: same_canonical_content`),
3. two different versions (`refuted: different_version`),
4. one package tampered with by a third party (`inconclusive`),
5. a proven fork reached through a rotated root and a delegated role, showing
   the reconstructed root chain and delegation authorization path.

Each verdict is printed as JSON and contains the original evidence digests,
the conflicting field paths and values, and both concrete authorization paths.

## Programmatic use

```python
from tuf.forensics import EnvelopeType, ObservationPackage, analyze_fork

first = ObservationPackage(
    envelope_a,
    trust_anchor=root_bytes,
    envelope_type=EnvelopeType.METADATA,
    root_chain=[root_v2_bytes],
)
second = ObservationPackage(
    envelope_b,
    trust_anchor=root_bytes,
    envelope_type=EnvelopeType.METADATA,
    root_chain=[root_v2_bytes],
)

report = analyze_fork(first, second)
if report.fork_proven:
    # report.conflict_fields describes exactly what the publisher signed twice.
    ...
```

For delegated targets roles, pass the delegated targets bytes in
`delegations` (keyed by role name) and the intermediate role names in
`delegation_chain`; the observed role itself is named with `role_name`.
