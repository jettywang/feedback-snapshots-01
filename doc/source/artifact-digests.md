# Artifact Digests

A link records artifact paths mapped to hash dictionaries, e.g.
`{"sha256": "<hex>"}`. A hash alone does not say which bytes were hashed. In
particular, a digest may be over the raw file bytes, or over a defined textual
normalization such as converting CRLF and CR line endings to LF.

Links can carry an explicit, signed `artifact_digest_config` descriptor that
states the content interpretation for each artifact side and hash algorithm:

```json
{
  "materials": {"sha256": "raw"},
  "products": {"sha256": "line-endings"}
}
```

The descriptor is part of the signed link payload. Tampering with it invalidates
the link signature.

## Legacy links

Links generated before this descriptor existed do not contain it. Absence is
treated as the historical **raw-byte** semantics; it is never guessed to be a
normalization. New links are written with an explicit descriptor, derived from
the recording options, so the historical and normalized forms are no longer
indistinguishable.

Unknown normalization names are rejected with `DigestConfigError`. They are
never silently compared as raw bytes.

## Recording

Use `--artifact-digest-config` with `in-toto-run` or `in-toto-record`, passing a
JSON object or a path to a JSON file:

```sh
in-toto-run -n build --signing-key key \\
  --artifact-digest-config '{"materials": "raw", "products": "line-endings"}' \\
  -m src -p dist -- make build
```

The API accepts the same configuration via the `artifact_digest_config`
argument of `in_toto.runlib.in_toto_run`, `in_toto_record_start`, and
`in_toto_record_stop`, as well as `in_toto_match_products`.

Convenience shorthands are accepted, including a bare normalization name
(`raw` or `line-endings`), `{"normalization": "line-endings"}`, or a per-side
string (`{"materials": "raw", "products": "line-endings"}`). The serialized
link always uses the explicit per-side, per-algorithm form.

## Verification

MATCH rules, same-step threshold agreement, summary links, and
`in-toto-match-products` compare both digest values and their effective
normalization. Equal digest values computed under different interpretations do
not match. Summary links preserve the first step's material policy and the last
step's product policy; a summary of two legacy links stays legacy.

## Byte recomputation

Raw mode is a byte claim. Recompute it with, e.g.:

```sh
sha256sum artifact.txt
```

This differs from `sha256sum` of a file with normalized line endings. To verify
the normalized form, hash the normalized bytes:

```sh
tr -d '\r' < artifact.txt | sha256sum
```

Do not treat "the text looks the same" as evidence: the descriptor states which
byte transformation was authenticated.
