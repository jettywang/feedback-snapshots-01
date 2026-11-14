# EXPERIMENTAL Ed25519 + ML-DSA-65 Composite Signer

> **Status: experimental and custom.** The key type, scheme, signature
> container and key serialization described on this page are a
> securesystemslib-specific experiment. They are **not** an interoperability
> standard, have no stability guarantee, and may change or be removed without
> notice. Signatures produced here cannot be verified by any other
> implementation. Do not treat this format as a finished or standardized
> product.

The composite signer combines a classical Ed25519 signature and a
post-quantum ML-DSA-65 signature so that a valid signature proves possession
of **both** private keys. It reuses the existing pyca/cryptography backend
(via `CryptoSigner` and `SSlibKey`) and the standard `Signer`/`Key`
extension mechanism.

The types are exported from `securesystemslib.signer` but are **not
registered by default**. An application opts in:

```python
from securesystemslib.signer import (
    CompositeSigner, Key, Signer, register_composite_signer,
)

register_composite_signer()  # idempotent; populates both dispatch tables

signer = CompositeSigner.generate()
signature = signer.sign(b"message")
signer.public_key.verify_signature(signature, b"message")
```

Constructing a `CompositeKey` or `CompositeSigner` always emits a
`FutureWarning` naming the format as experimental and non-standard.

## Identifiers

| Item | Value |
| --- | --- |
| Key type | `experimental-composite` |
| Scheme | `experimental-ed25519-mldsa65` |
| Private key URI scheme | `composite2:` |
| Component order (fixed) | `ed25519` first, `ml-dsa-65` second |

The `experimental-` prefix is visible in every serialized key so the custom
nature of the format cannot be confused with a built-in standard key type.

## What gets bound together

Both component algorithms sign the **same** byte string, the *composite
binding*. The binding commits, unambiguously, to:

1. a fixed domain separator (domain separation from any other usage),
2. the composite scheme identifier `experimental-ed25519-mldsa65`,
3. the two public keys in their fixed order (Ed25519, then ML-DSA-65),
4. the message.

Every field is length-prefixed with a 4-byte big-endian unsigned length, so
the encoding is injective (no ambiguous concatenation):

```
len(domain-separator) || domain-separator
len(scheme)           || scheme
len(ed25519-pub)      || ed25519-pub       # 32 bytes, first position
len(mldsa65-pub)      || mldsa65-pub       # 1952 bytes, second position
len(message)          || message
```

- `domain-separator` is the fixed ASCII string
  `securesystemslib-experimental-composite-v1`.
- Ed25519 signs the binding directly (pure Ed25519).
- ML-DSA-65 signs through the existing backend, i.e. the TAP 21 pre-hash
  (`get_mldsa_payload`) is applied inside `SSlibKey.verify_signature` /
  `CryptoSigner.sign`, exactly as for a standalone ML-DSA key.

Because the public keys and the scheme are inside the signed binding,
swapping component order, replacing either key, or reusing a component over a
different message all change the binding and fail verification.

## Signature container format

A composite signature is one self-describing byte string, hex-encoded inside
the usual `Signature.signature` field (so DSSE's base64 wrapping works
unchanged). Components are separated by explicit length prefixes rather than
relying on fixed offsets alone:

```
len(magic)        || magic                       # fixed 18-byte marker
len(ed25519-sig)  || ed25519-sig                 # 64 bytes, first position
len(mldsa65-sig)  || mldsa65-sig                # 3309 bytes, second position
```

- `magic` is the fixed ASCII string `SSLIB-COMPOSIG-V1` (18 bytes).
- All length prefixes are 4-byte big-endian unsigned integers.
- On parse, the magic, each component size, the absence of truncation and the
  absence of trailing bytes are all checked. Any deviation raises
  `VerificationError`.

### Fixed component sizes

| Component | Public key (raw) | Signature |
| --- | --- | --- |
| Ed25519 | 32 bytes | 64 bytes |
| ML-DSA-65 | 1952 bytes | 3309 bytes |

## Public key serialization

`CompositeKey.to_dict()` nests two complete, standard `SSlibKey` dictionaries
under `keyval`, keyed by the fixed component labels:

```json
{
  "keytype": "experimental-composite",
  "scheme": "experimental-ed25519-mldsa65",
  "keyval": {
    "ed25519": {
      "keytype": "ed25519",
      "scheme": "ed25519",
      "keyval": { "public": "<32-byte raw ed25519 public key, hex>" }
    },
    "ml-dsa-65": {
      "keytype": "ml-dsa",
      "scheme": "ml-dsa-65/1",
      "keyval": { "public": "<ML-DSA-65 SubjectPublicKeyInfo PEM>" }
    }
  }
}
```

`Key.from_dict` (after `register_composite_signer()`) strictly validates on
import and never downgrades:

- the outer `keytype`/`scheme` must be the experimental composite values;
- `keyval` must contain **exactly** the `ed25519` and `ml-dsa-65` entries;
- each component must have the expected key type and scheme
  (`ed25519/ed25519`, `ml-dsa/ml-dsa-65/1`) — a swapped or different algorithm
  is rejected;
- each decoded public key must have the exact raw size in the table above;
- a composite container is the only accepted signature shape — a bare
  Ed25519 or ML-DSA-65 signature is rejected, so verification can never
  silently fall back to the faster single algorithm.

The composite `keyid` is the standard default keyid (SHA-256 over the
canonical JSON of the composite key body), computed by
`compute_default_keyid`.

## Private key URIs

`CompositeSigner.from_priv_key_uri` accepts

```
composite2:?ed25519=<path-to-ed25519-pem>&ml-dsa-65=<path-to-mldsa65-pem>
```

Both paths point to PEM-encoded PKCS#8 private keys and are resolved with the
same `CRYPTO_SIGNER_PATH_PREFIX` handling as `CryptoSigner`'s `file2:` URIs.
The query must contain exactly the two named parameters; the loaded private
keys are checked against the public `CompositeKey` and a mismatch raises
`KeyMismatchError`.

## Failure matrix

All rows below are rejected. `UnverifiedSignatureError` is raised for a
well-formed container whose cryptography does not check out and for malformed
containers (the latter raise `VerificationError`, which is a subclass of
`UnverifiedSignatureError`). Import problems raise `ValueError` /
`VerificationError`.

| Attack / misuse | What is checked | Result |
| --- | --- | --- |
| Sign/verify normal round trip | both components valid over binding | succeeds |
| Wrong message | binding message mismatch | rejected |
| Drop the Ed25519 component | not a composite container (no magic/size) | rejected |
| Drop the ML-DSA-65 component | not a composite container | rejected |
| Verify only the faster Ed25519 sig | bare signature, container parse fails | rejected (no downgrade) |
| Swap component order | binding key order + size/position mismatch | rejected |
| Replace the Ed25519 key | Ed25519 verify over binding fails | rejected |
| Replace the ML-DSA-65 key | ML-DSA verify over binding fails | rejected |
| Splice components from two messages | cross-message binding mismatch | rejected |
| Splice components from two composite key sets | cross-key binding mismatch | rejected |
| Verify signature under a different composite key | at least one component fails | rejected |
| Truncated container / trailing bytes | strict length parse | rejected |
| Tampered or wrong magic | magic check | rejected |
| Wrong `keyid` on the signature | keyid equality check | rejected |
| Non-hex signature field | hex decode failure | rejected |
| Import wrong outer keytype/scheme | strict import check | `ValueError`, no downgrade |
| Import missing/extra component | exact-component-set check | `ValueError` |
| Import wrong component algorithm | per-component type/scheme check | `ValueError` |
| Import wrong component key size | raw size check (32 / 1952) | `ValueError`/`VerificationError` |
| Use without `register_composite_signer()` | dispatch lookup miss | `ValueError: Unsupported public key ...` |
| Load signer with mismatched private keys | key match check | `KeyMismatchError` |

## DSSE usage

A `CompositeSigner` is an ordinary `Signer`, so it works with
`securesystemslib.dsse.Envelope` without changes: the composite container is
hex-encoded in `Signature.signature` and then base64-wrapped by the envelope.
Each composite key counts as one key in the envelope's threshold logic; a
threshold of two therefore requires two distinct composite keys.
