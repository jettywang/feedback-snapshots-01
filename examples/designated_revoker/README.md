# Designated-revoker revocation verification (offline)

An offline-stored revocation key may need to publish an OpenPGP key revocation
on behalf of a primary key whose private material is no longer available. This
example shows how PGPy decides whether such a revocation actually revokes the
target key, without ever downloading a key from a network.

## The rule in one line

A revocation only revokes a target when **both** hold:

1. the signer is authorized to revoke *this* target, and
2. the signature is cryptographically valid *over this* target.

A plain successful signature verification is step 2 only. It never, by itself,
produces an "already revoked" conclusion. Step 1 is checked first.

## The verification path

`PGPKey.verify_revocation(signature, candidate_keys, at=...)`
(backed by `pgpy.verify_revocation`) runs these checks in order:

1. **Scope.** A primary key is revoked by signature type `0x20`; a subkey by
   `0x28`. The wrong type raises `PGPError`.
2. **Signer resolution.** The signer is matched against the *explicitly
   supplied* candidate public keys (full Issuer fingerprint preferred, Issuer
   key id as fallback). If no candidate matches, the result is
   `UnknownSigner` — the path cannot be completed offline, which is distinct
   from a bad signature.
3. **Self-revocation.** A primary revoking itself, or a parent primary revoking
   its own subkey, is `SelfRevoked` once the cryptographic check passes; no
   Revocation Key subpacket is required.
4. **Authorization first (third party).** For any other signer, PGPy looks for
   a Revocation Key subpacket that is **all** of:
   - in the **hashed** area of a self-signature (an unhashed claim is not bound
     by the signature and is ignored → `AuthorizationNotHashed`),
   - made by the **target's own primary key** (a designation carried by another
     primary's self-signature → `AuthorizationFromOtherKey`),
   - matching the signer on **both fingerprint and public-key algorithm**
     (→ `RevokerNotAuthorized` otherwise),
   - carrying the required class bit `0x80`,
   - still within the carrying self-signature's validity window at `at`
     (→ `AuthorizationExpired`).

   When no Revocation Key material exists at all, the result is
   `NoAuthorization`. The `missing_authorization` property groups these
   "no usable material" outcomes and keeps them separate from `BadSignature`.
5. **Signature over the target, second.** Only after authorization is
   established is the cryptographic signature checked against the target. If it
   verifies over a *different* supplied key instead, the result is
   `WrongTarget` (the signature is valid, just not about this key); if it
   verifies nowhere, it is `BadSignature`.

### Why hashed vs. unhashed matters

Subpackets in the hashed region are covered by the signature over the key;
subpackets in the unhashed region can be appended or altered by anyone without
invalidating the signature. A Revocation Key placed only in the unhashed region
therefore proves nothing about what the keyholder authorized, even though the
self-signature itself remains cryptographically valid.

## Fixed verification moment

Pass `at=<datetime>` to evaluate everything against one frozen instant rather
than the wall clock. At that moment PGPy uses the designation self-signatures
that are still valid, and ignores ones whose validity window has closed. This
makes the result reproducible: the same blocks always yield the same verdict at
the same `at`, and it is explicit *which* authorization was relied upon (the
matching hashed Revocation Key is returned as `result.authorization`).

## Status outcomes

| Status | Revoked? | Meaning |
| --- | --- | --- |
| `SelfRevoked` | yes | target (or its parent primary) revoked itself |
| `AuthorizedRevoked` | yes | hashed, in-scope designation; signature valid over target |
| `NoAuthorization` | no | no Revocation Key material present |
| `AuthorizationNotHashed` | no | claim exists only in the unhashed area |
| `AuthorizationFromOtherKey` | no | designation belongs to a different primary key |
| `RevokerNotAuthorized` | no | material exists but fingerprint/algorithm/class do not match |
| `AuthorizationExpired` | no | matching designation is out of its validity window at `at` |
| `WrongTarget` | no | signature valid, but computed over a different key |
| `BadSignature` | no | signature does not cryptographically verify |
| `UnknownSigner` | no | signer's key was not among the supplied candidates |

`result.is_revoked` is `True` only for the first two.
`result.missing_authorization` is `True` for the authorization-material group.

## Generating the local samples

```
.venv/bin/python examples/designated_revoker/build_samples.py
```

This creates armored keys, revocation signatures, and `report.json` under
`samples/`. Every block is produced locally; the verifier only ever sees the
candidate keys the script hands it. The three required families are:

- **primary-key self-revocation** → `SelfRevoked`,
- **legitimate designated revocation** → `AuthorizedRevoked`,
- **over-reaching revocations** (unhashed-only, foreign-key, wrong target,
  unknown signer, tampered) → each mapped to its specific non-revoking status.

The pytest companion is `tests/test_06_designated_revoker.py`.
