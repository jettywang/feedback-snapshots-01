# Encrypted first-party caveat — secrecy review

Scope: `EncryptedFirstPartyCaveatDelegate` + `SecretBoxEncryptor` (signifier
`sbe::`) in pymacaroons. Question under review: can an encrypted first-party
caveat hide a restriction from the token holder so that it is visible to the
server only?

## How the v1 key is actually derived

Source of truth: `pymacaroons/caveat_delegates/encrypted_first_party.py` and
`pymacaroons/field_encryptors/secret_box_encryptor.py`.

```
S_0 = HMAC(generate_derived_key(root_key), identifier)
S_i = HMAC(S_{i-1}, caveat_id_i)                       # chain signature
key_i = truncate_or_pad(S_i)                           # SecretBox key
blob_i = 'sbe::' + base64( SecretBox(key_i).encrypt(predicate_i) )
```

The encryption key is the macaroon's **running chain signature** at the caveat
position. Every `S_i` is an HMAC output that anyone holding the token at
attenuation state `i` already possesses (`signature_bytes`) or can recompute
with the standard attenuation rule. SecretBox and the random nonce provide
authenticated encryption and distinct ciphertexts; neither is a secret. The
secret boundary is `S_i`, and `S_i` is a chain value, not a server-only value.

## Capability matrix (empirical, rerunnable)

Each "decrypts secret?" result below comes from an actual SecretBox decryption
attempt against a synthetic secret predicate
(`time < 2026-12-31T00:00:00Z`), not from an argument about nonces or the
cipher. Printed by `python -m security_audit.encrypted_caveat_secrecy_tests`.

| Participant | Key material it holds | Decrypts the secret? | Mints accepted encrypted caveat? |
| --- | --- | --- | --- |
| Final token only | `S_N` (final signature) | **No** for earlier blobs | Yes, can append new encrypted caveats |
| Parent token (pre-append) | `S_i` at the secret position | **Yes** | Yes |
| Self-attenuating holder | `S_i` it just signed with | **Yes** | Yes (including arbitrary predicates the verifier then accepts) |
| Discharge holder | discharge `S_0` from its caveat key | **Yes** for its own discharge chain | Yes on that chain; root `vid` stays sealed |
| Foreign chain (different `S_i`) | unrelated signature | No | No (decrypt and signature check both fail) |

Participant-by-participant reading:

- **Final token only.** The holder sees just `S_N`. It cannot reverse the HMAC
  chain to recover `S_i`, so it cannot decrypt caveats already present above it
  (`test_final_token_holder_cannot_read_existing_secret_but_can_mint_new`).
  This is the *only* confidentiality the construction delivers, and it is
  conditional on the holder never having seen an earlier token state.
- **Parent token before the append.** The holder has exactly the `S_i` used as
  the key, so it decrypts the new blob directly
  (`test_parent_token_holder_decrypts_the_appended_secret`). Any delegation
  step that hands out an intermediate macaroon destroys the secrecy of every
  caveat added afterward.
- **Self-attenuating holder.** Attenuation computes `HMAC(S_i, ...)`, so the
  actor necessarily knows `S_i`; the "encryption" cannot hide anything from the
  party that performs the attenuation. The same test shows the holder can
  mint an encrypted caveat carrying any predicate and the standard verifier
  accepts it.
- **Discharge holder.** It is provisioned with the third-party caveat key, so
  it derives the discharge macaroon's `S_0` and reads every encrypted
  first-party caveat on that discharge chain. It does **not** learn the root
  macaroon's running signature, so the root `vid` (a separate SecretBox under
  the root chain key) remains closed to it
  (`test_discharge_holder_reads_own_chain_but_not_root_chain_secrets`).

## Ciphertext portability across signature chains

The blob has no binding to an identifier, chain position, or context; it is
bound only to `S_i`.

- Two independently built chains that reach the same `S_0` (same root key and
  identifier) accept the identical blob. Grafting the blob from chain A into
  chain B yields the same final signature and verifies, decrypting to the
  original predicate (`test_ciphertext_grafts_onto_a_second_chain_with_matching_signature`).
- A chain that diverges (different root key → different `S_0`) cannot decrypt
  the grafted blob and fails signature verification; flipping a ciphertext byte
  is rejected by the SecretBox MAC
  (`test_graft_fails_when_chains_diverge_and_tampering_is_detected`).

Conclusion: the ciphertext is replayable into any other chain that reproduces
the running signature, and there is no contextual binding preventing that.
Authenticity (tamper protection) holds; contextual non-malleability does not.

The nonce is not the secrecy boundary: random nonces produce different
ciphertexts under the same key, and a fixed all-zero nonce (as used in the
shipped test) still decrypts for anyone holding `S_i`
(`test_random_nonce_is_not_the_secrecy_boundary`).

## Verdict

The v1 construction does **not** provide a server-only restriction. It hides
predicates only from a party that sees exclusively the final token and never
an intermediate state. It cannot protect a secret from the parent-token
holder, the self-attenuator, or the relevant discharge holder — i.e. from the
very participants in a macaroon delegation flow. Do not rely on it for
confidential business rules; at most use it as an obfuscation layer against
naive inspection of the final token.

## Minimal versioned alternative: v2 server-bound field key

`v2_server_secret_encryptor.py` adds a new encryptor whose key never comes
from the chain:

```
field_key = HMAC('pymacaroons-encrypted-first-party-v2-server-field-key',
                 server_wrap_key)
blob = 'sbe2::' + base64( SecretBox(field_key).encrypt(predicate) )
```

- The wrapping key is held only by the minting/verifying service and is never
  placed in a token. The chain signature is passed for API parity but ignored
  in key derivation, so no holder — including a parent-token holder — can
  derive the key.
- A new signifier `sbe2::` is used. Existing `sbe::` blobs keep their exact
  meaning and still dispatch on the chain signature; the two formats can
  coexist in one token. No existing format semantics change. This is the
  required version marker.
- Control proofs: the field key differs from every chain signature and is
  stable across signature states; parent-token decryption fails while the
  configured server verifier succeeds; a holder-forged `sbe2::` blob is
  rejected at verify time; v1 still decrypts under the chain key
  (`v2_server_secret_encryptor_tests.py`).

Operational requirements for v2: distribute `server_wrap_key` out-of-band to
verifiers only; rotate it as a server secret; keep access control on the
verifier callbacks. The macaroon signature still proves caveat integrity; v2
adds holder-side confidentiality on top of it.

## Rerun

```
.venv/bin/python -m pytest security_audit -v
.venv/bin/python -m security_audit.encrypted_caveat_secrecy_tests   # matrix
```

Related pre-existing library behavior (not introduced here): the v1 verifier
delegate attempts `sbe::` decryption for every first-party caveat, so mixing
plaintext and encrypted first-party caveats on one macaroon raises
`CryptoError` at verification. The proof chains therefore use encrypted-only
caveats where a verifier is exercised.
