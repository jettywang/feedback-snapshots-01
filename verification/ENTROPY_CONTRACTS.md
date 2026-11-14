# Entropy call-chain contracts and fault-injection regression

Scope: `python-ecdsa` random key generation and probabilistic signing.
Deterministic signing (RFC 6979 / EdDSA) is intentionally out of scope and
keeps its existing, independent contract.

Re-run the evidence:

```sh
.venv/bin/python verification/entropy_fault_trace.py        # bounded trace
.venv/bin/python -m pytest -q -o addopts= src/ecdsa/test_entropy.py
```

## The chain

```
SigningKey.generate(curve, entropy)             # random key generation
├─ Weierstrass: util.randrange(order, entropy)
│                └─ util.entropy_bytes(entropy, n)
└─ Edwards:     util.entropy_bytes(entropy, curve.baselen)
                 └─ eddsa.PrivateKey(...)

SigningKey.sign(data, entropy)                  # probabilistic signing
└─ sign_digest(digest, entropy, k=None)
   └─ sign_number(number, entropy, k=None)
      ├─ randrange(order, entropy) -> entropy_bytes(entropy, n)   (nonce draw)
      └─ privkey.sign(number, k) -> may raise RSZeroError         (r==0 / s==0)
```

Deterministic signing is a separate branch and never reads `entropy`:

```
sign_deterministic / sign_digest_deterministic
└─ rfc6979.generate_k(..., retry_gen)   # retry_gen loop on RSZeroError
```

## Per-layer contract (what each layer owns)

| Layer | Accepts | On short/empty/over-long/non-bytes | On callback exception | Budget owned |
|---|---|---|---|---|
| `entropy` callback | one int `n`, returns exactly `n` bytes (`os.urandom` shape) | — | — | — |
| `util.entropy_bytes` | exact-length bytes-like | `EntropySourceError` | propagates unchanged (not wrapped) | none |
| `util.randrange` | any source through `entropy_bytes` | `EntropySourceError` | propagates | rejection budget = 128 consecutive out-of-range samples → `EntropyExhaustedError` |
| `SigningKey._*_keygen` | same as above | `EntropySourceError` | propagates | none |
| `SigningKey.sign_number` (entropy nonce) | `k is None` | `EntropySourceError` | propagates | nonce re-selection budget = 128 draws that all give `r==0`/`s==0` → `RSZeroError` |
| `SigningKey.sign_number` (`k` given) | explicit nonce | n/a | n/a | none; `RSZeroError` raised immediately, never replaced |
| RFC 6979 deterministic | no entropy | n/a | n/a | `retry_gen`, unchanged |

Key invariants:

* **Fail closed.** No layer substitutes a time-derived value, a constant, or an
  implicit PRNG. `os.urandom` is used **only** when the argument is exactly
  `None`, never as a fallback after a failure.
* **Errors are typed and not `ValueError`.** `EntropyError` subclasses
  `RuntimeError`, so a broad `except ValueError` cannot silently swallow a
  dead source.
* **Legitimate rejection is not an error.** `randrange` rejection-samples on
  unbiased bit masking (no `% order`); one out-of-range sample is retried.
  Only a *persistent* run exhausts the bounded budget.
* **No infinite loops are required to detect failure.** Every loop is bounded
  (128), so the tests and the trace script terminate deterministically; no
  test waits on wall-clock time.

## Fault samples (bounded, reproducible)

See `verification/entropy_fault_trace.py` for the runnable form. The samples
used in `src/ecdsa/test_entropy.py`:

* `lambda n: b""` — empty read.
* `lambda n: b"\x00"` / `b"\x00"*31` — short read.
* `b"\x00"*(n+1)` — over-long read.
* `lambda n: 1234` / `None` / `"text"` — non-bytes.
* a callback that raises `SourceDown` — exception propagation.
* toy order 167, samples `b"\xff\xff"` (mask → 256, rejected) then
  `b"\x10\x00"` (mask → 16 → k=17, accepted) — legitimate rejection then
  accept.
* `b"\xff\xff"` repeated 128× — persistent out-of-range → exhausted.
* toy curve nonce `k=15` (yields `r==0`) then `k=20` — nonce re-selection.
* toy curve nonce `k=15` repeated 128× — nonce budget exhausted.

## Deterministic path

`sign_deterministic` / `sign_digest_deterministic` take no `entropy`
argument. They retry via `rfc6979.generate_k(retry_gen=...)` when a computed
`r`/`s` is zero, and this remains byte-for-byte stable
(`test_deterministic_retry_contract_is_unchanged`,
`test_deterministic_signing_is_independent_of_entropy`).

## Uniformity

`randrange` masks the requested bytes to `bit_length(order-2)` bits and
rejects values outside `[1, order)`. There is no `% order` step, so no modulo
bias is introduced; the all-ones sample test asserts a `2**256`-valued sample
is rejected rather than folded into range.
