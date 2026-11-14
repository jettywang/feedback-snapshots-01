# Channel-bound login proof example

This example shows how a login proxy can carry a user credential inside a
Noise channel without letting that credential be moved to a different
connection to the same service.

The credential is a **test-only HMAC-SHA256 login proof**.  It is issued by
`HmacLoginIssuer`, verified by `HmacLoginVerifier`, and bound to:

- the service name,
- the user identity,
- the presenter's Noise role (initiator or responder),
- the hash of the completed Noise handshake.

The proof is encrypted as the payload of a normal Noise transport message.
It is used only after the handshake has completed and the peer has passed
the local admission check.  The verifier always recomputes the HMAC against
the handshake hash of the channel that actually received the proof; it does
not trust the hash carried inside the proof.

## What the binding value is, and is not

A Noise handshake hash is a public transcript digest.  It is not a password,
not an access token, and not a secret that authenticates anyone by itself.
Knowing the hash lets an attacker describe the channel, but the HMAC tag can
only be produced with the issuer's signing key.

The issuer signing key is deliberately independent of the Noise static keys
and transport keys.  Rotating the issuer key does not require rotating Noise
keys, and compromising a Noise key does not let an attacker mint login
proofs.

## State rules

`NoiseLoginChannel` only exposes `seal` / `open` for protected application
payloads when `authenticated_user` is set.  That happens only after:

1. the Noise handshake is finished,
2. `confirm_admission()` accepted the peer's authenticated static key,
3. `accept_login()` verified the proof against this channel's hash.

Any failure in `accept_login()` clears `authenticated_user` before raising.
A rejected proof therefore leaves no logged-in state and cannot be used for a
protected operation.  Once a channel is authenticated, a second login on the
same channel is rejected.

The example allows a correctly bound proof to be tried after a failed one.
Production code should normally close the connection or apply a strict retry
limit after a login failure.

## Rejected reuse cases

The proof cannot be reused:

- on a **reconnect**, because a new handshake produces a new hash,
- with the **reverse role**, because the role is inside the HMAC input,
- for **another service**, because the service name is inside the HMAC input,
- on **another simultaneous connection**, because the hash differs.

Forwarding is modeled by re-encrypting already-minted proof bytes under the
target connection's transport.  Noise decryption succeeds, so rejection comes
specifically from the login-proof binding rather than from a transport error.

## Running the example

From the repository root:

```bash
python examples/channel_binding/main.py
```

From this directory:

```bash
PYTHONPATH=../.. python main.py
```

The demo establishes two legitimate connections to the same service, swaps
their proofs, observes both rejections, and then completes one protected
operation on each genuine connection.

Run the focused tests with:

```bash
pytest tests/test_channel_binding_example.py -q
```

## Scope and limitations

This example prevents **cross-channel forwarding** of a login proof.  It does
not replace user authentication:

- the issuer is trusted to have authenticated the user and to attest the
  user's identity,
- the verifier shares the issuer's HMAC key in this test setup,
- authorization, account state, session lifetime, revocation, rate limiting,
  and audit logging are application responsibilities,
- a compromised endpoint can still misuse a proof minted for its own channel;
  channel binding prevents moving a proof, not misuse inside its own channel.

The HMAC issuer is a test fixture only.  A production design would use an
issuer key held by the identity service and an asymmetric signature or a
proper credential protocol rather than a shared test HMAC key.
