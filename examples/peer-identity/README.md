# Peer identity admission

`NoiseConnection.handshake_finished` means the cryptographic handshake flow
completed. It does **not** mean the peer's identity is acceptable.

Install an optional callback with `set_peer_identity_verifier`. It receives a
`noise.identity.PeerIdentityEvidence` snapshot immediately before transport
keys are derived and must return a true value to admit the peer.

Run the demonstration from the repository root:

```sh
.venv/bin/python examples/peer-identity/main.py
```

It runs three in-memory handshakes with the same crypto functions:

- `NN`: completes, but there is no peer identity at all.
- `XX`: the peer static key is observed and proven, so application trust
  policy must accept it explicitly.
- `IK` with a preset peer key: the peer static key was configured locally
  (not observed) and is proven by the handshake.

It then shows the same `IK` pattern failing against an unknown key and an
impersonator. In those cases the handshake never reaches the callback, so no
transport state exists.

Key fields on the evidence object:

- `pattern` / `protocol_name` / `role`: what actually ran, and this side's role.
- `peer_static_public_key`: the peer key actually used, or `None`.
- `peer_static_key_source`: `observed`, `configured`, or `none`.
- `peer_static_key_proven`: whether a peer-authenticated message bound the
  handshake to the peer's static private key.
- `handshake_hash`: final transcript hash, for channel binding.
- `peer_authentication`: `none`, `static`, or `static-unproven`.

A rejected callback, or one that raises, aborts the handshake: the final
handshake payload is not returned, no transport cipher state is derived, and
later `encrypt`/`decrypt` calls raise `NoiseHandshakeError`.
