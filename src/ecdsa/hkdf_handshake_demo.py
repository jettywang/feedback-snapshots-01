"""
Runnable, in-memory demonstration of ECDH + HKDF + key confirmation.

Run it with::

    python -m ecdsa.hkdf_handshake_demo

The script never touches the network: two endpoints live in the same
process and exchange keys through local variables. It shows:

1. a successful handshake that derives two directional traffic keys and
   mutually confirms them,
2. confirmation failing when the authenticated identities are swapped,
3. confirmation failing under a role-reflection attack, and
4. confirmation failing when the *same* ECDH shared secret is reused for a
   different protocol.

Authentication of the parties is assumed to be handled by a layer above
(validated certificates or signatures over the ephemeral public keys). This
module does not implement or replace that authentication.
"""

from .curves import NIST256p
from .hkdf import (
    HandshakeContext,
    HandshakeParty,
    KeyConfirmationError,
    ROLE_INITIATOR,
    ROLE_RESPONDER,
    confirmation_tag,
    derive_session_keys,
    shared_secret_from_ecdh,
    verify_confirmation_tag,
)


def _make_parties():
    initiator = HandshakeParty(b"client-alice", NIST256p)
    responder = HandshakeParty(b"server-bob", NIST256p)
    initiator.ecdh.load_received_public_key(responder.public_key)
    responder.ecdh.load_received_public_key(initiator.public_key)
    return initiator, responder


def _context(initiator, responder, **kwargs):
    return HandshakeContext(
        initiator.identity,
        responder.identity,
        initiator.public_bytes,
        responder.public_bytes,
        **kwargs
    )


def demo_successful_handshake():
    print("== 1. Successful in-memory handshake ==")
    initiator, responder = _make_parties()
    context = _context(initiator, responder)

    initiator.complete(context)
    responder.complete(context)

    initiator_tag = initiator.make_confirmation(context, ROLE_INITIATOR)
    responder_tag = responder.make_confirmation(context, ROLE_RESPONDER)

    responder.check_peer_confirmation(context, ROLE_INITIATOR, initiator_tag)
    initiator.check_peer_confirmation(context, ROLE_RESPONDER, responder_tag)

    secrets = initiator._secrets
    print("  shared secret length: %d bytes (fixed field width)"
          % len(shared_secret_from_ecdh(initiator.ecdh)))
    print("  initiator->responder key: %s"
          % secrets["initiator_to_responder_key"].hex())
    print("  responder->initiator key: %s"
          % secrets["responder_to_initiator_key"].hex())
    print("  both confirmation tags verified: OK")
    print()


def demo_swapped_identity():
    print("== 2. Swapped / mismatched identity is rejected ==")
    initiator, responder = _make_parties()
    real_context = _context(initiator, responder)

    # The responder binds an initiator identity that does not match what the
    # actual initiator used in its own derivation.
    confused_context = HandshakeContext(
        b"mallory",
        responder.identity,
        initiator.public_bytes,
        responder.public_bytes,
    )

    initiator.complete(real_context)
    responder.complete(confused_context)
    tag = initiator.make_confirmation(real_context, ROLE_INITIATOR)

    try:
        responder.check_peer_confirmation(
            confused_context, ROLE_INITIATOR, tag
        )
    except KeyConfirmationError:
        print("  confirmation failed as expected: identities do not match")
    else:  # pragma: no cover - defensive, the demo must always fail here
        raise AssertionError("identity swap was wrongly accepted")
    print()


def demo_role_reflection():
    print("== 3. Role reflection is rejected ==")
    initiator, responder = _make_parties()
    normal_context = _context(initiator, responder)

    # Reflected exchange: same keys and identities, but roles exchanged.
    reflected_context = HandshakeContext(
        responder.identity,
        initiator.identity,
        responder.public_bytes,
        initiator.public_bytes,
    )

    initiator.complete(normal_context)
    responder.complete(reflected_context)
    tag = initiator.make_confirmation(normal_context, ROLE_INITIATOR)

    try:
        responder.check_peer_confirmation(
            reflected_context, ROLE_INITIATOR, tag
        )
    except KeyConfirmationError:
        print("  confirmation failed as expected: roles do not match")
    else:  # pragma: no cover
        raise AssertionError("role reflection was wrongly accepted")
    print()


def demo_cross_protocol_reuse():
    print("== 4. Same secret reused in another protocol is rejected ==")
    initiator, responder = _make_parties()
    context = _context(initiator, responder)
    initiator.complete(context)

    same_secret = shared_secret_from_ecdh(initiator.ecdh)
    other_context = _context(
        initiator, responder, protocol_id=b"some-other-protocol/9.9"
    )
    other_secrets = derive_session_keys(same_secret, other_context)

    other_tag = confirmation_tag(
        other_secrets["initiator_confirmation_key"],
        other_context.transcript(),
    )
    initiator_confirmation_key = initiator._secrets[
        "initiator_confirmation_key"
    ]
    try:
        verify_confirmation_tag(
            initiator_confirmation_key,
            other_context.transcript(),
            other_tag,
        )
    except KeyConfirmationError:
        print("  confirmation failed as expected: protocol id is bound in")
    else:  # pragma: no cover
        raise AssertionError("cross-protocol reuse was wrongly accepted")
    print()


def main():
    demo_successful_handshake()
    demo_swapped_identity()
    demo_role_reflection()
    demo_cross_protocol_reuse()
    print("All demonstrations finished. Until both confirmation tags are")
    print("verified, application data must not be treated as belonging to an")
    print("established secure session.")


if __name__ == "__main__":
    main()
