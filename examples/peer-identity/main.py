"""Demonstrate that a finished Noise handshake is not by itself authentication."""
from noise.backends.default.keypairs import KeyPair25519
from noise.connection import Keypair, NoiseConnection
from noise.exceptions import NoiseHandshakeError, NoiseIdentityError

PROTOCOL = b'Noise_{}_25519_ChaChaPoly_SHA256'

INITIATOR_PRIVATE = bytes(range(0, 32))
RESPONDER_PRIVATE = bytes(range(32, 64))
ATTACKER_PRIVATE = bytes(range(64, 96))


def public_key(private_bytes):
    return KeyPair25519.from_private_bytes(private_bytes).public_bytes


INITIATOR_PUBLIC = public_key(INITIATOR_PRIVATE)
RESPONDER_PUBLIC = public_key(RESPONDER_PRIVATE)
ATTACKER_PUBLIC = public_key(ATTACKER_PRIVATE)


def connection(pattern, initiator):
    name = PROTOCOL.replace(b'{}', pattern.encode())
    instance = NoiseConnection.from_name(name)
    instance.set_as_initiator() if initiator else instance.set_as_responder()
    return instance


def describe(evidence):
    key = evidence.peer_static_public_key
    print('    pattern={} role={} auth={} source={} proven={} peer_key={}'.format(
        evidence.pattern,
        evidence.role,
        evidence.peer_authentication,
        evidence.peer_static_key_source,
        evidence.peer_static_key_proven,
        key.hex()[:16] if key else None,
    ))


def run(pattern, initiator, responder, init_policy, resp_policy):
    print('\n=== {} ==='.format(pattern))
    initiator.set_peer_identity_verifier(init_policy)
    responder.set_peer_identity_verifier(resp_policy)
    initiator.start_handshake()
    responder.start_handshake()

    sender, receiver = initiator, responder
    for _ in initiator.noise_protocol.pattern.tokens:
        ciphertext = sender.write_message(b'')
        receiver.read_message(ciphertext)
        sender, receiver = receiver, sender

    for label, side in (('initiator', initiator), ('responder', responder)):
        print('  {} finished={}'.format(label, side.handshake_finished))
        describe(side.get_peer_identity())
    print('  transport works:',
          responder.decrypt(initiator.encrypt(b'hello')) == b'hello')


def main():
    # NN: crypto completes, but no identity exists.
    run('NN', connection('NN', True), connection('NN', False), lambda e: True, lambda e: True)

    # XX: both peers send and prove static keys; application policy decides.
    xx_init, xx_resp = connection('XX', True), connection('XX', False)
    xx_init.set_keypair_from_private_bytes(Keypair.STATIC, INITIATOR_PRIVATE)
    xx_resp.set_keypair_from_private_bytes(Keypair.STATIC, RESPONDER_PRIVATE)
    trusted = {INITIATOR_PUBLIC, RESPONDER_PUBLIC}
    run('XX (trusted keys)', xx_init, xx_resp,
        lambda e: e.peer_static_public_key in trusted,
        lambda e: e.peer_static_public_key in trusted)

    # IK: preset responder key. It is configured locally, not observed.
    ik_init, ik_resp = connection('IK', True), connection('IK', False)
    ik_init.set_keypair_from_private_bytes(Keypair.STATIC, INITIATOR_PRIVATE)
    ik_init.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, RESPONDER_PUBLIC)
    ik_resp.set_keypair_from_private_bytes(Keypair.STATIC, RESPONDER_PRIVATE)
    run('IK (legitimate preset key)', ik_init, ik_resp,
        lambda e: e.peer_static_public_key == RESPONDER_PUBLIC,
        lambda e: e.peer_static_public_key == INITIATOR_PUBLIC)

    # IK against an unknown key: the responder rejects at admission.
    unknown_init, unknown_resp = connection('IK', True), connection('IK', False)
    unknown_init.set_keypair_from_private_bytes(Keypair.STATIC, INITIATOR_PRIVATE)
    unknown_init.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, ATTACKER_PUBLIC)
    unknown_resp.set_keypair_from_private_bytes(Keypair.STATIC, RESPONDER_PRIVATE)
    print('\n=== IK (unknown preset key) ===')
    unknown_resp.set_peer_identity_verifier(lambda e: e.peer_static_public_key == INITIATOR_PUBLIC)
    unknown_init.start_handshake()
    unknown_resp.start_handshake()
    try:
        unknown_resp.read_message(unknown_init.write_message(b'hello'))
        print('  unexpected success')
    except Exception as exc:
        print('  handshake failed before admission:', type(exc).__name__)
    print('  responder finished:', unknown_resp.handshake_finished)

    # IK impersonation: the attacker does not hold the configured key, so the
    # cryptographic handshake fails before any admission decision is made.
    spoof_init, attacker = connection('IK', True), connection('IK', False)
    spoof_init.set_keypair_from_private_bytes(Keypair.STATIC, INITIATOR_PRIVATE)
    spoof_init.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, RESPONDER_PUBLIC)
    attacker.set_keypair_from_private_bytes(Keypair.STATIC, ATTACKER_PRIVATE)
    print('\n=== IK (peer impersonating the configured key) ===')
    spoof_init.start_handshake()
    attacker.start_handshake()
    try:
        attacker.read_message(spoof_init.write_message(b'hello'))
        print('  unexpected success')
    except Exception as exc:
        print('  handshake failed before admission:', type(exc).__name__)

    # An application rejection after a completed handshake flow.
    reject_init, reject_resp = connection('NN', True), connection('NN', False)
    reject_resp.set_peer_identity_verifier(lambda e: False)
    reject_init.start_handshake()
    reject_resp.start_handshake()
    reject_resp.read_message(reject_init.write_message(b'one'))
    print('\n=== NN (application rejects peer) ===')
    try:
        reject_resp.write_message(b'final')
    except NoiseIdentityError as exc:
        print('  rejected:', exc)
    try:
        reject_resp.encrypt(b'payload')
    except NoiseHandshakeError as exc:
        print('  transport blocked:', exc)
    print('  responder finished:', reject_resp.handshake_finished)


if __name__ == '__main__':
    main()
