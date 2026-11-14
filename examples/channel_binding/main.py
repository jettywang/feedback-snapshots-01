"""Demonstration: channel-bound login proofs inside Noise channels.

Two legitimate connections to the same service are established at the
same time.  A test login proxy then forwards each user's login proof into
the *other* connection.  Both are rejected by the receiving service because
the proof's HMAC is bound to the original connection's handshake hash.
The genuine proof on its own connection is accepted, and a protected
operation succeeds.
"""

try:
    from .channel_binding import (
        HmacLoginIssuer,
        HmacLoginVerifier,
        LoginProofError,
        LoginProxy,
        establish_kk_channels,
        generate_issuer_key,
        generate_static_keypair,
    )
except ImportError:
    from channel_binding import (
        HmacLoginIssuer,
        HmacLoginVerifier,
        LoginProofError,
        LoginProxy,
        establish_kk_channels,
        generate_issuer_key,
        generate_static_keypair,
    )

SERVICE = 'demo-service'
USER = 'alice'


def _short(value):
    return value.hex()[:16]


def _transplant(proof, target_client, target_server, verifier):
    """Model a login proxy forwarding already-minted proof bytes.

    The proxy re-encrypts the proof under the target connection's
    transport, so Noise decryption succeeds.  Rejection therefore comes
    from the login-proof channel binding, not from transport failure.
    """
    ciphertext = target_client.seal_login(proof)
    return target_server.accept_login(ciphertext, verifier)


def _genuine_login(client_channel, server_channel, proxy, verifier):
    proof = proxy.proof_for(client_channel)
    server_channel.accept_login(client_channel.seal_login(proof), verifier)
    client_channel.accept_login_accepted(
        server_channel.seal_login_accepted(), expected_user=USER
    )
    assert client_channel.authenticated_user == server_channel.authenticated_user == USER


def main():
    issuer_key = generate_issuer_key()
    issuer = HmacLoginIssuer(issuer_key)
    verifier = HmacLoginVerifier(issuer_key)  # separate process in real life

    server_private, server_public = generate_static_keypair()
    pairs = {'A': None, 'B': None}
    for label in pairs:
        client_private, client_public = generate_static_keypair()
        pairs[label] = establish_kk_channels(
            client_private, client_public, server_private, server_public, SERVICE
        )

    print('Two legitimate Noise_KK connections to {!r} are established:'.format(SERVICE))
    for label, (client, server) in pairs.items():
        print('  channel {}  client hash={}  server hash={}  equal={}'.format(
            label, _short(client.handshake_hash), _short(server.handshake_hash),
            client.handshake_hash == server.handshake_hash,
        ))

    proxy_a = LoginProxy(issuer, USER)
    proxy_b = LoginProxy(issuer, USER)
    proof_a = proxy_a.proof_for(pairs['A'][0])
    proof_b = proxy_b.proof_for(pairs['B'][0])
    print('\nHandshake hashes are public transcript values, not secrets.')
    print('Proof A binds hash {}; proof B binds hash {}'.format(
        _short(proof_a.handshake_hash), _short(proof_b.handshake_hash)))

    print('\nCross-forwarding the proof from channel A into channel B:')
    try:
        _transplant(proof_a, pairs['B'][0], pairs['B'][1], verifier)
    except LoginProofError as exc:
        print('  rejected: {}'.format(exc))
        assert pairs['B'][1].authenticated_user is None
        print('  channel B server authenticated_user=None')

    print('Cross-forwarding the proof from channel B into channel A:')
    try:
        _transplant(proof_b, pairs['A'][0], pairs['A'][1], verifier)
    except LoginProofError as exc:
        print('  rejected: {}'.format(exc))
        assert pairs['A'][1].authenticated_user is None
        print('  channel A server authenticated_user=None')

    print('\nGenuine login on channel A:')
    _genuine_login(pairs['A'][0], pairs['A'][1], proxy_a, verifier)
    protected = pairs['A'][0].seal(b'read-account-balance')
    opened = pairs['A'][1].open(protected)
    print('  login accepted for user={!r}; protected operation round-trip={!r}'.format(
        pairs['A'][1].authenticated_user, opened.decode('utf-8')))

    print('Genuine login on channel B:')
    _genuine_login(pairs['B'][0], pairs['B'][1], proxy_b, verifier)
    protected = pairs['B'][0].seal(b'read-account-balance')
    opened = pairs['B'][1].open(protected)
    print('  login accepted for user={!r}; protected operation round-trip={!r}'.format(
        pairs['B'][1].authenticated_user, opened.decode('utf-8')))

    print('\nBoth cross-channel transfers were rejected; both genuine '
          'connections completed their own protected operation.')
    print('This example prevents cross-channel proof forwarding. It does not '
          'replace user authentication: the issuer is trusted to attest '
          'the user identity.')


if __name__ == '__main__':
    main()
