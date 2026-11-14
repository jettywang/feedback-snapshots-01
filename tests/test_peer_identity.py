import pytest

from noise.backends.default.keypairs import KeyPair25519
from noise.connection import NoiseConnection, Keypair
from noise.exceptions import NoiseHandshakeError, NoiseIdentityError
from noise.identity import PeerAuthentication, PeerRole, PeerStaticKeySource

PROTOCOL = b'Noise_{}_25519_ChaChaPoly_SHA256'

# Deterministic private keys keep the evidence stable across runs.
LEGIT_INITIATOR_PRIVATE = bytes(range(0, 32))
LEGIT_RESPONDER_PRIVATE = bytes(range(32, 64))
ATTACKER_PRIVATE = bytes(range(64, 96))


def public_key(private_bytes):
    return KeyPair25519.from_private_bytes(private_bytes).public_bytes


LEGIT_INITIATOR_PUBLIC = public_key(LEGIT_INITIATOR_PRIVATE)
LEGIT_RESPONDER_PUBLIC = public_key(LEGIT_RESPONDER_PRIVATE)
ATTACKER_PUBLIC = public_key(ATTACKER_PRIVATE)


class IdentityRecorder(object):
    """Callback test double that records evidence and applies a policy."""

    def __init__(self, policy=None):
        self.calls = []
        self._policy = policy or (lambda evidence: True)

    def __call__(self, evidence):
        self.calls.append(evidence)
        return self._policy(evidence)

    @property
    def evidence(self):
        assert len(self.calls) == 1
        return self.calls[0]


def make_pair(pattern):
    initiator = NoiseConnection.from_name(PROTOCOL.replace(b'{}', pattern.encode()))
    responder = NoiseConnection.from_name(PROTOCOL.replace(b'{}', pattern.encode()))
    initiator.set_as_initiator()
    responder.set_as_responder()
    return initiator, responder


def set_static(connection, private_bytes):
    connection.set_keypair_from_private_bytes(Keypair.STATIC, private_bytes)


def set_remote_static(connection, public_bytes):
    connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, public_bytes)


def run_handshake(initiator, responder, payloads=None):
    """Drive an in-memory handshake, alternating from the initiator."""
    message_count = len(initiator.noise_protocol.pattern.tokens)
    if payloads is None:
        payloads = [b''] * message_count
    assert len(payloads) == message_count

    initiator.start_handshake()
    responder.start_handshake()

    sender, receiver = initiator, responder
    delivered = []
    for payload in payloads:
        ciphertext = sender.write_message(payload)
        delivered.append(receiver.read_message(ciphertext))
        sender, receiver = receiver, sender
    return delivered


def assert_no_usable_transport(connection):
    assert not connection.handshake_finished
    assert connection.handshake_aborted
    assert connection.noise_protocol.cipher_state_encrypt is None
    assert connection.noise_protocol.cipher_state_decrypt is None
    assert connection.get_peer_identity() is None
    with pytest.raises(NoiseHandshakeError):
        connection.encrypt(b'payload')
    with pytest.raises(NoiseHandshakeError):
        connection.decrypt(b'payload')
    with pytest.raises(NoiseHandshakeError):
        connection.write_message(b'payload')
    with pytest.raises(NoiseHandshakeError):
        connection.read_message(b'payload')


class TestIdentityEvidence(object):
    def test_completed_handshakes_yield_different_identity_conclusions(self):
        """NN, XX, and preset-key IK all complete crypto but conclude differently."""
        nn_init, nn_resp = make_pair('NN')
        nn_init_rec, nn_resp_rec = IdentityRecorder(), IdentityRecorder()
        nn_init.set_peer_identity_verifier(nn_init_rec)
        nn_resp.set_peer_identity_verifier(nn_resp_rec)
        run_handshake(nn_init, nn_resp)

        xx_init, xx_resp = make_pair('XX')
        set_static(xx_init, LEGIT_INITIATOR_PRIVATE)
        set_static(xx_resp, LEGIT_RESPONDER_PRIVATE)
        xx_init_rec, xx_resp_rec = IdentityRecorder(), IdentityRecorder()
        xx_init.set_peer_identity_verifier(xx_init_rec)
        xx_resp.set_peer_identity_verifier(xx_resp_rec)
        run_handshake(xx_init, xx_resp)

        ik_init, ik_resp = make_pair('IK')
        set_static(ik_init, LEGIT_INITIATOR_PRIVATE)
        set_remote_static(ik_init, LEGIT_RESPONDER_PUBLIC)
        set_static(ik_resp, LEGIT_RESPONDER_PRIVATE)
        ik_init_rec, ik_resp_rec = IdentityRecorder(), IdentityRecorder()
        ik_init.set_peer_identity_verifier(ik_init_rec)
        ik_resp.set_peer_identity_verifier(ik_resp_rec)
        run_handshake(ik_init, ik_resp)

        for connection in (nn_init, nn_resp, xx_init, xx_resp, ik_init, ik_resp):
            assert connection.handshake_finished

        # ZZ transport is usable in every successful case.
        assert nn_resp.decrypt(nn_init.encrypt(b'nn')) == b'nn'
        assert xx_resp.decrypt(xx_init.encrypt(b'xx')) == b'xx'
        assert ik_resp.decrypt(ik_init.encrypt(b'ik')) == b'ik'

        nn = nn_init_rec.evidence
        assert nn.pattern == 'NN'
        assert nn.protocol_name == b'Noise_NN_25519_ChaChaPoly_SHA256'
        assert nn.role == PeerRole.INITIATOR
        assert nn.peer_static_public_key is None
        assert nn.peer_static_key_source == PeerStaticKeySource.NONE
        assert nn.peer_static_key_proven is False
        assert nn.peer_authentication == PeerAuthentication.NONE
        assert nn.peer_identity_available is False
        assert nn.handshake_hash == nn_init.get_handshake_hash()
        assert nn_resp_rec.evidence.peer_authentication == PeerAuthentication.NONE

        xx = xx_init_rec.evidence
        assert xx.pattern == 'XX'
        assert xx.role == PeerRole.INITIATOR
        assert xx.peer_static_public_key == LEGIT_RESPONDER_PUBLIC
        assert xx.peer_static_key_source == PeerStaticKeySource.OBSERVED
        assert xx.peer_static_key_proven is True
        assert xx.peer_authentication == PeerAuthentication.STATIC
        assert xx.handshake_hash == xx_resp_rec.evidence.handshake_hash
        assert xx_resp_rec.evidence.peer_static_public_key == LEGIT_INITIATOR_PUBLIC
        assert xx_resp_rec.evidence.peer_static_key_source == PeerStaticKeySource.OBSERVED

        ik = ik_init_rec.evidence
        assert ik.pattern == 'IK'
        assert ik.role == PeerRole.INITIATOR
        assert ik.peer_static_public_key == LEGIT_RESPONDER_PUBLIC
        # The initiator had this key before the handshake; it was not observed.
        assert ik.peer_static_key_source == PeerStaticKeySource.CONFIGURED
        assert ik.peer_static_key_proven is True
        assert ik.peer_authentication == PeerAuthentication.STATIC
        assert ik.handshake_hash == ik_resp_rec.evidence.handshake_hash
        assert ik_resp_rec.evidence.peer_static_public_key == LEGIT_INITIATOR_PUBLIC
        assert ik_resp_rec.evidence.peer_static_key_source == PeerStaticKeySource.OBSERVED
        assert ik_resp_rec.evidence.peer_static_key_proven is True

    def test_gratuitous_configured_key_is_not_peer_evidence_for_nn(self):
        """A key the pattern never uses must not be presented as peer identity."""
        initiator, responder = make_pair('NN')
        set_remote_static(initiator, LEGIT_RESPONDER_PUBLIC)
        set_remote_static(responder, ATTACKER_PUBLIC)
        init_rec, resp_rec = IdentityRecorder(), IdentityRecorder()
        initiator.set_peer_identity_verifier(init_rec)
        responder.set_peer_identity_verifier(resp_rec)

        run_handshake(initiator, responder)

        for recorder in (init_rec, resp_rec):
            evidence = recorder.evidence
            assert evidence.pattern == 'NN'
            assert evidence.peer_static_public_key is None
            assert evidence.peer_static_key_source == PeerStaticKeySource.NONE
            assert evidence.peer_authentication == PeerAuthentication.NONE

    def test_one_way_x_responder_has_no_initiator_identity_proof(self):
        """X lets the responder verify the initiator, not the reverse."""
        initiator = NoiseConnection.from_name(PROTOCOL.replace(b'{}', b'X'))
        responder = NoiseConnection.from_name(PROTOCOL.replace(b'{}', b'X'))
        initiator.set_as_initiator()
        responder.set_as_responder()
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_remote_static(initiator, LEGIT_RESPONDER_PUBLIC)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)
        set_remote_static(responder, LEGIT_INITIATOR_PUBLIC)
        init_rec, resp_rec = IdentityRecorder(), IdentityRecorder()
        initiator.set_peer_identity_verifier(init_rec)
        responder.set_peer_identity_verifier(resp_rec)

        run_handshake(initiator, responder)

        # The initiator only knew the responder key; it never sees proof of
        # possession because the responder sends no message at all.
        assert init_rec.evidence.peer_static_key_source == PeerStaticKeySource.CONFIGURED
        assert init_rec.evidence.peer_static_key_proven is False
        assert init_rec.evidence.peer_authentication == PeerAuthentication.STATIC_UNPROVEN
        # The responder decrypts the initiator's static key and payload, so
        # possession of the initiator's key is proven.
        assert resp_rec.evidence.peer_static_public_key == LEGIT_INITIATOR_PUBLIC
        assert resp_rec.evidence.peer_static_key_proven is True
        assert resp_rec.evidence.peer_authentication == PeerAuthentication.STATIC

    def test_ix_responder_does_not_gain_initiator_identity(self):
        """IX authenticates the responder to the initiator, not the reverse."""
        initiator = NoiseConnection.from_name(PROTOCOL.replace(b'{}', b'IX'))
        responder = NoiseConnection.from_name(PROTOCOL.replace(b'{}', b'IX'))
        initiator.set_as_initiator()
        responder.set_as_responder()
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)
        init_rec, resp_rec = IdentityRecorder(), IdentityRecorder()
        initiator.set_peer_identity_verifier(init_rec)
        responder.set_peer_identity_verifier(resp_rec)

        run_handshake(initiator, responder)

        assert init_rec.evidence.peer_static_public_key == LEGIT_RESPONDER_PUBLIC
        assert init_rec.evidence.peer_static_key_proven is True
        assert init_rec.evidence.peer_authentication == PeerAuthentication.STATIC
        assert resp_rec.evidence.peer_static_public_key == LEGIT_INITIATOR_PUBLIC
        assert resp_rec.evidence.peer_static_key_proven is False
        assert resp_rec.evidence.peer_authentication == PeerAuthentication.STATIC_UNPROVEN

    def test_kn_is_void_of_authentication(self):
        """KN has no authentication, even though static keys are configured."""
        initiator = NoiseConnection.from_name(PROTOCOL.replace(b'{}', b'KN'))
        responder = NoiseConnection.from_name(PROTOCOL.replace(b'{}', b'KN'))
        initiator.set_as_initiator()
        responder.set_as_responder()
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_remote_static(initiator, LEGIT_RESPONDER_PUBLIC)
        set_remote_static(responder, LEGIT_INITIATOR_PUBLIC)
        init_rec, resp_rec = IdentityRecorder(), IdentityRecorder()
        initiator.set_peer_identity_verifier(init_rec)
        responder.set_peer_identity_verifier(resp_rec)

        run_handshake(initiator, responder)

        # The initiator's peer has no static key in KN at all.
        assert init_rec.evidence.peer_static_public_key is None
        assert init_rec.evidence.peer_authentication == PeerAuthentication.NONE
        # The responder learns the initiator's static key from the pre-message
        # and uses it in "se", but never receives an authenticated message.
        assert resp_rec.evidence.peer_static_public_key == LEGIT_INITIATOR_PUBLIC
        assert resp_rec.evidence.peer_static_key_proven is False
        assert resp_rec.evidence.peer_authentication == PeerAuthentication.STATIC_UNPROVEN

    def test_admission_flags_require_an_explicit_accepting_callback(self):
        initiator, responder = make_pair('NN')
        run_handshake(initiator, responder)
        assert initiator.handshake_finished
        assert initiator.get_peer_identity() is not None
        assert initiator.peer_admitted is False
        assert initiator.peer_identity_admitted is False

        # A callback may allow anonymous NN, but it still admitted no identity.
        anonymous_initiator, anonymous_responder = make_pair('NN')
        anonymous_initiator.set_peer_identity_verifier(lambda evidence: True)
        anonymous_responder.set_peer_identity_verifier(lambda evidence: True)
        run_handshake(anonymous_initiator, anonymous_responder)
        assert anonymous_initiator.peer_admitted is True
        assert anonymous_initiator.peer_identity_admitted is False
        assert anonymous_initiator.get_peer_identity().peer_authentication == \
            PeerAuthentication.NONE

        accepting_initiator, accepting_responder = make_pair('XX')
        set_static(accepting_initiator, LEGIT_INITIATOR_PRIVATE)
        set_static(accepting_responder, LEGIT_RESPONDER_PRIVATE)
        accepting_initiator.set_peer_identity_verifier(lambda evidence: True)
        accepting_responder.set_peer_identity_verifier(lambda evidence: True)
        run_handshake(accepting_initiator, accepting_responder)
        assert accepting_initiator.peer_admitted is True
        assert accepting_initiator.peer_identity_admitted is True
        assert accepting_responder.peer_identity_admitted is True

    def test_evidence_is_an_immutable_snapshot(self):
        initiator, responder = make_pair('NN')
        recorder = IdentityRecorder()
        responder.set_peer_identity_verifier(recorder)
        run_handshake(initiator, responder)

        evidence = recorder.evidence
        with pytest.raises(AttributeError):
            evidence.peer_static_key_proven = True
        with pytest.raises(AttributeError):
            evidence.handshake_hash = b'forged'
        assert evidence.peer_static_key_proven is False

    def test_callback_runs_once_with_final_evidence(self):
        initiator, responder = make_pair('NN')
        recorder = IdentityRecorder()
        responder.set_peer_identity_verifier(recorder)
        run_handshake(initiator, responder)
        assert len(recorder.calls) == 1
        assert recorder.evidence.handshake_hash == responder.get_handshake_hash()

    def test_configured_expected_key_is_not_reported_as_observed(self):
        """A value set with set_keypair_from_public_bytes is not peer evidence."""
        initiator, responder = make_pair('XX')
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)
        # The application expects a different key than the peer will send.
        set_remote_static(initiator, ATTACKER_PUBLIC)

        # A policy that trusts only the configured expectation must reject,
        # because the observed key is the peer's real key, not the configured one.
        def only_configured_expectation(evidence):
            return evidence.peer_static_public_key == ATTACKER_PUBLIC

        recorder = IdentityRecorder(only_configured_expectation)
        initiator.set_peer_identity_verifier(recorder)

        initiator.start_handshake()
        responder.start_handshake()
        responder.read_message(initiator.write_message(b'one'))
        initiator.read_message(responder.write_message(b'two'))
        with pytest.raises(NoiseIdentityError) as exc_info:
            initiator.write_message(b'three')

        evidence = recorder.evidence
        assert evidence.pattern == 'XX'
        assert evidence.peer_static_public_key == LEGIT_RESPONDER_PUBLIC
        assert evidence.peer_static_public_key != ATTACKER_PUBLIC
        assert evidence.peer_static_key_source == PeerStaticKeySource.OBSERVED
        assert evidence.peer_static_key_proven is True
        assert exc_info.value.evidence is evidence
        assert_no_usable_transport(initiator)
        assert not responder.handshake_finished


class TestAdmissionDecisions(object):
    def test_legitimate_preset_key_is_admitted(self):
        initiator, responder = make_pair('IK')
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_remote_static(initiator, LEGIT_RESPONDER_PUBLIC)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)
        recorder = IdentityRecorder(lambda evidence: evidence.peer_static_public_key in (
            LEGIT_INITIATOR_PUBLIC, LEGIT_RESPONDER_PUBLIC))
        initiator.set_peer_identity_verifier(recorder)
        responder.set_peer_identity_verifier(recorder)

        run_handshake(initiator, responder, payloads=[b'first', b'second'])
        assert initiator.handshake_finished and responder.handshake_finished
        assert responder.decrypt(initiator.encrypt(b'hello')) == b'hello'
        assert initiator.get_peer_identity().peer_authentication == PeerAuthentication.STATIC

    def test_impersonating_a_configured_peer_never_reaches_admission(self):
        """The attacker does not hold the configured key, so crypto fails first."""
        initiator, attacker = make_pair('IK')
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_remote_static(initiator, LEGIT_RESPONDER_PUBLIC)
        set_static(attacker, ATTACKER_PRIVATE)
        recorder = IdentityRecorder()
        initiator.set_peer_identity_verifier(recorder)
        attacker.set_peer_identity_verifier(recorder)

        initiator.start_handshake()
        attacker.start_handshake()
        ciphertext = initiator.write_message(b'hello')
        with pytest.raises(Exception) as exc_info:
            attacker.read_message(ciphertext)

        assert 'InvalidTag' in type(exc_info.value).__name__
        assert recorder.calls == []
        assert not initiator.handshake_finished
        assert not attacker.handshake_finished
        assert initiator.get_peer_identity() is None
        assert attacker.get_peer_identity() is None
        for connection in (initiator, attacker):
            with pytest.raises(NoiseHandshakeError):
                connection.encrypt(b'payload')

    def test_unknown_preset_key_fails_to_complete(self):
        """An initiator keyed to a different responder cannot finish IK."""
        initiator, responder = make_pair('IK')
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_remote_static(initiator, ATTACKER_PUBLIC)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)
        recorder = IdentityRecorder()
        initiator.set_peer_identity_verifier(recorder)
        responder.set_peer_identity_verifier(recorder)

        initiator.start_handshake()
        responder.start_handshake()
        with pytest.raises(Exception) as exc_info:
            responder.read_message(initiator.write_message(b'hello'))

        assert 'InvalidTag' in type(exc_info.value).__name__
        assert recorder.calls == []
        assert not initiator.handshake_finished
        assert not responder.handshake_finished

    def test_unknown_observed_key_is_rejected_by_policy(self):
        """A cryptographically proven key is still subject to application trust."""
        attacker, responder = make_pair('IK')
        set_static(attacker, ATTACKER_PRIVATE)
        set_remote_static(attacker, LEGIT_RESPONDER_PUBLIC)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)

        def trust_only_legit_initiator(evidence):
            return evidence.peer_static_public_key == LEGIT_INITIATOR_PUBLIC

        recorder = IdentityRecorder(trust_only_legit_initiator)
        responder.set_peer_identity_verifier(recorder)

        attacker.start_handshake()
        responder.start_handshake()
        responder.read_message(attacker.write_message(b'hello'))
        # In IK the responder completes its own side after writing message 2.
        with pytest.raises(NoiseIdentityError) as exc_info:
            responder.write_message(b'hello-back')

        evidence = recorder.evidence
        assert evidence.pattern == 'IK'
        assert evidence.role == PeerRole.RESPONDER
        assert evidence.peer_static_public_key == ATTACKER_PUBLIC
        assert evidence.peer_static_key_source == PeerStaticKeySource.OBSERVED
        assert evidence.peer_static_key_proven is True
        assert exc_info.value.evidence is evidence
        assert_no_usable_transport(responder)
        assert not attacker.handshake_finished
        assert attacker.get_peer_identity() is None

    def test_rejection_withholds_final_payload_and_transport(self):
        initiator, responder = make_pair('XX')
        set_static(initiator, LEGIT_INITIATOR_PRIVATE)
        set_static(responder, LEGIT_RESPONDER_PRIVATE)
        recorder = IdentityRecorder(lambda evidence: False)
        initiator.set_peer_identity_verifier(recorder)

        initiator.start_handshake()
        responder.start_handshake()
        responder.read_message(initiator.write_message(b'one'))
        initiator.read_message(responder.write_message(b'two'))
        # The initiator passes its static key and a payload in message 3. The
        # rejection must discard both, and the responder must not complete.
        with pytest.raises(NoiseIdentityError):
            initiator.write_message(b'final-payload')

        assert len(recorder.calls) == 1
        assert_no_usable_transport(initiator)
        assert not responder.handshake_finished
        # No final message was produced, so the responder cannot complete by
        # feeding an empty or fabricated message.
        with pytest.raises(Exception):
            responder.read_message(b'')
        assert not responder.handshake_finished

    def test_responder_rejection_withholds_its_final_payload(self):
        initiator, responder = make_pair('NN')
        recorder = IdentityRecorder(lambda evidence: False)
        responder.set_peer_identity_verifier(recorder)

        initiator.start_handshake()
        responder.start_handshake()
        responder.read_message(initiator.write_message(b'one'))
        with pytest.raises(NoiseIdentityError):
            responder.write_message(b'final-payload')

        assert len(recorder.calls) == 1
        assert_no_usable_transport(responder)
        assert not initiator.handshake_finished

    def test_callback_exception_is_wrapped_and_blocks_transport(self):
        initiator, responder = make_pair('NN')
        recorder = IdentityRecorder()

        def broken_policy(evidence):
            raise RuntimeError('policy store unavailable')

        recorder._policy = broken_policy
        responder.set_peer_identity_verifier(recorder)

        initiator.start_handshake()
        responder.start_handshake()
        responder.read_message(initiator.write_message(b'one'))
        with pytest.raises(NoiseIdentityError) as exc_info:
            responder.write_message(b'final-payload')

        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert exc_info.value.evidence is recorder.evidence
        assert_no_usable_transport(responder)

    def test_abort_is_sticky(self):
        initiator, responder = make_pair('NN')
        recorder = IdentityRecorder(lambda evidence: False)
        responder.set_peer_identity_verifier(recorder)
        initiator.start_handshake()
        responder.start_handshake()
        responder.read_message(initiator.write_message(b'one'))
        with pytest.raises(NoiseIdentityError):
            responder.write_message(b'final')

        with pytest.raises(NoiseHandshakeError):
            responder.start_handshake()
        with pytest.raises(NoiseHandshakeError):
            responder.rekey_inbound_cipher()
        with pytest.raises(NoiseHandshakeError):
            responder.rekey_outbound_cipher()

    def test_callback_can_be_removed_before_start(self):
        initiator, responder = make_pair('NN')
        recorder = IdentityRecorder(lambda evidence: False)
        responder.set_peer_identity_verifier(recorder)
        responder.set_peer_identity_verifier(None)
        run_handshake(initiator, responder)
        assert recorder.calls == []
        assert responder.handshake_finished

    def test_callback_must_be_callable(self):
        connection, _ = make_pair('NN')
        with pytest.raises(Exception):
            connection.set_peer_identity_verifier('not callable')
