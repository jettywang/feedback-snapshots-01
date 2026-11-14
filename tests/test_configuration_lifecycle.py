import pytest

from noise.connection import Keypair, NoiseConnection
from noise.exceptions import (NoiseConfigurationFrozenError, NoiseInvalidMessage,
                              NoiseNegotiationError, NoisePSKError, NoiseProtocolNameError,
                              NoiseValidationError)
from noise.configuration import compose_prologue, parse_negotiation_prologue
from noise.negotiation import NegotiationRecord, negotiate

NN = b'Noise_NN_25519_ChaChaPoly_BLAKE2s'
NN_PSK = b'Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s'
OFFERS_INITIATOR = [NN, b'Noise_NN_448_ChaChaPoly_BLAKE2s']
OFFERS_RESPONDER = list(reversed(OFFERS_INITIATOR))


def make_pair(name=NN, record=None, initiator_prologue=b'', responder_prologue=b'',
              initiator_psks=None, responder_psks=None):
    initiator = NoiseConnection.from_name(name)
    responder = NoiseConnection.from_name(name)
    initiator.set_as_initiator()
    responder.set_as_responder()
    if record is not None:
        initiator.set_negotiation_record(record)
        responder.set_negotiation_record(record)
    if initiator_prologue:
        initiator.set_prologue(initiator_prologue)
    if responder_prologue:
        responder.set_prologue(responder_prologue)
    if initiator_psks is not None:
        initiator.set_psks(psks=initiator_psks)
    if responder_psks is not None:
        responder.set_psks(psks=responder_psks)
    return initiator, responder


def run_handshake(initiator, responder, messages=1):
    for _ in range(messages):
        message = initiator.write_message()
        assert responder.read_message(message) == b''
        message = responder.write_message()
        assert initiator.read_message(message) == b''


class TestNegotiationRecordEncoding(object):
    def test_contains_both_choices_and_offers(self):
        record = negotiate(OFFERS_INITIATOR, OFFERS_RESPONDER)
        assert record.initiator_choice == record.responder_choice == NN
        assert record.initiator_offers == tuple(OFFERS_INITIATOR)
        assert record.responder_offers == tuple(OFFERS_RESPONDER)
        assert NegotiationRecord.from_bytes(record.to_bytes()) == record

    def test_encoding_is_unambiguous(self):
        first = NegotiationRecord(b'Noise_NN_25519_ChaChaPoly_BLAKE2s',
                                  b'Noise_NN_25519_ChaChaPoly_BLAKE2s',
                                  (b'a', b'b'), (b'ab',))
        second = NegotiationRecord(b'Noise_NN_25519_ChaChaPoly_BLAKE2s',
                                   b'Noise_NN_25519_ChaChaPoly_BLAKE2s',
                                   (b'ab',), (b'a', b'b'))
        # Concatenating offer lists without length prefixes would collide here.
        assert first.to_bytes() != second.to_bytes()

    def test_tampered_encoding_is_rejected(self):
        encoded = negotiate(OFFERS_INITIATOR, OFFERS_RESPONDER).to_bytes()
        with pytest.raises(NoiseNegotiationError):
            NegotiationRecord.from_bytes(encoded[:-1])
        with pytest.raises(NoiseNegotiationError):
            NegotiationRecord.from_bytes(encoded + b'\x00')

    def test_record_must_match_connection_name(self):
        connection = NoiseConnection.from_name(NN)
        other = negotiate([b'Noise_NN_448_ChaChaPoly_BLAKE2s'],
                          [b'Noise_NN_448_ChaChaPoly_BLAKE2s'])
        with pytest.raises(NoiseNegotiationError):
            connection.set_negotiation_record(other)

    def test_original_offer_lists_do_not_own_record(self):
        initiator_offers = list(OFFERS_INITIATOR)
        responder_offers = list(OFFERS_RESPONDER)
        record = negotiate(initiator_offers, responder_offers)
        encoded = record.to_bytes()

        initiator_offers.clear()
        responder_offers.append(b'Noise_NN_25519_AESGCM_SHA256')

        assert record.to_bytes() == encoded
        assert record.initiator_offers == tuple(OFFERS_INITIATOR)


class TestNegotiationBinding(object):
    def test_consistent_negotiation_succeeds(self):
        record = negotiate(OFFERS_INITIATOR, OFFERS_RESPONDER)
        initiator, responder = make_pair(record=record, initiator_prologue=b'ctx',
                                        responder_prologue=b'ctx')
        initiator_configuration = initiator.start_handshake()
        responder_configuration = responder.start_handshake()

        assert initiator_configuration.prologue == responder_configuration.prologue
        assert initiator_configuration.negotiation_record == responder_configuration.negotiation_record
        run_handshake(initiator, responder)
        assert initiator.get_handshake_hash() == responder.get_handshake_hash()

    def test_tampered_record_fails_real_handshake(self):
        record = negotiate(OFFERS_INITIATOR, OFFERS_RESPONDER)
        tampered = record.replace(responder_offers=(b'Noise_NN_448_ChaChaPoly_BLAKE2s',))

        initiator, responder = make_pair(record=record, initiator_prologue=b'ctx',
                                        responder_prologue=b'ctx')
        responder.set_negotiation_record(tampered)

        initiator.start_handshake()
        responder.start_handshake()
        assert (initiator.startup_configuration.prologue !=
                responder.startup_configuration.prologue)

        message = initiator.write_message()
        responder.read_message(message)
        reply = responder.write_message()
        with pytest.raises(NoiseInvalidMessage):
            initiator.read_message(reply)

    def test_negotiation_record_is_part_of_prologue(self):
        plain = make_pair()[0]
        record = negotiate(OFFERS_INITIATOR, OFFERS_RESPONDER)
        negotiated = make_pair(record=record)[0]
        plain.start_handshake()
        negotiated.start_handshake()

        configuration = negotiated.startup_configuration
        assert configuration.negotiation_record.to_bytes() in configuration.prologue
        assert parse_negotiation_prologue(configuration.prologue) == (
            record, configuration.application_prologue)
        assert plain.startup_configuration.prologue != configuration.prologue

    def test_prologue_roundtrip_without_record(self):
        assert compose_prologue(b'ctx') == b'ctx'
        assert parse_negotiation_prologue(b'ctx') == (None, b'ctx')


class TestStartupFreeze(object):
    def test_setters_are_rejected_after_start(self):
        connection = make_pair()[0]
        connection.start_handshake()
        attempts = [
            lambda: connection.set_prologue(b'other'),
            lambda: connection.set_psks(b'\x00' * 32),
            connection.set_as_responder,
            connection.set_as_initiator,
            lambda: connection.set_keypair_from_private_bytes(Keypair.STATIC, b'\x00' * 32),
            lambda: connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, b'\x00' * 32),
        ]
        for attempt in attempts:
            with pytest.raises(NoiseConfigurationFrozenError):
                attempt()

    def test_direct_protocol_edits_are_rejected_after_start(self):
        connection = make_pair()[0]
        connection.start_handshake()
        protocol = connection.noise_protocol

        with pytest.raises(NoiseConfigurationFrozenError):
            protocol.initiator = False
        with pytest.raises(NoiseConfigurationFrozenError):
            protocol.prologue = b'other'
        with pytest.raises(NoiseConfigurationFrozenError):
            protocol.psks = [b'\x00' * 32]
        with pytest.raises(NoiseConfigurationFrozenError):
            protocol.keypairs['s'] = None
        with pytest.raises(NoiseConfigurationFrozenError):
            protocol.handshake_state.initiator = False
        with pytest.raises(NoiseConfigurationFrozenError):
            protocol.handshake_state.s = None
        with pytest.raises((NoiseConfigurationFrozenError, NoiseProtocolNameError)):
            protocol.name = NN
        with pytest.raises(NoiseConfigurationFrozenError):
            connection.protocol_name = NN

    @pytest.mark.filterwarnings('ignore: One of ephemeral keypairs')
    def test_rejected_edits_do_not_change_transcript(self):
        first_initiator, first_responder = make_pair(initiator_prologue=b'ctx',
                                                     responder_prologue=b'ctx')
        reference_initiator, reference_responder = make_pair(initiator_prologue=b'ctx',
                                                             responder_prologue=b'ctx')
        fixed_ephemeral = b'\x42' * 32
        for connection in (first_initiator, reference_initiator):
            connection.set_keypair_from_private_bytes(Keypair.EPHEMERAL, fixed_ephemeral)
        for connection in (first_responder, reference_responder):
            connection.set_keypair_from_private_bytes(Keypair.EPHEMERAL, fixed_ephemeral)

        first_initiator.start_handshake()
        first_responder.start_handshake()
        reference_initiator.start_handshake()
        reference_responder.start_handshake()

        with pytest.raises(NoiseConfigurationFrozenError):
            first_initiator.set_prologue(b'tampered')
        with pytest.raises(NoiseConfigurationFrozenError):
            first_initiator.noise_protocol.prologue = b'tampered'

        run_handshake(first_initiator, first_responder)
        run_handshake(reference_initiator, reference_responder)

        assert first_initiator.get_handshake_hash() == reference_initiator.get_handshake_hash()
        assert first_responder.get_handshake_hash() == reference_responder.get_handshake_hash()

    def test_audit_matches_snapshot_before_and_after_handshake(self):
        initiator, responder = make_pair(initiator_prologue=b'ctx',
                                        responder_prologue=b'ctx')
        initiator.start_handshake()
        responder.start_handshake()
        before = initiator.audit_configuration()

        run_handshake(initiator, responder)
        after = initiator.audit_configuration()

        assert before == after
        assert after['prologue_used'] == initiator.startup_configuration.prologue.hex()
        assert after['configuration_digest'] == initiator.startup_digest
        assert initiator.noise_protocol.configuration.prologue == \
            initiator.startup_configuration.prologue

    def test_audit_survives_completed_handshake(self):
        initiator, responder = make_pair(initiator_prologue=b'ctx',
                                        responder_prologue=b'ctx')
        initiator.start_handshake()
        responder.start_handshake()
        run_handshake(initiator, responder)

        audit = initiator.audit_configuration()
        assert audit['prologue_used'].startswith(b'ctx'.hex())
        assert audit['protocol_name'] == NN.decode()
        assert audit['configuration_digest'] == initiator.startup_digest
        assert responder.audit_configuration()['configuration_digest'] == responder.startup_digest


class TestCallerOwnershipAndInterleaving(object):
    def test_caller_psk_list_is_copied(self):
        psk = b'\x00' * 32
        psks = [psk]
        connection = NoiseConnection.from_name(NN_PSK)
        connection.set_as_initiator()
        connection.set_psks(psks=psks)

        psks[0] = b'\xff' * 32
        psks.append(b'\x11' * 32)

        configuration = connection.start_handshake()
        assert configuration.psks == (psk,)
        assert connection.noise_protocol.psks == (psk,)
        assert psks == [b'\xff' * 32, b'\x11' * 32]

    def test_last_setter_wins_and_is_auditable(self):
        first_psk = b'\x00' * 32
        second_psk = b'\x11' * 32
        connection = NoiseConnection.from_name(NN_PSK)
        connection.set_as_initiator()

        caller_owned = [first_psk]
        connection.set_psks(psks=caller_owned)
        caller_owned[0] = second_psk
        connection.set_psks(psks=caller_owned)

        configuration = connection.start_handshake()
        assert configuration.psks == (second_psk,)
        audit = connection.audit_configuration()
        assert audit['psk_digests'] == [
            __import__('hashlib').sha256(second_psk).hexdigest()
        ]

    def test_interleaved_mutation_and_setter_is_explained_by_audit(self):
        connection = NoiseConnection.from_name(NN)
        connection.set_as_initiator()
        context = bytearray(b'negotiated-context')
        connection.set_prologue(bytes(context))

        # The caller keeps ownership and mutates its own buffer; the earlier
        # setter must have committed a copy, not a view.
        committed = bytes(context)
        context[0:4] = b'MUTT'
        connection.set_prologue(bytes(context))

        connection.start_handshake()
        configuration = connection.startup_configuration
        assert configuration.prologue == bytes(context)
        assert configuration.prologue != committed
        assert connection.audit_configuration()['prologue_used'] == bytes(context).hex()

        # Mutating the caller buffer after startup cannot affect the transcript.
        context[0:4] = b'AFTR'
        assert configuration is connection.startup_configuration
        assert connection.audit_configuration()['prologue_used'] != bytes(context).hex()

    def test_later_setter_changes_effective_prologue(self):
        connection = NoiseConnection.from_name(NN)
        connection.set_as_initiator()
        connection.set_prologue(b'first')
        connection.start_handshake()

        other = NoiseConnection.from_name(NN)
        other.set_as_initiator()
        other.set_prologue(b'first')
        other.set_prologue(b'second')
        other.start_handshake()

        assert connection.startup_configuration.prologue == b'first'
        assert other.startup_configuration.prologue == b'second'
        assert connection.startup_digest != other.startup_digest


class TestExplicitPreflight(object):
    def test_validate_is_non_destructive_and_repeatable(self):
        connection = NoiseConnection.from_name(NN_PSK)
        connection.set_as_initiator()
        psks = [b'\x00' * 32]
        connection.set_psks(psks=psks)

        connection.validate()
        connection.validate()
        assert connection.startup_configuration is None
        assert connection.noise_protocol.psks == (psks[0],)

        configuration = connection.start_handshake()
        assert configuration.psks == (psks[0],)

    def test_validate_reports_missing_pre_start_inputs(self):
        connection = NoiseConnection.from_name(NN)
        with pytest.raises(NoiseValidationError):
            connection.validate()
        assert connection.startup_configuration is None

    def test_second_start_is_rejected(self):
        connection = make_pair()[0]
        first = connection.start_handshake()
        with pytest.raises(NoiseConfigurationFrozenError):
            connection.start_handshake()
        assert connection.startup_configuration is first


class TestFailedStartupIsRepeatable(object):
    def test_missing_role_does_not_consume_psks(self):
        connection = NoiseConnection.from_name(NN_PSK)
        psks = [b'\x00' * 32]
        connection.set_psks(psks=psks)

        with pytest.raises(NoiseValidationError):
            connection.start_handshake()
        assert connection.startup_configuration is None
        assert connection.noise_protocol.psks == (psks[0],)
        assert psks == [b'\x00' * 32]

        connection.set_as_initiator()
        configuration = connection.start_handshake()
        assert configuration.psks == (psks[0],)

    def test_bad_psk_count_can_be_corrected(self):
        connection = NoiseConnection.from_name(NN_PSK)
        connection.set_as_initiator()
        connection.set_psks(psks=[b'\x00' * 32, b'\x11' * 32])

        with pytest.raises(NoisePSKError):
            connection.start_handshake()
        assert connection.noise_protocol.psks == (b'\x00' * 32, b'\x11' * 32)

        connection.set_psks(psk=b'\x22' * 32)
        configuration = connection.start_handshake()
        assert configuration.psks == (b'\x22' * 32,)

    def test_failure_after_freeze_rolls_back(self, monkeypatch):
        connection = NoiseConnection.from_name(NN)
        connection.set_as_initiator()
        original = connection.noise_protocol.initialise_handshake_state
        calls = []

        def fail_once():
            calls.append(True)
            raise RuntimeError('simulated startup failure')

        monkeypatch.setattr(connection.noise_protocol, 'initialise_handshake_state', fail_once)
        with pytest.raises(RuntimeError):
            connection.start_handshake()
        assert connection.startup_configuration is None
        assert not connection.noise_protocol.frozen
        assert connection.noise_protocol.initiator is True

        monkeypatch.setattr(connection.noise_protocol, 'initialise_handshake_state', original)
        configuration = connection.start_handshake()
        assert configuration.psks == ()
        assert connection.noise_protocol.frozen
