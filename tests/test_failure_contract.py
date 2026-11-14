import pytest

from noise.connection import NoiseConnection
from noise.exceptions import NoiseHandshakeError, NoiseValidationError, NoiseValueError

XX_NAME = b'Noise_XX_25519_AESGCM_SHA256'
XXPSK0_NAME = b'Noise_XXpsk0_25519_ChaChaPoly_SHA256'
XXPSK2_NAME = b'Noise_XXpsk2_25519_AESGCM_SHA256'
NNPSK0_NAME = b'Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s'

PSK = b'\x00' * 32
WRONG_PSK = b'\x01' * 32


def make_pair(name=XX_NAME, psk=None, wrong_psk=False):
    left = NoiseConnection.from_name(name)
    right = NoiseConnection.from_name(name)
    if psk is not None:
        left.set_psks(psk)
        right.set_psks(WRONG_PSK if wrong_psk else psk)
    left.set_as_initiator()
    right.set_as_responder()
    left.noise_protocol.keypairs['s'] = left.noise_protocol.dh_fn.generate_keypair()
    right.noise_protocol.keypairs['s'] = right.noise_protocol.dh_fn.generate_keypair()
    left.start_handshake()
    right.start_handshake()
    return left, right


def complete_xx_handshake(left, right):
    right.read_message(left.write_message())
    left.read_message(right.write_message())
    right.read_message(left.write_message())
    assert left.handshake_finished
    assert right.handshake_finished
    assert left.get_handshake_hash() == right.get_handshake_hash()


def assert_terminated_contract(conn):
    assert conn.terminated
    entry_points = [
        lambda: conn.start_handshake(),
        lambda: conn.write_message(),
        lambda: conn.read_message(b'\x00' * 96),
        lambda: conn.encrypt(b'data'),
        lambda: conn.decrypt(b'data'),
        lambda: conn.rekey_inbound_cipher(),
        lambda: conn.rekey_outbound_cipher(),
        lambda: conn.get_handshake_hash(),
    ]
    for call in entry_points:
        with pytest.raises(NoiseHandshakeError) as excinfo:
            call()
        assert 'terminated' in str(excinfo.value)
        assert excinfo.value.__cause__ is not None


class TestXXFailureContract:
    def test_encoding_failure_at_e_token(self):
        left, right = make_pair()
        message = left.write_message()
        with pytest.raises(NoiseValueError):
            right.read_message(bytes(message[:16]))
        assert_terminated_contract(right)

    def test_dh_failure_at_ee_token(self, monkeypatch):
        left, right = make_pair()
        right.read_message(left.write_message())

        def failing_dh(*args):
            raise ValueError('injected DH failure')

        monkeypatch.setattr(right.noise_protocol.dh_fn, 'dh', failing_dh)
        with pytest.raises(ValueError):
            right.write_message()
        assert_terminated_contract(right)

    def test_authentication_failure_at_s_token(self):
        left, right = make_pair()
        right.read_message(left.write_message())
        message = bytearray(right.write_message())
        message[40] ^= 1
        with pytest.raises(Exception):
            left.read_message(bytes(message))
        assert_terminated_contract(left)

    def test_authentication_failure_at_payload(self):
        left, right = make_pair()
        right.read_message(left.write_message())
        left.read_message(right.write_message())
        message = bytearray(left.write_message())
        message[-1] ^= 1
        with pytest.raises(Exception):
            right.read_message(bytes(message))
        assert_terminated_contract(right)

    def test_partial_write_output_not_returned(self, monkeypatch):
        left, right = make_pair()
        right.read_message(left.write_message())

        def failing_dh(*args):
            raise ValueError('injected DH failure')

        monkeypatch.setattr(right.noise_protocol.dh_fn, 'dh', failing_dh)
        result = None
        with pytest.raises(ValueError):
            result = right.write_message()
        assert result is None
        assert not right.handshake_finished

    def test_fresh_connections_still_handshake_after_failure(self):
        left, right = make_pair()
        with pytest.raises(NoiseValueError):
            right.read_message(bytes(left.write_message()[:16]))
        assert_terminated_contract(right)

        fresh_left, fresh_right = make_pair()
        complete_xx_handshake(fresh_left, fresh_right)
        ciphertext = fresh_left.encrypt(b'still works')
        assert fresh_right.decrypt(ciphertext) == b'still works'


class TestPSKFailureContract:
    def test_injected_failure_at_psk_token(self, monkeypatch):
        left, right = make_pair(XXPSK0_NAME, psk=PSK)

        def failing_mix(*args):
            raise ValueError('injected psk token failure')

        monkeypatch.setattr(right.noise_protocol.symmetric_state, 'mix_key_and_hash', failing_mix)
        with pytest.raises(ValueError):
            right.read_message(left.write_message())
        assert_terminated_contract(right)

    def test_mismatched_psk_fails_first_message(self):
        left, right = make_pair(NNPSK0_NAME, psk=PSK, wrong_psk=True)
        with pytest.raises(Exception):
            right.read_message(left.write_message())
        assert_terminated_contract(right)

    def test_mismatched_psk_fails_second_message(self):
        left, right = make_pair(XXPSK2_NAME, psk=PSK, wrong_psk=True)
        right.read_message(left.write_message())
        with pytest.raises(Exception):
            left.read_message(right.write_message())
        assert_terminated_contract(left)

    def test_fresh_connections_still_handshake_after_psk_failure(self):
        left, right = make_pair(NNPSK0_NAME, psk=PSK, wrong_psk=True)
        with pytest.raises(Exception):
            right.read_message(left.write_message())
        assert_terminated_contract(right)

        fresh_left, fresh_right = make_pair(NNPSK0_NAME, psk=PSK)
        fresh_right.read_message(fresh_left.write_message())
        fresh_left.read_message(fresh_right.write_message())
        assert fresh_left.handshake_finished
        assert fresh_right.handshake_finished


class TestRetryBeforeStateTouched:
    def test_wrong_turn_does_not_terminate(self):
        left, right = make_pair()
        with pytest.raises(NoiseHandshakeError):
            left.read_message(b'\x00' * 32)
        assert not left.terminated
        complete_xx_handshake(left, right)

    def test_read_before_start_does_not_terminate(self):
        conn = NoiseConnection.from_name(XX_NAME)
        conn.set_as_responder()
        with pytest.raises(NoiseHandshakeError):
            conn.read_message(b'\x00' * 32)
        assert not conn.terminated

    def test_failed_start_handshake_is_retryable(self):
        conn = NoiseConnection.from_name(XX_NAME)
        conn.set_as_initiator()
        with pytest.raises(NoiseValidationError):
            conn.start_handshake()
        assert not conn.terminated

        conn.noise_protocol.keypairs['s'] = conn.noise_protocol.dh_fn.generate_keypair()
        conn.start_handshake()
        assert conn._handshake_started

    def test_write_after_finish_does_not_terminate(self):
        left, right = make_pair()
        complete_xx_handshake(left, right)
        with pytest.raises(NoiseHandshakeError):
            left.write_message()
        assert not left.terminated
        ciphertext = left.encrypt(b'transport still fine')
        assert right.decrypt(ciphertext) == b'transport still fine'
