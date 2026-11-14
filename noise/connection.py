from enum import Enum
from typing import Union, List

from cryptography.exceptions import InvalidTag

from noise.backends.default import noise_backend
from noise.constants import MAX_MESSAGE_LEN
from noise.exceptions import (NoiseConfigurationError, NoiseConfigurationFrozenError,
                              NoiseHandshakeError, NoiseInvalidMessage, NoiseNegotiationError,
                              NoiseProtocolNameError, NoisePSKError, NoiseValueError)
from noise.negotiation import NegotiationRecord
from .noise_protocol import NoiseProtocol


class Keypair(Enum):
    STATIC = 1
    REMOTE_STATIC = 2
    EPHEMERAL = 3
    REMOTE_EPHEMERAL = 4


_keypairs = {Keypair.STATIC: 's', Keypair.REMOTE_STATIC: 'rs',
             Keypair.EPHEMERAL: 'e', Keypair.REMOTE_EPHEMERAL: 're'}


class NoiseConnection(object):
    def __init__(self):
        self.backend = None
        self._noise_protocol = None
        self.handshake_finished = False
        self._handshake_started = False
        self._next_fn = None

    @property
    def noise_protocol(self):
        return self._noise_protocol

    @classmethod
    def from_name(cls, name: Union[str, bytes], backend=noise_backend):
        instance = cls()
        # Forgiving passing string. Bytes are good too, anything else will fail inside NoiseProtocol
        try:
            protocol_name = name.encode('ascii') if isinstance(name, str) else name
        except ValueError:
            raise NoiseValueError('If passing string as protocol name, it must contain only ASCII characters')
        instance.backend = backend
        instance._noise_protocol = NoiseProtocol(protocol_name=protocol_name, backend=backend)
        return instance

    @property
    def protocol_name(self):
        return None if self._noise_protocol is None else self._noise_protocol.protocol_name

    @protocol_name.setter
    def protocol_name(self, value):
        # Pattern and crypto functions are derived at construction time.
        self._ensure_mutable()
        raise NoiseProtocolNameError(
            'Protocol name is fixed at construction; create a new NoiseConnection instead')

    @property
    def startup_configuration(self):
        """The immutable configuration captured by start_handshake()."""
        if self._noise_protocol is None:
            return None
        return self._noise_protocol.startup_configuration

    @property
    def startup_digest(self):
        configuration = self.startup_configuration
        return None if configuration is None else configuration.hexdigest

    @property
    def negotiation_record(self):
        if self._noise_protocol is None:
            return None
        return self._noise_protocol.negotiation_record

    def audit_configuration(self):
        """
        Describe the exact startup configuration that entered the handshake
        hash, including both sides' negotiation choices.
        """
        configuration = self.startup_configuration
        if configuration is None:
            raise NoiseConfigurationError('Handshake has not been started')
        return configuration.audit()

    def _ensure_mutable(self):
        if self._handshake_started:
            raise NoiseConfigurationFrozenError(
                'Startup configuration is frozen; setters may only be called before start_handshake')

    def set_negotiation_record(self, record: Union[NegotiationRecord, bytes]):
        self._ensure_mutable()
        if isinstance(record, (bytes, bytearray, memoryview)):
            record = NegotiationRecord.from_bytes(record)
        if not isinstance(record, NegotiationRecord):
            raise NoiseNegotiationError('Negotiation record must be a NegotiationRecord')
        if record.initiator_choice != record.responder_choice:
            raise NoiseNegotiationError('Both parties must select the same protocol')
        if record.initiator_choice != self.protocol_name:
            raise NoiseNegotiationError(
                'Negotiated protocol {!r} does not match connection protocol {!r}'.format(
                    record.initiator_choice, self.protocol_name))
        self.noise_protocol.negotiation_record = record

    def set_psks(self, psk: Union[bytes, str] = None, psks: List[Union[str, bytes]] = None):
        self._ensure_mutable()
        if psk and psks:
            raise NoisePSKError('Provide single PSK as psk or list of PSKs as psks')
        if not psk and not psks:
            raise NoisePSKError('No PSKs provided')

        psks = psks or [psk]
        if not all([isinstance(psk, (bytes, str, bytearray, memoryview)) for psk in psks]):
            raise NoisePSKError('PSKs must be strings or bytes')

        try:
            # Copy caller-owned byte strings and never mutate or retain the caller's list.
            converted = [psk.encode('ascii') if isinstance(psk, str) else bytes(psk) for psk in psks]
        except UnicodeEncodeError:
            raise NoisePSKError('If providing psks as (unicode) string, it must only contain ASCII characters')
        self.noise_protocol.psks = converted

    def set_prologue(self, prologue: Union[bytes, str]):
        self._ensure_mutable()
        if isinstance(prologue, (bytes, bytearray, memoryview)):
            self.noise_protocol.application_prologue = bytes(prologue)
        elif isinstance(prologue, str):
            try:
                self.noise_protocol.application_prologue = prologue.encode('ascii')
            except UnicodeEncodeError:
                raise NoiseValueError('Prologue must be ASCII string or bytes')
        else:
            raise NoiseValueError('Prologue must be ASCII string or bytes')

    def set_as_initiator(self):
        self._ensure_mutable()
        self.noise_protocol.initiator = True
        self._next_fn = self.write_message

    def set_as_responder(self):
        self._ensure_mutable()
        self.noise_protocol.initiator = False
        self._next_fn = self.read_message

    def _set_keypair(self, keypair: Keypair, value):
        self._ensure_mutable()
        self.noise_protocol.keypairs[_keypairs[keypair]] = value

    def set_keypair_from_private_bytes(self, keypair: Keypair, private_bytes: bytes):
        self._ensure_mutable()
        self._set_keypair(
            keypair,
            self.noise_protocol.dh_fn.klass.from_private_bytes(bytes(private_bytes)))

    def set_keypair_from_public_bytes(self, keypair: Keypair, private_bytes: bytes):
        self._ensure_mutable()
        self._set_keypair(
            keypair,
            self.noise_protocol.dh_fn.klass.from_public_bytes(bytes(private_bytes)))

    def set_keypair_from_private_path(self, keypair: Keypair, path: str):
        self._ensure_mutable()
        with open(path, 'rb') as fd:
            self._set_keypair(
                keypair,
                self.noise_protocol.dh_fn.klass.from_private_bytes(fd.read()))

    def set_keypair_from_public_path(self, keypair: Keypair, path: str):
        self._ensure_mutable()
        with open(path, 'rb') as fd:
            self._set_keypair(
                keypair,
                self.noise_protocol.dh_fn.klass.from_public_bytes(fd.read()))

    def validate(self):
        """
        Check the configuration without consuming PSKs or changing any state.

        This is the explicit preflight form of the checks performed by
        start_handshake(). It is safe to call repeatedly and to correct a
        rejected configuration afterwards.
        """
        self._ensure_mutable()
        self.noise_protocol.validate()

    def start_handshake(self):
        """
        Validate, freeze and start one and only one handshake configuration.

        Returns the immutable ``StartupConfiguration`` that was bound. Any
        validation failure leaves the pre-start configuration usable and
        unconsumed; a failure after freezing rolls it back.
        """
        self._ensure_mutable()
        self.noise_protocol.start()
        self._handshake_started = True
        return self.startup_configuration

    def write_message(self, payload: bytes=b'') -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError('Call NoiseConnection.start_handshake first')
        if self._next_fn != self.write_message:
            raise NoiseHandshakeError('NoiseConnection.read_message has to be called now')
        if self.handshake_finished:
            raise NoiseHandshakeError('Handshake finished. NoiseConnection.encrypt should be used now')
        self._next_fn = self.read_message

        buffer = bytearray()
        result = self.noise_protocol.handshake_state.write_message(payload, buffer)
        if result:
            self.handshake_finished = True
        return buffer

    def read_message(self, data: bytes) -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError('Call NoiseConnection.start_handshake first')
        if self._next_fn != self.read_message:
            raise NoiseHandshakeError('NoiseConnection.write_message has to be called now')
        if self.handshake_finished:
            raise NoiseHandshakeError('Handshake finished. NoiseConnection.decrypt should be used now')
        self._next_fn = self.write_message

        buffer = bytearray()
        try:
            result = self.noise_protocol.handshake_state.read_message(data, buffer)
        except InvalidTag:
            raise NoiseInvalidMessage('Failed authentication of handshake message')
        if result:
            self.handshake_finished = True
        return buffer

    def encrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise NoiseHandshakeError('Handshake not finished yet!')
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage('Data must be bytes and less or equal {} bytes in length'.format(MAX_MESSAGE_LEN))
        return self.noise_protocol.cipher_state_encrypt.encrypt_with_ad(None, data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise NoiseHandshakeError('Handshake not finished yet!')
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage('Data must be bytes and less or equal {} bytes in length'.format(MAX_MESSAGE_LEN))
        try:
            return self.noise_protocol.cipher_state_decrypt.decrypt_with_ad(None, data)
        except InvalidTag:
            raise NoiseInvalidMessage('Failed authentication of message')

    def get_handshake_hash(self) -> bytes:
        return self.noise_protocol.handshake_hash

    def rekey_inbound_cipher(self):
        self.noise_protocol.cipher_state_decrypt.rekey()

    def rekey_outbound_cipher(self):
        self.noise_protocol.cipher_state_encrypt.rekey()
