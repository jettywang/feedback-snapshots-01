from enum import Enum
from typing import Union, List

from cryptography.exceptions import InvalidTag

from noise.backends.default import noise_backend
from noise.constants import MAX_MESSAGE_LEN, Empty
from noise.exceptions import NoisePSKError, NoiseValueError, NoiseHandshakeError, NoiseInvalidMessage
from .noise_protocol import NoiseProtocol


# Mapping of handshake patterns to the fallback pattern used when the initial handshake fails after the first
# message, as per Section 10.2 of the Noise specification (e.g. the peer's static key was rotated)
FALLBACK_PROTOCOLS = {b'IK': b'XXfallback'}


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
        self.noise_protocol = None
        self.protocol_name = None
        self.handshake_finished = False
        self._handshake_started = False
        self._next_fn = None
        self._messages_read = 0
        self._messages_written = 0
        self._fallback_triggered = False
        self._requires_static_confirmation = False
        self._static_confirmed = None

    @classmethod
    def from_name(cls, name: Union[str, bytes], backend=noise_backend):
        instance = cls()
        # Forgiving passing string. Bytes are good too, anything else will fail inside NoiseProtocol
        try:
            instance.protocol_name = name.encode('ascii') if isinstance(name, str) else name
        except ValueError:
            raise NoiseValueError('If passing string as protocol name, it must contain only ASCII characters')
        instance.noise_protocol = NoiseProtocol(protocol_name=name, backend=backend)
        return instance

    def set_psks(self, psk: Union[bytes, str] = None, psks: List[Union[str, bytes]] = None):
        if psk and psks:
            raise NoisePSKError('Provide single PSK as psk or list of PSKs as psks')
        if not psk and not psks:
            raise NoisePSKError('No PSKs provided')

        psks = psks or [psk]
        if not all([isinstance(psk, (bytes, str)) for psk in psks]):
            raise NoisePSKError('PSKs must be strings or bytes')

        try:
            self.noise_protocol.psks = [psk.encode('ascii') if isinstance(psk, str) else psk for psk in psks]
        except UnicodeEncodeError:
            raise NoisePSKError('If providing psks as (unicode) string, it must only contain ASCII characters')

    def set_prologue(self, prologue: Union[bytes, str]):
        if isinstance(prologue, bytes):
            self.noise_protocol.prologue = prologue
        elif isinstance(prologue, str):
            try:
                self.noise_protocol.prologue = prologue.encode('ascii')
            except UnicodeEncodeError:
                raise NoiseValueError('Prologue must be ASCII string or bytes')
        else:
            raise NoiseValueError('Prologue must be ASCII string or bytes')

    def set_as_initiator(self):
        self.noise_protocol.initiator = True
        # In fallback patterns the initiator's first message became a pre-message, so the responder speaks first
        self._next_fn = self.read_message if self.noise_protocol.pattern.fallback else self.write_message

    def set_as_responder(self):
        self.noise_protocol.initiator = False
        self._next_fn = self.write_message if self.noise_protocol.pattern.fallback else self.read_message

    def set_keypair_from_private_bytes(self, keypair: Keypair, private_bytes: bytes):
        self.noise_protocol.keypairs[_keypairs[keypair]] = \
            self.noise_protocol.dh_fn.klass.from_private_bytes(private_bytes)

    def set_keypair_from_public_bytes(self, keypair: Keypair, private_bytes: bytes):
        self.noise_protocol.keypairs[_keypairs[keypair]] = \
            self.noise_protocol.dh_fn.klass.from_public_bytes(private_bytes)

    def set_keypair_from_private_path(self, keypair: Keypair, path: str):
        with open(path, 'rb') as fd:
            self.noise_protocol.keypairs[_keypairs[keypair]] = \
                self.noise_protocol.dh_fn.klass.from_private_bytes(fd.read())

    def set_keypair_from_public_path(self, keypair: Keypair, path: str):
        with open(path, 'rb') as fd:
            self.noise_protocol.keypairs[_keypairs[keypair]] = \
                self.noise_protocol.dh_fn.klass.from_public_bytes(fd.read())

    def start_handshake(self):
        self.noise_protocol.validate()
        self.noise_protocol.initialise_handshake_state()
        self._handshake_started = True

    def begin_fallback(self) -> 'NoiseConnection':
        """
        Explicitly switches this connection to the fallback pattern (e.g. IK -> XXfallback), as per Section 10
        of the Noise specification. This is never done automatically - the application authorises the switch by
        calling this method after the initial handshake failed following the first message (typically because
        the responder's static key was rotated and the initiator cached the old one).

        The new connection is initialised with a fresh protocol name, so the chained key and cipher state of the
        failed handshake are discarded. Only the ephemeral material from the first message is carried over as a
        pre-message: the initiator reuses her own ephemeral keypair, the responder reuses the ephemeral public
        key received in the first message. Payloads of the failed handshake are not carried over and must be
        re-sent by the application.

        The remote static key learned through the fallback handshake has to be explicitly confirmed by the
        application with confirm_remote_static() before transport messages can be exchanged.

        :return: a new NoiseConnection for the fallback protocol, with role, prologue, local static keypair and
            the ephemeral pre-message already set. Call start_handshake() on it to proceed.
        """
        if not self._handshake_started:
            raise NoiseHandshakeError('Cannot fall back before the handshake has started')
        if self.handshake_finished:
            raise NoiseHandshakeError('Cannot fall back after the handshake has finished')
        if self._fallback_triggered:
            raise NoiseHandshakeError('Fallback was already triggered for this connection')

        unpacked_pattern = self.protocol_name.split(b'_', 2)[1]
        if unpacked_pattern not in FALLBACK_PROTOCOLS:
            raise NoiseHandshakeError('No fallback pattern defined for {}'.format(unpacked_pattern.decode()))

        handshake_state = self.noise_protocol.handshake_state
        if self.noise_protocol.initiator:
            if self._messages_written != 1 or isinstance(handshake_state.e, Empty):
                raise NoiseHandshakeError('Initiator can only fall back after sending the first message '
                                          'of the initial pattern')
        else:
            if self._messages_written != 0 or self._messages_read != 0 or isinstance(handshake_state.re, Empty):
                raise NoiseHandshakeError('Responder can only fall back after failing to decrypt the first '
                                          'message of the initial pattern')

        prefix, _, rest = self.protocol_name.split(b'_', 2)
        fallback_name = b'_'.join([prefix, FALLBACK_PROTOCOLS[unpacked_pattern], rest])
        fallback = NoiseConnection.from_name(fallback_name, backend=self.noise_protocol.backend)

        # The remote static keypair is deliberately not carried over - it is precisely what may have changed,
        # so it has to be re-learned (and re-confirmed by the application) through the fallback handshake
        fallback.noise_protocol.keypairs['s'] = self.noise_protocol.keypairs['s']
        if self.noise_protocol.prologue:
            fallback.noise_protocol.prologue = self.noise_protocol.prologue

        if self.noise_protocol.initiator:
            fallback.noise_protocol.keypairs['e'] = handshake_state.e
            fallback.set_as_initiator()
        else:
            fallback.noise_protocol.keypairs['re'] = handshake_state.re
            fallback.set_as_responder()
        fallback._requires_static_confirmation = True

        self._fallback_triggered = True
        return fallback

    def write_message(self, payload: bytes=b'') -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError('Call NoiseConnection.start_handshake first')
        if self._fallback_triggered:
            raise NoiseHandshakeError('This connection was superseded by a fallback connection')
        if self._next_fn != self.write_message:
            raise NoiseHandshakeError('NoiseConnection.read_message has to be called now')
        if self.handshake_finished:
            raise NoiseHandshakeError('Handshake finished. NoiseConnection.encrypt should be used now')
        self._next_fn = self.read_message

        buffer = bytearray()
        result = self.noise_protocol.handshake_state.write_message(payload, buffer)
        self._messages_written += 1
        if result:
            self.handshake_finished = True
        return buffer

    def read_message(self, data: bytes) -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError('Call NoiseConnection.start_handshake first')
        if self._fallback_triggered:
            raise NoiseHandshakeError('This connection was superseded by a fallback connection')
        if self._next_fn != self.read_message:
            raise NoiseHandshakeError('NoiseConnection.write_message has to be called now')
        if self.handshake_finished:
            raise NoiseHandshakeError('Handshake finished. NoiseConnection.decrypt should be used now')
        self._next_fn = self.write_message

        buffer = bytearray()
        result = self.noise_protocol.handshake_state.read_message(data, buffer)
        self._messages_read += 1
        if result:
            self.handshake_finished = True
        return buffer

    def encrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise NoiseHandshakeError('Handshake not finished yet!')
        if self._requires_static_confirmation and self._static_confirmed is not True:
            raise NoiseHandshakeError('Remote static identity learned through the fallback handshake requires '
                                      'application confirmation - call confirm_remote_static first')
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage('Data must be bytes and less or equal {} bytes in length'.format(MAX_MESSAGE_LEN))
        return self.noise_protocol.cipher_state_encrypt.encrypt_with_ad(None, data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.handshake_finished:
            raise NoiseHandshakeError('Handshake not finished yet!')
        if self._requires_static_confirmation and self._static_confirmed is not True:
            raise NoiseHandshakeError('Remote static identity learned through the fallback handshake requires '
                                      'application confirmation - call confirm_remote_static first')
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage('Data must be bytes and less or equal {} bytes in length'.format(MAX_MESSAGE_LEN))
        try:
            return self.noise_protocol.cipher_state_decrypt.decrypt_with_ad(None, data)
        except InvalidTag:
            raise NoiseInvalidMessage('Failed authentication of message')

    def get_handshake_hash(self) -> bytes:
        return self.noise_protocol.handshake_hash

    def get_remote_static_key(self) -> bytes:
        """
        :return: public bytes of the remote party's static key if it is already known, None otherwise
        """
        remote_static = self.noise_protocol.remote_static
        handshake_state = getattr(self.noise_protocol, 'handshake_state', None)
        if remote_static is None and handshake_state is not None and not isinstance(handshake_state, Empty):
            candidate = handshake_state.rs
            if not isinstance(candidate, Empty):
                remote_static = candidate
        return remote_static.public_bytes if remote_static is not None else None

    def confirm_remote_static(self):
        """
        Application authorisation of the remote static identity learned through a fallback handshake.
        Required before encrypt/decrypt can be used on a connection created with begin_fallback().
        """
        if not self._requires_static_confirmation:
            raise NoiseHandshakeError('Remote static confirmation is only required on fallback connections')
        if self._static_confirmed is False:
            raise NoiseHandshakeError('Remote static identity was already rejected')
        self._static_confirmed = True

    def reject_remote_static(self):
        """
        Rejects the remote static identity learned through a fallback handshake. The rejection is permanent -
        the connection can no longer be used for transport messages.
        """
        if not self._requires_static_confirmation:
            raise NoiseHandshakeError('Remote static rejection is only applicable on fallback connections')
        self._static_confirmed = False

    def rekey_inbound_cipher(self):
        self.noise_protocol.cipher_state_decrypt.rekey()

    def rekey_outbound_cipher(self):
        self.noise_protocol.cipher_state_encrypt.rekey()
