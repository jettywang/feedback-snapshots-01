from enum import Enum
from typing import Union, List

from cryptography.exceptions import InvalidTag

from noise.backends.default import noise_backend
from noise.constants import MAX_MESSAGE_LEN
from noise.exceptions import (NoisePSKError, NoiseValueError, NoiseHandshakeError, NoiseInvalidMessage,
                             NoiseIdentityError)
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
        self.noise_protocol = None
        self.protocol_name = None
        self.handshake_finished = False
        self._handshake_started = False
        self._next_fn = None

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

    def set_peer_identity_verifier(self, verifier):
        """
        Install an optional application admission callback for peer identity.

        The callback receives a :class:`noise.identity.PeerIdentityEvidence`
        snapshot immediately before transport keys are derived. It must return
        a true value to admit the peer. Returning a false value raises
        ``NoiseIdentityError``; any exception from the callback is wrapped in
        ``NoiseIdentityError``. In both refusal cases the handshake is aborted,
        the reply/payload from the final handshake message is not returned, and
        no transport cipher state is created.

        Pass ``None`` to remove a previously installed callback.
        """
        if verifier is not None and not callable(verifier):
            raise NoiseValueError('Peer identity verifier must be callable or None')
        if self.handshake_finished:
            raise NoiseHandshakeError('Handshake finished. Identity verifier cannot be changed now')
        self.noise_protocol.peer_identity_verifier = verifier

    def get_peer_identity(self):
        """Return the accepted peer identity evidence, or None if unavailable."""
        return self.noise_protocol.peer_identity

    @property
    def peer_identity(self):
        return self.noise_protocol.peer_identity

    @property
    def peer_admitted(self):
        """
        True only if an application peer-identity callback accepted this peer.

        A finished handshake alone never sets this. This flag only records the
        callback's decision; it does not imply that the pattern provided any
        peer identity.
        """
        return self.noise_protocol.peer_admitted

    @property
    def peer_identity_admitted(self):
        """
        True only if a callback accepted evidence naming a peer static key.

        A finished handshake alone never sets this. NN can never set it because
        it has no peer identity to admit.
        """
        return self.noise_protocol.peer_identity_admitted

    @property
    def handshake_aborted(self):
        return getattr(self.noise_protocol, 'handshake_aborted', False)

    def set_as_initiator(self):
        self.noise_protocol.initiator = True
        self._next_fn = self.write_message

    def set_as_responder(self):
        self.noise_protocol.initiator = False
        self._next_fn = self.read_message

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
        if self.handshake_aborted:
            raise NoiseHandshakeError('Handshake aborted by peer identity policy; use a new connection')
        self.noise_protocol.validate()
        self.noise_protocol.initialise_handshake_state()
        self._handshake_started = True

    def write_message(self, payload: bytes=b'') -> bytearray:
        if not self._handshake_started:
            raise NoiseHandshakeError('Call NoiseConnection.start_handshake first')
        if self.handshake_aborted:
            raise NoiseHandshakeError('Handshake aborted by peer identity policy')
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
        if self.handshake_aborted:
            raise NoiseHandshakeError('Handshake aborted by peer identity policy')
        if self._next_fn != self.read_message:
            raise NoiseHandshakeError('NoiseConnection.write_message has to be called now')
        if self.handshake_finished:
            raise NoiseHandshakeError('Handshake finished. NoiseConnection.decrypt should be used now')
        self._next_fn = self.write_message

        buffer = bytearray()
        result = self.noise_protocol.handshake_state.read_message(data, buffer)
        if result:
            self.handshake_finished = True
        return buffer

    def encrypt(self, data: bytes) -> bytes:
        if self.handshake_aborted:
            raise NoiseHandshakeError('Handshake aborted by peer identity policy')
        if not self.handshake_finished:
            raise NoiseHandshakeError('Handshake not finished yet!')
        if not isinstance(data, bytes) or len(data) > MAX_MESSAGE_LEN:
            raise NoiseInvalidMessage('Data must be bytes and less or equal {} bytes in length'.format(MAX_MESSAGE_LEN))
        return self.noise_protocol.cipher_state_encrypt.encrypt_with_ad(None, data)

    def decrypt(self, data: bytes) -> bytes:
        if self.handshake_aborted:
            raise NoiseHandshakeError('Handshake aborted by peer identity policy')
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
        self._get_transport_cipher('cipher_state_decrypt').rekey()

    def rekey_outbound_cipher(self):
        self._get_transport_cipher('cipher_state_encrypt').rekey()

    def _get_transport_cipher(self, name):
        if self.handshake_aborted:
            raise NoiseHandshakeError('Handshake aborted by peer identity policy')
        if not self.handshake_finished:
            raise NoiseHandshakeError('Handshake not finished yet!')
        cipher_state = getattr(self.noise_protocol, name)
        if cipher_state is None:
            raise NoiseHandshakeError('No transport cipher exists for this direction')
        return cipher_state
