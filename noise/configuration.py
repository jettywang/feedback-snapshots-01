import hashlib
import warnings
from collections import namedtuple
from types import MappingProxyType

from noise.encoding import Decoder, encode_bytes, encode_bytes_list
from noise.negotiation import NegotiationRecord
from noise.exceptions import (NoiseConfigurationError, NoiseConfigurationFrozenError,
                              NoiseNegotiationError, NoisePSKError, NoiseValidationError)


_STARTUP_CONFIGURATION_MAGIC = b'NOISE-STARTUP-CONFIGURATION\x00\x01'
NEGOTIATION_PROLOGUE_MAGIC = b'NOISE-NEGOTIATION-PROLOGUE\x00\x01'
_KEYPAIR_TOKENS = ('s', 'e', 'rs', 're')


class FrozenTuple(tuple):
    """A tuple which reports mutation attempts as configuration errors."""

    def _frozen(self, *args, **kwargs):
        raise NoiseConfigurationFrozenError('Startup configuration is frozen')

    __setitem__ = _frozen
    __delitem__ = _frozen
    __iadd__ = _frozen
    __imul__ = _frozen
    append = _frozen
    clear = _frozen
    extend = _frozen
    insert = _frozen
    pop = _frozen
    remove = _frozen
    reverse = _frozen
    sort = _frozen


class FrozenDict(dict):
    """A dict which raises instead of mutating once startup has begun."""

    def _frozen(self, *args, **kwargs):
        raise NoiseConfigurationFrozenError('Startup configuration is frozen')

    __setitem__ = _frozen
    __delitem__ = _frozen
    __ior__ = _frozen
    clear = _frozen
    pop = _frozen
    popitem = _frozen
    setdefault = _frozen
    update = _frozen


class FrozenKeypair(object):
    """
    Read-only view of a keypair captured by the startup configuration.

    The underlying cryptography objects remain usable for DH operations, but
    the keypair object that entered the handshake cannot be replaced or edited.
    """
    __slots__ = ('_private', '_public', '_public_bytes')

    def __init__(self, keypair):
        object.__setattr__(self, '_private', getattr(keypair, 'private', None))
        object.__setattr__(self, '_public', getattr(keypair, 'public', None))
        object.__setattr__(self, '_public_bytes',
                           bytes(getattr(keypair, 'public_bytes', b'') or b''))

    def __setattr__(self, name, value):
        raise NoiseConfigurationFrozenError('Startup configuration is frozen')

    def __delattr__(self, name):
        raise NoiseConfigurationFrozenError('Startup configuration is frozen')

    @property
    def private(self):
        return self._private

    @property
    def public(self):
        return self._public

    @property
    def public_bytes(self):
        return self._public_bytes

    def __repr__(self):
        return 'FrozenKeypair(public_bytes={!r})'.format(self._public_bytes)


def _ascii_for_audit(value):
    return value.decode('ascii', 'backslashreplace')


def _to_bytes(value, field_name):
    if isinstance(value, str):
        try:
            return value.encode('ascii')
        except UnicodeEncodeError:
            raise NoiseConfigurationError('{} must be ASCII'.format(field_name))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise NoiseConfigurationError('{} must be bytes or an ASCII string'.format(field_name))


def compose_prologue(application_prologue, negotiation_record=None):
    """
    Compose the byte string actually mixed into the Noise handshake hash.

    A negotiation record is length-prefixed and role-labelled. Without a
    record the application prologue is used verbatim, preserving the standard
    Noise test vectors.
    """
    application_prologue = bytes(application_prologue or b'')
    if negotiation_record is None:
        return application_prologue
    return (NEGOTIATION_PROLOGUE_MAGIC +
            encode_bytes(negotiation_record.to_bytes()) +
            encode_bytes(application_prologue))


def parse_negotiation_prologue(prologue):
    """
    Split an effective prologue into ``(NegotiationRecord, application_prologue)``.

    Returns ``(None, prologue)`` for prologues that were not built with
    :func:`compose_prologue`. This lets an auditor reconstruct exactly which
    negotiation record entered the handshake hash.
    """
    prologue = bytes(prologue or b'')
    if not prologue.startswith(NEGOTIATION_PROLOGUE_MAGIC):
        return None, prologue
    decoder = Decoder(prologue[len(NEGOTIATION_PROLOGUE_MAGIC):])
    record = NegotiationRecord.from_bytes(decoder.read_bytes())
    application_prologue = decoder.read_bytes()
    decoder.ensure_exhausted()
    return record, application_prologue


class StartupConfiguration(namedtuple(
        'StartupConfiguration',
        'protocol_name initiator application_prologue negotiation_record prologue psks keypairs')):
    """
    Immutable snapshot of exactly what a single handshake was started with.

    ``prologue`` is the byte string actually mixed into the handshake hash.
    ``application_prologue`` is the caller's value before the negotiation
    record is bound in, and ``negotiation_record`` keeps both parties'
    selections as a structured value.
    """
    __slots__ = ()

    def __new__(cls, protocol_name, initiator, application_prologue, negotiation_record,
                prologue, psks, keypairs):
        if isinstance(protocol_name, str):
            protocol_name = protocol_name.encode('ascii')
        if isinstance(application_prologue, str):
            application_prologue = application_prologue.encode('ascii')
        return super(StartupConfiguration, cls).__new__(
            cls,
            bytes(protocol_name),
            bool(initiator),
            bytes(application_prologue or b''),
            negotiation_record,
            bytes(prologue or b''),
            FrozenTuple(bytes(psk) for psk in (psks or ())),
            MappingProxyType({token: (None if value is None else bytes(value))
                              for token, value in dict(keypairs or {}).items()}),
        )

    def __reduce__(self):
        return (type(self), (self.protocol_name, self.initiator, self.application_prologue,
                             self.negotiation_record, self.prologue, tuple(self.psks),
                             dict(self.keypairs)))

    @property
    def role(self):
        return 'initiator' if self.initiator else 'responder'

    @property
    def negotiation_record_bytes(self):
        return self.negotiation_record.to_bytes() if self.negotiation_record is not None else b''

    @property
    def digest(self):
        """SHA-256 over the complete startup configuration."""
        return hashlib.sha256(self.to_bytes()).digest()

    @property
    def hexdigest(self):
        return self.digest.hex()

    @property
    def prologue_digest(self):
        return hashlib.sha256(self.prologue).digest()

    def to_bytes(self):
        """
        Canonical encoding of the snapshot. Length prefixes make every field,
        including PSKs and pre-message keys, unambiguous.
        """
        keypair_tokens = [token for token in _KEYPAIR_TOKENS if token in self.keypairs]
        keypair_values = [self.keypairs[token] if self.keypairs[token] is not None else b''
                          for token in keypair_tokens]
        return b''.join([
            _STARTUP_CONFIGURATION_MAGIC,
            encode_bytes(self.protocol_name),
            b'\x01' if self.initiator else b'\x00',
            encode_bytes(self.application_prologue),
            encode_bytes(self.negotiation_record_bytes),
            encode_bytes(self.prologue),
            encode_bytes_list([hashlib.sha256(psk).digest() for psk in self.psks]),
            encode_bytes_list([token.encode('ascii') for token in keypair_tokens]),
            encode_bytes_list(keypair_values),
        ])

    def audit(self):
        """
        Human-readable description of the configuration that entered the
        handshake hash. PSKs are represented by digests rather than raw bytes.
        """
        record = self.negotiation_record
        return {
            'protocol_name': _ascii_for_audit(self.protocol_name),
            'role': self.role,
            'initiator': self.initiator,
            'application_prologue': self.application_prologue.hex(),
            'negotiation_record': None if record is None else {
                'initiator_choice': _ascii_for_audit(record.initiator_choice),
                'responder_choice': _ascii_for_audit(record.responder_choice),
                'initiator_offers': [_ascii_for_audit(offer) for offer in record.initiator_offers],
                'responder_offers': [_ascii_for_audit(offer) for offer in record.responder_offers],
                'encoded': record.to_bytes().hex(),
                'consistent': (record.initiator_choice == self.protocol_name and
                               record.responder_choice == self.protocol_name),
            },
            'prologue_used': self.prologue.hex(),
            'prologue_digest': self.prologue_digest.hex(),
            'psk_count': len(self.psks),
            'psk_digests': [hashlib.sha256(psk).hexdigest() for psk in self.psks],
            'public_keys': {token: None if value is None else value.hex()
                            for token, value in self.keypairs.items()},
            'configuration_digest': self.hexdigest,
        }


class HandshakeConfiguration(object):
    """
    Single mutable pre-start configuration, owned by a NoiseProtocol.

    All public configuration access (connection setters and direct protocol
    attribute access) goes through this object. ``freeze()`` replaces mutable
    containers with frozen copies, so references retained by the caller can no
    longer affect the handshake after startup.
    """
    def __init__(self, protocol_name):
        self._protocol_name = bytes(protocol_name)
        self._initiator = None
        self._application_prologue = b''
        self._negotiation_record = None
        self._psks = ()
        self._has_psks = False
        self._keypairs = {token: None for token in _KEYPAIR_TOKENS}
        self._started = False
        self._startup_configuration = None
        self._psk_queue = []
        self._psk_queue_prepared = False

    def _ensure_mutable(self):
        if self._started:
            raise NoiseConfigurationFrozenError(
                'Startup configuration is frozen; it cannot change during or after a handshake')

    @property
    def started(self):
        return self._started

    @property
    def startup_configuration(self):
        return self._startup_configuration

    @property
    def protocol_name(self):
        return self._protocol_name

    @property
    def initiator(self):
        return self._initiator

    @initiator.setter
    def initiator(self, value):
        self._ensure_mutable()
        if value is not None and not isinstance(value, bool):
            raise NoiseConfigurationError('Role must be a boolean')
        self._initiator = value

    @property
    def role(self):
        return 'initiator' if self._initiator else 'responder'

    @property
    def application_prologue(self):
        return self._application_prologue

    @application_prologue.setter
    def application_prologue(self, value):
        self._ensure_mutable()
        self._application_prologue = _to_bytes(value or b'', 'Prologue')

    @property
    def negotiation_record(self):
        return self._negotiation_record

    @negotiation_record.setter
    def negotiation_record(self, record):
        self._ensure_mutable()
        if record is not None and not hasattr(record, 'to_bytes'):
            raise NoiseNegotiationError('Negotiation record must be a NegotiationRecord')
        self._negotiation_record = record

    @property
    def prologue(self):
        """The byte string that will actually enter the handshake hash."""
        return compose_prologue(self._application_prologue, self._negotiation_record)

    @prologue.setter
    def prologue(self, value):
        # Legacy direct assignment to ``noise_protocol.prologue`` is treated
        # as application prologue data. A negotiation record, if present,
        # remains bound and is prepended deterministically.
        self.application_prologue = value

    @property
    def psks(self):
        return self._psks if self._has_psks else None

    @psks.setter
    def psks(self, value):
        self._ensure_mutable()
        if value is None:
            self._psks = ()
            self._has_psks = False
            return
        psks = tuple(_to_bytes(psk, 'PSK') for psk in value)
        self._psks = psks
        self._has_psks = True

    @property
    def keypairs(self):
        return self._keypairs

    @property
    def psk_queue(self):
        return self._psk_queue

    def prepare_psk_queue(self):
        if not self._started:
            self._psk_queue = list(self._psks) if self._has_psks else []
            self._psk_queue_prepared = True

    def consume_psk(self):
        # Legacy direct users of NoiseProtocol may initialise a HandshakeState
        # without going through start(). In that path no frozen queue exists
        # yet, so prepare it from the pre-start configuration exactly once.
        if not self._started and not self._psk_queue_prepared:
            self.prepare_psk_queue()
        if not self._psk_queue:
            raise NoisePSKError('No PSKs remain for this handshake')
        return self._psk_queue.pop(0)

    def consume_remaining_psks(self):
        self._psk_queue = []

    def validate(self, pattern):
        """
        Validate everything needed to start a handshake without mutating any
        configuration or consuming a PSK.
        """
        if self._initiator is None:
            raise NoiseValidationError(
                'You need to set role with NoiseConnection.set_as_initiator '
                'or NoiseConnection.set_as_responder')

        record = self._negotiation_record
        if record is not None:
            if record.initiator_choice != record.responder_choice:
                raise NoiseNegotiationError('Both parties must select the same protocol')
            if record.initiator_choice != self._protocol_name:
                raise NoiseNegotiationError(
                    'Negotiated protocol {!r} does not match connection protocol {!r}'.format(
                        record.initiator_choice, self._protocol_name))

        if pattern.psk_count:
            if not self._has_psks:
                raise NoisePSKError('No PSKs provided')
            if any(len(psk) != 32 for psk in self._psks):
                raise NoisePSKError('Invalid psk length! Has to be 32 bytes long')
            if len(self._psks) != pattern.psk_count:
                raise NoisePSKError('Bad number of PSKs provided to this protocol! {} are required, '
                                    'given {}'.format(pattern.psk_count, len(self._psks)))
        elif self._has_psks:
            raise NoisePSKError('PSKs were provided to a non-PSK handshake pattern')

        for keypair in pattern.get_required_keypairs(self._initiator):
            if self._keypairs[keypair] is None:
                raise NoiseValidationError(
                    'Keypair {} has to be set for chosen handshake pattern'.format(keypair))

        initiator_pre_messages = pattern.get_initiator_pre_messages()
        responder_pre_messages = pattern.get_responder_pre_messages()
        local_pre_messages = initiator_pre_messages if self._initiator else responder_pre_messages
        remote_pre_messages = responder_pre_messages if self._initiator else initiator_pre_messages
        for token in local_pre_messages:
            if self._keypairs[token] is None:
                raise NoiseValidationError(
                    'Keypair {} has to be set for chosen handshake pattern'.format(token))
        for token in remote_pre_messages:
            remote_token = 'r' + token
            if self._keypairs[remote_token] is None:
                raise NoiseValidationError(
                    'Keypair {} has to be set for chosen handshake pattern'.format(remote_token))

        if self._keypairs['e'] is not None or self._keypairs['re'] is not None:
            warnings.warn('One of ephemeral keypairs is already set. '
                          'This is OK for testing, but should NEVER happen in production!')

    def snapshot_for_startup(self):
        keypairs = {}
        for token, keypair in self._keypairs.items():
            if keypair is None:
                continue
            keypairs[token] = getattr(keypair, 'public_bytes', None)
        return StartupConfiguration(
            protocol_name=self._protocol_name,
            initiator=bool(self._initiator),
            application_prologue=self._application_prologue,
            negotiation_record=self._negotiation_record,
            prologue=self.prologue,
            psks=self._psks if self._has_psks else (),
            keypairs=keypairs,
        )

    def snapshot_for_rollback(self):
        return {
            'initiator': self._initiator,
            'application_prologue': self._application_prologue,
            'negotiation_record': self._negotiation_record,
            'psks': self._psks,
            'has_psks': self._has_psks,
            'keypairs': dict(self._keypairs),
            'started': self._started,
            'startup_configuration': self._startup_configuration,
            'psk_queue': list(self._psk_queue),
            'psk_queue_prepared': self._psk_queue_prepared,
        }

    def restore(self, snapshot):
        self._initiator = snapshot['initiator']
        self._application_prologue = snapshot['application_prologue']
        self._negotiation_record = snapshot['negotiation_record']
        self._psks = snapshot['psks']
        self._has_psks = snapshot['has_psks']
        self._keypairs = snapshot['keypairs']
        self._started = snapshot['started']
        self._startup_configuration = snapshot['startup_configuration']
        self._psk_queue = snapshot['psk_queue']
        self._psk_queue_prepared = snapshot['psk_queue_prepared']

    def freeze(self, startup_configuration):
        """
        Bind this configuration to the snapshot produced by start_handshake().

        Mutable containers are replaced with copies so references the caller
        retained from before startup cannot mutate the handshake.
        """
        self._ensure_mutable()
        self._startup_configuration = startup_configuration
        self._psks = FrozenTuple(startup_configuration.psks)
        self._has_psks = bool(startup_configuration.psks)
        self._psk_queue = list(startup_configuration.psks)
        self._psk_queue_prepared = True
        self._keypairs = FrozenDict({
            token: (FrozenKeypair(keypair) if keypair is not None else None)
            for token, keypair in self._keypairs.items()
        })
        self._started = True
