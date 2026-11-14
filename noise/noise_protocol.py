from functools import partial

from noise.configuration import HandshakeConfiguration
from noise.constants import MAX_PROTOCOL_NAME_LEN, Empty
from noise.exceptions import NoiseProtocolNameError
from noise.state import HandshakeState


class NoiseProtocol(object):
    """
    Per-handshake Noise protocol description.

    All startup-affecting inputs live in one ``HandshakeConfiguration``
    object. Before ``start_handshake`` it may be constructed and validated;
    after startup it is frozen and ``startup_configuration`` is the sole
    auditable record of what entered the handshake hash.
    """
    def __init__(self, protocol_name: bytes, backend: 'NoiseBackend'):
        self.backend = backend
        unpacked_name = UnpackedName.from_protocol_name(protocol_name)
        mappings = self.backend.map_protocol_name_to_crypto(unpacked_name)

        # A valid Pattern instance (see Section 7 of specification (rev 32))
        self.pattern = mappings['pattern']()
        self.pattern_modifiers = unpacked_name.pattern_modifiers
        if self.pattern_modifiers:
            self.pattern.apply_pattern_modifiers(self.pattern_modifiers)

        # Handle PSK handshake options
        self.is_psk_handshake = any([modifier.startswith('psk') for modifier in self.pattern_modifiers])

        # Preinitialized
        self.dh_fn = mappings['dh']()
        self.hash_fn = mappings['hash']()
        self.hmac = partial(backend.hmac, algorithm=self.hash_fn.fn)
        self.hkdf = partial(backend.hkdf, hmac_hash_fn=self.hmac)

        # Initialized where needed
        self.cipher_class = mappings['cipher']
        self.keypair_class = mappings['keypair']

        self._configuration = HandshakeConfiguration(protocol_name)
        self.handshake_hash = None

        self.handshake_state = Empty()
        self.symmetric_state = Empty()
        self.cipher_state_handshake = Empty()
        self.cipher_state_encrypt = Empty()
        self.cipher_state_decrypt = Empty()

    # ------------------------------------------------------------------
    # Configuration delegation. These properties are the single source of
    # truth before startup and become frozen afterwards.
    # ------------------------------------------------------------------
    @property
    def configuration(self):
        return self._configuration

    @property
    def name(self):
        return self.configuration.protocol_name

    @name.setter
    def name(self, value):
        # The handshake pattern and crypto functions were derived from the
        # construction-time name, so replacing it is never safe.
        self.configuration._ensure_mutable()
        raise NoiseProtocolNameError(
            'Protocol name is fixed at construction; create a new NoiseConnection instead')

    @property
    def protocol_name(self):
        return self.configuration.protocol_name

    @property
    def initiator(self):
        return self.configuration.initiator

    @initiator.setter
    def initiator(self, value):
        self.configuration.initiator = value

    @property
    def prologue(self):
        """Byte string actually mixed into the handshake hash."""
        return self.configuration.prologue

    @prologue.setter
    def prologue(self, value):
        self.configuration.prologue = value

    @property
    def application_prologue(self):
        return self.configuration.application_prologue

    @application_prologue.setter
    def application_prologue(self, value):
        self.configuration.application_prologue = value

    @property
    def negotiation_record(self):
        return self.configuration.negotiation_record

    @negotiation_record.setter
    def negotiation_record(self, value):
        self.configuration.negotiation_record = value

    @property
    def psks(self):
        return self.configuration.psks

    @psks.setter
    def psks(self, value):
        self.configuration.psks = value

    @property
    def keypairs(self):
        return self.configuration.keypairs

    @keypairs.setter
    def keypairs(self, value):
        self.configuration._ensure_mutable()
        keypairs = self.configuration.keypairs
        keypairs.clear()
        keypairs.update(value)

    @property
    def startup_configuration(self):
        return self.configuration.startup_configuration

    @property
    def frozen(self):
        return self.configuration.started

    @property
    def psk_queue(self):
        return self.configuration.psk_queue

    def consume_psk(self):
        return self.configuration.consume_psk()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def validate(self):
        """Validate startup inputs without mutating or consuming anything."""
        self.configuration.validate(self.pattern)

    def start(self):
        """
        Validate, snapshot, freeze and initialise in that order.

        Validation failures leave the connection exactly as it was. Any failure
        during snapshot/freeze/initialisation rolls the configuration and
        handshake state back to their pre-start values, so a corrected retry is
        possible and no list is consumed by the failed attempt.
        """
        self.configuration._ensure_mutable()
        self.validate()

        startup = self.configuration.snapshot_for_startup()
        rollback = self.configuration.snapshot_for_rollback()
        handshake_state = self.handshake_state
        symmetric_state = self.symmetric_state
        cipher_state_handshake = self.cipher_state_handshake
        try:
            self.configuration.freeze(startup)
            self.initialise_handshake_state()
        except BaseException:
            self.configuration.restore(rollback)
            self.handshake_state = handshake_state
            self.symmetric_state = symmetric_state
            self.cipher_state_handshake = cipher_state_handshake
            raise
        return startup

    def handshake_done(self):
        if self.pattern.one_way:
            if self.initiator:
                self.cipher_state_decrypt = None
            else:
                self.cipher_state_encrypt = None
        self.handshake_hash = self.symmetric_state.get_handshake_hash()
        self.configuration.consume_remaining_psks()
        del self.handshake_state
        del self.symmetric_state
        del self.cipher_state_handshake

    def initialise_handshake_state(self):
        if not self.configuration.started:
            # Direct NoiseProtocol users get the same validate/freeze contract
            # as NoiseConnection.start_handshake().
            self.start()
            return
        configuration = self.configuration
        configuration.prepare_psk_queue()
        kwargs = {'initiator': configuration.initiator}
        if configuration.prologue:
            kwargs['prologue'] = configuration.prologue
        for keypair, value in configuration.keypairs.items():
            if value:
                kwargs[keypair] = value
        self.handshake_state = HandshakeState.initialize(self, **kwargs)
        self.symmetric_state = self.handshake_state.symmetric_state


class UnpackedName:
    def __init__(self, pattern, dh, cipher, hash, keypair, pattern_modifiers):
        self.pattern = pattern
        self.dh = dh
        self.cipher = cipher
        self.hash = hash
        self.keypair = keypair
        self.pattern_modifiers = pattern_modifiers

    @classmethod
    def from_protocol_name(cls, name):
        if not isinstance(name, bytes):
            raise NoiseProtocolNameError('Protocol name has to be of type "bytes" not {}'.format(type(name)))
        if len(name) > MAX_PROTOCOL_NAME_LEN:
            raise NoiseProtocolNameError('Protocol name too long, has to be at most '
                                         '{} chars long'.format(MAX_PROTOCOL_NAME_LEN))

        unpacked = name.decode().split('_')
        if unpacked[0] != 'Noise':
            raise NoiseProtocolNameError('Noise Protocol name shall begin with Noise! Provided: {}'.format(name))

        # Extract pattern name and pattern modifiers
        pattern = ''
        modifiers_str = None
        for i, char in enumerate(unpacked[1]):
            if char.isupper():
                pattern += char
            else:
                # End of pattern, now look for modifiers
                modifiers_str = unpacked[1][i:]  # Will be empty string if it exceeds string size
                break
        modifiers = modifiers_str.split('+') if modifiers_str else []

        return cls(
            pattern=pattern,
            dh=unpacked[2],
            cipher=unpacked[3],
            hash=unpacked[4],
            keypair=unpacked[2],
            pattern_modifiers=modifiers
        )
