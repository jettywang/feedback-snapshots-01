from collections.abc import Mapping
from typing import Optional, Tuple


class PeerStaticKeySource(object):
    """Where the peer static public key seen by the application came from."""

    #: No peer static public key exists in this handshake.
    NONE = 'none'
    #: The peer static public key was received in a handshake message.
    OBSERVED = 'observed'
    #: The peer static public key was supplied locally before the handshake.
    CONFIGURED = 'configured'


class PeerAuthentication(object):
    """The cryptographic identity guarantee established for the peer."""

    #: No peer static public key was used; the peer is anonymous.
    NONE = 'none'
    #: A peer static public key was used in a DH operation and a later peer
    #: message authenticated under that key chain, proving possession of the
    #: corresponding private key. Whether that identity is trusted is still an
    #: application decision.
    STATIC = 'static'
    #: A peer static public key is present but no authenticated peer message
    #: bound it to the handshake, so possession of its private key has not been
    #: proven.
    STATIC_UNPROVEN = 'static-unproven'


class PeerRole(object):
    INITIATOR = 'initiator'
    RESPONDER = 'responder'


class PeerIdentityEvidence(Mapping):
    """
    Evidence about the peer identity available when a handshake completes.

    ``handshake_finished`` only means that the cryptographic handshake flow
    completed. It does not mean that the peer's identity is acceptable. This
    object exposes the actual facts needed by an application trust policy:

    * ``pattern`` / ``protocol_name``: the handshake pattern that was actually
      executed;
    * ``role``: this party's role in that handshake;
    * ``peer_static_public_key``: the peer static public key actually used by
      the handshake, or ``None`` when the pattern has no peer static key (for
      example NN, or the anonymous side of XN);
    * ``peer_static_key_source``: ``observed`` when the key was received in a
      handshake message, ``configured`` when it was supplied locally before the
      handshake, or ``none``. A configured value is never reported as observed;
    * ``peer_static_key_proven``: whether a peer message authenticated under a
      key chain that included a DH with that exact peer static public key.
      This proves possession of the peer's static private key, nothing more;
    * ``handshake_hash``: the final handshake hash, suitable for channel
      binding.

    ``peer_authentication`` is ``none`` for NN (no identity guarantee at all),
    ``static`` when a peer static key was proven, and ``static-unproven`` when
    a key exists but possession was not proven.

    This evidence is a snapshot; it cannot be used to authenticate a different
    handshake.
    """

    _fields = (
        'pattern',
        'protocol_name',
        'pattern_modifiers',
        'role',
        'handshake_hash',
        'peer_static_public_key',
        'peer_static_key_proven',
        'peer_static_key_source',
        'local_static_public_key',
    )

    __slots__ = _fields + ('_frozen',)

    def __init__(self, pattern: str, protocol_name: bytes, role: str, handshake_hash: bytes,
                 peer_static_public_key: Optional[bytes], peer_static_key_proven: bool,
                 peer_static_key_source: str, pattern_modifiers: Tuple[str, ...] = (),
                 local_static_public_key: Optional[bytes] = None):
        # Snapshots are immutable: a callback may inspect them but cannot
        # rewrite the evidence later consumers rely on.
        object.__setattr__(self, '_frozen', False)
        object.__setattr__(self, 'pattern', pattern)
        object.__setattr__(self, 'protocol_name', protocol_name)
        object.__setattr__(self, 'pattern_modifiers', tuple(pattern_modifiers))
        object.__setattr__(self, 'role', role)
        object.__setattr__(self, 'handshake_hash', handshake_hash)
        object.__setattr__(self, 'peer_static_public_key', peer_static_public_key)
        object.__setattr__(self, 'peer_static_key_proven', bool(peer_static_key_proven))
        object.__setattr__(self, 'peer_static_key_source', peer_static_key_source)
        object.__setattr__(self, 'local_static_public_key', local_static_public_key)
        object.__setattr__(self, '_frozen', True)

    def __setattr__(self, name, value):
        if getattr(self, '_frozen', False):
            raise AttributeError('PeerIdentityEvidence is immutable')
        object.__setattr__(self, name, value)

    @property
    def pattern_name(self) -> str:
        return self.pattern

    @property
    def handshake_pattern(self) -> str:
        return self.pattern

    @property
    def remote_static_public_key(self) -> Optional[bytes]:
        return self.peer_static_public_key

    @property
    def remote_static(self) -> Optional[bytes]:
        return self.peer_static_public_key

    @property
    def peer_static_key_observed(self) -> bool:
        return self.peer_static_key_source == PeerStaticKeySource.OBSERVED

    @property
    def peer_static_key_configured(self) -> bool:
        return self.peer_static_key_source == PeerStaticKeySource.CONFIGURED

    @property
    def peer_static_key_is_proven(self) -> bool:
        return self.peer_static_key_proven

    @property
    def peer_identity_available(self) -> bool:
        return self.peer_static_public_key is not None

    @property
    def has_peer_identity(self) -> bool:
        return self.peer_identity_available

    @property
    def identity_available(self) -> bool:
        return self.peer_identity_available

    @property
    def requires_application_trust(self) -> bool:
        return self.peer_static_public_key is not None

    @property
    def is_initiator(self) -> bool:
        return self.role == PeerRole.INITIATOR

    @property
    def initiator(self) -> bool:
        return self.is_initiator

    @property
    def peer_authentication(self) -> str:
        if self.peer_static_public_key is None:
            return PeerAuthentication.NONE
        if self.peer_static_key_proven:
            return PeerAuthentication.STATIC
        return PeerAuthentication.STATIC_UNPROVEN

    @property
    def authentication(self) -> str:
        return self.peer_authentication

    def __getitem__(self, key):
        if isinstance(key, int):
            return getattr(self, self._fields[key])
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __iter__(self):
        return iter(self._fields)

    def __len__(self):
        return len(self._fields)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        return self._fields

    def items(self):
        return tuple((field, getattr(self, field)) for field in self._fields)

    def _asdict(self):
        return dict(self.items())

    def __repr__(self):
        pairs = ', '.join('{}={!r}'.format(field, getattr(self, field)) for field in self._fields)
        return '{}({})'.format(type(self).__name__, pairs)

    def __eq__(self, other):
        if not isinstance(other, PeerIdentityEvidence):
            return NotImplemented
        return all(getattr(self, field) == getattr(other, field) for field in self._fields)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result


# Convenient shorter name for callers.
PeerIdentity = PeerIdentityEvidence
