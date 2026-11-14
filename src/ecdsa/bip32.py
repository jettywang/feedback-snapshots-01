"""
Minimal BIP32 hierarchical deterministic key derivation for secp256k1.

The module implements the extended private and public key structure, the two
child key derivation functions, and the standard Base58Check serialization
(``xprv``/``xpub`` and ``tprv``/``tpub``).  It deliberately implements only
BIP32 and only secp256k1; it is not a wallet, an address encoder, or a
replacement for secure key storage.

A public extended key can derive non-hardened descendants.  A hardened child
index can only be used with a private extended key.  A hardened marker is
never discarded and an invalid child is never skipped: :meth:`derive` raises
:class:`InvalidChildKey` and leaves the choice of trying another index to the
caller.

The parent fingerprint stored in a serialized extended key is only a hint for
finding a parent.  It is not authenticated and may collide; it must not be
used as an identity or as a proof that a key really descends from that parent.

Known BIP32 risk: a parent extended public key plus any non-hardened child
private key is equivalent to the parent extended private key.  Holding an xpub
on a watch-only host and a child xprv on a signer is therefore not a security
boundary by itself.  Hardened account boundaries and real isolation of private
material are required; this module does not provide hardware isolation.
"""

import binascii
import hashlib
import hmac
import re

from six import PY2, int2byte, integer_types, string_types

from .curves import SECP256k1
from .ellipticcurve import INFINITY, PointJacobi
from .errors import MalformedPointError
from .keys import SigningKey, VerifyingKey
from .util import number_to_string, string_to_number

__all__ = [
    "HARDENED",
    "MAINNET_PRIVATE",
    "MAINNET_PUBLIC",
    "TESTNET_PRIVATE",
    "TESTNET_PUBLIC",
    "NETWORKS",
    "BIP32Error",
    "ExtendedKeyError",
    "ExtendedKeyParseError",
    "UnknownVersionError",
    "InvalidExtendedKeyError",
    "PathError",
    "DepthOverflowError",
    "HardenedDerivationError",
    "InvalidChildKey",
    "ExtendedKey",
    "ExtendedPrivateKey",
    "ExtendedPublicKey",
    "parse_path",
    "master_from_seed",
]


HARDENED = 0x80000000
MAX_INDEX = 0xFFFFFFFF

MAINNET_PRIVATE = 0x0488ADE4
MAINNET_PUBLIC = 0x0488B21E
TESTNET_PRIVATE = 0x04358394
TESTNET_PUBLIC = 0x043587CF

NETWORKS = {
    "mainnet": (MAINNET_PRIVATE, MAINNET_PUBLIC),
    "testnet": (TESTNET_PRIVATE, TESTNET_PUBLIC),
}

_PRIVATE_VERSIONS = {
    MAINNET_PRIVATE: "mainnet",
    TESTNET_PRIVATE: "testnet",
}
_PUBLIC_VERSIONS = {
    MAINNET_PUBLIC: "mainnet",
    TESTNET_PUBLIC: "testnet",
}

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE = len(_ALPHABET)
_PATH_INDEX = re.compile(r"^[0-9]+$")
_CURVE_ORDER = SECP256k1.order
_ZERO4 = b"\x00" * 4


class BIP32Error(ValueError):
    """Base class for errors raised by :mod:`ecdsa.bip32`."""


class ExtendedKeyError(BIP32Error):
    """Base class for invalid extended key values."""


class ExtendedKeyParseError(ExtendedKeyError):
    """Raised when serialized extended key data cannot be decoded."""


class UnknownVersionError(ExtendedKeyError):
    """Raised for an extended key version that is not BIP32 mainnet/testnet."""


class InvalidExtendedKeyError(ExtendedKeyError):
    """Raised when decoded extended key fields are inconsistent or invalid."""


class PathError(BIP32Error):
    """Raised for malformed derivation paths."""


class DepthOverflowError(BIP32Error):
    """Raised when derivation would make the BIP32 depth exceed 255."""


class HardenedDerivationError(BIP32Error):
    """Raised when a hardened index is used with an extended public key."""

    def __init__(self, index):
        self.index = index
        BIP32Error.__init__(
            self,
            "cannot derive hardened child {0} from an extended public key; "
            "the hardened bit is preserved and no non-hardened fallback "
            "is attempted".format(index),
        )


class InvalidChildKey(BIP32Error):
    """Raised when BIP32 declares a derived child invalid.

    The caller may explicitly try the next index, but this module never does
    that automatically: doing so silently would hide which index was used.
    """

    def __init__(self, index, reason):
        self.index = index
        self.reason = reason
        BIP32Error.__init__(
            self,
            "invalid child key at index {0}: {1}; no automatic index "
            "increment was performed".format(index, reason),
        )


def _ser32(value):
    return binascii.unhexlify("%08x" % value)


def _ser256(value):
    return number_to_string(value, _CURVE_ORDER)


def _as_bytes(value):
    if isinstance(value, bytearray):
        return bytes(value)
    if PY2 and isinstance(value, buffer):  # noqa: F821
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return value


def _check_int(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, integer_types):
        raise TypeError("{0} must be an integer".format(name))
    if not minimum <= value <= maximum:
        raise ValueError(
            "{0} must be between {1} and {2}, got {3}".format(
                name, minimum, maximum, value
            )
        )
    return value


def _check_chain_code(chain_code):
    chain_code = _as_bytes(chain_code)
    if not isinstance(chain_code, bytes) or len(chain_code) != 32:
        raise ValueError("chain code must be exactly 32 bytes")
    return chain_code


def _check_fingerprint(fingerprint):
    fingerprint = _as_bytes(fingerprint)
    if not isinstance(fingerprint, bytes) or len(fingerprint) != 4:
        raise ValueError("parent fingerprint must be exactly 4 bytes")
    return fingerprint


def _check_depth(depth):
    return _check_int(depth, "depth", 0, 255)


def _check_child_number(index):
    return _check_int(index, "child number", 0, MAX_INDEX)


def _hash160(data):
    try:
        ripe = hashlib.new("ripemd160")
    except (ValueError, TypeError):
        raise RuntimeError(
            "BIP32 fingerprints require RIPEMD160 support in hashlib"
        )
    ripe.update(hashlib.sha256(data).digest())
    return ripe.digest()


def _hmac_sha512(key, data):
    """HMAC-SHA512, kept as a named function so tests can replace it."""
    return hmac.new(key, data, hashlib.sha512).digest()


def _checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def _constant_time_equal(left, right):
    # hmac.compare_digest is not available on the oldest supported Python
    # versions; this fallback still avoids a simple prefix-dependent exit.
    if hasattr(hmac, "compare_digest"):
        return hmac.compare_digest(left, right)
    if len(left) != len(right):
        return False
    result = 0
    for l_byte, r_byte in zip(left, right):
        result |= l_byte ^ r_byte
    return result == 0


def _base58_encode(data):
    data = _as_bytes(data)
    number = int(binascii.hexlify(data), 16) if data else 0
    encoded = []
    while number:
        number, remainder = divmod(number, _BASE)
        encoded.append(_ALPHABET[remainder])
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + "".join(reversed(encoded))


def _base58_decode(text):
    if isinstance(text, bytes):
        raw = text
    elif isinstance(text, string_types):
        try:
            raw = text.encode("ascii")
        except UnicodeEncodeError:
            raise ExtendedKeyParseError("Base58 data must be ASCII")
    else:
        raise TypeError("Base58 data must be a string")

    number = 0
    for char in raw:
        if not isinstance(char, integer_types):
            char = ord(char)
        value = _ALPHABET.find(chr(char))
        if value < 0:
            raise ExtendedKeyParseError(
                "invalid Base58 character {0!r}".format(chr(char))
            )
        number = number * _BASE + value

    leading_ones = len(raw) - len(raw.lstrip(b"1"))
    if number:
        hex_number = "%x" % number
        if len(hex_number) % 2:
            hex_number = "0" + hex_number
        body = binascii.unhexlify(hex_number)
    else:
        body = b""
    return b"\x00" * leading_ones + body


def _base58check_encode(payload):
    payload = _as_bytes(payload)
    return _base58_encode(payload + _checksum(payload))


def _base58check_decode(text):
    data = _base58_decode(text)
    if len(data) < 4:
        raise ExtendedKeyParseError("Base58Check data is too short")
    payload, checksum = data[:-4], data[-4:]
    if not _constant_time_equal(checksum, _checksum(payload)):
        raise ExtendedKeyParseError("invalid Base58Check checksum")
    return payload


def _network_versions(network):
    try:
        return NETWORKS[network]
    except (KeyError, TypeError):
        raise ValueError(
            "unknown network {0!r}, expected one of {1}".format(
                network, ", ".join(sorted(NETWORKS))
            )
        )


def parse_path(path):
    """Parse a BIP32 path into a tuple of 32-bit child numbers.

    Accepted forms are strings such as ``"m/0'/1/2h/2H"`` or paths relative
    to the current node such as ``"0'/1"``, as well as iterables of integer
    child numbers.  ``'``, ``h``, and ``H`` are hardened markers.  A textual
    index without a marker must be below 2**31; raw integer iterables may use
    the full 32-bit range.

    Leading ``m``/``M`` is accepted as the root marker.  Whitespace, empty
    path components, signs, decimal points, and stacked markers are rejected.
    A hardened marker is never removed: ``"0'"`` becomes ``0x80000000``.
    """
    indices, _absolute = _parse_path(path)
    return indices


def _parse_path(path):
    if isinstance(path, bytes):
        try:
            path = path.decode("ascii")
        except UnicodeDecodeError:
            raise PathError("derivation path must be ASCII")
    elif isinstance(path, str) and not PY2:
        try:
            path.encode("ascii")
        except UnicodeEncodeError:
            raise PathError("derivation path must be ASCII")
    if isinstance(path, string_types):
        absolute = False
        if path[:1] in ("m", "M"):
            absolute = True
            path = path[1:]
            if not path:
                return (), True
            if not path.startswith("/"):
                raise PathError("root marker must be followed by '/'")
            path = path[1:]
        if not path:
            raise PathError("derivation path must not be empty")
        components = path.split("/")
        indices = []
        for component in components:
            indices.append(_parse_text_component(component))
        return tuple(indices), absolute

    try:
        components = list(path)
    except TypeError:
        raise TypeError(
            "path must be a string or an iterable of child numbers"
        )
    indices = []
    for component in components:
        indices.append(_check_child_number(component))
    return tuple(indices), False


def _parse_text_component(component):
    if not component:
        raise PathError("empty path component")
    hardened = component[-1:] in ("'", "h", "H")
    number_text = component[:-1] if hardened else component
    if not number_text or not _PATH_INDEX.match(number_text):
        raise PathError(
            "invalid path component {0!r}; expected decimal digits with an "
            "optional single hardened marker".format(component)
        )
    number = int(number_text)
    if number >= HARDENED:
        raise PathError(
            "path component {0!r} exceeds the non-hardened index range; "
            "use a hardened marker instead of a raw hardened index".format(
                component
            )
        )
    return number + HARDENED if hardened else number


def _parse_extended_payload(payload):
    if len(payload) != 78:
        raise ExtendedKeyParseError(
            "extended key payload must be 78 bytes, got {0}".format(
                len(payload)
            )
        )
    version = int(binascii.hexlify(payload[0:4]), 16)
    depth = int(binascii.hexlify(payload[4:5]), 16)
    parent_fingerprint = payload[5:9]
    child_number = int(binascii.hexlify(payload[9:13]), 16)
    chain_code = payload[13:45]
    key_data = payload[45:78]

    if depth == 0:
        if parent_fingerprint != _ZERO4:
            raise InvalidExtendedKeyError(
                "depth 0 key has a non-zero parent fingerprint"
            )
        if child_number != 0:
            raise InvalidExtendedKeyError(
                "depth 0 key has a non-zero child number"
            )

    if version in _PRIVATE_VERSIONS:
        return (
            "private",
            _PRIVATE_VERSIONS[version],
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            key_data,
        )
    if version in _PUBLIC_VERSIONS:
        return (
            "public",
            _PUBLIC_VERSIONS[version],
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            key_data,
        )
    raise UnknownVersionError(
        "unknown extended key version 0x{0:08x}".format(version)
    )


class ExtendedKey(object):
    """Common BIP32 extended key fields and operations.

    Do not instantiate this class directly; use
    :class:`ExtendedPrivateKey` or :class:`ExtendedPublicKey`.
    """

    _is_private = None

    def __init__(
        self,
        network,
        version,
        depth,
        parent_fingerprint,
        child_number,
        chain_code,
    ):
        self._network = network
        self._version = _check_child_number(version)
        self._depth = _check_depth(depth)
        self._parent_fingerprint = _check_fingerprint(parent_fingerprint)
        self._child_number = _check_child_number(child_number)
        self._chain_code = _check_chain_code(chain_code)
        if self._depth == 0:
            if self._parent_fingerprint != _ZERO4:
                raise InvalidExtendedKeyError(
                    "depth 0 key has a non-zero parent fingerprint"
                )
            if self._child_number != 0:
                raise InvalidExtendedKeyError(
                    "depth 0 key has a non-zero child number"
                )

    @property
    def network(self):
        """Network name, either ``"mainnet"`` or ``"testnet"``."""
        return self._network

    @property
    def version(self):
        """The four-byte extended key version as an integer."""
        return self._version

    @property
    def depth(self):
        """Derivation depth, from 0 (master) to 255."""
        return self._depth

    @property
    def parent_fingerprint(self):
        """Four-byte parent fingerprint (a hint, not authentication)."""
        return self._parent_fingerprint

    @property
    def child_number(self):
        """The 32-bit child number; values >= 2**31 are hardened."""
        return self._child_number

    @property
    def chain_code(self):
        """The 32-byte chain code."""
        return self._chain_code

    @property
    def is_private(self):
        """Whether this is an extended private key."""
        return self._is_private

    @property
    def is_hardened(self):
        """Whether this node's own child number is hardened."""
        return bool(self._child_number & HARDENED)

    @property
    def identifier(self):
        """HASH160 of the compressed public key (20 bytes)."""
        raise NotImplementedError

    @property
    def fingerprint(self):
        """First four bytes of :attr:`identifier`."""
        return self.identifier[:4]

    @property
    def public_key(self):
        """The corresponding :class:`~ecdsa.keys.VerifyingKey`."""
        raise NotImplementedError

    def neuter(self):
        """Return the extended public key for this node."""
        raise NotImplementedError

    def derive(self, index):
        """Derive one child at exactly ``index``; no index retry."""
        raise NotImplementedError

    def derive_path(self, path):
        """Derive every component of ``path`` in order."""
        indices, absolute = _parse_path(path)
        if absolute and self._depth != 0:
            raise PathError(
                "absolute path requires a depth 0 node, got depth {0}".format(
                    self._depth
                )
            )
        node = self
        for index in indices:
            node = node.derive(index)
        return node

    def _check_depth_for_child(self):
        if self._depth >= 255:
            raise DepthOverflowError(
                "cannot derive below depth 255; BIP32 depth is one byte"
            )

    def _payload(self):
        raise NotImplementedError

    def to_bytes(self):
        """Return the 78-byte binary extended key payload."""
        return self._payload()

    def to_base58(self):
        """Return the Base58Check string (``xprv``/``xpub`` etc.)."""
        return _base58check_encode(self._payload())

    def to_string(self):
        """Alias for :meth:`to_base58`."""
        return self.to_base58()

    @classmethod
    def from_bytes(cls, payload):
        """Decode a 78-byte binary extended key payload."""
        payload = _as_bytes(payload)
        if not isinstance(payload, bytes):
            raise TypeError("extended key payload must be bytes-like")
        fields = _parse_extended_payload(payload)
        kind = fields[0]
        if kind == "private":
            return ExtendedPrivateKey._from_fields(fields)
        return ExtendedPublicKey._from_fields(fields)

    @classmethod
    def from_base58(cls, text):
        """Decode a Base58Check extended key into the matching node type."""
        return cls.from_bytes(_base58check_decode(text))

    @classmethod
    def from_string(cls, text):
        """Alias for :meth:`from_base58`."""
        return cls.from_base58(text)

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            return NotImplemented
        return self._payload() == other._payload()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result


class ExtendedPrivateKey(ExtendedKey):
    """A BIP32 extended private key on secp256k1."""

    _is_private = True

    def __init__(
        self,
        private_scalar,
        chain_code,
        network="mainnet",
        depth=0,
        parent_fingerprint=_ZERO4,
        child_number=0,
    ):
        _network_versions(network)
        private_scalar = _check_int(
            private_scalar, "private key", 1, _CURVE_ORDER - 1
        )
        version = NETWORKS[network][0]
        ExtendedKey.__init__(
            self,
            network,
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
        )
        self._private_scalar = private_scalar
        self._signing_key = None
        self._public_key = SigningKey.from_secret_exponent(
            private_scalar, curve=SECP256k1
        ).get_verifying_key()

    @classmethod
    def from_bytes(cls, payload):
        """Decode a private extended key payload, rejecting public keys."""
        key = ExtendedKey.from_bytes(payload)
        if not isinstance(key, ExtendedPrivateKey):
            raise InvalidExtendedKeyError(
                "expected an extended private key, got an extended public key"
            )
        return key

    @classmethod
    def _from_fields(cls, fields):
        (
            _kind,
            network,
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            key_data,
        ) = fields
        if key_data[0:1] != b"\x00":
            raise InvalidExtendedKeyError(
                "private extended key data must start with 0x00"
            )
        scalar = string_to_number(key_data[1:])
        if not 1 <= scalar < _CURVE_ORDER:
            raise InvalidExtendedKeyError(
                "private key is not in the range 1..n-1"
            )
        key = cls(
            scalar,
            chain_code,
            network,
            depth,
            parent_fingerprint,
            child_number,
        )
        if key.version != version:
            raise InvalidExtendedKeyError("private key version mismatch")
        return key

    @classmethod
    def from_private_key(
        cls,
        signing_key,
        chain_code,
        network="mainnet",
        depth=0,
        parent_fingerprint=_ZERO4,
        child_number=0,
    ):
        """Build an extended private key from a secp256k1 signing key."""
        if not isinstance(signing_key, SigningKey):
            raise TypeError("signing_key must be a SigningKey")
        if signing_key.curve != SECP256k1:
            raise ValueError("BIP32 is only defined for secp256k1")
        return cls(
            signing_key.privkey.secret_multiplier,
            chain_code,
            network,
            depth,
            parent_fingerprint,
            child_number,
        )

    @classmethod
    def master_from_seed(cls, seed, network="mainnet"):
        """Create the depth 0 extended private key from a seed.

        The seed must be between 16 and 64 bytes, as specified by BIP32.
        """
        seed = _as_bytes(seed)
        if not isinstance(seed, bytes):
            raise TypeError("seed must be bytes-like")
        if not 16 <= len(seed) <= 64:
            raise ValueError(
                "BIP32 seed must be between 16 and 64 bytes, got {0}".format(
                    len(seed)
                )
            )
        _network_versions(network)
        digest = _hmac_sha512(b"Bitcoin seed", seed)
        scalar = string_to_number(digest[:32])
        if scalar == 0 or scalar >= _CURVE_ORDER:
            raise InvalidExtendedKeyError(
                "master private key produced by HMAC-SHA512 is invalid"
            )
        return cls(
            scalar,
            digest[32:],
            network,
            depth=0,
            parent_fingerprint=_ZERO4,
            child_number=0,
        )

    @property
    def private_key(self):
        """The corresponding :class:`~ecdsa.keys.SigningKey`."""
        if self._signing_key is None:
            self._signing_key = SigningKey.from_secret_exponent(
                self._private_scalar, curve=SECP256k1
            )
        return self._signing_key

    @property
    def public_key(self):
        """The corresponding :class:`~ecdsa.keys.VerifyingKey`."""
        return self._public_key

    @property
    def identifier(self):
        return _hash160(self._public_key.to_string("compressed"))

    def neuter(self):
        return ExtendedPublicKey(
            self._public_key,
            self._chain_code,
            self._network,
            self._depth,
            self._parent_fingerprint,
            self._child_number,
        )

    def derive(self, index):
        """Derive the private child at exactly ``index``.

        Hardened indices (``index >= 2**31``) are supported.  If BIP32
        declares the child invalid, :class:`InvalidChildKey` is raised; this
        method does not increment ``index`` or wrap around.
        """
        _check_child_number(index)
        self._check_depth_for_child()
        if index & HARDENED:
            data = b"\x00" + _ser256(self._private_scalar) + _ser32(index)
        else:
            data = self._public_key.to_string("compressed") + _ser32(index)
        digest = _hmac_sha512(self._chain_code, data)
        left = digest[:32]
        right = digest[32:]
        tweak = string_to_number(left)
        if tweak >= _CURVE_ORDER:
            raise InvalidChildKey(index, "I_L >= curve order")
        scalar = (tweak + self._private_scalar) % _CURVE_ORDER
        if scalar == 0:
            raise InvalidChildKey(index, "derived private key is zero")
        return ExtendedPrivateKey(
            scalar,
            right,
            self._network,
            self._depth + 1,
            self.fingerprint,
            index,
        )

    def _payload(self):
        key_data = b"\x00" + _ser256(self._private_scalar)
        return (
            _ser32(self._version)
            + int2byte(self._depth)
            + self._parent_fingerprint
            + _ser32(self._child_number)
            + self._chain_code
            + key_data
        )

    def __repr__(self):
        return (
            "ExtendedPrivateKey(network={0!r}, depth={1}, "
            "child_number={2})".format(
                self._network, self._depth, self._child_number
            )
        )


class ExtendedPublicKey(ExtendedKey):
    """A BIP32 extended public key on secp256k1."""

    _is_private = False

    def __init__(
        self,
        public_key,
        chain_code,
        network="mainnet",
        depth=0,
        parent_fingerprint=_ZERO4,
        child_number=0,
    ):
        _network_versions(network)
        if not isinstance(public_key, VerifyingKey):
            raise TypeError("public_key must be a VerifyingKey")
        if public_key.curve != SECP256k1:
            raise ValueError("BIP32 is only defined for secp256k1")
        version = NETWORKS[network][1]
        ExtendedKey.__init__(
            self,
            network,
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
        )
        self._public_key = public_key

    @classmethod
    def from_bytes(cls, payload):
        """Decode a public extended key payload, rejecting private keys."""
        key = ExtendedKey.from_bytes(payload)
        if not isinstance(key, ExtendedPublicKey):
            raise InvalidExtendedKeyError(
                "expected an extended public key, got an extended private key"
            )
        return key

    @classmethod
    def _from_fields(cls, fields):
        (
            _kind,
            network,
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            key_data,
        ) = fields
        if key_data[0:1] not in (b"\x02", b"\x03"):
            raise InvalidExtendedKeyError(
                "public extended key data must use a compressed key"
            )
        try:
            public_key = VerifyingKey.from_string(
                key_data,
                curve=SECP256k1,
                valid_encodings=("compressed",),
            )
        except (MalformedPointError, ValueError, AssertionError):
            raise InvalidExtendedKeyError(
                "public key is not a valid secp256k1 point"
            )
        key = cls(
            public_key,
            chain_code,
            network,
            depth,
            parent_fingerprint,
            child_number,
        )
        if key.version != version:
            raise InvalidExtendedKeyError("public key version mismatch")
        return key

    @classmethod
    def from_public_key(
        cls,
        verifying_key,
        chain_code,
        network="mainnet",
        depth=0,
        parent_fingerprint=_ZERO4,
        child_number=0,
    ):
        """Build an extended public key from a secp256k1 verifying key."""
        return cls(
            verifying_key,
            chain_code,
            network,
            depth,
            parent_fingerprint,
            child_number,
        )

    @property
    def public_key(self):
        return self._public_key

    @property
    def identifier(self):
        return _hash160(self._public_key.to_string("compressed"))

    def neuter(self):
        return self

    def derive(self, index):
        """Derive the public child at exactly ``index``.

        Only non-hardened indices are defined.  A hardened index raises
        :class:`HardenedDerivationError`; the hardened bit is not cleared and
        no private derivation is attempted.
        """
        _check_child_number(index)
        if index & HARDENED:
            raise HardenedDerivationError(index)
        self._check_depth_for_child()
        data = self._public_key.to_string("compressed") + _ser32(index)
        digest = _hmac_sha512(self._chain_code, data)
        left = digest[:32]
        right = digest[32:]
        tweak = string_to_number(left)
        if tweak >= _CURVE_ORDER:
            raise InvalidChildKey(index, "I_L >= curve order")
        point = SECP256k1.generator * tweak + self._public_key.pubkey.point
        if point == INFINITY:
            raise InvalidChildKey(index, "derived public key is infinity")
        if isinstance(point, PointJacobi):
            point = point.scale()
        child_public = VerifyingKey.from_public_point(
            point, curve=SECP256k1, validate_point=True
        )
        return ExtendedPublicKey(
            child_public,
            right,
            self._network,
            self._depth + 1,
            self.fingerprint,
            index,
        )

    def _payload(self):
        key_data = self._public_key.to_string("compressed")
        return (
            _ser32(self._version)
            + int2byte(self._depth)
            + self._parent_fingerprint
            + _ser32(self._child_number)
            + self._chain_code
            + key_data
        )

    def __repr__(self):
        return (
            "ExtendedPublicKey(network={0!r}, depth={1}, "
            "child_number={2})".format(
                self._network, self._depth, self._child_number
            )
        )


def master_from_seed(seed, network="mainnet"):
    """Return the BIP32 master extended private key for ``seed``."""
    return ExtendedPrivateKey.master_from_seed(seed, network)
