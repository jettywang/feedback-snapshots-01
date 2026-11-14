"""
HKDF key derivation and key confirmation on top of ECDH.

This module is an example of how to turn the raw ECDH shared secret into
separate, direction-specific traffic keys and explicit key confirmation.
It deliberately uses only the standard library :mod:`hashlib` and
:mod:`hmac` modules together with the existing
:class:`~ecdsa.ecdh.ECDH` class; it does not implement, and is not a
substitute for, an authenticated key exchange. Both parties are assumed to
have been authenticated by a layer above (for example by validating
certificates or signatures over the exchanged public keys).

The derivation input (the "handshake transcript") is bound to:

* the protocol version,
* a fixed protocol identifier (so the same secret can never be reused for
  a different protocol),
* both party identities,
* both ephemeral public keys, and
* the initiator/responder role of every participant.

Every field is encoded with a fixed label and an explicit length prefix,
so two different messages can never be serialised to the same byte string:
there is no ambiguity from bare concatenation, empty fields, or field
boundaries.

References:
    RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    NIST SP 800-56C - Key derivation using a single-step/HKDF construction
"""

import hashlib
import hmac
import struct

from ._compat import str_idx_as_int
from .ecdh import ECDH

__all__ = [
    "PROTOCOL_VERSION",
    "PROTOCOL_ID",
    "ROLE_INITIATOR",
    "ROLE_RESPONDER",
    "KeyConfirmationError",
    "encode_fields",
    "hkdf_extract",
    "hkdf_expand",
    "hkdf",
    "encode_public_key",
    "shared_secret_from_ecdh",
    "HandshakeContext",
    "derive_session_keys",
    "confirmation_tag",
    "verify_confirmation_tag",
    "HandshakeParty",
    "run_in_memory_handshake",
]


#: Example protocol version bound into every derivation.
PROTOCOL_VERSION = b"example-hkdf-kc/1.0"

#: Fixed identifier that namespaces this example away from any other
#: protocol that might ever use the same shared secret.
PROTOCOL_ID = b"python-ecdsa.example.hkdf-key-confirmation"

#: Role labels used when binding the handshake transcript.
ROLE_INITIATOR = b"initiator"
ROLE_RESPONDER = b"responder"


class KeyConfirmationError(Exception):
    """Raised when a key confirmation tag cannot be verified."""

    pass


def _hmac(key, data, hash_name):
    """Return an HMAC digest, accepting bytes-like key and data."""
    return hmac.new(bytes(key), bytes(data), hash_name).digest()


def _constant_time_compare(first, second):
    """
    Compare two byte strings without short-circuiting on the first mismatch.

    Uses :func:`hmac.compare_digest` when available (Python 2.7.7 / 3.3 and
    newer) and falls back to a manual constant-time comparison on older
    interpreters that this library still supports.
    """
    first = bytes(first)
    second = bytes(second)
    if hasattr(hmac, "compare_digest"):
        return hmac.compare_digest(first, second)
    if len(first) != len(second):
        return False
    result = 0
    for index in range(len(first)):
        result |= str_idx_as_int(first, index) ^ str_idx_as_int(
            second, index
        )
    return result == 0


def encode_fields(fields):
    """
    Encode labelled fields into an unambiguous byte string.

    Each ``(label, value)`` pair is rendered as::

        len(label) || label || len(value) || value

    with both lengths as unsigned 32-bit big-endian integers. The labels and
    the order of the pairs are fixed by the caller, so the encoding is
    canonical and free of the ambiguity of bare concatenation: swapping two
    fields, changing a label, or moving a byte across a field boundary all
    change the output.

    :param fields: ordered ``(label, value)`` pairs, both byte strings
    :type fields: iterable of tuple(bytes, bytes)

    :return: the length-prefixed serialisation
    :rtype: bytes
    """
    parts = []
    for label, value in fields:
        label = bytes(label)
        value = bytes(value)
        parts.append(struct.pack(">I", len(label)))
        parts.append(label)
        parts.append(struct.pack(">I", len(value)))
        parts.append(value)
    return b"".join(parts)


def hkdf_extract(salt, input_key_material, hash_name="sha256"):
    """
    HKDF-Extract step from RFC 5869.

    :param salt: optional salt value (a non-secret random value); an empty
        or ``None`` salt is replaced by a string of zeros of the hash length,
        as required by the RFC
    :type salt: bytes-like object or None
    :param input_key_material: the input keying material, here the raw ECDH
        shared secret
    :type input_key_material: bytes-like object
    :param hash_name: name of the hash function, e.g. ``"sha256"``
    :type hash_name: str

    :return: the pseudorandom key (PRK)
    :rtype: bytes
    """
    hash_length = hashlib.new(hash_name).digest_size
    if not salt:
        salt = b"\x00" * hash_length
    return _hmac(salt, input_key_material, hash_name)


def hkdf_expand(prk, info, length, hash_name="sha256"):
    """
    HKDF-Expand step from RFC 5869.

    :param prk: the pseudorandom key from :func:`hkdf_extract`
    :type prk: bytes-like object
    :param info: optional context and application specific information
    :type info: bytes-like object
    :param length: number of output bytes to produce (at most 255 times the
        hash length)
    :type length: int
    :param hash_name: name of the hash function, e.g. ``"sha256"``
    :type hash_name: str

    :return: the output keying material
    :rtype: bytes
    """
    hash_length = hashlib.new(hash_name).digest_size
    if length <= 0:
        raise ValueError("length must be positive")
    if length > 255 * hash_length:
        raise ValueError(
            "length too large for this hash (max %d bytes)"
            % (255 * hash_length)
        )
    if info is None:
        info = b""

    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = _hmac(
            prk,
            previous + bytes(info) + struct.pack(">B", counter),
            hash_name,
        )
        output += previous
        counter += 1
    return output[:length]


def hkdf(salt, input_key_material, info, length, hash_name="sha256"):
    """
    Full HKDF (RFC 5869): extract followed by expand.

    :return: ``length`` bytes of output keying material
    :rtype: bytes
    """
    prk = hkdf_extract(salt, input_key_material, hash_name)
    return hkdf_expand(prk, info, length, hash_name)


def encode_public_key(verifying_key):
    """
    Canonical byte encoding of an ephemeral ECDH public key.

    The SEC1 uncompressed point encoding is used so that both sides bind the
    exact same public-key bytes into the transcript.

    :param verifying_key: the local or remote ECDH public key
    :type verifying_key: ecdsa.keys.VerifyingKey

    :return: SEC1 uncompressed point bytes
    :rtype: bytes
    """
    return bytes(verifying_key.to_string("uncompressed"))


def shared_secret_from_ecdh(ecdh):
    """
    Return the fixed-length ECDH shared secret as bytes.

    :class:`~ecdsa.ecdh.ECDH.generate_sharedsecret_bytes` renders the
    x-coordinate of the shared point using the full byte length of the
    curve field, so leading zero bytes are preserved. That fixed-width
    encoding matters: truncating leading zeros would change the byte string
    fed to HKDF and could let two different integer secrets collide.

    :param ecdh: an ECDH object with a private and a remote public key loaded
    :type ecdh: ecdsa.ecdh.ECDH

    :return: the shared secret, padded to the curve's field byte length
    :rtype: bytes
    """
    return bytes(ecdh.generate_sharedsecret_bytes())


class HandshakeContext(object):
    """
    All of the negotiated values that the key derivation is bound to.

    Both parties must construct *identical* contexts (same version, protocol
    identifier, identities and public keys, and the same view of who is the
    initiator and who is the responder). A mismatch in any field changes the
    transcript and therefore every derived key and confirmation tag.

    :ivar version: protocol version bytes
    :vartype version: bytes
    :ivar protocol_id: protocol identifier bytes used for cross-protocol
        separation
    :vartype protocol_id: bytes
    :ivar initiator_id: authenticated initiator identity
    :vartype initiator_id: bytes
    :ivar responder_id: authenticated responder identity
    :vartype responder_id: bytes
    :ivar initiator_public: initiator ephemeral public key (SEC1 bytes)
    :vartype initiator_public: bytes
    :ivar responder_public: responder ephemeral public key (SEC1 bytes)
    :vartype responder_public: bytes
    """

    def __init__(
        self,
        initiator_id,
        responder_id,
        initiator_public,
        responder_public,
        version=PROTOCOL_VERSION,
        protocol_id=PROTOCOL_ID,
    ):
        self.version = bytes(version)
        self.protocol_id = bytes(protocol_id)
        self.initiator_id = bytes(initiator_id)
        self.responder_id = bytes(responder_id)
        self.initiator_public = bytes(initiator_public)
        self.responder_public = bytes(responder_public)

    def transcript(self):
        """
        Build the canonical, length-prefixed handshake transcript.

        Roles are carried both by the field labels and by the explicit role
        fields, so reflecting the two parties produces a different
        transcript rather than an identical one.

        :return: the serialised transcript used as HKDF ``info``
        :rtype: bytes
        """
        return encode_fields(
            [
                (b"version", self.version),
                (b"protocol_id", self.protocol_id),
                (b"role", ROLE_INITIATOR),
                (b"identity", self.initiator_id),
                (b"ephemeral_public_key", self.initiator_public),
                (b"role", ROLE_RESPONDER),
                (b"identity", self.responder_id),
                (b"ephemeral_public_key", self.responder_public),
            ]
        )

    def __eq__(self, other):
        if not isinstance(other, HandshakeContext):
            return NotImplemented
        return self.transcript() == other.transcript()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result


def _derive_secret(prk, transcript, label, length, hash_name):
    """Derive one labelled secret from the PRK with a distinct info."""
    info = transcript + encode_fields([(b"derived_secret", label)])
    return hkdf_expand(prk, info, length, hash_name)


def derive_session_keys(shared_secret, context, hash_name="sha256"):
    """
    Derive two direction keys and two confirmation MAC keys.

    A single HKDF-Extract turns the fixed-length ECDH secret into a
    pseudorandom key. Four independent HKDF-Expand calls then produce, each
    under a distinct label, the key protecting initiator-to-responder
    traffic, the key protecting responder-to-initiator traffic, and the two
    keys used only for key confirmation. Because every label is different,
    the four outputs are domain-separated.

    :param shared_secret: the fixed-length ECDH shared secret
    :type shared_secret: bytes-like object
    :param context: the negotiated handshake context
    :type context: HandshakeContext
    :param hash_name: hash function for HKDF and HMAC
    :type hash_name: str

    :return: a dict with the four derived byte strings
    :rtype: dict
    """
    hash_length = hashlib.new(hash_name).digest_size
    prk = hkdf_extract(None, shared_secret, hash_name)
    transcript = context.transcript()
    return {
        "initiator_to_responder_key": _derive_secret(
            prk,
            transcript,
            b"initiator_to_responder_traffic",
            hash_length,
            hash_name,
        ),
        "responder_to_initiator_key": _derive_secret(
            prk,
            transcript,
            b"responder_to_initiator_traffic",
            hash_length,
            hash_name,
        ),
        "initiator_confirmation_key": _derive_secret(
            prk,
            transcript,
            b"initiator_confirmation",
            hash_length,
            hash_name,
        ),
        "responder_confirmation_key": _derive_secret(
            prk,
            transcript,
            b"responder_confirmation",
            hash_length,
            hash_name,
        ),
    }


def confirmation_tag(confirmation_key, transcript, hash_name="sha256"):
    """
    Compute a key confirmation tag over the handshake transcript.

    The tag proves possession of the shared secret (and therefore of the
    derived confirmation key) without revealing either one.

    :param confirmation_key: the sender's derived confirmation key
    :type confirmation_key: bytes-like object
    :param transcript: the canonical handshake transcript
    :type transcript: bytes-like object
    :param hash_name: hash function for the HMAC
    :type hash_name: str

    :return: the HMAC confirmation tag
    :rtype: bytes
    """
    return _hmac(confirmation_key, transcript, hash_name)


def verify_confirmation_tag(
    confirmation_key, transcript, tag, hash_name="sha256"
):
    """
    Verify a key confirmation tag in constant time.

    :param confirmation_key: the expected sender's confirmation key
    :type confirmation_key: bytes-like object
    :param transcript: the canonical handshake transcript
    :type transcript: bytes-like object
    :param tag: the received tag
    :type tag: bytes-like object
    :param hash_name: hash function for the HMAC
    :type hash_name: str

    :raises KeyConfirmationError: if the tag does not match

    :return: ``True`` when the tag is valid
    :rtype: bool
    """
    expected = confirmation_tag(confirmation_key, transcript, hash_name)
    if not _constant_time_compare(expected, bytes(tag)):
        raise KeyConfirmationError("key confirmation tag mismatch")
    return True


class HandshakeParty(object):
    """
    One endpoint of the example in-memory handshake.

    A party wraps an :class:`~ecdsa.ecdh.ECDH` instance and the identity it
    has been authenticated under by the layer above. It derives the same
    session keys as its peer and produces/checks confirmation tags.

    :ivar identity: the authenticated identity of this party
    :vartype identity: bytes
    :ivar ecdh: the underlying ECDH key agreement object
    :vartype ecdh: ecdsa.ecdh.ECDH
    """

    def __init__(self, identity, curve, hash_name="sha256"):
        self.identity = bytes(identity)
        self.hash_name = hash_name
        self.ecdh = ECDH(curve=curve)
        self.public_key = self.ecdh.generate_private_key()
        self.public_bytes = encode_public_key(self.public_key)
        self._secrets = None

    def complete(self, context):
        """
        Derive the session keys from the agreed context and shared secret.

        :param context: the mutually negotiated handshake context
        :type context: HandshakeContext

        :return: the four derived secrets
        :rtype: dict
        """
        secret = shared_secret_from_ecdh(self.ecdh)
        self._secrets = derive_session_keys(secret, context, self.hash_name)
        return self._secrets

    def make_confirmation(self, context, role):
        """
        Produce this party's confirmation tag.

        :param context: the negotiated handshake context
        :type context: HandshakeContext
        :param role: :data:`ROLE_INITIATOR` or :data:`ROLE_RESPONDER`
        :type role: bytes

        :return: the HMAC tag over the transcript
        :rtype: bytes
        """
        if role == ROLE_INITIATOR:
            key = self._secrets["initiator_confirmation_key"]
        elif role == ROLE_RESPONDER:
            key = self._secrets["responder_confirmation_key"]
        else:
            raise ValueError("unknown role %r" % role)
        return confirmation_tag(key, context.transcript(), self.hash_name)

    def check_peer_confirmation(self, context, peer_role, tag):
        """
        Verify the peer's confirmation tag.

        :param context: the negotiated handshake context
        :type context: HandshakeContext
        :param peer_role: the role the peer claims
        :type peer_role: bytes
        :param tag: the peer's confirmation tag
        :type tag: bytes

        :raises KeyConfirmationError: if verification fails

        :return: ``True`` when the peer is confirmed
        :rtype: bool
        """
        if peer_role == ROLE_INITIATOR:
            key = self._secrets["initiator_confirmation_key"]
        elif peer_role == ROLE_RESPONDER:
            key = self._secrets["responder_confirmation_key"]
        else:
            raise ValueError("unknown role %r" % peer_role)
        return verify_confirmation_tag(
            key, context.transcript(), tag, self.hash_name
        )


def run_in_memory_handshake(curve, hash_name="sha256"):
    """
    Run the full example handshake between two parties in memory.

    The steps mirror a real deployment:

    1. Each party generates an ephemeral ECDH key pair.
    2. They exchange (and, in a real system, authenticate) identities and
       public keys.
    3. Both build the same :class:`HandshakeContext` and derive keys.
    4. They exchange HMAC confirmation tags and verify the peer.

    The function returns everything needed to inspect or assert on the
    result. It does not send anything over a real network.

    :param curve: the NIST/Brainpool curve to use, e.g. ``NIST256p``
    :type curve: ecdsa.curves.Curve
    :param hash_name: hash function for HKDF and HMAC
    :type hash_name: str

    :return: ``(initiator, responder, context, secrets)`` where both parties
        have already verified each other's confirmation tag
    :rtype: tuple
    """
    initiator = HandshakeParty(b"client-alice", curve, hash_name)
    responder = HandshakeParty(b"server-bob", curve, hash_name)

    initiator.ecdh.load_received_public_key(responder.public_key)
    responder.ecdh.load_received_public_key(initiator.public_key)

    context = HandshakeContext(
        initiator.identity,
        responder.identity,
        initiator.public_bytes,
        responder.public_bytes,
    )

    initiator.complete(context)
    responder.complete(context)

    initiator_tag = initiator.make_confirmation(context, ROLE_INITIATOR)
    responder_tag = responder.make_confirmation(context, ROLE_RESPONDER)

    responder.check_peer_confirmation(context, ROLE_INITIATOR, initiator_tag)
    initiator.check_peer_confirmation(context, ROLE_RESPONDER, responder_tag)

    return initiator, responder, context, initiator._secrets
