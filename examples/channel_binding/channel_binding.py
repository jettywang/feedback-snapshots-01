"""Channel binding for a login proof carried inside a Noise channel.

The login proof in this example is an HMAC-SHA256 tag issued by a test
issuer.  The tag covers:

  * a domain separator,
  * the service name,
  * the user identity,
  * the presenter's Noise role (initiator or responder),
  * the completed Noise handshake hash.

The handshake hash is public transcript material.  It is not a password,
an access token, or a substitute for the issuer key.  The proof is
authenticated by the HMAC issuer key, which is deliberately separate from
all Noise static and transport keys.

This module is an integration example.  A production system still needs
its own user authentication, issuer key management, authorization, replay
policy, and rate limiting.
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from noise.connection import Keypair, NoiseConnection


PROTOCOL_LABEL = b'noise-login-channel-binding-v1'
PROOF_DOMAIN = b'noise-login-hmac-proof-v1'
PROOF_MAGIC = b'NPB1'
LOGIN_ACCEPTED = b'noise-login-accepted-v1'

ROLE_INITIATOR = 'initiator'
ROLE_RESPONDER = 'responder'
ROLES = (ROLE_INITIATOR, ROLE_RESPONDER)

DEFAULT_PROTOCOL = b'Noise_KK_25519_ChaChaPoly_SHA256'
TAG_LEN = 32
MIN_HASH_LEN = 16
MAX_HASH_LEN = 64
MAX_FIELD_LEN = 4096


class LoginBindingError(Exception):
    """Base class for channel-binding and login-proof errors."""


class LoginProofError(LoginBindingError):
    """The proof is malformed, misbound, or has an invalid HMAC tag."""


class LoginStateError(LoginBindingError):
    """The channel is not ready for the requested login operation."""


class LoginAdmissionError(LoginBindingError):
    """The authenticated peer failed the local admission policy."""


def build_prologue(service):
    """Return the Noise prologue used for a given service name.

    Binding the service in the prologue is defense in depth.  The actual
    login proof also binds the service name, so a proof for service A
    cannot be accepted by service B even if the prologue were ignored.
    """
    if not isinstance(service, str) or not service:
        raise LoginBindingError('service must be a non-empty string')
    return PROTOCOL_LABEL + b'|' + service.encode('utf-8')


def generate_static_keypair():
    """Generate an X25519 static keypair as raw private/public bytes."""
    private_key = x25519.X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def generate_issuer_key():
    """Generate a test issuer key, independent of every Noise key."""
    return os.urandom(32)


def _encode_parts(parts):
    output = bytearray(PROOF_MAGIC)
    for part in parts:
        if len(part) > MAX_FIELD_LEN:
            raise LoginProofError('proof field is too long')
        output += struct.pack('!I', len(part))
        output += part
    return bytes(output)


def _decode_parts(data):
    if not isinstance(data, bytes):
        raise LoginProofError('serialized proof must be bytes')
    if not data.startswith(PROOF_MAGIC):
        raise LoginProofError('invalid proof magic')
    offset = len(PROOF_MAGIC)
    parts = []
    for _ in range(5):
        if offset + 4 > len(data):
            raise LoginProofError('truncated proof')
        length = struct.unpack('!I', data[offset:offset + 4])[0]
        offset += 4
        if length > MAX_FIELD_LEN:
            raise LoginProofError('proof field is too long')
        if offset + length > len(data):
            raise LoginProofError('truncated proof')
        parts.append(data[offset:offset + length])
        offset += length
    if offset != len(data):
        raise LoginProofError('trailing bytes in proof')
    return parts


def _proof_tag(signing_key, service, user, role, handshake_hash):
    message = _encode_parts([
        PROOF_DOMAIN,
        service.encode('utf-8'),
        user.encode('utf-8'),
        role.encode('ascii'),
        handshake_hash,
    ])
    return hmac.new(signing_key, message, hashlib.sha256).digest()


class LoginProof(object):
    """An HMAC login proof bound to one Noise connection.

    The fields are intentionally visible: they describe what was bound.
    Consequential security comes from the tag, which is checked against
    the accepting channel's handshake hash and the verifier's issuer key.
    """

    __slots__ = ('service', 'user', 'role', 'handshake_hash', 'tag')

    def __init__(self, service, user, role, handshake_hash, tag):
        if not isinstance(service, str) or not service:
            raise LoginProofError('service must be a non-empty string')
        if not isinstance(user, str) or not user:
            raise LoginProofError('user must be a non-empty string')
        if role not in ROLES:
            raise LoginProofError('role must be one of {}'.format(ROLES))
        if not isinstance(handshake_hash, bytes):
            raise LoginProofError('handshake_hash must be bytes')
        if not MIN_HASH_LEN <= len(handshake_hash) <= MAX_HASH_LEN:
            raise LoginProofError('unexpected handshake hash length')
        if not isinstance(tag, bytes) or len(tag) != TAG_LEN:
            raise LoginProofError('proof tag must be {} bytes'.format(TAG_LEN))
        self.service = service
        self.user = user
        self.role = role
        self.handshake_hash = handshake_hash
        self.tag = tag

    def to_bytes(self):
        return _encode_parts([
            self.service.encode('utf-8'),
            self.user.encode('utf-8'),
            self.role.encode('ascii'),
            self.handshake_hash,
            self.tag,
        ])

    @classmethod
    def from_bytes(cls, data):
        service, user, role, handshake_hash, tag = _decode_parts(data)
        try:
            service = service.decode('utf-8')
            user = user.decode('utf-8')
            role = role.decode('ascii')
        except UnicodeDecodeError:
            raise LoginProofError('proof fields are not valid text')
        return cls(service, user, role, handshake_hash, tag)

    def __repr__(self):
        return 'LoginProof(service={!r}, user={!r}, role={!r}, handshake_hash={!r})'.format(
            self.service, self.user, self.role, self.handshake_hash
        )


class HmacLoginIssuer(object):
    """Test-only HMAC issuer.

    The signing key must be at least 32 bytes and must be managed
    independently of every Noise key.  In a production system this
    component represents the authority that has already authenticated the
    user and is willing to assert the user's identity to the verifier.
    """

    def __init__(self, signing_key):
        if not isinstance(signing_key, (bytes, bytearray)):
            raise LoginBindingError('issuer key must be bytes')
        signing_key = bytes(signing_key)
        if len(signing_key) < 32:
            raise LoginBindingError('issuer key must be at least 32 bytes')
        self._signing_key = signing_key

    def issue(self, service, user, handshake_hash, presenter_role):
        if presenter_role not in ROLES:
            raise LoginBindingError('presenter_role must be one of {}'.format(ROLES))
        tag = _proof_tag(self._signing_key, service, user, presenter_role, handshake_hash)
        return LoginProof(service, user, presenter_role, handshake_hash, tag)


class HmacLoginVerifier(object):
    """Verifies proofs using the issuer's shared HMAC key.

    ``verify`` must be called with the handshake hash of the channel that
    actually received the proof.  It never trusts the hash carried in the
    proof for the tag calculation; that carried hash is only compared for
    an explicit binding failure.
    """

    def __init__(self, signing_key):
        if not isinstance(signing_key, (bytes, bytearray)):
            raise LoginBindingError('verifier key must be bytes')
        signing_key = bytes(signing_key)
        if len(signing_key) < 32:
            raise LoginBindingError('verifier key must be at least 32 bytes')
        self._signing_key = signing_key

    def verify(self, proof, expected_service, expected_role, handshake_hash):
        if not isinstance(proof, LoginProof):
            raise LoginProofError('proof must be a LoginProof')
        if not isinstance(expected_service, str) or not expected_service:
            raise LoginProofError('expected_service must be a non-empty string')
        if expected_role not in ROLES:
            raise LoginProofError('expected_role must be one of {}'.format(ROLES))
        if not isinstance(handshake_hash, bytes):
            raise LoginProofError('handshake_hash must be bytes')

        if proof.service != expected_service:
            raise LoginProofError('proof is bound to a different service')
        if proof.role != expected_role:
            raise LoginProofError('proof is bound to a different role')
        if len(proof.handshake_hash) != len(handshake_hash):
            raise LoginProofError('proof is bound to a different handshake')
        if not hmac.compare_digest(proof.handshake_hash, handshake_hash):
            raise LoginProofError('proof is bound to a different handshake')

        expected_tag = _proof_tag(
            self._signing_key, expected_service, proof.user, expected_role, handshake_hash
        )
        if not hmac.compare_digest(proof.tag, expected_tag):
            raise LoginProofError('invalid proof tag')
        return proof.user


class NoiseLoginChannel(object):
    """State machine around a NoiseConnection used for login binding.

    Lifecycle:
      1. Complete the Noise handshake.
      2. Call ``confirm_admission`` after checking the peer's authenticated
         static key against the local admission policy.
      3. Exchange a login proof with ``seal_login`` / ``accept_login``.
      4. Only after successful verification may protected operations use
         ``seal`` / ``open``.

    A failed ``accept_login`` leaves no authenticated identity and does not
    mark the channel as logged in.  The example allows a later, correctly
    bound proof to be tried; production code should normally close the
    connection or apply a strict retry policy after a failed login.
    """

    def __init__(self, connection, service, local_role, expected_remote_static=None):
        if not isinstance(connection, NoiseConnection):
            raise LoginBindingError('connection must be a NoiseConnection')
        if not isinstance(service, str) or not service:
            raise LoginBindingError('service must be a non-empty string')
        if local_role not in ROLES:
            raise LoginBindingError('local_role must be one of {}'.format(ROLES))
        if expected_remote_static is not None and not isinstance(expected_remote_static, bytes):
            raise LoginBindingError('expected_remote_static must be bytes or None')

        self.connection = connection
        self.service = service
        self.local_role = local_role
        self.expected_remote_static = expected_remote_static
        self._admitted = False
        self._authenticated_user = None
        self._failed_attempts = 0
        self._closed = False

    @property
    def is_authenticated(self):
        return self._authenticated_user is not None

    @property
    def authenticated_user(self):
        return self._authenticated_user

    @property
    def failed_attempts(self):
        return self._failed_attempts

    @property
    def is_closed(self):
        return self._closed

    @property
    def handshake_finished(self):
        return self.connection.handshake_finished

    @property
    def handshake_hash(self):
        return self.connection.get_handshake_hash()

    @property
    def remote_role(self):
        return ROLE_RESPONDER if self.local_role == ROLE_INITIATOR else ROLE_INITIATOR

    def confirm_admission(self):
        """Confirm the completed handshake and admit the authenticated peer."""
        if self._closed:
            raise LoginStateError('channel is closed')
        if not self.connection.handshake_finished:
            raise LoginStateError('Noise handshake is not finished')
        if self.expected_remote_static is not None:
            remote_static = self.connection.noise_protocol.keypairs.get('rs')
            if remote_static is None:
                self._admitted = False
                raise LoginAdmissionError('peer static key is unavailable')
            if not hmac.compare_digest(remote_static.public_bytes, self.expected_remote_static):
                self._admitted = False
                raise LoginAdmissionError('peer admission failed')
        self._admitted = True
        return self

    def require_binding_ready(self):
        """Require a completed handshake and an admitted peer."""
        if self._closed:
            raise LoginStateError('channel is closed')
        if not self.connection.handshake_finished:
            raise LoginStateError('Noise handshake is not finished')
        if not self._admitted:
            raise LoginStateError('peer admission has not been confirmed')
        return self

    def seal_login(self, proof):
        """Serialize and encrypt a proof for this channel.

        This is the presenter-side operation.  It does not decide whether
        the proof actually matches this channel; the receiver's verifier
        is authoritative.  A login proxy that forwards the wrong proof is
        therefore rejected by the service, not merely by client code.
        """
        self.require_binding_ready()
        if self._authenticated_user is not None:
            raise LoginStateError('channel is already authenticated')
        if not isinstance(proof, LoginProof):
            raise LoginProofError('proof must be a LoginProof')
        return self.connection.encrypt(proof.to_bytes())

    def accept_login(self, ciphertext, verifier):
        """Decrypt, parse, and verify a proof on the accepting channel.

        The handshake hash passed to the verifier is this channel's hash,
        not the hash claimed inside the proof.  Any failure clears the
        authenticated identity before re-raising the error.
        """
        self.require_binding_ready()
        if self._authenticated_user is not None:
            raise LoginStateError('channel is already authenticated')
        try:
            plaintext = self.connection.decrypt(ciphertext)
            proof = LoginProof.from_bytes(plaintext)
            user = verifier.verify(
                proof,
                expected_service=self.service,
                expected_role=self.remote_role,
                handshake_hash=self.handshake_hash,
            )
        except Exception:
            self._authenticated_user = None
            self._failed_attempts += 1
            raise
        self._authenticated_user = user
        return user

    def seal_login_accepted(self):
        """Send the post-verification acknowledgement on this channel."""
        self._require_authenticated()
        return self.connection.encrypt(LOGIN_ACCEPTED)

    def accept_login_accepted(self, ciphertext, expected_user):
        """Accept the server's acknowledgement and mark the client logged in."""
        self.require_binding_ready()
        if self._authenticated_user is not None:
            raise LoginStateError('channel is already authenticated')
        if not isinstance(expected_user, str) or not expected_user:
            raise LoginStateError('expected_user must be a non-empty string')
        try:
            plaintext = self.connection.decrypt(ciphertext)
            if not hmac.compare_digest(plaintext, LOGIN_ACCEPTED):
                raise LoginStateError('invalid login acknowledgement')
        except Exception:
            self._authenticated_user = None
            self._failed_attempts += 1
            raise
        self._authenticated_user = expected_user
        return expected_user

    def close(self):
        self._authenticated_user = None
        self._admitted = False
        self._closed = True

    def _require_authenticated(self):
        if self._closed:
            raise LoginStateError('channel is closed')
        if self._authenticated_user is None:
            raise LoginStateError('channel is not authenticated')
        return self

    def seal(self, payload):
        """Encrypt a protected application payload after successful login."""
        self._require_authenticated()
        if not isinstance(payload, bytes):
            raise LoginBindingError('payload must be bytes')
        return self.connection.encrypt(payload)

    def open(self, ciphertext):
        """Decrypt a protected application payload after successful login."""
        self._require_authenticated()
        return self.connection.decrypt(ciphertext)


class LoginProxy(object):
    """Test login proxy that forwards a user-bound proof into a channel.

    It obtains the proof only after the channel handshake and peer
    admission are complete.  The issuer is the trusted component that
    asserts the user's identity; the proxy does not invent identity.
    """

    def __init__(self, issuer, user):
        if not isinstance(issuer, HmacLoginIssuer):
            raise LoginBindingError('issuer must be an HmacLoginIssuer')
        if not isinstance(user, str) or not user:
            raise LoginBindingError('user must be a non-empty string')
        self.issuer = issuer
        self.user = user

    def proof_for(self, channel):
        channel.require_binding_ready()
        return self.issuer.issue(
            service=channel.service,
            user=self.user,
            handshake_hash=channel.handshake_hash,
            presenter_role=channel.local_role,
        )

    def login(self, channel):
        return channel.seal_login(self.proof_for(channel))


def establish_kk_channels(client_private, client_public,
                          server_private, server_public,
                          service, protocol_name=DEFAULT_PROTOCOL, admit=True):
    """Run a complete KK handshake and return two admitted login channels.

    KK authenticates both static public keys during the handshake.  The
    explicit expected-remote-static checks in ``confirm_admission`` model
    an additional local peer-admission policy.
    """
    prologue = build_prologue(service)

    client = NoiseConnection.from_name(protocol_name)
    client.set_as_initiator()
    client.set_keypair_from_private_bytes(Keypair.STATIC, client_private)
    client.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_public)
    client.set_prologue(prologue)
    client.start_handshake()

    server = NoiseConnection.from_name(protocol_name)
    server.set_as_responder()
    server.set_keypair_from_private_bytes(Keypair.STATIC, server_private)
    server.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, client_public)
    server.set_prologue(prologue)
    server.start_handshake()

    first = client.write_message()
    server.read_message(first)
    second = server.write_message()
    client.read_message(second)

    client_channel = NoiseLoginChannel(
        client, service, ROLE_INITIATOR, expected_remote_static=server_public
    )
    server_channel = NoiseLoginChannel(
        server, service, ROLE_RESPONDER, expected_remote_static=client_public
    )
    if admit:
        client_channel.confirm_admission()
        server_channel.confirm_admission()
    return client_channel, server_channel
