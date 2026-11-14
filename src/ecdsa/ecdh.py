"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

import threading
from contextlib import contextmanager

from .util import number_to_string
from .ellipticcurve import INFINITY
from .keys import SigningKey, VerifyingKey


__all__ = [
    "ECDH",
    "NoKeyError",
    "NoCurveError",
    "InvalidCurveError",
    "InvalidSharedSecretError",
    "ConcurrentUseError",
]


class NoKeyError(Exception):
    """ECDH. Key not found but it is needed for operation."""

    pass


class NoCurveError(Exception):
    """ECDH. Curve not set but it is needed for operation."""

    pass


class InvalidCurveError(Exception):
    """
    ECDH. Raised in case the public and private keys use different curves.
    """

    pass


class InvalidSharedSecretError(Exception):
    """ECDH. Raised in case the shared secret we obtained is an INFINITY."""

    pass


class ConcurrentUseError(Exception):
    """
    ECDH. Raised when the object is used from multiple threads at once.

    A single ECDH object does not support concurrent use: any operation
    started while another one is in progress is rejected with this
    exception instead of producing a mixed session state.
    """

    pass


class ECDH(object):
    """
    Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.

    Allows two parties, each having an elliptic-curve public-private key
    pair, to establish a shared secret over an insecure channel.

    A complete session consists of three pieces of state that belong
    together: the curve, the local private key, and the received public
    key of the peer. Two APIs manage that state:

    * :meth:`configure_session` (the recommended one, especially when
      ECDH objects are pooled and reused for multiple handshakes) sets
      the curve and both keys atomically, as a single unit. It validates
      everything before committing: on failure the previous session is
      kept fully intact, on success the old session is replaced
      wholesale. A successful call therefore always leaves exactly one
      complete, self-consistent session in the object.
    * The incremental legacy API (:meth:`set_curve`,
      :meth:`generate_private_key`, :meth:`load_private_key`,
      :meth:`load_received_public_key` and the ``*_bytes``/``*_der``/
      ``*_pem`` variants) is kept for backwards compatibility. To avoid
      silently carrying a peer public key over into an exchange it does
      not belong to, replacing the local private key drops the received
      public key, and changing the curve drops both keys. The object
      then is in an explicit non-computable state in which
      :meth:`generate_sharedsecret` raises :class:`NoKeyError` until a
      matching peer key is loaded.

    :meth:`reset` discards the whole session explicitly, also leaving
    the object in the non-computable state.

    A single ECDH object is not safe for concurrent use. Concurrent
    calls are detected and rejected with :class:`ConcurrentUseError`;
    use one object per thread (or serialise access externally) instead.
    """

    def __init__(self, curve=None, private_key=None, public_key=None):
        """
        ECDH init.

        Call can be initialised without parameters, then the first operation
        (loading either key) will set the used curve.
        All parameters must be ultimately set before shared secret
        calculation will be allowed.

        :param curve: curve for operations
        :type curve: Curve
        :param private_key: `my` private key for ECDH
        :type private_key: SigningKey
        :param public_key:  `their` public key for ECDH
        :type public_key: VerifyingKey
        """
        self._lock = threading.Lock()
        self.curve = curve
        self.private_key = None
        self.public_key = None
        if private_key:
            self._load_private_key(private_key)
        if public_key:
            self._load_received_public_key(public_key)

    @contextmanager
    def _exclusive(self):
        """
        Serialise operations on this object.

        The object does not support concurrent use, so instead of
        blocking, a second overlapping operation is rejected reliably
        with :class:`ConcurrentUseError`.
        """
        if not self._lock.acquire(False):
            raise ConcurrentUseError(
                "ECDH object is being used by another thread; concurrent "
                "use of a single ECDH object is not supported."
            )
        try:
            yield
        finally:
            self._lock.release()

    def _get_shared_secret(self, remote_public_key):
        if not self.private_key:
            raise NoKeyError(
                "Private key needs to be set to create shared secret"
            )
        if not self.public_key:
            raise NoKeyError(
                "Public key needs to be set to create shared secret"
            )
        if not (
            self.private_key.curve == self.curve == remote_public_key.curve
        ):
            raise InvalidCurveError(
                "Curves for public key and private key is not equal."
            )

        # shared secret = PUBKEYtheirs * PRIVATEKEYours
        result = (
            remote_public_key.pubkey.point
            * self.private_key.privkey.secret_multiplier
        )
        if result == INFINITY:
            raise InvalidSharedSecretError("Invalid shared secret (INFINITY).")

        return result.x()

    def configure_session(self, curve=None, private_key=None, public_key=None):
        """
        Configure a complete ECDH session atomically.

        The curve, the local private key, and the received public key of
        the peer are validated together and take effect as a single
        unit. This is the recommended way to (re)initialise an ECDH
        object, in particular when objects are pooled and reused for
        multiple handshakes: it is impossible to observe or compute with
        a mix of parameters from two different exchanges.

        The call is all-or-nothing: if any parameter is missing or
        inconsistent, an exception is raised and the previously
        configured session (if any) is left completely untouched, so it
        can still be used or explicitly discarded with :meth:`reset`.
        On success the previous session is replaced wholesale - no key
        or curve from a previous exchange is carried over.

        :param curve: curve for operations
        :type curve: Curve
        :param private_key: `my` private key for ECDH
        :type private_key: SigningKey
        :param public_key: `their` public key for ECDH
        :type public_key: VerifyingKey

        :raises NoCurveError: curve not provided
        :raises NoKeyError: private_key or public_key not provided
        :raises InvalidCurveError: the keys do not match the curve
        :raises ConcurrentUseError: the object is busy in another thread

        :return: public (verifying) key matching the local private key,
            to be sent to the remote party
        :rtype: VerifyingKey
        """
        with self._exclusive():
            # Validate and compute everything before touching the object
            # state, so that a failure leaves the old session intact.
            if curve is None:
                raise NoCurveError(
                    "Curve must be provided to configure a session."
                )
            if private_key is None:
                raise NoKeyError(
                    "Private key must be provided to configure a session."
                )
            if public_key is None:
                raise NoKeyError(
                    "Public key must be provided to configure a session."
                )
            if not (private_key.curve == curve == public_key.curve):
                raise InvalidCurveError(
                    "Curve mismatch between the provided keys and the "
                    "session curve."
                )
            verifying_key = private_key.get_verifying_key()
            # All checks passed: commit the new session as one unit.
            self.curve = curve
            self.private_key = private_key
            self.public_key = public_key
            return verifying_key

    def reset(self):
        """
        Discard the whole session explicitly.

        Clears the curve and both keys, putting the object into a
        non-computable state: :meth:`generate_sharedsecret` will raise
        :class:`NoKeyError` until a new session is configured (with
        :meth:`configure_session` or the incremental legacy API).

        :raises ConcurrentUseError: the object is busy in another thread
        """
        with self._exclusive():
            self.curve = None
            self.private_key = None
            self.public_key = None

    def set_curve(self, key_curve):
        """
        Set the working curve for ecdh operations.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Changing to a different curve invalidates the keys of the
        previous exchange, so both the private key and the received
        public key are dropped: a peer key must never be carried over
        silently into an exchange it does not belong to. The object is
        then in a non-computable state until new keys are loaded.
        Setting the same curve that is already in use leaves the session
        untouched.

        :param key_curve: curve from `curves` module
        :type key_curve: Curve

        :raises ConcurrentUseError: the object is busy in another thread
        """
        with self._exclusive():
            self._set_curve(key_curve)

    def _set_curve(self, key_curve):
        if self.curve is not None and key_curve != self.curve:
            # keys belong to the previous curve, they are not valid for
            # the new one; drop them so no stale peer key can be reused
            self.private_key = None
            self.public_key = None
        self.curve = key_curve

    def generate_private_key(self):
        """
        Generate local private key for ecdh operation with curve that was set.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step. Like
        :meth:`load_private_key`, replacing an existing private key
        drops the received public key of the previous exchange.

        :raises NoCurveError: Curve must be set before key generation.
        :raises ConcurrentUseError: the object is busy in another thread

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        with self._exclusive():
            if not self.curve:
                raise NoCurveError("Curve must be set prior to key generation.")
            return self._load_private_key(SigningKey.generate(curve=self.curve))

    def load_private_key(self, private_key):
        """
        Load private key from SigningKey (keys.py) object.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Needs to have the same curve as was set with set_curve method.
        If curve is not set - it sets from this SigningKey.

        Replacing an already loaded private key starts a new exchange,
        so the received public key of the previous exchange (if any) is
        dropped: it must not be reused silently with the new local key.
        The object is then in a non-computable state until a new peer
        key is loaded.

        :param private_key: Initialised SigningKey class
        :type private_key: SigningKey

        :raises InvalidCurveError: private_key curve not the same as self.curve
        :raises ConcurrentUseError: the object is busy in another thread

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        with self._exclusive():
            return self._load_private_key(private_key)

    def _load_private_key(self, private_key):
        if not self.curve:
            self.curve = private_key.curve
        if self.curve != private_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        if self.private_key is not None and self.private_key is not private_key:
            # a new local key means a new exchange; the previously
            # received public key does not belong to it
            self.public_key = None
        self.private_key = private_key
        return self.private_key.get_verifying_key()

    def load_private_key_bytes(self, private_key):
        """
        Load private key from byte string.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Uses current curve and checks if the provided key matches
        the curve of ECDH key agreement.
        Key loads via from_string method of SigningKey class

        :param private_key: private key in bytes string format
        :type private_key: :term:`bytes-like object`

        :raises NoCurveError: Curve must be set before loading.
        :raises ConcurrentUseError: the object is busy in another thread

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        with self._exclusive():
            if not self.curve:
                raise NoCurveError("Curve must be set prior to key load.")
            return self._load_private_key(
                SigningKey.from_string(private_key, curve=self.curve)
            )

    def load_private_key_der(self, private_key_der):
        """
        Load private key from DER byte string.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only DER format supported is the RFC5915
        Look at keys.py:SigningKey.from_der()

        :param private_key_der: string with the DER encoding of private ECDSA
            key
        :type private_key_der: string

        :raises InvalidCurveError: private_key curve not the same as self.curve
        :raises ConcurrentUseError: the object is busy in another thread

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        with self._exclusive():
            return self._load_private_key(SigningKey.from_der(private_key_der))

    def load_private_key_pem(self, private_key_pem):
        """
        Load private key from PEM string.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only PEM format supported is the RFC5915
        Look at keys.py:SigningKey.from_pem()
        it needs to have `EC PRIVATE KEY` section

        :param private_key_pem: string with PEM-encoded private ECDSA key
        :type private_key_pem: string

        :raises InvalidCurveError: private_key curve not the same as self.curve
        :raises ConcurrentUseError: the object is busy in another thread

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        with self._exclusive():
            return self._load_private_key(SigningKey.from_pem(private_key_pem))

    def get_public_key(self):
        """
        Provides a public key that matches the local private key.

        Needs to be sent to the remote party.

        :return: public (verifying) key from local private key.
        :rtype: VerifyingKey
        """
        return self.private_key.get_verifying_key()

    def load_received_public_key(self, public_key):
        """
        Load public key from VerifyingKey (keys.py) object.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Needs to have the same curve as set as current for ecdh operation.
        If curve is not set - it sets it from VerifyingKey.

        :param public_key: Initialised VerifyingKey class
        :type public_key: VerifyingKey

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises ConcurrentUseError: the object is busy in another thread
        """
        with self._exclusive():
            self._load_received_public_key(public_key)

    def _load_received_public_key(self, public_key):
        if not self.curve:
            self.curve = public_key.curve
        if self.curve != public_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.public_key = public_key

    def load_received_public_key_bytes(
        self, public_key_str, valid_encodings=None
    ):
        """
        Load public key from byte string.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Uses current curve and checks if key length corresponds to
        the current curve.
        Key loads via from_string method of VerifyingKey class

        :param public_key_str: public key in bytes string format
        :type public_key_str: :term:`bytes-like object`
        :param valid_encodings: list of acceptable point encoding formats,
            supported ones are: :term:`uncompressed`, :term:`compressed`,
            :term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
            name). All formats by default (specified with ``None``).
        :type valid_encodings: :term:`set-like object`

        :raises ConcurrentUseError: the object is busy in another thread
        """
        with self._exclusive():
            self._load_received_public_key(
                VerifyingKey.from_string(
                    public_key_str, self.curve, valid_encodings
                )
            )

    def load_received_public_key_der(self, public_key_der):
        """
        Load public key from DER byte string.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only DER format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_der()

        :param public_key_der: string with the DER encoding of public ECDSA key
        :type public_key_der: string

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises ConcurrentUseError: the object is busy in another thread
        """
        with self._exclusive():
            self._load_received_public_key(
                VerifyingKey.from_der(public_key_der)
            )

    def load_received_public_key_pem(self, public_key_pem):
        """
        Load public key from PEM string.

        Legacy incremental API; prefer :meth:`configure_session` for
        setting up a session in one step.

        Compares the curve of the PEM-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only PEM format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_pem()

        :param public_key_pem: string with PEM-encoded public ECDSA key
        :type public_key_pem: string

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises ConcurrentUseError: the object is busy in another thread
        """
        with self._exclusive():
            self._load_received_public_key(
                VerifyingKey.from_pem(public_key_pem)
            )

    def generate_sharedsecret_bytes(self):
        """
        Generate shared secret from local private key and remote public key.

        The objects needs to have both private key and received public key
        before generation is allowed.

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises NoKeyError: public_key or private_key is not set
        :raises ConcurrentUseError: the object is busy in another thread

        :return: shared secret
        :rtype: bytes
        """
        with self._exclusive():
            return number_to_string(
                self._get_shared_secret(self.public_key),
                self.private_key.curve.curve.p(),
            )

    def generate_sharedsecret(self):
        """
        Generate shared secret from local private key and remote public key.

        The objects needs to have both private key and received public key
        before generation is allowed.

        It's the same for local and remote party,
        shared secret(local private key, remote public key) ==
        shared secret(local public key, remote private key)

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises NoKeyError: public_key or private_key is not set
        :raises ConcurrentUseError: the object is busy in another thread

        :return: shared secret
        :rtype: int
        """
        with self._exclusive():
            return self._get_shared_secret(self.public_key)
