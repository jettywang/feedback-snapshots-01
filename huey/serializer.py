import datetime
import gzip
import hashlib
import hmac
import logging
import pickle
import time
import zlib

from huey.exceptions import ConfigurationError
from huey.utils import encode


logger = logging.getLogger('huey.serializer')


def is_compressed(data):
    return data and (data[0] == 0x1f or data[0] == 0x78)


class Serializer(object):
    def __init__(self, compression=False, compression_level=6, use_zlib=False,
                 pickle_protocol=pickle.HIGHEST_PROTOCOL):
        self.comp = compression
        self.comp_level = compression_level
        self.use_zlib = use_zlib
        self.pickle_protocol = pickle_protocol or pickle.HIGHEST_PROTOCOL

    def _serialize(self, data):
        return pickle.dumps(data, self.pickle_protocol)

    def _deserialize(self, data):
        return pickle.loads(data)

    def serialize(self, data):
        data = self._serialize(data)
        if self.comp:
            if self.use_zlib:
                data = zlib.compress(data, self.comp_level)
            else:
                data = gzip.compress(data, self.comp_level)
        return data

    def deserialize(self, data):
        if self.comp:
            if not is_compressed(data):
                logger.warning('compression enabled but message data does not '
                               'appear to be compressed.')
            elif self.use_zlib:
                data = zlib.decompress(data)
            else:
                data = gzip.decompress(data)
        return self._deserialize(data)


def constant_time_compare(s1, s2):
    return hmac.compare_digest(s1, s2)


class SignedSerializer(Serializer):
    def __init__(self, secret=None, salt='huey', **kwargs):
        super(SignedSerializer, self).__init__(**kwargs)
        if not secret or not salt:
            raise ConfigurationError('The secret and salt parameters are '
                                     'required by %r' % type(self))
        self.secret = encode(secret)
        self.salt = encode(salt)
        self.separator = b':'
        self._key = hashlib.sha1(self.salt + self.secret).digest()

    def _signature(self, message):
        signature = hmac.new(self._key, msg=message, digestmod=hashlib.sha1)
        return signature.hexdigest().encode('utf8')

    def _sign(self, message):
        return message + self.separator + self._signature(message)

    def _unsign(self, signed):
        if self.separator not in signed:
            raise ValueError('Separator "%s" not found' % self.separator)

        msg, sig = signed.rsplit(self.separator, 1)
        if constant_time_compare(sig, self._signature(msg)):
            return msg

        raise ValueError('Signature "%s" mismatch!' % sig)

    def _serialize(self, message):
        data = super(SignedSerializer, self)._serialize(message)
        return self._sign(data)

    def _deserialize(self, data):
        return super(SignedSerializer, self)._deserialize(self._unsign(data))


# Signing-key lifecycle states used by the rotating signed serializer.
KEY_ACTIVE = 'active'      # Signs new messages and verifies old ones.
KEY_ACCEPTED = 'accepted'  # Verification-only, optionally until a deadline.
KEY_RETIRED = 'retired'    # Kept for identification, but never trusted.

_KEY_STATES = (KEY_ACTIVE, KEY_ACCEPTED, KEY_RETIRED)


class SigningKey(object):
    """
    A single HMAC key with a lifecycle state.

    :param str key_id: stable identifier used in configuration and logs.
    :param str secret: secret value mixed with the salt to derive the HMAC key.
    :param str state: one of ``KEY_ACTIVE``, ``KEY_ACCEPTED`` or
        ``KEY_RETIRED``.
    :param valid_until: optional deadline after which an ``accepted`` key is
        treated as retired. Accepts a ``datetime`` or a unix timestamp.
    :param str salt: salt combined with the secret.
    """
    def __init__(self, key_id, secret, state=KEY_ACCEPTED, valid_until=None,
                 salt='huey'):
        if not key_id:
            raise ConfigurationError('SigningKey requires a key_id.')
        if not secret:
            raise ConfigurationError('SigningKey %r requires a secret.' %
                                     key_id)
        if state not in _KEY_STATES:
            raise ConfigurationError('SigningKey %r state must be one of %s.' %
                                     (key_id, ', '.join(_KEY_STATES)))
        self.key_id = key_id
        self.secret = encode(secret)
        self.state = state
        self.salt = encode(salt)
        self.valid_until = self._coerce_deadline(valid_until)
        self._key = hashlib.sha1(self.salt + self.secret).digest()

    @staticmethod
    def _coerce_deadline(valid_until):
        if valid_until is None:
            return None
        if isinstance(valid_until, datetime.datetime):
            if valid_until.tzinfo is not None:
                valid_until = valid_until.astimezone(datetime.timezone.utc)
                valid_until = valid_until.replace(tzinfo=None)
            return valid_until.timestamp()
        return float(valid_until)

    def signature(self, message):
        return hmac.new(self._key, msg=message,
                        digestmod=hashlib.sha1).hexdigest().encode('utf8')

    def is_expired(self, now):
        return self.valid_until is not None and now >= self.valid_until

    def is_usable(self, now):
        """Whether messages signed with this key may still be verified."""
        if self.state == KEY_RETIRED:
            return False
        if self.state == KEY_ACCEPTED and self.is_expired(now):
            return False
        return True

    def effective_state(self, now):
        """State accounting for the acceptance window, not just config."""
        if self.state == KEY_ACCEPTED and self.is_expired(now):
            return KEY_RETIRED
        return self.state


class RotatingSignedSerializer(SignedSerializer):
    """
    Signed serializer that supports zero-downtime secret rotation.

    New messages are signed with the single ``active`` key while messages
    already in the queue can still be verified with ``accepted`` keys, each of
    which may carry a ``valid_until`` compatibility deadline. ``retired``
    keys are retained so their signatures can be identified and reported but
    are never trusted.

    Keys may be provided as :class:`SigningKey` instances or as dicts with the
    same fields::

        serializer = RotatingSignedSerializer(keys=[
            {'key_id': 'k2026', 'secret': 'new-secret', 'state': 'active'},
            {'key_id': 'k2025', 'secret': 'old-secret', 'state': 'accepted',
             'valid_until': 1798761600},
            {'key_id': 'k2024', 'secret': 'ancient-secret',
             'state': 'retired'},
        ])

    :param keys: iterable of :class:`SigningKey` instances or config dicts.
    :param callable time_func: injected clock returning a unix timestamp,
        useful for tests and for controlling the acceptance window.
    """
    def __init__(self, keys, salt='huey', time_func=None, **kwargs):
        # Bypass SignedSerializer.__init__: the key material lives on the
        # individual SigningKey instances rather than a single secret.
        super(SignedSerializer, self).__init__(**kwargs)
        self.salt = encode(salt)
        self.separator = b':'
        self.time_func = time_func
        self.keys = []
        for entry in keys:
            self.keys.append(self._coerce_key(entry))
        if not self.keys:
            raise ConfigurationError(
                'RotatingSignedSerializer requires at least one key.')
        active = [key for key in self.keys if key.state == KEY_ACTIVE]
        if len(active) != 1:
            raise ConfigurationError(
                'RotatingSignedSerializer requires exactly one active key, '
                'got %d.' % len(active))
        ids = [key.key_id for key in self.keys]
        if len(set(ids)) != len(ids):
            raise ConfigurationError(
                'RotatingSignedSerializer key_id values must be unique.')
        self._active_key = active[0]
        # Keep the base-class attribute populated for introspection.
        self.secret = self._active_key.secret
        self._key = self._active_key._key

    def _coerce_key(self, entry):
        if isinstance(entry, SigningKey):
            return entry
        params = dict(entry)
        params.setdefault('salt', self.salt)
        return SigningKey(**params)

    def _now(self):
        if self.time_func is None:
            return time.time()
        value = self.time_func()
        if isinstance(value, datetime.datetime):
            return value.timestamp()
        return float(value)

    def get_key(self, key_id):
        for key in self.keys:
            if key.key_id == key_id:
                return key

    def key_state(self, key_id=None):
        """Configured or effective state of a key (defaults to active key)."""
        key = self._active_key if key_id is None else self.get_key(key_id)
        if key is None:
            raise KeyError(key_id)
        return key.effective_state(self._now())

    def _signature(self, message, key=None):
        return (key or self._active_key).signature(message)

    def _sign(self, message):
        return message + self.separator + self._signature(message)

    def _find_matching_key(self, msg, sig):
        """Return the key whose signature matches, regardless of state."""
        for key in self.keys:
            if constant_time_compare(sig, key.signature(msg)):
                return key

    def _unsign(self, signed):
        if self.separator not in signed:
            raise ValueError('Separator "%s" not found' % self.separator)
        msg, sig = signed.rsplit(self.separator, 1)
        now = self._now()
        key = self._find_matching_key(msg, sig)
        if key is None:
            raise ValueError('Signature "%s" mismatch!' % sig)
        if not key.is_usable(now):
            raise ValueError(
                'Signature matches %s key "%s", but that key is %s and can '
                'no longer be trusted.' % (
                    key.state, key.key_id, key.effective_state(now)))
        return msg
