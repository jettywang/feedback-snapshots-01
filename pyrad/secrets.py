# secrets.py
#
# Shared secrets of trusted RADIUS peers with a bounded compatibility
# window for secret rotation.

import threading
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


class SharedSecret:
    """A shared secret of a trusted peer and its validity constraints.

    A peer can have several of these: one *current* secret and one or more
    *retired* secrets that are still accepted for a limited time and for a
    limited number of requests while the peer is rotated to the new secret.
    A current secret is created with ``retired_at=None`` and no limits.

    The secret material is only read through :attr:`secret`; it is never
    included in :meth:`__repr__` or any log message. Use :attr:`label` (a
    non-secret identifier) and the configuration :attr:`version` to refer
    to a secret in logs.

    :ivar secret: the RADIUS shared secret
    :type secret: bytes
    :ivar label: non-secret identifier of the secret, used in logs
    :type label: str
    :ivar retired_at: moment the secret was retired, or None for the
        current secret. A retired secret is not accepted at or after this
        moment plus ``valid_after_retirement``
    :type retired_at: datetime
    :ivar valid_after_retirement: how long the retired secret stays
        accepted after ``retired_at``; ignored for the current secret
    :type valid_after_retirement: datetime.timedelta
    :ivar max_attempts: maximum number of requests that may still be
        accepted with a retired secret, or None for unlimited; ignored for
        the current secret
    :type max_attempts: int
    :ivar version: configuration version this secret comes from, used in
        logs, never the secret itself
    :type version: int
    """

    def __init__(self, secret, label=None, retired_at=None,
                 valid_after_retirement=None, max_attempts=None, version=0):
        if not isinstance(secret, (bytes, str)):
            raise TypeError('secret must be a binary string')
        if retired_at is not None and retired_at.tzinfo is None:
            raise ValueError('retired_at must be timezone-aware')
        if max_attempts is not None and max_attempts < 0:
            raise ValueError('max_attempts must not be negative')
        self.secret = secret
        self.label = label or ('current' if retired_at is None else 'retired')
        self.retired_at = retired_at
        self.valid_after_retirement = valid_after_retirement
        self.max_attempts = max_attempts
        self.version = version
        self.attempts = 0

    @property
    def current(self):
        """Whether this is the current (unrestricted) secret."""
        return self.retired_at is None

    def expired(self, now=None):
        """Whether the compatibility window of a retired secret is over.

        The current secret never expires. A retired secret expires when
        its time window has elapsed or its attempt budget is exhausted.

        :param now: current moment, defaults to the current UTC time
        :type now: datetime
        """
        if self.current:
            return False
        now = now or _utcnow()
        if self.max_attempts is not None and self.attempts >= self.max_attempts:
            return True
        if self.valid_after_retirement is not None and \
                now >= self.retired_at + self.valid_after_retirement:
            return True
        return False

    def __repr__(self):
        return ('SharedSecret(label=%r, current=%r, version=%r, '
                'attempts=%r, max_attempts=%r)'
                % (self.label, self.current, self.version,
                   self.attempts, self.max_attempts))


class SecretRing:
    """The candidate shared secrets of one trusted peer.

    Holds the current secret and the retired secrets that are still in
    their compatibility window. Candidates are only those configured for
    the peer: the ring never learns a secret from a request and never
    caches a successful authentication, so an expired or removed secret
    can not be re-admitted by a retry or a duplicate packet.

    The ring is thread-safe: a configuration reload replaces the whole
    ring atomically through :class:`RemoteHost`, while a request in
    progress keeps using the candidates it selected from.

    :param secrets: configured secrets, current first, retired ones after
    :type secrets: list[SharedSecret]
    :param clock: callable returning the current timezone-aware moment,
        defaults to UTC wall clock time; inject a fake clock in tests
    """

    def __init__(self, secrets=None, clock=None):
        self._lock = threading.RLock()
        self._clock = clock or _utcnow
        self._secrets = []
        if secrets:
            for entry in secrets:
                self.add(entry)

    @property
    def clock(self):
        return self._clock

    @property
    def rotation_configured(self):
        """Whether more than one secret was ever configured.

        A ring created for a single-secret peer keeps the legacy
        behaviour (the secret is trusted without a per-request check); a
        ring built for a rotation (current plus retired secrets) always
        authenticates the request against the candidates, even after the
        retired secrets have expired and only the current one remains.
        """
        with self._lock:
            return len(self._secrets) > 1

    def add(self, entry):
        """Add a configured secret; the first current secret wins.

        :param entry: secret to add
        :type entry: SharedSecret
        """
        if not isinstance(entry, SharedSecret):
            raise TypeError('expected a SharedSecret')
        with self._lock:
            if entry.current and any(item.current for item in self._secrets):
                raise ValueError('only one current secret is allowed')
            self._secrets.append(entry)

    @property
    def current(self):
        """The current secret, or None if the ring has no current secret."""
        with self._lock:
            for entry in self._secrets:
                if entry.current:
                    return entry
            return None

    @property
    def secret(self):
        """The material of the current secret, or None."""
        entry = self.current
        return entry.secret if entry is not None else None

    def candidates(self):
        """Return the still-valid candidate secrets, current first.

        Retired secrets whose compatibility window has elapsed or whose
        attempt budget is exhausted are skipped. Each call re-evaluates
        the constraints, so an expired secret never becomes a candidate
        again.

        :return: valid candidate secrets in priority order
        :rtype: list[SharedSecret]
        """
        now = self._clock()
        with self._lock:
            return [entry for entry in self._secrets
                    if not entry.expired(now)]

    def record_attempt(self, entry):
        """Charge one accepted request to a retired secret.

        The attempt count of the current secret is not limited and left
        untouched. The check-and-increment is atomic: once the budget is
        exhausted no further request is admitted.

        :param entry: the secret that authenticated the request
        :type entry: SharedSecret
        :return: True if the attempt was admitted, False if the budget was
            already exhausted
        :rtype: bool
        """
        if entry.current:
            return True
        with self._lock:
            if entry.expired(self._clock()):
                return False
            if entry.max_attempts is not None and \
                    entry.attempts >= entry.max_attempts:
                return False
            entry.attempts += 1
            return True

    def __len__(self):
        with self._lock:
            return len(self._secrets)

    def __iter__(self):
        with self._lock:
            return iter(list(self._secrets))
