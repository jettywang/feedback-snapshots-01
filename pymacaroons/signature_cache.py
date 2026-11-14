import time
from collections import OrderedDict


class SignatureCache(object):
    '''Bounded cache for intermediate macaroon signature chain state.

    Stores only pure cryptographic state: the HMAC chain signature that
    is fully determined by (root key, identifier, caveat prefix). It
    never stores caveat check outcomes, discharge consumption, request
    timestamps, or any other per-request authentication decision, so a
    cache hit can never resurrect a past authorization conclusion.

    Entries are evicted least-recently-used once ``maxsize`` is exceeded
    and expire ``ttl`` seconds after they are stored.
    '''

    def __init__(self, maxsize=1024, ttl=300.0, clock=None):
        if maxsize < 1:
            raise ValueError('maxsize must be at least 1')
        if ttl <= 0:
            raise ValueError('ttl must be positive')
        self.maxsize = maxsize
        self.ttl = ttl
        self.clock = clock or getattr(time, 'monotonic', time.time)
        self._entries = OrderedDict()

    def get(self, key):
        '''Return the cached signature for key, or None on miss/expiry.'''
        try:
            expires_at, signature = self._entries[key]
        except KeyError:
            return None
        if expires_at <= self.clock():
            del self._entries[key]
            return None
        self._entries.move_to_end(key)
        return signature

    def put(self, key, signature):
        if key in self._entries:
            del self._entries[key]
        self._entries[key] = (self.clock() + self.ttl, signature)
        while len(self._entries) > self.maxsize:
            self._entries.popitem(last=False)

    def clear(self):
        self._entries.clear()

    def __len__(self):
        self._expire_stale()
        return len(self._entries)

    def _expire_stale(self):
        now = self.clock()
        stale = [
            key for key, (expires_at, _) in self._entries.items()
            if expires_at <= now
        ]
        for key in stale:
            del self._entries[key]
