class CSPNonceError(Exception):
    pass


class CSPCacheError(Exception):
    """Raised when a cached, nonce-bearing response cannot be rebuilt for the
    current request. The stale entry must be discarded and the page rendered
    afresh rather than serving a reused nonce."""
