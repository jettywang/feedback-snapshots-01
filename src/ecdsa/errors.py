class MalformedPointError(AssertionError):
    """Raised in case the encoding of private or public key is malformed."""

    pass


class EntropyError(RuntimeError):
    """Base class for unrecoverable failures of an entropy source.

    Errors of this class are raised when a caller-supplied entropy callback
    breaks its contract.  They are deliberately *not* subclasses of
    :class:`ValueError` so that a broad ``except ValueError`` in application
    code does not silently turn a dead entropy source into a retry with some
    other value.
    """

    pass


class EntropySourceError(EntropyError):
    """The entropy callback returned a value that violates its contract.

    Raised for example when the callback returns fewer or more bytes than
    requested, or a value that is not a byte string at all.  Exceptions that
    the callback raises itself are propagated unchanged instead of being
    wrapped in this class.
    """

    pass


class EntropyExhaustedError(EntropyError):
    """Too many candidate values were rejected by rejection sampling.

    Rejection sampling is a normal part of :func:`ecdsa.util.randrange`, so a
    single out-of-range sample is not an error.  A source that keeps producing
    out-of-range values (a stuck or non-uniform source) will exhaust the
    bounded rejection budget and this exception is raised instead of looping
    forever or falling back to a different source.
    """

    pass
