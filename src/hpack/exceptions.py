"""
Exceptions used in hpack.
"""
from __future__ import annotations


class HPACKError(Exception):
    """
    The base class for all ``hpack`` exceptions.
    """

    #: Whether the HPACK decoding context remains usable after this error.
    #: Decoding errors are fatal: callers must not reuse the same decoder
    #: (or continue the HTTP/2 connection) after receiving one.
    connection_usable = False



class HPACKDecodingError(HPACKError):
    """
    An error has been encountered while performing HPACK decoding.
    """



class InvalidTableIndexError(HPACKDecodingError):
    """
    An invalid table index was received.

    .. versionadded:: 4.1.0
    """

class InvalidTableIndex(InvalidTableIndexError):  # noqa: N818
    """
    An invalid table index was received.

    .. deprecated:: 4.1.0
       Renamed to :class:`InvalidTableIndexError`, use it instead.
    """


class OversizedHeaderListError(HPACKDecodingError):
    """
    A header list that was larger than we allow has been received. This may be
    a DoS attack.

    In the default strict decoding mode this exception is fatal: the HPACK
    decoding context is no longer usable and the connection must be closed.
    When using :meth:`hpack.Decoder.decode` in discard mode, an oversized
    header list is instead reported as a :class:`hpack.DiscardedHeaderList`
    result after the block has been fully validated.

    .. versionadded:: 2.3.0
    """


class InvalidTableSizeError(HPACKDecodingError):
    """
    An attempt was made to change the decoder table size to a value larger than
    allowed, or the list was shrunk and the remote peer didn't shrink their
    table size.

    .. versionadded:: 3.0.0
    """


class DecodeWorkBudgetExceededError(HPACKDecodingError):
    """
    The decoder exhausted the configured work budget for a single header
    block.

    This is a fatal decoding error. A block that cannot be validated within the
    budget must not be treated as an application-level rejection of just one
    header list: the decoder is no longer able to establish that its HPACK
    context matches the peer's, so the connection must be closed.

    .. versionadded:: 4.3.0
    """


class DecodeWorkBudgetExceeded(DecodeWorkBudgetExceededError):  # noqa: N818
    """
    Alias of :class:`DecodeWorkBudgetExceededError`.

    .. versionadded:: 4.3.0
    """
