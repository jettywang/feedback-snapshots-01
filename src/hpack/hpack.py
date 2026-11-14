"""
Implements the HPACK header compression algorithm as detailed by RFC 7541.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING, Any

from .exceptions import (
    DecodeWorkBudgetExceededError,
    HPACKDecodingError,
    InvalidTableSizeError,
    OversizedHeaderListError,
)
from .huffman import HuffmanEncoder
from .huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
from .huffman_table import decode_huffman
from .struct import HeaderTuple, HeaderWeaklyTyped, NeverIndexedHeaderTuple
from .table import HeaderTable, table_entry_size

if TYPE_CHECKING:
    from collections.abc import Iterable  # pragma: no cover

log = logging.getLogger(__name__)

INDEX_NONE = b"\x00"
INDEX_NEVER = b"\x10"
INDEX_INCREMENTAL = b"\x40"

VARINT_MAX_LENGTH = 5 # octets, enough for encoding prefix + uint32

# Precompute 2^i for 1-8 for use in prefix calcs.
# Zero index is not used but there to save a subtraction
# as prefix numbers are not zero indexed.
_PREFIX_BIT_MAX_NUMBERS = [(2 ** i) - 1 for i in range(9)]

# We default the maximum header list we're willing to accept to 64kB. That's a
# lot of headers, but if applications want to raise it they can do.
DEFAULT_MAX_HEADER_LIST_SIZE = 2 ** 16


class DecodeMode(Enum):
    """
    Selects how :meth:`Decoder.decode` treats an oversized header list.

    ``STRICT`` is the default and preserves historical behaviour: the block is
    abandoned as soon as the application header list limit is exceeded and an
    :class:`OversizedHeaderListError` is raised. The decoding context is
    unusable afterwards, so the whole connection must be closed.

    ``DISCARD`` validates the rest of the block and applies all dynamic table
    updates, but returns a :class:`DiscardedHeaderList` instead of any decoded
    business headers. The decoding context remains usable.

    .. versionadded:: 4.3.0
    """

    STRICT = "strict"
    DISCARD = "discard"


class DecodeStats:
    """
    Observability counters for a single :meth:`Decoder.decode` call.

    These counters make the memory bound of discard mode testable: in discard
    mode ``peak_retained_header_bytes`` and ``peak_retained_headers`` stop
    growing once the application limit is crossed, no matter how many further
    headers the block contains. ``peak_dynamic_table_size`` is bounded by the
    configured HPACK table size, as required by RFC 7541.

    The values describe the most recent decode call. ``header_count`` and
    ``header_list_size`` cover the whole block, including headers decoded after
    the application limit was crossed. The ``peak_*`` values are maxima over
    the whole call; in discard mode the retained-header peaks are bounded by
    the application limit rather than by the number of discarded headers, and
    ``peak_dynamic_table_size`` is bounded by the configured table size.

    .. versionadded:: 4.3.0
    """

    __slots__ = (
        "header_count",
        "header_list_size",
        "peak_dynamic_table_size",
        "peak_retained_header_bytes",
        "peak_retained_headers",
        "table_update_count",
    )

    def __init__(self) -> None:
        self.header_count = 0
        self.header_list_size = 0
        self.peak_retained_headers = 0
        self.peak_retained_header_bytes = 0
        self.peak_dynamic_table_size = 0
        self.table_update_count = 0

    def as_dict(self) -> dict[str, int]:
        """Return the counters as a plain dictionary."""
        return {slot: getattr(self, slot) for slot in self.__slots__}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DecodeStats):
            return NotImplemented
        return self.as_dict() == other.as_dict()

    def __hash__(self) -> int:
        return hash(tuple(self.as_dict().items()))

    def __repr__(self) -> str:
        values = ", ".join(f"{k}={v}" for k, v in self.as_dict().items())
        return f"{self.__class__.__name__}({values})"


class DiscardedHeaderList(list[HeaderTuple]):
    """
    The result of a successfully validated header block whose header list was
    discarded because it exceeded the application limit.

    This object intentionally behaves like an empty list: it never exposes any
    of the decoded header names or values, not even a prefix. The HPACK
    decoding context has been fully updated, so the decoder may continue to be
    used for subsequent header blocks on the same connection.

    :param max_header_list_size: The application limit that was exceeded.
    :param header_list_size: The full inflated size of the discarded list.
    :param header_count: The number of header fields in the discarded list.

    .. versionadded:: 4.3.0
    """

    __slots__ = ("header_count", "header_list_size", "max_header_list_size", "stats")

    discarded = True
    oversized = True
    connection_usable = True
    fatal = False

    def __init__(
        self,
        *,
        max_header_list_size: int,
        header_list_size: int,
        header_count: int,
        stats: DecodeStats | None = None,
    ) -> None:
        super().__init__()
        self.max_header_list_size = max_header_list_size
        self.header_list_size = header_list_size
        self.header_count = header_count
        self.stats = stats

    @property
    def size(self) -> int:
        """Alias for :attr:`header_list_size`."""
        return self.header_list_size

    @property
    def headers(self) -> tuple[HeaderTuple, ...]:
        """The discarded headers are never retained or exposed."""
        return ()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"max_header_list_size={self.max_header_list_size}, "
            f"header_list_size={self.header_list_size}, "
            f"header_count={self.header_count})"
        )


def _coerce_decode_mode(mode: DecodeMode | str) -> DecodeMode:
    """
    Accept a :class:`DecodeMode` or its string value.
    """
    if isinstance(mode, DecodeMode):
        return mode
    if isinstance(mode, str):
        try:
            return DecodeMode(mode)
        except ValueError:
            pass
    msg = f"mode must be a DecodeMode or one of its values, got {mode!r}"
    raise ValueError(msg)


def _unicode_if_needed(header: HeaderWeaklyTyped, raw: bool) -> HeaderTuple:
    """
    Provides a header as a unicode string if raw is False, otherwise returns
    it as a bytestring.
    """
    name = bytes(header[0])  # type: ignore
    value = bytes(header[1])  # type: ignore

    if not raw:
        return header.__class__(name.decode("utf-8"), value.decode("utf-8"))  # type: ignore
    return header.__class__(name, value)  # type: ignore


def _validate_header_utf8(headers: Iterable[HeaderTuple], raw: bool) -> None:
    """
    Validate that discarded headers would decode as UTF-8 when ``raw`` is
    false, without retaining the decoded strings.

    Invalid UTF-8 is corrupt input, not an application-level oversized-list
    rejection, so it must stay fatal even while discarding business headers.
    """
    if raw:
        return
    for header in headers:
        try:
            _unicode_if_needed(header, raw)
        except UnicodeDecodeError as err:
            msg = "Unable to decode headers as UTF-8"
            raise HPACKDecodingError(msg) from err


class _HeaderAccumulator:
    """
    Accumulates a decoded header list, enforcing the application limit.

    In strict mode crossing the limit raises immediately, preserving the
    historical contract. In discard mode the accumulated prefix is dropped at
    that point and every later field is validated and applied to the dynamic
    table without being retained.
    """

    __slots__ = (
        "discarding",
        "header_count",
        "headers",
        "inflated_size",
        "max_header_list_size",
        "max_retained_bytes",
        "max_retained_headers",
        "mode",
        "raw",
        "retained_bytes",
    )

    def __init__(
        self,
        max_header_list_size: int,
        raw: bool,
        mode: DecodeMode,
    ) -> None:
        self.max_header_list_size = max_header_list_size
        self.raw = raw
        self.mode = mode
        self.headers: list[HeaderTuple] = []
        self.discarding = False
        self.header_count = 0
        self.inflated_size = 0
        self.retained_bytes = 0
        self.max_retained_headers = 0
        self.max_retained_bytes = 0

    def add(self, header: HeaderTuple) -> None:
        """Account for one decoded header field."""
        self.header_count += 1
        entry_size = table_entry_size(header[0], header[1])
        self.inflated_size += entry_size

        if self.discarding:
            _validate_header_utf8((header,), self.raw)
            return

        if self.inflated_size > self.max_header_list_size:
            if self.mode is DecodeMode.STRICT:
                msg = f"A header list larger than {self.max_header_list_size} has been received"
                raise OversizedHeaderListError(msg)
            # Validate both the retained prefix and the field that crossed the
            # limit: invalid UTF-8 is corrupt input, not an application-level
            # rejection, so it must stay fatal in discard mode too.
            _validate_header_utf8((*self.headers, header), self.raw)
            self.headers.clear()
            self.discarding = True
            self.retained_bytes = 0
            return

        self.headers.append(header)
        self.retained_bytes += entry_size
        self.max_retained_headers = max(self.max_retained_headers, len(self.headers))
        self.max_retained_bytes = max(self.max_retained_bytes, self.retained_bytes)

    def finish(self, stats: DecodeStats) -> list[HeaderTuple] | DiscardedHeaderList:
        """Produce the decode result and fill in the statistics."""
        stats.header_count = self.header_count
        stats.header_list_size = self.inflated_size
        stats.peak_retained_headers = self.max_retained_headers
        stats.peak_retained_header_bytes = self.max_retained_bytes

        if self.discarding:
            return DiscardedHeaderList(
                max_header_list_size=self.max_header_list_size,
                header_list_size=self.inflated_size,
                header_count=self.header_count,
                stats=stats,
            )

        try:
            return [_unicode_if_needed(h, self.raw) for h in self.headers]
        except UnicodeDecodeError as err:
            msg = "Unable to decode headers as UTF-8"
            raise HPACKDecodingError(msg) from err


def encode_integer(integer: int, prefix_bits: int) -> bytearray:
    """
    Encodes an integer according to the wacky integer encoding rules
    defined in the HPACK spec.
    """
    log.debug("Encoding %d with %d bits", integer, prefix_bits)

    if integer < 0:
        msg = f"Can only encode positive integers, got {integer}"
        raise ValueError(msg)

    if prefix_bits < 1 or prefix_bits > 8:
        msg = f"Prefix bits must be between 1 and 8, got {prefix_bits}"
        raise ValueError(msg)

    max_number = _PREFIX_BIT_MAX_NUMBERS[prefix_bits]

    if integer < max_number:
        return bytearray([integer])  # Seriously?
    elements = [max_number]
    integer -= max_number

    while integer >= 128:
        elements.append((integer & 127) + 128)
        integer >>= 7

    elements.append(integer)

    return bytearray(elements)


def decode_integer(data: bytes | memoryview, prefix_bits: int) -> tuple[int, int]:
    """
    Decodes an integer according to the wacky integer encoding rules
    defined in the HPACK spec. Returns a tuple of the decoded integer and the
    number of bytes that were consumed from ``data`` in order to get that
    integer.
    """
    if prefix_bits < 1 or prefix_bits > 8:
        msg = f"Prefix bits must be between 1 and 8, got {prefix_bits}"
        raise ValueError(msg)

    max_number = _PREFIX_BIT_MAX_NUMBERS[prefix_bits]
    index = 1
    shift = 0
    mask = (0xFF >> (8 - prefix_bits))

    try:
        number = data[0] & mask
        if number == max_number:
            while True:
                next_byte = data[index]
                index += 1

                if next_byte >= 128:
                    number += (next_byte - 128) << shift
                else:
                    number += next_byte << shift
                    break
                shift += 7

                if index > VARINT_MAX_LENGTH:  # sanity check to prevent infinite loops
                    # We have consumed more than enough bytes for a typical unsigned integer.
                    # The maximum size is not defined in HPACK RFC7541 Section 5.1:
                    #   > This integer representation allows for values of indefinite size.  It
                    #   > is also possible for an encoder to send a large number of zero
                    #   > values, which can waste octets and could be used to overflow integer
                    #   > values.  Integer encodings that exceed implementation limits -- in
                    #   > value or octet length -- MUST be treated as decoding errors.
                    msg = f"Variable integer representation is too long: {data!r}"
                    raise HPACKDecodingError(msg)

    except IndexError as err:
        msg = f"Unable to decode HPACK integer representation from {data!r}"
        raise HPACKDecodingError(msg) from err

    log.debug("Decoded %d, consumed %d bytes", number, index)

    return number, index


def _dict_to_iterable(header_dict: dict[bytes | str, bytes | str]) \
        -> Iterable[tuple[bytes | str, bytes | str]]:
    """
    Converts a dictionary to an iterable of key-value tuples. This is a
    HPACK-specific function because it pulls "special-headers" out first and
    then emits them.
    """
    if not isinstance(header_dict, dict):  # pragma: no cover
        msg = f"header_dict not a dict, but {type(header_dict)}"
        raise TypeError(msg)

    keys = sorted(
        header_dict.keys(),
        key=lambda k: not _to_bytes(k).startswith(b":"),
    )
    for key in keys:
        yield key, header_dict[key]


def _to_bytes(value: bytes | str | Any) -> bytes:
    """
    Convert anything to bytes through a UTF-8 encoded string
    """
    t = type(value)
    if t is bytes:
        return value  # type: ignore
    if t is not str:
        value = str(value)
    return value.encode("utf-8")  # type: ignore


class Encoder:
    """
    An HPACK encoder object. This object takes HTTP headers and emits encoded
    HTTP/2 header blocks.
    """

    def __init__(self) -> None:
        self.header_table = HeaderTable()
        self.huffman_coder = HuffmanEncoder(
            REQUEST_CODES, REQUEST_CODES_LENGTH,
        )
        self.table_size_changes: list[int] = []

    @property
    def header_table_size(self) -> int:
        """
        Controls the size of the HPACK header table.
        """
        return self.header_table.maxsize

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self.header_table.maxsize = value
        if self.header_table.resized:
            self.table_size_changes.append(value)

    def encode(self,
               headers: Iterable[\
                   HeaderTuple | \
                   tuple[bytes | str, bytes | str] | \
                   tuple[bytes | str, bytes | str, bool | None]] | \
                   dict[bytes | str, bytes | str],
               huffman: bool = True) -> bytes:
        """
        Takes a set of headers and encodes them into a HPACK-encoded header
        block.

        :param headers: The headers to encode. Must be either an iterable of
                        tuples, an iterable of :class:`HeaderTuple
                        <hpack.HeaderTuple>`, or a ``dict``.

                        If an iterable of tuples, the tuples may be either
                        two-tuples or three-tuples. If they are two-tuples, the
                        tuples must be of the format ``(name, value)``. If they
                        are three-tuples, they must be of the format
                        ``(name, value, sensitive)``, where ``sensitive`` is a
                        boolean value indicating whether the header should be
                        added to header tables anywhere. If not present,
                        ``sensitive`` defaults to ``False``.

                        If an iterable of :class:`HeaderTuple
                        <hpack.HeaderTuple>`, the tuples must always be
                        two-tuples. Instead of using ``sensitive`` as a third
                        tuple entry, use :class:`NeverIndexedHeaderTuple
                        <hpack.NeverIndexedHeaderTuple>` to request that
                        the field never be indexed.

                        .. warning:: HTTP/2 requires that all special headers
                            (headers whose names begin with ``:`` characters)
                            appear at the *start* of the header block. While
                            this method will ensure that happens for ``dict``
                            subclasses, callers using any other iterable of
                            tuples **must** ensure they place their special
                            headers at the start of the iterable.

                            For efficiency reasons users should prefer to use
                            iterables of two-tuples: fixing the ordering of
                            dictionary headers is an expensive operation that
                            should be avoided if possible.

        :param huffman: (optional) Whether to Huffman-encode any header sent as
                        a literal value. Except for use when debugging, it is
                        recommended that this be left enabled.

        :returns: A bytestring containing the HPACK-encoded header block.
        """
        # Transforming the headers into a header block is a procedure that can
        # be modeled as a chain or pipe. First, the headers are encoded. This
        # encoding can be done a number of ways. If the header name-value pair
        # are already in the header table we can represent them using the
        # indexed representation: the same is true if they are in the static
        # table. Otherwise, a literal representation will be used.
        header_block = []

        # Before we begin, if the header table size has been changed we need
        # to signal all changes since last emission appropriately.
        if self.header_table.resized:
            header_block.append(self._encode_table_size_change())
            self.header_table.resized = False

        if isinstance(headers, dict):
            # Turn the headers into a list of tuples if possible. This is the
            # natural way to interact with them in HPACK. Because dictionaries are
            # un-ordered, we need to make sure we grab the "special" headers first.
            hpack_headers = _dict_to_iterable(headers)
        else:
            """
            Assume headers is an iterable of HeaderTuples, or plain 2-tuples, or plain 3-tuples:

            examples:
            [
                HeaderTuple(':method', 'GET'),
                NeverIndexedHeaderTuple('customkey', 'sensitiveinfo'),
            ]
            or
            [
                (':method', 'GET'),
                ('customkey', 'some-data'),
            ]
            or
            [
                (':method', 'GET', True),
                ('customkey', 'sensitiveinfo', True),
            ]
            """
            hpack_headers = iter(headers)  # type: ignore

        # Add each header to the header block
        for header in hpack_headers:
            sensitive = False
            if isinstance(header, HeaderTuple):
                # HeaderTuple implies it's a 2-tuple with the sensitive information stored as instance attribute
                sensitive = not header.indexable
            elif len(header) > 2:
                sensitive = header[2]

            new_header = (_to_bytes(header[0]), _to_bytes(header[1]))
            header_block.append(self.add(new_header, sensitive, huffman))

        encoded = b"".join(header_block)

        log.debug("Encoded header block to %s", encoded)

        return encoded

    def add(self, to_add: tuple[bytes, bytes], sensitive: bool, huffman: bool = False) -> bytes:
        """
        Serializes a header key-value tuple.

        When sensitive is True, the header will not be added to the header table
        (see https://www.rfc-editor.org/rfc/rfc7541.html#section-7.1.3 for details),
        furthermore, the header value will be redacted in debug logs, as "SENSITIVE_REDACTED",
        to prevent accidental exposure of sensitive information.
        """
        name, value = to_add

        display_value = value if not sensitive else b"SENSITIVE_REDACTED"
        log.debug(
            "Adding %s=%s to the header table, sensitive:%s, huffman:%s",
            name,
            display_value,
            sensitive,
            huffman,
        )

        # Set our indexing mode
        indexbit = INDEX_INCREMENTAL if not sensitive else INDEX_NEVER

        # Search for a matching header in the header table.
        match = self.header_table.search(name, value)

        if match is None:
            # Not in the header table. Encode using the literal syntax,
            # and add it to the header table.
            encoded = self._encode_literal(name, value, indexbit, huffman)
            if not sensitive:
                self.header_table.add(name, value)
            return encoded

        # The header is in the table, break out the values. If we matched
        # perfectly, we can use the indexed representation: otherwise we
        # can use the indexed literal.
        index, name, perfect = match

        if perfect is not None:
            # Indexed representation.
            encoded = self._encode_indexed(index)
        else:
            # Indexed literal. We are going to add header to the
            # header table unconditionally. It is a future todo to
            # filter out headers which are known to be ineffective for
            # indexing since they just take space in the table and
            # pushed out other valuable headers.
            encoded = self._encode_indexed_literal(
                index, value, indexbit, huffman,
            )
            if not sensitive:
                self.header_table.add(name, value)

        return encoded

    def _encode_indexed(self, index: int) -> bytes:
        """
        Encodes a header using the indexed representation.
        """
        field = encode_integer(index, 7)
        field[0] |= 0x80  # we set the top bit
        return bytes(field)

    def _encode_literal(self, name: bytes, value: bytes, indexbit: bytes, huffman: bool = False) -> bytes:
        """
        Encodes a header with a literal name and literal value. If ``indexing``
        is True, the header will be added to the header table: otherwise it
        will not.
        """
        if huffman:
            name = self.huffman_coder.encode(name)
            value = self.huffman_coder.encode(value)

        name_len = encode_integer(len(name), 7)
        value_len = encode_integer(len(value), 7)

        if huffman:
            name_len[0] |= 0x80
            value_len[0] |= 0x80

        return b"".join(
            [indexbit, bytes(name_len), name, bytes(value_len), value],
        )

    def _encode_indexed_literal(self, index: int, value: bytes, indexbit: bytes, huffman: bool = False) -> bytes:
        """
        Encodes a header with an indexed name and a literal value and performs
        incremental indexing.
        """
        if indexbit != INDEX_INCREMENTAL:
            prefix = encode_integer(index, 4)
        else:
            prefix = encode_integer(index, 6)

        prefix[0] |= ord(indexbit)

        if huffman:
            value = self.huffman_coder.encode(value)

        value_len = encode_integer(len(value), 7)

        if huffman:
            value_len[0] |= 0x80

        return b"".join([bytes(prefix), bytes(value_len), value])

    def _encode_table_size_change(self) -> bytes:
        """
        Produces the encoded form of all header table size change context
        updates.
        """
        block = b""
        for size_bytes in self.table_size_changes:
            b = encode_integer(size_bytes, 5)
            b[0] |= 0x20
            block += bytes(b)
        self.table_size_changes = []
        return block


class Decoder:
    """
    An HPACK decoder object.

    .. versionchanged:: 2.3.0
       Added ``max_header_list_size`` argument.

    :param max_header_list_size: The maximum decompressed size we will allow
        for any single header block. This is a protection against DoS attacks
        that attempt to force the application to expand a relatively small
        amount of data into a really large header list, allowing enormous
        amounts of memory to be allocated.

        If this amount of data is exceeded, the outcome depends on the ``mode``
        argument to :meth:`decode`. The default strict mode raises
        `OversizedHeaderListError <hpack.OversizedHeaderListError>` and leaves
        the connection unusable. :attr:`DecodeMode.DISCARD` instead validates
        the rest of the block, keeps the HPACK context in sync, and returns a
        :class:`DiscardedHeaderList` without any business headers.

        Defaults to 64kB.
    :type max_header_list_size: ``int``
    :param max_decode_work: The maximum number of header field representations
        to process from a single header block, or ``None`` for no limit. See
        :attr:`max_decode_work`. Defaults to ``None``.
    :type max_decode_work: ``int | None``

    .. versionchanged:: 4.3.0
       Added the ``mode`` argument to :meth:`decode`, the :meth:`decode_discard`
       convenience method, the ``max_decode_work`` limit, and
       ``connection_usable``.
    """

    def __init__(
        self,
        max_header_list_size: int = DEFAULT_MAX_HEADER_LIST_SIZE,
        max_decode_work: int | None = None,
    ) -> None:
        self.header_table = HeaderTable()

        #: The maximum decompressed size we will allow for any single header
        #: block. This is a protection against DoS attacks that attempt to
        #: force the application to expand a relatively small amount of data
        #: into a really large header list, allowing enormous amounts of memory
        #: to be allocated.
        #:
        #: If this amount of data is exceeded, the default strict decoding mode
        #: raises `OversizedHeaderListError
        #: <hpack.OversizedHeaderListError>` and the connection must be shut
        #: down. :attr:`DecodeMode.DISCARD` instead returns a
        #: :class:`DiscardedHeaderList` after keeping the HPACK context in sync.
        #:
        #: Defaults to 64kB.
        #:
        #: .. versionadded:: 2.3.0
        self.max_header_list_size = max_header_list_size

        #: Maximum allowed header table size.
        #:
        #: A HTTP/2 implementation should set this to the most recent value of
        #: SETTINGS_HEADER_TABLE_SIZE that it sent *and has received an ACK
        #: for*. Once this setting is set, the actual header table size will be
        #: checked at the end of each decoding run and whenever it is changed,
        #: to confirm that it fits in this size.
        self.max_allowed_table_size = self.header_table.maxsize

        #: The maximum number of header field representations that may be
        #: processed from a single header block, or ``None`` for no limit.
        #:
        #: This bounds the amount of decoding work spent on a block independently
        #: of the size of the decoded header list. It protects against blocks
        #: made from a very large number of tiny representations.
        #:
        #: Exhausting this budget raises :class:`DecodeWorkBudgetExceeded
        #: <hpack.DecodeWorkBudgetExceeded>`. That error is fatal: the decoder
        #: cannot know whether its dynamic table matches the peer's, so the
        #: connection must be closed. It is never converted into a discarded
        #: header list.
        #:
        #: Defaults to ``None`` (no limit), preserving historical behaviour.
        #:
        #: .. versionadded:: 4.3.0
        self.max_decode_work: int | None = max_decode_work

        #: Whether this decoder may still be used with the same connection.
        #:
        #: This starts as ``True``. A fatal decoding error sets it to ``False``,
        #: because the dynamic table may no longer match the encoder and no
        #: further blocks can be trusted. An oversized header list handled in
        #: :attr:`DecodeMode.DISCARD` mode does not clear this flag: the block
        #: has been fully validated and the connection can continue.
        #:
        #: .. versionadded:: 4.3.0
        self.connection_usable = True

        #: Counters for the most recent successful :meth:`decode` call, or
        #: ``None`` if the last call raised a decoding error. See
        #: :class:`DecodeStats`.
        #:
        #: .. versionadded:: 4.3.0
        self.last_decode_stats: DecodeStats | None = None

    @property
    def header_table_size(self) -> int:
        """
        Controls the size of the HPACK header table.
        """
        return self.header_table.maxsize

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self.header_table.maxsize = value

    def decode(self,
               data: bytes,
               raw: bool = False,
               mode: DecodeMode | str = DecodeMode.STRICT) -> list[HeaderTuple] | DiscardedHeaderList:
        """
        Takes an HPACK-encoded header block and decodes it into a header set.

        :param data: A bytestring representing a complete HPACK-encoded header
                     block.
        :param raw: (optional) Whether to return the headers as tuples of raw
                    byte strings or to decode them as UTF-8 before returning
                    them. The default value is False, which returns tuples of
                    Unicode strings
        :param mode: (optional) How to handle a header list that exceeds
                    :attr:`max_header_list_size`.

                    With the default :attr:`DecodeMode.STRICT`, an
                    :class:`OversizedHeaderListError` is raised as soon as the
                    limit is exceeded. That error is fatal to the decoding
                    context: the connection must be closed.

                    With :attr:`DecodeMode.DISCARD`, the whole block is still
                    parsed, including all dynamic table updates, but decoded
                    headers stop being accumulated once the limit is exceeded.
                    The call then returns a :class:`DiscardedHeaderList` that
                    exposes no headers at all. No partial header list is ever
                    returned, and the decoding context remains usable for later
                    blocks on the same connection.

        :returns: A list of two-tuples of ``(name, value)`` representing the
                  HPACK-encoded headers, in the order they were decoded, or a
                  :class:`DiscardedHeaderList` in discard mode.
        :raises HPACKDecodingError: If an error is encountered while decoding
                                    the header block. This includes
                                    :class:`DecodeWorkBudgetExceededError` when
                                    :attr:`max_decode_work` is exhausted; such
                                    errors always mean the connection cannot
                                    continue.
        """
        log.debug("Decoding %s", data)

        mode = _coerce_decode_mode(mode)

        return self._decode(data, raw, mode)

    def decode_discard(
        self,
        data: bytes,
        raw: bool = False,
    ) -> list[HeaderTuple] | DiscardedHeaderList:
        """
        Decode a header block, discarding business headers that exceed the
        application limit while keeping the HPACK context usable.

        This is equivalent to calling :meth:`decode` with
        :attr:`DecodeMode.DISCARD`. It differs from the default strict mode in
        one important way: an oversized header list does not invalidate the
        connection. Everything else remains fatal. Corrupt compressed input,
        an exhausted work budget and an invalid table size still raise
        :class:`HPACKDecodingError` (or its subclasses), in which case the
        connection must be closed and no result is returned.

        The returned :class:`DiscardedHeaderList` is empty: it does not retain
        or reveal any of the discarded header names or values, not even a
        prefix. Memory used while validating the remainder of the block is
        bounded by the dynamic table and the work budget, not by the number of
        discarded headers.

        :param data: A bytestring representing a complete HPACK-encoded header
                     block.
        :param raw: (optional) Whether to return the headers as tuples of raw
                    byte strings or to decode them as UTF-8.
        :returns: The decoded headers, or a :class:`DiscardedHeaderList`.
        :raises HPACKDecodingError: For any fatal decoding error.
        """
        return self.decode(data, raw, mode=DecodeMode.DISCARD)

    def _decode(
        self,
        data: bytes,
        raw: bool,
        mode: DecodeMode,
    ) -> list[HeaderTuple] | DiscardedHeaderList:
        try:
            return self._decode_block(data, raw, mode)
        except HPACKDecodingError:
            # The compressed input could not be validated: the dynamic table
            # may have been partially updated, so the connection cannot
            # continue. An application-level oversized-list rejection in
            # discard mode is returned as a value instead of raised.
            self.connection_usable = False
            raise

    def _decode_block(
        self,
        data: bytes,
        raw: bool,
        mode: DecodeMode,
    ) -> list[HeaderTuple] | DiscardedHeaderList:
        self.last_decode_stats = None
        data_mem = memoryview(data)
        accumulator = _HeaderAccumulator(self.max_header_list_size, raw, mode)
        stats = DecodeStats()
        stats.peak_dynamic_table_size = self.header_table.current_size
        current_index = 0
        work = 0

        while current_index < len(data):
            if self.max_decode_work is not None:
                work += 1
                if work > self.max_decode_work:
                    msg = (
                        f"Decoding work budget of {self.max_decode_work} "
                        "header field representations was exhausted"
                    )
                    raise DecodeWorkBudgetExceededError(msg)

            header, consumed, context_update = self._decode_representation(
                data_mem, current_index, accumulator.header_count,
            )

            if context_update:
                stats.table_update_count += 1
            elif header is not None:
                accumulator.add(header)

            stats.peak_dynamic_table_size = max(
                stats.peak_dynamic_table_size,
                self.header_table.current_size,
            )

            current_index += consumed

        # Confirm that the table size is lower than the maximum. We do this
        # here to ensure that we catch when the max has been *shrunk* and the
        # remote peer hasn't actually done that.
        self._assert_valid_table_size()

        result = accumulator.finish(stats)
        self.last_decode_stats = stats
        return result

    def _decode_representation(
        self,
        data_mem: memoryview,
        current_index: int,
        header_count: int,
    ) -> tuple[HeaderTuple | None, int, bool]:
        """
        Decode one header field representation at ``current_index``.

        Returns ``(header, consumed, context_update)``. ``header`` is ``None``
        for a dynamic table size update, which is flagged by
        ``context_update``.
        """
        current = data_mem[current_index]

        # If the high bit is 1, it's an indexed field.
        if current & 0x80:
            header, consumed = self._decode_indexed(data_mem[current_index:])
            return header, consumed, False

        # Otherwise, if the second-highest bit is 1 it's a field that does
        # alter the header table.
        if current & 0x40:
            header, consumed = self._decode_literal_index(
                data_mem[current_index:],
            )
            return header, consumed, False

        # Otherwise, if the third-highest bit is 1 it's an encoding context
        # update. These are forbidden in a header block after any actual
        # header.
        if current & 0x20:
            if header_count:
                msg = "Table size update not at the start of the block"
                raise HPACKDecodingError(msg)
            consumed = self._update_encoding_context(
                data_mem[current_index:],
            )
            return None, consumed, True

        # Otherwise, it's a literal header that does not affect the header
        # table.
        header, consumed = self._decode_literal_no_index(
            data_mem[current_index:],
        )
        return header, consumed, False

    def _assert_valid_table_size(self) -> None:
        """
        Check that the table size set by the encoder is lower than the maximum
        we expect to have.
        """
        if self.header_table_size > self.max_allowed_table_size:
            msg = "Encoder did not shrink table size to within the max"
            raise InvalidTableSizeError(msg)

    def _update_encoding_context(self, data: bytes | memoryview) -> int:
        """
        Handles a byte that updates the encoding context.
        """
        # We've been asked to resize the header table.
        new_size, consumed = decode_integer(data, 5)
        if new_size > self.max_allowed_table_size:
            msg = "Encoder exceeded max allowable table size"
            raise InvalidTableSizeError(msg)
        self.header_table_size = new_size
        return consumed

    def _decode_indexed(self, data: bytes | memoryview) -> tuple[HeaderTuple, int]:
        """
        Decodes a header represented using the indexed representation.
        """
        index, consumed = decode_integer(data, 7)
        header = HeaderTuple(*self.header_table.get_by_index(index))
        log.debug("Decoded %s, consumed %d", header, consumed)
        return header, consumed

    def _decode_literal_no_index(self, data: bytes | memoryview) -> tuple[HeaderTuple, int]:
        return self._decode_literal(data, should_index=False)

    def _decode_literal_index(self, data: bytes | memoryview) -> tuple[HeaderTuple, int]:
        return self._decode_literal(data, should_index=True)

    def _decode_literal(self, data: bytes | memoryview, should_index: bool) -> tuple[HeaderTuple, int]:
        """
        Decodes a header represented with a literal.

        ``data`` may be a memoryview of the remainder of the header block. Only
        the bytes belonging to this field are copied, so decoding cost and
        transitory memory stay proportional to the field size rather than the
        size of the rest of the block.
        """
        total_consumed = 0

        # When should_index is true, if the low six bits of the first byte are
        # nonzero, the header name is indexed.
        # When should_index is false, if the low four bits of the first byte
        # are nonzero the header name is indexed.
        if should_index:
            indexed_name = data[0] & 0x3F
            name_len = 6
            not_indexable = False
        else:
            high_byte = data[0]
            indexed_name = high_byte & 0x0F
            name_len = 4
            not_indexable = bool(high_byte & 0x10)

        if indexed_name:
            # Indexed header name.
            index, consumed = decode_integer(data, name_len)
            name = self.header_table.get_by_index(index)[0]

            total_consumed = consumed
            length = 0
        else:
            # Literal header name. The first byte was consumed, so we need to
            # move forward.
            data = data[1:]

            length, consumed = decode_integer(data, 7)
            name = bytes(data[consumed:consumed + length])
            if len(name) != length:
                msg = "Truncated header block"
                raise HPACKDecodingError(msg)

            if data[0] & 0x80:
                name = decode_huffman(name)
            total_consumed = consumed + length + 1  # Since we moved forward 1.

        data = data[consumed + length:]

        # The header value is definitely length-based.
        length, consumed = decode_integer(data, 7)
        value = bytes(data[consumed:consumed + length])
        if len(value) != length:
            msg = "Truncated header block"
            raise HPACKDecodingError(msg)

        if data[0] & 0x80:
            value = decode_huffman(value)

        # Updated the total consumed length.
        total_consumed += length + consumed

        # If we have been told never to index the header field, encode that in
        # the tuple we use.
        header: HeaderTuple
        if not_indexable:
            header = NeverIndexedHeaderTuple(name, value)
        else:
            header = HeaderTuple(name, value)

        # If we've been asked to index this, add it to the header table.
        if should_index:
            self.header_table.add(name, value)

        log.debug(
            "Decoded %s, total consumed %d bytes, indexed %s",
            header,
            total_consumed,
            should_index,
        )

        return header, total_consumed
