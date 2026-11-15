"""
Contains structures for representing header fields with associated metadata.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing_extensions import Self, TypeAlias  # pragma: no cover


@dataclass(frozen=True, slots=True)
class ByteRange:
    """
    A half-open byte range ``[start, end)`` inside an encoded header block.

    Ranges always describe offsets into the bytes that were actually put on the
    wire. For a Huffman-encoded string this covers the compressed octets, not
    the decompressed output.
    """

    start: int
    end: int


@dataclass(frozen=True, slots=True)
class WireString:
    """
    A string as it appeared on the wire.

    ``encoded`` holds the raw on-wire octets (Huffman-compressed when
    ``huffman_encoded`` is true) and ``encoded_range`` records their absolute
    position inside the header block, excluding the length prefix.
    """

    encoded: bytes
    huffman_encoded: bool
    encoded_range: ByteRange


@dataclass(frozen=True, slots=True)
class IndexedEvent:
    """
    A parse event emitted for an indexed header field representation.
    """

    base_offset: int
    field_range: ByteRange
    index: int
    index_range: ByteRange


@dataclass(frozen=True, slots=True)
class LiteralEvent:
    """
    A parse event emitted for a literal header field representation.

    ``name`` is ``None`` when the header name was carried as a table reference,
    in which case ``name_index`` and ``name_index_range`` describe that
    reference.
    """

    base_offset: int
    field_range: ByteRange
    representation: str
    should_index: bool
    name_index: int | None
    name_index_range: ByteRange | None
    name: WireString | None
    value: WireString


@dataclass(frozen=True, slots=True)
class TableSizeUpdateEvent:
    """
    A parse event emitted for a dynamic table size update.
    """

    base_offset: int
    field_range: ByteRange
    new_size: int
    index_range: ByteRange


class HeaderTuple(tuple[bytes, bytes]):
    """
    A data structure that stores a single header field.

    HTTP headers can be thought of as tuples of ``(field name, field value)``.
    A single header block is a sequence of such tuples.

    In HTTP/2, however, certain bits of additional information are required for
    compressing these headers: in particular, whether the header field can be
    safely added to the HPACK compression context.

    This class stores a header that can be added to the compression context. In
    all other ways it behaves exactly like a tuple.
    """

    __slots__ = ()

    indexable = True

    def __new__(cls, *args: Any) -> Self:
        return tuple.__new__(cls, args)


class NeverIndexedHeaderTuple(HeaderTuple):
    """
    A data structure that stores a single header field that cannot be added to
    a HTTP/2 header compression context.
    """

    __slots__ = ()

    indexable = False

    def __new__(cls, *args: Any) -> Self:
        return tuple.__new__(cls, args)


Header: TypeAlias = "HeaderTuple | NeverIndexedHeaderTuple | tuple[bytes, bytes]"
HeaderWeaklyTyped: TypeAlias = "HeaderTuple | NeverIndexedHeaderTuple | tuple[bytes | str, bytes | str]"
