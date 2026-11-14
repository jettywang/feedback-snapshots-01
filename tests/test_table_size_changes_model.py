"""
Cross-block model tests for HPACK dynamic table size changes.

The expectations in this module come from a small, self-contained model of the
dynamic table and from parsing the raw header blocks emitted by the encoder.
No assertion uses the encoder's or decoder's header table as the expected
answer.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

import pytest

from hpack import (
    Decoder,
    Encoder,
    HPACKDecodingError,
    InvalidTableIndexError,
    InvalidTableSizeError,
)

ENTRY_OVERHEAD = 32
STATIC_LENGTH = 61

# The static rows needed to resolve indexes used by these tests. This is a
# copy of the corresponding RFC 7541 Appendix A entries, not a view into the
# production table.
STATIC_TABLE = {
    1: (b":authority", b""),
    2: (b":method", b"GET"),
    3: (b":method", b"POST"),
    4: (b":path", b"/"),
    5: (b":path", b"/index.html"),
    6: (b":scheme", b"http"),
    7: (b":scheme", b"https"),
    8: (b":status", b"200"),
    9: (b":status", b"204"),
    10: (b":status", b"206"),
    11: (b":status", b"304"),
    12: (b":status", b"400"),
    13: (b":status", b"404"),
    14: (b":status", b"500"),
    23: (b"authorization", b""),
}


def entry_size(name: bytes, value: bytes) -> int:
    return ENTRY_OVERHEAD + len(name) + len(value)


def read_integer(data: bytes, position: int, prefix_bits: int) -> tuple[int, int]:
    prefix_max = (1 << prefix_bits) - 1
    number = data[position] & prefix_max
    position += 1
    if number < prefix_max:
        return number, position
    shift = 0
    while True:
        octet = data[position]
        position += 1
        number += (octet & 0x7F) << shift
        if octet < 0x80:
            return number, position
        shift += 7


def read_string(data: bytes, position: int) -> tuple[bytes, int]:
    start = position
    length, position = read_integer(data, position, 7)
    if data[start] & 0x80:
        raise AssertionError("the model deliberately avoids Huffman-coded strings")
    end = position + length
    assert end <= len(data), "truncated string in encoded block"
    return data[position:end], end


def encode_integer_model(value: int, prefix_bits: int) -> bytes:
    prefix_max = (1 << prefix_bits) - 1
    if value < prefix_max:
        return bytes([value])
    output = bytearray([prefix_max])
    value -= prefix_max
    while value >= 128:
        output.append((value & 0x7F) + 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_indexed_model(index: int) -> bytes:
    encoded = bytearray(encode_integer_model(index, 7))
    encoded[0] |= 0x80
    return bytes(encoded)


def encode_size_update_model(size: int) -> bytes:
    encoded = bytearray(encode_integer_model(size, 5))
    encoded[0] |= 0x20
    return bytes(encoded)


@dataclass(frozen=True)
class SizeUpdate:
    size: int
    raw: bytes


@dataclass(frozen=True)
class IndexedField:
    index: int
    raw: bytes


@dataclass(frozen=True)
class LiteralField:
    name_index: int
    name: bytes | None
    value: bytes
    add_to_table: bool
    never_indexed: bool
    raw: bytes


Operation = SizeUpdate | IndexedField | LiteralField


def parse_block(block: bytes) -> list[Operation]:
    operations: list[Operation] = []
    position = 0
    while position < len(block):
        start = position
        first = block[position]

        if first & 0x80:
            index, position = read_integer(block, position, 7)
            operations.append(IndexedField(index, block[start:position]))
            continue

        if first & 0x40:
            name_index, position = read_integer(block, position, 6)
            name = None
            if name_index == 0:
                name, position = read_string(block, position)
            value, position = read_string(block, position)
            operations.append(
                LiteralField(name_index, name, value, True, False, block[start:position]),
            )
            continue

        if first & 0x20:
            size, position = read_integer(block, position, 5)
            operations.append(SizeUpdate(size, block[start:position]))
            continue

        name_index, position = read_integer(block, position, 4)
        name = None
        if name_index == 0:
            name, position = read_string(block, position)
        value, position = read_string(block, position)
        operations.append(
            LiteralField(
                name_index,
                name,
                value,
                False,
                bool(first & 0x10),
                block[start:position],
            ),
        )

    return operations


class ModelTable:
    """A minimal dynamic table model, independent of hpack.table.HeaderTable."""

    def __init__(self, maxsize: int = 4096) -> None:
        self.maxsize = maxsize
        self.entries: deque[tuple[bytes, bytes]] = deque()
        self.size = 0

    def clone(self) -> ModelTable:
        other = ModelTable(self.maxsize)
        other.entries = deque(self.entries)
        other.size = self.size
        return other

    def entries_tuple(self) -> tuple[tuple[bytes, bytes], ...]:
        return tuple(self.entries)

    def _recalculate_size(self) -> None:
        self.size = sum(entry_size(name, value) for name, value in self.entries)

    def resize(self, maxsize: int) -> None:
        self.maxsize = maxsize
        if maxsize <= 0:
            self.entries.clear()
            self.size = 0
            return
        while self.size > maxsize:
            self.entries.pop()
            self._recalculate_size()

    def add(self, name: bytes, value: bytes) -> None:
        size = entry_size(name, value)
        if size > self.maxsize:
            self.entries.clear()
            self.size = 0
            return
        self.entries.appendleft((name, value))
        self.size += size
        while self.size > self.maxsize:
            self.entries.pop()
            self._recalculate_size()

    def lookup(self, index: int) -> tuple[bytes, bytes]:
        if 1 <= index <= STATIC_LENGTH:
            if index in STATIC_TABLE:
                return STATIC_TABLE[index]
            raise AssertionError(f"model does not know static index {index}")
        return self.dynamic_lookup(index)

    def dynamic_lookup(self, index: int) -> tuple[bytes, bytes]:
        dynamic_index = index - STATIC_LENGTH - 1
        if not 0 <= dynamic_index < len(self.entries):
            raise InvalidTableIndexError(f"Invalid table index {index} in model")
        return self.entries[dynamic_index]

    def has_exact(self, name: bytes, value: bytes) -> bool:
        if any(static_name == name and static_value == value for static_name, static_value in STATIC_TABLE.values()):
            return True
        return any(entry_name == name and entry_value == value for entry_name, entry_value in self.entries)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ModelTable):
            return NotImplemented
        return self.maxsize == other.maxsize and self.entries_tuple() == other.entries_tuple()

    def __repr__(self) -> str:
        return f"ModelTable(maxsize={self.maxsize}, entries={self.entries_tuple()!r})"


def apply_operations(table: ModelTable, operations: list[Operation]) -> list[tuple[bytes, bytes]]:
    """
    Apply a block to a model table and return its fields.  Lookups are checked
    against the table state at the moment they occur, so an index that refers to
    an entry that is no longer present fails immediately.
    """
    fields: list[tuple[bytes, bytes]] = []
    for operation in operations:
        if isinstance(operation, SizeUpdate):
            table.resize(operation.size)
        elif isinstance(operation, IndexedField):
            fields.append(table.lookup(operation.index))
        else:
            name = operation.name if operation.name_index == 0 else table.lookup(operation.name_index)[0]
            fields.append((name, operation.value))
            if operation.add_to_table:
                table.add(name, operation.value)
    return fields


def _header_bytes(header: tuple) -> tuple[bytes, bytes]:
    name = header[0].encode("utf-8") if isinstance(header[0], str) else header[0]
    value = header[1].encode("utf-8") if isinstance(header[1], str) else header[1]
    return name, value


def _header_text(field: tuple[bytes, bytes]) -> tuple[str, str]:
    return field[0].decode("utf-8"), field[1].decode("utf-8")


def _is_sensitive(header: tuple) -> bool:
    if not getattr(header, "indexable", True):
        return True
    return len(header) > 2 and bool(header[2])


def predict_table_after(before: ModelTable, changes: tuple[int, ...], headers: list[tuple]) -> ModelTable:
    predicted = before.clone()
    for size in changes:
        predicted.resize(size)
    for header in headers:
        name, value = _header_bytes(header)
        if _is_sensitive(header) or predicted.has_exact(name, value):
            continue
        predicted.add(name, value)
    return predicted


def expected_updates(changes: tuple[int, ...], previous_maxsize: int) -> tuple[int, ...]:
    """RFC 7541 Section 4.2: smallest intermediate value, plus the final value."""
    recorded: list[int] = []
    current = previous_maxsize
    for value in changes:
        if value != current:
            recorded.append(value)
            current = value
    if not recorded:
        return ()
    minimum = min(recorded)
    return (minimum,) if minimum == current else (minimum, current)


def probe_decoder_entries(decoder: Decoder) -> tuple[tuple[bytes, bytes], ...]:
    entries: list[tuple[bytes, bytes]] = []
    index = STATIC_LENGTH + 1
    while True:
        try:
            decoded = decoder.decode(encode_indexed_model(index), raw=True)
        except InvalidTableIndexError:
            return tuple(entries)
        assert len(decoded) == 1
        entries.append(tuple(decoded[0]))
        index += 1


def assert_decoder_table_matches(decoder: Decoder, expected: ModelTable, context: str) -> None:
    actual = probe_decoder_entries(decoder)
    assert actual == expected.entries_tuple(), f"{context}: decoder table {actual!r} != model {expected!r}"


@dataclass(frozen=True)
class BlockRecord:
    number: int
    raw: bytes
    changes: tuple[int, ...]
    emitted_updates: tuple[int, ...]
    model_entries: tuple[tuple[bytes, bytes], ...]
    decoder_entries: tuple[tuple[bytes, bytes], ...]
    decoded_fields: tuple[tuple[str, str], ...]
    allowed: int


def run_session(
    steps: list[tuple[list[tuple], tuple[int, ...]]],
    allowed_sizes: list[int] | None = None,
) -> list[BlockRecord]:
    encoder = Encoder()
    decoder = Decoder()
    encoder_table = ModelTable()
    decoder_model = ModelTable()
    records: list[BlockRecord] = []

    if allowed_sizes is None:
        allowed_sizes = [decoder.max_allowed_table_size] * len(steps)
    assert len(allowed_sizes) == len(steps)

    for number, (headers, changes) in enumerate(steps, start=1):
        allowed = allowed_sizes[number - 1]
        decoder.max_allowed_table_size = allowed

        previous_maxsize = encoder.header_table_size
        for value in changes:
            encoder.header_table_size = value

        raw = encoder.encode(headers, huffman=False)
        operations = parse_block(raw)
        assert b"".join(operation.raw for operation in operations) == raw, (
            f"block {number}: parsed operations do not reproduce the raw block"
        )
        emitted = tuple(operation.size for operation in operations if isinstance(operation, SizeUpdate))
        expected = expected_updates(changes, previous_maxsize)
        assert emitted == expected, (
            f"block {number}: expected size updates {expected}, encoder emitted {emitted}; raw={raw!r}"
        )

        wire_table = encoder_table.clone()
        wire_fields = apply_operations(wire_table, operations)
        predicted = predict_table_after(encoder_table, changes, headers)
        assert wire_table == predicted, f"block {number}: wire table {wire_table!r} != predicted {predicted!r}"
        encoder_table = predicted

        decoded = decoder.decode(raw)
        actual_fields = [tuple(field) for field in decoded]
        assert actual_fields == [_header_text(field) for field in wire_fields], (
            f"block {number}: decoded fields diverged; raw={raw!r}"
        )

        decoder_fields = apply_operations(decoder_model, operations)
        assert [_header_text(field) for field in decoder_fields] == [_header_text(field) for field in wire_fields]
        assert_decoder_table_matches(decoder, decoder_model, f"block {number}")
        decoder_entries = probe_decoder_entries(decoder)
        assert decoder_entries == encoder_table.entries_tuple(), (
            f"block {number}: encoder and decoder tables diverged; raw={raw!r}"
        )

        records.append(
            BlockRecord(
                number=number,
                raw=raw,
                changes=changes,
                emitted_updates=emitted,
                model_entries=encoder_table.entries_tuple(),
                decoder_entries=decoder_entries,
                decoded_fields=tuple(actual_fields),
                allowed=allowed,
            ),
        )

    return records


def test_shrink_then_grow_uses_minimum_and_final_updates() -> None:
    steps = [
        ([(":method", "GET"), ("x-alpha", "value-alpha"), ("x-beta", "value-beta")], ()),
        ([(":method", "GET"), ("x-gamma", "value-gamma")], (60, 4096)),
        ([("x-beta", "value-beta"), ("x-gamma", "value-gamma")], ()),
    ]
    records = run_session(steps)

    assert records[0].emitted_updates == ()
    assert records[1].emitted_updates == (60, 4096)
    assert records[1].raw.startswith(encode_size_update_model(60) + encode_size_update_model(4096))
    assert records[1].model_entries == ((b"x-gamma", b"value-gamma"), (b"x-beta", b"value-beta"))
    assert (b"x-alpha", b"value-alpha") not in records[1].model_entries

    # The next block only indexes entries that survived the minimum size.
    operations = parse_block(records[2].raw)
    indexed = [operation.index for operation in operations if isinstance(operation, IndexedField)]
    # records[1].model_entries is exactly the table state before block 3.
    before_block = ModelTable()
    before_block.entries = deque(records[1].model_entries)
    for index in indexed:
        assert before_block.dynamic_lookup(index) in before_block.entries
    assert [before_block.dynamic_lookup(index) for index in indexed] == [
        (b"x-beta", b"value-beta"),
        (b"x-gamma", b"value-gamma"),
    ]
    assert records[2].decoded_fields == (("x-beta", "value-beta"), ("x-gamma", "value-gamma"))


def test_shrink_to_zero_then_restore_evicts_every_entry() -> None:
    steps = [
        ([("x-one", "one")], ()),
        ([("x-two", "two")], (0, 4096)),
        ([("x-two", "two"), ("x-one", "one")], ()),
    ]
    records = run_session(steps)

    assert records[1].emitted_updates == (0, 4096)
    assert records[1].raw.startswith(b"\x20" + encode_size_update_model(4096))
    assert records[1].model_entries == ((b"x-two", b"two"),)
    assert (b"x-one", b"one") not in records[1].model_entries

    # x-one was evicted and had to be re-added behind x-two.
    assert records[2].model_entries == ((b"x-one", b"one"), (b"x-two", b"two"))
    assert records[2].decoder_entries == records[2].model_entries


def test_sensitive_entries_are_evicted_at_the_minimum_not_kept_by_a_late_update() -> None:
    """
    A previously indexed sensitive-looking value must be evicted when the
    table passes through a size that cannot hold it, even if the final size
    would hold it again and the current field is marked sensitive.
    """
    steps = [
        ([("authorization", "Bearer secret-value-0001")], ()),
        ([("authorization", "Bearer secret-value-0001", True)], (0, 4096)),
        ([("authorization", "Bearer secret-value-0001", True)], ()),
    ]
    records = run_session(steps)

    assert records[0].model_entries == ((b"authorization", b"Bearer secret-value-0001"),)
    assert records[1].emitted_updates == (0, 4096)
    assert records[1].model_entries == ()
    assert records[1].decoder_entries == ()

    # The sensitive field on the wire must be a literal, never an index into
    # the stale entry.  The name is the static index 23 with a literal value
    # and the "never indexed" pattern.
    value = b"Bearer secret-value-0001"
    name_prefix = bytearray(encode_integer_model(23, 4))
    name_prefix[0] |= 0x10
    expected_literal = bytes(name_prefix) + bytes([len(value)]) + value
    operations = parse_block(records[2].raw)
    assert records[2].raw == expected_literal
    assert operations == [
        LiteralField(
            23,
            None,
            value,
            False,
            True,
            expected_literal,
        ),
    ]
    assert records[2].model_entries == records[2].decoder_entries == ()


def test_repeated_values_emit_one_update_and_never_three() -> None:
    steps = [
        ([("x", "a")], ()),
        ([("x", "a")], (40, 40, 40)),
        ([("x", "a")], ()),
        ([("x", "a")], (100, 40, 100)),
        ([("x", "a")], ()),
    ]
    records = run_session(steps)

    assert records[1].emitted_updates == (40,)
    assert records[1].raw.startswith(encode_size_update_model(40))
    assert records[3].emitted_updates == (40, 100)
    for record in records:
        assert len(record.emitted_updates) <= 2
        assert record.decoded_fields == (("x", "a"),)


def test_shrink_and_restore_to_same_value_still_signals_the_minimum() -> None:
    steps = [
        ([("x-long", "a" * 40)], ()),
        ([("x-new", "new")], (0, 4096)),
        ([("x-new", "new")], ()),
    ]
    records = run_session(steps)

    assert records[1].emitted_updates == (0, 4096)
    assert records[1].model_entries == ((b"x-new", b"new"),)


def test_empty_header_blocks_still_carry_the_size_updates() -> None:
    steps = [
        ([("x-long", "a" * 40)], ()),
        ([], (0, 4096)),
        ([("x-new", "new")], ()),
        ([], ()),
    ]
    records = run_session(steps)

    assert records[1].raw == b"\x20" + encode_size_update_model(4096)
    assert records[1].decoded_fields == ()
    assert records[1].model_entries == ()
    assert records[3].raw == b""
    assert records[3].model_entries == ((b"x-new", b"new"),)


def test_peer_allowed_size_changes_between_blocks() -> None:
    steps = [
        ([("x-one", "one")], ()),
        ([("x-two", "two")], (100, 200)),
        ([("x-two", "two")], (50, 60)),
        ([("x-two", "two")], ()),
    ]
    records = run_session(steps, allowed_sizes=[4096, 200, 60, 60])

    for record in records:
        assert all(size <= record.allowed for size in record.emitted_updates)

    assert [record.emitted_updates for record in records] == [(), (100, 200), (50, 60), ()]
    assert records[2].model_entries == ((b"x-two", b"two"),)
    assert records[3].model_entries == ((b"x-two", b"two"),)


def test_decoder_rejects_update_after_indexed_field() -> None:
    decoder = Decoder()
    with pytest.raises(HPACKDecodingError, match="not at the start"):
        decoder.decode(b"\x82" + encode_size_update_model(40))


def test_decoder_rejects_update_after_literal_field() -> None:
    decoder = Decoder()
    with pytest.raises(HPACKDecodingError, match="not at the start"):
        decoder.decode(b"\x40\x05x-one\x03one" + encode_size_update_model(100))


def test_decoder_applies_repeated_updates_in_order() -> None:
    """
    A decoder must apply updates in order even when a block repeats a value.
    Emitting more than the required two updates is not a decoding error in
    RFC 7541; it only wastes bytes, so the decoder must stay in sync with the
    model instead of rejecting the block.
    """
    decoder = Decoder()
    data = (
        encode_size_update_model(40)
        + encode_size_update_model(40)
        + encode_size_update_model(100)
        + encode_size_update_model(4096)
        + b"\x82"
    )
    assert decoder.decode(data) == [(":method", "GET")]
    assert decoder.header_table_size == 4096

    model = ModelTable()
    assert apply_operations(model, parse_block(data)) == [(b":method", b"GET")]
    assert model.maxsize == 4096
    assert_decoder_table_matches(decoder, model, "repeated updates")


def test_decoder_accepts_exactly_two_updates() -> None:
    decoder = Decoder()
    data = encode_size_update_model(40) + encode_size_update_model(4096) + b"\x82"
    assert decoder.decode(data) == [(":method", "GET")]
    assert decoder.header_table_size == 4096


def test_decoder_rejects_update_above_peer_allowance() -> None:
    decoder = Decoder()
    decoder.max_allowed_table_size = 127
    with pytest.raises(InvalidTableSizeError):
        decoder.decode(encode_size_update_model(128) + b"\x82")


def test_decoder_rejects_late_update_after_peer_shrinks_allowance() -> None:
    decoder = Decoder()
    decoder.decode(b"\x40\x05x-one\x03one")

    decoder.max_allowed_table_size = 40
    with pytest.raises(InvalidTableSizeError):
        decoder.decode(b"\x82")


def test_decoder_rejects_update_after_peer_shrinks_allowance() -> None:
    decoder = Decoder()
    decoder.decode(b"\x40\x05x-one\x03one")

    decoder.max_allowed_table_size = 50
    with pytest.raises(InvalidTableSizeError):
        decoder.decode(encode_size_update_model(100) + b"\x82")


def test_omitted_minimum_update_is_located_at_first_desynchronised_block() -> None:
    steps = [
        ([("x-alpha", "value-alpha"), ("x-beta", "value-beta")], ()),
        ([("x-gamma", "value-gamma")], (60, 4096)),
        ([("x-gamma", "value-gamma"), ("x-delta", "value-delta")], ()),
    ]
    records = run_session(steps)
    assert records[1].emitted_updates == (60, 4096)
    assert records[1].model_entries == ((b"x-gamma", b"value-gamma"), (b"x-beta", b"value-beta"))

    operations = parse_block(records[1].raw)
    minimum_update = next(operation for operation in operations if isinstance(operation, SizeUpdate))
    assert minimum_update.size == 60

    # Retain the final-size update, but omit the update for the minimum size.
    mutated_raw = b"".join(
        operation.raw
        for operation in operations
        if not (isinstance(operation, SizeUpdate) and operation is minimum_update)
    )
    assert encode_size_update_model(60) not in mutated_raw

    decoder = Decoder()
    assert [tuple(field) for field in decoder.decode(records[0].raw)] == list(records[0].decoded_fields)
    assert [tuple(field) for field in decoder.decode(mutated_raw)] == list(records[1].decoded_fields)

    # The model now represents what the faulty stream says, not what the
    # encoder intended: x-alpha was never evicted.
    expected_table = ModelTable()
    apply_operations(expected_table, parse_block(records[0].raw))
    apply_operations(expected_table, parse_block(mutated_raw))

    correct_table = ModelTable()
    apply_operations(correct_table, parse_block(records[0].raw))
    apply_operations(correct_table, parse_block(records[1].raw))

    actual = probe_decoder_entries(decoder)
    assert actual == expected_table.entries_tuple()
    assert actual != correct_table.entries_tuple()

    # First divergence: the decoder still serves x-alpha at the stale dynamic
    # index, in the very block whose update was dropped.  This is caught here
    # rather than by waiting for a later request.
    assert len(actual) == len(correct_table.entries) + 1
    stale_index = STATIC_LENGTH + 1 + len(correct_table.entries)
    with pytest.raises(InvalidTableIndexError):
        correct_table.dynamic_lookup(stale_index)
    assert tuple(decoder.decode(encode_indexed_model(stale_index), raw=True)[0]) == (b"x-alpha", b"value-alpha")

    # Decoding the next block still succeeds and returns the same fields as
    # the correct stream, so a test that only compares header values would
    # miss the desynchronised table entirely.
    assert [tuple(field) for field in decoder.decode(records[2].raw)] == list(records[2].decoded_fields)
    assert probe_decoder_entries(decoder) != correct_table.entries_tuple()
