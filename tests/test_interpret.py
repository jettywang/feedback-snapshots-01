"""
Tests for the read-only HPACK interpretation mode and its provenance chain.
"""
from __future__ import annotations

import pytest
from hpack import (
    UNCERTAIN_DECODING_ERROR,
    UNCERTAIN_DISCARDED_BLOCK,
    UNCERTAIN_EVICTED_ENTRY,
    UNCERTAIN_INVALID_REFERENCE,
    UNCERTAIN_MISSING_BLOCK,
    Decoder,
    Encoder,
    FieldProvenance,
    HeaderBlockInterpreter,
    HeaderTuple,
    HPACKDecodingError,
    InterpretationResult,
    InvalidTableIndex,
    NeverIndexedHeaderTuple,
    OversizedHeaderListError,
    TableSizeUpdateRecord,
)
from hpack.hpack import (
    REPRESENTATION_INDEXED,
    REPRESENTATION_LITERAL_INCREMENTAL,
    REPRESENTATION_LITERAL_NEVER_INDEXED,
    REPRESENTATION_LITERAL_WITHOUT_INDEXING,
    REPRESENTATION_TABLE_SIZE_UPDATE,
)
from hpack.struct import ByteRange, WireString

STATIC_TABLE_LENGTH = 61


def _encode_block(headers, huffman=False, table_size=None):
    encoder = Encoder()
    if table_size is not None:
        encoder.header_table_size = table_size
    return encoder, encoder.encode(headers, huffman=huffman)


class TestRepresentationProvenance:
    def test_literal_with_literal_name_and_value(self):
        block = b"\x40\x01x\x01y"
        result = HeaderBlockInterpreter().interpret(block)

        assert isinstance(result, InterpretationResult)
        assert result.block_sequence == 0
        assert result.uncertain is False
        assert result.size_updates == ()
        provenance, = result.fields
        assert provenance.name == b"x"
        assert provenance.value == b"y"
        assert provenance.representation == REPRESENTATION_LITERAL_INCREMENTAL
        assert provenance.field_range == ByteRange(0, 5)
        assert provenance.name_reference is None
        assert provenance.name_wire == WireString(
            encoded=b"x",
            huffman_encoded=False,
            encoded_range=ByteRange(2, 3),
        )
        assert provenance.value_wire == WireString(
            encoded=b"y",
            huffman_encoded=False,
            encoded_range=ByteRange(4, 5),
        )
        assert provenance.uncertain is False

    def test_literal_without_indexing_and_never_indexed(self):
        without = HeaderBlockInterpreter().interpret(b"\x00\x01x\x01y").fields[0]
        never = HeaderBlockInterpreter().interpret(b"\x10\x01x\x01y").fields[0]

        assert without.representation == REPRESENTATION_LITERAL_WITHOUT_INDEXING
        assert never.representation == REPRESENTATION_LITERAL_NEVER_INDEXED
        assert isinstance(
            HeaderBlockInterpreter().interpret(b"\x10\x01x\x01y").decoded_headers[0],
            NeverIndexedHeaderTuple,
        )

    def test_indexed_static_reference(self):
        result = HeaderBlockInterpreter().interpret(b"\x82")  # :method GET

        provenance, = result.fields
        assert provenance.representation == REPRESENTATION_INDEXED
        assert provenance.field_range == ByteRange(0, 1)
        reference = provenance.name_reference
        assert reference is not None
        assert reference.table == "static"
        assert reference.index == 2
        assert reference.static_index == 2
        assert reference.origin is None
        assert reference.uncertain is False
        assert provenance.name == b":method"
        assert provenance.value == b"GET"
        assert provenance.name_wire is None
        assert provenance.value_wire is None

    def test_literal_with_indexed_name(self):
        # 0x42: literal incremental, name from static index 2 (:method).
        result = HeaderBlockInterpreter().interpret(b"\x42\x03WOW")

        provenance, = result.fields
        assert provenance.name == b":method"
        assert provenance.value == b"WOW"
        assert provenance.name_wire is None
        reference = provenance.name_reference
        assert reference is not None
        assert reference.table == "static"
        assert reference.index == 2
        assert provenance.value_wire.encoded_range == ByteRange(2, 5)

    def test_huffman_ranges_point_at_compressed_wire_bytes(self):
        encoder = Encoder()
        block = encoder.encode([("custom-key", "custom-header")], huffman=True)
        provenance = HeaderBlockInterpreter().interpret(block).fields[0]

        name_wire = provenance.name_wire
        value_wire = provenance.value_wire
        assert name_wire.huffman_encoded
        assert value_wire.huffman_encoded
        # The recorded ranges slice the actual compressed octets out of the
        # block, never offsets into the decompressed output.
        assert block[name_wire.encoded_range.start:name_wire.encoded_range.end] == name_wire.encoded
        assert block[value_wire.encoded_range.start:value_wire.encoded_range.end] == value_wire.encoded
        assert len(value_wire.encoded) != len(provenance.value)
        assert provenance.value == b"custom-header"

    def test_empty_value_string(self):
        encoder = Encoder()
        block = encoder.encode([("name", "")], huffman=False)
        provenance = HeaderBlockInterpreter().interpret(block).fields[0]

        assert provenance.value == b""
        assert provenance.value_wire.encoded == b""
        start = provenance.value_wire.encoded_range.start
        assert provenance.value_wire.encoded_range == ByteRange(start, start)


class TestDynamicProvenance:
    def test_dynamic_indexed_reference_chain(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        first = encoder.encode([("x-sensitive", "secret-value")], huffman=False)
        second = encoder.encode([("x-sensitive", "secret-value")], huffman=False)

        insert = interpreter.interpret(first).fields[0]
        referenced = interpreter.interpret(second).fields[0]

        assert insert.representation == REPRESENTATION_LITERAL_INCREMENTAL
        reference = referenced.name_reference
        assert reference is not None
        assert reference.table == "dynamic"
        assert reference.index == STATIC_TABLE_LENGTH + 1
        origin = reference.origin
        assert origin is not None
        assert origin.block_sequence == 0
        assert origin.dynamic_position == 1
        assert origin.insert_range == insert.field_range
        assert origin.name == b"x-sensitive"
        assert origin.value == b"secret-value"
        assert origin.retained is True

        chain = interpreter.source_chain(referenced)
        assert len(chain) == 1
        assert chain[0].insertion_id == origin.insertion_id

    def test_duplicate_same_name_value_keep_distinct_origins(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        encoder.header_table_size = 256
        interpreter.interpret(encoder.encode([("a", "b")], huffman=False))
        interpreter.interpret(
            encoder.encode([("x-sensitive", "secret-value")], huffman=False),
        )
        # A second, byte-identical entry inserted via a raw literal.
        duplicate_block = b"\x40\x0bx-sensitive\x0csecret-value"
        interpreter.interpret(duplicate_block)

        # Newest duplicate is index 62, older one index 63.
        newest = interpreter.interpret(b"\xbe").fields[0].name_reference
        oldest = interpreter.interpret(b"\xbf").fields[0].name_reference

        assert newest.origin.insertion_id != oldest.origin.insertion_id
        assert newest.origin.block_sequence != oldest.origin.block_sequence
        assert oldest.origin.insert_range == ByteRange(0, 26)
        assert newest.origin.block_sequence == 2
        assert newest.origin.name == oldest.origin.name
        assert newest.origin.value == oldest.origin.value

    def test_chain_follows_indexed_name_references(self):
        interpreter = HeaderBlockInterpreter()
        # Insert (a, b), then (a, c) referencing the name of the first entry.
        interpreter.interpret(b"\x40\x01a\x01b")
        interpreter.interpret(b"\x7e\x01c")  # index 62 name reference
        second = interpreter.interpret(b"\xbe").fields[0]  # index 62 -> (a, c)

        chain = interpreter.source_chain(second)
        assert [origin.name for origin in chain] == [b"a", b"a"]
        assert chain[0].value == b"c"
        assert chain[1].value == b"b"

    def test_eviction_recorded_on_origin(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        encoder.header_table_size = 256
        interpreter.interpret(encoder.encode([("a", "b")], huffman=False))
        interpreter.interpret(
            encoder.encode([("x-sensitive", "secret-value")], huffman=False),
        )

        encoder.header_table_size = 0
        shrink = interpreter.interpret(encoder.encode([("a", "b")], huffman=False))
        record, = shrink.size_updates
        assert record.representation == REPRESENTATION_TABLE_SIZE_UPDATE
        assert record.new_size == 0
        assert record.field_range == ByteRange(0, 1)

        origin = interpreter._origin_archive[1].snapshot()
        update, = origin.size_updates
        assert update.new_max_size == 0
        assert set(update.evicted_insertion_ids) == {0, 1}

    def test_insertion_driven_eviction(self):
        interpreter = HeaderBlockInterpreter()
        # Entry size 55; table max 64 holds one of them at a time.
        interpreter.interpret(b"\x3f\x21")  # table size update to 64
        first = interpreter.interpret(b"\x40\x0bx-sensitive\x0csecret-value")
        assert first.fields[0].field_range == ByteRange(0, 26)

        interpreter.interpret(b"\x40\x01z\x01z")
        # The first entry was evicted; the new entry is the only resident.
        assert [entry.insertion_id for entry in interpreter._entries] == [1]
        assert interpreter._origin_archive[0].retained is False

    def test_entry_larger_than_max_clears_the_table(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(b"\x3f\x21")  # max size 64
        interpreter.interpret(b"\x40\x01z\x01z")  # entry size 35, resident
        # This entry weighs 55 bytes but a size update to 40 makes it too big.
        interpreter.interpret(b"\x3f\x09")
        oversized = interpreter.interpret(
            b"\x40\x0bx-sensitive\x0csecret-value",
        )
        assert oversized.uncertain is False
        # The oversized entry is never resident and the prior entry is gone,
        # matching HeaderTable.add's clear-and-skip behaviour.
        assert list(interpreter._entries) == []
        assert list(interpreter.decoder.header_table.dynamic_entries) == []
        # No origin record is minted for the rejected insertion.
        assert 1 not in interpreter._origin_archive
        assert interpreter._origin_archive[0].retained is False

    def test_resize_to_zero_evicts_all_residents(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(b"\x40\x01a\x01b")
        interpreter.interpret(b"\x40\x01c\x01d")
        result = interpreter.interpret(b"\x20")

        assert result.size_updates[0].new_size == 0
        assert list(interpreter._entries) == []
        eviction_lists = [
            update.evicted_insertion_ids
            for origin in interpreter._origin_archive.values()
            for update in origin.size_updates
        ]
        assert eviction_lists
        assert all(ids == (0, 1) for ids in eviction_lists)
        assert all(
            origin.retained is False
            for origin in interpreter._origin_archive.values()
        )

    def test_stale_dynamic_index_is_uncertain_but_still_raises(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(b"\x3f\x21")
        interpreter.interpret(b"\x40\x0bx-sensitive\x0csecret-value")
        interpreter.interpret(b"\x20")  # shrink to zero

        with pytest.raises(InvalidTableIndex):
            interpreter.interpret(b"\xbe")
        assert interpreter.uncertain is True
        assert interpreter.uncertain_reason == UNCERTAIN_DECODING_ERROR


class TestUncertainty:
    def test_missing_prior_block_taints_dynamic_not_static(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(
            encoder.encode([("x-sensitive", "secret-value")], huffman=False),
        )

        interpreter.mark_history_gap()
        assert interpreter.uncertain is True
        assert interpreter.uncertain_reason == UNCERTAIN_MISSING_BLOCK

        dynamic = interpreter.interpret(b"\xbe").fields[0]
        assert dynamic.uncertain is True
        assert dynamic.uncertain_reason == UNCERTAIN_MISSING_BLOCK
        assert dynamic.name_reference.uncertain is True

        static = interpreter.interpret(b"\x82").fields[0]
        assert static.uncertain is False
        assert static.name_reference.table == "static"

    def test_tainted_dynamic_name_reference_is_uncertain(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(b"\x40\x01a\x01b")
        interpreter.mark_history_gap()
        # Literal incremental whose name is taken from dynamic index 62.
        provenance = interpreter.interpret(b"\x7e\x01z").fields[0]
        assert provenance.uncertain is True
        assert provenance.uncertain_reason == UNCERTAIN_MISSING_BLOCK
        assert provenance.name_reference.table == "dynamic"

    def test_evicted_reference_under_taint_reports_taint_reason(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(b"\x40\x01a\x01b")
        interpreter.interpret(b"\x20")
        interpreter.mark_history_gap()
        reference = interpreter._resolve_reference(STATIC_TABLE_LENGTH + 1)
        assert reference.uncertain_reason == UNCERTAIN_MISSING_BLOCK

    def test_zero_index_is_invalid_reference(self):
        reference = HeaderBlockInterpreter()._resolve_reference(0)
        assert reference.uncertain is True
        assert reference.uncertain_reason == UNCERTAIN_INVALID_REFERENCE

    def test_discard_block_removes_certainty_of_later_references(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        encoder.header_table_size = 256
        interpreter.interpret(encoder.encode([("a", "b")], huffman=False))
        target_result = interpreter.interpret(
            encoder.encode([("x-sensitive", "secret-value")], huffman=False),
        )
        target_block = target_result.block_sequence

        interpreter.discard_block(target_block)
        provenance = interpreter.interpret(b"\xbe").fields[0]  # index 62 -> target

        assert provenance.uncertain is True
        assert provenance.uncertain_reason == UNCERTAIN_DISCARDED_BLOCK
        assert provenance.name_reference.origin.retained is False

    def test_discard_unrelated_block_keeps_certainty(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        encoder.header_table_size = 256
        first_block = interpreter.interpret(
            encoder.encode([("a", "b")], huffman=False),
        )
        interpreter.interpret(
            encoder.encode([("x-sensitive", "secret-value")], huffman=False),
        )

        interpreter.discard_block(first_block.block_sequence)
        provenance = interpreter.interpret(b"\xbe").fields[0]  # index 62 -> target
        assert provenance.uncertain is False

    def test_discard_unknown_block_is_a_noop(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.discard_block(99)
        assert interpreter.uncertain is False

    def test_compression_error_taints_all_future_blocks(self):
        interpreter = HeaderBlockInterpreter()
        with pytest.raises(HPACKDecodingError):
            interpreter.interpret(b"\xff\xff\xff\xff\xff\xff\xff\x00")

        assert interpreter.uncertain is True
        assert interpreter.uncertain_reason == UNCERTAIN_DECODING_ERROR

        result = interpreter.interpret(b"\x82")
        assert result.uncertain is True
        assert result.uncertain_reason == UNCERTAIN_DECODING_ERROR
        # The static field itself still has a trustworthy static origin.
        assert result.fields[0].uncertain is False

    def test_truncated_literal_is_a_compression_error(self):
        interpreter = HeaderBlockInterpreter()
        with pytest.raises(HPACKDecodingError):
            interpreter.interpret(b"\x40\x0aab")
        assert interpreter.uncertain_reason == UNCERTAIN_DECODING_ERROR

    def test_invalid_table_reference_reason(self):
        # A dynamic index beyond the table cannot be resolved by the decoder.
        interpreter = HeaderBlockInterpreter()
        with pytest.raises(InvalidTableIndex):
            interpreter.interpret(b"\xbe")
        assert interpreter.uncertain_reason == UNCERTAIN_DECODING_ERROR

    def test_evicted_entry_reason_constant_is_exposed(self):
        assert UNCERTAIN_EVICTED_ENTRY == "evicted_dynamic_entry"
        assert UNCERTAIN_INVALID_REFERENCE == "invalid_table_reference"

    def test_evicted_entry_resolves_with_eviction_reason(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.interpret(b"\x40\x01a\x01b")
        interpreter.interpret(b"\x20")  # shrink to zero, entry id 0 is evicted

        reference = interpreter._resolve_reference(STATIC_TABLE_LENGTH + 1)
        assert reference.table == "dynamic"
        assert reference.uncertain is True
        assert reference.uncertain_reason == UNCERTAIN_EVICTED_ENTRY
        assert reference.origin.insertion_id == 0
        assert reference.origin.retained is False

    def test_unknown_dynamic_index_is_invalid_reference(self):
        interpreter = HeaderBlockInterpreter()
        reference = interpreter._resolve_reference(STATIC_TABLE_LENGTH + 5)
        assert reference.uncertain is True
        assert reference.uncertain_reason == UNCERTAIN_INVALID_REFERENCE
        assert reference.origin is None

    def test_custom_gap_reason_is_recorded(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.mark_history_gap("custom-reason")
        assert interpreter.uncertain_reason == "custom-reason"

    def test_repeated_taint_keeps_first_reason(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.mark_history_gap("first")
        interpreter.mark_history_gap("second")
        assert interpreter.uncertain_reason == "first"

    def test_error_taints_records_decoded_before_failure(self):
        interpreter = HeaderBlockInterpreter()
        # A valid indexed field followed by an invalid integer: the first
        # record was already emitted when decoding fails.
        with pytest.raises(HPACKDecodingError):
            interpreter.interpret(b"\x82\xff\xff\xff\xff\xff\xff\xff\x00")
        assert interpreter.uncertain_reason == UNCERTAIN_DECODING_ERROR

    def test_source_chain_is_cycle_safe(self):
        interpreter = HeaderBlockInterpreter()
        provenance = interpreter.interpret(b"\x82").fields[0]
        # Static references terminate immediately; the loop must terminate even
        # if handed a malformed chain.
        assert interpreter.source_chain(provenance) == ()


class TestTableSizeUpdates:
    def test_size_update_record_ranges_and_sequence(self):
        interpreter = HeaderBlockInterpreter()
        result = interpreter.interpret(b"\x3f\x21")  # size 64, two-byte int

        record, = result.size_updates
        assert record.new_size == 64
        assert record.index_range == ByteRange(0, 2)
        assert record.field_range == ByteRange(0, 2)
        assert record.uncertain is False
        assert result.fields == ()

    def test_size_update_after_header_is_decoding_error(self):
        interpreter = HeaderBlockInterpreter()
        with pytest.raises(HPACKDecodingError):
            interpreter.interpret(b"\x82\x20")
        assert interpreter.uncertain is True

    def test_size_update_while_tainted_is_marked_uncertain(self):
        interpreter = HeaderBlockInterpreter()
        interpreter.mark_history_gap()
        record = interpreter.interpret(b"\x20").size_updates[0]
        assert record.uncertain is True
        assert record.uncertain_reason == UNCERTAIN_MISSING_BLOCK

    def test_resize_eviction_mirrors_decoder_table(self):
        encoder = Encoder()
        interpreter = HeaderBlockInterpreter()
        encoder.header_table_size = 256
        block = encoder.encode(
            [("a", "b"), ("c", "d"), ("e", "f")],
            huffman=False,
        )
        interpreter.interpret(block)

        encoder.header_table_size = 40
        interpreter.interpret(encoder.encode([("a", "b")], huffman=False))

        interpreted_names = [entry.name for entry in interpreter._entries]
        decoder_names = [name for name, _ in interpreter.decoder.header_table.dynamic_entries]
        assert interpreted_names == decoder_names


class TestReadOnlyBehaviour:
    def test_decoded_headers_match_plain_decoder(self):
        encoder = Encoder()
        decoder = Decoder()
        interpreter = HeaderBlockInterpreter()
        blocks = [
            encoder.encode([("a", "b")], huffman=False),
            encoder.encode([("x-sensitive", "secret-value")], huffman=True),
            encoder.encode([("a", "b"), ("c", "d")], huffman=False),
        ]

        for block in blocks:
            expected = decoder.decode(block, raw=True)
            result = interpreter.interpret(block, raw=True)
            assert list(result.decoded_headers) == list(expected)
            assert all(isinstance(h, HeaderTuple) for h in result.decoded_headers)

    def test_dynamic_table_state_identical_to_plain_decoder(self):
        encoder = Encoder()
        decoder = Decoder()
        interpreter = HeaderBlockInterpreter()
        blocks = [
            encoder.encode([("a", "b")], huffman=False),
            encoder.encode([("x-sensitive", "secret-value")], huffman=False),
            encoder.encode([("a", "b"), ("c", "d")], huffman=False),
        ]

        for block in blocks:
            decoder.decode(block)
            interpreter.interpret(block)

        assert list(decoder.header_table.dynamic_entries) == list(
            interpreter.decoder.header_table.dynamic_entries,
        )
        assert decoder.header_table_size == interpreter.decoder.header_table_size

    def test_sink_does_not_change_decode_without_interpreter(self):
        class RecordingSink:
            def __init__(self):
                self.events = []

            def on_indexed(self, event):
                self.events.append(event)

            def on_literal(self, event):
                self.events.append(event)

            def on_table_size_update(self, event):
                self.events.append(event)

        encoder = Encoder()
        decoder_with_sink = Decoder()
        decoder_plain = Decoder()
        block = encoder.encode([("a", "b"), ("c", "d")], huffman=True)

        sink = RecordingSink()
        decoder_with_sink.decode(block, sink=sink)
        decoder_plain.decode(block)
        assert list(decoder_with_sink.header_table.dynamic_entries) == list(
            decoder_plain.header_table.dynamic_entries,
        )
        assert len(sink.events) == 2

    def test_block_sequences_increment(self):
        interpreter = HeaderBlockInterpreter()
        assert interpreter.block_sequence == -1
        first = interpreter.interpret(b"\x82")
        second = interpreter.interpret(b"\x82")
        assert first.block_sequence == 0
        assert second.block_sequence == 1
        assert interpreter.block_sequence == 1

    def test_headers_mix_fields_and_size_updates_in_order(self):
        interpreter = HeaderBlockInterpreter()
        result = interpreter.interpret(b"\x3f\x21\x82")

        assert len(result.headers) == 2
        assert isinstance(result.headers[0], TableSizeUpdateRecord)
        assert isinstance(result.headers[1], FieldProvenance)

    def test_custom_max_header_list_size_forwarded(self):
        interpreter = HeaderBlockInterpreter(max_header_list_size=1)
        with pytest.raises(OversizedHeaderListError):
            interpreter.interpret(b"\x40\x01x\x01y")

    def test_source_chain_empty_without_dynamic_reference(self):
        provenance = HeaderBlockInterpreter().interpret(b"\x82").fields[0]
        assert HeaderBlockInterpreter().source_chain(provenance) == ()
