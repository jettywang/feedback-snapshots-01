"""
Tests for the optional Encoder context-switch interface used when one HPACK
encoder multiplexes headers from several request sources.

These tests assert, among other things, that switching sources:

* empties the local dynamic table and emits a legal dynamic table size update
  that empties the peer's table in lockstep,
* keeps the shared static table usable,
* leaves the encoder in a defined state for zero peer size, repeated
  switches, and a failed first block after a switch,
* prevents a source's first block from shrinking because another source
  previously emitted the same value.

The mitigation only targets cross-source dynamic-table probing; it does not
claim to remove every length-based side channel.
"""
from __future__ import annotations

import pytest
from hpack import Decoder, Encoder, InvalidTableSizeError, NeverIndexedHeaderTuple

SECRET_NAME = "x-secret-token"
SECRET_VALUE = "s3cr3t-value-shared-by-sources"


def _switch_prefix(encoder: Encoder) -> bytes:
    """The wire bytes that resynchronize the peer after a switch."""
    # The switch always queues a zero update, then a restore update unless the
    # peer forbids any dynamic table.
    prefix = b"\x20"
    if encoder.max_allowed_table_size > 0:
        prefix += _encode_size_update(encoder.max_allowed_table_size)
    return prefix


def _encode_size_update(size: int) -> bytes:
    from hpack.hpack import encode_integer

    field = encode_integer(size, 5)
    field[0] |= 0x20
    return bytes(field)


class TestContextSwitchEncoder:
    def test_switch_queues_legal_size_updates_and_clears_local_history(self):
        encoder = Encoder()
        encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)
        assert len(encoder.header_table.dynamic_entries) == 1

        encoder.switch_context("source-b")

        assert list(encoder.header_table.dynamic_entries) == []
        assert encoder.table_size_changes == [0, encoder.max_allowed_table_size]
        assert encoder.header_table_size == encoder.max_allowed_table_size
        assert encoder.current_source == "source-b"
        # The resized flag marks the queued updates for emission at the start
        # of the next block; rebuilding the local object would not reach the
        # peer, so wire updates rather than object identity do the sync.
        assert encoder.header_table.resized is True

    def test_first_block_after_switch_carries_size_update_prefix(self):
        encoder = Encoder()
        encoder.switch_context("source-a")

        block = encoder.encode([(":method", "GET")], huffman=False)

        assert block.startswith(_switch_prefix(encoder))
        # The queued updates are consumed exactly once.
        assert encoder.table_size_changes == []

    def test_peer_with_zero_allowed_size(self):
        encoder = Encoder()
        encoder.max_allowed_table_size = 0
        encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)

        encoder.switch_context("source-a")

        assert encoder.header_table_size == 0
        assert encoder.table_size_changes == [0, 0]
        block = encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)
        assert block.startswith(b"\x20")
        # Nothing can be indexed while the peer forbids a dynamic table.
        assert list(encoder.header_table.dynamic_entries) == []

        Decoder().decode(block)  # a default decoder accepts the zero update

    def test_decoder_rejects_switch_update_when_peer_forbids_any_table(self):
        # If the peer advertised a zero SETTINGS_HEADER_TABLE_SIZE, an
        # encoder that ignores it and tries to restore a non-zero table is
        # rejected by the decoder with a defined error.
        decoder = Decoder()
        decoder.max_allowed_table_size = 0

        encoder = Encoder()  # default max 4096, misconfigured for this peer
        encoder.switch_context("source-a")
        block = encoder.encode([(":method", "GET")], huffman=False)

        with pytest.raises(InvalidTableSizeError):
            decoder.decode(block)

    def test_repeated_and_same_source_switches_are_idempotent(self):
        encoder = Encoder()
        encoder.switch_context("source-a")
        first = encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)

        encoder.switch_context("source-a")
        encoder.switch_context("source-b")
        encoder.switch_context("source-b")

        assert encoder.table_size_changes == [0, encoder.max_allowed_table_size]
        assert list(encoder.header_table.dynamic_entries) == []
        assert encoder.current_source == "source-b"

        second = encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)
        assert second.startswith(_switch_prefix(encoder))
        # Both blocks must decode correctly on the same decoder.
        decoder = Decoder()
        assert decoder.decode(first) == [(SECRET_NAME, SECRET_VALUE)]
        assert decoder.decode(second) == [(SECRET_NAME, SECRET_VALUE)]

    def test_failed_first_block_after_switch_keeps_defined_state(self):
        encoder = Encoder()
        encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)
        encoder.switch_context("source-b")

        class Broken:
            def __str__(self) -> str:
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            encoder.encode([("name", Broken())], huffman=False)

        # The queued synchronization must survive so the peer still empties
        # its table, and the local table must stay empty.
        assert encoder.table_size_changes == [0, encoder.max_allowed_table_size]
        assert list(encoder.header_table.dynamic_entries) == []
        assert encoder.current_source == "source-b"

        # Retrying with a valid block succeeds and still carries the prefix.
        retry = encoder.encode([(SECRET_NAME, SECRET_VALUE)], huffman=False)
        assert retry.startswith(_switch_prefix(encoder))
        assert encoder.table_size_changes == []
        Decoder().decode(retry)

    def test_static_table_remains_usable_across_switches(self):
        encoder = Encoder()
        encoder.switch_context("source-a")
        block = encoder.encode([(":method", "GET"), (":path", "/")], huffman=False)

        # Static entries keep their one-byte indexed representation (0x82,
        # 0x84) immediately after the size-update prefix.
        assert block == _switch_prefix(encoder) + b"\x82\x84"
        assert Decoder().decode(block) == [(":method", "GET"), (":path", "/")]

    def test_switch_replaces_previously_pending_resize(self):
        encoder = Encoder()
        encoder.header_table_size = 40
        encoder.switch_context("source-a")

        # The pre-switch resize belongs to the old context and must not leak.
        assert encoder.table_size_changes == [0, encoder.max_allowed_table_size]

    def test_negative_peer_size_is_rejected(self):
        encoder = Encoder()
        encoder.max_allowed_table_size = -1

        with pytest.raises(ValueError, match="zero or a positive integer"):
            encoder.switch_context("source-a")


class TestTwoSourceInterleaving:
    def _source_blocks(self) -> dict[str, list[bytes]]:
        encoder = Encoder()
        headers = [(":method", "GET"), (SECRET_NAME, SECRET_VALUE)]

        blocks: dict[str, list[bytes]] = {"a": [], "b": []}
        blocks["a"].append(encoder.encode(headers, huffman=False))
        encoder.switch_context("b")
        blocks["b"].append(encoder.encode(headers, huffman=False))
        encoder.switch_context("a")
        blocks["a"].append(encoder.encode(headers, huffman=False))
        encoder.switch_context("b")
        blocks["b"].append(encoder.encode(headers, huffman=False))
        return blocks

    def test_single_decoder_decodes_interleaved_blocks_correctly(self):
        blocks = self._source_blocks()
        decoder = Decoder()

        for block in blocks["a"][:1] + blocks["b"][:1] + blocks["a"][1:] + blocks["b"][1:]:
            assert decoder.decode(block) == [
                (":method", "GET"),
                (SECRET_NAME, SECRET_VALUE),
            ]

    def test_second_source_first_block_is_not_shortened_by_first_source(self):
        blocks = self._source_blocks()
        prefix = _switch_prefix(Encoder())

        # Reference: without any context switch the encoder *would* reuse the
        # dynamic-table entry, turning the secret into a short indexed field.
        reuse_encoder = Encoder()
        first_payload = reuse_encoder.encode(
            [(":method", "GET"), (SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        reused_payload = reuse_encoder.encode(
            [(":method", "GET"), (SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        assert len(reused_payload) < len(first_payload)
        assert SECRET_VALUE.encode() not in reused_payload

        # After a switch neither source gets that shortening: every block that
        # follows a switch carries the full literal again.
        b_payload = blocks["b"][0][len(prefix):]
        a_payload_after_switch = blocks["a"][1][len(prefix):]
        assert b_payload == first_payload
        assert a_payload_after_switch == first_payload

        # B's first block is byte-for-byte what a brand-new encoder that never
        # saw A's traffic would produce.
        fresh = Encoder()
        fresh.switch_context("b")
        fresh_b_first = fresh.encode(
            [(":method", "GET"), (SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        assert blocks["b"][0] == fresh_b_first

        # And concretely: the secret's literal bytes are present, rather than
        # a one- or two-byte dynamic-table index.
        assert SECRET_VALUE.encode() in b_payload

    def test_baseline_without_switch_does_shorten(self):
        # Control case: without switching, the same encoder would compress B's
        # block using A's history, exactly the leakage being prevented.
        encoder = Encoder()
        first = encoder.encode(
            [(":method", "GET"), (SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        second = encoder.encode(
            [(":method", "GET"), (SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        assert len(second) < len(first)
        assert SECRET_VALUE.encode() not in second

    def test_sensitive_headers_never_indexed_across_sources(self):
        encoder = Encoder()
        encoder.switch_context("a")
        block_a = encoder.encode(
            [NeverIndexedHeaderTuple(SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        encoder.switch_context("b")
        block_b = encoder.encode(
            [NeverIndexedHeaderTuple(SECRET_NAME, SECRET_VALUE)], huffman=False,
        )
        decoder = Decoder()
        assert decoder.decode(block_a) == [(SECRET_NAME, SECRET_VALUE)]
        assert decoder.decode(block_b) == [(SECRET_NAME, SECRET_VALUE)]
        assert list(encoder.header_table.dynamic_entries) == []
