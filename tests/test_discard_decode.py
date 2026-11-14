"""
Tests for discard-mode HPACK decoding.

An HPACK header list that exceeds the application limit is a rejection at the
HTTP/2 stream level, not necessarily a connection-level failure. Discard mode
therefore validates and applies the whole block (including dynamic table
updates) while never retaining or returning the business headers.
"""
import json
import time
import tracemalloc
from pathlib import Path

import pytest

from hpack import (
    DecodeMode,
    DecodeStats,
    DecodeWorkBudgetExceeded,
    DecodeWorkBudgetExceededError,
    Decoder,
    DiscardedHeaderList,
    Encoder,
    HPACKDecodingError,
    InvalidTableIndex,
    InvalidTableSizeError,
    OversizedHeaderListError,
)


def _encode(headers: list[tuple[str, str]], *, huffman: bool = False) -> bytes:
    return Encoder().encode(headers, huffman=huffman)


def _reference_decoder() -> Decoder:
    """A decoder with no application limit, used as the normal reference."""
    return Decoder(max_header_list_size=2 ** 30)


def test_default_mode_is_strict_and_unchanged():
    """
    The historical strict behaviour remains the default: an oversized list
    raises immediately and leaves the decoding context unusable.
    """
    d = Decoder(max_header_list_size=44)
    data = b'\x14\x0c/sample/path'

    assert Decoder().decode(b'\x82') == [(':method', 'GET')]
    with pytest.raises(OversizedHeaderListError):
        d.decode(data)
    assert d.connection_usable is False
    assert d.last_decode_stats is None


def test_explicit_strict_mode_matches_default():
    d1 = Decoder(max_header_list_size=44)
    d2 = Decoder(max_header_list_size=44)
    data = b'\x14\x0c/sample/path'

    with pytest.raises(OversizedHeaderListError):
        d1.decode(data)
    with pytest.raises(OversizedHeaderListError):
        d2.decode(data, mode=DecodeMode.STRICT)


def test_work_budget_defaults_to_none():
    assert Decoder().max_decode_work is None


def test_work_budget_constructor_argument():
    d = Decoder(max_decode_work=2)
    assert d.max_decode_work == 2
    assert d.decode(b'\x82\x84') == [(':method', 'GET'), (':path', '/')]
    with pytest.raises(DecodeWorkBudgetExceededError):
        d.decode(b'\x82\x84\x85')
    assert d.connection_usable is False


def test_discarded_result_is_empty_list_compatible():
    headers = [(f'x-pad-{i}', 'p' * 40) for i in range(20)]
    result = Decoder(max_header_list_size=16).decode_discard(_encode(headers))
    assert result == []
    assert not result
    assert list(result) == []
    assert list(reversed(result)) == []
    result.extend([(':method', 'GET')])
    assert result == [(':method', 'GET')]


def test_decoder_remains_usable_for_many_blocks_after_discard():
    enc = Encoder()
    filler = [(f'x-fill-{i}', 'f' * 30) for i in range(20)]
    small = [(':method', 'GET'), (':path', '/')]

    d = Decoder(max_header_list_size=128)
    ref = _reference_decoder()
    for _ in range(3):
        filler_block = enc.encode(filler)
        small_block = enc.encode(small)
        assert isinstance(d.decode_discard(filler_block), DiscardedHeaderList)
        assert len(ref.decode(filler_block)) == len(filler)
        assert d.decode(small_block) == small
        assert ref.decode(small_block) == small
        assert list(d.header_table.dynamic_entries) == list(ref.header_table.dynamic_entries)


def test_discard_mode_returns_no_partial_headers():
    """
    Crossing the limit in discard mode must not leak even the headers that
    were accumulated before the limit was crossed.
    """
    headers = [(':method', 'GET'), (':path', '/')] + [
        (f'x-padded-{i}', 'p' * 40) for i in range(30)
    ]
    data = _encode(headers)
    d = Decoder(max_header_list_size=64)

    result = d.decode(data, mode=DecodeMode.DISCARD)

    assert isinstance(result, DiscardedHeaderList)
    assert result.discarded is True
    assert result.oversized is True
    assert result.connection_usable is True
    assert result.fatal is False
    assert len(result) == 0
    assert list(result) == []
    assert result[:] == []
    assert result.headers == ()
    assert d.decode_discard(data) == result


def test_discarded_result_does_not_retain_decoded_headers():
    """
    A discarded result must not keep references to any business header, even
    when the limit is only crossed late in the block.
    """
    headers = [('x-early', 'visible-before-limit')] + [
        (f'x-late-{i}', f'secret-{i}' * 8) for i in range(100)
    ]
    data = _encode(headers)
    d = Decoder(max_header_list_size=60)

    result = d.decode_discard(data)

    assert isinstance(result, DiscardedHeaderList)
    for header in headers:
        assert header[0] not in result.__repr__()
        assert header[1] not in result.__repr__()
    stats = result.stats
    # Only the bounded prefix accumulated before the limit was crossed may be
    # reflected in the peak; nothing from the discarded tail is retained.
    assert stats.peak_retained_header_bytes <= d.max_header_list_size + 64
    assert stats.peak_retained_headers * 64 <= d.max_header_list_size + 64


def test_discarded_block_applies_trailing_table_update_and_next_block_references_it():
    """
    The acceptance scenario: a discarded block adds a dynamic table entry at
    the very end. A following block may reference it, and decoding must match
    a normal reference decoder that saw both blocks without a limit.
    """
    new_entry = ('x-tail-entry', 'tail-value')

    # Build a block with many headers, then append an incremental-indexed
    # literal at the end. That entries lands at dynamic index 1 (index 62).
    enc = Encoder()
    filler = [(f'x-filler-{i}', 'f' * 20) for i in range(40)]
    block = enc.encode(filler + [new_entry], huffman=False)
    follow_up = b'\xbe'  # 0xBE == indexed field, index 62.

    assert enc.header_table.get_by_index(62) == (b'x-tail-entry', b'tail-value')

    reference = _reference_decoder()
    expected_first = reference.decode(block)
    expected_second = reference.decode(follow_up)
    assert expected_second == [new_entry]

    discarding = Decoder(max_header_list_size=64)
    first = discarding.decode_discard(block)
    assert isinstance(first, DiscardedHeaderList)
    assert discarding.decode(follow_up, raw=True) == [
        (b'x-tail-entry', b'tail-value')
    ]

    assert list(discarding.header_table.dynamic_entries) == list(
        reference.header_table.dynamic_entries
    )
    assert discarding.header_table.current_size == reference.header_table.current_size
    assert discarding.connection_usable is True

    # The discarded block never surfaces any business headers, even though
    # the same bytes produce a full list in the reference decoder.
    assert len(expected_first) == 41
    assert len(first) == 0


def test_discard_mode_validates_suffix_and_rejects_corruption():
    """
    Corruption after the point where the limit was crossed is still fatal: the
    dynamic table may have been partially updated, so no result is returned.
    """
    headers = [('x-filler', 'f' * 100), (':method', 'GET')]
    good = _encode(headers, huffman=False)

    # Same prefix, but the trailing literal claims a value longer than the
    # remaining bytes.
    corrupt = good + b'\x40\x03bad\x7f'

    d = Decoder(max_header_list_size=32)
    with pytest.raises(HPACKDecodingError):
        d.decode_discard(corrupt)
    assert d.connection_usable is False
    assert d.last_decode_stats is None

    reference = _reference_decoder()
    with pytest.raises(HPACKDecodingError):
        reference.decode(corrupt)


def test_discard_mode_rejects_invalid_dynamic_index():
    """
    A dynamic index that does not exist is a compression error, not a stream
    level rejection, and must not be recovered from.
    """
    headers = [('x-filler', 'f' * 100)]
    data = _encode(headers) + b'\xbf\xff\xff'  # bogus index
    d = Decoder(max_header_list_size=16)

    with pytest.raises(InvalidTableIndex):
        d.decode_discard(data)
    assert d.connection_usable is False


def test_discard_mode_rejects_invalid_table_size():
    """
    A table size update above the allowed maximum stays fatal even in discard
    mode.
    """
    headers = [('x-filler', 'f' * 100)]
    data = _encode(headers)
    d = Decoder(max_header_list_size=16)
    d.max_allowed_table_size = 128
    d.header_table_size = 256  # local state inconsistent with the peer

    with pytest.raises(InvalidTableSizeError):
        d.decode_discard(data)
    assert d.connection_usable is False


def test_discard_mode_rejects_table_update_above_maximum():
    d = Decoder(max_header_list_size=8)
    d.max_allowed_table_size = 127

    with pytest.raises(InvalidTableSizeError):
        d.decode_discard(b'?a\x82')

    assert d.connection_usable is False


def test_work_budget_error_alias_is_compatible():
    assert issubclass(DecodeWorkBudgetExceeded, DecodeWorkBudgetExceededError)
    assert issubclass(DecodeWorkBudgetExceededError, HPACKDecodingError)


def test_work_budget_exhaustion_is_fatal_even_when_discarding():
    """
    The work budget is about validation cost, not the retained header list, so
    it applies in both modes and always invalidates the connection.
    """
    data = _encode([(':method', 'GET'), (':path', '/')])
    d = Decoder(max_header_list_size=8)
    d.max_decode_work = 1

    with pytest.raises(DecodeWorkBudgetExceededError):
        d.decode_discard(data)
    assert d.connection_usable is False
    assert d.last_decode_stats is None


def test_work_budget_can_allow_a_full_block():
    data = _encode([(':method', 'GET'), (':path', '/')])
    d = Decoder()
    d.max_decode_work = 2

    assert d.decode(data) == [(':method', 'GET'), (':path', '/')]
    assert d.connection_usable is True


def test_discard_mode_with_huffman_matches_reference():
    headers = [(':method', 'GET'), (':scheme', 'https')] + [
        (f'x-huff-{i}', 'value-' * 4) for i in range(20)
    ]
    data = _encode(headers, huffman=True)

    reference = _reference_decoder()
    assert reference.decode(data) == headers

    d = Decoder(max_header_list_size=32)
    result = d.decode_discard(data)
    assert isinstance(result, DiscardedHeaderList)
    assert list(d.header_table.dynamic_entries) == list(
        reference.header_table.dynamic_entries
    )


def test_discard_mode_does_not_affect_static_only_blocks():
    data = _encode([(':method', 'GET'), (':path', '/')])

    d = Decoder(max_header_list_size=10 ** 6)
    assert d.decode(data, mode=DecodeMode.DISCARD) == [
        (':method', 'GET'),
        (':path', '/'),
    ]
    assert d.connection_usable is True
    assert isinstance(d.last_decode_stats, DecodeStats)


def test_discard_returns_stats_with_bounded_dynamic_table():
    headers = [(f'x-stat-{i}', 's' * 40) for i in range(80)]
    data = _encode(headers)
    d = Decoder(max_header_list_size=32)
    d.header_table.maxsize = 512

    result = d.decode_discard(data)
    stats = d.last_decode_stats

    assert isinstance(result, DiscardedHeaderList)
    assert stats.header_count == 80
    assert stats.peak_retained_header_bytes <= d.max_header_list_size + 72
    assert stats.peak_dynamic_table_size <= 512
    assert result.stats.as_dict() == stats.as_dict()


@pytest.mark.parametrize('huffman', [False, True])
def test_peak_retained_memory_is_bounded_by_limit_not_header_count(huffman):
    """
    Regression guard for the stated acceptance property: peak retained
    header memory in discard mode depends on the application limit, not on how
    many headers the discarded block contains.
    """
    def block(filler_count: int) -> bytes:
        return _encode(
            [(':method', 'GET'), (':path', '/')]
            + [(f'x-fill-{i}', 'z' * 30) for i in range(filler_count)],
            huffman=huffman,
        )

    limit = 256
    small = Decoder(max_header_list_size=limit)
    large = Decoder(max_header_list_size=limit)

    small_result = small.decode_discard(block(10))
    large_result = large.decode_discard(block(400))

    assert isinstance(small_result, DiscardedHeaderList)
    assert isinstance(large_result, DiscardedHeaderList)

    small_stats = small.last_decode_stats
    large_stats = large.last_decode_stats

    # The peak retained memory is governed by the limit, and here the prefix
    # before the limit is identical, so the peak is identical despite the
    # 40x difference in discarded header count.
    assert small_stats.peak_retained_headers == large_stats.peak_retained_headers
    assert small_stats.peak_retained_header_bytes == large_stats.peak_retained_header_bytes
    assert large_stats.peak_retained_header_bytes <= limit + 64

    # Both validate the whole block and both end with the same HPACK table
    # state as a reference decoder that never discards.
    reference = _reference_decoder()
    reference.decode(block(10))
    reference.decode(block(400))
    assert list(large.header_table.dynamic_entries) == list(
        reference.header_table.dynamic_entries
    )
    assert large_stats.header_count == 402


def test_peak_retained_memory_does_not_grow_with_discarded_headers_tracemalloc():
    """
    Independent check using tracemalloc: decoding a much larger discarded block
    must not allocate proportionally more memory while validating it.
    """
    def measure(data: bytes) -> int:
        d = Decoder(max_header_list_size=128)
        tracemalloc.start()
        try:
            d.decode_discard(data)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        return peak

    # Pre-build both blocks so allocation during compression does not distort
    # the measurement, then warm up the measurement itself.
    small_data = _encode([(f'x-mem-{i}', 'm' * 30) for i in range(50)])
    large_data = _encode([(f'x-mem-{i}', 'm' * 30) for i in range(2000)])

    measure(small_data)
    small_peak = measure(small_data)
    large_peak = measure(large_data)

    # Literal decoding no longer copies the remaining block for every field, so
    # tracked memory during validation is dominated by one field and the
    # dynamic table, not by the number of discarded headers.
    assert large_peak < small_peak * 8, (small_peak, large_peak)


def test_memoryview_literal_decoding_still_handles_truncation():
    d = Decoder()
    # Name length says 5, only three bytes are present.
    data = b'\x00\x85\xf2\xb2J'
    with pytest.raises(HPACKDecodingError):
        d.decode(data)


def test_table_size_update_after_headers_is_fatal_in_discard_mode():
    """
    A context update in the middle of a block is a syntax error, so discard
    mode must not swallow it even though the header list is being rejected
    anyway.
    """
    data = _encode([('x-filler', 'f' * 100)]) + b'\x3f\xe1\x1f'
    d = Decoder(max_header_list_size=16)

    with pytest.raises(HPACKDecodingError):
        d.decode_discard(data)
    assert d.connection_usable is False


def test_table_size_update_after_oversize_is_still_rejected():
    headers = [('x-filler', 'f' * 100), (':method', 'GET')]
    data = _encode(headers) + b'\x3f\xe1\x1f'
    d = Decoder(max_header_list_size=16)

    with pytest.raises(HPACKDecodingError):
        d.decode_discard(data)
    assert d.connection_usable is False


def test_leading_table_size_update_in_discard_mode_is_accepted():
    headers = [('x-filler', 'f' * 100)]
    data = b'\x3f\x42' + _encode(headers)  # size update to 97, then fields
    d = Decoder(max_header_list_size=16)
    result = d.decode_discard(data)

    assert isinstance(result, DiscardedHeaderList)
    assert d.last_decode_stats.table_update_count == 1
    assert d.header_table_size == 97
    assert d.connection_usable is True


def test_invalid_utf8_in_discarded_suffix_is_fatal():
    """
    Invalid UTF-8 after the limit is corrupt input, not an application
    rejection, and must not be masked by discard mode.
    """
    data = _encode([('x-filler', 'f' * 100)]) + b'\x00\x01x\x01\xff'
    d = Decoder(max_header_list_size=16)

    with pytest.raises(HPACKDecodingError):
        d.decode_discard(data)
    assert d.connection_usable is False

    # With raw=True there is no UTF-8 contract to enforce, so the same bytes
    # are a valid, discarded block.
    d = Decoder(max_header_list_size=16)
    result = d.decode_discard(data, raw=True)
    assert isinstance(result, DiscardedHeaderList)
    assert d.connection_usable is True


def test_invalid_utf8_on_the_header_that_crosses_the_limit_is_fatal():
    """The field that first exceeds the limit is still validated."""
    enc = Encoder()
    prefix = enc.encode([('x-small', 'v')], huffman=False)
    bad = b'\x00\x01x\x01\xff'
    d = Decoder(max_header_list_size=8)

    with pytest.raises(HPACKDecodingError):
        d.decode_discard(prefix + bad)
    assert d.connection_usable is False


def test_invalid_utf8_before_limit_is_fatal_in_discard_mode():
    data = b'\x00\x01x\x01\xff'
    d = Decoder(max_header_list_size=10 ** 6)

    with pytest.raises(HPACKDecodingError):
        d.decode_discard(data)
    assert d.connection_usable is False


FIXTURE_ROOT = Path(__file__).parent / "test_fixtures"


def _fixture_blocks() -> list[bytes]:
    """A small, deterministic sample of real-world HPACK blocks."""
    blocks = []
    for story in ("go-hpack/story_00.json", "nghttp2/story_01.json"):
        path = FIXTURE_ROOT / story
        if not path.exists():  # large integration fixtures are not in sdist
            continue
        for case in json.loads(path.read_text())["cases"]:
            blocks.append(bytes.fromhex(case["wire"]))
    return blocks


def test_real_fixture_blocks_match_unlimited_reference():
    """
    For every sampled real block, discard mode either returns the exact same
    headers as an unlimited reference decoder or reports an oversized result,
    and in both cases the dynamic table ends in the same state.
    """
    blocks = _fixture_blocks()
    if not blocks:
        pytest.skip("integration fixtures are not available")

    reference = Decoder(max_header_list_size=2 ** 30)
    discarding = Decoder(max_header_list_size=128)
    discarded = 0

    for block in blocks:
        expected = reference.decode(block, raw=True)
        result = discarding.decode_discard(block, raw=True)

        if isinstance(result, DiscardedHeaderList):
            discarded += 1
            assert len(result) == 0
        else:
            assert result == expected
            assert list(discarding.header_table.dynamic_entries) == list(
                reference.header_table.dynamic_entries
            )
            assert discarding.header_table.current_size == reference.header_table.current_size

    assert discarded > 0, "sample should exercise at least one discarded block"


def test_real_fixture_discarded_block_keeps_state_for_next_block():
    """
    Discard a real block, then let the next real block rely on the dynamic
    table it built, comparing against the unlimited reference.
    """
    blocks = _fixture_blocks()
    if len(blocks) < 2:
        pytest.skip("integration fixtures are not available")

    reference = Decoder(max_header_list_size=2 ** 30)
    discarding = Decoder(max_header_list_size=128)

    first = discarding.decode_discard(blocks[0], raw=True)
    expected_second = reference.decode(blocks[1], raw=True)
    second = discarding.decode_discard(blocks[1], raw=True)

    assert isinstance(first, DiscardedHeaderList)
    if isinstance(second, DiscardedHeaderList):
        # The follow-up block also exceeded the tiny sample limit; its table
        # effects must still match the reference exactly.
        assert len(second) == 0
    else:
        assert second == expected_second
    assert list(discarding.header_table.dynamic_entries) == list(
        reference.header_table.dynamic_entries
    )
    assert discarding.header_table.current_size == reference.header_table.current_size


def test_work_budget_counts_table_updates_too():
    """
    Context updates also consume work, so a block made only of tiny updates
    cannot bypass the budget.
    """
    data = b'\x20' * 5  # five table size updates to zero
    d = Decoder(max_decode_work=3)

    with pytest.raises(DecodeWorkBudgetExceededError):
        d.decode(data)
    assert d.connection_usable is False


def test_large_discarded_block_completes_quickly():
    """
    Guard against reintroducing per-field copies of the remaining block: the
    old literal decoder did O(n^2) byte copying on long blocks.
    """
    data = _encode([(f'x-time-{i}', 't' * 20) for i in range(4000)])
    d = Decoder(max_header_list_size=128)
    started = time.perf_counter()
    result = d.decode_discard(data)
    elapsed = time.perf_counter() - started

    assert isinstance(result, DiscardedHeaderList)
    assert elapsed < 2.0, elapsed


def test_invalid_mode_value_is_rejected():
    d = Decoder()
    with pytest.raises(ValueError):
        d.decode(b'\x82', mode='lenient')
    assert d.decode(b'\x82', mode='strict') == [(':method', 'GET')]
    assert d.decode(b'\x82', mode=DecodeMode.STRICT) == [(':method', 'GET')]
