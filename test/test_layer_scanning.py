"""Chunked-scanning contract tests.

These tests pin down the contract between the layer scanning machinery and the
scanner implementations:

* a match straddling a chunk boundary is still reported, provided the scanner's
  ``overlap`` is at least as long as the rule;
* a match entirely inside the overlap is reported exactly once, never once per
  adjacent chunk, and this does not depend on ``chunk_size``;
* bytes on either side of a missing physical range are never concatenated, so a
  rule cannot be stitched together across a hole;
* every result keeps its logical offset and can be paired with the data layer
  that actually supplied the matching bytes;
* serial and parallel (threaded) scans return the same set of results;
* the overlap cache genuinely reduces the number of bytes read, demonstrated
  with a small counting layer rather than a large memory image.
"""

from typing import List, Optional, Tuple

import pytest

from volatility3.framework import constants, contexts, interfaces
from volatility3.framework.layers import linear, physical
from volatility3.framework.layers.scanners import (
    BytesScanner,
    MultiStringScanner,
    RegExScanner,
)


class SegmentedLayer(linear.LinearlyMappedLayer):
    """A linear translation layer with explicit readable ranges and holes.

    ``layout`` maps logical ranges onto a single backing data layer.  Anything
    between two ranges is a missing physical range: it is absent from
    :meth:`mapping` and therefore must never be joined into a scan chunk.
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        backing_name: str,
        layout: List[Tuple[int, int, int]],
        metadata: Optional[dict] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )
        self._backing_name = backing_name
        # Each entry is (logical_start, logical_end, backing_start).
        self._layout = layout

    @property
    def name(self) -> str:
        return self._name

    @property
    def minimum_address(self) -> int:
        return self._layout[0][0]

    @property
    def maximum_address(self) -> int:
        return self._layout[-1][1] - 1

    @property
    def dependencies(self) -> List[str]:
        return [self._backing_name]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return any(
            start <= offset and offset + length <= end
            for start, end, _ in self._layout
        )

    def mapping(self, offset: int, length: int, ignore_errors: bool = False):
        requested_end = offset + length
        for start, end, backing_start in self._layout:
            low = max(start, offset)
            high = min(end, requested_end)
            if low < high:
                yield (
                    low,
                    high - low,
                    backing_start + (low - start),
                    high - low,
                    self._backing_name,
                )

    def write(self, offset: int, value: bytes) -> None:
        raise NotImplementedError("SegmentedLayer is read-only")

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return []


class NonLinearSegmentedLayer(SegmentedLayer):
    """A segmented layer that scans through itself rather than the backing layer.

    This exercises the ``linear=False`` branch of the translation iterator, in
    which a chunk's segments name the scanned layer (because data must be decoded
    through it) instead of the underlying data layer.
    """

    def _scan_iterator(self, scanner, sections, linear: bool = False):
        return super()._scan_iterator(scanner, sections, linear=False)


def occurrences(haystack: bytes, needle: bytes) -> List[int]:
    return sorted(i for i in range(len(haystack)) if haystack.startswith(needle, i))


def make_buffer_layer(data: bytes, name: str = "memory"):
    context = contexts.Context()
    layer = physical.BufferDataLayer(context, f"{name}_config", name, data)
    context.add_layer(layer)
    return context, layer


def make_segmented(backing: bytes, layout, name: str = "segmented"):
    context = contexts.Context()
    backing_name = "backing"
    context.add_layer(
        physical.BufferDataLayer(context, "backing_config", backing_name, backing)
    )
    layer = SegmentedLayer(
        context, f"{name}_config", name, backing_name, layout
    )
    context.add_layer(layer)
    return context, layer


def configured(scanner, chunk_size: int, overlap: int):
    scanner.chunk_size = chunk_size
    scanner.overlap = overlap
    return scanner


# ---------------------------------------------------------------------------
# Chunk boundary / overlap de-duplication
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scanner_cls", [BytesScanner, RegExScanner, MultiStringScanner]
)
@pytest.mark.parametrize("chunk_size,overlap", [(7, 2), (8, 4), (13, 6), (31, 4)])
def test_results_independent_of_chunk_size(scanner_cls, chunk_size, overlap):
    needle = b"AB"
    data = (b"0123456789" + needle + b"X" * 40) * 3
    pattern = [needle] if scanner_cls is MultiStringScanner else needle
    context, layer = make_buffer_layer(data)
    scanner = configured(scanner_cls(pattern), chunk_size, overlap)

    results = list(layer.scan(context, scanner))
    offsets = sorted(r[0] if isinstance(r, tuple) else r for r in results)

    assert offsets == occurrences(data, needle)


def test_match_straddling_chunk_boundary_is_found():
    # The 6-byte rule crosses the boundary at offset 10; overlap (8) covers it.
    needle = b"NEEDLE"
    data = b"0123456789" + needle + b"Z" * 40
    context, layer = make_buffer_layer(data)
    scanner = configured(BytesScanner(needle), 10, 8)

    assert sorted(layer.scan(context, scanner)) == occurrences(data, needle)


def test_match_fully_inside_overlap_reported_once():
    # 'GHIJKL' starts at offset 6, inside the [10, 18) overlap of a cs=10 scan.
    needle = b"GHIJKL"
    data = b"ABCDEFGHIJKLMNOP" + b"R" * 40
    context, layer = make_buffer_layer(data)
    scanner = configured(BytesScanner(needle), 10, 8)

    hits = sorted(layer.scan(context, scanner))
    assert hits == occurrences(data, needle)
    assert len(hits) == 1


def test_changing_chunk_size_keeps_result_set_identical():
    needle = b"NDL3"
    data = (b"AA" + needle + b"Q" * 30) * 5
    baseline = None
    for chunk_size, overlap in [(8, 4), (11, 6), (17, 4), (64, 8)]:
        context, layer = make_buffer_layer(data)
        scanner = configured(BytesScanner(needle), chunk_size, overlap)
        current = sorted(layer.scan(context, scanner))
        if baseline is None:
            baseline = current
        else:
            assert current == baseline
    assert baseline == occurrences(data, needle)


def test_overlap_must_be_smaller_than_chunk_size():
    context, layer = make_buffer_layer(b"whatever")
    scanner = configured(BytesScanner(b"ab"), 4, 4)
    with pytest.raises(ValueError):
        list(layer.scan(context, scanner))


def test_chunk_size_must_be_positive():
    context, layer = make_buffer_layer(b"whatever")
    scanner = configured(BytesScanner(b"ab"), 0, 0)
    with pytest.raises(ValueError):
        list(layer.scan(context, scanner))


# ---------------------------------------------------------------------------
# Holes: identical bytes on both sides, no stitching across the hole
# ---------------------------------------------------------------------------


def test_identical_bytes_on_both_sides_of_hole_both_reported():
    needle = b"needle"
    # Two readable regions, each holding the same needle, separated by a hole.
    region_a = b"X" * 10 + needle + b"Y" * 20
    region_b = b"Z" * 10 + needle + b"W" * 20
    backing = region_a + region_b
    layout = [
        (0, len(region_a), 0),
        (len(region_a) + 0x100, len(region_a) + 0x100 + len(region_b), len(region_a)),
    ]
    context, layer = make_segmented(backing, layout)
    scanner = configured(BytesScanner(needle), 16, 8)

    hits = sorted(layer.scan(context, scanner))
    logical_b = len(region_a) + 0x100 + 10
    assert hits == [10, logical_b]


def test_rule_is_not_stitched_across_a_hole():
    # 'nee' ends the first region, 'dle' starts the second.  Only the hole
    # separates them, so 'needle' must never match.
    first = bytearray(b"K" * 40)
    first[-3:] = b"nee"
    second = bytearray(b"M" * 40)
    second[:3] = b"dle"
    backing = bytes(first) + bytes(second)
    layout = [(0, 40, 0), (0x100, 0x100 + 40, 40)]
    context, layer = make_segmented(backing, layout)
    scanner = configured(BytesScanner(b"needle"), 16, 8)

    assert list(layer.scan(context, scanner)) == []


def test_hole_ends_a_chunk_in_scan_iterator():
    layout = [(0, 40, 0), (0x100, 0x100 + 40, 40)]
    context, layer = make_segmented(b"Q" * 80, layout)
    scanner = configured(BytesScanner(b"Q"), 16, 8)

    chunks = list(layer._scan_iterator(scanner, [(0, 0x100 + 40)]))
    # No chunk may span the hole: each chunk's logical extent stays inside one
    # readable region.
    for segments, logical_start in chunks:
        assert logical_start < 40 or logical_start >= 0x100
        for _layer_name, _address, length in segments:
            assert logical_start + length <= 40 or logical_start >= 0x100


def test_multiple_holes_keep_each_readable_region_independent():
    # Three regions separated by holes, each holding the same needle once.  Each
    # region reports its own match and nothing is ever joined across a hole.
    needle = b"needle"
    regions = [needle + b"P" * 10, needle + b"Q" * 10, needle + b"R" * 10]
    backing = b"".join(regions)
    layout = [
        (0x100, 0x100 + 16, 0),
        (0x200, 0x200 + 16, 16),
        (0x300, 0x300 + 16, 32),
    ]
    context = contexts.Context()
    context.add_layer(
        physical.BufferDataLayer(context, "backing_config", "backing", backing)
    )
    layer = SegmentedLayer(context, "seg_config", "segmented", "backing", layout)
    context.add_layer(layer)
    scanner = configured(BytesScanner(needle), 16, 8)

    assert sorted(layer.scan(context, scanner, sections=[(0, 0x310)])) == [
        0x100,
        0x200,
        0x300,
    ]


# ---------------------------------------------------------------------------
# Logical offset + the layer that actually matched
# ---------------------------------------------------------------------------


def test_locate_results_pairs_offset_with_backing_layer():
    needle = b"needle"
    region_a = b"X" * 10 + needle + b"Y" * 20
    region_b = b"Z" * 10 + needle + b"W" * 20
    backing = region_a + region_b
    layout = [(0, len(region_a), 0), (0x80, 0x80 + len(region_b), len(region_a))]
    context, layer = make_segmented(backing, layout)
    scanner = configured(BytesScanner(needle), 16, 8)

    located = list(layer.scan(context, scanner, locate_results=True))
    assert len(located) == 2
    for result, location in located:
        assert result == location.offset
        assert location.layer_name == "backing"
    assert [loc.offset for _res, loc in located] == [10, 0x80 + 10]


def test_locate_results_non_linear_names_scanned_layer():
    needle = b"needle"
    region_a = b"X" * 10 + needle + b"Y" * 20
    backing = region_a
    layout = [(0, len(region_a), 0)]
    context = contexts.Context()
    context.add_layer(
        physical.BufferDataLayer(context, "backing_config", "backing", backing)
    )
    layer = NonLinearSegmentedLayer(
        context, "nonlinear_config", "nonlinear", "backing", layout
    )
    context.add_layer(layer)
    scanner = configured(BytesScanner(needle), 16, 8)

    located = list(layer.scan(context, scanner, locate_results=True))
    # In the non-linear path the data is read *through* the scanned layer, so the
    # participating layer is the scanned layer rather than its backing layer.
    assert [(res, loc.offset, loc.layer_name) for res, loc in located] == [
        (10, 10, "nonlinear")
    ]


def test_plain_scan_keeps_scanner_result_shape():
    # locate_results defaults to False, so existing consumers see bare offsets.
    # An explicit full-length section keeps the test independent of the layer's
    # inclusive maximum_address convention.
    section = [(0, len(b"xxABxxAB"))]
    context, layer = make_buffer_layer(b"xxABxxAB")
    scanner = configured(BytesScanner(b"AB"), 4, 2)
    assert sorted(layer.scan(context, scanner, sections=section)) == [2, 6]

    context, layer = make_buffer_layer(b"xxABxxAB")
    multi = configured(MultiStringScanner([b"AB"]), 4, 2)
    assert sorted(layer.scan(context, multi, sections=section)) == [
        (2, b"AB"),
        (6, b"AB"),
    ]


# ---------------------------------------------------------------------------
# Serial vs parallel equivalence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scanner_cls", [BytesScanner, RegExScanner, MultiStringScanner]
)
def test_serial_and_threaded_scans_match(monkeypatch, scanner_cls):
    needle = b"AB"
    data = (b"0123456789" + needle + b"X" * 40) * 4
    pattern = [needle] if scanner_cls is MultiStringScanner else needle

    def run(mode):
        context, layer = make_buffer_layer(data)
        scanner = configured(scanner_cls(pattern), 11, 4)
        monkeypatch.setattr(constants, "PARALLELISM", mode)
        results = list(layer.scan(context, scanner))
        return sorted(r[0] if isinstance(r, tuple) else r for r in results)

    expected = occurrences(data, needle)
    assert run(constants.Parallelism.Off) == expected
    assert run(constants.Parallelism.Threading) == expected


# ---------------------------------------------------------------------------
# Read-volume accounting via the counting layer
# ---------------------------------------------------------------------------


def test_overlap_cache_reduces_bytes_read():
    needle = b"needle"
    region_a = b"X" * 10 + needle + b"Y" * 20
    region_b = b"Z" * 10 + needle + b"W" * 20
    backing = region_a + region_b
    layout = [(0, len(region_a), 0), (0x80, 0x80 + len(region_b), len(region_a))]
    full_section = [(layout[0][0], layout[-1][1] - layout[0][0])]

    def build(suffix: str):
        context = contexts.Context()
        backing_name = f"backing_{suffix}"
        backing_layer = physical.CountingBufferDataLayer(
            context, f"backing_cfg_{suffix}", backing_name, backing
        )
        context.add_layer(backing_layer)
        layer = SegmentedLayer(
            context,
            f"seg_cfg_{suffix}",
            f"segmented_{suffix}",
            backing_name,
            layout,
        )
        # The inherited linear read() is memoized on self; start from a clean
        # cache so the byte counters measure the overlap cache alone.
        layer.read.cache_clear()
        context.add_layer(layer)
        return context, layer, backing_layer

    # Cached (default serial) scan.
    context, layer, cached_backing = build("cached")
    scanner = configured(BytesScanner(needle), 16, 8)
    cached_hits = sorted(layer.scan(context, scanner, sections=full_section))
    cached_bytes = cached_backing.bytes_read

    # Uncached scan: distinct layer names keep the two runs independent of the
    # per-instance read() memoization, leaving use_overlap_cache as the only
    # difference.  It produces identical results while reading every chunk.
    context, layer, uncached_backing = build("uncached")
    scanner = configured(BytesScanner(needle), 16, 8)
    uncached_hits = sorted(
        layer.scan(
            context,
            scanner,
            sections=full_section,
            use_overlap_cache=False,
        )
    )
    uncached_bytes = uncached_backing.bytes_read

    assert cached_hits == uncached_hits
    assert cached_bytes < uncached_bytes


def test_counting_layer_records_read_volume():
    context = contexts.Context()
    layer = physical.CountingBufferDataLayer(context, "cfg", "counting", b"abcdefgh")
    context.add_layer(layer)
    assert layer.bytes_read == 0 and layer.read_calls == 0
    layer.read(0, 3)
    layer.read(3, 2)
    assert layer.read_calls == 2 and layer.bytes_read == 5
