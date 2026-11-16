# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Tests for the run-based segmented translation layers.

These use a small two-layer synthetic address space: a sparse data layer at the
bottom and a segmented layer on top.  They focus on the contract that
``is_valid`` must agree with a real ``read``: a segment whose first mapped byte
exists but whose remaining mapped range is missing in the base layer must not be
reported as fully readable.
"""

from typing import Any, Dict, List, Optional, Tuple

import pytest

from volatility3.framework import contexts, exceptions, interfaces
from volatility3.framework.layers import segmented


class SparseDataLayer(interfaces.layers.DataLayerInterface):
    """A data layer whose readable ranges are explicit, possibly sparse blocks."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        blocks: Dict[int, bytes],
        size: int,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )
        self._blocks = dict(blocks)
        self._size = size

    @property
    def maximum_address(self) -> int:
        return self._size - 1

    @property
    def minimum_address(self) -> int:
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if length <= 0:
            raise ValueError("Length must be positive")
        end = offset + length - 1
        if offset < 0 or end >= self._size:
            return False
        for start, data in self._blocks.items():
            if start <= offset and end < start + len(data):
                return True
        return False

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        for start, data in self._blocks.items():
            if start <= offset and offset + length <= start + len(data):
                relative = offset - start
                return data[relative : relative + length]
        raise exceptions.InvalidAddressException(
            self.name, offset, "Read from a sparse hole"
        )

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError


class LinearSegmentedLayer(segmented.SegmentedLayer):
    """A linearly mapped segmented layer fed with test-provided segments."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        segments: List[Tuple[int, int, int, int]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._test_segments = segments
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

    def _load_segments(self) -> None:
        self._segments = list(self._test_segments)


class NonLinearSegmentedLayer(segmented.NonLinearlySegmentedLayer):
    """A non-linearly mapped layer emulating single-byte compressed blocks."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        segments: List[Tuple[int, int, int, int]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._test_segments = segments
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

    def _load_segments(self) -> None:
        self._segments = list(self._test_segments)

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        # A single physical byte expands to fill the logical block, mirroring
        # the compressed-page handling in formats such as QEMU suspend files.
        return data * output_length


def build_context(
    segments: List[Tuple[int, int, int, int]],
    blocks: Dict[int, bytes],
    size: int = 256,
) -> contexts.Context:
    context = contexts.Context()
    context.config["base_layer"] = "memory"
    context.layers.add_layer(
        SparseDataLayer(context, "base_layer", "memory", blocks, size)
    )
    context.config["segmented.base_layer"] = "memory"
    return context


def make_linear_layer(segments, blocks, size=256):
    context = build_context(segments, blocks, size)
    return LinearSegmentedLayer(context, "segmented", "segmented", segments)


def make_non_linear_layer(segments, blocks, size=256):
    context = build_context(segments, blocks, size)
    return NonLinearSegmentedLayer(context, "segmented", "segmented", segments)


def test_is_valid_matches_read_when_base_range_is_missing() -> None:
    """A segment starting on a valid byte but missing later bytes must fail.

    The logical segment covers [0, 16) mapped 1:1 onto the base layer, but the
    base layer only backs the first eight physical bytes.
    """
    layer = make_linear_layer([(0, 0, 16, 16)], {0: bytes(range(8))})

    assert layer.is_valid(0, 1)
    assert layer.read(0, 1) == b"\x00"

    # The whole segment must not be treated as readable when half is missing.
    assert not layer.is_valid(0, 16)
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(0, 16)

    # A request that crosses into the missing half is invalid as well.
    assert not layer.is_valid(4, 8)
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(4, 8)

    # The first address inside the hole was already correctly rejected.
    assert not layer.is_valid(8, 1)
    with pytest.raises(exceptions.InvalidAddressException) as exc_info:
        layer.read(8, 1)
    assert exc_info.value.invalid_address == 8


def test_compressed_segment_uses_mapped_length_not_logical_length() -> None:
    """A 16-byte logical block backed by one physical byte stays valid.

    The logical length (16) must never be checked against the physical backing
    store; only the mapped length (1) describes the base-layer range.
    """
    segment = (0, 0, 16, 1)
    layer = make_non_linear_layer([segment], {0: b"\xaa"})

    assert list(layer.mapping(0, 16)) == [(0, 16, 0, 1, "memory")]
    assert layer.is_valid(0, 16)
    assert layer.read(0, 16) == b"\xaa" * 16

    # Removing the single backing byte must flip validity without touching the
    # logical length used above.
    broken = make_non_linear_layer([segment], {})
    assert not broken.is_valid(0, 16)
    with pytest.raises(exceptions.InvalidAddressException):
        broken.read(0, 16)


def test_segmentation_boundary_does_not_change_validity_or_data() -> None:
    """Splitting one fully backed range into adjacent segments gives same data."""
    blocks = {0: bytes(range(16))}
    split = make_linear_layer([(0, 0, 8, 8), (8, 8, 8, 8)], blocks)
    whole = make_linear_layer([(0, 0, 16, 16)], blocks)

    assert split.is_valid(0, 16) == whole.is_valid(0, 16)
    assert split.read(0, 16) == whole.read(0, 16) == bytes(range(16))

    # Cross-segment reads remain readable when every backing byte exists.
    assert split.is_valid(4, 8)
    assert split.read(4, 8) == bytes(range(4, 12))


def test_normal_read_raises_while_pad_fills_only_segment_gaps() -> None:
    """Normal reads surface base-layer holes; pad only null-fills mapping gaps.

    ``ignore_errors`` (driven by ``pad``) skips logical addresses that no
    segment maps; it does not paper over holes inside a mapped base-layer range.
    """
    layer = make_linear_layer([(0, 0, 16, 16)], {0: bytes(range(8))})

    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(0, 16)
    with pytest.raises(exceptions.InvalidAddressException):
        # The physical hole [8, 16) is inside a mapped segment, so padding does
        # not suppress the base-layer fault.
        layer.read(0, 16, pad=True)


def test_ignore_errors_skips_only_unmapped_logical_gaps() -> None:
    """ignore_errors returns available maps and omits addresses no segment covers."""
    segments = [(0, 0, 8, 8), (16, 32, 8, 8)]
    blocks = {0: bytes(range(8)), 32: bytes(range(8))}
    layer = make_linear_layer(segments, blocks)

    # Without ignore_errors the unmapped logical gap [8, 16) raises.
    with pytest.raises(exceptions.InvalidAddressException) as exc_info:
        list(layer.mapping(0, 24))
    assert exc_info.value.invalid_address == 8

    # With ignore_errors the gap is skipped; only mapped chunks are returned.
    mappings = list(layer.mapping(0, 24, ignore_errors=True))
    assert mappings == [
        (0, 8, 0, 8, "memory"),
        (16, 8, 32, 8, "memory"),
    ]

    # Addresses backed by both segments remain valid; a request spanning the
    # gap is not wholly valid because the gap itself cannot be translated.
    assert layer.is_valid(0, 8)
    assert layer.is_valid(16, 8)
    assert not layer.is_valid(0, 24)


def test_is_valid_false_when_request_falls_outside_all_segments() -> None:
    """Addresses beyond every segment are invalid rather than silently valid."""
    layer = make_linear_layer([(0, 0, 8, 8)], {0: bytes(range(8))})

    assert not layer.is_valid(8, 1)
    assert not layer.is_valid(4, 8)
    with pytest.raises(exceptions.InvalidAddressException):
        layer.read(8, 1)
