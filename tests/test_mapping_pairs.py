"""Model-based tests for NTFS mapping pairs.

The expected runs and expected on-disk bytes in this module are produced by the small, independent integer
model in ``encode_mapping_pairs``/``model_disk_bytes`` below. They are never derived from
``AttributeHeader.dataruns``. The product code is only used to produce the actual result under test.

Every test case starts from a reachable, non-resident ``$DATA`` attribute in a synthetic ``$MFT`` record that is
opened through :class:`dissect.ntfs.ntfs.NTFS`, after which both the decoded runs and the actual cross-run reads
from the synthetic volume are compared against the model.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import BinaryIO

import pytest
from dissect.util.stream import RunlistStream

from dissect.ntfs.attr import Attribute
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, c_ntfs
from dissect.ntfs.ntfs import NTFS

CLUSTER_SIZE = 512
RECORD_SIZE = 1024
MFT_LCN = 4
ATTRIBUTE_OFFSET = 0x38
ATTRIBUTE_HEADER_SIZE = 0x40

Run = tuple[int | None, int]
Widths = tuple[int, int]


@dataclass(frozen=True)
class MappingPairsCase:
    """A logical run list and the field widths used to encode it."""

    runs: tuple[Run, ...]
    widths: tuple[Widths, ...]
    tail: bytes = b""

    @property
    def size(self) -> int:
        return sum(count for _, count in self.runs) * CLUSTER_SIZE


def encode_mapping_pairs(case: MappingPairsCase) -> bytes:
    """Encode a logical run list into mapping pairs, using the requested field widths.

    Run lengths are unsigned and LCN deltas are signed, just like the on-disk format. Extra field width is filled
    with zero extension (run length) or sign extension (LCN delta), which makes the decoder honor the declared width.
    """
    assert len(case.runs) == len(case.widths)

    buf = bytearray()
    previous_lcn = 0

    for (lcn, count), (size_width, delta_width) in zip(case.runs, case.widths):
        assert 1 <= size_width <= 8
        assert 0 <= delta_width <= 8

        if lcn is None:
            assert delta_width == 0, "a sparse run has no LCN delta field"
            buf.append(size_width)
            buf += count.to_bytes(size_width, "little")
            continue

        assert delta_width > 0, "a data run needs an LCN delta field"
        delta = lcn - previous_lcn
        previous_lcn = lcn

        buf.append((delta_width << 4) | size_width)
        buf += count.to_bytes(size_width, "little")
        buf += delta.to_bytes(delta_width, "little", signed=True)

    buf.append(0)
    buf += case.tail
    return bytes(buf)


def model_disk_bytes(runs: tuple[Run, ...]) -> bytes:
    """Return the bytes a correct decoder must read for the given logical runs."""
    out = bytearray()
    for lcn, count in runs:
        if lcn is None:
            out += b"\x00" * (count * CLUSTER_SIZE)
        else:
            out += b"".join(cluster_pattern(lcn + i) for i in range(count))
    return bytes(out)


def cluster_pattern(lcn: int) -> bytes:
    """Return the deterministic content of a cluster, encoding its physical LCN."""
    assert lcn > 0, "tests reserve LCN 0 to keep zero-filled sparse runs distinguishable"
    return struct.pack("<Q", lcn) * (CLUSTER_SIZE // 8)


class PatternVolume(io.RawIOBase):
    """A sparse, read-only volume where every cluster encodes its own LCN."""

    def __init__(self, clusters: int):
        super().__init__()
        self.clusters = clusters
        self.size = clusters * CLUSTER_SIZE
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            pos = offset
        elif whence == io.SEEK_CUR:
            pos = self._pos + offset
        elif whence == io.SEEK_END:
            pos = self.size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")

        if pos < 0:
            raise ValueError("negative seek position")
        self._pos = pos
        return pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = self.size - self._pos
        n = min(n, max(0, self.size - self._pos))

        out = bytearray()
        while n > 0:
            lcn, offset = divmod(self._pos, CLUSTER_SIZE)
            chunk = min(n, CLUSTER_SIZE - offset)
            out += cluster_pattern(lcn)[offset : offset + chunk]
            self._pos += chunk
            n -= chunk
        return bytes(out)


def boot_sector() -> bytes:
    boot = c_ntfs.BOOT_SECTOR()
    boot.Jump = b"\xeb\x52\x90"
    boot.Oem = b"NTFS    "
    boot.Bpb.BytesPerSector = CLUSTER_SIZE
    boot.Bpb.SectorsPerCluster = 1
    boot.MftStartLcn = MFT_LCN
    boot.Mft2StartLcn = MFT_LCN
    boot.ClustersPerFileRecordSegment = 2
    boot.ClustersPerIndexBuffer = 8
    boot.NumberSectors = 1 << 20
    return bytes(boot).ljust(CLUSTER_SIZE, b"\x00")


def nonresident_data_attribute(pairs: bytes, size: int, *, record_length: int | None = None) -> bytes:
    """Build a non-resident, unnamed $DATA attribute containing ``pairs``."""
    record_length = record_length if record_length is not None else max(ATTRIBUTE_HEADER_SIZE + len(pairs), 0x48)
    data = bytearray(max(record_length, 0x48))

    struct.pack_into("<I", data, 0, ATTRIBUTE_TYPE_CODE.DATA.value)
    struct.pack_into("<I", data, 4, record_length)
    data[8] = 1  # non-resident
    struct.pack_into("<H", data, 10, ATTRIBUTE_HEADER_SIZE)  # NameOffset
    struct.pack_into("<Q", data, 16, 0)  # LowestVcn
    struct.pack_into("<Q", data, 24, max(size // CLUSTER_SIZE - 1, 0))  # HighestVcn
    struct.pack_into("<H", data, 32, ATTRIBUTE_HEADER_SIZE)  # MappingPairsOffset
    struct.pack_into("<q", data, 40, size)  # AllocatedLength
    struct.pack_into("<q", data, 48, size)  # FileSize
    struct.pack_into("<q", data, 56, size)  # ValidDataLength
    struct.pack_into("<q", data, 64, size)  # TotalAllocated
    data[ATTRIBUTE_HEADER_SIZE : ATTRIBUTE_HEADER_SIZE + len(pairs)] = pairs

    return bytes(data[:record_length])


def mft_record(attributes: list[bytes], flags: int = 1, sequence: int = 1) -> bytes:
    """Build a single FILE record with the given attributes and an END marker."""
    data = bytearray(RECORD_SIZE)
    data[:4] = b"FILE"
    struct.pack_into("<H", data, 4, 0x30)
    struct.pack_into("<H", data, 6, 3)
    struct.pack_into("<H", data, 16, sequence)
    struct.pack_into("<H", data, 18, 1)
    struct.pack_into("<H", data, 20, ATTRIBUTE_OFFSET)
    struct.pack_into("<H", data, 22, flags)
    struct.pack_into("<I", data, 28, RECORD_SIZE)

    offset = ATTRIBUTE_OFFSET
    for attr in attributes:
        data[offset : offset + len(attr)] = attr
        offset += len(attr)

    end = struct.pack("<II", ATTRIBUTE_TYPE_CODE.END.value, 0)
    data[offset : offset + len(end)] = end
    offset += len(end)
    struct.pack_into("<I", data, 24, offset)

    # Update sequence array
    data[0x30:0x32] = b"\xaa\xbb"
    data[0x32:0x34] = b"\x11\x22"
    data[0x34:0x36] = b"\x33\x44"
    data[0x1FE:0x200] = b"\xaa\xbb"
    data[0x3FE:0x400] = b"\xaa\xbb"

    return bytes(data)


def mft_image(record: bytes) -> io.BytesIO:
    """Return a minimal $MFT with a file record at segment 0 and a root directory at segment 5."""
    image = bytearray(RECORD_SIZE * 6)
    image[:RECORD_SIZE] = record
    image[5 * RECORD_SIZE : 6 * RECORD_SIZE] = mft_record([], flags=3, sequence=1)
    return io.BytesIO(bytes(image))


def open_case(case: MappingPairsCase, *, pairs: bytes | None = None, record_length: int | None = None) -> NTFS:
    pairs = pairs if pairs is not None else encode_mapping_pairs(case)
    attr = nonresident_data_attribute(pairs, case.size, record_length=record_length)
    record = mft_record([attr])

    max_lcn = max((lcn or 0) for lcn, _ in case.runs)
    clusters = max_lcn + sum(count for _, count in case.runs) + 8
    return NTFS(fh=PatternVolume(clusters), boot=io.BytesIO(boot_sector()), mft=mft_image(record))


def attribute_of(fs: NTFS) -> Attribute:
    record = fs.mft.get(0)
    attrs = record.attributes[ATTRIBUTE_TYPE_CODE.DATA]
    assert len(attrs) == 1
    return attrs[0]


def mutant_dataruns(
    buf: bytes,
    start: int = 0,
    end: int | None = None,
    *,
    unsigned_delta: bool = False,
    signed_size: bool = False,
    sparse_advances_base: bool = False,
) -> tuple[list[Run], int]:
    """A deliberately buggy decoder with one switch per historical failure mode.

    ``end`` models honoring the attribute record boundary. Leaving it out reproduces the old unbounded
    ``read``-until-terminator decoder, so the same fixture bytes can be replayed against the buggy logic.
    """
    pos = start
    limit = end if end is not None else len(buf)
    lcn = 0
    runs: list[Run] = []

    while pos < limit:
        header = buf[pos]
        pos += 1
        if header == 0:
            break

        size_width = header & 0xF
        delta_width = (header >> 4) & 0xF

        if signed_size:
            # Reproduce the historical varint() padding, which turns high-bit lengths into negative numbers
            raw = buf[pos : pos + size_width]
            if len(raw) < 8:
                raw += (b"\xff" if raw[-1] & 0x80 else b"\x00") * (8 - len(raw))
            run_size = int.from_bytes(raw, "little", signed=True)
        else:
            run_size = int.from_bytes(buf[pos : pos + size_width], "little")
        pos += size_width

        if delta_width == 0:
            runs.append((None, run_size))
            if sparse_advances_base:
                lcn += run_size
        else:
            delta = int.from_bytes(buf[pos : pos + delta_width], "little", signed=not unsigned_delta)
            pos += delta_width
            lcn += delta
            runs.append((lcn, run_size))

    return runs, pos


CASES = [
    MappingPairsCase(((40, 1),), ((1, 1),)),
    MappingPairsCase(((6, 3), (300, 2)), ((1, 2), (1, 2))),
    MappingPairsCase(((100, 2), (97, 3)), ((1, 1), (1, 1))),
    MappingPairsCase(((500, 2), (499, 1)), ((8, 8), (8, 8))),
    MappingPairsCase(((100, 2), (None, 3), (101, 1)), ((1, 1), (1, 0), (1, 1))),
    MappingPairsCase(((None, 1), (20, 2)), ((1, 0), (1, 1))),
    MappingPairsCase(((None, 4),), ((3, 0),)),
    MappingPairsCase(((30, 1), (None, 2)), ((1, 1), (2, 0))),
    MappingPairsCase(((64, 1), (63, 1)), ((2, 1), (2, 1))),
    MappingPairsCase(((50, 200),), ((1, 1),)),
]
CASES += [MappingPairsCase(((50, 1),), ((width, 1),)) for width in range(1, 9)]
CASES += [MappingPairsCase(((64, 1), (63, 1)), ((1, 1), (1, width))) for width in range(1, 9)]


@pytest.mark.parametrize(
    "case",
    CASES,
    ids=[f"runs={case.runs}-widths={case.widths}" for case in CASES],
)
def test_mapping_pairs_model(case: MappingPairsCase) -> None:
    fs = open_case(case)
    attr = attribute_of(fs)

    # The expected runs come from the logical model, not from the decoder under test.
    assert attr.dataruns() == list(case.runs)

    # All reads, including ones that span run boundaries, must match the model's disk bytes.
    expected = model_disk_bytes(case.runs)
    stream = fs.mft.get(0).open()
    assert stream.read() == expected

    boundaries = []
    offset = 0
    for _, count in case.runs:
        offset += count * CLUSTER_SIZE
        boundaries.append(offset)

    for boundary in boundaries[:-1]:
        # Read a window that starts inside the previous run and ends inside the next one
        start = max(0, boundary - CLUSTER_SIZE - 3)
        length = min(2 * CLUSTER_SIZE + 6, len(expected) - start)
        stream.seek(start)
        assert stream.read(length) == expected[start : start + length]

        # The exact run boundary must be contiguous
        assert stream.readoffset(boundary - 1, 2) == expected[boundary - 1 : boundary + 1]


def test_terminator_stops_before_trailing_bytes() -> None:
    """Bytes after the terminator inside the attribute record must never become runs."""
    case = MappingPairsCase(((70, 2),), ((1, 1),), tail=b"\x11\x01\x63\x00")
    fs = open_case(case)

    assert attribute_of(fs).dataruns() == [(70, 2)]
    assert fs.mft.get(0).open().read() == model_disk_bytes(case.runs)


def test_negative_delta_is_signed() -> None:
    """A legal negative LCN delta must move the physical base backwards."""
    case = MappingPairsCase(((100, 1), (97, 1)), ((1, 1), (1, 1)))
    pairs = encode_mapping_pairs(case)
    assert pairs == bytes.fromhex("1101641101fd00")

    fs = open_case(case)
    attr = attribute_of(fs)
    assert attr.dataruns() == [(100, 1), (97, 1)]

    expected = model_disk_bytes(case.runs)
    assert fs.mft.get(0).open().read() == expected

    # Replayable counterexample: interpreting the same bytes as an unsigned delta lands on LCN 353.
    buggy_runs, _ = mutant_dataruns(pairs, unsigned_delta=True)
    assert buggy_runs == [(100, 1), (353, 1)]
    assert buggy_runs != list(case.runs)

    buggy_bytes = RunlistStream(PatternVolume(400), buggy_runs, case.size, CLUSTER_SIZE).read()
    assert buggy_bytes != expected


def test_run_length_is_unsigned() -> None:
    """A run length with the high bit set is a positive unsigned value, not a negative signed integer."""
    case = MappingPairsCase(((50, 200),), ((1, 1),))
    pairs = encode_mapping_pairs(case)
    assert pairs == bytes.fromhex("11c83200")

    fs = open_case(case)
    attr = attribute_of(fs)
    assert attr.dataruns() == [(50, 200)]

    expected = model_disk_bytes(case.runs)
    assert fs.mft.get(0).open().read() == expected

    # Replayable counterexample: the old sign-extending varint turns 0xc8 into -56.
    buggy_runs, _ = mutant_dataruns(pairs, 0, len(pairs), signed_size=True)
    assert buggy_runs == [(50, -56)]
    assert buggy_runs != list(case.runs)


def test_sparse_run_does_not_advance_physical_base() -> None:
    """A sparse run yields zeroes but keeps the physical LCN base where it was."""
    case = MappingPairsCase(((100, 2), (None, 3), (101, 1)), ((1, 1), (1, 0), (1, 1)))
    pairs = encode_mapping_pairs(case)

    fs = open_case(case)
    attr = attribute_of(fs)
    assert attr.dataruns() == [(100, 2), (None, 3), (101, 1)]

    expected = model_disk_bytes(case.runs)
    assert expected[2 * CLUSTER_SIZE : 5 * CLUSTER_SIZE] == b"\x00" * (3 * CLUSTER_SIZE)
    assert fs.mft.get(0).open().read() == expected

    # Replayable counterexample: advancing the base by the sparse length lands the next run on LCN 104.
    buggy_runs, _ = mutant_dataruns(pairs, 0, len(pairs), sparse_advances_base=True)
    assert buggy_runs == [(100, 2), (None, 3), (104, 1)]
    assert buggy_runs != list(case.runs)

    buggy_bytes = RunlistStream(PatternVolume(120), buggy_runs, case.size, CLUSTER_SIZE).read()
    assert buggy_bytes != expected


def test_truncated_field_does_not_read_past_attribute() -> None:
    """A run field truncated at the attribute boundary must be rejected, not completed with following bytes."""
    pairs = bytes.fromhex("110128210205")  # second run declares size=1, delta=2 but only one delta byte exists
    case = MappingPairsCase(((40, 1),), ((1, 1),))
    record_length = ATTRIBUTE_HEADER_SIZE + len(pairs)

    fs = open_case(case, pairs=pairs, record_length=record_length)
    attr = attribute_of(fs)

    with pytest.raises(ValueError, match="past the end of the attribute record"):
        attr.dataruns()

    # Replayable counterexample: without the attribute boundary the decoder consumes the END marker bytes.
    record = mft_image(open_case(case, pairs=pairs, record_length=record_length).mft.get(0).data).getvalue()
    start = ATTRIBUTE_OFFSET + ATTRIBUTE_HEADER_SIZE
    attribute_end = ATTRIBUTE_OFFSET + record_length
    buggy_runs, consumed = mutant_dataruns(record, start)

    assert consumed > attribute_end
    assert buggy_runs == [(40, 1), (-211, 2), (-211, 0xFFFF)]

    # Bounding the same bytes to the attribute record stops at the truncated field, proving the fixture actually
    # depends on the boundary rather than on the terminator happening to be absent.
    bounded_runs, bounded_consumed = mutant_dataruns(record, start, attribute_end)
    assert bounded_consumed >= attribute_end
    assert bounded_runs == [(40, 1), (-211, 2)]


def test_missing_terminator_is_rejected() -> None:
    """Mapping pairs without a terminator must not silently run into the next attribute."""
    case = MappingPairsCase(((40, 1),), ((1, 1),))
    pairs = bytes.fromhex("110128")  # no 0x00 terminator
    record_length = ATTRIBUTE_HEADER_SIZE + len(pairs)

    fs = open_case(case, pairs=pairs, record_length=record_length)
    attr = attribute_of(fs)

    with pytest.raises(ValueError, match="missing terminator"):
        attr.dataruns()

    # Replayable counterexample: the unbounded decoder reads through the END marker and fabricates runs.
    record = mft_image(open_case(case, pairs=pairs, record_length=record_length).mft.get(0).data).getvalue()
    buggy_runs, consumed = mutant_dataruns(record, ATTRIBUTE_OFFSET + ATTRIBUTE_HEADER_SIZE)

    assert consumed > ATTRIBUTE_OFFSET + record_length
    assert buggy_runs == [(40, 1), (40, 0xFFFFFF)]


def test_real_volume_multi_run_stream(ntfs_bin: BinaryIO) -> None:
    """Cross-check a real, multi-run uncompressed file against the model and direct volume slices."""
    fs = NTFS(ntfs_bin)
    record = fs.mft.get("$MFT")
    header = record.attributes[ATTRIBUTE_TYPE_CODE.DATA][0].header

    start = header.offset + header.header.Form.Nonresident.MappingPairsOffset
    end = header.offset + header.record_length
    header.fh.seek(start)
    pairs = header.fh.read(end - start)

    runs, consumed = mutant_dataruns(pairs, 0, len(pairs))
    assert consumed <= len(pairs)
    assert record.dataruns() == runs

    expected = bytearray()
    for lcn, count in runs:
        if lcn is None:
            expected += b"\x00" * (count * fs.cluster_size)
        else:
            fs.fh.seek(lcn * fs.cluster_size)
            expected += fs.fh.read(count * fs.cluster_size)

    assert record.open().read() == bytes(expected)


@pytest.mark.parametrize(
    ("pairs", "match"),
    [
        pytest.param(bytes.fromhex("1001"), "zero-length run size", id="zero-size-field"),
        pytest.param(bytes.fromhex("910100"), "invalid field width", id="size-width-nine"),
        pytest.param(bytes.fromhex("1101"), "past the end", id="missing-size-byte"),
        pytest.param(bytes.fromhex("11000000"), "zero-length run", id="zero-length-run"),
        pytest.param(bytes.fromhex("1101ff00"), "negative LCN", id="negative-lcn"),
    ],
)
def test_malformed_mapping_pairs_are_rejected(pairs: bytes, match: str) -> None:
    """Malformed fields must fail closed instead of producing a plausible but wrong run."""
    case = MappingPairsCase(((1, 1),), ((1, 1),))
    record_length = ATTRIBUTE_HEADER_SIZE + len(pairs)
    fs = open_case(case, pairs=pairs, record_length=record_length)

    with pytest.raises(ValueError, match=match):
        attribute_of(fs).dataruns()
