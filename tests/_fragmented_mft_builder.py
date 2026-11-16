"""Synthetic, fully controlled fragmented ``$MFT`` volume builder.

The fragmented ``$MFT`` bootstrap regression needs volumes where the ``$MFT`` is opened in multiple
reachability stages: the initial ``$MFT`` record only describes the first fragment of its own data, and
every later fragment is described by an ``$ATTRIBUTE_LIST`` entry pointing at another MFT record.

Real disk samples cannot be mutated to create a reference order conflict, an unreachable extension or a
dependency cycle, so this module assembles minimal NTFS volumes from scratch. Nothing here scans the volume
for ``FILE`` signatures: every record is located either through the boot sector location or through a
previously confirmed datarun, which is exactly the contract the bootstrap code in :mod:`dissect.ntfs.ntfs`
is tested against.

Coordinate systems:

- logical MFT byte offsets (``segment * RECORD_SIZE``): positions inside the conceptual ``$MFT`` file;
- physical volume cluster numbers (LCNs): where the record bytes are actually stored.

A fragment's dataruns translate logical positions into physical LCNs, mirroring a real fragmented volume.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from io import BytesIO

from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE, NTFS_SIGNATURE, c_ntfs
from dissect.util.stream import MappingStream

SECTOR_SIZE = 512
CLUSTER_SIZE = 1024
RECORD_SIZE = 1024
RECORDS_PER_CLUSTER = CLUSTER_SIZE // RECORD_SIZE
ATTRIBUTE_HEADER_SIZE = len(c_ntfs._ATTRIBUTE_RECORD_HEADER())
ATTRIBUTE_LIST_ENTRY_SIZE = 32
FIRST_ATTRIBUTE_OFFSET = 0x38


def encode_dataruns(runs: list[tuple[int | None, int]]) -> bytes:
    """Encode NTFS mapping pairs for ``(lcn, cluster_count)`` runs.

    An ``lcn`` of ``None`` produces a sparse run. Offsets after the first run are signed deltas relative to
    the previous run's LCN, as NTFS stores them on disk.
    """
    encoded = b""
    previous_lcn = 0
    for index, (lcn, cluster_count) in enumerate(runs):
        length_size = max(1, (cluster_count.bit_length() + 7) // 8)
        length_bytes = cluster_count.to_bytes(length_size, "little")

        if lcn is None:
            encoded += bytes([length_size]) + length_bytes
            continue

        delta = lcn if index == 0 else lcn - previous_lcn
        offset_size = max(1, (abs(delta).bit_length() + 8) // 8)
        offset_bytes = delta.to_bytes(offset_size, "little", signed=True)
        encoded += bytes([(offset_size << 4) | length_size]) + length_bytes + offset_bytes
        previous_lcn = lcn

    return encoded + b"\x00"


def nonresident_attribute(
    attr_type: ATTRIBUTE_TYPE_CODE,
    lowest_vcn: int,
    highest_vcn: int,
    runs: list[tuple[int | None, int]],
    data_size: int | None = None,
) -> bytes:
    """Serialize a non-resident attribute header followed by its mapping pairs."""
    mapping = encode_dataruns(runs)
    cluster_count = sum(run_length for _, run_length in runs)
    size = data_size if data_size is not None else (highest_vcn - lowest_vcn + 1) * CLUSTER_SIZE

    header = c_ntfs._ATTRIBUTE_RECORD_HEADER()
    header.TypeCode = attr_type
    header.RecordLength = ATTRIBUTE_HEADER_SIZE + len(mapping)
    header.FormCode = 1
    header.NameLength = 0
    header.NameOffset = 0
    header.Flags = 0
    header.Instance = 0
    header.Form.Nonresident.LowestVcn = lowest_vcn
    header.Form.Nonresident.HighestVcn = highest_vcn
    header.Form.Nonresident.MappingPairsOffset = ATTRIBUTE_HEADER_SIZE
    header.Form.Nonresident.CompressionUnit = 0
    header.Form.Nonresident.AllocatedLength = cluster_count * CLUSTER_SIZE
    header.Form.Nonresident.FileSize = size
    header.Form.Nonresident.ValidDataLength = size
    header.Form.Nonresident.TotalAllocated = cluster_count * CLUSTER_SIZE

    return header.dumps() + mapping


def resident_attribute(attr_type: ATTRIBUTE_TYPE_CODE, value: bytes, instance: int = 0) -> bytes:
    """Serialize a resident attribute whose value lives inside the MFT record."""
    value_offset = ATTRIBUTE_HEADER_SIZE
    record_length = value_offset + len(value)

    header = c_ntfs._ATTRIBUTE_RECORD_HEADER()
    header.TypeCode = attr_type
    header.RecordLength = record_length
    header.FormCode = 0
    header.NameLength = 0
    header.NameOffset = 0
    header.Flags = 0
    header.Instance = instance
    header.Form.Resident.ValueLength = len(value)
    header.Form.Resident.ValueOffset = value_offset
    header.Form.Resident.Flags = 0
    header.Form.Resident.Reserved = 0

    return header.dumps() + value


def end_marker() -> bytes:
    marker = c_ntfs._ATTRIBUTE_RECORD_HEADER()
    marker.TypeCode = ATTRIBUTE_TYPE_CODE.END
    return marker.dumps()[:4]


def attribute_list_entry(lowest_vcn: int, segment: int, sequence: int = 1) -> bytes:
    """Serialize one unnamed, 8-byte aligned ``$ATTRIBUTE_LIST`` entry."""
    entry = c_ntfs._ATTRIBUTE_LIST_ENTRY()
    entry.AttributeTypeCode = ATTRIBUTE_TYPE_CODE.DATA
    entry.RecordLength = ATTRIBUTE_LIST_ENTRY_SIZE
    entry.AttributeNameLength = 0
    entry.AttributeNameOffset = 0
    entry.LowestVcn = lowest_vcn
    entry.SegmentReference.SegmentNumberLowPart = segment & 0xFFFFFFFF
    entry.SegmentReference.SegmentNumberHighPart = segment >> 32
    entry.SegmentReference.SequenceNumber = sequence
    entry.Reserved = 0

    raw = entry.dumps()
    return raw + b"\x00" * (ATTRIBUTE_LIST_ENTRY_SIZE - len(raw))


def build_record(sequence: int, attributes: bytes, flags: int = 0x0001) -> bytes:
    """Assemble a fixed-up 1024-byte MFT record around a serialized attribute blob."""
    record = bytearray(RECORD_SIZE)
    record[0:4] = b"FILE"

    fixup_offset = 0x30
    fixup_count = RECORD_SIZE // SECTOR_SIZE
    struct.pack_into("<HH", record, 4, fixup_offset, fixup_count + 1)
    struct.pack_into("<Q", record, 8, 0)
    struct.pack_into("<H", record, 16, sequence)
    struct.pack_into("<H", record, 18, 1)
    struct.pack_into("<H", record, 20, FIRST_ATTRIBUTE_OFFSET)
    struct.pack_into("<H", record, 22, flags)
    struct.pack_into("<I", record, 24, FIRST_ATTRIBUTE_OFFSET + len(attributes))
    struct.pack_into("<I", record, 28, RECORD_SIZE)

    record[FIRST_ATTRIBUTE_OFFSET : FIRST_ATTRIBUTE_OFFSET + len(attributes)] = attributes

    struct.pack_into("<H", record, fixup_offset, sequence)
    for index in range(fixup_count):
        sector_end = (index + 1) * SECTOR_SIZE - 2
        original = struct.unpack("<H", record[sector_end : sector_end + 2])[0]
        struct.pack_into("<H", record, fixup_offset + 2 + index * 2, original)
        record[sector_end : sector_end + 2] = struct.pack("<H", sequence)

    return bytes(record)


@dataclass
class MftFragment:
    """One logical fragment of the fragmented ``$MFT`` stream.

    Args:
        vcn: Lowest VCN of this fragment within the ``$MFT`` stream.
        runs: Physical ``(lcn, cluster_count)`` runs holding this fragment's MFT records.
        descriptor_segment: MFT segment number of the record that carries this fragment's ``$DATA`` runs.
        attribute_list_value: Optional serialized ``$ATTRIBUTE_LIST`` value (only on the initial record).
        attribute_list_lcn: Physical LCN holding a non-resident ``$ATTRIBUTE_LIST`` value. When omitted the
            list is stored resident inside the descriptor record.
        record_flags: Optional ``$FILE`` record flags for the descriptor (e.g. the directory bit for root).
    """

    vcn: int
    runs: list[tuple[int | None, int]]
    descriptor_segment: int
    attribute_list_value: bytes | None = None
    attribute_list_lcn: int | None = None
    record_flags: int = 0x0001

    @property
    def cluster_count(self) -> int:
        return sum(run_length for _, run_length in self.runs)

    @property
    def highest_vcn(self) -> int:
        return self.vcn + self.cluster_count - 1


@dataclass
class FragmentedMftVolume:
    """Assembled volume and the bookkeeping used to assert per-stage reachability."""

    stream: MappingStream
    mft_start_lcn: int
    fragments: list[MftFragment]
    physical_lcns: dict[int, int] = field(default_factory=dict)

    def confirmed_segments(self, cluster_runlist: list[tuple[int | None, int]]) -> set[int]:
        """Return the MFT segment numbers logically covered by the given confirmed cluster runlist."""
        confirmed_clusters = sum(run_length for _, run_length in cluster_runlist)
        last_segment = (confirmed_clusters * CLUSTER_SIZE) // RECORD_SIZE
        return set(range(last_segment))


class FragmentedMftBuilder:
    """Build a sparse volume containing a multi-stage fragmented ``$MFT``."""

    def __init__(self, mft_start_lcn: int = 0x1000):
        self.mft_start_lcn = mft_start_lcn
        self._clusters: dict[int, bytearray] = {}
        self._record_lcns: dict[int, int] = {}

    def _cluster(self, lcn: int) -> bytearray:
        return self._clusters.setdefault(lcn, bytearray(CLUSTER_SIZE))

    def _write_record(self, lcn: int, record: bytes, segment: int) -> None:
        if len(record) != RECORD_SIZE:
            raise ValueError("MFT records must be exactly one record in size")
        self._cluster(lcn)[:RECORD_SIZE] = record
        self._record_lcns[segment] = lcn

    def place_standalone_record(self, segment: int, record: bytes, lcn: int) -> None:
        """Place an independently located record (e.g. a later query target) in its own cluster."""
        self._write_record(lcn, record, segment)

    def build_boot_sector(self) -> bytes:
        boot = bytearray(SECTOR_SIZE)
        boot[0:3] = b"\xeb\x52\x90"
        boot[3:11] = NTFS_SIGNATURE
        struct.pack_into("<H", boot, 11, SECTOR_SIZE)
        struct.pack_into("<b", boot, 13, CLUSTER_SIZE // SECTOR_SIZE)
        struct.pack_into("<Q", boot, 0x28, 0)
        struct.pack_into("<Q", boot, 0x30, self.mft_start_lcn)
        struct.pack_into("<Q", boot, 0x38, self.mft_start_lcn + 0x10)
        # One cluster per file record segment (1024-byte records) and four clusters per index buffer.
        struct.pack_into("<b", boot, 0x40, 1)
        struct.pack_into("<b", boot, 0x44, 4)
        struct.pack_into("<Q", boot, 0x48, 0x0123456789ABCDEF)
        boot[510:512] = b"\x55\xaa"
        return bytes(boot)

    def build(self, fragments: list[MftFragment]) -> FragmentedMftVolume:
        if not fragments or fragments[0].descriptor_segment != 0 or fragments[0].vcn != 0:
            raise ValueError("The first fragment must start at VCN 0 and be described by MFT segment 0")

        # Logical -> physical translation across the concatenated fragment runlists.
        def logical_to_physical(logical_byte: int) -> tuple[int, int] | None:
            cursor = 0
            for fragment in fragments:
                for lcn, cluster_count in fragment.runs:
                    run_bytes = cluster_count * CLUSTER_SIZE
                    if cursor <= logical_byte < cursor + run_bytes:
                        within = logical_byte - cursor
                        if lcn is None:
                            return None
                        return lcn + within // CLUSTER_SIZE, within % CLUSTER_SIZE
                    cursor += run_bytes
            return None

        # Ensure every physical cluster referenced by a fragment run exists on the volume, even when it only
        # holds ordinary MFT records rather than a fragment descriptor. This is what makes later segments
        # reachable through the confirmed runlists after each stage extends them.
        for fragment in fragments:
            for lcn, cluster_count in fragment.runs:
                if lcn is None:
                    continue
                for cluster_offset in range(cluster_count):
                    self._cluster(lcn + cluster_offset)

        # Build and place every descriptor record through the fragment runlists.
        for fragment in fragments:
            record = self._build_fragment_record(fragment)
            location = logical_to_physical(fragment.descriptor_segment * RECORD_SIZE)
            if location is None:
                raise ValueError(
                    f"Descriptor segment {fragment.descriptor_segment} is not reachable through the fragment runs"
                )
            lcn, within_cluster = location
            if within_cluster != 0:
                raise ValueError("Descriptor records are expected to be cluster aligned in this builder")
            self._write_record(lcn, record, fragment.descriptor_segment)

        # The boot sector reads segment 0 directly at MftStartLcn.
        initial_lcn = self._record_lcns[0]
        if initial_lcn != self.mft_start_lcn:
            self._cluster(self.mft_start_lcn)[:] = self._clusters[initial_lcn]
            self._record_lcns[0] = self.mft_start_lcn

        stream = MappingStream(align=SECTOR_SIZE)
        for lcn, cluster in self._clusters.items():
            stream.add(lcn * CLUSTER_SIZE, CLUSTER_SIZE, BytesIO(bytes(cluster)), 0)
        stream.add(0, SECTOR_SIZE, BytesIO(self.build_boot_sector()), 0)

        return FragmentedMftVolume(
            stream=stream,
            mft_start_lcn=self.mft_start_lcn,
            fragments=list(fragments),
            physical_lcns=dict(self._record_lcns),
        )

    def _build_fragment_record(self, fragment: MftFragment) -> bytes:
        attributes = b""
        if fragment.attribute_list_value is not None:
            if fragment.attribute_list_lcn is None:
                attributes += resident_attribute(
                    ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST, fragment.attribute_list_value
                )
            else:
                # A non-resident $ATTRIBUTE_LIST occupies its own single-cluster run on the volume.
                list_runs = [(fragment.attribute_list_lcn, 1)]
                attributes += nonresident_attribute(
                    ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST,
                    lowest_vcn=0,
                    highest_vcn=0,
                    runs=list_runs,
                    data_size=len(fragment.attribute_list_value),
                )
                self._cluster(fragment.attribute_list_lcn)[: len(fragment.attribute_list_value)] = (
                    fragment.attribute_list_value
                )
        attributes += nonresident_attribute(
            ATTRIBUTE_TYPE_CODE.DATA,
            fragment.vcn,
            fragment.highest_vcn,
            fragment.runs,
        )
        attributes += end_marker()
        return build_record(1, attributes, flags=fragment.record_flags)
