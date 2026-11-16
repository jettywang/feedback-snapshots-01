from __future__ import annotations

from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.ntfs.attr import AttributeHeader
from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    DEFAULT_CLUSTER_SIZE,
    DEFAULT_INDEX_SIZE,
    DEFAULT_RECORD_SIZE,
    DEFAULT_SECTOR_SIZE,
    FILE_NUMBER_VOLUME,
    NTFS_SIGNATURE,
    c_ntfs,
)
from dissect.ntfs.exceptions import (
    Error,
    FileNotFoundError,
    MftUnreachableError,
    VolumeNotAvailableError,
)
from dissect.ntfs.mft import Mft, MftRecord
from dissect.ntfs.secure import Secure
from dissect.ntfs.usnjrnl import UsnJrnl
from dissect.ntfs.util import bsf, segment_reference
from dissect.util.stream import RunlistStream

if TYPE_CHECKING:
    from collections.abc import Iterator


class NTFS:
    """Implementation for Microsoft NTFS.

    This implementation supports parsing NTFS from either a full NTFS volume or from separate files.
    If you have a file-like object of an NTFS volume, simply pass it as the fh argument. If you have separate
    file-like objects for things like ``$BOOT`` or ``$MFT``, pass those as the boot and mft arguments.
    The separate arguments take precedence over parsing from the volume file-like object.

    Args:
        fh: A file-like object for the volume to use for parsing NTFS. This is where "data on disk" is read from.
        boot: A file-like object for the ``$BOOT`` file.
        mft: A file-like object for the ``$MFT`` file.
        usnjrnl: A file-like object for the ``$Extend/$Usnjrnl:$J`` file.
        sds: A file-like object for the ``$Secure:$SDS`` file.
    """

    def __init__(
        self,
        fh: BinaryIO | None = None,
        boot: BinaryIO | None = None,
        mft: BinaryIO | None = None,
        usnjrnl: BinaryIO | None = None,
        sds: BinaryIO | None = None,
    ):
        self.fh = fh

        boot_fh = boot or fh
        if boot_fh:
            boot_fh.seek(0)
            self.boot_sector = c_ntfs.BOOT_SECTOR(boot_fh)

            if self.boot_sector.Oem != NTFS_SIGNATURE:
                raise Error(f"Invalid NTFS magic: {self.boot_sector.Oem}")

            self.sector_size = self.boot_sector.Bpb.BytesPerSector
            if self.boot_sector.Bpb.SectorsPerCluster & 0xFF > 0x80:
                sectors_per_cluster = 1 << (-self.boot_sector.Bpb.SectorsPerCluster)
            else:
                sectors_per_cluster = self.boot_sector.Bpb.SectorsPerCluster & 0xFF
            self.cluster_size = sectors_per_cluster * self.sector_size

            if self.boot_sector.ClustersPerFileRecordSegment < 0:
                self._record_size = 1 << (-self.boot_sector.ClustersPerFileRecordSegment)
            else:
                self._record_size = self.boot_sector.ClustersPerFileRecordSegment * self.cluster_size

            if self.boot_sector.ClustersPerIndexBuffer < 0:
                self._index_size = 2 << (-self.boot_sector.ClustersPerIndexBuffer)
            else:
                self._index_size = self.boot_sector.ClustersPerIndexBuffer * self.cluster_size
        else:
            # Provide some defaults if we don't have a volume or $BOOT file
            self.boot_sector = None
            self.sector_size = DEFAULT_SECTOR_SIZE
            self.cluster_size = DEFAULT_CLUSTER_SIZE
            self._record_size = DEFAULT_RECORD_SIZE
            self._index_size = DEFAULT_INDEX_SIZE

        self.sector_size_shift = bsf(self.sector_size)
        self.cluster_size_shift = bsf(self.cluster_size)

        self.mft = None
        self.secure = None
        self.usnjrnl = None

        if mft:
            self.mft = Mft(mft, ntfs=self)
        elif self.fh:
            self.mft = self._bootstrap_fragmented_mft()

        if sds:
            self.secure = Secure(sds=sds)
        elif self.mft:
            try:
                self.secure = Secure(self.mft.get("$Secure"))
            except (FileNotFoundError, VolumeNotAvailableError):
                pass

        if usnjrnl:
            self.usnjrnl = UsnJrnl(usnjrnl, ntfs=self)
        elif self.mft:
            try:
                self.usnjrnl = UsnJrnl(self.mft.get("$Extend\\$Usnjrnl").open("$J"), ntfs=self)
            except (FileNotFoundError, NotADirectoryError, VolumeNotAvailableError):
                pass

    @cached_property
    def serial(self) -> int | None:
        return self.boot_sector.SerialNumber if self.boot_sector else None

    @cached_property
    def volume_name(self) -> str | None:
        if not self.mft:
            return None

        try:
            volume_file = self.mft.get(FILE_NUMBER_VOLUME)
            volume_name = volume_file.attributes[ATTRIBUTE_TYPE_CODE.VOLUME_NAME].data()
            return volume_name.decode("utf-16-le")
        except (AttributeError, FileNotFoundError):
            return None

    def _bootstrap_fragmented_mft(self) -> Mft:
        """Incrementally open a fragmented ``$MFT`` without assuming the whole file is readable up front.

        The bootstrap proceeds in explicit stages, and at every stage the only ``$MFT`` bytes that may be
        read are the ones covered by the runs confirmed in the preceding stages:

        1. Parse the single ``$MFT`` record located through the boot sector. Its own ``$DATA`` attribute
           describes the first fragment of the ``$MFT`` file.
        2. Open a temporary :class:`~dissect.ntfs.mft.Mft` on exactly those initial runs. Because no MFT is
           bound yet, attribute lists are not dereferenced at this point.
        3. Walk the ``$ATTRIBUTE_LIST`` in stored order. Each ``$DATA`` entry references another MFT record,
           which must be reachable through the runs confirmed so far. Its runs are appended before the next
           entry is considered, so reachability is established one fragment at a time.

        The attribute list is parsed from the record bytes directly rather than through
        :attr:`MftRecord.attributes`, because that property eagerly dereferences every referenced record and
        would defeat the staged reachability checks.

        Raises:
            MftUnreachableError: If an attribute list entry references a record outside the confirmed range,
                if entries are ordered in a way that breaks incremental reachability, or if the references
                form a cycle. The error carries the failing stage and the confirmed VCN range at that point.
        """
        # Stage 1: only the single $MFT record pointed at by the boot sector is readable
        mft_offset = self.boot_sector.MftStartLcn * self.cluster_size
        mft_record = MftRecord.from_fh(self.fh, mft_offset, ntfs=self)

        # Stage 2: a temporary MFT covering only the runs described by the initial $MFT record.
        # self.mft is deliberately left unbound while scanning the record, so the cached
        # MftRecord.attributes property can not recursively dereference the attribute list yet.
        mft = Mft(mft_record.open(), ntfs=self)

        list_attribute = _find_attribute_header(mft_record, ATTRIBUTE_TYPE_CODE.ATTRIBUTE_LIST)
        if list_attribute is None:
            return mft
        list_offset, list_header = list_attribute

        data_entries = [
            entry
            for entry in _iter_attribute_list_entries(mft_record, list_offset, list_header, self.fh)
            if entry.AttributeTypeCode == ATTRIBUTE_TYPE_CODE.DATA
        ]

        # Stage 3: resolve $ATTRIBUTE_LIST entries in order, extending the confirmed range after each $DATA run.
        # Segment 0 is the initial record whose runs already back the temporary MFT. Its LowestVcn 0 entry is
        # the legitimate self-description of the first fragment; any later entry pointing back at an already
        # resolved segment adds no runs and is a circular dependency.
        initial_segment = mft_record.segment if mft_record.segment is not None else 0
        resolved_segments: set[int] = {initial_segment}
        previous_vcn = 0
        for stage, entry in enumerate(data_entries):
            segment = segment_reference(entry.SegmentReference)
            confirmed_clusters = _runlist_length(mft.fh.runlist)

            if segment == initial_segment and entry.LowestVcn == 0 and stage == 0:
                # The initial fragment is already part of the confirmed runs
                continue

            if segment in resolved_segments:
                # A self or mutual reference can never add new runs and would only loop back on itself
                raise MftUnreachableError(
                    f"Circular $ATTRIBUTE_LIST reference at stage {stage}: segment {segment} was already "
                    "used to describe part of the $MFT",
                    stage=stage,
                    segment=segment,
                    confirmed_runs=mft.fh.runlist,
                )

            if not _segment_in_runlist(mft.fh.runlist, segment, self._record_size, self.cluster_size):
                raise MftUnreachableError(
                    f"$ATTRIBUTE_LIST entry at stage {stage} references segment {segment}, which is outside "
                    f"the confirmed $MFT range of {confirmed_clusters} clusters; the referenced record must be "
                    "described by a previously confirmed run",
                    stage=stage,
                    segment=segment,
                    confirmed_runs=mft.fh.runlist,
                )

            if entry.LowestVcn < previous_vcn:
                raise MftUnreachableError(
                    f"$ATTRIBUTE_LIST entry at stage {stage} starts at VCN {entry.LowestVcn}, before the "
                    f"previously confirmed VCN {previous_vcn}; entries must be ordered so each extension is "
                    "reachable before it is referenced",
                    stage=stage,
                    segment=segment,
                    confirmed_runs=mft.fh.runlist,
                )

            try:
                extension_record = mft.get(segment)
            except MftUnreachableError as e:
                raise MftUnreachableError(
                    f"$ATTRIBUTE_LIST entry at stage {stage} references segment {segment}, but the record "
                    "could not be read through the currently confirmed runs",
                    stage=stage,
                    segment=segment,
                    confirmed_runs=mft.fh.runlist,
                ) from e
            extension_runs = _get_dataruns_from_record(extension_record)
            if not extension_runs:
                raise MftUnreachableError(
                    f"$ATTRIBUTE_LIST entry at stage {stage} references segment {segment}, which provides no "
                    "$DATA runs to extend the $MFT",
                    stage=stage,
                    segment=segment,
                    confirmed_runs=mft.fh.runlist,
                )

            mft.fh.runlist += extension_runs
            # The runlist now covers more of the $MFT stream; grow the stream size so the newly confirmed
            # records become readable. The original FileSize only describes the initial fragment.
            mft.fh.size = _runlist_length(mft.fh.runlist) * self.cluster_size
            resolved_segments.add(segment)
            previous_vcn = entry.LowestVcn

        return mft


def _runlist_length(runlist: list[tuple[int | None, int]]) -> int:
    """Return the total number of clusters described by a runlist, including sparse runs."""
    return sum(run_length for _, run_length in runlist)


def _segment_in_runlist(
    runlist: list[tuple[int | None, int]], segment: int, record_size: int, cluster_size: int
) -> bool:
    """Return whether the MFT record at ``segment`` is fully inside the cluster range covered by ``runlist``.

    The runlist is interpreted in VCN order, so this only checks the logical length of the confirmed
    ``$MFT`` stream: a record whose offset is below that length is readable through the confirmed runs.
    """
    record_offset = segment * record_size
    record_end = record_offset + record_size
    confirmed_bytes = _runlist_length(runlist) * cluster_size
    return record_end <= confirmed_bytes


def _iter_record_attributes(record: MftRecord) -> Iterator[tuple[int, AttributeHeader]]:
    """Yield ``(offset, AttributeHeader)`` pairs by scanning a record's raw bytes.

    Unlike :attr:`MftRecord.attributes`, this never dereferences an ``$ATTRIBUTE_LIST`` and therefore stays
    safe to use while the ``$MFT`` is only partially confirmed.
    """
    fh = BytesIO(record.data)
    offset = record.header.FirstAttributeOffset
    while True:
        try:
            header = AttributeHeader(fh, offset, record)
        except EOFError:
            return

        if header.type == ATTRIBUTE_TYPE_CODE.END or header.record_length == 0:
            return

        yield offset, header
        offset += header.record_length


def _find_attribute_header(
    record: MftRecord, attr_type: ATTRIBUTE_TYPE_CODE
) -> tuple[int, AttributeHeader] | None:
    """Return the offset and header of the first attribute with the given type, without dereferencing lists."""
    for offset, header in _iter_record_attributes(record):
        if header.type == attr_type:
            return offset, header
    return None


def _iter_attribute_list_entries(
    record: MftRecord, list_offset: int, list_header: AttributeHeader, volume_fh: BinaryIO
) -> Iterator[c_ntfs._ATTRIBUTE_LIST_ENTRY]:
    """Yield the entries of an ``$ATTRIBUTE_LIST`` attribute without binding or dereferencing an MFT.

    A non-resident list is read straight from the volume through the header's dataruns. The normal
    :meth:`AttributeHeader.open` path refuses non-resident attributes when no volume is bound, which is
    precisely the state during the earliest bootstrap stages, so the volume is wired through explicitly here.
    """
    if list_header.resident:
        value_offset = list_offset + list_header.header.Form.Resident.ValueOffset
        value_length = list_header.header.Form.Resident.ValueLength
        list_data = record.data[value_offset : value_offset + value_length]
    else:
        list_data = RunlistStream(
            volume_fh,
            list_header.dataruns(),
            list_header.size,
            record.ntfs.cluster_size,
        ).read(list_header.size)

    offset = 0
    while offset < len(list_data):
        entry = c_ntfs._ATTRIBUTE_LIST_ENTRY(BytesIO(list_data[offset:]))
        if entry.RecordLength == 0:
            break
        yield entry
        offset += entry.RecordLength


def _get_dataruns_from_record(record: MftRecord) -> list[tuple[int | None, int]]:
    """Collect the non-resident ``$DATA`` runs of an MFT record, ordered by lowest VCN."""
    data_headers = [
        header
        for _, header in _iter_record_attributes(record)
        if header.type == ATTRIBUTE_TYPE_CODE.DATA and not header.resident
    ]
    data_headers.sort(key=lambda header: header.lowest_vcn)

    runs: list[tuple[int | None, int]] = []
    for header in data_headers:
        runs += header.dataruns()
    return runs
