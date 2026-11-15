from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.clfs.c_clfs import BlockHeader, c_clfs

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.clfs.blf import Container, Stream

# Ambiguity kinds reported by StreamReadPlan
DUPLICATE_CLIENT_ID = "duplicate_client_id"
MISSING_CLIENT_CONTEXT = "missing_client_context"
MISSING_CONTAINER_CONTEXT = "missing_container_context"
BLOCK_IDENTITY_CONFLICT = "block_identity_conflict"


class StreamBlock(NamedTuple):
    """On-disk identity of a single log block.

    The ``client_id`` is the client declaration stored in the log block header itself and is the
    only on-block evidence that ties the records inside the block to a client stream.
    """

    offset: int
    client_id: int
    container_id: int
    current_lsn: int
    next_lsn: int


class StreamBoundaries(NamedTuple):
    """Raw LSN values of a single stream.

    Every LSN keeps its own role. They are deliberately *not* collapsed into a single read
    start/end pair: ``lsn_base`` and ``lsn_archive_tail`` describe what may still be relevant for
    archival, while ``lsn_last`` and ``lsn_flush`` describe the volatile tail of the stream.
    """

    lsn_base: int
    lsn_last: int
    lsn_flush: int
    lsn_archive_tail: int


class RawRecord(NamedTuple):
    """A raw record as stored inside a log block.

    The record data is returned uninterpreted; dissect.clfs does not explain transaction
    contents on behalf of the application.
    """

    offset: int
    header: c_clfs.RECORD_HEADER
    data: bytes


class Ambiguity(NamedTuple):
    """A reported ambiguity that prevents definitive attribution of blocks to a stream."""

    kind: str
    client_id: int | None
    offsets: tuple[int, ...]
    detail: str


class StreamPlan(NamedTuple):
    """Read plan for a single stream: its client context, raw boundaries and owned blocks."""

    stream: Stream
    boundaries: StreamBoundaries
    blocks: tuple[StreamBlock, ...]


def block_identity(fh: BinaryIO, offset: int) -> StreamBlock:
    """Read the on-block identity of the log block at ``offset``.

    Args:
        fh: A file-like object of a container file.
        offset: Offset of the log block within the container.
    """
    header = BlockHeader(fh=fh, offset=offset).header
    return StreamBlock(
        offset=offset,
        client_id=header.ClientId,
        container_id=header.CurrentLsn.Offset.ContainerId,
        current_lsn=header.CurrentLsn.PhysicalOffset,
        next_lsn=header.NextLsn.PhysicalOffset,
    )


def read_block_records(fh: BinaryIO, offset: int) -> Iterator[RawRecord]:
    """Yield all raw records stored in the log block at ``offset`` without interpreting them.

    Args:
        fh: A file-like object of a container file.
        offset: Offset of the log block within the container.
    """
    log_block = BlockHeader(fh=fh, offset=offset)
    buf = log_block.open()

    for record_offset in log_block.header.RecordOffsets:
        if record_offset == 0:
            break

        buf.seek(record_offset)
        header = c_clfs.RECORD_HEADER(buf)
        data = buf.read(max(header.DataSize - header.Offset, 0))

        yield RawRecord(offset=offset + record_offset, header=header, data=data)


class StreamReadPlan:
    """Stream-level read plan for a (multiplexed) BLF.

    A BLF can hold multiple client streams that share the same physical log segments. This plan
    ties three sources of evidence together before any record is attributed to a stream:

    - the client contexts from the base record (``streams``),
    - the container contexts from the base record (``containers``),
    - the client declaration stored in every log block header (``blocks``).

    A block is only used as definitive evidence for a stream when its client declaration
    unambiguously matches exactly one client context and the block itself is not contested.
    Anything else is reported through ``ambiguities`` and the involved blocks are withheld from
    every stream, so records of another client are never handed to the current investigation.

    Args:
        streams: Client contexts as parsed from the base record.
        containers: Container contexts as parsed from the base record.
        blocks: On-disk identities of the log blocks in the physical log segments.
    """

    def __init__(self, streams: Iterable[Stream], containers: Iterable[Container], blocks: Iterable[StreamBlock]):
        self.streams = list(streams)
        self.containers = list(containers)
        self.blocks = list(blocks)

        self.ambiguities: list[Ambiguity] = []
        self.unassigned_blocks: list[StreamBlock] = []

        # Client ids declared by more than one client context cannot be used as evidence
        client_id_counts = Counter(stream.id for stream in self.streams)
        contested_client_ids = set()
        for client_id, count in client_id_counts.items():
            if count > 1:
                contested_client_ids.add(client_id)
                self.ambiguities.append(
                    Ambiguity(
                        kind=DUPLICATE_CLIENT_ID,
                        client_id=client_id,
                        offsets=(),
                        detail=f"{count} client contexts share client id {client_id}",
                    )
                )

        # Blocks at the same offset with conflicting declarations contest each other
        blocks_by_offset: dict[int, list[StreamBlock]] = {}
        for block in self.blocks:
            blocks_by_offset.setdefault(block.offset, []).append(block)

        contested_offsets = set()
        for offset, blocks_at_offset in blocks_by_offset.items():
            identities = {(block.client_id, block.container_id, block.current_lsn) for block in blocks_at_offset}
            if len(identities) > 1:
                contested_offsets.add(offset)
                client_ids = sorted({block.client_id for block in blocks_at_offset})
                self.ambiguities.append(
                    Ambiguity(
                        kind=BLOCK_IDENTITY_CONFLICT,
                        client_id=None,
                        offsets=(offset,),
                        detail=f"conflicting block declarations at offset {offset:#x}: client ids {client_ids}",
                    )
                )

        container_ids = {container.id for container in self.containers}

        assigned: dict[int, list[StreamBlock]] = {}
        seen_identities = set()
        for block in self.blocks:
            identity = (block.offset, block.client_id, block.container_id, block.current_lsn)
            if identity in seen_identities:
                continue
            seen_identities.add(identity)

            if block.offset in contested_offsets or block.client_id in contested_client_ids:
                self.unassigned_blocks.append(block)
            elif block.client_id not in client_id_counts:
                self.unassigned_blocks.append(block)
                self.ambiguities.append(
                    Ambiguity(
                        kind=MISSING_CLIENT_CONTEXT,
                        client_id=block.client_id,
                        offsets=(block.offset,),
                        detail=f"block at offset {block.offset:#x} declares client id {block.client_id} "
                        "but no client context exists for it",
                    )
                )
            elif container_ids and block.container_id not in container_ids:
                self.unassigned_blocks.append(block)
                self.ambiguities.append(
                    Ambiguity(
                        kind=MISSING_CONTAINER_CONTEXT,
                        client_id=block.client_id,
                        offsets=(block.offset,),
                        detail=f"block at offset {block.offset:#x} belongs to container {block.container_id} "
                        "but no container context exists for it",
                    )
                )
            else:
                assigned.setdefault(block.client_id, []).append(block)

        self.plans: dict[int, StreamPlan] = {}
        for stream in self.streams:
            if stream.id in contested_client_ids or stream.id in self.plans:
                continue
            self.plans[stream.id] = StreamPlan(
                stream=stream,
                boundaries=StreamBoundaries(
                    lsn_base=stream.lsn_base,
                    lsn_last=stream.lsn_last,
                    lsn_flush=stream.lsn_flush,
                    lsn_archive_tail=stream.lsn_archive_tail,
                ),
                blocks=tuple(sorted(assigned.get(stream.id, []), key=lambda block: block.offset)),
            )

    def plan_for(self, client_id: int) -> StreamPlan | None:
        """Return the definitive read plan for ``client_id``, or ``None`` if it is ambiguous."""
        return self.plans.get(client_id)

    def records(self, fh: BinaryIO, client_id: int) -> Iterator[RawRecord]:
        """Yield the raw records that definitively belong to the stream ``client_id``.

        Only records from blocks whose client declaration unambiguously matches the stream are
        yielded. The records are returned uninterpreted.

        Args:
            fh: A file-like object of a container file.
            client_id: The client id of the stream to read.
        """
        plan = self.plan_for(client_id)
        if plan is None:
            return

        for block in plan.blocks:
            yield from read_block_records(fh, block.offset)
