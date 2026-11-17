"""Read-only QCOW2 cluster occupancy audit.

This module implements a forensic, strictly read-only cross-check of a QCOW2
image's cluster bookkeeping. It reads the refcount table and refcount blocks
(decoding entries of ``2 ** refcount_order`` bits), walks the active L1/L2
tables and explicitly selected internal snapshots, and correlates both views
per host cluster.

Key properties:

- Nothing is ever written back to the image; no refcounts are "repaired".
- The ``QCOW_OFLAG_COPIED`` bit is treated as a hint only, never as a
  substitute for the actual refcount.
- Roots that are not traversed (unselected snapshots) are recorded as
  coverage limitations instead of being silently ignored.
- Clusters that are referenced but have a zero refcount are reported with
  both sides of the evidence: the referencing entry and the exact refcount
  bit location.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING

from dissect.hypervisor.disk.c_qcow2 import c_qcow2
from dissect.hypervisor.exceptions import Error

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.hypervisor.disk.qcow2 import QCow2, QCow2Snapshot

# Default refcount_order for version 2 images, which do not store it (qemu uses 4, i.e. 16-bit entries)
DEFAULT_REFCOUNT_ORDER = 4

VALID_REFCOUNT_WIDTHS = (1, 2, 4, 8, 16, 32, 64)

ACTIVE_ROOT = "active"


class ClusterKind(enum.Enum):
    """The kind of a cluster reference."""

    METADATA = "metadata"
    DATA = "data"
    COMPRESSED = "compressed"


class Occupancy(enum.Enum):
    """Occupancy classification of a single host cluster."""

    FREE = "free"  # no references, refcount 0
    EXCLUSIVE = "exclusive"  # exactly one reference, refcount 1
    SHARED = "shared"  # multiple references, refcount matches
    CONTRADICTORY = "contradictory"  # referenced, but refcount is 0
    MISMATCH = "mismatch"  # referenced, but refcount != number of references
    UNREFERENCED = "unreferenced"  # refcount > 0, no reference found, full coverage (leaked)
    UNACCOUNTED = "unaccounted"  # refcount > 0, no reference found, coverage limited


@dataclass(frozen=True)
class RefcountLocation:
    """Exact location of the refcount bits for a cluster.

    Attributes:
        table_index: Index into the refcount table.
        block_offset: File offset of the refcount block (``None`` if the table entry is out of range).
        block_index: Index of the entry within the refcount block.
        byte_offset: Byte offset of the entry within the refcount block.
        bit_offset: Bit offset of the entry within :attr:`byte_offset` (counted from the most significant bit).
        width: Width of the entry in bits (``2 ** refcount_order``).
    """

    table_index: int
    block_offset: int | None
    block_index: int
    byte_offset: int
    bit_offset: int
    width: int

    def __str__(self) -> str:
        if self.block_offset is None:
            return f"refcount table[{self.table_index}] (out of range)"
        return (
            f"refcount table[{self.table_index}] -> block @ {self.block_offset:#x}, "
            f"byte {self.byte_offset}, bit {self.bit_offset}, width {self.width}"
        )


@dataclass(frozen=True)
class Reference:
    """A single reference to a host cluster.

    Attributes:
        kind: Whether the cluster holds metadata, normal data or compressed data.
        root: The view that references the cluster (``active`` or ``snapshot:<id>``).
        entry: Human-readable pointer to the referencing entry (e.g. ``L2[3] (L1[0], L2 @ 0x200)``).
        copied: State of the ``QCOW_OFLAG_COPIED`` bit for data references (hint only), ``None`` otherwise.
    """

    kind: ClusterKind
    root: str
    entry: str
    copied: bool | None = None


@dataclass
class ClusterFinding:
    """Audit outcome for a single host cluster."""

    cluster: int
    offset: int
    refcount: int
    location: RefcountLocation
    references: list[Reference]
    occupancy: Occupancy
    notes: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    """Result of a read-only cluster occupancy audit."""

    refcount_order: int
    refcount_width: int
    cluster_bits: int
    clusters_examined: int
    roots_traversed: list[str]
    roots_untraversed: list[str]
    coverage_complete: bool
    notes: list[str]
    findings: list[ClusterFinding]

    def summary(self) -> dict[Occupancy, int]:
        """Count findings per occupancy class."""
        counts: dict[Occupancy, int] = {}
        for finding in self.findings:
            counts[finding.occupancy] = counts.get(finding.occupancy, 0) + 1
        return counts


class RefcountTable:
    """Read-only view over the refcount table and refcount blocks of a QCOW2 image.

    Refcount entries are ``2 ** refcount_order`` bits wide and packed most-significant-bit
    first within big-endian 64-bit words, as stored on disk.
    """

    def __init__(self, qcow2: QCow2):
        self.qcow2 = qcow2

        self.order = qcow2.header.refcount_order if qcow2.header.version >= 3 else DEFAULT_REFCOUNT_ORDER
        self.width = 1 << self.order
        if self.width not in VALID_REFCOUNT_WIDTHS:
            raise Error(f"Unsupported refcount width: {self.width} (refcount_order = {self.order})")

        self.entries_per_word = 64 // self.width
        self.entries_per_block = (qcow2.cluster_size * 8) // self.width

        table_size = qcow2.header.refcount_table_clusters << qcow2.cluster_bits
        qcow2.fh.seek(qcow2.header.refcount_table_offset)
        self.entries: list[int] = list(c_qcow2.uint64[table_size // 8](qcow2.fh)) if table_size else []

        self._block = lru_cache(maxsize=64)(self._read_block)

    def _read_block(self, table_index: int) -> bytes | None:
        offset = self.entries[table_index]
        if not offset:
            return None
        self.qcow2.fh.seek(offset)
        return self.qcow2.fh.read(self.qcow2.cluster_size)

    def locate(self, cluster_index: int) -> RefcountLocation:
        """Return the exact on-disk location of the refcount bits for ``cluster_index``."""
        table_index, block_index = divmod(cluster_index, self.entries_per_block)
        block_offset = self.entries[table_index] if table_index < len(self.entries) else None
        bit_position = block_index * self.width
        return RefcountLocation(
            table_index=table_index,
            block_offset=block_offset,
            block_index=block_index,
            byte_offset=bit_position // 8,
            bit_offset=bit_position % 8,
            width=self.width,
        )

    def get(self, cluster_index: int) -> int:
        """Return the refcount for ``cluster_index`` (0 if no refcount block covers it)."""
        location = self.locate(cluster_index)
        if not location.block_offset:
            return 0

        block = self._block(location.table_index)
        if block is None:
            return 0

        word_index, entry_in_word = divmod(location.block_index, self.entries_per_word)
        word = int.from_bytes(block[word_index * 8 : (word_index + 1) * 8], "big")
        shift = 64 - self.width * (entry_in_word + 1)
        return (word >> shift) & ((1 << self.width) - 1)


class QCow2Auditor:
    """Read-only cluster occupancy auditor for a single QCOW2 image.

    Args:
        qcow2: The :class:`~dissect.hypervisor.disk.qcow2.QCow2` image to audit.
        snapshots: Snapshot ids to explicitly include in the reference walk.
            Snapshots that are not selected are recorded as coverage limitations.
    """

    def __init__(self, qcow2: QCow2, snapshots: Iterable[str] = ()):
        self.qcow2 = qcow2
        self.refcounts = RefcountTable(qcow2)

        self.references: dict[int, list[Reference]] = {}
        self.notes: list[str] = []
        self.roots_traversed: list[str] = []
        self.roots_untraversed: list[str] = []

        selected = {str(snapshot_id) for snapshot_id in snapshots}
        known = {snapshot.id for snapshot in qcow2.snapshots}
        unknown = selected - known
        if unknown:
            raise Error(f"Unknown snapshot id(s): {', '.join(sorted(unknown))}")
        self.selected_snapshots = [snapshot for snapshot in qcow2.snapshots if snapshot.id in selected]

        if qcow2.has_subclusters:
            self.notes.append(
                "image uses extended L2 entries; subcluster allocation is reported at cluster granularity"
            )
        if qcow2.has_data_file:
            self.notes.append("image uses an external data file; data cluster references use guest offsets")

    def run(self) -> AuditReport:
        """Perform the audit and return the report. Only reads from the image."""
        self._walk_metadata()
        self._walk_root(ACTIVE_ROOT, self.qcow2.l1_table, self.qcow2.header.l1_size)
        self.roots_traversed.append(ACTIVE_ROOT)

        for snapshot in self.selected_snapshots:
            self._walk_snapshot(snapshot)

        selected_ids = {snapshot.id for snapshot in self.selected_snapshots}
        self.roots_untraversed = [
            f"snapshot:{snapshot.id}" for snapshot in self.qcow2.snapshots if snapshot.id not in selected_ids
        ]
        coverage_complete = not self.roots_untraversed

        findings = self._classify(coverage_complete)
        return AuditReport(
            refcount_order=self.refcounts.order,
            refcount_width=self.refcounts.width,
            cluster_bits=self.qcow2.cluster_bits,
            clusters_examined=len(findings),
            roots_traversed=self.roots_traversed,
            roots_untraversed=self.roots_untraversed,
            coverage_complete=coverage_complete,
            notes=self.notes,
            findings=findings,
        )

    def _add_reference(
        self, cluster: int, kind: ClusterKind, root: str, entry: str, copied: bool | None = None
    ) -> None:
        self.references.setdefault(cluster, []).append(Reference(kind=kind, root=root, entry=entry, copied=copied))

    def _add_metadata_span(self, offset: int, size: int, root: str, entry: str) -> None:
        if size <= 0:
            return
        cluster_bits = self.qcow2.cluster_bits
        first = offset >> cluster_bits
        last = (offset + size - 1) >> cluster_bits
        for cluster in range(first, last + 1):
            self._add_reference(cluster, ClusterKind.METADATA, root, entry)

    def _walk_metadata(self) -> None:
        qcow2 = self.qcow2
        cluster_bits = qcow2.cluster_bits

        self._add_reference(0, ClusterKind.METADATA, ACTIVE_ROOT, "header")

        self._add_metadata_span(
            qcow2.header.l1_table_offset,
            qcow2.header.l1_size * 8,
            ACTIVE_ROOT,
            "L1 table (active)",
        )
        self._add_metadata_span(
            qcow2.header.refcount_table_offset,
            qcow2.header.refcount_table_clusters << cluster_bits,
            ACTIVE_ROOT,
            "refcount table",
        )
        for table_index, block_offset in enumerate(self.refcounts.entries):
            if block_offset:
                self._add_reference(
                    block_offset >> cluster_bits,
                    ClusterKind.METADATA,
                    ACTIVE_ROOT,
                    f"refcount block (refcount table[{table_index}])",
                )

        if qcow2.header.nb_snapshots and qcow2.snapshots:
            last = qcow2.snapshots[-1]
            end = last.offset + ((last.entry_size + 7) & ~7)
            self._add_metadata_span(
                qcow2.header.snapshots_offset,
                end - qcow2.header.snapshots_offset,
                ACTIVE_ROOT,
                "snapshot table",
            )

    def _walk_snapshot(self, snapshot: QCow2Snapshot) -> None:
        root = f"snapshot:{snapshot.id}"
        self._add_metadata_span(
            snapshot.header.l1_table_offset,
            snapshot.header.l1_size * 8,
            root,
            f"L1 table (snapshot '{snapshot.id}')",
        )
        self._walk_root(root, snapshot.l1_table, snapshot.header.l1_size)
        self.roots_traversed.append(root)

    def _walk_root(self, root: str, l1_table: list[int], l1_size: int) -> None:
        qcow2 = self.qcow2
        cluster_bits = qcow2.cluster_bits

        for l1_index in range(l1_size):
            l2_offset = l1_table[l1_index] & c_qcow2.L1E_OFFSET_MASK
            if not l2_offset:
                continue

            self._add_reference(
                l2_offset >> cluster_bits,
                ClusterKind.METADATA,
                root,
                f"L2 table (L1[{l1_index}] @ {l2_offset:#x})",
            )

            l2_table = qcow2.l2_table(l2_offset)
            for l2_index in range(qcow2.l2_size):
                entry = l2_table.entry(l2_index)
                if not entry:
                    continue

                desc = f"L2[{l2_index}] (L1[{l1_index}], L2 @ {l2_offset:#x})"
                if entry & c_qcow2.QCOW_OFLAG_COMPRESSED:
                    self._walk_compressed(root, entry, desc)
                elif entry & c_qcow2.L2E_OFFSET_MASK:
                    copied = bool(entry & c_qcow2.QCOW_OFLAG_COPIED)
                    if entry & c_qcow2.QCOW_OFLAG_ZERO:
                        desc += " (zero)"
                    host_offset = entry & c_qcow2.L2E_OFFSET_MASK
                    self._add_reference(host_offset >> cluster_bits, ClusterKind.DATA, root, desc, copied)
                elif qcow2.has_data_file and entry & c_qcow2.QCOW_OFLAG_COPIED:
                    # External data file: the host offset is the guest offset
                    guest_cluster = (l1_index << qcow2.l2_bits) | l2_index
                    self._add_reference(guest_cluster, ClusterKind.DATA, root, f"{desc} (external data file)", True)

    def _walk_compressed(self, root: str, entry: int, desc: str) -> None:
        qcow2 = self.qcow2
        cluster_bits = qcow2.cluster_bits

        coffset = entry & qcow2.cluster_offset_mask
        nb_csectors = ((entry >> qcow2.csize_shift) & qcow2.csize_mask) + 1
        csize = nb_csectors * c_qcow2.QCOW2_COMPRESSED_SECTOR_SIZE - (coffset & 511)

        first = coffset >> cluster_bits
        last = (coffset + csize - 1) >> cluster_bits
        for cluster in range(first, last + 1):
            self._add_reference(cluster, ClusterKind.COMPRESSED, root, desc)

    def _classify(self, coverage_complete: bool) -> list[ClusterFinding]:
        qcow2 = self.qcow2

        try:
            qcow2.fh.seek(0, 2)
            clusters_in_file = -(-qcow2.fh.tell() // qcow2.cluster_size)
        except (OSError, AttributeError):
            clusters_in_file = 0

        clusters = set(self.references)
        for cluster in range(clusters_in_file):
            if self.refcounts.get(cluster):
                clusters.add(cluster)

        findings = []
        for cluster in sorted(clusters):
            refcount = self.refcounts.get(cluster)
            references = self.references.get(cluster, [])
            notes = []

            if references and refcount == 0:
                occupancy = Occupancy.CONTRADICTORY
                notes.append(
                    f"referenced by {len(references)} entr{'ies' if len(references) != 1 else 'y'} "
                    f"but refcount is 0 at {self.refcounts.locate(cluster)}"
                )
            elif references:
                if refcount == len(references):
                    occupancy = Occupancy.EXCLUSIVE if refcount == 1 else Occupancy.SHARED
                else:
                    occupancy = Occupancy.MISMATCH
                    notes.append(f"refcount {refcount} != {len(references)} reference(s)")
            elif refcount > 0:
                if coverage_complete:
                    occupancy = Occupancy.UNREFERENCED
                    notes.append("refcount > 0 but no reference found in any traversed root (leaked cluster)")
                else:
                    occupancy = Occupancy.UNACCOUNTED
                    notes.append(
                        "refcount > 0 but no reference found; coverage is limited "
                        f"(untraversed roots: {', '.join(self.roots_untraversed)})"
                    )
            else:
                occupancy = Occupancy.FREE

            # The copied bit is only a hint; compare it against the actual refcount without acting on it
            for reference in references:
                if reference.copied is None:
                    continue
                if reference.copied and refcount != 1:
                    notes.append(f"copied bit set in {reference.entry} but refcount is {refcount} (hint only)")
                elif not reference.copied and refcount == 1:
                    notes.append(f"copied bit clear in {reference.entry} but refcount is 1 (hint only)")

            findings.append(
                ClusterFinding(
                    cluster=cluster,
                    offset=cluster << qcow2.cluster_bits,
                    refcount=refcount,
                    location=self.refcounts.locate(cluster),
                    references=references,
                    occupancy=occupancy,
                    notes=notes,
                )
            )

        return findings


def audit(qcow2: QCow2, snapshots: Iterable[str] = ()) -> AuditReport:
    """Run a read-only cluster occupancy audit on ``qcow2``.

    Args:
        qcow2: The image to audit.
        snapshots: Snapshot ids to explicitly include next to the active view.
    """
    return QCow2Auditor(qcow2, snapshots).run()


def render_text(report: AuditReport) -> str:
    """Render an :class:`AuditReport` as human-readable text."""
    lines = [
        f"refcount width: {report.refcount_width} bits (refcount_order = {report.refcount_order})",
        f"cluster size: 2**{report.cluster_bits} bytes",
        f"roots traversed: {', '.join(report.roots_traversed) or '(none)'}",
    ]
    if report.roots_untraversed:
        lines.append(f"coverage limited, untraversed roots: {', '.join(report.roots_untraversed)}")
    else:
        lines.append("coverage: complete")

    summary = report.summary()
    counts = ", ".join(
        f"{occupancy.value}={count}" for occupancy, count in sorted(summary.items(), key=lambda item: item[0].value)
    )
    lines.append(f"findings: {counts or 'none'}")

    for note in report.notes:
        lines.append(f"note: {note}")

    for finding in report.findings:
        if finding.occupancy == Occupancy.FREE:
            continue
        lines.append("")
        lines.append(
            f"cluster {finding.cluster} (@ {finding.offset:#x}): {finding.occupancy.value}, refcount={finding.refcount}"
        )
        lines.append(f"  refcount bits: {finding.location}")
        for reference in finding.references:
            copied = {None: "-", True: "1", False: "0"}[reference.copied]
            lines.append(
                f"  reference: {reference.kind.value} via {reference.root}: {reference.entry} (copied={copied})"
            )
        for note in finding.notes:
            lines.append(f"  note: {note}")

    return "\n".join(lines)
