"""Restricted hash-chain verification for sealed APFS volumes.

A sealed APFS volume does not rely on the per-object Fletcher-64 checksum for
its integrity. Instead, the volume's hashed B-trees are protected by a
Merkle-style hash chain:

* Every node of a hashed B-tree carries the ``BTNODE_HASHED`` flag and the
  tree itself carries the ``BTREE_HASHED`` flag.
* A non-leaf node stores, for each child, a ``btn_index_node_val`` record whose
  ``binv_child_hash`` field is the hash of the child node's full on-disk block,
  computed with the first ``MAX_CKSUM_SIZE`` bytes (the Fletcher checksum field)
  excluded.
* The hash of each tree's root node is anchored in the volume's integrity
  metadata object (``integrity_meta_phys``).

Only the four hash algorithms documented in the APFS reference are accepted:
SHA-256, SHA-512/256, SHA-384 and SHA-512.

A passing Fletcher-64 checksum is recorded for every inspected node but is
never treated as evidence that the seal is intact: an attacker who modifies a
node can simply recompute its Fletcher checksum, while the parent's stored hash
and the root anchor cannot be recomputed without the seal's hash chain.

This module can verify the internal consistency of the hash chain from the
on-disk integrity metadata alone. It only reports trust against an external
root digest when the caller explicitly supplies one. It never claims that the
machine's boot chain actually trusted the volume.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Literal

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.btree import BTree
from dissect.apfs.objects.btree_node import BTreeNode
from dissect.apfs.objects.integrity_meta import IntegrityMeta

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS
    from dissect.apfs.objects.omap import ObjectMap

#: Maximum number of blocks of integrity metadata we are willing to read to
#: reach the root hash. Layouts requiring more are reported as unknown.
MAX_INTEGRITY_META_BLOCKS = 8

#: Mapping of ``apfs_hash_type_t`` to (hashlib name, digest size).
_HASH_ALGORITHMS: dict[int, tuple[str, int]] = {
    int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA256): ("sha256", c_apfs.APFS_HASH_CCSHA256_SIZE),
    int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA512_256): ("sha512_256", c_apfs.APFS_HASH_CCSHA512_256_SIZE),
    int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA384): ("sha384", c_apfs.APFS_HASH_CCSHA384_SIZE),
    int(c_apfs.apfs_hash_type_t.APFS_HASH_SHA512): ("sha512", c_apfs.APFS_HASH_CCSHA512_SIZE),
}

_Q = struct.Struct("<Q")


class SealStatus(str, Enum):
    """Outcome of a seal verification attempt.

    Note that :attr:`VERIFIED` only means the hash chain matched a root digest
    (external or on-disk); it never implies the boot loader trusted the volume.
    """

    #: The full hash chain was walked and matched an explicit root digest.
    VERIFIED = "verified"

    #: The hash chain is internally consistent, but no trusted root digest was
    #: available to anchor it.
    INTERNAL_CONSISTENT = "internal_consistent"

    #: A hash in the chain (or the root anchor) did not match.
    INVALID = "invalid"

    #: A node was missing, an unsupported hash algorithm or layout was found, or
    #: the chain could not be walked completely. No volume-wide success may be
    #: reported.
    INCOMPLETE = "incomplete"

    #: The volume is not marked as a sealed volume.
    NOT_SEALED = "not_sealed"


@dataclass
class ChainFailure:
    """Where and why a hash-chain verification stopped."""

    layer: int
    kind: str
    message: str
    parent_address: int | None = None
    child_address: int | None = None
    child_oid: int | None = None


@dataclass
class CheckedNode:
    """A B-tree node that was actually inspected during verification."""

    address: int
    oid: int
    level: int
    is_leaf: bool
    computed_hash: bytes
    fletcher_valid: bool
    parent_address: int | None = None
    expected_hash: bytes | None = None


@dataclass
class HashChainReport:
    """Result of verifying a single hashed B-tree."""

    tree_name: str
    status: SealStatus
    root_address: int
    hash_algorithm: str | None
    root_hash: bytes | None
    anchor: bytes | None
    anchor_source: Literal["external", "integrity_meta", "none"]
    checked_nodes: list[CheckedNode] = field(default_factory=list)
    failure: ChainFailure | None = None

    @property
    def node_count(self) -> int:
        """The number of B-tree nodes that were inspected."""
        return len(self.checked_nodes)


@dataclass
class SealReport:
    """Result of verifying the seal of a volume."""

    status: SealStatus
    volume_name: str
    integrity_meta_oid: int
    seal_broken_flag: bool
    trees: list[HashChainReport] = field(default_factory=list)
    hash_algorithm: str | None = None
    failure: ChainFailure | None = None
    notes: list[str] = field(default_factory=list)

    #: Always ``False``: on-disk verification cannot prove what the boot chain
    #: trusted. Exposed as a field so callers cannot mistake the seal status for
    #: a boot-trust decision.
    trusted_at_boot: bool = False


def _new_hash(algorithm_name: str) -> hashlib._Hash:
    """Create a hashlib object, accepting both spellings of SHA-512/256."""
    try:
        return hashlib.new(algorithm_name)
    except ValueError:
        if algorithm_name == "sha512_256":
            return hashlib.new("sha512-256")
        raise


def _resolve_algorithm(hash_type: int) -> tuple[str, int] | None:
    """Resolve an ``apfs_hash_type_t`` value to a hashlib name and digest size."""
    return _HASH_ALGORITHMS.get(int(hash_type))


def compute_node_hash(block: bytes, algorithm_name: str) -> bytes:
    """Compute the seal hash of a B-tree node block.

    The first ``MAX_CKSUM_SIZE`` bytes (the ``obj_phys`` Fletcher checksum) are
    excluded from the hash input, which is equivalent to zeroing them as the
    reference implementation does.
    """
    digest = _new_hash(algorithm_name)
    digest.update(block[c_apfs.MAX_CKSUM_SIZE :])
    return digest.digest()


def verify_hash_chain(
    btree: BTree,
    hash_type: int,
    expected_root_hash: bytes | None = None,
    *,
    anchor_source: Literal["external", "integrity_meta", "none"] = "external",
    tree_name: str = "btree",
    omap: ObjectMap | None = None,
    oid: int = 0,
    xid: int | None = None,
) -> HashChainReport:
    """Verify the parent/child hash chain of a hashed B-tree.

    The walk starts at the root node. For every non-leaf node, each
    ``btn_index_node_val`` record must name a child whose actual block hash
    equals the record's ``binv_child_hash``. The root node's own hash is then
    compared to ``expected_root_hash``.

    Args:
        btree: The B-tree to verify.
        hash_type: The ``apfs_hash_type_t`` value from the integrity metadata.
        expected_root_hash: Optional trusted hash of the root node. When
            ``None``, only internal chain consistency is reported.
        anchor_source: Where ``expected_root_hash`` came from. ``"external"``
            for a caller-supplied trusted root, ``"integrity_meta"`` for the
            on-disk integrity metadata, ``"none"`` when no anchor exists.
        tree_name: Human-readable name used in the report.
        omap: Object map required to resolve virtual child OIDs (sealed root
            trees). Physical trees pass ``None``.
        oid: Base OID for virtual child resolution.
        xid: Transaction ID for virtual child resolution.

    Returns:
        A :class:`HashChainReport` describing every node inspected and the
        first mismatch or structural problem encountered.
    """
    root = btree.root
    report = HashChainReport(
        tree_name=tree_name,
        status=SealStatus.INCOMPLETE,
        root_address=root.address,
        hash_algorithm=None,
        root_hash=None,
        anchor=expected_root_hash,
        anchor_source=anchor_source if expected_root_hash is not None else "none",
    )

    algorithm = _resolve_algorithm(hash_type)
    if algorithm is None:
        report.failure = ChainFailure(
            layer=root.level,
            kind="unsupported_hash_algorithm",
            message=f"Unsupported apfs_hash_type_t value {int(hash_type)}; no seal hash can be computed",
            parent_address=root.address,
        )
        return report

    algorithm_name, hash_size = algorithm
    report.hash_algorithm = algorithm_name

    if c_apfs.BTREE.HASHED not in btree.flags:
        report.failure = ChainFailure(
            layer=root.level,
            kind="unknown_layout",
            message=f"B-tree {tree_name!r} is not marked BTREE_HASHED; it has no seal hash chain to verify",
            parent_address=root.address,
        )
        return report

    if btree._node_size != btree.container.block_size:
        report.failure = ChainFailure(
            layer=root.level,
            kind="unknown_layout",
            message=(
                f"Multi-block B-tree nodes are not supported (node size {btree._node_size} != "
                f"block size {btree.container.block_size})"
            ),
            parent_address=root.address,
        )
        return report

    if expected_root_hash is not None and len(expected_root_hash) != hash_size:
        report.failure = ChainFailure(
            layer=root.level,
            kind="bad_anchor",
            message=(
                f"Expected root hash has length {len(expected_root_hash)}, "
                f"but {algorithm_name} digests have length {hash_size}"
            ),
            parent_address=root.address,
        )
        return report

    @dataclass
    class _Pending:
        node: BTreeNode
        parent_address: int | None
        expected_hash: bytes | None
        depth: int

    stack: list[_Pending] = [_Pending(root, None, expected_root_hash, 0)]

    while stack:
        pending = stack.pop()
        node = pending.node
        block = node.block

        if c_apfs.BTNODE.HASHED not in node.flags:
            report.failure = ChainFailure(
                layer=node.level,
                kind="unknown_layout",
                message=f"Node at address {node.address} lacks BTNODE_HASHED; cannot place it in a seal hash chain",
                parent_address=pending.parent_address,
                child_address=node.address,
            )
            return report

        if len(block) != btree._node_size:
            report.failure = ChainFailure(
                layer=node.level,
                kind="unknown_layout",
                message=(
                    f"Node at address {node.address} spans {len(block)} bytes, expected {btree._node_size}; "
                    "multi-block nodes are not supported"
                ),
                parent_address=pending.parent_address,
                child_address=node.address,
            )
            return report

        digest = compute_node_hash(block, algorithm_name)
        report.checked_nodes.append(
            CheckedNode(
                address=node.address,
                oid=node.oid,
                level=node.level,
                is_leaf=node.is_leaf,
                computed_hash=digest,
                fletcher_valid=node.is_valid(),
                parent_address=pending.parent_address,
                expected_hash=pending.expected_hash,
            )
        )

        if pending.expected_hash is not None and not hmac.compare_digest(digest, pending.expected_hash):
            if pending.parent_address is None:
                message = (
                    f"Root node hash {digest.hex()} does not match the {report.anchor_source} anchor "
                    f"{pending.expected_hash.hex()}"
                )
            else:
                message = (
                    f"Child node at level {node.level} (address {node.address}) hash {digest.hex()} does not match "
                    f"the hash stored by its parent (address {pending.parent_address}): "
                    f"{pending.expected_hash.hex()}"
                )
            report.failure = ChainFailure(
                layer=node.level,
                kind="hash_mismatch",
                message=message,
                parent_address=pending.parent_address,
                child_address=node.address,
                child_oid=node.oid,
            )
            report.status = SealStatus.INVALID
            return report

        if node.is_leaf:
            continue

        for idx in range(node.nkeys):
            raw_value = btree._read_value(node, idx)
            if len(raw_value) < c_apfs.MAX_CKSUM_SIZE + hash_size:
                report.failure = ChainFailure(
                    layer=node.level,
                    kind="unknown_layout",
                    message=(
                        f"Non-leaf value {idx} at address {node.address} is {len(raw_value)} bytes, too small to "
                        f"hold a child OID and {algorithm_name} hash ({8 + hash_size} bytes required)"
                    ),
                    parent_address=node.address,
                )
                return report

            child_oid = _Q.unpack_from(raw_value, 0)[0]
            child_hash = bytes(raw_value[c_apfs.MAX_CKSUM_SIZE : c_apfs.MAX_CKSUM_SIZE + hash_size])

            try:
                child_node = btree._node_child(node, idx, omap, oid, xid)
            except (OSError, EOFError, KeyError, ValueError) as exc:
                report.failure = ChainFailure(
                    layer=node.level,
                    kind="missing_node",
                    message=(
                        f"Child {idx} (oid {child_oid}) of node at address {node.address} could not be read: "
                        f"{exc.__class__.__name__}: {exc}"
                    ),
                    parent_address=node.address,
                    child_oid=child_oid,
                )
                return report

            stack.append(_Pending(child_node, node.address, child_hash, pending.depth + 1))

    report.root_hash = report.checked_nodes[0].computed_hash if report.checked_nodes else None

    if expected_root_hash is None:
        report.status = SealStatus.INTERNAL_CONSISTENT
    else:
        report.status = SealStatus.VERIFIED

    return report


def _read_integrity_meta_root_hash(
    integrity_meta: IntegrityMeta, hash_size: int
) -> tuple[bytes | None, str | None]:
    """Read the on-disk root hash from an integrity metadata object.

    Returns ``(root_hash, note)``. ``root_hash`` is ``None`` when the layout is
    absent or cannot be parsed; ``note`` explains why.
    """
    offset = integrity_meta.object.im_root_hash_offset
    if offset == 0:
        return None, "Integrity metadata has no root hash (im_root_hash_offset == 0); chain cannot be anchored on disk"

    container = integrity_meta.container
    block_size = container.block_size
    blocks_needed = (offset + hash_size + block_size - 1) // block_size
    if blocks_needed > MAX_INTEGRITY_META_BLOCKS:
        return None, (
            f"Root hash at offset {offset} needs {blocks_needed} integrity metadata blocks, "
            f"exceeding the supported limit of {MAX_INTEGRITY_META_BLOCKS}"
        )

    try:
        data = container._read_block(integrity_meta.address, blocks_needed)
    except OSError as exc:
        return None, f"Integrity metadata could not be read fully: {exc}"

    if offset + hash_size > len(data):
        return None, (
            f"Root hash window [offset={offset}, size={hash_size}] is outside the integrity metadata object "
            f"({len(data)} bytes readable)"
        )

    return bytes(data[offset : offset + hash_size]), None


def verify_volume_seal(fs: FS, *, trusted_root: bytes | None = None) -> SealReport:
    """Verify the seal hash chains of a sealed volume.

    The check is deliberately restricted to the documented sealed structures:
    the volume's root file-system B-tree and, when present, its sealed file
    extent (fext) B-tree.

    Args:
        fs: The sealed volume (an :class:`~dissect.apfs.objects.fs.FS`).
        trusted_root: Optional caller-supplied trusted hash of the root tree's
            root node. When omitted, only internal consistency against the
            on-disk integrity metadata is reported.

    Returns:
        A :class:`SealReport`. Missing nodes, unsupported hash algorithms and
        unknown layouts always produce a non-success status; a successful
        report never claims the volume was trusted at boot.
    """
    volume_name = getattr(fs, "name", "<unknown>")
    report = SealReport(
        status=SealStatus.INCOMPLETE,
        volume_name=volume_name,
        integrity_meta_oid=0,
        seal_broken_flag=False,
    )

    if not fs.is_sealed:
        report.status = SealStatus.NOT_SEALED
        report.notes.append("Volume does not have the SEALED_VOLUME incompatible feature; there is no seal to verify")
        return report

    integrity_meta_oid = fs.object.apfs_integrity_meta_oid
    report.integrity_meta_oid = integrity_meta_oid
    if not integrity_meta_oid:
        report.failure = ChainFailure(
            layer=-1,
            kind="missing_integrity_metadata",
            message="Sealed volume has no apfs_integrity_meta_oid; seal cannot be verified",
        )
        return report

    try:
        integrity_meta = IntegrityMeta.from_address(fs.container, integrity_meta_oid)
    except (OSError, EOFError, ValueError) as exc:
        report.failure = ChainFailure(
            layer=-1,
            kind="missing_integrity_metadata",
            message=f"Integrity metadata object (oid {integrity_meta_oid}) could not be read: {exc}",
            child_oid=integrity_meta_oid,
        )
        return report

    report.seal_broken_flag = bool(integrity_meta.object.im_flags & c_apfs.APFS_SEAL_BROKEN)
    if report.seal_broken_flag:
        report.failure = ChainFailure(
            layer=-1,
            kind="seal_broken",
            message=(
                f"Integrity metadata marks the seal broken at xid {integrity_meta.object.im_broken_xid} "
                "(APFS_SEAL_BROKEN)"
            ),
        )
        report.status = SealStatus.INVALID
        return report

    algorithm = _resolve_algorithm(integrity_meta.object.im_hash_type)
    if algorithm is None:
        report.failure = ChainFailure(
            layer=-1,
            kind="unsupported_hash_algorithm",
            message=(
                f"Integrity metadata uses unsupported apfs_hash_type_t value "
                f"{int(integrity_meta.object.im_hash_type)}"
            ),
        )
        return report

    algorithm_name, hash_size = algorithm
    report.hash_algorithm = algorithm_name

    on_disk_root, note = _read_integrity_meta_root_hash(integrity_meta, hash_size)
    if note:
        report.notes.append(note)

    root_anchor = trusted_root if trusted_root is not None else on_disk_root
    anchor_source: Literal["external", "integrity_meta", "none"]
    if trusted_root is not None:
        anchor_source = "external"
    elif on_disk_root is not None:
        anchor_source = "integrity_meta"
    else:
        anchor_source = "none"

    root_tree = fs.root_tree
    root_report = verify_hash_chain(
        root_tree,
        integrity_meta.object.im_hash_type,
        root_anchor,
        anchor_source=anchor_source,
        tree_name="root_tree",
        omap=fs.omap,
        oid=fs.object.apfs_root_tree_oid,
        xid=fs.xid,
    )
    report.trees.append(root_report)

    if fs.object.apfs_fext_tree_oid:
        fext_report = verify_hash_chain(
            fs.fext_tree,
            integrity_meta.object.im_hash_type,
            None,
            anchor_source="none",
            tree_name="fext_tree",
        )
        report.trees.append(fext_report)
    else:
        report.notes.append("Volume has no sealed file extent (fext) tree; only the root tree was checked")

    report.notes.append(
        "Per-node Fletcher-64 checksums were recorded but are not evidence of seal integrity; "
        "only the parent/child hash chain and root anchor are"
    )

    failing = next((tree for tree in report.trees if tree.status == SealStatus.INVALID), None)
    incomplete = next((tree for tree in report.trees if tree.status == SealStatus.INCOMPLETE), None)

    if failing is not None:
        report.status = SealStatus.INVALID
        report.failure = failing.failure
    elif incomplete is not None:
        report.status = SealStatus.INCOMPLETE
        report.failure = incomplete.failure
    elif trusted_root is not None and root_report.status == SealStatus.VERIFIED:
        report.status = SealStatus.VERIFIED
        report.notes.append(
            "Root tree hash matched the caller-supplied trusted root; this does not prove the boot chain "
            "trusted the volume"
        )
    else:
        report.status = SealStatus.INTERNAL_CONSISTENT
        report.notes.append(
            "Hash chains are internally consistent but were only anchored by on-disk (unauthenticated) data; "
            "supply a trusted root to obtain an externally anchored result"
        )

    return report
