from __future__ import annotations

import io
import logging
import os
from dataclasses import dataclass
from enum import IntFlag
from functools import cached_property
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util import ts
from dissect.util.hash.crc32c import crc32c

from dissect.xfs.c_xfs import XFS_NULL, c_xfs

if TYPE_CHECKING:
    from datetime import datetime
    from typing import BinaryIO

    from dissect.xfs.xfs import XFS

# dquot and header checksums are stored little endian even though the rest of
# the on-disk quota structures are big endian. The shared cstruct instance is
# big endian, so CRC fields are decoded from the raw bytes with this one.
c_xfs_le = cstruct(endian="<")

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_XFS", "CRITICAL"))


class QuotaType:
    """The three dquot identities XFS keeps in separate quota files."""

    USER = "user"
    GROUP = "group"
    PROJECT = "project"

    _ALL = (USER, GROUP, PROJECT)

    # Maps the public name to (on-disk d_flags value, superblock inode field).
    _DISK_FLAG = {
        USER: c_xfs.XFS_DQTYPE_USER,
        GROUP: c_xfs.XFS_DQTYPE_GROUP,
        PROJECT: c_xfs.XFS_DQTYPE_PROJ,
    }

    _INODE_FIELD = {
        USER: "sb_uquotino",
        GROUP: "sb_gquotino",
        PROJECT: "sb_pquotino",
    }


class QuotaPolicyFlag(IntFlag):
    """Per-identity policy state decoded from ``sb_qflags``.

    These describe what the filesystem was configured to do at the time the
    image was written. They are deliberately separate from the mere presence
    of a dquot record.
    """

    ACCOUNTING = 1
    ENFORCEMENT = 2
    CHECKED = 4
    ACTIVE = 8


@dataclass(frozen=True)
class QuotaPolicy:
    """Read-only view of the superblock enforcement state for one identity."""

    quota_type: str
    accounting: bool
    enforcement: bool
    checked: bool
    active: bool

    @property
    def flags(self) -> QuotaPolicyFlag:
        result = QuotaPolicyFlag(0)
        if self.accounting:
            result |= QuotaPolicyFlag.ACCOUNTING
        if self.enforcement:
            result |= QuotaPolicyFlag.ENFORCEMENT
        if self.checked:
            result |= QuotaPolicyFlag.CHECKED
        if self.active:
            result |= QuotaPolicyFlag.ACTIVE
        return result


class QuotaEvidence:
    """Read-only evidence extracted from one on-disk dquot record.

    All raw on-disk values are kept verbatim. Normalised counters and decoded
    timers are offered as convenience properties, but a failed checksum, an
    unknown record version or an inconsistent counter never causes a record to
    be dropped or rewritten; such conditions are recorded in :attr:`issues`.
    """

    def __init__(self, manager: QuotaManager, data: bytes, file_offset: int, expected_type: str | None = None):
        self._manager = manager
        self._raw = data
        self.file_offset = file_offset
        self.expected_type = expected_type

        record = c_xfs.xfs_dqblk(io.BytesIO(data))
        self._record = record
        disk = record.dd_diskdq
        self._disk = disk

        self.record_type_raw = disk.d_flags
        self.quota_type = _dquot_type_name(disk.d_flags)
        self.id = disk.d_id

        # Raw counters, in the exact unit XFS stores them in (512 byte blocks).
        self.block_count_raw = disk.d_bcount
        self.block_soft_limit_raw = disk.d_blk_softlimit
        self.block_hard_limit_raw = disk.d_blk_hardlimit
        self.inode_count_raw = disk.d_icount
        self.inode_soft_limit_raw = disk.d_ino_softlimit
        self.inode_hard_limit_raw = disk.d_ino_hardlimit

        # Timers are exposed both as the encoded on-disk integers and as best
        # effort decoded datetimes. None means "no timer was set".
        self.block_timer_raw = disk.d_btimer
        self.inode_timer_raw = disk.d_itimer
        self.block_warnings = disk.d_bwarns
        self.inode_warnings = disk.d_iwarns

        self.magic = disk.d_magic
        self.version_raw = disk.d_version
        # The CRC is stored little endian while c_xfs parses big endian, so
        # decode it from the raw bytes instead of trusting record.d_crc.
        crc_offset = c_xfs.xfs_dqblk.lookup["d_crc"].offset
        self.crc_raw = c_xfs_le.uint32(data[crc_offset : crc_offset + 4])
        self.lsn = record.d_lsn
        self.block_number = record.d_blkno

        self.issues: set[str] = set()
        self._validate()

    def __repr__(self) -> str:
        return f"<{self.quota_type} dquot id={self.id} issues={sorted(self.issues) or 'none'}>"

    def _validate(self) -> None:
        if self.magic != c_xfs.XFS_DQUOT_MAGIC:
            self.issues.add("invalid_magic")
        if self.version_raw != c_xfs.XFS_DQUOT_VERSION:
            self.issues.add("unsupported_version")
        if self.quota_type is None:
            self.issues.add("unknown_record_type")
        elif self.expected_type is not None and self.quota_type != self.expected_type:
            # The record's d_flags does not match the quota file it lives in.
            self.issues.add("record_type_mismatch")

        if self._manager.crc_required:
            expected = crc32c(self._raw_with_zeroed_crc())
            if expected != self.crc_raw:
                self.issues.add("crc_mismatch")

        # A usage counter above a configured limit is suspicious evidence, not
        # proof that the limit was enforced at the time. Report it, do not fix.
        if self.block_hard_limit_raw and self.block_count_raw > self.block_hard_limit_raw:
            self.issues.add("block_count_exceeds_hard_limit")
        if self.inode_hard_limit_raw and self.inode_count_raw > self.inode_hard_limit_raw:
            self.issues.add("inode_count_exceeds_hard_limit")

    @property
    def valid(self) -> bool:
        """Whether the record passed every check the filesystem version allows."""
        return not self.issues

    @property
    def crc_verified(self) -> bool | None:
        """``None`` when the filesystem does not use dquot CRCs."""
        if not self._manager.crc_required:
            return None
        return "crc_mismatch" not in self.issues

    def _raw_with_zeroed_crc(self) -> bytes:
        crc_offset = c_xfs.xfs_dqblk.lookup["d_crc"].offset
        crc_size = c_xfs.xfs_dqblk.lookup["d_crc"].type.size
        view = bytearray(self._raw)
        view[crc_offset : crc_offset + crc_size] = b"\x00" * crc_size
        return bytes(view)

    @property
    def block_size_bytes(self) -> int:
        """The unit of every block counter, fixed at 512 bytes by XFS."""
        return c_xfs.XFS_DQUOT_BLOCK_SIZE

    @property
    def block_count_bytes(self) -> int:
        return self.block_count_raw * c_xfs.XFS_DQUOT_BLOCK_SIZE

    @property
    def block_soft_limit_bytes(self) -> int:
        return self.block_soft_limit_raw * c_xfs.XFS_DQUOT_BLOCK_SIZE

    @property
    def block_hard_limit_bytes(self) -> int:
        return self.block_hard_limit_raw * c_xfs.XFS_DQUOT_BLOCK_SIZE

    @property
    def block_timer(self) -> datetime | None:
        return self._manager.decode_timer(self.block_timer_raw, self._disk.d_btime_hi)

    @property
    def inode_timer(self) -> datetime | None:
        return self._manager.decode_timer(self.inode_timer_raw, self._disk.d_itime_hi)

    @property
    def block_over_soft_limit(self) -> bool:
        return bool(self.block_soft_limit_raw) and self.block_count_raw > self.block_soft_limit_raw

    @property
    def inode_over_soft_limit(self) -> bool:
        return bool(self.inode_soft_limit_raw) and self.inode_count_raw > self.inode_soft_limit_raw

    def to_dict(self) -> dict:
        """Snapshot suitable for serialisation; retains every raw value."""
        return {
            "quota_type": self.quota_type,
            "expected_type": self.expected_type,
            "record_type_raw": self.record_type_raw,
            "id": self.id,
            "block_count_raw": self.block_count_raw,
            "block_count_bytes": self.block_count_bytes,
            "block_soft_limit_raw": self.block_soft_limit_raw,
            "block_hard_limit_raw": self.block_hard_limit_raw,
            "block_soft_limit_bytes": self.block_soft_limit_bytes,
            "block_hard_limit_bytes": self.block_hard_limit_bytes,
            "inode_count_raw": self.inode_count_raw,
            "inode_soft_limit_raw": self.inode_soft_limit_raw,
            "inode_hard_limit_raw": self.inode_hard_limit_raw,
            "block_timer_raw": self.block_timer_raw,
            "inode_timer_raw": self.inode_timer_raw,
            "block_timer": self.block_timer.isoformat() if self.block_timer else None,
            "inode_timer": self.inode_timer.isoformat() if self.inode_timer else None,
            "block_warnings": self.block_warnings,
            "inode_warnings": self.inode_warnings,
            "magic": self.magic,
            "version_raw": self.version_raw,
            "crc_raw": self.crc_raw,
            "crc_verified": self.crc_verified,
            "file_offset": self.file_offset,
            "issues": sorted(self.issues),
        }


class QuotaHeader:
    """Read-only view of the first block of a quota file."""

    def __init__(self, data: bytes):
        self._raw = data
        header = c_xfs.xfs_dqblk_hdr(io.BytesIO(data))
        self.magic = header.d_magic
        self.version_raw = header.d_version
        self.flags_raw = header.d_flags
        self.lsn = header.d_lsn

        crc_offset = c_xfs.xfs_dqblk_hdr.lookup["d_crc"].offset
        self.crc_raw = c_xfs_le.uint32(data[crc_offset : crc_offset + 4])

        self.issues: set[str] = set()
        if self.magic != c_xfs.XFS_QF_MAGIC:
            self.issues.add("invalid_magic")
        if self.version_raw != 1:
            self.issues.add("unsupported_version")
        if self.flags_raw & c_xfs.XFS_QF_QUOTA_CRC:
            view = bytearray(data[: len(c_xfs.xfs_dqblk_hdr)])
            crc_size = c_xfs.xfs_dqblk_hdr.lookup["d_crc"].type.size
            view[crc_offset : crc_offset + crc_size] = b"\x00" * crc_size
            if crc32c(bytes(view)) != self.crc_raw:
                self.issues.add("crc_mismatch")

    @property
    def crc_enabled(self) -> bool:
        return bool(self.flags_raw & c_xfs.XFS_QF_QUOTA_CRC)

    @property
    def valid(self) -> bool:
        return not self.issues


class QuotaManager:
    """Parses the quota files of an :class:`~dissect.xfs.xfs.XFS` image.

    The manager never touches the host operating system's live quotas. Every
    value comes from the image's quota inodes and superblock.
    """

    def __init__(self, xfs: XFS):
        self.xfs = xfs
        self.sb = xfs.sb
        self._record_size = len(c_xfs.xfs_dqblk)
        self.records_per_block = xfs.block_size // self._record_size
        self.has_quota_bigtime = bool(
            xfs.version == 5 and xfs.sb.sb_features_ro_compat & c_xfs.XFS_SB_FEAT_RO_COMPAT_QUOTABIGTIME
        )
        # dquot CRCs only exist on CRC enabled (v5) filesystems.
        self.crc_required = xfs._has_crc

    @cached_property
    def qflags_raw(self) -> int:
        return self.sb.sb_qflags

    @cached_property
    def qflags_version(self) -> int:
        return 2 if self.qflags_raw & c_xfs.XFS_QF_VERSION else 1

    @cached_property
    def quota_enabled(self) -> bool:
        """Whether any identity has accounting enabled in the superblock."""
        return any(self.policy(quota_type).accounting for quota_type in QuotaType._ALL)

    @cached_property
    def enforcement_enabled(self) -> bool:
        """Whether any identity has hard enforcement enabled in the superblock."""
        return any(self.policy(quota_type).enforcement for quota_type in QuotaType._ALL)

    def quota_inode_number(self, quota_type: str) -> int | None:
        """The inode backing an identity, or ``None`` when no inode is set."""
        field = QuotaType._INODE_FIELD[quota_type]
        # sb_pquotino only exists in version 5 superblocks.
        if not hasattr(self.sb, field):
            return None
        inode_number = getattr(self.sb, field)
        return None if inode_number in (0, XFS_NULL) else inode_number

    def policy(self, quota_type: str) -> QuotaPolicy:
        """Decode the superblock accounting/enforcement state for an identity."""
        flags = self.qflags_raw
        v1 = self.qflags_version == 1

        if quota_type == QuotaType.USER:
            accounting = bool(flags & c_xfs.XFS_UQUOTA_ACCT)
            enforcement = bool(flags & c_xfs.XFS_UQUOTA_ENFD)
            checked = bool(flags & c_xfs.XFS_UQUOTA_CHKD)
            active = bool(flags & c_xfs.XFS_UQUOTA_ACTIVE)
        elif quota_type == QuotaType.GROUP:
            accounting = bool(flags & c_xfs.XFS_GQUOTA_ACCT)
            # On the v1 layout group and project share the OQUOTA enforcement bits.
            if v1:
                enforcement = bool(flags & c_xfs.XFS_OQUOTA_ENFD)
                checked = bool(flags & c_xfs.XFS_OQUOTA_CHKD)
            else:
                enforcement = bool(flags & c_xfs.XFS_GQUOTA_ENFD)
                checked = bool(flags & c_xfs.XFS_GQUOTA_CHKD)
            active = bool(flags & c_xfs.XFS_GQUOTA_ACTIVE)
        else:
            accounting = bool(flags & c_xfs.XFS_PQUOTA_ACCT)
            # v1 filesystems cannot represent project quota separately.
            enforcement = False if v1 else bool(flags & c_xfs.XFS_PQUOTA_ENFD)
            checked = False if v1 else bool(flags & c_xfs.XFS_PQUOTA_CHKD)
            active = bool(flags & c_xfs.XFS_PQUOTA_ACTIVE)

        return QuotaPolicy(quota_type, accounting, enforcement, checked, active)

    def policies(self) -> dict[str, QuotaPolicy]:
        return {quota_type: self.policy(quota_type) for quota_type in QuotaType._ALL}

    def _open_quota_file(self, quota_type: str) -> BinaryIO | None:
        inode_number = self.quota_inode_number(quota_type)
        if inode_number is None:
            return None
        inode = self.xfs.get_inode(inode_number)
        return inode.open()

    def quota_header(self, quota_type: str) -> QuotaHeader | None:
        """Parse the first block header of an identity's quota file."""
        fh = self._open_quota_file(quota_type)
        if fh is None:
            return None
        block = fh.read(self.xfs.block_size)
        if len(block) < len(c_xfs.xfs_dqblk_hdr):
            return None
        return QuotaHeader(block)

    def dquots(self, quota_type: str) -> list[QuotaEvidence]:
        """All non-empty dquot records for an identity, in on-disk order."""
        fh = self._open_quota_file(quota_type)
        if fh is None:
            return []

        block_size = self.xfs.block_size
        data = fh.read()
        # A truncated or zero-length quota file (for example a pointer set in
        # the superblock but no blocks allocated) carries no parseable records.
        if len(data) < block_size:
            return []

        results = []
        # Block 0 is the quota file header, dquot blocks start at block 1.
        for block_index in range(1, len(data) // block_size):
            block = data[block_index * block_size : (block_index + 1) * block_size]
            for slot in range(self.records_per_block):
                start = slot * self._record_size
                end = start + self._record_size
                record_data = block[start:end]
                # Empty slots are zero filled; magic 0 means "never used".
                if int.from_bytes(record_data[:2], "big") == 0:
                    continue
                evidence = QuotaEvidence(
                    self, record_data, block_index * block_size + start, expected_type=quota_type
                )
                results.append(evidence)
        return results

    def all_dquots(self) -> dict[str, list[QuotaEvidence]]:
        return {quota_type: self.dquots(quota_type) for quota_type in QuotaType._ALL}

    def get_dquot(self, quota_type: str, identity: int) -> QuotaEvidence | None:
        """Look up a single identity by its user/group/project id."""
        for evidence in self.dquots(quota_type):
            if evidence.id == identity:
                return evidence
        return None

    def decode_timer(self, timer: int, timer_hi: int) -> datetime | None:
        """Decode an on-disk grace timer without guessing.

        Returns ``None`` when no timer is set. Legacy timers are signed 32 bit
        absolute Unix timestamps. Quota bigtime packs the deadline into a 48
        bit counter whose epoch is the legacy timer minimum (Dec 13 1901).
        """
        if timer == 0:
            return None

        if not self.has_quota_bigtime:
            seconds = timer
        else:
            # c_xfs decodes d_btimer as a signed int32, but bigtime packs an
            # unsigned 32 bit low word together with the 16 bit high word.
            combined = (timer_hi << 32) | (timer & 0xFFFFFFFF)
            if combined == 0:
                return None
            seconds = combined - (1 << 31)

        try:
            return ts.from_unix(seconds)
        except (OverflowError, OSError, ValueError):
            # Keep the raw value on the evidence object; never invent a time.
            return None


def _dquot_type_name(flags: int) -> str | None:
    for name, disk_flag in QuotaType._DISK_FLAG.items():
        if flags == disk_flag:
            return name
    return None


# Fields describing *who* the record belongs to.
_IDENTITY_FIELDS = ("quota_type", "record_type_raw", "id")
# Fields describing *how much* the identity used and its configured limits.
_USAGE_FIELDS = (
    "block_count_raw",
    "block_soft_limit_raw",
    "block_hard_limit_raw",
    "inode_count_raw",
    "inode_soft_limit_raw",
    "inode_hard_limit_raw",
    "block_timer_raw",
    "inode_timer_raw",
    "block_warnings",
    "inode_warnings",
)


def diff_dquots(left: QuotaEvidence, right: QuotaEvidence) -> dict[str, dict[str, object]]:
    """Compare two records, grouping differences by identity, usage and policy.

    Records carrying identical counters but a different type, id or
    enforcement state are reported as distinct differences instead of looking
    equal. Enforcement state comes from the superblock policy, never from the
    mere presence of a record.
    """
    result: dict[str, dict[str, object]] = {"identity": {}, "usage": {}, "policy": {}, "integrity": {}}

    for field in _IDENTITY_FIELDS:
        left_value, right_value = getattr(left, field), getattr(right, field)
        if left_value != right_value:
            result["identity"][field] = (left_value, right_value)

    for field in _USAGE_FIELDS:
        left_value, right_value = getattr(left, field), getattr(right, field)
        if left_value != right_value:
            result["usage"][field] = (left_value, right_value)

    # Enforcement state belongs to the identity of each record, taken from the
    # superblock policy rather than inferred from the record's mere existence.
    for record, peer in ((left, right), (right, left)):
        quota_type = record.quota_type
        if quota_type is None:
            continue
        policy = record._manager.policy(quota_type)
        peer_policy = peer._manager.policy(quota_type)
        for policy_field in ("accounting", "enforcement", "checked", "active"):
            key = f"{quota_type}_{policy_field}"
            left_value, right_value = getattr(policy, policy_field), getattr(peer_policy, policy_field)
            if left_value != right_value and key not in result["policy"]:
                result["policy"][key] = (left_value, right_value)

    for field in ("valid", "crc_verified", "issues", "version_raw", "magic"):
        left_value, right_value = getattr(left, field), getattr(right, field)
        if left_value != right_value:
            result["integrity"][field] = (left_value, right_value)

    return {group: values for group, values in result.items() if values}

