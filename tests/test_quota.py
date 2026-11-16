from __future__ import annotations

import datetime

from dissect.xfs import QuotaType, diff_dquots
from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.xfs import XFS

from tests.quota_image import DquotSpec, QuotaImageBuilder


def _xfs(builder: QuotaImageBuilder) -> XFS:
    return XFS(builder.build())


def test_no_quota_in_superblock_means_empty_evidence(xfs_bin) -> None:
    manager = XFS(xfs_bin).quota

    assert manager.quota_enabled is False
    assert manager.enforcement_enabled is False
    assert manager.all_dquots() == {"user": [], "group": [], "project": []}
    for quota_type in QuotaType._ALL:
        assert manager.quota_inode_number(quota_type) is None
        policy = manager.policy(quota_type)
        assert policy.accounting is False
        assert policy.enforcement is False


def test_three_dquot_identities_are_separated() -> None:
    builder = QuotaImageBuilder(
        quotas={
            "user": [DquotSpec(identity=1000, bcount=200)],
            "group": [DquotSpec(identity=10, bcount=200)],
            "project": [DquotSpec(identity=7, bcount=200)],
        }
    )
    manager = _xfs(builder).quota

    records = manager.all_dquots()
    assert [record.quota_type for record in records["user"]] == ["user"]
    assert [record.quota_type for record in records["group"]] == ["group"]
    assert [record.quota_type for record in records["project"]] == ["project"]
    assert [record.id for record in records["user"]] == [1000]
    assert manager.get_dquot("group", 10).record_type_raw == c_xfs.XFS_DQTYPE_GROUP
    assert manager.get_dquot("project", 7).record_type_raw == c_xfs.XFS_DQTYPE_PROJ


def test_block_counters_use_512_byte_basic_blocks() -> None:
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, bcount=200, blk_soft=100, blk_hard=500, icount=4)]}
    )
    record = _xfs(builder).quota.dquots("user")[0]

    assert record.block_size_bytes == 512
    assert record.block_count_raw == 200
    assert record.block_count_bytes == 200 * 512
    assert record.block_soft_limit_bytes == 100 * 512
    assert record.block_hard_limit_bytes == 500 * 512
    # Inode counters have no block unit.
    assert record.inode_count_raw == 4


def test_superblock_accounting_and_enforcement_policy() -> None:
    qflags = (
        c_xfs.XFS_UQUOTA_ACCT
        | c_xfs.XFS_UQUOTA_ENFD
        | c_xfs.XFS_GQUOTA_ACCT
        | c_xfs.XFS_PQUOTA_ACCT
        | c_xfs.XFS_QF_VERSION
    )
    manager = _xfs(QuotaImageBuilder(qflags=qflags)).quota

    assert manager.qflags_version == 2
    assert manager.quota_enabled is True
    assert manager.enforcement_enabled is True

    user_policy = manager.policy("user")
    assert user_policy.accounting is True
    assert user_policy.enforcement is True
    group_policy = manager.policy("group")
    assert group_policy.accounting is True
    assert group_policy.enforcement is False
    project_policy = manager.policy("project")
    assert project_policy.accounting is True
    assert project_policy.enforcement is False


def test_record_presence_does_not_imply_enforcement() -> None:
    # Accounting and a dquot exist, but no enforcement bit is set.
    builder = QuotaImageBuilder(
        qflags=c_xfs.XFS_UQUOTA_ACCT,
        quotas={"user": [DquotSpec(identity=1000, bcount=999, blk_hard=10)]},
    )
    manager = _xfs(builder).quota
    record = manager.dquots("user")[0]

    assert manager.policy("user").enforcement is False
    assert record is not None
    # The inconsistent counter is flagged but the raw value is preserved.
    assert "block_count_exceeds_hard_limit" in record.issues
    assert record.block_count_raw == 999
    assert record.block_hard_limit_raw == 10


def test_crc_mismatch_is_reported_but_value_kept() -> None:
    builder = QuotaImageBuilder(quotas={"user": [DquotSpec(identity=1, bcount=42, corrupt_crc=True)]})
    record = _xfs(builder).quota.dquots("user")[0]

    assert record.crc_verified is False
    assert "crc_mismatch" in record.issues
    assert record.valid is False
    # Original counter remains available for evidence purposes.
    assert record.block_count_raw == 42


def test_valid_record_passes_checks() -> None:
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, bcount=10, blk_soft=20, blk_hard=30)]}
    )
    record = _xfs(builder).quota.dquots("user")[0]

    assert record.crc_verified is True
    assert record.valid is True
    assert record.issues == set()


def test_bad_magic_and_unknown_type_are_retained() -> None:
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, magic=0x1234, d_flags=0x7F)]}
    )
    record = _xfs(builder).quota.dquots("user")[0]

    assert "invalid_magic" in record.issues
    assert "unknown_record_type" in record.issues
    assert record.quota_type is None
    assert record.record_type_raw == 0x7F


def test_record_type_mismatch_with_quota_file_is_flagged() -> None:
    # A group d_flags record placed inside the user quota file.
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, d_flags=c_xfs.XFS_DQTYPE_GROUP)]}
    )
    record = _xfs(builder).quota.dquots("user")[0]

    assert "record_type_mismatch" in record.issues
    assert record.quota_type == "group"
    assert record.expected_type == "user"
    assert record.id == 1


def test_unsupported_version_is_flagged() -> None:
    builder = QuotaImageBuilder(quotas={"user": [DquotSpec(identity=1, version=99)]})
    record = _xfs(builder).quota.dquots("user")[0]

    assert "unsupported_version" in record.issues
    assert record.version_raw == 99


def test_grace_timer_decoding_and_missing_timer() -> None:
    legacy = datetime.datetime(2020, 5, 1, tzinfo=datetime.timezone.utc)
    raw_timer = int(legacy.timestamp())
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, btimer=raw_timer, itimer=raw_timer), DquotSpec(identity=2)]}
    )
    manager = _xfs(builder).quota
    with_timer = manager.get_dquot("user", 1)
    without_timer = manager.get_dquot("user", 2)

    assert with_timer.block_timer == legacy
    assert with_timer.block_timer_raw == raw_timer
    assert with_timer.inode_timer == legacy
    assert without_timer.block_timer is None
    assert without_timer.inode_timer is None


def test_quota_bigtime_timer() -> None:
    target = datetime.datetime(2050, 6, 1, tzinfo=datetime.timezone.utc)
    combined = int(target.timestamp()) + (1 << 31)
    high = (combined >> 32) & 0xFFFF
    low = combined & 0xFFFFFFFF
    builder = QuotaImageBuilder(
        ro_compat=c_xfs.XFS_SB_FEAT_RO_COMPAT_QUOTABIGTIME,
        quotas={"user": [DquotSpec(identity=1, btimer=low, btime_hi=high)]},
    )
    manager = _xfs(builder).quota

    assert manager.has_quota_bigtime is True
    assert manager.dquots("user")[0].block_timer == target


def test_over_soft_limit_is_numeric_only_without_violation_claim() -> None:
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, bcount=100, blk_soft=10)]}
    )
    record = _xfs(builder).quota.dquots("user")[0]

    assert record.block_over_soft_limit is True
    # No grace timer means the evidence does not establish an overdue violation.
    assert record.block_timer is None
    assert "block_count_exceeds_hard_limit" not in record.issues


def test_v4_superblock_has_no_project_inode() -> None:
    builder = QuotaImageBuilder(
        version=4,
        qflags=c_xfs.XFS_UQUOTA_ACCT | c_xfs.XFS_OQUOTA_ENFD,
        quotas={"user": [DquotSpec(identity=1, bcount=5)]},
    )
    manager = _xfs(builder).quota

    assert manager.qflags_version == 1
    assert manager.quota_inode_number("project") is None
    # On v1 flag layout the shared OQUOTA bit governs group enforcement.
    assert manager.policy("group").enforcement is True
    # Project quota cannot be represented separately on the v1 layout.
    assert manager.policy("project").enforcement is False
    record = manager.dquots("user")[0]
    assert record.crc_verified is None
    assert record.block_count_raw == 5


def test_diff_distinguishes_identity_usage_and_policy() -> None:
    qflags = c_xfs.XFS_UQUOTA_ACCT | c_xfs.XFS_UQUOTA_ENFD | c_xfs.XFS_QF_VERSION
    left_builder = QuotaImageBuilder(
        qflags=qflags, quotas={"user": [DquotSpec(identity=1, bcount=100, blk_soft=50)]}
    )
    right_builder = QuotaImageBuilder(
        qflags=c_xfs.XFS_UQUOTA_ACCT,
        quotas={"group": [DquotSpec(identity=1, bcount=100, blk_soft=50)]},
    )
    left = _xfs(left_builder).quota.dquots("user")[0]
    right = _xfs(right_builder).quota.dquots("group")[0]

    diff = diff_dquots(left, right)
    assert "quota_type" in diff["identity"]
    assert "usage" not in diff
    # The left image enforces user quotas while the right only accounts, so the
    # enforcement policy difference is surfaced even though counters are equal.
    assert diff["policy"]["user_enforcement"] == (True, False)


def test_diff_detects_usage_change_with_same_identity() -> None:
    left = _xfs(
        QuotaImageBuilder(quotas={"user": [DquotSpec(identity=1, bcount=100)]})
    ).quota.dquots("user")[0]
    right = _xfs(
        QuotaImageBuilder(quotas={"user": [DquotSpec(identity=1, bcount=200)]})
    ).quota.dquots("user")[0]

    diff = diff_dquots(left, right)
    assert "identity" not in diff
    assert diff["usage"]["block_count_raw"] == (100, 200)


def test_multiple_records_and_slot_stride() -> None:
    capacity = 4096 // len(c_xfs.xfs_dqblk)
    specs = [DquotSpec(identity=identity, bcount=identity) for identity in range(capacity)]
    manager = _xfs(QuotaImageBuilder(quotas={"user": specs})).quota
    records = manager.dquots("user")

    assert manager.records_per_block == capacity
    assert [record.id for record in records] == list(range(capacity))
    stride = records[1].file_offset - records[0].file_offset
    assert stride == len(c_xfs.xfs_dqblk)
    assert all(record.valid for record in records)


def test_on_disk_dquot_geometry() -> None:
    # These invariants come directly from the on-disk XFS quota format; getting
    # them wrong shifts every record after the first one.
    assert len(c_xfs.xfs_disk_dquot) == 104
    assert len(c_xfs.xfs_dqblk) == 128
    assert 4096 // len(c_xfs.xfs_dqblk) == 32
    assert c_xfs.xfs_disk_dquot.lookup["d_bcount"].offset == 40
    assert c_xfs.xfs_disk_dquot.lookup["d_btimer"].offset == 56
    assert c_xfs.xfs_dqblk.lookup["d_crc"].offset == 104


def test_quota_header_v5_is_crc_protected() -> None:
    manager = _xfs(QuotaImageBuilder(quotas={"user": [DquotSpec(identity=1)]})).quota
    header = manager.quota_header("user")

    assert header is not None
    assert header.magic == c_xfs.XFS_QF_MAGIC
    assert header.version_raw == 1
    assert header.crc_enabled is True
    assert header.valid is True
    assert header.issues == set()


def test_quota_header_v4_has_no_crc_flag() -> None:
    builder = QuotaImageBuilder(
        version=4, qflags=c_xfs.XFS_UQUOTA_ACCT, quotas={"user": [DquotSpec(identity=1)]}
    )
    header = _xfs(builder).quota.quota_header("user")

    assert header.crc_enabled is False
    assert header.valid is True


def test_quota_header_missing_without_inode() -> None:
    manager = _xfs(QuotaImageBuilder()).quota
    assert manager.quota_header("user") is None


def test_to_dict_keeps_raw_and_decoded_values() -> None:
    builder = QuotaImageBuilder(
        quotas={"user": [DquotSpec(identity=1, bcount=10, blk_hard=20, icount=2)]}
    )
    snapshot = _xfs(builder).quota.dquots("user")[0].to_dict()

    assert snapshot["quota_type"] == "user"
    assert snapshot["id"] == 1
    assert snapshot["block_count_raw"] == 10
    assert snapshot["block_count_bytes"] == 10 * 512
    assert snapshot["crc_verified"] is True
    assert snapshot["issues"] == []


def test_missing_quota_file_returns_empty() -> None:
    # Pointers set but backing blocks omitted: parser stays read-only and
    # reports no records instead of treating the pointer as live evidence.
    builder = QuotaImageBuilder(
        qflags=c_xfs.XFS_UQUOTA_ACCT,
        quotas={"user": [DquotSpec(identity=1)]},
        write_files=False,
    )
    manager = _xfs(builder).quota

    assert manager.quota_inode_number("user") is not None
    assert manager.dquots("user") == []
