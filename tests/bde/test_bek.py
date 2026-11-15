from __future__ import annotations

import contextlib
import struct
import uuid
from io import BytesIO
from typing import BinaryIO

import pytest

from dissect.fve.bde import bde
from dissect.fve.bde.bek import BekStatus
from dissect.fve.bde.c_bde import FVE_DATUM_ROLE, FVE_DATUM_TYPE, FVE_KEY_TYPE
from tests._util import open_file, open_file_gz

# Identifiers and key material of the existing test BEK, taken from the structures themselves
RECOVERY_KEY_IDENTIFIER = uuid.UUID("99b0081a-60b6-47e4-8482-dea46ee1891d")
RECOVERY_KEY_VOLUME_IDENTIFIER = uuid.UUID("7414ad48-bb37-47b0-8f84-92e29b76db0a")
RECOVERY_KEY = bytes.fromhex("48a608e5cd6f2112e4b390e38a086a5ec62a1a014afaf092c9117630deecd805")

UNKNOWN_IDENTIFIER = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")


def _datum(role: int, type_: int, data: bytes, flags: int = 0x0100) -> bytes:
    return struct.pack("<HHHH", 8 + len(data), role, type_, flags) + data


def _external_info_datum(identifier: uuid.UUID, key: bytes | None) -> bytes:
    properties = b""
    if key is not None:
        properties = _datum(
            FVE_DATUM_ROLE.PROPERTY,
            FVE_DATUM_TYPE.KEY,
            struct.pack("<HH", FVE_KEY_TYPE.EXTERN_KEY, 0) + key,
        )
    return _datum(
        FVE_DATUM_ROLE.STARTUP_KEY,
        FVE_DATUM_TYPE.EXTERNAL_INFO,
        identifier.bytes_le + struct.pack("<Q", 0) + properties,
    )


def _bek_fh(*datums: bytes) -> BytesIO:
    """Build a short BEK structure (dataset header + datums) with the given datums."""
    end_offset = 0x30 + sum(len(datum) for datum in datums)
    header = struct.pack("<IIII", end_offset, 1, 0x30, end_offset) + bytes(16) + struct.pack("<IHHQ", 1, 0, 0, 0)
    return BytesIO(header + b"".join(datums))


def _candidate_summary(candidates: list) -> list[tuple[uuid.UUID | None, BekStatus]]:
    return sorted(
        ((candidate.bek_identifier, candidate.status) for candidate in candidates),
        key=lambda item: (str(item[0]), item[1].value),
    )


def test_bek_candidates_existing_bek() -> None:
    """The existing test BEKs match their volume's external VMK protector and unlock it."""
    for test_file, bek_file, bek_identifier in (
        ("_data/bde/recovery_key.bin.gz", "_data/bde/recovery_key.bek", RECOVERY_KEY_IDENTIFIER),
        (
            "_data/bde/startup_key.bin.gz",
            "_data/bde/startup_key.bek",
            uuid.UUID("b3411a58-3400-420a-8b7e-9b5f706425c0"),
        ),
    ):
        with (
            contextlib.contextmanager(open_file_gz)(test_file) as fh,
            contextlib.contextmanager(open_file)(bek_file) as bek_fh,
        ):
            bde_obj = bde.BDE(fh)

            candidates = bde_obj.bek_candidates([bek_fh])
            assert len(candidates) == 1

            candidate = candidates[0]
            assert candidate.status is BekStatus.MATCHED
            assert candidate.bek_identifier == bek_identifier
            assert candidate.volume_identifier == bde_obj.information.dataset.identifier
            assert candidate.vmk.identifier == bek_identifier

            bde_obj.unlock_bek_candidate(candidate)
            assert candidate.status is BekStatus.UNLOCKED
            assert bde_obj.unlocked

            stream = bde_obj.open()
            assert stream.read(512)[3:11] == b"NTFS    "


def test_bek_candidates_short_structures_order_independent() -> None:
    """Two short structures with different identifiers give consistent candidates when swapped."""
    bek_match = _bek_fh(_external_info_datum(RECOVERY_KEY_IDENTIFIER, RECOVERY_KEY))
    bek_no_match = _bek_fh(_external_info_datum(UNKNOWN_IDENTIFIER, b"\x11" * 32))

    with contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        bek_match.seek(0)
        bek_no_match.seek(0)
        forward = bde_obj.bek_candidates([bek_match, bek_no_match])

        bek_match.seek(0)
        bek_no_match.seek(0)
        swapped = bde_obj.bek_candidates([bek_no_match, bek_match])

        assert _candidate_summary(forward) == _candidate_summary(swapped) == [
            (RECOVERY_KEY_IDENTIFIER, BekStatus.MATCHED),
            (UNKNOWN_IDENTIFIER, BekStatus.NO_MATCH),
        ]

        matched = next(candidate for candidate in forward if candidate.status is BekStatus.MATCHED)
        assert matched.volume_identifier == RECOVERY_KEY_VOLUME_IDENTIFIER
        assert matched.vmk.identifier == RECOVERY_KEY_IDENTIFIER


def test_bek_candidate_same_identifier_different_key() -> None:
    """A matching identifier with different key material fails authentication."""
    bek_wrong_key = _bek_fh(_external_info_datum(RECOVERY_KEY_IDENTIFIER, b"\x00" * 32))

    with contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        (candidate,) = bde_obj.bek_candidates([bek_wrong_key])
        assert candidate.status is BekStatus.MATCHED

        bde_obj.unlock_bek_candidate(candidate)
        assert candidate.status is BekStatus.KEY_MISMATCH
        assert not bde_obj.unlocked


def test_bek_candidate_duplicate_external_info() -> None:
    """Duplicate external info (same identifier and key) is only matched once."""
    datum = _external_info_datum(RECOVERY_KEY_IDENTIFIER, RECOVERY_KEY)
    bek_duplicate = _bek_fh(datum, datum)

    with contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        candidates = bde_obj.bek_candidates([bek_duplicate])
        assert _candidate_summary(candidates) == [
            (RECOVERY_KEY_IDENTIFIER, BekStatus.DUPLICATE),
            (RECOVERY_KEY_IDENTIFIER, BekStatus.MATCHED),
        ]

        # The duplicate is not retried, but the matched candidate still unlocks
        matched = next(candidate for candidate in candidates if candidate.status is BekStatus.MATCHED)
        bde_obj.unlock_bek_candidate(matched)
        assert matched.status is BekStatus.UNLOCKED
        assert bde_obj.unlocked


def test_bek_candidate_unsupported_datum() -> None:
    """Unsupported datum structures are distinguished from real candidates."""
    unsupported_type = _datum(FVE_DATUM_ROLE.STARTUP_KEY, 0x7FFF, UNKNOWN_IDENTIFIER.bytes_le + bytes(8))
    missing_key = _external_info_datum(UNKNOWN_IDENTIFIER, None)
    bek_unsupported = _bek_fh(unsupported_type, missing_key)

    with contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        candidates = bde_obj.bek_candidates([bek_unsupported])
        assert _candidate_summary(candidates) == [
            (None, BekStatus.UNSUPPORTED),
            (UNKNOWN_IDENTIFIER, BekStatus.UNSUPPORTED),
        ]

        with pytest.raises(ValueError, match="Unable to unlock with BEK"):
            bde_obj.unlock_with_bek(_bek_fh(unsupported_type, missing_key))


def test_bek_candidate_wrong_identifier_no_attribution() -> None:
    """A wrong identifier must not be attributed an unlock achieved by another protector."""
    bek_no_match = _bek_fh(_external_info_datum(UNKNOWN_IDENTIFIER, b"\x11" * 32))
    bek_match = _bek_fh(_external_info_datum(RECOVERY_KEY_IDENTIFIER, RECOVERY_KEY))

    with contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        candidates = bde_obj.bek_candidates([bek_no_match, bek_match])
        no_match = next(candidate for candidate in candidates if candidate.status is BekStatus.NO_MATCH)
        matched = next(candidate for candidate in candidates if candidate.status is BekStatus.MATCHED)

        with pytest.raises(ValueError, match="Unable to unlock with BEK candidate"):
            bde_obj.unlock_bek_candidate(no_match)

        bde_obj.unlock_bek_candidate(matched)
        assert matched.status is BekStatus.UNLOCKED
        assert bde_obj.unlocked

        # The unlock by the other protector does not change the wrong identifier's conclusion
        assert no_match.status is BekStatus.NO_MATCH

        bek_no_match.seek(0)
        (rechecked,) = bde_obj.bek_candidates([bek_no_match])
        assert rechecked.status is BekStatus.NO_MATCH
