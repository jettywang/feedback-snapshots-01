from __future__ import annotations

import io
import struct
from contextlib import contextmanager
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.etl import etl as etl_module
from dissect.etl.c_etl import BufferFlag, c_etl
from dissect.etl.etl import ETL
from dissect.etl.headers.logfile import LogfileHeader

from .testutils import FIRST_BUFFER

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.etl.headers.headers import Header

BUFFER_HEADER_SIZE = 0x48


@pytest.fixture(autouse=True)
def _restore_c_etl() -> Iterator[None]:
    # Other test modules replace the module-level c_etl with a MagicMock
    # without restoring it. Ensure real parsing is available for every test.
    etl_module.c_etl = c_etl
    yield
    etl_module.c_etl = c_etl


def make_etl(data: bytes = FIRST_BUFFER) -> ETL:
    return ETL(io.BytesIO(data))


@contextmanager
def patch_logfile_counts(*, events_lost: int, buffers_lost: int, buffers_written: int) -> Iterator[None]:
    with (
        patch.object(LogfileHeader, "events_lost", new=events_lost),
        patch.object(LogfileHeader, "buffers_lost", new=buffers_lost),
        patch.object(LogfileHeader, "buffers_written", new=buffers_written),
    ):
        yield


def test_healthy_single_buffer_keeps_logger_zero_claims() -> None:
    etl = make_etl()
    with patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=1):
        summary = etl.health_summary()
    dumped = summary.as_dict()

    assert dumped["logfile_loss"]["events_lost"] == {"value": 0, "source": "TraceLogfileHeader"}
    assert dumped["logfile_loss"]["buffers_lost"] == {"value": 0, "source": "TraceLogfileHeader"}
    assert dumped["physical_buffers"]["present"] == 1
    assert dumped["physical_buffers"]["missing"]["value"] == 0
    assert dumped["physical_buffers"]["truncated"]["value"] == 0

    # The fixture's last record is physically cut short, so zero logger claims
    # must not be reported as complete coverage.
    assert summary.coverage_complete is False
    assert dumped["records"]["parse_failures"]["value"] == 1
    failure = dumped["records"]["parse_failures"]["ranges"][0]
    assert failure["buffer_index"] == 0
    assert failure["start_offset"] < failure["end_offset"] == 680
    assert failure["error"] == "EOFError"


def test_nonzero_logger_loss_claims_are_kept_separate() -> None:
    etl = make_etl()
    with patch_logfile_counts(events_lost=7, buffers_lost=2, buffers_written=1):
        summary = etl.health_summary()
    dumped = summary.as_dict()

    assert dumped["logfile_loss"]["events_lost"]["value"] == 7
    assert dumped["logfile_loss"]["buffers_lost"]["value"] == 2
    # Logger claims are not folded into the physical or parse counters.
    assert dumped["physical_buffers"]["missing"]["value"] == 0
    assert dumped["physical_buffers"]["truncated"]["value"] == 0
    assert dumped["records"]["parse_failures"]["value"] == 1
    assert summary.coverage_complete is False


def test_physically_truncated_tail_is_distinguished_from_missing_buffers() -> None:
    declared = 17
    # Construct from the full fixture so the logfile header can be parsed,
    # then point the scanner at a file handle truncated inside the first buffer.
    etl = make_etl()
    etl.fh = io.BytesIO(FIRST_BUFFER[:400])
    with patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=declared):
        summary = etl.health_summary()
    dumped = summary.as_dict()

    assert dumped["physical_buffers"]["declared"]["value"] == declared
    assert dumped["physical_buffers"]["truncated"] == {
        "value": 1,
        "buffer_indices": [0],
        "source": "BufferHeader",
    }
    # A truncated buffer is not also counted as missing; the declared tail is
    # simply unreachable once scanning stops.
    assert dumped["physical_buffers"]["missing"]["value"] == 0
    assert dumped["physical_buffers"]["present"] == 0
    assert summary.coverage_complete is False


def test_missing_buffers_after_a_complete_head_buffer() -> None:
    etl = make_etl()
    with patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=17):
        summary = etl.health_summary()
    physical = summary.as_dict()["physical_buffers"]

    assert physical["present"] == 1
    assert physical["missing"]["value"] == 16
    assert physical["missing"]["buffer_indices"] == list(range(1, 17))
    assert physical["truncated"]["value"] == 0


def test_truncated_buffer_header_is_reported() -> None:
    etl = make_etl()
    # Keep enough bytes for construction, but remove part of the buffer header
    # that a fresh scan would re-read from disk.
    etl.fh = io.BytesIO(FIRST_BUFFER[: BUFFER_HEADER_SIZE - 4])
    with patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=2):
        summary = etl.health_summary()
    physical = summary.as_dict()["physical_buffers"]

    assert physical["truncated"]["buffer_indices"] == [0]
    assert physical["missing"]["value"] == 0


def test_buffer_loss_flags_are_counted_with_their_source() -> None:
    # BufferFlag lives at offset 0x34 of the buffer header; set both loss bits.
    data = bytearray(FIRST_BUFFER)
    loss_bits = int(BufferFlag.EVENTS_LOST) | int(BufferFlag.BUFFER_LOST)
    struct.pack_into("<H", data, 0x34, loss_bits)
    etl = make_etl(bytes(data))

    with patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=1):
        summary = etl.health_summary()

    physical = summary.as_dict()["physical_buffers"]
    assert physical["events_lost_flagged"] == {
        "value": 1,
        "buffer_indices": [0],
        "source": "BufferHeader.BufferFlag",
    }
    assert physical["buffer_lost_flagged"] == {
        "value": 1,
        "buffer_indices": [0],
        "source": "BufferHeader.BufferFlag",
    }


def test_providers_without_manifests_are_counted_separately() -> None:
    etl = make_etl()

    def force_manifest_missing(header: Header) -> etl_module.Event:
        return etl_module.Event(header, None)

    with (
        patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=1),
        patch.object(etl_module, "parse_payload", side_effect=force_manifest_missing),
    ):
        summary = etl.health_summary()

    records = summary.as_dict()["records"]
    # The logfile header control record is excluded; the remaining two records
    # come from one kernel provider group and share a provider id.
    assert records["providers_skipped"]["value"] == 2
    assert records["providers_skipped"]["source"] == "manifest.lookup"
    assert all(count == 2 for count in records["providers_skipped"]["by_provider_id"].values())
    assert summary.interpretation_complete is False
    # Skipped providers still parse as records and keep their own provider id.
    assert records["parsed"] == 3


def test_parsed_events_keep_their_own_provider_source() -> None:
    etl = make_etl()
    with patch_logfile_counts(events_lost=0, buffers_lost=0, buffers_written=1):
        etl.health_summary()

    records = list(etl.buffer(0))
    provider_ids = [str(record.header.provider_id) for record in records]
    assert len(provider_ids) == 3
    assert all(provider_id for provider_id in provider_ids)


def test_counters_are_never_combined_into_a_total() -> None:
    etl = make_etl()
    with patch_logfile_counts(events_lost=7, buffers_lost=2, buffers_written=17):
        dumped = etl.health_summary().as_dict()

    assert set(dumped) == {
        "file_size",
        "coverage_complete",
        "interpretation_complete",
        "logfile_loss",
        "physical_buffers",
        "records",
    }
    assert "total_lost" not in dumped
    assert dumped["logfile_loss"]["events_lost"]["value"] == 7
