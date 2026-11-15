from __future__ import annotations

import io
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from dissect.cstruct import cstruct

import dissect.etl.etl as etl
from dissect.etl.c_etl import etl_def
from dissect.etl.etl import Buffer
from dissect.etl.exceptions import InvalidBufferError

from .test_wmi_buffer_header import RAW_BUFFER_HEADER

if TYPE_CHECKING:
    from collections.abc import Iterator


BUFFER_HEADER_SIZE = 0x48


@pytest.fixture(autouse=True)
def restore_c_etl() -> Iterator[None]:
    original = etl.c_etl
    yield
    etl.c_etl = original


def load_etl_definition() -> cstruct:
    return cstruct().load(etl_def)


def setup_mocked_etlfile(start_offset: int = 0, data: bytes | None = None) -> MagicMock:
    stream = io.BytesIO(RAW_BUFFER_HEADER if data is None else data)

    mocked_etlfile = MagicMock()
    mocked_etlfile.fh.read.side_effect = stream.read
    mocked_etlfile.fh.seek.side_effect = stream.seek
    mocked_etlfile.fh.tell.side_effect = stream.tell
    return mocked_etlfile


def setup_buffer_with_offsets(data_offset: int, start_offset: int = 0) -> Buffer:
    mocked_etl = setup_mocked_etlfile(data=b"\x00" * data_offset)
    etl.c_etl = MagicMock()
    etl.c_etl.BufferHeader.return_value.FilledBytes = data_offset
    etl.c_etl.BufferHeader.return_value.BufferSize = data_offset
    etl.c_etl.BufferHeader.return_value.BufferFlag = 0
    etl.c_etl.BufferHeader.__len__.return_value = BUFFER_HEADER_SIZE
    return Buffer(mocked_etl, start_offset)


def setup_buffer_iterator(mocked_read_record: MagicMock, data_offset: int) -> Iterator[Buffer]:
    mocked_read_record.return_value.aligned_size = 0x10
    buffer = setup_buffer_with_offsets(data_offset=data_offset)
    return iter(buffer)


def test_buffer_data_len() -> None:
    filled_bytes = 0x2A8
    mocked_etl = setup_mocked_etlfile(data=RAW_BUFFER_HEADER + b"\x00" * (filled_bytes - BUFFER_HEADER_SIZE))
    mocked_etl.c_etl = load_etl_definition()

    buffer = Buffer(mocked_etl, 0)
    assert buffer.data

    assert buffer.physical_size == filled_bytes - BUFFER_HEADER_SIZE
    mocked_etl.fh.read.assert_called_with(buffer.physical_size)


@patch.object(Buffer, "read_record")
def test_buffer_iteration_succeed(mocked_read_record: Buffer) -> None:
    buffer_iterator = setup_buffer_iterator(mocked_read_record, data_offset=0x58)
    assert next(buffer_iterator) == mocked_read_record.return_value


@pytest.mark.parametrize(
    ("header_offset", "data_offset"),
    [(0, 0x58), (0, 0x48)],
)
@patch.object(Buffer, "read_record", side_effect=[EOFError])
def test_buffer_iterations(mocked_read_record: Buffer, header_offset: int, data_offset: int) -> None:
    buffer_iterator = setup_buffer_iterator(mocked_read_record, data_offset)
    with pytest.raises(StopIteration):
        next(buffer_iterator)


def test_negative_read_offset() -> None:
    buffer = setup_buffer_with_offsets(start_offset=10, data_offset=5)
    with pytest.raises(InvalidBufferError):
        assert buffer.data


def test_different_buffer_sizes() -> None:
    buffer1 = Buffer(MagicMock(), 0)
    buffer1._header = MagicMock()
