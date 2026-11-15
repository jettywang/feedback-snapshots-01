# Resources:
#   https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/callouts/hookid.htm
#   https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw // For most of the header definitions
#   https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header // for timestamp calculation
#   https://docs.rs/winapi-ui-automation/0.3.9/winapi_ui_automation/um/evntcons/index.html
#   Windows Development Kit
#
# TMF parser:
#   https://searchcode.com/file/116783567/Tools/ETW/traceEvent/WPPTraceEventParser.cs
#
# Maybe interesting files to look at:
#   AppData\\Local\\Microsoft\\Windows\\Explorer\\ExplorerStartupLog.etl
#   Windows\\Performance\\WinSAT\\DataStore
#   Windows\\System32\\NDF\\*.etl
#   Windows\\System32\\LogFiles\\WMI
#   Windows\\System32\\SleepStudy
#   Windows\\Panther\\*.etl
#   Windows\\System32\\WDI\\LogFiles
from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct import Structure
from dissect.util.sid import read_sid
from dissect.util.ts import wintimestamp

from dissect.etl import manifest
from dissect.etl.c_etl import BufferFlag, c_etl
from dissect.etl.exceptions import (
    InvalidBufferError,
    InvalidHeaderError,
    InvalidMarkerError,
    InvalidRecordError,
    ManifestNotFoundError,
    NoMoreEventsError,
)
from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.headers.utils import select_event_header

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from types import ModuleType
    from uuid import UUID

    from dissect.etl.headers.headers import Header


MAX_DECOMPRESSED_SIZE = 1 << 26
"""Upper bound for the output of a single decompressed buffer (64 MiB)."""

BUFFER_HEADER_SIZE = len(c_etl.BufferHeader)


def _decompression_limit(etl: ETL) -> int:
    """Return the configured output limit, falling back for lightweight stubs."""
    limit = getattr(etl, "max_decompressed_size", None)
    return limit if isinstance(limit, int) and limit >= 0 else MAX_DECOMPRESSED_SIZE


def _decompress_lzxpress(src: bytes, limit: int) -> bytes:
    """Decompress an LZXPRESS stream without ever growing beyond ``limit`` bytes.

    ``dissect.util``'s decompressor has no output limit, so a small malicious
    buffer can expand into an arbitrarily large allocation.  This implementation
    follows the same [MS-XCA] decoding rules, but checks the projected output
    size before copying a match or appending a literal.
    """
    stream = io.BytesIO(src)
    size = len(src)
    dst = bytearray()

    def read(count: int) -> bytes:
        data = stream.read(count)
        if len(data) != count:
            raise InvalidBufferError("Truncated LZXPRESS stream")
        return data

    buffered_flags = 0
    buffered_flags_count = 0
    last_length_half_byte = 0

    while stream.tell() < size:
        if buffered_flags_count == 0:
            buffered_flags = struct.unpack("<I", read(4))[0]
            buffered_flags_count = 32

        buffered_flags_count -= 1
        if buffered_flags & (1 << buffered_flags_count) == 0:
            if len(dst) + 1 > limit:
                raise InvalidBufferError(f"Decompressed buffer exceeds the limit of {limit} bytes")
            dst += read(1)
            continue

        if stream.tell() == size:
            break

        match = struct.unpack("<H", read(2))[0]
        match_offset, match_length = divmod(match, 8)
        match_offset += 1

        if match_length == 7:
            if last_length_half_byte == 0:
                last_length_half_byte = stream.tell()
                match_length = read(1)[0] % 16
            else:
                rewind = stream.tell()
                stream.seek(last_length_half_byte)
                match_length = read(1)[0] // 16
                stream.seek(rewind)
                last_length_half_byte = 0

            if match_length == 15:
                match_length = read(1)[0]
                if match_length == 255:
                    match_length = struct.unpack("<H", read(2))[0]
                    if match_length == 0:
                        match_length = struct.unpack("<I", read(4))[0]

                    if match_length < 15 + 7:
                        raise InvalidBufferError("Invalid LZXPRESS match length")

                    match_length -= 15 + 7
                match_length += 15
            match_length += 7
        match_length += 3

        if match_offset > len(dst):
            raise InvalidBufferError("Invalid LZXPRESS match offset")

        # Check the whole match before copying it.  A single token can declare
        # a multi-megabyte match, so growing first and checking later is too late.
        if len(dst) + match_length > limit:
            raise InvalidBufferError(f"Decompressed buffer exceeds the limit of {limit} bytes")

        remaining = match_length
        while remaining > 0:
            match_size = min(remaining, match_offset)
            dst += dst[-match_offset : (-match_offset + match_size) or None]
            remaining -= match_size

    return bytes(dst)


class ETL:
    """The main interface when controlling an ETL file."""

    def __init__(self, fh: BinaryIO, max_decompressed_size: int | None = None):
        self.fh = fh
        # ``None`` means "use MAX_DECOMPRESSED_SIZE at read time", so the module
        # setting can still be changed after construction.
        self.max_decompressed_size = max_decompressed_size

        # Load the first buffer inside the file,
        # The first event of the buffer contains a logfile header
        first_buffer = Buffer(self, 0)
        self.buffer_header = first_buffer.header
        trace_header = first_buffer.read_record(0).header
        self.logfile_header = LogfileHeader(trace_header)

        # Lookup PointerSize
        self.pointer_size = self.logfile_header.pointer_size

        if self.pointer_size not in (4, 8):
            raise InvalidHeaderError(f"invalid pointer size: {self.pointer_size}")

        self.is_64bit = self.logfile_header.is_64bit

        self.start_time = self.logfile_header.start_time
        self.buffer_size = self.buffer_header.BufferSize
        self.start = wintimestamp(self.logfile_header.start_time)
        self.end = wintimestamp(self.logfile_header.end_time)

        self._buffer_cache = {0: first_buffer}

    def buffer(self, index: int) -> Buffer:
        """Reads a specific buffer into memory."""
        if index < 0 or index >= self.logfile_header.buffers_written:
            raise IndexError("buffer index out of range")

        try:
            buf = self._buffer_cache[index]
        except KeyError:
            prev_buf = self.buffer(index - 1)
            buf = Buffer(self, prev_buf.next_buffer)
            self._buffer_cache[index] = buf

        return buf

    def buffers(self) -> Iterator[Buffer]:
        for i in range(self.logfile_header.buffers_written):
            yield self.buffer(i)

    def __iter__(self) -> Iterator[Event]:
        for buffer in self.buffers():
            yield from buffer

    def calculate_timestamp(self, time_delta: int) -> datetime:
        return wintimestamp(self.get_filetime_for_event(time_delta))

    def get_filetime_for_event(self, time_delta: int) -> int:
        return self.logfile_header.timestamp_base + int(self._calculate_timescale_for_event(time_delta))

    def _calculate_timescale_for_event(self, time_delta: int) -> float:
        return self.logfile_header.timestamp_scale * time_delta


class Buffer:
    def __init__(self, etl: ETL, offset: int):
        self.fh = etl.fh
        self.etl = etl
        self.offset = offset

        self._header = None
        self._data = None

    @property
    def header(self) -> c_etl.BufferHeader:
        if not self._header:
            self.fh.seek(self.offset)
            self._header = c_etl.BufferHeader(self.fh)

        return self._header

    @property
    def size(self) -> int:
        return self.header.BufferSize

    @property
    def data(self) -> memoryview:
        if self._data is None:
            data_len = self.physical_size
            self.fh.seek(self.data_offset)

            tmp_data = self.fh.read(data_len)
            if len(tmp_data) != data_len:
                raise InvalidBufferError(
                    f"Truncated buffer at offset {self.offset:#x}: expected {data_len} bytes, got {len(tmp_data)}"
                )

            if self.header.BufferFlag & BufferFlag.COMPRESSED:
                tmp_data = self._decompress(tmp_data)

            self._data = memoryview(tmp_data)
        return self._data

    @property
    def physical_size(self) -> int:
        """Number of bytes on disk between this buffer's header and its end.

        ``BufferSize`` is the stride between buffers, while ``FilledBytes`` is
        the number of bytes that actually belong to this buffer.  Both are
        physical byte counts; neither says anything about a decompressed
        payload.  A declared size that exceeds the stride would make the read
        spill into the next buffer, so it is rejected instead.
        """
        if self.size < BUFFER_HEADER_SIZE:
            raise InvalidBufferError(f"Invalid data length: BufferSize ({self.size}) is smaller than the header")

        if self.filled_bytes > self.size:
            raise InvalidBufferError(
                f"FilledBytes ({self.filled_bytes}) exceeds BufferSize ({self.size}) at offset {self.offset:#x}"
            )

        data_len = self.filled_bytes - BUFFER_HEADER_SIZE
        if data_len < 0:
            raise InvalidBufferError(
                f"Invalid data length: FilledBytes ({self.filled_bytes}) does not contain the buffer header"
            )

        return data_len

    def _decompress(self, data: bytes) -> bytes:
        if not data:
            return b""

        # LZXPRESS has no declared output size, so bound the expansion before
        # allocating the result.  The stream is validated against the same
        # limit while decoding.
        return _decompress_lzxpress(data, _decompression_limit(self.etl))

    @property
    def data_offset(self) -> int:
        return self.offset + len(c_etl.BufferHeader)

    @property
    def filled_bytes(self) -> int:
        return self.header.FilledBytes

    @property
    def next_buffer(self) -> int:
        return self.offset + self.size

    @property
    def record_data_size(self) -> int:
        """Number of bytes that can contain records after decompression."""
        return len(self.data)

    def __iter__(self) -> Iterator[EventRecord]:
        offset = 0
        data_size = self.record_data_size
        while offset < data_size:
            try:
                event = self.read_record(offset)
            except (EOFError, NoMoreEventsError, InvalidHeaderError, InvalidMarkerError, InvalidRecordError):
                # A partial or non-record tail is padding or a truncated write,
                # not an event.  Explicit read_record calls still raise.
                break
            offset += event.aligned_size
            yield event

    def read_record(self, offset: int) -> EventRecord:
        """Parse a record from a given offset inside a buffer."""
        data = self.data[offset:]
        if not data:
            raise EOFError("No record data left")

        event_record = EventRecord()
        header = select_event_header(
            data=data,
            etl=self.etl,
        )

        if header.size > len(data):
            raise InvalidRecordError(
                f"Record at offset {offset} declares {header.size} bytes, but only {len(data)} are available"
            )

        event_record._header = header

        return event_record

    def open(self) -> BinaryIO:
        return io.BytesIO(self.data)


class EventRecord:
    __slots__ = (
        "_event",
        "_header",
    )

    def __init__(self):
        self._event = None
        self._header = None

    @property
    def header(self) -> Header:
        """A header of the type Header."""
        return self._header

    @property
    def size(self) -> int:
        """Size of the whole record."""
        return self.header.size

    @property
    def event(self) -> Event:
        """Parse payload inside the event header."""
        if not self._event:
            self._event = parse_payload(self._header)

        return self._event

    @property
    def aligned_size(self) -> int:
        return (self.size + 7) & 0xFFFFFFF8

    def __repr__(self) -> str:
        return "<EventRecord>"


class Event:
    __slots__ = [
        "_event",
        "_header",
        "_manifest",
        "_record",
        "_struct",
    ]

    def __init__(self, header: Header, event_manifest: ModuleType):
        self._header = header
        self._manifest = event_manifest
        self._event = None

        # Not every header has an opcode and version, so check it like this.
        opcode = getattr(header, "opcode", None)
        version = getattr(header, "version", None)
        key = (opcode, version)

        if event_manifest:
            try:
                self._event = event_manifest.EVENTS[key]
                self._struct = self._event.template(header.payload)
            except KeyError:
                self._struct = None
        else:
            self._struct = None

    def __getattr__(self, attribute: str) -> Any:
        try:
            return getattr(self._struct, attribute)
        except AttributeError:
            return object.__getattribute__(self, attribute)

    def provider_name(self) -> str | None:
        """Returns the manifest provider name."""
        return self._manifest.PROVIDER_NAME if self._manifest else None

    def ts(self) -> datetime:
        """Returns the event timestamp."""
        return self._header.timestamp

    def provider_id(self) -> UUID:
        """Returns the GUID of the provider from the header."""
        return self._header.provider_id

    def symbol(self) -> str | None:
        return self._event.symbol if self._event else None

    def event_values(self) -> dict[str, Any]:
        """Create an items view that holds event and header data.

        The header data is additional information provided from a specific header.
        The event data is from a specific manifest file if it exists.
        """
        event_values = self._header.additional_header_fields()
        struct_events = self._struct._values if self._struct else {}

        # Pretty print Instance values.
        update_event = {}
        instance_values = ((key, value) for key, value in struct_events.items() if isinstance(value, Structure))
        for key, value in instance_values:
            if hasattr(value, "sid"):
                update_event[key] = read_sid(value.sid.dumps())

        event_values.update(struct_events)
        event_values.update(update_event)
        return event_values

    def __repr__(self) -> str:
        symbol = self._event.symbol if self._event else None
        return f"{self._header} <{symbol} {self._struct!r}>"


def parse_payload(header: Header) -> Event:
    """Parse the event payload using the appropriate manifest, if available."""
    try:
        mf = manifest.lookup(header.provider_id)
        if header.is_64bit:
            mf.c_parser.EtwPointer.as_64bit()
            mf.c_parser.UserSID_blob.as_64bit()
        else:
            mf.c_parser.EtwPointer.as_32bit()
            mf.c_parser.UserSID_blob.as_32bit()
    except (ManifestNotFoundError, AttributeError):
        mf = None

    return Event(header, mf)
