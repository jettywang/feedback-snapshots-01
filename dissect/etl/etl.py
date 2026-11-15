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
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct import Structure
from dissect.util.compression.lzxpress import decompress as xpress_decompress
from dissect.util.sid import read_sid
from dissect.util.ts import wintimestamp

from dissect.etl import manifest
from dissect.etl.c_etl import BufferFlag, c_etl
from dissect.etl.exceptions import (
    InvalidBufferError,
    InvalidHeaderError,
    ManifestNotFoundError,
    NoMoreEventsError,
)
from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.headers.utils import select_event_header

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from datetime import datetime
    from types import ModuleType
    from uuid import UUID

    from dissect.etl.headers.headers import Header


# The number of bytes of decompressed buffer payload kept in memory. Event records returned to a
# caller hold their own view of the payload bytes they were parsed from, so evicting a buffer never
# changes previously returned events. Buffer headers are indexed separately and do not use this
# budget.
BUFFER_CACHE_BUDGET = 32 * 1024 * 1024

# Buffer objects cache only a parsed header, never a payload. Keeping a small number of them
# avoids re-reading headers on repeated access without retaining data on behalf of a payload.
BUFFER_HEADER_CACHE_SIZE = 64


class ETL:
    """The main interface when controlling an ETL file."""

    def __init__(self, fh: BinaryIO, buffer_cache_budget: int | None = None):
        self.fh = fh

        # Buffer payloads are cached separately from the buffer header index, so locating a
        # buffer never pins decompressed payloads in memory.
        self.buffer_cache_budget = BUFFER_CACHE_BUDGET if buffer_cache_budget is None else buffer_cache_budget
        self._payload_cache: OrderedDict[int, memoryview] = OrderedDict()
        self._payload_cache_bytes = 0
        self._payload_cache_peak_bytes = 0

        # Physical offsets of the buffers known so far, indexed by buffer index. The list grows
        # on demand: locating buffer N only reads the headers before it. Only offsets are kept
        # here; parsed headers live in the bounded ``_buffer_cache``.
        self._buffer_offsets = [0]
        self._buffer_cache: OrderedDict[int, Buffer] = OrderedDict()

        # Load the first buffer inside the file,
        # The first event of the buffer contains a logfile header
        first_buffer = self._new_buffer(0)
        self._cache_buffer(0, first_buffer)

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

    def buffer(self, index: int) -> Buffer:
        """Reads a specific buffer into memory."""
        if index < 0 or index >= self.logfile_header.buffers_written:
            raise IndexError("buffer index out of range")

        try:
            buf = self._buffer_cache[index]
        except KeyError:
            buf = self._new_buffer(index)
            self._cache_buffer(index, buf)
        else:
            self._buffer_cache.move_to_end(index)

        return buf

    def buffers(self) -> Iterator[Buffer]:
        for i in range(self.logfile_header.buffers_written):
            yield self.buffer(i)

    def __iter__(self) -> Iterator[Event]:
        for buffer in self.buffers():
            yield from buffer

    @property
    def buffer_cache_bytes(self) -> int:
        """The number of decompressed payload bytes currently retained in the cache."""
        return self._payload_cache_bytes

    @property
    def buffer_cache_peak_bytes(self) -> int:
        """The highest number of decompressed payload bytes retained in the cache so far."""
        return self._payload_cache_peak_bytes

    @property
    def buffer_offsets(self) -> list[int]:
        """The physical offsets of the buffers indexed so far."""
        return list(self._buffer_offsets)

    def _new_buffer(self, index: int) -> Buffer:
        offset, header = self._locate_buffer(index)
        return Buffer(self, offset, index=index, loader=self._load_payload, header=header)

    def _cache_buffer(self, index: int, buffer: Buffer) -> None:
        # Buffer objects only hold a header, never the payload. Keep the recently used ones so
        # repeated access does not need to parse the same header again; any bound is acceptable
        # here because payload memory is accounted for by ``_payload_cache``.
        self._buffer_cache.pop(index, None)
        self._buffer_cache[index] = buffer
        while len(self._buffer_cache) > BUFFER_HEADER_CACHE_SIZE:
            self._buffer_cache.popitem(last=False)

    def _locate_buffer(self, index: int) -> tuple[int, c_etl.BufferHeader]:
        """Return the offset and header of ``index``, expanding the position index as needed."""
        if index < len(self._buffer_offsets):
            cached = self._buffer_cache.get(index)
            if cached is not None:
                return self._buffer_offsets[index], cached.header
            return self._buffer_offsets[index], self._read_buffer_header(self._buffer_offsets[index], index)

        current = len(self._buffer_offsets) - 1
        cached = self._buffer_cache.get(current)
        header = cached.header if cached is not None else None

        while len(self._buffer_offsets) <= index:
            offset = self._buffer_offsets[current]
            if header is None:
                header = self._read_buffer_header(offset, current)

            size = header.BufferSize
            if size <= 0:
                raise InvalidBufferError(f"invalid buffer size {size} for buffer {current} at offset 0x{offset:x}")

            if cached is None:
                # Keep the header of a buffer we just indexed, so reverse or repeated access can
                # reuse it without re-reading. This holds no payload.
                self._cache_buffer(
                    current,
                    Buffer(self, offset, index=current, loader=self._load_payload, header=header),
                )

            self._buffer_offsets.append(offset + size)
            current += 1
            header = None
            cached = None

        offset = self._buffer_offsets[index]
        if current == index and header is not None:
            return offset, header
        return offset, self._read_buffer_header(offset, index)

    def _read_buffer_header(self, offset: int, index: int) -> c_etl.BufferHeader:
        """Read and parse only the physical buffer header at ``offset``."""
        header_size = len(c_etl.BufferHeader)
        self.fh.seek(offset)
        data = self.fh.read(header_size)

        if len(data) < header_size:
            raise InvalidBufferError(
                f"truncated buffer header for buffer {index} at offset 0x{offset:x}: "
                f"expected {header_size} bytes, got {len(data)}"
            )

        return c_etl.BufferHeader(data)

    def _load_payload(self, buffer: Buffer) -> memoryview:
        """Return the decompressed payload of ``buffer``, using the byte-budgeted cache."""
        cached = self._payload_cache.get(buffer.offset)
        if cached is not None:
            self._payload_cache.move_to_end(buffer.offset)
            return cached

        data = buffer._read_payload(validate=True)
        self._cache_payload(buffer.offset, data)
        return data

    def _cache_payload(self, offset: int, data: memoryview) -> None:
        size = len(data)
        if size > self.buffer_cache_budget:
            # A payload larger than the whole budget is returned to the caller, but not retained
            # here: the caller (or an event it keeps) already keeps the bytes alive when needed.
            return

        while self._payload_cache and self._payload_cache_bytes + size > self.buffer_cache_budget:
            _, evicted = self._payload_cache.popitem(last=False)
            self._payload_cache_bytes -= len(evicted)

        self._payload_cache.pop(offset, None)
        self._payload_cache[offset] = data
        self._payload_cache_bytes += size
        self._payload_cache_peak_bytes = max(self._payload_cache_peak_bytes, self._payload_cache_bytes)

    def calculate_timestamp(self, time_delta: int) -> datetime:
        return wintimestamp(self.get_filetime_for_event(time_delta))

    def get_filetime_for_event(self, time_delta: int) -> int:
        return self.logfile_header.timestamp_base + int(self._calculate_timescale_for_event(time_delta))

    def _calculate_timescale_for_event(self, time_delta: int) -> float:
        return self.logfile_header.timestamp_scale * time_delta


class Buffer:
    def __init__(
        self,
        etl: ETL,
        offset: int,
        index: int | None = None,
        loader: Callable[[Buffer], memoryview] | None = None,
        header: c_etl.BufferHeader | None = None,
    ):
        self.fh = etl.fh
        self.etl = etl
        self.offset = offset
        self.index = index
        self._loader = loader

        self._header = header

    @property
    def header(self) -> c_etl.BufferHeader:
        if self._header is None:
            self._header = self._read_header()

        return self._header

    def _read_header(self) -> c_etl.BufferHeader:
        self.fh.seek(self.offset)
        data = self.fh.read(len(c_etl.BufferHeader))
        if len(data) < len(c_etl.BufferHeader):
            raise InvalidBufferError(
                f"truncated buffer header for buffer {self.index} at offset 0x{self.offset:x}: "
                f"expected {len(c_etl.BufferHeader)} bytes, got {len(data)}"
            )
        return c_etl.BufferHeader(data)

    @property
    def size(self) -> int:
        return self.header.BufferSize

    @property
    def data(self) -> memoryview:
        if self._loader is None:
            return self._read_payload()
        return self._loader(self)

    def _read_payload(self, validate: bool = False) -> memoryview:
        data_len = min(self.size, self.filled_bytes) - len(c_etl.BufferHeader)
        if data_len < 0:
            raise InvalidBufferError(f"invalid data length {data_len} for buffer at offset 0x{self.offset:x}")
        self.fh.seek(self.data_offset)

        tmp_data = self.fh.read(data_len)

        if validate and len(tmp_data) != data_len:
            raise InvalidBufferError(
                f"truncated payload for buffer {self.index} at data offset 0x{self.data_offset:x} "
                f"(buffer at 0x{self.offset:x}): expected {data_len} bytes, got {len(tmp_data)}"
            )

        if self.header.BufferFlag & BufferFlag.COMPRESSED:
            tmp_data = xpress_decompress(tmp_data)

        return memoryview(tmp_data)

    @property
    def data_offset(self) -> int:
        return self.offset + len(c_etl.BufferHeader)

    @property
    def filled_bytes(self) -> int:
        return self.header.FilledBytes

    @property
    def next_buffer(self) -> int:
        return self.offset + self.size

    def __iter__(self) -> Iterator[EventRecord]:
        # Take one payload snapshot for the traversal. An event keeps a reference to the bytes it
        # was parsed from, so it stays readable after this buffer is evicted from the payload cache,
        # and the buffer is read at most once per traversal.
        data: memoryview | None = None
        snapshot_attempted = False

        offset = 0
        try:
            while offset < self.filled_bytes:
                if not snapshot_attempted:
                    snapshot_attempted = True
                    try:
                        data = self.data
                    except InvalidBufferError:
                        # Let read_record surface the error as it did before.
                        data = None

                event = self.read_record(offset, data=data)
                offset += event.aligned_size
                yield event
        except (EOFError, NoMoreEventsError):
            pass

    def read_record(self, offset: int, data: memoryview | None = None) -> EventRecord:
        """Parse a record from a given offset inside a buffer."""
        event_record = EventRecord()
        if data is None:
            data = self.data
        record_data = data[offset:]
        header = select_event_header(
            data=record_data,
            etl=self.etl,
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
