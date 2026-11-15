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
from dissect.etl.mapping import MapDefinition

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from types import ModuleType
    from uuid import UUID

    from dissect.etl.headers.headers import Header
    from dissect.etl.mapping import MappedValue


class ETL:
    """The main interface when controlling an ETL file."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

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
        if not self._data:
            data_len = min(self.size, self.filled_bytes) - len(c_etl.BufferHeader)
            if data_len < 0:
                raise InvalidBufferError("Invalid data length")
            self.fh.seek(self.data_offset)

            tmp_data = self.fh.read(data_len)

            if self.header.BufferFlag & BufferFlag.COMPRESSED:
                tmp_data = xpress_decompress(tmp_data)

            self._data = memoryview(tmp_data)
        return self._data

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
        offset = 0
        try:
            while offset < self.filled_bytes:
                event = self.read_record(offset)
                offset += event.aligned_size
                yield event
        except (EOFError, NoMoreEventsError):
            pass

    def read_record(self, offset: int) -> EventRecord:
        """Parse a record from a given offset inside a buffer."""
        event_record = EventRecord()
        data = self.data[offset:]
        header = select_event_header(
            data=data,
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
        "_mappings",
        "_record",
        "_struct",
    ]

    def __init__(self, header: Header, event_manifest: ModuleType):
        self._header = header
        self._manifest = event_manifest
        self._event = None
        self._mappings = None

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

    @property
    def mappings(self) -> dict[str, MappedValue]:
        """Interpreted manifest value/bit maps, keyed by original payload field name.

        The values in this view are derived from the same parsed structure as
        :meth:`event_values`; :attr:`MappedValue.raw_value` always preserves the original numeric
        value so display text never replaces the value used for rule evaluation.
        """
        if self._mappings is None:
            self._mappings = self._resolve_mappings()
        return self._mappings

    def mapped_values(self) -> dict[str, MappedValue]:
        """Alias for :attr:`mappings`."""
        return self.mappings

    def mapping_results(self) -> dict[str, dict[str, Any]]:
        """Return the mapped fields as JSON-friendly dictionaries for backend display."""
        return {field: mapped.as_dict() for field, mapped in self.mappings.items()}

    def _resolve_mappings(self) -> dict[str, MappedValue]:
        if self._manifest is None or self._struct is None or self._event is None:
            return {}

        # Map definitions and template associations are provider-local: a same-named map in
        # another provider must never be consulted here.
        template_maps = getattr(self._manifest, "TEMPLATE_MAPS", {})
        field_maps = template_maps.get(self._event.template)
        if not field_maps:
            return {}

        definitions = getattr(self._manifest, "MAPS", {})
        provider_guid = getattr(self._manifest, "PROVIDER_GUID", None)
        provider_name = getattr(self._manifest, "PROVIDER_NAME", None)
        struct_values = _struct_values(self._struct)

        resolved = {}
        for field_name, (map_name, width, signed) in field_maps.items():
            if field_name not in struct_values:
                continue

            raw_value = struct_values[field_name]
            if not isinstance(raw_value, int):
                continue

            definition = definitions.get(map_name)
            if definition is None:
                # Preserve the intended provider-local map identity instead of dropping the
                # field; no numeric interpretation is attempted without a definition.
                definition = MapDefinition.missing(map_name, provider_guid, provider_name)

            resolved[field_name] = definition.resolve(raw_value, width or 0, field_name, signed)
        return resolved

    def event_values(self) -> dict[str, Any]:
        """Create an items view that holds event and header data.

        The header data is additional information provided from a specific header.
        The event data is from a specific manifest file if it exists.
        """
        event_values = self._header.additional_header_fields()
        struct_events = _struct_values(self._struct)

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


def _struct_values(struct: Structure | None) -> dict[str, Any]:
    """Return the parsed field values of a cstruct structure across supported versions."""
    if struct is None:
        return {}
    return getattr(struct, "__values__", getattr(struct, "_values", {}))


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
