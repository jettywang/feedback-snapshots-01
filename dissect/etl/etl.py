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
from types import MappingProxyType
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
    from collections.abc import Iterator, Mapping
    from datetime import datetime
    from types import ModuleType
    from uuid import UUID

    from dissect.etl.headers.headers import Header


# Provenance labels for the facets of an EventResult.
SOURCE_HEADER = "etw-header"
SOURCE_EXTENSION = "etw-header-extension"
SOURCE_MANIFEST = "manifest-template"


def _snapshot_value(value: Any) -> Any:
    """Materialize a parsed value into an immutable, self-contained snapshot.

    Nested structures become read-only mappings (keeping their original field names),
    arrays become tuples and mutable byte buffers become bytes. The snapshot no longer
    references any live cstruct state, so continued parsing can never rewrite it.
    """
    if isinstance(value, Structure):
        return MappingProxyType({key: _snapshot_value(val) for key, val in value.__values__.items()})
    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, dict):
        return MappingProxyType({key: _snapshot_value(val) for key, val in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_snapshot_value(item) for item in value)
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return value


def _display_value(value: Any) -> Any:
    """Convert a parsed value to its legacy display form for the flat event_values view.

    SID structures are pretty-printed (a display-only conversion; the raw value stays
    available in the payload facet). Every other value is snapshotted so the flat view
    never holds references to live parser state.
    """
    if isinstance(value, Structure) and hasattr(value, "sid"):
        return read_sid(value.sid.dumps())
    return _snapshot_value(value)


class EventResult:
    """Immutable, faceted representation of a single parsed event.

    The facets never merge and always keep their original field names, so a manifest
    payload field can never overwrite ETW header metadata:

    - ``header``: metadata from the ETW event header. This is the only facet that
      business correlation (process or activity mapping) may use, exposed directly
      through the ``process_id``, ``thread_id`` and ``activity_id`` properties.
    - ``extensions``: extended data items carried by the header.
    - ``payload``: values decoded with the provider manifest template, or ``None``
      when the template is unknown (no manifest found or no matching event in it).

    All values are materialized snapshots taken at parse time; continuing to parse
    other events can never rewrite a previously returned result.
    """

    __slots__ = (
        "_activity_id",
        "_extensions",
        "_header",
        "_legacy_header",
        "_legacy_payload",
        "_payload",
        "_process_id",
        "_provider_name",
        "_symbol",
        "_thread_id",
    )

    def __init__(
        self,
        *,
        header_fields: dict[str, Any],
        legacy_header_fields: dict[str, Any],
        extensions: list[dict[str, Any]],
        payload: dict[str, Any] | None,
        legacy_payload: dict[str, Any],
        process_id: int | None,
        thread_id: int | None,
        activity_id: UUID | None,
        provider_name: str | None,
        symbol: str | None,
    ):
        self._header = MappingProxyType({key: _snapshot_value(value) for key, value in header_fields.items()})
        self._legacy_header = dict(legacy_header_fields)
        self._extensions = tuple(_snapshot_value(item) for item in extensions)
        self._payload = (
            None if payload is None else MappingProxyType({key: _snapshot_value(v) for key, v in payload.items()})
        )
        self._legacy_payload = dict(legacy_payload)
        self._process_id = process_id
        self._thread_id = thread_id
        self._activity_id = activity_id
        self._provider_name = provider_name
        self._symbol = symbol

    @property
    def header(self) -> Mapping[str, Any]:
        """Header metadata facet (source: ``etw-header``), with native value types."""
        return self._header

    @property
    def extensions(self) -> tuple[Mapping[str, Any], ...]:
        """Extended data items facet (source: ``etw-header-extension``)."""
        return self._extensions

    @property
    def payload(self) -> Mapping[str, Any] | None:
        """Manifest template values facet (source: ``manifest-template``).

        ``None`` when the template is unknown, which is explicitly distinct from an
        empty payload; see :func:`template_known`.
        """
        return self._payload

    @property
    def template_known(self) -> bool:
        """Whether a manifest template was available to decode the payload."""
        return self._payload is not None

    @property
    def provider_name(self) -> str | None:
        return self._provider_name

    @property
    def symbol(self) -> str | None:
        return self._symbol

    @property
    def process_id(self) -> int | None:
        """Process id from the ETW header metadata facet. Never taken from the payload."""
        return self._process_id

    @property
    def thread_id(self) -> int | None:
        """Thread id from the ETW header metadata facet. Never taken from the payload."""
        return self._thread_id

    @property
    def activity_id(self) -> UUID | None:
        """Activity id from the ETW header metadata facet. Never taken from the payload."""
        return self._activity_id

    @property
    def collisions(self) -> frozenset[str]:
        """Field names present in both the header metadata and the manifest payload."""
        if self._payload is None:
            return frozenset()
        return frozenset(self._header) & frozenset(self._payload)

    def field_sources(self, name: str) -> tuple[str, ...]:
        """Return the provenance labels of every facet that contains a field ``name``."""
        sources = []
        if name in self._header:
            sources.append(SOURCE_HEADER)
        if any(name in extension for extension in self._extensions):
            sources.append(SOURCE_EXTENSION)
        if self._payload is not None and name in self._payload:
            sources.append(SOURCE_MANIFEST)
        return tuple(sources)

    def flatten(self) -> dict[str, Any]:
        """Recreate the legacy flat ``event_values`` view.

        Compatibility rule (historical behaviour, kept for existing consumers): header
        fields are inserted first and manifest payload values are written afterwards, so
        on a name collision the *payload* value wins. Nested structures are represented
        by their immutable snapshot and SID structures by their pretty-printed string.

        This is a display-oriented view only. Never derive process or activity
        correlation from it; use the ``header`` facet or the ``process_id``,
        ``thread_id`` and ``activity_id`` properties instead.
        """
        flat = dict(self._legacy_header)
        flat.update(self._legacy_payload)
        return flat

    def __repr__(self) -> str:
        return (
            f"<EventResult symbol={self._symbol!r} header={dict(self._header)!r} "
            f"extensions={len(self._extensions)} items payload={self._payload!r}>"
        )


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
        "_record",
        "_result",
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

        self._result = self._build_result()

    def _build_result(self) -> EventResult:
        """Snapshot the parsed event into the faceted, immutable result representation."""
        header = self._header

        header_fields = header.standard_header_fields()
        header_fields.update(header.metadata_fields())

        payload = None
        legacy_payload = {}
        if self._struct is not None:
            payload = dict(self._struct.__values__)
            legacy_payload = {key: _display_value(value) for key, value in payload.items()}

        process_id = getattr(header, "process_id", None)
        if process_id is None:
            process_id = header_fields.get("ProcessId")
        thread_id = getattr(header, "thread_id", None)
        if thread_id is None:
            thread_id = header_fields.get("ThreadId")
        activity_id = getattr(header, "activity_id", None)

        return EventResult(
            header_fields=header_fields,
            legacy_header_fields=header.additional_header_fields(),
            extensions=header.extended_data_fields(),
            payload=payload,
            legacy_payload=legacy_payload,
            process_id=process_id,
            thread_id=thread_id,
            activity_id=activity_id,
            provider_name=self.provider_name(),
            symbol=self.symbol(),
        )

    def __getattr__(self, attribute: str) -> Any:
        try:
            return getattr(self._struct, attribute)
        except AttributeError:
            return object.__getattribute__(self, attribute)

    @property
    def result(self) -> EventResult:
        """The faceted, immutable result of this event.

        Forensic reports and correlation logic must be built on this representation:
        the header metadata facet always keeps its own values, even when the manifest
        payload contains fields with the same name.
        """
        return self._result

    @property
    def process_id(self) -> int | None:
        """Process id from the ETW header metadata facet."""
        return self._result.process_id

    @property
    def thread_id(self) -> int | None:
        """Thread id from the ETW header metadata facet."""
        return self._result.thread_id

    @property
    def activity_id(self) -> UUID | None:
        """Activity id from the ETW header metadata facet."""
        return self._result.activity_id

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

        .. warning::
            This is the legacy flat view. On a name collision the manifest payload
            value overwrites the header value (see :func:`EventResult.flatten`), so
            never use this view for process or activity correlation. Use
            :func:`Event.result` instead, which keeps both values with their source.
        """
        return self._result.flatten()

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
