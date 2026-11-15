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
from enum import IntEnum
from typing import TYPE_CHECKING, Any, BinaryIO
from uuid import UUID

from dissect.cstruct import Structure
from dissect.util.compression.lzxpress import decompress as xpress_decompress
from dissect.util.sid import read_sid
from dissect.util.ts import wintimestamp

from dissect.etl import manifest
from dissect.etl.c_etl import BufferFlag, c_etl
from dissect.etl.exceptions import (
    InvalidBufferError,
    InvalidEventError,
    InvalidHeaderError,
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

    from dissect.etl.headers.headers import Header


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
        while offset < self.filled_bytes:
            try:
                event = self.read_record(offset)
            except NoMoreEventsError:
                # The 0xFFFFFFFF padding marker marks the end of the events inside the buffer.
                break

            if event.header is None:
                # A truncated header has no reliable size, so it must be the last record.
                yield event
                break

            offset += event.aligned_size
            yield event

    @staticmethod
    def _decode_header(header: Header) -> None:
        """Eagerly decode a header so truncation surfaces while reading the record."""
        _ = header.header

    def read_record(self, offset: int) -> EventRecord:
        """Parse a record from a given offset inside a buffer."""
        data = self.data[offset:]
        file_offset = self.data_offset + offset
        try:
            header = select_event_header(
                data=data,
                etl=self.etl,
            )
            # Force the underlying structure to decode now: a marker can be valid while the
            # header itself is truncated. Such a record is corruption, not an unknown event.
            self._decode_header(header)
        except (EOFError, InvalidRecordError) as exc:
            return EventRecord.corrupt(
                data=data,
                buffer_offset=offset,
                file_offset=file_offset,
                error=exc,
            )

        return EventRecord(
            header=header,
            buffer_offset=offset,
            file_offset=file_offset,
        )

    def open(self) -> BinaryIO:
        return io.BytesIO(self.data)


class EventResult(IntEnum):
    """The outcome of turning a raw record into a structured event.

    Only ``MANIFEST_NOT_FOUND`` and ``UNKNOWN_TEMPLATE`` are "unknown but retained" results.
    ``TEMPLATE_FAILED`` and ``TRUNCATED`` signal genuine corruption and must never be reported
    as ordinary unknown events.
    """

    DECODED = 0
    MANIFEST_NOT_FOUND = 1
    UNKNOWN_TEMPLATE = 2
    EMPTY_PAYLOAD = 3
    TEMPLATE_FAILED = 4
    TRUNCATED = 5

    @property
    def is_unknown(self) -> bool:
        """Whether the record is unknown yet intact and therefore safe to retain as raw data."""
        return self in (EventResult.MANIFEST_NOT_FOUND, EventResult.UNKNOWN_TEMPLATE)

    @property
    def is_corrupt(self) -> bool:
        """Whether the record is damaged rather than merely unknown."""
        return self in (EventResult.TEMPLATE_FAILED, EventResult.TRUNCATED)


class RawEvent:
    """The raw, lossless view of a record.

    This object is always available, even when no manifest exists or decoding failed. It keeps
    the original payload bytes as an independent copy so later parsing attempts can neither
    overwrite nor re-encode the physical record.
    """

    __slots__ = (
        "_error",
        "_header",
        "_payload",
        "buffer_offset",
        "file_offset",
        "result",
    )

    def __init__(
        self,
        header: Header | None,
        payload: bytes,
        result: EventResult,
        buffer_offset: int,
        file_offset: int,
        error: Exception | None = None,
    ):
        self._header = header
        # Copy the bytes: a memoryview is backed by the buffer and must not keep mutable state.
        self._payload = bytes(payload)
        self.result = result
        self.buffer_offset = buffer_offset
        self.file_offset = file_offset
        self._error = error

    @classmethod
    def from_header(
        cls,
        header: Header,
        result: EventResult,
        buffer_offset: int,
        file_offset: int,
        error: Exception | None = None,
    ) -> RawEvent:
        return cls(
            header=header,
            payload=header.payload,
            result=result,
            buffer_offset=buffer_offset,
            file_offset=file_offset,
            error=error,
        )

    @property
    def provider_id(self) -> UUID | None:
        """The provider GUID from the header, if the header decoded far enough to expose it."""
        if self._header is None:
            return None
        return getattr(self._header, "provider_id", None)

    @property
    def header_type(self) -> int | None:
        """The numeric trace header type (marker header type), when determinable."""
        if self._header is None:
            return None
        return self._header._marker.header_type

    @property
    def marker(self) -> int | None:
        """The raw marker word of the record, when a header could be constructed."""
        return None if self._header is None else self._header.marker

    @property
    def event_identity(self) -> tuple[int | None, int | None]:
        """The ``(opcode, version)`` pair used to select a manifest event, when available."""
        if self._header is None:
            return (None, None)
        return (getattr(self._header, "opcode", None), getattr(self._header, "version", None))

    @property
    def payload(self) -> bytes:
        """An immutable copy of the original payload exactly as it sits in the file."""
        return self._payload

    @property
    def error(self) -> Exception | None:
        """The decoding error for corrupt records, ``None`` for every other result."""
        return self._error

    @property
    def reason(self) -> str:
        """A human-readable explanation of why no structured fields are available."""
        reasons = {
            EventResult.DECODED: "decoded from a known manifest template",
            EventResult.MANIFEST_NOT_FOUND: "no manifest is registered for this provider",
            EventResult.UNKNOWN_TEMPLATE: "the provider manifest has no template for this event opcode/version",
            EventResult.EMPTY_PAYLOAD: "the record carries no payload bytes, so there is nothing to decode",
            EventResult.TEMPLATE_FAILED: "a known template exists but decoding the payload failed",
            EventResult.TRUNCATED: "the record is truncated and its header could not be decoded",
        }
        text = reasons[self.result]
        if self._error is not None:
            text = f"{text}: {type(self._error).__name__}: {self._error}"
        return text

    def __repr__(self) -> str:
        return (
            f"<RawEvent result={self.result.name} header_type={self.header_type} "
            f"provider_id={self.provider_id} payload={len(self._payload)} bytes "
            f"file_offset=0x{self.file_offset:x}>"
        )


class EventRecord:
    __slots__ = (
        "_event",
        "_header",
        "_raw",
        "buffer_offset",
        "file_offset",
    )

    def __init__(self, header: Header, buffer_offset: int = 0, file_offset: int = 0):
        self._header = header
        self._event = None
        self._raw = None
        self.buffer_offset = buffer_offset
        self.file_offset = file_offset

    @classmethod
    def corrupt(
        cls,
        data: memoryview,
        buffer_offset: int,
        file_offset: int,
        error: Exception,
    ) -> EventRecord:
        """Build a record for bytes that could not even be decoded into a header."""
        record = cls(header=None, buffer_offset=buffer_offset, file_offset=file_offset)
        record._raw = RawEvent(
            header=None,
            payload=data,
            result=EventResult.TRUNCATED,
            buffer_offset=buffer_offset,
            file_offset=file_offset,
            error=error,
        )
        return record

    @property
    def header(self) -> Header | None:
        """A header of the type Header, or ``None`` for a truncated record."""
        return self._header

    @property
    def size(self) -> int:
        """Size of the whole record."""
        return 0 if self._header is None else self._header.size

    @property
    def aligned_size(self) -> int:
        return (self.size + 7) & 0xFFFFFFF8

    @property
    def raw(self) -> RawEvent:
        """The lossless raw view of the record, available for every record."""
        if self._raw is None:
            self._parse()
        return self._raw

    @property
    def event(self) -> Event:
        """Parse payload inside the event header.

        Known events keep their existing structured interface. Unknown events return an ``Event``
        without structured fields, while corrupt records raise the original decoding error instead
        of pretending to be a normal unknown event.
        """
        if self._event is None:
            self._parse()
        if self._event is None:
            raise InvalidEventError(f"record at 0x{self.file_offset:x} is corrupt: {self._raw.reason}")
        return self._event

    def _parse(self) -> None:
        if self._raw is not None:
            # Already classified (e.g. a truncated record built via ``corrupt``).
            return
        raw, parsed_event = parse_payload(
            header=self._header,
            buffer_offset=self.buffer_offset,
            file_offset=self.file_offset,
        )
        self._raw = raw
        self._event = parsed_event

    def __repr__(self) -> str:
        result = self._raw.result.name if self._raw else "unparsed"
        return f"<EventRecord {result}>"


class Event:
    __slots__ = [
        "_event",
        "_header",
        "_manifest",
        "_struct",
    ]

    def __init__(
        self,
        header: Header,
        event_manifest: ModuleType | None,
        event_definition: Any = None,
        struct: Structure | None = None,
    ):
        self._header = header
        self._manifest = event_manifest
        self._event = event_definition
        self._struct = struct

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
        struct_events = self._struct.__values__ if self._struct else {}

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


def parse_payload(
    header: Header,
    buffer_offset: int = 0,
    file_offset: int = 0,
) -> tuple[RawEvent, Event | None]:
    """Parse the event payload using the appropriate manifest, if available.

    Returns the lossless :class:`RawEvent` together with a structured :class:`Event` when one can
    be produced. Records without a usable manifest are classified as unknown but retained; a known
    template that fails to decode is reported as corrupt instead of being disguised as unknown.
    """
    try:
        event_manifest = manifest.lookup(header.provider_id)
        if header.is_64bit:
            event_manifest.c_parser.EtwPointer.as_64bit()
            event_manifest.c_parser.UserSID_blob.as_64bit()
        else:
            event_manifest.c_parser.EtwPointer.as_32bit()
            event_manifest.c_parser.UserSID_blob.as_32bit()
    except (ManifestNotFoundError, AttributeError):
        return (
            RawEvent.from_header(header, EventResult.MANIFEST_NOT_FOUND, buffer_offset, file_offset),
            Event(header, None),
        )

    opcode = getattr(header, "opcode", None)
    version = getattr(header, "version", None)
    try:
        event_definition = event_manifest.EVENTS[(opcode, version)]
    except KeyError:
        return (
            RawEvent.from_header(header, EventResult.UNKNOWN_TEMPLATE, buffer_offset, file_offset),
            Event(header, event_manifest),
        )

    if len(header.payload) == 0:
        return (
            RawEvent.from_header(header, EventResult.EMPTY_PAYLOAD, buffer_offset, file_offset),
            Event(header, event_manifest),
        )

    try:
        struct = event_definition.template(header.payload)
    except Exception as exc:
        # A known template exists, but the actual payload does not fit it. This is corruption,
        # not an unknown event: keep the raw bytes and attach the decoding error.
        raw = RawEvent.from_header(
            header,
            EventResult.TEMPLATE_FAILED,
            buffer_offset,
            file_offset,
            error=exc,
        )
        return raw, None

    return (
        RawEvent.from_header(header, EventResult.DECODED, buffer_offset, file_offset),
        Event(header, event_manifest, event_definition, struct),
    )
