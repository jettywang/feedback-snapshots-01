from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from dissect.etl.c_etl import BufferFlag

if TYPE_CHECKING:
    from dissect.etl.etl import ETL


@dataclass(frozen=True, slots=True)
class LogfileLoss:
    """Loss counters claimed by the logfile header.

    These are values reported by the logger itself, not measurements taken
    from the physical file. They must not be added to physical or parse
    failures to produce a "total lost" number.
    """

    events_lost: int
    buffers_lost: int
    source: str = "TraceLogfileHeader"

    def as_dict(self) -> dict[str, Any]:
        return {
            "events_lost": {"value": self.events_lost, "source": self.source},
            "buffers_lost": {"value": self.buffers_lost, "source": self.source},
        }


@dataclass(frozen=True, slots=True)
class PhysicalBuffers:
    """Buffer availability observed from the physical file layout."""

    declared: int
    present: int
    missing: list[int]
    truncated: list[int]
    events_lost_flagged: list[int]
    buffer_lost_flagged: list[int]
    source: str = "BufferHeader"

    @property
    def missing_count(self) -> int:
        return len(self.missing)

    @property
    def truncated_count(self) -> int:
        return len(self.truncated)

    def as_dict(self) -> dict[str, Any]:
        return {
            "declared": {"value": self.declared, "source": "TraceLogfileHeader.BuffersWritten"},
            "present": self.present,
            "missing": {"value": self.missing_count, "buffer_indices": self.missing, "source": self.source},
            "truncated": {"value": self.truncated_count, "buffer_indices": self.truncated, "source": self.source},
            "events_lost_flagged": {
                "value": len(self.events_lost_flagged),
                "buffer_indices": self.events_lost_flagged,
                "source": "BufferHeader.BufferFlag",
            },
            "buffer_lost_flagged": {
                "value": len(self.buffer_lost_flagged),
                "buffer_indices": self.buffer_lost_flagged,
                "source": "BufferHeader.BufferFlag",
            },
        }


@dataclass(frozen=True, slots=True)
class RecordFailure:
    """The byte range of a buffer that could not be scanned."""

    buffer_index: int
    start_offset: int
    end_offset: int
    error: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "buffer_index": self.buffer_index,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class RecordHealth:
    """Record-level parse outcome.

    The three counters are deliberately separate: a record can fail to parse,
    belong to a provider without a manifest (actively skipped), or parse fully.
    Skipped providers are reported with their provider id so the raw counts can
    be traced back to a concrete source.
    """

    parsed: int
    providers_skipped: dict[str, int]
    parse_failures: list[RecordFailure]

    @property
    def providers_skipped_count(self) -> int:
        return sum(self.providers_skipped.values())

    @property
    def parse_failure_count(self) -> int:
        return len(self.parse_failures)

    def as_dict(self) -> dict[str, Any]:
        return {
            "parsed": self.parsed,
            "providers_skipped": {
                "value": self.providers_skipped_count,
                "by_provider_id": dict(sorted(self.providers_skipped.items())),
                "source": "manifest.lookup",
            },
            "parse_failures": {
                "value": self.parse_failure_count,
                "ranges": [failure.as_dict() for failure in self.parse_failures],
                "source": "Buffer.read_record",
            },
        }


@dataclass(frozen=True, slots=True)
class HealthSummary:
    """A layered view of how reliable the observation coverage of an ETL is.

    The sections are independent observations from different sources. They are
    never summed into a single loss figure, because a header claim, a missing
    physical buffer and a malformed record describe different things. A header
    reporting zero losses does not make the trace complete when the physical
    layout or the parser disagree.
    """

    logfile: LogfileLoss
    physical: PhysicalBuffers
    records: RecordHealth
    file_size: int

    @property
    def coverage_complete(self) -> bool:
        """True only when no source reports a coverage limitation."""
        return (
            self.logfile.events_lost == 0
            and self.logfile.buffers_lost == 0
            and self.physical.missing_count == 0
            and self.physical.truncated_count == 0
            and not self.physical.events_lost_flagged
            and not self.physical.buffer_lost_flagged
            and self.records.parse_failure_count == 0
        )

    @property
    def interpretation_complete(self) -> bool:
        """True when every parsed record had a manifest to decode its payload."""
        return self.records.providers_skipped_count == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_size": self.file_size,
            "coverage_complete": self.coverage_complete,
            "interpretation_complete": self.interpretation_complete,
            "logfile_loss": self.logfile.as_dict(),
            "physical_buffers": self.physical.as_dict(),
            "records": self.records.as_dict(),
        }


def _make_error_callback(
    buffer_index: int, parse_failures: list[RecordFailure]
) -> Callable[[int, int, Exception], None]:
    def on_error(start_offset: int, end_offset: int, error: Exception) -> None:
        parse_failures.append(
            RecordFailure(
                buffer_index=buffer_index,
                start_offset=start_offset,
                end_offset=end_offset,
                error=type(error).__name__,
            )
        )

    return on_error


def build_health_summary(etl: ETL) -> HealthSummary:
    """Scan an ETL and build a :class:`HealthSummary`.

    Already parsed events are left untouched; this scan only reads the same
    buffers and records where coverage is limited. It walks the declared
    buffers sequentially so a truncated tail can be distinguished from a
    fully missing buffer.
    """
    from dissect.etl.etl import Buffer

    fh = etl.fh
    fh.seek(0, 2)
    file_size = fh.tell()

    logfile_header = etl.logfile_header
    declared = logfile_header.buffers_written
    buffer_header_size = len(etl.buffer(0).header)

    missing: list[int] = []
    truncated: list[int] = []
    events_lost_flagged: list[int] = []
    buffer_lost_flagged: list[int] = []

    parsed = 0
    providers_skipped: dict[str, int] = {}
    parse_failures: list[RecordFailure] = []

    present = 0
    offset = 0
    for index in range(declared):
        if offset >= file_size:
            missing.extend(range(index, declared))
            break

        if offset + buffer_header_size > file_size:
            truncated.append(index)
            break

        buffer = Buffer(etl, offset)
        header = buffer.header

        if header.BufferFlag & BufferFlag.EVENTS_LOST:
            events_lost_flagged.append(index)
        if header.BufferFlag & BufferFlag.BUFFER_LOST:
            buffer_lost_flagged.append(index)

        # A buffer is truncated when the bytes it claims to have filled
        # (BufferHeader + records) run past the physical end of the file.
        # The full BufferSize may legitimately exceed the file for the last
        # buffer, since only the filled portion is persisted.
        if offset + header.FilledBytes > file_size:
            truncated.append(index)
            break

        present += 1

        for record in buffer.__iter__(on_error=_make_error_callback(index, parse_failures)):
            parsed += 1
            # The logfile header event is a control record, not an observed
            # event from a provider, so it is excluded from provider stats.
            if index == 0 and _is_logfile_header(record):
                continue
            event = record.event
            if record.provider_skipped:
                provider_id = str(event.provider_id())
                providers_skipped[provider_id] = providers_skipped.get(provider_id, 0) + 1

        offset = buffer.next_buffer

    return HealthSummary(
        logfile=LogfileLoss(
            events_lost=logfile_header.events_lost,
            buffers_lost=logfile_header.buffers_lost,
        ),
        physical=PhysicalBuffers(
            declared=declared,
            present=present,
            missing=missing,
            truncated=truncated,
            events_lost_flagged=events_lost_flagged,
            buffer_lost_flagged=buffer_lost_flagged,
        ),
        records=RecordHealth(
            parsed=parsed,
            providers_skipped=providers_skipped,
            parse_failures=parse_failures,
        ),
        file_size=file_size,
    )


def _is_logfile_header(record: Any) -> bool:
    """Whether a record is the logfile header control event (hook id 0x0000)."""
    header = record.header
    hook_id = getattr(header, "hook_id", None)
    return hook_id == 0
