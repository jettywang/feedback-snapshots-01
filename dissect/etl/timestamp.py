"""Exact conversion of ETW clock values to Windows ``FILETIME`` values and datetimes.

An ETL logfile header describes how the ``TimeDelta`` field of an event header relates to
wall-clock time.  The relation depends on the clock type stored in ``ReservedFlags``:

- ``PERF_FREQ`` (1): performance counter (QPC) ticks, ``10_000_000 / PerfFreq`` 100ns ticks
  per counter.
- ``SYSTEM_TIME`` (2): 100ns intervals, ``1`` tick per counter.
- ``CPU_CYCLE`` (3): CPU cycles, ``10 / CpuSpeedInMHz`` 100ns ticks per counter.

``CpuSpeedInMHz`` is expressed in MHz, hence the ``10`` numerator: one cycle takes
``1 / (CpuSpeedInMHz * 1_000_000)`` seconds, which is ``10 / CpuSpeedInMHz`` 100ns ticks.

Every conversion of a counter to 100ns ticks in this module is performed with integers (or,
equivalently, exact rational numbers); no binary floating point value is involved.  When the
conversion is not an exact integer number of 100ns ticks, the result is rounded **down**
(floor), i.e. only complete 100ns ticks are retained.  Combined with the requirement that a
``TimeDelta`` is non-negative, this keeps the mapping monotonic: a larger raw counter can
never produce an earlier timestamp, and adjacent counters remain ordered.

The raw counter value (``TimeDelta``) is never discarded by the ETL parser: it remains
available as :attr:`dissect.etl.headers.headers.Header.time_delta`.  The converted 100ns
value is available as :attr:`dissect.etl.headers.headers.Header.timestamp_filetime`, and
the datetime representation is derived from that integer.

Datetimes have microsecond resolution, while ``FILETIME`` has 100ns resolution.  Converting
100ns ticks to a datetime uses integer round-half-to-even on the tick remainder: it minimises
the distance to the exact instant (at most 0.5us) instead of letting a value like
``...999999`` silently fall back into the previous second.  The exact sub-microsecond value
is still available through the retained FILETIME integer.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from fractions import Fraction

from dissect.etl.exceptions import InvalidTimestampError

FILETIME_TICKS_PER_SECOND = 10_000_000
FILETIME_TICKS_PER_MICROSECOND = 10

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Largest FILETIME value that still fits in a datetime (datetime.max, 9999-12-31 23:59:59.999999).
_MAX_DATETIME = datetime.max.replace(tzinfo=timezone.utc)
_MAX_DATETIME_DELTA = _MAX_DATETIME - FILETIME_EPOCH
_MAX_DATETIME_MICROSECONDS = (
    _MAX_DATETIME_DELTA.days * 86400 + _MAX_DATETIME_DELTA.seconds
) * 1_000_000 + _MAX_DATETIME_DELTA.microseconds
# The largest FILETIME whose nearest-microsecond datetime still fits datetime.max. Ticks
# below half a microsecond above the exact maximum round back down; the rest overflow.
MAX_FILETIME = _MAX_DATETIME_MICROSECONDS * FILETIME_TICKS_PER_MICROSECOND + (FILETIME_TICKS_PER_MICROSECOND // 2 - 1)


class ClockType(IntEnum):
    """The clock that produced the ``TimeDelta`` values in an ETL file."""

    NONE = 0
    PERF_FREQ = 1
    SYSTEM_TIME = 2
    CPU_CYCLE = 3

    # Historical names, kept so ``ReservedFlags.PERFORMANCE_FREQ`` etc. keep working.
    PERFORMANCE_FREQ = 1
    FILETIME = 2
    CPU_FREQ = 3


@dataclass(frozen=True)
class TimestampConverter:
    """Convert raw ETW clock counters to ``FILETIME`` ticks and datetimes.

    The converter is an immutable value object, so converting the same counter always
    produces the same result regardless of the order in which events are read, and it can
    be serialized and restored without changing its behaviour.

    Args:
        clock_type: The clock that produced the raw counters.
        timestamp_base: The ``FILETIME`` value (100ns since 1601-01-01 UTC) that belongs to
            a raw counter of zero.
        scale_numerator: Numerator of the exact number of 100ns ticks per raw counter.
        scale_denominator: Denominator of the exact number of 100ns ticks per raw counter.
    """

    clock_type: ClockType
    timestamp_base: int
    scale_numerator: int
    scale_denominator: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "clock_type", _coerce_clock_type(self.clock_type))

        try:
            timestamp_base = operator.index(self.timestamp_base)
            scale_numerator = operator.index(self.scale_numerator)
            scale_denominator = operator.index(self.scale_denominator)
        except TypeError as e:
            raise InvalidTimestampError(f"timestamp scale and base must be integers: {self!r}") from e

        if scale_denominator <= 0:
            raise InvalidTimestampError(f"timestamp scale denominator must be positive: {scale_denominator}")
        if scale_numerator <= 0:
            raise InvalidTimestampError(f"timestamp scale numerator must be positive: {scale_numerator}")

        object.__setattr__(self, "timestamp_base", timestamp_base)
        object.__setattr__(self, "scale_numerator", scale_numerator)
        object.__setattr__(self, "scale_denominator", scale_denominator)

    @classmethod
    def from_clock(
        cls,
        clock_type: ClockType | int,
        *,
        perf_freq: int = 0,
        cpu_speed_mhz: int = 0,
        timestamp_base: int = 0,
    ) -> TimestampConverter:
        """Create a converter for a logfile header clock configuration.

        Arguments are validated strictly: frequencies must be positive integers, because a
        zero, negative or fractional frequency cannot define a clock.

        Args:
            clock_type: Value of the logfile header ``ReservedFlags`` field.
            perf_freq: ``PerfFreq`` from the logfile header, required for ``PERF_FREQ``.
            cpu_speed_mhz: ``CpuSpeedInMHz`` from the logfile header, required for ``CPU_CYCLE``.
            timestamp_base: ``FILETIME`` value belonging to a raw counter of zero.

        Raises:
            InvalidTimestampError: If the clock type is unsupported, or the frequency that
                the clock type requires is not a positive integer.
        """
        clock = _coerce_clock_type(clock_type)

        if clock is ClockType.SYSTEM_TIME:
            scale = Fraction(1, 1)
        elif clock is ClockType.PERF_FREQ:
            perf_freq = _positive_frequency(perf_freq, "PerfFreq", clock)
            scale = Fraction(FILETIME_TICKS_PER_SECOND, perf_freq)
        elif clock is ClockType.CPU_CYCLE:
            cpu_speed_mhz = _positive_frequency(cpu_speed_mhz, "CpuSpeedInMHz", clock)
            scale = Fraction(FILETIME_TICKS_PER_MICROSECOND, cpu_speed_mhz)
        else:
            raise InvalidTimestampError(f"unsupported clock type: {clock_type!r}")

        try:
            timestamp_base = operator.index(timestamp_base)
        except TypeError as e:
            raise InvalidTimestampError(f"timestamp base must be an integer: {timestamp_base!r}") from e

        return cls(
            clock_type=clock,
            timestamp_base=timestamp_base,
            scale_numerator=scale.numerator,
            scale_denominator=scale.denominator,
        )

    @property
    def scale(self) -> Fraction:
        """The exact number of 100ns ticks per raw counter."""
        return Fraction(self.scale_numerator, self.scale_denominator)

    def scale_delta(self, time_delta: int) -> int:
        """Convert a raw counter to a number of 100ns ticks, rounding down."""
        try:
            time_delta = operator.index(time_delta)
        except TypeError as e:
            raise InvalidTimestampError(f"time delta must be an integer: {time_delta!r}") from e

        if time_delta < 0:
            raise InvalidTimestampError(f"negative time delta: {time_delta}")

        return (time_delta * self.scale_numerator) // self.scale_denominator

    def to_filetime(self, time_delta: int) -> int:
        """Convert a raw counter to a ``FILETIME`` value.

        Args:
            time_delta: The raw counter value, e.g. a QPC tick count.

        Raises:
            InvalidTimestampError: If the counter is negative, or if the resulting value
                falls outside the range that ``FILETIME`` and :class:`datetime` can express.
        """
        filetime = self.timestamp_base + self.scale_delta(time_delta)
        return self.check_filetime(filetime, time_delta=time_delta)

    @staticmethod
    def check_filetime(filetime: int, *, time_delta: int | None = None) -> int:
        """Validate a ``FILETIME`` value and return it unchanged.

        Args:
            filetime: The ``FILETIME`` value (100ns since 1601-01-01 UTC).
            time_delta: Optional raw counter, used to make error messages more informative.

        Raises:
            InvalidTimestampError: If the value is before 1601-01-01 or after the last
                datetime that Python can represent.
        """
        try:
            filetime = operator.index(filetime)
        except TypeError as e:
            raise InvalidTimestampError(f"FILETIME must be an integer: {filetime!r}") from e

        context = "" if time_delta is None else f" for time delta {time_delta}"

        if filetime < 0:
            raise InvalidTimestampError(f"FILETIME{context} is before 1601-01-01: {filetime}")
        if filetime > MAX_FILETIME:
            raise InvalidTimestampError(f"FILETIME{context} exceeds datetime range: {filetime}")

        return filetime

    @staticmethod
    def filetime_to_datetime(filetime: int) -> datetime:
        """Convert a ``FILETIME`` value to an aware UTC datetime using integer arithmetic.

        The 100ns remainder is rounded to the nearest microsecond with ties to even, because
        :class:`datetime` cannot represent sub-microsecond values.

        Raises:
            InvalidTimestampError: If the value falls outside the range of :class:`datetime`.
        """
        filetime = TimestampConverter.check_filetime(filetime)
        microseconds, remainder = divmod(filetime, FILETIME_TICKS_PER_MICROSECOND)

        halfway = FILETIME_TICKS_PER_MICROSECOND // 2
        if remainder > halfway or (remainder == halfway and microseconds % 2):
            microseconds += 1

        try:
            return FILETIME_EPOCH + timedelta(microseconds=microseconds)
        except OverflowError as e:
            raise InvalidTimestampError(f"FILETIME exceeds datetime range: {filetime}") from e

    def to_datetime(self, time_delta: int) -> datetime:
        """Convert a raw counter directly to an aware UTC datetime."""
        return self.filetime_to_datetime(self.to_filetime(time_delta))


def _coerce_clock_type(value: ClockType | int) -> ClockType:
    """Return a supported :class:`ClockType`, or raise :class:`InvalidTimestampError`."""
    try:
        value = operator.index(value)
        return ClockType(value)
    except (TypeError, ValueError) as e:
        raise InvalidTimestampError(f"unsupported clock type: {value!r}") from e


def _positive_frequency(value: int, name: str, clock: ClockType) -> int:
    """Return a strictly positive integer frequency, or raise :class:`InvalidTimestampError`."""
    try:
        value = operator.index(value)
    except TypeError as e:
        raise InvalidTimestampError(f"invalid {name} for {clock.name} clock: {value!r}") from e

    if value <= 0:
        raise InvalidTimestampError(f"invalid {name} for {clock.name} clock: {value!r}")

    return value
