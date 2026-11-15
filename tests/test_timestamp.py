from __future__ import annotations

import io
import itertools
import json
import math
import pickle
import random
import struct
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from fractions import Fraction

import pytest

import dissect.etl.etl as etl_module
from dissect.etl import ETL
from dissect.etl.exceptions import InvalidTimestampError
from dissect.etl.headers.logfile import LogfileHeader
from dissect.etl.timestamp import (
    FILETIME_EPOCH,
    FILETIME_TICKS_PER_MICROSECOND,
    FILETIME_TICKS_PER_SECOND,
    MAX_FILETIME,
    ClockType,
    TimestampConverter,
)

from .test_logfile_header import create_event
from .testutils import FIRST_BUFFER


@pytest.fixture(autouse=True)
def restore_c_etl() -> None:
    """Some buffer tests replace the module-level ``c_etl`` parser; undo that pollution."""
    from dissect.etl.c_etl import c_etl as real_c_etl

    previous = etl_module.c_etl
    etl_module.c_etl = real_c_etl
    yield
    etl_module.c_etl = previous


def reference_ticks(clock: ClockType, delta: int, *, perf_freq: int = 0, cpu_speed_mhz: int = 0) -> int:
    """Independent reference: exact rational scale, floored to whole 100ns ticks."""
    if clock is ClockType.SYSTEM_TIME:
        per_tick = Fraction(1, 1)
    elif clock is ClockType.PERF_FREQ:
        per_tick = Fraction(FILETIME_TICKS_PER_SECOND, perf_freq)
    else:
        per_tick = Fraction(FILETIME_TICKS_PER_MICROSECOND, cpu_speed_mhz)

    return math.floor(Fraction(delta) * per_tick)


def reference_filetime(base: int, ticks: int) -> int:
    return base + ticks


def reference_datetime(filetime: int) -> datetime:
    """Independent reference: FILETIME to datetime with integer round-half-to-even on micros."""
    microseconds, remainder = divmod(filetime, FILETIME_TICKS_PER_MICROSECOND)
    halfway = FILETIME_TICKS_PER_MICROSECOND // 2
    if remainder > halfway or (remainder == halfway and microseconds % 2):
        microseconds += 1

    return FILETIME_EPOCH + timedelta(microseconds=microseconds)


def test_clock_type_values() -> None:
    assert int(ClockType.PERF_FREQ) == 1
    assert int(ClockType.SYSTEM_TIME) == 2
    assert int(ClockType.CPU_CYCLE) == 3
    assert ClockType.PERFORMANCE_FREQ is ClockType.PERF_FREQ
    assert ClockType.FILETIME is ClockType.SYSTEM_TIME
    assert ClockType.CPU_FREQ is ClockType.CPU_CYCLE


@pytest.mark.parametrize(
    ("clock", "kwargs", "expected"),
    [
        (ClockType.SYSTEM_TIME, {}, Fraction(1, 1)),
        (ClockType.PERF_FREQ, {"perf_freq": 10}, Fraction(1_000_000, 1)),
        (ClockType.PERF_FREQ, {"perf_freq": 20}, Fraction(500_000, 1)),
        (ClockType.PERF_FREQ, {"perf_freq": 3_579_545}, Fraction(2_000_000, 715_909)),
        (ClockType.CPU_CYCLE, {"cpu_speed_mhz": 2112}, Fraction(5, 1056)),
        (ClockType.CPU_CYCLE, {"cpu_speed_mhz": 10}, Fraction(1, 1)),
    ],
)
def test_scale_rules(clock: ClockType, kwargs: dict, expected: Fraction) -> None:
    converter = TimestampConverter.from_clock(clock, **kwargs)
    assert converter.scale == expected
    assert Fraction(converter.scale_numerator, converter.scale_denominator) == expected


def test_legacy_timestamp_scale_is_exact_view() -> None:
    """The old float attribute now only mirrors the exact rational scale."""
    header = LogfileHeader(create_event(bit64=True))
    converter = header.timestamp_converter
    assert header.clock_type is ClockType.PERF_FREQ
    assert converter.scale == Fraction(1, 1)
    assert header.timestamp_scale == float(converter.scale) == 1.0
    assert header.timestamp_base == converter.timestamp_base == 132586490803526455


@pytest.mark.parametrize(
    ("clock", "kwargs"),
    [
        (ClockType.SYSTEM_TIME, {}),
        (ClockType.PERF_FREQ, {"perf_freq": 3_579_545}),
        (ClockType.PERF_FREQ, {"perf_freq": 10_000_000}),
        (ClockType.CPU_CYCLE, {"cpu_speed_mhz": 2112}),
    ],
)
@pytest.mark.parametrize("base", [0, 116_444_736_000_000_000, 132_586_490_803_526_455])
def test_exact_expected_vectors(clock: ClockType, kwargs: dict, base: int) -> None:
    converter = TimestampConverter.from_clock(clock, timestamp_base=base, **kwargs)

    for delta in [0, 1, 2, 3, 999, 1000, 2**40, 2**40 + 1, 2**53 - 1, 2**53, 2**53 + 1]:
        ticks = reference_ticks(clock, delta, **kwargs)
        expected_filetime = reference_filetime(base, ticks)

        assert converter.scale_delta(delta) == ticks
        assert converter.to_filetime(delta) == expected_filetime
        assert converter.to_datetime(delta) == reference_datetime(expected_filetime)


def test_floor_rounding_for_non_divisible_scales() -> None:
    """A non-integral tick count keeps only complete 100ns ticks (floor), never rounds up."""
    qpc = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=3)
    assert qpc.scale_delta(1) == 3_333_333  # 10_000_000 / 3
    assert qpc.scale_delta(2) == 6_666_666
    assert qpc.scale_delta(3) == 10_000_000
    assert qpc.scale_delta(4) == 13_333_333

    cpu = TimestampConverter.from_clock(ClockType.CPU_CYCLE, cpu_speed_mhz=2112)
    assert cpu.scale_delta(1) == 0
    assert cpu.scale_delta(211) == 0  # 211 * 10 / 2112 ~= 0.999
    assert cpu.scale_delta(212) == 1
    assert cpu.scale_delta(1056) == 5
    assert cpu.scale_delta(2112) == 10


def test_adjacent_counters_beyond_float_integer_range() -> None:
    """Counters beyond 2**53 must stay distinct; a float FILETIME cannot represent them."""
    base = 132_586_490_803_526_400
    converter = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=10_000_000, timestamp_base=base)

    deltas = [2**53 - 1, 2**53, 2**53 + 1, 2**53 + 2, 2**53 + 9, 2**53 + 10]
    filetimes = [converter.to_filetime(delta) for delta in deltas]

    expected = [reference_filetime(base, reference_ticks(ClockType.PERF_FREQ, d, perf_freq=10_000_000)) for d in deltas]
    assert filetimes == expected
    assert all(later > earlier for earlier, later in itertools.pairwise(filetimes))
    # The vector really is beyond exact float integers: the legacy float pipeline collapses it.
    assert len({float(value) for value in filetimes}) < len(filetimes)
    # Datetimes have microsecond resolution, so they are non-decreasing but not strictly increasing.
    datetimes = [converter.to_datetime(delta) for delta in deltas]
    assert all(later >= earlier for earlier, later in itertools.pairwise(datetimes))


def test_adjacent_counters_with_fractional_qpc_scale() -> None:
    """Fractional QPC scale must not lose order either, even if some counters map to one tick."""
    base = 132_586_490_803_526_400
    converter = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=3_579_545, timestamp_base=base)
    start = 2**56

    previous = converter.to_filetime(start)
    for delta in range(start + 1, start + 500):
        current = converter.to_filetime(delta)
        assert current >= previous
        assert current == reference_filetime(base, reference_ticks(ClockType.PERF_FREQ, delta, perf_freq=3_579_545))
        previous = current


def test_read_order_does_not_change_result() -> None:
    base = 132_586_490_803_526_455
    converter = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=3_579_545, timestamp_base=base)
    deltas = [2**53 - 1, 2**53, 2**53 + 7, 2**54, 2**55, 2**56]

    expected = {delta: converter.to_filetime(delta) for delta in deltas}
    for order in (deltas, list(reversed(deltas)), [deltas[3], deltas[0], deltas[5], deltas[2], deltas[1], deltas[4]]):
        seen = {delta: converter.to_filetime(delta) for delta in order}
        assert seen == expected
        assert [seen[delta] for delta in sorted(seen)] == sorted(expected.values())


def test_serialization_roundtrip() -> None:
    converter = TimestampConverter.from_clock(
        ClockType.PERF_FREQ, perf_freq=3_579_545, timestamp_base=132_586_490_803_526_455
    )
    deltas = [0, 1, 2**52, 2**53, 2**53 + 1, 2**59]
    expected = {delta: converter.to_filetime(delta) for delta in deltas}

    restored = [
        TimestampConverter(**asdict(converter)),
        pickle.loads(pickle.dumps(converter)),
        TimestampConverter(**json.loads(json.dumps(asdict(converter)))),
    ]

    for candidate in restored:
        assert candidate == converter
        assert {delta: candidate.to_filetime(delta) for delta in deltas} == expected


def test_base_shift_is_exact() -> None:
    delta = 2**53 + 3
    first = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=10_000_000, timestamp_base=1_000)
    second = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=10_000_000, timestamp_base=2_500)
    assert second.to_filetime(delta) - first.to_filetime(delta) == 1_500


def test_ordinary_durations_stay_compatible_with_legacy_interpretation() -> None:
    """Ordinary durations keep the legacy interpretation: same second, same microsecond scale."""
    from dissect.util.ts import wintimestamp

    base = 132_586_490_800_000_000
    converter = TimestampConverter.from_clock(ClockType.SYSTEM_TIME, timestamp_base=base)
    deltas = [0, 1, 9, 10, 1_234_567, 10**9, 3_600 * 10_000_000, 86_400 * 10_000_000]

    for delta in deltas:
        filetime = base + delta
        new = converter.to_datetime(delta)
        old = wintimestamp(filetime)

        assert new.tzinfo is timezone.utc
        # The exact value is authoritative; the old float path itself drifts a few
        # microseconds at this magnitude, so compatibility is bounded and second-aligned.
        assert new == reference_datetime(filetime)
        assert abs(new - old) < timedelta(microseconds=10)
        assert new.replace(microsecond=0) == old.replace(microsecond=0)

    # Exact-float FILETIMEs differ at most by the legacy 1e-7 multiply's own rounding.
    for filetime in [0, 1, 5, 10**7, 4 * 10**15 + 1, 2**53 - 1]:
        exact = TimestampConverter.filetime_to_datetime(filetime)
        assert abs(exact - wintimestamp(filetime)) <= timedelta(microseconds=1)
        assert exact.replace(microsecond=0) == wintimestamp(filetime).replace(microsecond=0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"clock_type": ClockType.PERF_FREQ, "perf_freq": 0},
        {"clock_type": ClockType.PERF_FREQ, "perf_freq": -1},
        {"clock_type": ClockType.PERF_FREQ, "perf_freq": 1.5},
        {"clock_type": ClockType.CPU_CYCLE, "cpu_speed_mhz": 0},
        {"clock_type": ClockType.CPU_CYCLE, "cpu_speed_mhz": -2112},
        {"clock_type": ClockType.NONE},
        {"clock_type": 4},
        {"clock_type": -1},
    ],
)
def test_invalid_clock_configuration_raises(kwargs: dict) -> None:
    with pytest.raises(InvalidTimestampError):
        TimestampConverter.from_clock(**kwargs)


def test_invalid_denominator_and_numerator() -> None:
    with pytest.raises(InvalidTimestampError):
        TimestampConverter(ClockType.SYSTEM_TIME, 0, 1, 0)
    with pytest.raises(InvalidTimestampError):
        TimestampConverter(ClockType.SYSTEM_TIME, 0, 1, -1)
    with pytest.raises(InvalidTimestampError):
        TimestampConverter(ClockType.SYSTEM_TIME, 0, -1, 1)
    with pytest.raises(InvalidTimestampError):
        TimestampConverter(ClockType.SYSTEM_TIME, 0, 0, 1)
    with pytest.raises(InvalidTimestampError):
        TimestampConverter(None, 0, 1, 1)


@pytest.mark.parametrize("delta", [-1, -(2**53), -(2**63)])
def test_negative_time_delta_raises(delta: int) -> None:
    converter = TimestampConverter.from_clock(ClockType.PERF_FREQ, perf_freq=10_000_000, timestamp_base=1)
    with pytest.raises(InvalidTimestampError, match="negative time delta"):
        converter.scale_delta(delta)
    with pytest.raises(InvalidTimestampError, match="negative time delta"):
        converter.to_filetime(delta)
    with pytest.raises(InvalidTimestampError, match="negative time delta"):
        converter.to_datetime(delta)


def test_overflow_and_underflow_raise_instead_of_now() -> None:
    converter = TimestampConverter.from_clock(ClockType.SYSTEM_TIME, timestamp_base=MAX_FILETIME)
    assert converter.to_filetime(0) == MAX_FILETIME
    assert converter.to_datetime(0) == datetime.max.replace(tzinfo=timezone.utc)

    with pytest.raises(InvalidTimestampError, match="exceeds datetime range"):
        converter.to_filetime(1)
    with pytest.raises(InvalidTimestampError, match="exceeds datetime range"):
        converter.to_datetime(1)

    before_1601 = TimestampConverter.from_clock(ClockType.SYSTEM_TIME, timestamp_base=-1)
    with pytest.raises(InvalidTimestampError, match="before 1601-01-01"):
        before_1601.to_filetime(0)
    with pytest.raises(InvalidTimestampError, match="before 1601-01-01"):
        TimestampConverter.filetime_to_datetime(-1)

    with pytest.raises(InvalidTimestampError, match="exceeds datetime range"):
        TimestampConverter.filetime_to_datetime(2**64 - 1)


def test_invalid_logfile_clock_raises() -> None:
    for reserved_flags in (0, 4, 0xFFFFFFFF):
        header = LogfileHeader(create_event(bit64=True))
        header.header.ReservedFlags = reserved_flags
        with pytest.raises(InvalidTimestampError):
            assert header.timestamp_converter

    header = LogfileHeader(create_event(bit64=True))
    header.header.PerfFreq = 0
    with pytest.raises(InvalidTimestampError, match="PerfFreq"):
        assert header.timestamp_converter

    header = LogfileHeader(create_event(bit64=True))
    header.header.ReservedFlags = ClockType.CPU_CYCLE
    header.header.LogInstanceGuid = b"\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    with pytest.raises(InvalidTimestampError, match="CpuSpeedInMHz"):
        assert header.timestamp_converter


def test_logfile_negative_system_delta_raises() -> None:
    header = LogfileHeader(create_event(bit64=True))
    header.system_header.header.TimeDelta = -1
    with pytest.raises(InvalidTimestampError, match="negative time delta"):
        assert header.timestamp_converter


def test_etl_start_end_are_exact_utc() -> None:
    etl = ETL(io.BytesIO(FIRST_BUFFER))

    assert etl.start == reference_datetime(etl.logfile_header.start_time)
    assert etl.end == reference_datetime(etl.logfile_header.end_time)
    assert etl.start.tzinfo is timezone.utc
    assert etl.end.tzinfo is timezone.utc
    assert etl.start < etl.end


def test_etl_event_conversion_exposes_raw_and_100ns_values() -> None:
    etl = ETL(io.BytesIO(FIRST_BUFFER))
    records = list(etl.buffer(0))

    first = records[0].header
    assert first.time_delta == 2722959
    assert first.timestamp_filetime == etl.logfile_header.start_time
    assert first.timestamp == reference_datetime(first.timestamp_filetime)
    assert first.timestamp == etl.start


def test_sub_microsecond_ticks_are_retained_in_filetime() -> None:
    """The 100ns value keeps the remainder that the datetime must truncate."""
    etl = ETL(io.BytesIO(FIRST_BUFFER))
    first = next(iter(etl.buffer(0))).header

    remainder = first.timestamp_filetime % FILETIME_TICKS_PER_MICROSECOND
    assert remainder
    exact = first.timestamp_filetime // FILETIME_TICKS_PER_MICROSECOND
    assert first.timestamp == FILETIME_EPOCH + timedelta(microseconds=exact)
    assert (first.timestamp - FILETIME_EPOCH) // timedelta(microseconds=1) == exact


def test_logfile_clock_types_end_to_end() -> None:
    """CPU-cycle and system-time logfile headers produce the documented scales."""
    cpu = LogfileHeader(create_event(bit64=True))
    cpu.header.ReservedFlags = ClockType.CPU_CYCLE
    cpu.header.LogInstanceGuid = struct.pack("<IIII", 1, 8, 0, 2112)
    assert cpu.cpu_speed_in_MHz == 2112
    cpu_converter = cpu.timestamp_converter
    assert cpu.clock_type is ClockType.CPU_CYCLE
    assert cpu_converter.scale == Fraction(FILETIME_TICKS_PER_MICROSECOND, cpu.cpu_speed_in_MHz)
    assert cpu.timestamp_scale == float(cpu_converter.scale)

    system = LogfileHeader(create_event(bit64=True))
    system.header.ReservedFlags = ClockType.SYSTEM_TIME
    system_converter = system.timestamp_converter
    assert system.clock_type is ClockType.SYSTEM_TIME
    assert system_converter.scale == 1
    assert system_converter.timestamp_base == system.start_time - system.system_header.time_delta


def test_etl_rejects_invalid_counters() -> None:
    etl = ETL(io.BytesIO(FIRST_BUFFER))
    with pytest.raises(InvalidTimestampError, match="negative time delta"):
        etl.get_filetime_for_event(-1)
    with pytest.raises(InvalidTimestampError, match="negative time delta"):
        etl.calculate_timestamp(-1)

    too_large = MAX_FILETIME - etl.logfile_header.timestamp_base + 1
    with pytest.raises(InvalidTimestampError, match="exceeds datetime range"):
        etl.get_filetime_for_event(too_large)


def test_public_exports() -> None:
    import dissect.etl as package

    assert {"ClockType", "TimestampConverter", "InvalidTimestampError"} <= set(package.__all__)
    assert package.ClockType is ClockType
    assert package.TimestampConverter is TimestampConverter


def test_etl_converter_serialization_matches_header() -> None:
    etl = ETL(io.BytesIO(FIRST_BUFFER))
    converter = etl.timestamp_converter
    restored = TimestampConverter(**json.loads(json.dumps(asdict(converter))))
    assert restored == converter

    for delta in (0, 1, 2**53, 2**53 + 1):
        assert restored.to_filetime(delta) == etl.get_filetime_for_event(delta)


def test_shuffled_reads_are_stable() -> None:
    etl = ETL(io.BytesIO(FIRST_BUFFER))
    rng = random.Random(1234)
    deltas = [2**53 + index for index in range(10)]
    expected = {delta: etl.get_filetime_for_event(delta) for delta in deltas}

    shuffled = deltas[:]
    rng.shuffle(shuffled)
    assert {delta: etl.get_filetime_for_event(delta) for delta in shuffled} == expected
    ordered = [expected[delta] for delta in sorted(expected)]
    assert ordered == sorted(ordered)
