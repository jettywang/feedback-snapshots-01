# dissect.etl

A Dissect module implementing a parser for Event Trace Log (ETL) files, used by the Windows operating system to log
kernel events. For more information, please see [the
documentation](https://docs.dissect.tools/en/latest/projects/dissect.etl/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.etl` is available on [PyPI](https://pypi.org/project/dissect.etl/).

```bash
pip install dissect.etl
```

This module is also automatically installed if you install the `dissect` package.

## Timestamps

ETW event headers store a raw clock counter (`TimeDelta`). The logfile header determines how
that counter maps to wall-clock time, based on the clock type in `ReservedFlags`:

- `PERF_FREQ` (1, QPC ticks): `10_000_000 / PerfFreq` 100ns ticks per counter.
- `SYSTEM_TIME` (2): one 100ns tick per counter.
- `CPU_CYCLE` (3): `10 / CpuSpeedInMHz` 100ns ticks per counter.

`dissect.etl` performs this conversion with exact integers (via `TimestampConverter`) rather
than floating point, so adjacent counters stay ordered even in long traces whose FILETIME
values exceed the exact integer range of a float. Non-integral results are rounded **down**
to whole 100ns ticks, and datetimes truncate the sub-microsecond remainder. Use
`ETL.timestamp_converter` (or `LogfileHeader.timestamp_converter`) to convert counters
directly, and `Header.time_delta` / `Header.timestamp_filetime` to keep both the raw counter
and the converted 100ns value. Invalid frequencies, negative counters and values outside the
`datetime` range raise `InvalidTimestampError` instead of producing a bogus timestamp.

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
