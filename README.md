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

## Evidence-based process lineage

`dissect.etl.lineage` turns the kernel process events in an ETL trace into a defensible process genealogy. A process is
modelled as a lifecycle rather than a PID: the kernel `UniqueProcessKey` is used as the stable identity when present,
and PID-only (V0/V1) events are grouped over the interval in which the PID is known to be alive. PID reuse, rundown
(`DCStart`/`DCEnd`) processes that predate the trace, missing end events and missing parent events are handled
explicitly. Every relationship keeps the event location (buffer index, byte offset, sequence) and the original payload
fields; a parent link that the evidence cannot prove is returned as *unresolved* with a reason instead of a confident
edge. Start times are never inferred from an event's position in the file.

```python
from dissect.etl import ETL
from dissect.etl.lineage import build_process_lineage

with open("trace.etl", "rb") as fh:
    lineage = build_process_lineage(ETL(fh))

print(lineage.render_text())
```

A runnable demonstration on a small synthetic trace is available in
[`examples/process_lineage_demo.py`](examples/process_lineage_demo.py).

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
