# dissect.xfs

A Dissect module implementing a parser for the XFS file system, commonly used by RedHat Linux distributions. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.xfs/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.xfs` is available on [PyPI](https://pypi.org/project/dissect.xfs/).

```bash
pip install dissect.xfs
```

This module is also automatically installed if you install the `dissect` package.

## Read-only journal summary

For investigation work, `dissect.xfs` exposes a strictly read-only view of the internal XFS
write-ahead log through `XFS.journal`. It reconstructs logical log records from their circular,
possibly wrapping on-disk layout, orders them by LSN (log cycle and block) rather than physical
offset, groups them into transactions, and reports whether each transaction is fully committed,
left uncommitted, or only partially present because log material is missing.

```python
from dissect.xfs import XFS

xfs = XFS(fh)
for transaction in xfs.journal.transactions():
    print(transaction.tid, transaction.status, transaction.operation_types)

print(xfs.journal.summary().render_text())
```

Redo payloads are described (LSN, transaction id, operation type, source ranges and commit state)
but never replayed: regular file access keeps reading the original evidence volume unchanged.


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
