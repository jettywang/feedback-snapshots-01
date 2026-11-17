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

## Realtime devices

XFS can store file data on a separate realtime device. A realtime device is
different evidence from the data device, so it must be supplied explicitly:

```python
from dissect.xfs import XFS

with open("data.img", "rb") as fh, open("realtime.img", "rb") as rt:
    xfs = XFS(fh, rtdev=rt)

    inode = xfs.get("/some/realtime/file")
    print(inode.is_realtime)
    print(inode.realtime_ranges)  # per-range status, logical offsets and length
    print(xfs.realtime.geometry)  # sb_rblocks, sb_rextsize, sb_rextents, ...
    print(xfs.realtime.bitmap.state)
    data = inode.open().read()
```

Realtime extent records use realtime block numbers; they are never read from
the data device. Without `rtdev`, opening a realtime file raises
`RealtimeDeviceMissingException`. Holes and unwritten extents read as zeroes,
and contradictory ranges (for example unallocated, out-of-bounds, overlapping
or misaligned extents) raise `RealtimeRangeError` instead of returning other
evidence.

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
