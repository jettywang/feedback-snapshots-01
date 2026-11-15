# dissect.regf

A Dissect module implementing a parser for Windows registry file format, used to store application and OS configuration
on Windows operating systems. For more information, please see [the
documentation](https://docs.dissect.tools/en/latest/projects/dissect.regf/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.regf` is available on [PyPI](https://pypi.org/project/dissect.regf/).

```bash
pip install dissect.regf
```

This module is also automatically installed if you install the `dissect` package.

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

## MountedDevices correlation

`dissect.regf.mounted` provides a read-only view of the drive letters and
volume names stored in `SYSTEM\MountedDevices`. It recognizes the 12-byte MBR
form (disk signature and partition offset) and the 24-byte `DMIO:ID:` GPT form
(partition GUID), retains every original value and cell offset, and keeps
unknown layouts as evidence.

```python
from dissect.regf import analyze_mounted_devices, correlate_mounted_devices

first = analyze_mounted_devices(hive_a, snapshot="capture-a")
second = analyze_mounted_devices(hive_b, snapshot="capture-b")
correlation = correlate_mounted_devices(first, second)

for record in correlation.records:
    print(record.identity.canonical, record.alias_names, record.snapshots)
```

Each value record includes `name`, `value_cell_offset`, `data_cell_offset`,
`raw_hex`, `kind`, `status`, `identity`, and `parse_basis`, so every alias can
be checked against the bytes it came from. Unknown layouts have
`kind == "unknown"` and no identity.

Text references to another registry value are followed only by exact name, with
cycle, missing-target, duplicate-name, and conflicting-reuse cases reported
instead of guessed. A drive letter reused by different identities in two
snapshots appears in `conflicts`; its aliases are not merged.

`examples/mounted_devices.py SYSTEM=path/to/SYSTEM` prints the same records as
JSON.
