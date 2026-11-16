# dissect.ntfs

A Dissect module implementing a parser for the NTFS file system, used by the Windows operating system. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.ntfs/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.ntfs` is available on [PyPI](https://pypi.org/project/dissect.ntfs/).

```bash
pip install dissect.ntfs
```

This module is also automatically installed if you install the `dissect` package.

## Object ID reports

Files with an `$OBJECT_ID` attribute can be correlated with the volume-level `$ObjId:$O` index. Reports are
read-only and keep both the raw GUID bytes and their display form:

```python
from dissect.ntfs import NTFS

fs = NTFS(open("ntfs.raw", "rb"))
report = fs.objid.report_path("Directory/File.txt") if fs.objid else None

print(report.status)  # "consistent", "conflict" or "insufficient"
print(report.attribute.describe())  # the concrete $OBJECT_ID attribute
print(report.index_entry.describe())  # the concrete $ObjId:$O index entry
```

The current object ID is compared with the index key and its MFT file reference (segment and record generation).
Birth volume/object IDs are compared separately. A cross-volume move is only reported as proven
(`report.proven_cross_volume_move`) when both the attribute and index carry matching birth information and the
current volume ID is known; one-sided material, conflicting IDs, or missing birth information remain
`insufficient` or `conflict` instead of a proven move.

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
