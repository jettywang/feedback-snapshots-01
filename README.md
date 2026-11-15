# dissect.shellitem

A Dissect module implementing a parser for the Shellitem structures, commonly used by Microsoft Windows. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.shellitem/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.shellitem` is available on [PyPI](https://pypi.org/project/dissect.shellitem/).

```bash
pip install dissect.shellitem
```

This module is also automatically installed if you install the `dissect` package.

## Target evidence

Besides parsing the individual structures, `dissect.shellitem.lnk.targets.collect_targets` collects a unified
target evidence set from a parsed LNK file. A (malicious) shortcut can advertise different targets in its display
name, LinkInfo, IDList and environment variable data blocks, so instead of returning a single assembled path, every
source yields a `TargetCandidate` recording its provenance: source structure, encoding, runtime dependencies
(environment variables, drive letters, known folders, link file location) and raw byte range. Command line
arguments and icon locations are collected for visibility but never mixed into the program path comparison.

The returned `TargetReport` classifies the evidence as `CONSISTENT`, `CONFLICT` or `INCOMPARABLE`. Truncated
structures and unsupported IDList shell item types are preserved raw and reported as incomparable — no other
source is used as a substitute to claim full agreement. Note that this is a static comparison of file bytes:
Windows resolves the executed target at runtime, so the bytes alone cannot guarantee which target is ultimately
executed.

```python
from dissect.shellitem.lnk import Lnk, collect_targets

with open("suspicious.lnk", "rb") as fh:
    report = collect_targets(Lnk(fh))

print(report.verdict())
for candidate in report.candidates:
    print(candidate.source, candidate.status.value, candidate.value)
```

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
