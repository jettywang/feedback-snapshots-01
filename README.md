# dissect.apfs

A Dissect module implementing a parser for the APFS file system, a commonly used Apple file system. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.apfs/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.apfs` is available on [PyPI](https://pypi.org/project/dissect.apfs/).

```bash
pip install dissect.apfs
```

This module is also automatically installed if you install the `dissect` package.

## Sealed volume verification

A sealed APFS volume protects its hashed B-trees with a parent/child hash chain, not with the per-object Fletcher-64
checksum. Passing a Fletcher checksum therefore does not mean the seal is intact: an attacker who changes a node can
recompute that checksum, but cannot recompute the parent's stored hash or the root digest.

Use `FS.verify_seal()` (or `dissect.apfs.verify_volume_seal()`) to walk the hash chains of a sealed volume:

```python
from dissect.apfs import SealStatus

report = volume.verify_seal()
if report.status == SealStatus.INTERNAL_CONSISTENT:
    # The on-disk chains are self-consistent, but there was no external trusted root.
    ...

# Anchor the root tree against a trusted root digest obtained out of band.
report = volume.verify_seal(trusted_root=root_digest)
```

Only the four documented algorithms are accepted (SHA-256, SHA-512/256, SHA-384 and SHA-512). The report lists every
node actually inspected, the algorithm used, the root digest source, and the layer at which any chain breaks. Missing
nodes or unknown layouts never produce a volume-wide success. A successful report only describes the on-disk data; it
does not prove that the machine's boot chain trusted the volume.

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
