# dissect.fve

A Dissect module implementing parsers for full volume encryption implementations, currently Linux Unified Key Setup (LUKS1 and LUKS2), Microsoft's Bitlocker Disk Encryption (BDE) and VeraCrypt.
For more information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.fve/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.fve` is available on [PyPI](https://pypi.org/project/dissect.fve/).

```bash
pip install dissect.fve
```

This module is also automatically installed if you install the `dissect` package.

## BitLocker volume status

`BDE.status()` returns a display-oriented report that separates what the volume metadata
declares from what was actually observed by reading sectors:

```python
from dissect.fve.bde import BDE

bde = BDE(fh)
status = bde.status()  # verify=False to skip sector sampling

status.state  # "suspended", "paused", "decrypted", "encrypted", ...
status.ciphertext.declared  # from the EOW bitmap / StateOffset layout
status.ciphertext.observed  # from comparing raw and decrypted sector samples; None if untested
status.access.without_external_credentials  # clear key / TPM / plaintext
status.access.requires_credential  # a user passphrase, recovery password or BEK is needed
status.access.readable  # None means "not tested", never "unreadable"
status.sector_map.ranges  # per-range nominal state plus sampled evidence
status.to_dict()["display"]  # badge and headline fields for a backend UI
```

A suspended volume can therefore report both `ciphertext.conclusion == "present"` and
`access.without_external_credentials == True`: the sectors still contain ciphertext, while
the clear (obfuscated) key protector allows the volume to be opened without a user secret.
`status.to_dict()` is JSON-serialisable.

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
