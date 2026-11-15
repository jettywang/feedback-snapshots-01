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

## Event result model

Each parsed `Event` exposes an immutable, faceted `EventResult` via `event.result`. The facets never merge and always
keep their original field names, so a manifest payload field can never overwrite ETW header metadata:

- `result.header`: metadata from the ETW event header, with native value types (e.g. `UUID`, not display strings).
- `result.extensions`: extended data items carried by the header.
- `result.payload`: values decoded with the provider manifest template, or `None` when the template is unknown
  (explicitly distinct from an empty payload; see `result.template_known`).

Field names that occur in multiple facets are reported by `result.collisions`, and `result.field_sources(name)`
returns the provenance (`etw-header`, `etw-header-extension`, `manifest-template`) of every facet holding that name.
All values are snapshots taken at parse time: continuing to parse other events never rewrites a previously returned
result.

Business correlation (process or activity mapping) must only use the explicitly chosen metadata facet, i.e.
`result.process_id`, `result.thread_id` and `result.activity_id` (also available directly on the `Event`). These are
always sourced from the ETW header, never from the payload and never from dictionary merge order.

The legacy flat `event.event_values()` view is kept for compatibility: header fields are inserted first and manifest
payload values afterwards, so on a name collision the payload value wins. It is a display-oriented view only — do not
derive correlation identities from it.

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
