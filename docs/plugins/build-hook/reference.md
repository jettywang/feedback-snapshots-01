# Build hook plugins

-----

A build hook provides code that will be executed at various stages of the build process. See the documentation for [build hook configuration](../../config/build.md#build-hooks).

## Known third-party

- [hatch-argparse-manpage](https://github.com/damonlynch/hatch-argparse-manpage) - generate man pages for [argparse](https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser)-based CLIs
- [hatch-autorun](https://github.com/ofek/hatch-autorun) - used to inject code into an installation that will automatically run before the first import
- [hatch-build-scripts](https://github.com/rmorshea/hatch-build-scripts) - run arbitrary shell commands that create artifacts
- [hatch-cython](https://github.com/joshua-auchincloss/hatch-cython) - build [Cython](https://github.com/cython/cython) extensions
- [hatch-gettext](https://github.com/damonlynch/hatch-gettext) - compiles multi-lingual messages with GNU `gettext` tools
- [hatch-jupyter-builder](https://github.com/jupyterlab/hatch-jupyter-builder) - used for packages in the Project Jupyter ecosystem
- [hatch-mypyc](https://github.com/ofek/hatch-mypyc) - compiles code with [Mypyc](https://github.com/mypyc/mypyc)
- [hatch-odoo](https://github.com/acsone/hatch-odoo) - package Odoo add-ons into the appropriate namespace
- [hatch-project-name](https://github.com/valentinoli/hatch-project-name/) - writes the project name to a file
- [scikit-build-core](https://github.com/scikit-build/scikit-build-core) - build extension modules with CMake

## Overview

Build hooks run for every selected [version](../../config/build.md#versions) of build targets.

The [initialization](#hatchling.builders.hooks.plugin.interface.BuildHookInterface.initialize) stage occurs immediately before each build and the [finalization](#hatchling.builders.hooks.plugin.interface.BuildHookInterface.finalize) stage occurs immediately after. Each stage has the opportunity to view or modify [build data](#build-data).

## Build data

Build data is a simple mapping whose contents can influence the behavior of builds. Which fields exist and are recognized depends on each build target.

The following fields are always present and recognized by the build system itself:

| Field | Type | Description |
| --- | --- | --- |
| `artifacts` | `#!python list[str]` | This is a list of extra [`artifact` patterns](../../config/build.md#artifacts) and should generally only be appended to |
| `force_include` | `#!python dict[str, str]` | This is a mapping of extra [forced inclusion paths](../../config/build.md#forced-inclusion), with this mapping taking precedence in case of conflicts |
| `build_hooks` | `#!python tuple[str, ...]` | This is an immutable sequence of the names of the configured build hooks and matches the order in which they run |

!!! attention
    While user-facing TOML options are hyphenated, build data fields should be named with underscores to allow plugins to use them as valid Python identifiers.

## Notes

In some cases it may be necessary to use `force_include` rather than `artifacts`. For example, say that you want to install a `lib.so` directly at the root of `site-packages` and a project defines a [package](../../config/build.md#packages) `src/foo`. If you create `src/lib.so`, there will never be a match because the directory traversal starts at `src/foo` rather than `src`. In that case you must do either:

```python
build_data['force_include']['src/lib.so'] = 'src/lib.so'
```

or

```python
build_data['force_include']['/absolute/path/to/src/lib.so'] = 'src/lib.so'
```

## Managed hooks and per-target approval

When a single project produces artifacts for more than one build target (for example separate channels), a build hook can be marked as **managed** so that every membership change it makes through the build data is approved on a per-target basis.

Set the `managed` option on the hook configuration, then declare the changes that are approved for that target under `approvals`. Three kinds of change are recognized for the membership fields (`artifacts`, `force_include`, `force_include_editable`, `shared_data`, `shared_scripts`, `extra_metadata`, and `sbom_files`):

| Kind | Meaning |
| --- | --- |
| `add` | A new member or distribution path is introduced |
| `relocate` | An existing source is mapped to a different distribution path |
| `clean` | A member is removed from the build data |

Each entry is a distribution path, optionally constrained by a `source`. Entries without a source match any source; when a `source` is given it is matched against the normalized source or, for files generated in temporary locations, its file name.

```toml config-example
[tool.hatch.build.targets.wheel.hooks.custom]
managed = true

[tool.hatch.build.targets.wheel.hooks.custom.approvals]
add = ["channels/wheel/shared.txt", { path = "data/x.txt", source = "x.txt" }]
relocate = [{ path = "moved/x.txt", source = "x.txt" }]
clean = ["channels/wheel/shared.txt"]
```

Approval is evaluated independently for each target using that target's own configuration, so a mapping approved for one target can never enter another target's artifact. Hooks that are not managed continue to modify the build data freely. A managed hook attempting a change that was not approved raises an error, records the denied change, and aborts that target without mutating its build data.

### Build receipts

Every target that runs at least one managed hook produces a `BuildReceipt`, available on the builder as the `receipts` attribute. The receipt records, per hook and per build data field, each attempted operation together with whether it was applied or denied, and the final membership that entered the result. Its `status` is `success` or `failed` (with the error message), which makes it possible to tell which modifications actually made it into an artifact even when another target's post-processing fails. Targets are isolated: a failure in one target never removes members from an artifact already produced by another target.

::: hatchling.builders.hooks.plugin.interface.BuildHookInterface
    options:
      members:
      - PLUGIN_NAME
      - app
      - root
      - config
      - build_config
      - target_name
      - directory
      - dependencies
      - clean
      - initialize
      - finalize
