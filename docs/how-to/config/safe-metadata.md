# How to read metadata safely without running project plugins

----

Reviewing a package before approval often means inspecting its [project metadata](../../config/metadata.md). Some fields are produced by [dynamic metadata hooks](../../plugins/metadata-hook/reference.md), and resolving them normally executes arbitrary project code such as a `hatch_build.py` script. The safe read mode lets an approval interface inspect metadata without running plugins that have not been explicitly trusted.

## Overview

Use the `SafeMetadataReader` from the `hatchling.metadata.safe` module. It never imports or executes a metadata hook unless that hook is named in `approved_hooks`:

```python
from hatchling.metadata.core import ProjectMetadata
from hatchling.metadata.safe import SafeMetadataReader
from hatchling.plugin.manager import PluginManager

metadata = ProjectMetadata(root, PluginManager())

# Only the `trusted` hook is allowed to run.
report = SafeMetadataReader(metadata, approved_hooks=("trusted",)).read()
```

Every reported field is tagged with one of three statuses:

- `static`: read directly from `pyproject.toml`, no plugin involved.
- `dynamic-approved`: produced by a hook that was explicitly approved.
- `dynamic-pending`: requires a hook (or a formal build environment) that was not approved, so no value is claimed.

Static fields are always available. A dynamic field is only confirmed when an approved hook supplies it; otherwise it stays pending and keeps no value.

## What runs and what does not

The reader works on a private copy of the raw metadata and builds an isolated `CoreMetadata` view, so approved hooks can never mutate the project's cached configuration. Hooks that are not approved are not even instantiated: their build scripts are never imported.

The `callback_counts` mapping records how many times each approved hook's `update()` method ran, and `unapproved_hooks` lists the hooks that were skipped:

```python
report.callback_counts     # e.g. {"trusted": 1}
report.unapproved_hooks    # e.g. ("custom",)
```

The version is itself resolved through a [version source](../../plugins/version-source/reference.md), which is a plugin. It is therefore only read when no metadata hooks are configured, or once at least one configured hook has been approved.

## Pending fields are never confirmed

A pending field cannot influence a release decision. Use the helper views instead of guessing from raw values:

```python
report.static_fields            # static name/value pairs
report.approved_dynamic_fields  # dynamic values produced by approved hooks
report.pending_fields           # field names still awaiting confirmation
report.confirmed_fields         # everything that may be relied upon
report.is_confirmed("keywords")  # False while the field is pending
```

## Reviewing the built artifact

Once the package is built in a formal build environment, every configured hook runs. Re-check the values embedded in an artifact against the report with `verify_artifact()`. Confirmed fields are compared and reported as `verified` or `mismatched`, while previously pending fields are surfaced under `pending` with the value the artifact actually carries. A pending field is presented for review rather than being marked as confirmed on its own:

```python
verification = report.verify_artifact(artifact_metadata)
verification["verified"]     # confirmed values that match the artifact
verification["mismatched"]   # confirmed values that differ from the artifact
verification["pending"]      # values that still need a reviewer's sign-off
```

The full structured result, including each field's status, source, and reason, is available through `report.to_dict()`.
