"""Controlled merge preview.

Allows a caller (e.g. a configuration panel) to see how Dynaconf would
merge a chosen set of sources *before* applying them, without mutating
the running settings object and without triggering load hooks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import TYPE_CHECKING

from dynaconf import default_settings
from dynaconf.loaders.base import SourceMetadata
from dynaconf.utils.functional import is_lazy

if TYPE_CHECKING:  # pragma: no cover
    from dynaconf.base import Settings

_INTERNAL_KEYS = {key for key in dir(default_settings) if key.isupper()}


def _raw_snapshot(value):
    """Convert to plain types without triggering lazy evaluation."""
    if isinstance(value, dict):
        return {key: _raw_snapshot(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_raw_snapshot(item) for item in value]
    return value


@dataclass
class PreviewReport:
    """Snapshot of a merge preview.

    Attributes:
        data: Merged key/value snapshot. Dynamic (lazy) values are kept
            unevaluated, see ``pending``.
        pending: Keys whose stored value is still an unevaluated lazy
            value and therefore needs a follow-up check.
        merge_order: Sources in the order they were applied to reach
            the previewed state, including anything loaded before the
            preview itself.
        settings: The throwaway clone used to build the preview, kept
            for further inspection. Discarding it loses nothing.
    """

    data: dict[str, Any]
    pending: list[str]
    merge_order: list[SourceMetadata]
    settings: "Settings"


def preview_merge(obj, files=None, loaders=None, env=None, silent=True):
    """Preview how the given sources would merge into ``obj``.

    The merge is replayed on a disposable clone of ``obj``:

    - the running settings object is never mutated;
    - no post-load hooks (instance or module) are executed;
    - lazy values are stored but not evaluated, and reported as pending.

    Only the sources explicitly chosen by the caller are replayed.

    :param obj: A Settings (or LazySettings) instance.
    :param files: Optional file path or list of paths to load.
    :param loaders: Optional list of loader modules/objects exposing
        ``load(obj, env, silent=..., key=...)``.
    :param env: Which env to load (default: the object's current env).
    :param silent: Should loading errors be silenced?
    :return: PreviewReport
    """
    clone = obj.dynaconf_clone()
    # deepcopied containers keep a reference to the original object in
    # their metadata, make the clone self-contained
    clone.store.__meta__.core = clone

    if files:
        clone.load_file(path=files, env=env, silent=silent, run_hooks=False)

    for loader in loaders or []:
        loader.load(clone, env, silent=silent, key=None)

    data = _raw_snapshot(clone.store)
    for key in _INTERNAL_KEYS:
        data.pop(key, None)

    pending = [key for key, value in data.items() if is_lazy(value)]

    return PreviewReport(
        data=data,
        pending=pending,
        merge_order=list(clone.loaded_by_loaders),
        settings=clone,
    )
