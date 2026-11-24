from __future__ import annotations

from typing import TYPE_CHECKING

from dynaconf.loaders.base import SourceMetadata
from dynaconf.utils import upperfy

if TYPE_CHECKING:
    from dynaconf.base import Settings

IDENTIFIER = "memory_generation"


def _registry(obj: "Settings"):
    """Return the per-core registry holding committed generation overrides.

    The registry lives on the active core so a published generation keeps
    taking effect when ``execute_loaders`` reloads every source (notably during
    a ``fresh`` read). Each entry maps an upper-cased key to its raw value.
    """
    return obj.__core__.config.memory_generation_data


def load(obj, env=None, silent=True, key=None, validate=False, **kwargs):
    """Re-apply the committed in-memory generation to ``obj``.

    Invoked by ``execute_loaders``, including the reload triggered by a
    ``fresh`` read, so committed values always win over file/env sources for
    the keys that belong to the approved generation.
    """
    registry = _registry(obj)
    if not registry:
        return

    source_metadata = SourceMetadata(loader="memory", identifier=IDENTIFIER)

    if key is not None:
        upper_key = upperfy(key)
        if upper_key not in registry:
            return
        obj.set(
            upper_key,
            registry[upper_key],
            loader_identifier=source_metadata,
            validate=False,
        )
        return

    for name, value in list(registry.items()):
        obj.set(
            name,
            value,
            loader_identifier=source_metadata,
            validate=False,
        )
