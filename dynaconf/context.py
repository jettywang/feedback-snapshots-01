from __future__ import annotations

import contextvars
import copy
from dataclasses import dataclass
from typing import Any
from typing import Optional

from dynaconf.nodes import DataDict


class LayeredStore:
    """Read-through / write-local view over a settings store.

    Reads fall back to the immutable snapshot that was already loaded and
    shared between tasks; every write performed inside an active read context
    lands in a private overlay so that temporary overrides, fresh reloads and
    env switches never mutate state that another task (or the outer context)
    can observe.

    The class implements the small dict-like surface used by ``Settings``.
    """

    def __init__(self, base: dict, local: Optional[dict] = None):
        # ``base`` is treated as read-only; it is the shared, already-loaded
        # snapshot.
        self._base = base
        self._local = local if local is not None else self._new_local(base)

    @staticmethod
    def _new_local(base: dict) -> dict:
        if isinstance(base, DataDict):
            return DataDict(box_settings=base.__meta__.core)
        return {}

    def _resolve_key(self, key, container):
        if isinstance(container, DataDict):
            from dynaconf import utils as _utils

            return _utils.find_the_correct_casing(
                key, tuple(container.keys())
            ) or key
        return key

    def __getitem__(self, key):
        if key in self._local:
            return self._local[key]
        return self._base[key]

    def __setitem__(self, key, value):
        self._local[key] = value

    def __delitem__(self, key):
        if key in self._local:
            del self._local[key]
            return
        # The key only exists on the shared snapshot. Materialize every other
        # shared key into the overlay before dropping this one, so the base
        # snapshot stays untouched while the local view loses the key.
        self._promote_base()
        resolved = self._resolve_key(key, self._local)
        del self._local[resolved]

    def _promote_base(self):
        if not getattr(self, "_promoted", False):
            for base_key in list(self._base.keys()):
                if base_key not in self._local:
                    self._local[base_key] = self._base[base_key]
            self._promoted = True

    def get(self, key, default=None, bypass_eval=False):
        if key in self._local:
            if isinstance(self._local, DataDict):
                return self._local.get(key, default, bypass_eval=bypass_eval)
            return self._local.get(key, default)
        if isinstance(self._base, DataDict):
            return self._base.get(key, default, bypass_eval=bypass_eval)
        return self._base.get(key, default)

    def __contains__(self, key):
        return key in self._local or key in self._base

    def __iter__(self):
        seen = set()
        for key in self._local:
            seen.add(key)
            yield key
        for key in self._base:
            if key not in seen:
                yield key

    def keys(self):
        return list(self)

    def values(self):
        return [self[key] for key in self]

    def items(self, bypass_eval=False):
        if bypass_eval:
            return [
                (key, self.get(key, bypass_eval=True)) for key in self
            ]
        return [(key, self[key]) for key in self]

    def __len__(self):
        return len(self._local) + sum(
            1 for key in self._base if key not in self._local
        )

    def copy(self, bypass_eval=False):
        if isinstance(self._local, DataDict):
            merged = self._local.copy(bypass_eval=bypass_eval)
        else:
            merged = copy.copy(self._local)
        for key in self._base:
            if key not in merged:
                if isinstance(self._base, DataDict):
                    merged[key] = self._base.get(
                        key, bypass_eval=bypass_eval
                    )
                else:
                    merged[key] = self._base[key]
        if isinstance(merged, DataDict):
            return merged
        if isinstance(self._base, DataDict):
            return DataDict(
                merged, box_settings=self._base.__meta__.core
            )
        return merged

    def materialize(self):
        """Return a concrete dict containing the effective merged view."""
        return self.copy()


@dataclass
class ReadContext:
    """The private state of a single read context (task/nested scope)."""

    config: Any
    store: LayeredStore
    cache: dict
    # True when the context was opened by a direct ``setenv`` rather than by
    # a ``using_env``/``fresh`` block. A later direct ``setenv`` replaces the
    # previous one instead of nesting on top of it.
    setenv_owned: bool = False


class ContextState:
    """Holds the active :class:`ReadContext` for the running execution.

    A :class:`contextvars.ContextVar` gives each asyncio task (and each
    thread) an independent chain of read contexts while nested scopes inside
    the same task inherit the parent's local state copy-on-write.
    """

    def __init__(self, core):
        self._core = core
        self._var: contextvars.ContextVar[Optional[ReadContext]] = (
            contextvars.ContextVar(
                f"dynaconf_read_context_{id(core)}", default=None
            )
        )
        # Token of the context opened by a direct ``setenv`` in this task.
        self._setenv_token_var: contextvars.ContextVar[object] = (
            contextvars.ContextVar(
                f"dynaconf_setenv_token_{id(core)}", default=None
            )
        )

    # accessors -----------------------------------------------------------

    @property
    def current(self) -> Optional[ReadContext]:
        return self._var.get()

    def get_context(self) -> ReadContext:
        ctx = self._var.get()
        if ctx is None:
            raise LookupError("No active dynaconf read context")
        return ctx

    def is_active(self) -> bool:
        return self._var.get() is not None

    @property
    def setenv_token(self):
        return self._setenv_token_var.get()

    @setenv_token.setter
    def setenv_token(self, token) -> None:
        self._setenv_token_var.set(token)

    # lifecycle -----------------------------------------------------------

    def push(self, config, store, cache, setenv_owned=False) -> object:
        parent = self._var.get()
        ctx = ReadContext(
            config=config,
            store=store,
            cache=cache,
            setenv_owned=setenv_owned,
        )
        token = self._var.set(ctx)
        return _ContextToken(self, token, parent)

    def pop(self, token) -> None:
        self._var.reset(token._token)


class _ContextToken:
    def __init__(self, state, token, parent):
        self._state = state
        self._token = token
        self.parent = parent
