# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Processors useful regardless of the logging framework.
"""

from __future__ import annotations


__lazy_modules__ = ["datetime", "logging", "threading"]

import datetime as dt
import enum
import json
import logging
import operator
import os
import sys
import threading
import time

from collections.abc import Callable, Collection, Sequence
from types import FrameType, TracebackType
from typing import (
    Any,
    ClassVar,
    Final,
    NamedTuple,
    TextIO,
    cast,
)

from ._frames import (
    _find_first_app_frame_and_name,
    _format_exception,
    _format_stack,
)
from ._log_levels import NAME_TO_LEVEL, add_log_level
from ._utils import get_processname
from .contextvars import _ASYNC_CALLING_THREAD
from .tracebacks import ExceptionDictTransformer, safe_str
from .typing import (
    EventDict,
    ExceptionTransformer,
    ExcInfo,
    WrappedLogger,
)


__all__ = [
    "NAME_TO_LEVEL",  # some people rely on it being here
    "BUDGET_TRUNCATION_KEY",
    "BudgetedExceptionRenderer",
    "CallsiteParameter",
    "CallsiteParameterAdder",
    "EventRenamer",
    "ExceptionPrettyPrinter",
    "JSONRenderer",
    "KeyValueRenderer",
    "LogfmtRenderer",
    "MIN_STRUCTURED_BUDGET",
    "StackInfoRenderer",
    "TimeStamper",
    "UnicodeDecoder",
    "UnicodeEncoder",
    "add_log_level",
    "dict_tracebacks",
    "format_exc_info",
]


class KeyValueRenderer:
    """
    Render ``event_dict`` as a list of ``Key=repr(Value)`` pairs.

    Args:
        sort_keys: Whether to sort keys when formatting.

        key_order:
            List of keys that should be rendered in this exact order.  Missing
            keys will be rendered as ``None``, extra keys depending on
            *sort_keys* and the dict class.

        drop_missing:
            When ``True``, extra keys in *key_order* will be dropped rather
            than rendered as ``None``.

        repr_native_str:
            When ``True``, :func:`repr()` is also applied to native strings.

    .. versionadded:: 0.2.0 *key_order*
    .. versionadded:: 16.1.0 *drop_missing*
    .. versionadded:: 17.1.0 *repr_native_str*
    """

    def __init__(
        self,
        sort_keys: bool = False,
        key_order: Sequence[str] | None = None,
        drop_missing: bool = False,
        repr_native_str: bool = True,
    ):
        self._ordered_items = _items_sorter(sort_keys, key_order, drop_missing)

        if repr_native_str is True:
            self._repr = repr
        else:

            def _repr(inst: Any) -> str:
                if isinstance(inst, str):
                    return inst

                return repr(inst)

            self._repr = _repr

    def __call__(
        self, _: WrappedLogger, __: str, event_dict: EventDict
    ) -> str:
        return " ".join(
            k + "=" + self._repr(v) for k, v in self._ordered_items(event_dict)
        )


class LogfmtRenderer:
    """
    Render ``event_dict`` using the logfmt_ format.

    .. _logfmt: https://brandur.org/logfmt

    Args:
        sort_keys: Whether to sort keys when formatting.

        key_order:
            List of keys that should be rendered in this exact order. Missing
            keys are rendered with empty values, extra keys depending on
            *sort_keys* and the dict class.

        drop_missing:
            When ``True``, extra keys in *key_order* will be dropped rather
            than rendered with empty values.

        bool_as_flag:
            When ``True``, render ``{"flag": True}`` as ``flag``, instead of
            ``flag=true``. ``{"flag": False}`` is always rendered as
            ``flag=false``.

    Raises:
        ValueError: If a key contains non-printable or whitespace characters.

    .. versionadded:: 21.5.0
    """

    bool_as_flag: bool

    def __init__(
        self,
        sort_keys: bool = False,
        key_order: Sequence[str] | None = None,
        drop_missing: bool = False,
        bool_as_flag: bool = True,
    ):
        self._ordered_items = _items_sorter(sort_keys, key_order, drop_missing)
        self.bool_as_flag = bool_as_flag

    def __call__(
        self, _: WrappedLogger, __: str, event_dict: EventDict
    ) -> str:
        elements: list[str] = []
        for key, value in self._ordered_items(event_dict):
            if any(c <= " " for c in key):
                msg = f'Invalid key: "{key}"'
                raise ValueError(msg)

            if value is None:
                elements.append(f"{key}=")
                continue

            if isinstance(value, bool):
                if self.bool_as_flag and value:
                    elements.append(f"{key}")
                    continue
                value = "true" if value else "false"

            value = str(value)
            backslashes_need_escaping = (
                " " in value or "=" in value or '"' in value
            )
            if backslashes_need_escaping and "\\" in value:
                value = value.replace("\\", "\\\\")

            value = value.replace('"', '\\"').replace("\n", "\\n")

            if backslashes_need_escaping:
                value = f'"{value}"'

            elements.append(f"{key}={value}")

        return " ".join(elements)


def _items_sorter(
    sort_keys: bool,
    key_order: Sequence[str] | None,
    drop_missing: bool,
) -> Callable[[EventDict], list[tuple[str, object]]]:
    """
    Return a function to sort items from an ``event_dict``.

    See `KeyValueRenderer` for an explanation of the parameters.
    """
    # Use an optimized version for each case.
    if key_order and sort_keys:

        def ordered_items(event_dict: EventDict) -> list[tuple[str, Any]]:
            items = []
            for key in key_order:
                value = event_dict.pop(key, None)
                if value is not None or not drop_missing:
                    items.append((key, value))

            items += sorted(event_dict.items())

            return items

    elif key_order:

        def ordered_items(event_dict: EventDict) -> list[tuple[str, Any]]:
            items = []
            for key in key_order:
                value = event_dict.pop(key, None)
                if value is not None or not drop_missing:
                    items.append((key, value))

            items += event_dict.items()

            return items

    elif sort_keys:

        def ordered_items(event_dict: EventDict) -> list[tuple[str, Any]]:
            return sorted(event_dict.items())

    else:
        ordered_items = operator.methodcaller(  # type: ignore[assignment]
            "items"
        )

    return ordered_items


class UnicodeEncoder:
    """
    Encode unicode values in ``event_dict``.

    Args:
        encoding: Encoding to encode to (default: ``"utf-8"``).

        errors:
            How to cope with encoding errors (default ``"backslashreplace"``).

    Just put it in the processor chain before the renderer.

    .. note:: Not very useful in a Python 3-only world.
    """

    _encoding: str
    _errors: str

    def __init__(
        self, encoding: str = "utf-8", errors: str = "backslashreplace"
    ) -> None:
        self._encoding = encoding
        self._errors = errors

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        for key, value in event_dict.items():
            if isinstance(value, str):
                event_dict[key] = value.encode(self._encoding, self._errors)

        return event_dict


class UnicodeDecoder:
    """
    Decode byte string values in ``event_dict``.

    Args:
        encoding: Encoding to decode from (default: ``"utf-8"``).

        errors: How to cope with encoding errors (default: ``"replace"``).

    Useful to prevent ``b"abc"`` being rendered as as ``'b"abc"'``.

    Just put it in the processor chain before the renderer.

    .. versionadded:: 15.4.0
    """

    _encoding: str
    _errors: str

    def __init__(
        self, encoding: str = "utf-8", errors: str = "replace"
    ) -> None:
        self._encoding = encoding
        self._errors = errors

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        for key, value in event_dict.items():
            if isinstance(value, bytes):
                event_dict[key] = value.decode(self._encoding, self._errors)

        return event_dict


class JSONRenderer:
    """
    Render the ``event_dict`` using ``serializer(event_dict, **dumps_kw)``.

    Args:
        dumps_kw:
            Are passed unmodified to *serializer*.  If *default* is passed, it
            will disable support for ``__structlog__``-based serialization.

        serializer:
            A :func:`json.dumps`-compatible callable that will be used to
            format the string.  This can be used to use alternative JSON
            encoders (default: :func:`json.dumps`).

            .. seealso:: :doc:`performance` for examples.

    .. versionadded:: 0.2.0 Support for ``__structlog__`` serialization method.
    .. versionadded:: 15.4.0 *serializer* parameter.
    .. versionadded:: 18.2.0
       Serializer's *default* parameter can be overwritten now.
    """

    def __init__(
        self,
        serializer: Callable[..., str | bytes] = json.dumps,
        **dumps_kw: Any,
    ) -> None:
        dumps_kw.setdefault("default", _json_fallback_handler)
        self._dumps_kw = dumps_kw
        self._dumps = serializer

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> str | bytes:
        """
        The return type of this depends on the return type of self._dumps.
        """
        return self._dumps(event_dict, **self._dumps_kw)


def _json_fallback_handler(obj: Any) -> Any:
    """
    Serialize custom datatypes and pass the rest to __structlog__ & repr().
    """
    # circular imports :(
    from structlog.threadlocal import _ThreadLocalDictWrapper

    if isinstance(obj, _ThreadLocalDictWrapper):
        return obj._dict

    try:
        return obj.__structlog__()
    except AttributeError:
        return repr(obj)


class ExceptionRenderer:
    """
    Replace an ``exc_info`` field with an ``exception`` field which is rendered
    by *exception_formatter*.

    The contents of the ``exception`` field depends on the return value of the
    *exception_formatter* that is passed:

    - The default produces a formatted string via Python's built-in traceback
      formatting (this is :obj:`.format_exc_info`).
    - If you pass a :class:`~structlog.tracebacks.ExceptionDictTransformer`, it
      becomes a list of stack dicts that can be serialized to JSON.

    If *event_dict* contains the key ``exc_info``, there are three possible
    behaviors:

    1. If the value is a tuple, render it into the key ``exception``.
    2. If the value is an Exception render it into the key ``exception``.
    3. If the value true but no tuple, obtain exc_info ourselves and render
       that.

    If there is no ``exc_info`` key, the *event_dict* is not touched. This
    behavior is analog to the one of the stdlib's logging.

    Args:
        exception_formatter:
            A callable that is used to format the exception from the
            ``exc_info`` field into the ``exception`` field.

    .. seealso::
        :doc:`exceptions` for a broader explanation of *structlog*'s exception
        features.

    .. versionadded:: 22.1.0
    """

    format_exception: ExceptionTransformer

    def __init__(
        self,
        exception_formatter: ExceptionTransformer = _format_exception,
    ) -> None:
        self.format_exception = exception_formatter

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        exc_info = _figure_out_exc_info(event_dict.pop("exc_info", None))
        if exc_info:
            event_dict["exception"] = self.format_exception(exc_info)

        return event_dict


format_exc_info: Final = ExceptionRenderer()
"""
Replace an ``exc_info`` field with an ``exception`` string field using Python's
built-in traceback formatting.

If *event_dict* contains the key ``exc_info``, there are three possible
behaviors:

1. If the value is a tuple, render it into the key ``exception``.
2. If the value is an Exception render it into the key ``exception``.
3. If the value is true but no tuple, obtain exc_info ourselves and render
   that.

If there is no ``exc_info`` key, the *event_dict* is not touched. This behavior
is analog to the one of the stdlib's logging.

.. seealso::
    :doc:`exceptions` for a broader explanation of *structlog*'s exception
    features.
"""

dict_tracebacks: Final = ExceptionRenderer(ExceptionDictTransformer())
"""
Replace an ``exc_info`` field with an ``exception`` field containing structured
tracebacks suitable for, e.g., JSON output.

It is a shortcut for :class:`ExceptionRenderer` with a
:class:`~structlog.tracebacks.ExceptionDictTransformer`.

The treatment of the ``exc_info`` key is identical to `format_exc_info`.

.. versionadded:: 22.1.0

.. seealso::
    :doc:`exceptions` for a broader explanation of *structlog*'s exception
    features.
"""


BUDGET_TRUNCATION_KEY = "exception_truncation"
"""
Key under which a budgeted renderer stores truncation metadata.

.. versionadded:: 26.2.0
"""

_BUDGET_TRUNCATED_MARKER = "[truncated] "
# A structured fallback is an object with two string fields, which cannot be
# serialized below this many bytes, even with empty values.  String output
# can honor any budget >= 2.
MIN_STRUCTURED_BUDGET = 33
"""
Smallest budget that can reliably hold a structured fallback object.

.. versionadded:: 26.2.0
"""


def _rendered_size(value: Any, serializer: Callable[..., str | bytes]) -> int:
    """
    Return the size in bytes of *value* as produced by *serializer*.

    Serialization problems must never break logging, so an upper bound based
    on the object's string representation is returned as a fallback.
    """
    try:
        rendered = serializer(value)
    except Exception:  # noqa: BLE001
        return len(repr(value).encode("utf-8", "replace"))

    if isinstance(rendered, str):
        return len(rendered.encode("utf-8"))

    return len(rendered)


def _shrink_to_budget(text: str, budget: int) -> tuple[str, bool]:
    """
    Shrink *text* so that ``_BUDGET_TRUNCATED_MARKER + text`` fits *budget*
    UTF-8 bytes.

    Return the shrunk text without the marker and whether shrinking happened.
    Budgets too small to hold the marker leave the text to the caller, which
    drops the marker in that case.
    """
    prefix = _BUDGET_TRUNCATED_MARKER.encode("utf-8")
    encoded = text.encode("utf-8")
    if len(prefix) + len(encoded) <= budget:
        return text, False

    capacity = max(budget - len(prefix), 0)
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(text[:middle].encode("utf-8")) <= capacity:
            low = middle
        else:
            high = middle - 1

    return text[:low], True


def _truncate_text(text: str, budget: int) -> str:
    """
    Return *text* cut to *budget* UTF-8 bytes.

    The truncation marker is prepended only when content had to be removed
    and there is room for it; budgets smaller than the marker keep the raw
    cut text.
    """
    shrunk, shrank = _shrink_to_budget(text, budget)
    if not shrank:
        return text
    marked = _BUDGET_TRUNCATED_MARKER + shrunk
    if len(marked.encode("utf-8")) <= budget:
        return marked
    # Budget is smaller than the marker itself: cut the raw text instead.
    capacity = budget
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(text[:middle].encode("utf-8")) <= capacity:
            low = middle
        else:
            high = middle - 1
    return text[:low]


def _root_exception(exc_info: ExcInfo) -> ExcInfo:
    """
    Walk the explicit/implicit cause chain to its deepest exception.
    """
    seen: set[int] = set()
    exc_type, exc_value, traceback = exc_info
    while id(exc_value) not in seen:
        seen.add(id(exc_value))
        cause = getattr(exc_value, "__cause__", None)
        if cause is None and not getattr(
            exc_value, "__suppress_context__", False
        ):
            cause = exc_value.__context__
        if cause is None:
            break
        exc_type, exc_value, traceback = (
            cause.__class__,
            cause,
            cause.__traceback__,
        )

    return exc_type, exc_value, traceback


def _trim_stacks(
    stacks: Any,
    *,
    keep_root_only: bool,
    keep_frames: int | None,
    strip_locals: bool,
) -> Any:
    """
    Reduce structured traceback stacks in place.

    With *keep_root_only*, only the final (root-cause) stack of each chain is
    kept.  *keep_frames* limits the number of frames of every remaining stack;
    ``None`` keeps every frame.  When *strip_locals* is true, frame locals are
    removed, so each reduction step produces a verifiably lower detail level.
    """
    if not isinstance(stacks, list):
        return stacks

    if keep_root_only:
        stacks = stacks[-1:] if stacks else stacks

    for stack in stacks:
        if not isinstance(stack, dict):
            continue

        frames = stack.get("frames")
        if isinstance(frames, list):
            if strip_locals:
                for frame in frames:
                    if isinstance(frame, dict) and "locals" in frame:
                        del frame["locals"]
            if keep_frames is not None and len(frames) > keep_frames:
                stack["frames"] = frames[-keep_frames:]

        nested = stack.get("exceptions")
        if isinstance(nested, list):
            _trim_stacks(
                nested,
                keep_root_only=keep_root_only,
                keep_frames=keep_frames,
                strip_locals=strip_locals,
            )

    return stacks


class BudgetedExceptionRenderer:
    """
    Replace an ``exc_info`` field with a size-budgeted ``exception`` field.

    Centralized log systems reject or truncate log events that exceed a per
    event size limit.  A verbose exception -- for example one with a wide
    stack, a long cause chain, or large local variables -- can therefore blow
    the whole event, causing the exception *and* every other field of the
    event to be lost.  This processor renders the exception with the same
    *exception_formatter* as `ExceptionRenderer`, but guarantees that the
    serialized ``exception`` field does not exceed *max_size* bytes.

    The exception is rendered at progressively lower detail levels until one
    fits the budget:

    - The full, unmodified formatter output.
    - For string output, the root-cause traceback.  For structured output,
      the same stacks with bulky frame locals removed.
    - For string output, the last traceback line (the root-cause summary).
      For structured output, a frame-count cap, then only the root-cause
      stack, then a single root-cause frame.
    - A minimal ``{"exc_type", "exc_value"}`` dictionary as a last resort for
      structured output.

    Whenever the output had to be reduced, metadata describing the original
    and final size, the applied detail level, and how much was cut is stored
    under *truncation_key*.  The event itself is never dropped: subsequent
    processors keep running, so ordinary events logged right after an
    over-budget exception are unaffected.

    Args:
        max_size:
            Maximum size of the serialized ``exception`` field in bytes.

        exception_formatter:
            A callable that is used to format the exception, identical to the
            one accepted by `ExceptionRenderer`.

        serializer:
            A :func:`json.dumps`-compatible callable used to measure the
            size of rendered values.  Should match the serializer used by
            your renderer (defaults to :func:`json.dumps`).

        truncation_key:
            Key under which truncation metadata is stored when the exception
            had to be reduced.

    Raises:
        ValueError: If *max_size* is smaller than 1.

    .. note::

        String formatters can honor any budget of two bytes or more.
        Structured formatters (like
        :class:`~structlog.tracebacks.ExceptionDictTransformer`) ultimately
        fall back to a small two-field object, so a *max_size* below
        :data:`MIN_STRUCTURED_BUDGET` cannot be satisfied for them.

    .. seealso::
        :doc:`exceptions` for a broader explanation of *structlog*'s exception
        features.

    .. versionadded:: 26.2.0
    """

    format_exception: ExceptionTransformer
    max_size: int
    truncation_key: str

    def __init__(
        self,
        max_size: int = 8192,
        exception_formatter: ExceptionTransformer = _format_exception,
        serializer: Callable[..., str | bytes] = json.dumps,
        truncation_key: str = BUDGET_TRUNCATION_KEY,
    ) -> None:
        if max_size < 1:
            msg = f'"max_size" must be >= 1: {max_size}'
            raise ValueError(msg)

        self.max_size = max_size
        self.format_exception = exception_formatter
        self._serializer = serializer
        self.truncation_key = truncation_key

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        exc_info = _figure_out_exc_info(event_dict.pop("exc_info", None))
        if not exc_info:
            return event_dict

        try:
            rendered = self.format_exception(exc_info)
        except Exception as error:  # noqa: BLE001
            # A broken formatter must not take the whole event down.
            rendered = (
                f"<exception-formatter-error "
                f"{type(error).__name__}: {error}>"
            )

        original_size = self._size(rendered)
        if self._fits(rendered, original_size):
            event_dict["exception"] = rendered
            return event_dict

        if isinstance(rendered, str):
            value, info = self._budget_string(exc_info, rendered)
        else:
            value, info = self._budget_dict(exc_info, rendered)

        info["original_size"] = original_size
        info["rendered_size"] = self._size(value)
        event_dict["exception"] = value
        event_dict[self.truncation_key] = info

        return event_dict

    def _size(self, value: Any) -> int:
        return _rendered_size(value, self._serializer)

    def _fits(self, value: Any, size: int | None = None) -> bool:
        """
        Check whether *value* stays within the budget once embedded in an
        event.  A top-level string gets two quote characters from JSON.
        """
        if size is None:
            size = self._size(value)
        if isinstance(value, str):
            size += 2
        return size <= self.max_size

    def _text_budget(self) -> int:
        # Two bytes are spent on the quotes surrounding a JSON string.
        return max(self.max_size - 2, 0)

    def _budget_string(
        self, exc_info: ExcInfo, full: str
    ) -> tuple[str, dict[str, Any]]:
        root = _root_exception(exc_info)
        chain_length = _chain_length(exc_info[1])
        candidates: list[tuple[str, str]] = [
            ("root_traceback", self.format_exception(root)),
        ]
        root_line = _format_exception(root).strip().splitlines()
        root_summary = root_line[-1] if root_line else safe_str(root[1])
        candidates.append(("root_summary", root_summary))

        budget = self._text_budget()
        for detail, candidate in candidates:
            value = _truncate_text(candidate, budget)
            if self._fits(value):
                return value, self._info(
                    detail, full, value, chain_length
                )

        # Neither level fits uncut; the truncated summary is the last resort
        # and always honors the byte budget by construction.
        value = _truncate_text(root_summary, budget)
        return value, self._info(
            "root_summary", full, value, chain_length
        )

    def _budget_dict(
        self, exc_info: ExcInfo, full: Any
    ) -> tuple[Any, dict[str, Any]]:
        root = _root_exception(exc_info)
        chain_length = _chain_length(exc_info[1])
        frame_cap = self._frame_cap()
        candidates: list[tuple[str, Any]] = [
            # Drop bulky frame locals but keep every stack and frame.
            (
                "locals_removed",
                _trim_stacks(
                    _copy_jsonish(full),
                    keep_root_only=False,
                    keep_frames=None,
                    strip_locals=True,
                ),
            ),
            # Also cap the number of frames per stack.
            (
                "frames_capped",
                _trim_stacks(
                    _copy_jsonish(full),
                    keep_root_only=False,
                    keep_frames=frame_cap,
                    strip_locals=True,
                ),
            ),
            # Collapse the chain to the root-cause stack.
            (
                "root_stack",
                _trim_stacks(
                    _copy_jsonish(full),
                    keep_root_only=True,
                    keep_frames=frame_cap,
                    strip_locals=True,
                ),
            ),
            # Keep a single root-cause frame.
            (
                "root_summary",
                _trim_stacks(
                    _copy_jsonish(full),
                    keep_root_only=True,
                    keep_frames=1,
                    strip_locals=True,
                ),
            ),
        ]

        for detail, candidate in candidates:
            if self._fits(candidate):
                return candidate, self._info(
                    detail, full, candidate, chain_length
                )
            shrunk = self._shrink_json_strings(candidate)
            if self._fits(shrunk):
                return shrunk, self._info(
                    detail, full, shrunk, chain_length
                )

        fallback = self._fallback(root)
        return fallback, self._info(
            "root_cause_only", full, fallback, chain_length
        )

    def _frame_cap(self) -> int:
        # Keep the cap small relative to the budget while staying useful.
        return max(2, min(50, self.max_size // 256))

    def _shrink_json_strings(self, value: Any) -> Any:
        if isinstance(value, str):
            return _truncate_text(value, self.max_size)
        if isinstance(value, list):
            return [self._shrink_json_strings(item) for item in value]
        if isinstance(value, dict):
            return {
                key: self._shrink_json_strings(item)
                for key, item in value.items()
            }
        return value

    def _fallback(self, root: ExcInfo) -> dict[str, str]:
        result = {
            "exc_type": safe_str(root[0].__name__),
            "exc_value": safe_str(root[1]),
        }
        if self._fits(result):
            return result

        # Shrink the value against the bytes already spent on the keys and
        # the exception type.
        overhead = self._size(result) - self._size(result["exc_value"])
        result["exc_value"] = _truncate_text(
            result["exc_value"], max(self.max_size - overhead, 0)
        )
        if self._fits(result):
            return result

        # Drop the value entirely; the type is the most traceable remnant.
        result["exc_value"] = ""
        if self._fits(result):
            return result

        # Only reached for budgets below the structural minimum.
        result["exc_type"] = ""
        return result

    def _info(
        self,
        detail: str,
        full: Any,
        value: Any,
        chain_length: int,
    ) -> dict[str, Any]:
        full_size = self._size(full)
        value_size = self._size(value)
        return {
            "detail": detail,
            "chain_length": chain_length,
            "original_size": full_size,
            "rendered_size": value_size,
            "dropped_bytes": full_size - value_size,
        }


def _chain_length(exc_value: BaseException) -> int:
    """
    Count the exceptions in the explicit/implicit cause chain.
    """
    seen: set[int] = set()
    length = 0
    current: BaseException | None = exc_value
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        length += 1
        cause: BaseException | None = getattr(current, "__cause__", None)
        if cause is None and not getattr(
            current, "__suppress_context__", False
        ):
            cause = current.__context__
        current = cause
    return length


def _copy_jsonish(value: Any) -> Any:
    """
    Deep-copy JSON-compatible structures without importing ``copy``.
    """
    if isinstance(value, dict):
        return {key: _copy_jsonish(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_jsonish(item) for item in value]
    return value


class TimeStamper:
    """
    Add a timestamp to ``event_dict``.

    Args:
        fmt:
            strftime format string, or ``"iso"`` for `ISO 8601
            <https://en.wikipedia.org/wiki/ISO_8601>`_, or `None` for a `UNIX
            timestamp <https://en.wikipedia.org/wiki/Unix_time>`_.

        utc: Whether timestamp should be in UTC or local time.

        key: Target key in *event_dict* for added timestamps.

    .. versionchanged:: 19.2.0 Can be pickled now.
    """

    __slots__ = ("_stamper", "fmt", "key", "utc")

    fmt: str | None
    utc: bool
    key: str

    def __init__(
        self,
        fmt: str | None = None,
        utc: bool = True,
        key: str = "timestamp",
    ) -> None:
        self.fmt, self.utc, self.key = fmt, utc, key

        self._stamper = _make_stamper(fmt, utc, key)

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        return self._stamper(event_dict)

    def __getstate__(self) -> dict[str, Any]:
        return {"fmt": self.fmt, "utc": self.utc, "key": self.key}

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.fmt = state["fmt"]
        self.utc = state["utc"]
        self.key = state["key"]

        self._stamper = _make_stamper(**state)


def _make_stamper(
    fmt: str | None, utc: bool, key: str
) -> Callable[[EventDict], EventDict]:
    """
    Create a stamper function.
    """
    if fmt is None and not utc:
        msg = "UNIX timestamps are always UTC."
        raise ValueError(msg)

    now: Callable[[], dt.datetime]

    if utc:

        def now() -> dt.datetime:
            return dt.datetime.now(tz=dt.timezone.utc)

    else:

        def now() -> dt.datetime:
            # We don't need the TZ for our own formatting. We add it only for
            # user-defined formats later.
            return dt.datetime.now()  # noqa: DTZ005

    if fmt is None:

        def stamper_unix(event_dict: EventDict) -> EventDict:
            event_dict[key] = time.time()

            return event_dict

        return stamper_unix

    if fmt.upper() == "ISO":

        def stamper_iso_local(event_dict: EventDict) -> EventDict:
            event_dict[key] = now().isoformat()
            return event_dict

        def stamper_iso_utc(event_dict: EventDict) -> EventDict:
            event_dict[key] = now().isoformat().replace("+00:00", "Z")
            return event_dict

        if utc:
            return stamper_iso_utc

        return stamper_iso_local

    def stamper_fmt_local(event_dict: EventDict) -> EventDict:
        event_dict[key] = now().astimezone().strftime(fmt)
        return event_dict

    def stamper_fmt_utc(event_dict: EventDict) -> EventDict:
        event_dict[key] = now().strftime(fmt)
        return event_dict

    if utc:
        return stamper_fmt_utc

    return stamper_fmt_local


class MaybeTimeStamper:
    """
    A timestamper that only adds a timestamp if there is none.

    This allows you to overwrite the ``timestamp`` key in the event dict for
    example when the event is coming from another system.

    It takes the same arguments as `TimeStamper`.

    .. versionadded:: 23.2.0
    """

    __slots__ = ("stamper",)

    stamper: TimeStamper

    def __init__(
        self,
        fmt: str | None = None,
        utc: bool = True,
        key: str = "timestamp",
    ):
        self.stamper = TimeStamper(fmt=fmt, utc=utc, key=key)

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        if self.stamper.key not in event_dict:
            return self.stamper(logger, name, event_dict)

        return event_dict


def _figure_out_exc_info(v: Any) -> ExcInfo | None:
    """
    Try to convert *v* into an ``exc_info`` tuple.

    Return ``None`` if *v* does not represent an exception or if there is no
    current exception.
    """
    if isinstance(v, BaseException):
        return (v.__class__, v, v.__traceback__)

    if isinstance(v, tuple) and len(v) == 3:
        has_type = isinstance(v[0], type) and issubclass(v[0], BaseException)
        has_exc = isinstance(v[1], BaseException)
        has_tb = v[2] is None or isinstance(v[2], TracebackType)
        if has_type and has_exc and has_tb:
            return v

    if v:
        result = sys.exc_info()
        if result == (None, None, None):
            return None
        return cast(ExcInfo, result)

    return None


class ExceptionPrettyPrinter:
    """
    Pretty print exceptions rendered by *exception_formatter* and remove them
    from the ``event_dict``.

    Args:
        file: Target file for output (default: ``sys.stdout``).
        exception_formatter:
            A callable that is used to format the exception from the
            ``exc_info`` field into the ``exception`` field.

    This processor is mostly for development and testing so you can read
    exceptions properly formatted.

    It behaves like `format_exc_info`, except that it removes the exception data
    from the event dictionary after printing it using the passed
    *exception_formatter*, which defaults to Python's built-in traceback formatting.

    It's tolerant to having `format_exc_info` in front of itself in the
    processor chain but doesn't require it.  In other words, it handles both
    ``exception`` as well as ``exc_info`` keys.

    .. versionadded:: 0.4.0

    .. versionchanged:: 16.0.0
       Added support for passing exceptions as ``exc_info`` on Python 3.

    .. versionchanged:: 25.4.0
       Fixed *exception_formatter* so that it overrides the default if set.
    """

    format_exception: ExceptionTransformer

    def __init__(
        self,
        file: TextIO | None = None,
        exception_formatter: ExceptionTransformer = _format_exception,
    ) -> None:
        self.format_exception = exception_formatter
        if file is not None:
            self._file = file
        else:
            self._file = sys.stdout

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        exc = event_dict.pop("exception", None)
        if exc is None:
            exc_info = _figure_out_exc_info(event_dict.pop("exc_info", None))
            if exc_info:
                exc = self.format_exception(exc_info)

        if exc:
            print(exc, file=self._file)

        return event_dict


class StackInfoRenderer:
    """
    Add stack information with key ``stack`` if ``stack_info`` is `True`.

    Useful when you want to attach a stack dump to a log entry without
    involving an exception and works analogously to the *stack_info* argument
    of the Python standard library logging.

    Args:
        additional_ignores:
            By default, stack frames coming from *structlog* are ignored. With
            this argument you can add additional names that are ignored, before
            the stack starts being rendered. They are matched using
            ``startswith()``, so they don't have to match exactly. The names
            are used to find the first relevant name, therefore once a frame is
            found that doesn't start with *structlog* or one of
            *additional_ignores*, **no filtering** is applied to subsequent
            frames.

    .. versionadded:: 0.4.0
    .. versionadded:: 22.1.0  *additional_ignores*
    """

    __slots__ = ("_additional_ignores",)

    def __init__(self, additional_ignores: list[str] | None = None) -> None:
        self._additional_ignores = additional_ignores

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> EventDict:
        if event_dict.pop("stack_info", None):
            event_dict["stack"] = _format_stack(
                _find_first_app_frame_and_name(self._additional_ignores)[0]
            )

        return event_dict


class CallsiteParameter(enum.Enum):
    """
    Callsite parameters that can be added to an event dictionary with the
    `structlog.processors.CallsiteParameterAdder` processor class.

    The string values of the members of this enum will be used as the keys for
    the callsite parameters in the event dictionary.

    .. versionadded:: 21.5.0

    .. versionadded:: 25.5.0
       `QUAL_NAME` parameter.

    .. versionadded:: 26.1.0
       `QUAL_MODULE` parameter.
    """

    #: The full path to the python source file of the callsite.
    PATHNAME = "pathname"
    #: The basename part of the full path to the python source file of the
    #: callsite.
    FILENAME = "filename"
    #: The python module the callsite was in. This mimics the module attribute
    #: of `logging.LogRecord` objects and will be the basename, without
    #: extension, of the full path to the python source file of the callsite.
    MODULE = "module"
    #: The fully qualified import name of the module of the callsite.
    QUAL_MODULE = "qual_module"
    #: The name of the function that the callsite was in.
    FUNC_NAME = "func_name"
    #: The qualified name of the callsite (includes scope and class names).
    #: Requires Python 3.11+.
    QUAL_NAME = "qual_name"
    #: The line number of the callsite.
    LINENO = "lineno"
    #: The ID of the thread the callsite was executed in.
    THREAD = "thread"
    #: The name of the thread the callsite was executed in.
    THREAD_NAME = "thread_name"
    #: The ID of the process the callsite was executed in.
    PROCESS = "process"
    #: The name of the process the callsite was executed in.
    PROCESS_NAME = "process_name"


def _get_callsite_pathname(module: str, frame: FrameType) -> Any:
    return frame.f_code.co_filename


def _get_callsite_filename(module: str, frame: FrameType) -> Any:
    return os.path.basename(frame.f_code.co_filename)


def _get_callsite_module(module: str, frame: FrameType) -> Any:
    return os.path.splitext(os.path.basename(frame.f_code.co_filename))[0]


def _get_callsite_func_name(module: str, frame: FrameType) -> Any:
    return frame.f_code.co_name


def _get_callsite_qual_name(module: str, frame: FrameType) -> Any:
    return frame.f_code.co_qualname  # will crash on Python <3.11


def _get_callsite_qual_module(module: str, frame: FrameType) -> Any:
    return module


def _get_callsite_lineno(module: str, frame: FrameType) -> Any:
    return frame.f_lineno


def _get_callsite_thread(module: str, frame: FrameType) -> Any:
    thread_info = _ASYNC_CALLING_THREAD.get(None)
    if thread_info is None:
        return threading.get_ident()

    return thread_info[0]


def _get_callsite_thread_name(module: str, frame: FrameType) -> Any:
    thread_info = _ASYNC_CALLING_THREAD.get(None)
    if thread_info is None:
        return threading.current_thread().name

    return thread_info[1]


def _get_callsite_process(module: str, frame: FrameType) -> Any:
    return os.getpid()


def _get_callsite_process_name(module: str, frame: FrameType) -> Any:
    return get_processname()


class CallsiteParameterAdder:
    """
    Adds parameters of the callsite that an event dictionary originated from to
    the event dictionary. This processor can be used to enrich events
    dictionaries with information such as the function name, line number and
    filename that an event dictionary originated from.

    If the event dictionary has an embedded `logging.LogRecord` object and did
    not originate from *structlog* then the callsite information will be
    determined from the `logging.LogRecord` object. For event dictionaries
    without an embedded `logging.LogRecord` object the callsite will be
    determined from the stack trace, ignoring all intra-structlog calls, calls
    from the `logging` module, and stack frames from modules with names that
    start with values in ``additional_ignores``, if it is specified.

    The keys used for callsite parameters in the event dictionary are the
    string values of `CallsiteParameter` enum members.

    Args:
        parameters:
            A collection of `CallsiteParameter` values that should be added to
            the event dictionary.

        additional_ignores:
            Additional names with which a stack frame's module name must not
            start for it to be considered when determening the callsite.

    .. note::

        When used with `structlog.stdlib.ProcessorFormatter` the most efficient
        configuration is to either use this processor in ``foreign_pre_chain``
        of `structlog.stdlib.ProcessorFormatter` and in ``processors`` of
        `structlog.configure`, or to use it in ``processors`` of
        `structlog.stdlib.ProcessorFormatter` without using it in
        ``processors`` of `structlog.configure` and ``foreign_pre_chain`` of
        `structlog.stdlib.ProcessorFormatter`.

    .. versionadded:: 21.5.0
    """

    _handlers: ClassVar[
        dict[CallsiteParameter, Callable[[str, FrameType], Any]]
    ] = {
        # We can't use lambda functions here because they are not pickleable.
        CallsiteParameter.PATHNAME: _get_callsite_pathname,
        CallsiteParameter.FILENAME: _get_callsite_filename,
        CallsiteParameter.MODULE: _get_callsite_module,
        CallsiteParameter.QUAL_MODULE: _get_callsite_qual_module,
        CallsiteParameter.FUNC_NAME: _get_callsite_func_name,
        CallsiteParameter.QUAL_NAME: _get_callsite_qual_name,
        CallsiteParameter.LINENO: _get_callsite_lineno,
        CallsiteParameter.THREAD: _get_callsite_thread,
        CallsiteParameter.THREAD_NAME: _get_callsite_thread_name,
        CallsiteParameter.PROCESS: _get_callsite_process,
        CallsiteParameter.PROCESS_NAME: _get_callsite_process_name,
    }
    _record_attribute_map: ClassVar[dict[CallsiteParameter, str]] = {
        CallsiteParameter.PATHNAME: "pathname",
        CallsiteParameter.FILENAME: "filename",
        CallsiteParameter.MODULE: "module",
        CallsiteParameter.FUNC_NAME: "funcName",
        CallsiteParameter.LINENO: "lineno",
        CallsiteParameter.THREAD: "thread",
        CallsiteParameter.THREAD_NAME: "threadName",
        CallsiteParameter.PROCESS: "process",
        CallsiteParameter.PROCESS_NAME: "processName",
    }

    _all_parameters: ClassVar[set[CallsiteParameter]] = set(CallsiteParameter)

    class _RecordMapping(NamedTuple):
        event_dict_key: str
        record_attribute: str

    __slots__ = ("_active_handlers", "_additional_ignores", "_record_mappings")

    def __init__(
        self,
        parameters: Collection[CallsiteParameter] = _all_parameters,
        additional_ignores: list[str] | None = None,
    ) -> None:
        if additional_ignores is None:
            additional_ignores = []
        # Ignore stack frames from the logging module. They will occur if this
        # processor is used in ProcessorFormatter, and additionally the logging
        # module should not be logging using structlog.
        self._additional_ignores = ["logging", *additional_ignores]
        self._active_handlers: list[
            tuple[CallsiteParameter, Callable[[str, FrameType], Any]]
        ] = []
        self._record_mappings: list[CallsiteParameterAdder._RecordMapping] = []
        for parameter in parameters:
            self._active_handlers.append(
                (parameter, self._handlers[parameter])
            )
            if (
                record_attr := self._record_attribute_map.get(parameter)
            ) is not None:
                self._record_mappings.append(
                    self._RecordMapping(
                        parameter.value,
                        record_attr,
                    )
                )

    def __call__(
        self, logger: logging.Logger, name: str, event_dict: EventDict
    ) -> EventDict:
        record: logging.LogRecord | None = event_dict.get("_record")
        from_structlog: bool = event_dict.get("_from_structlog", False)

        # If the event dictionary has a record, but it comes from structlog,
        # then the callsite parameters of the record will not be correct.
        if record is not None and not from_structlog:
            for mapping in self._record_mappings:
                event_dict[mapping.event_dict_key] = record.__dict__[
                    mapping.record_attribute
                ]

            return event_dict

        frame, module = _find_first_app_frame_and_name(
            additional_ignores=self._additional_ignores
        )
        for parameter, handler in self._active_handlers:
            event_dict[parameter.value] = handler(module, frame)

        return event_dict


class EventRenamer:
    r"""
    Rename the ``event`` key in event dicts.

    This is useful if you want to use consistent log message keys across
    platforms and/or use the ``event`` key for something custom.

    .. warning::

       It's recommended to put this processor right before the renderer, since
       some processors may rely on the presence and meaning of the ``event``
       key.

    Args:
        to: Rename ``event_dict["event"]`` to ``event_dict[to]``

        replace_by:
            Rename ``event_dict[replace_by]`` to ``event_dict["event"]``.
            *replace_by* missing from ``event_dict`` is handled gracefully.

    .. versionadded:: 22.1.0

    See also the :ref:`rename-event` recipe.
    """

    to: str
    replace_by: str | None

    def __init__(self, to: str, replace_by: str | None = None):
        self.to = to
        self.replace_by = replace_by

    def __call__(
        self, logger: logging.Logger, name: str, event_dict: EventDict
    ) -> EventDict:
        event = event_dict.pop("event")
        event_dict[self.to] = event

        if self.replace_by is not None:
            replace_by = event_dict.pop(self.replace_by, None)
            if replace_by is not None:
                event_dict["event"] = replace_by

        return event_dict
