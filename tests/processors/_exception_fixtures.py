# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
In-memory exception factories for the budgeted exception renderer.

The factories build exceptions whose rendered size is large for *known*
reasons, so tests can reason about size calculations and detail levels
deterministically without touching the file system:

- :func:`wide_exception` produces a deep call stack with bulky local
  variables on every frame.
- :func:`chained_exception` produces a long explicit/implicit cause chain
  with long messages on every link.
- :func:`chained_wide_exception` produces a cause chain whose every link
  carries a real multi-frame traceback.
- :func:`rendered_size` measures a value the same way the renderer does, so
  tests do not have to duplicate the serialization logic.
"""

from __future__ import annotations

import json

from collections.abc import Callable
from typing import Any


class WideStackError(ValueError):
    """Raised at the bottom of a deliberately wide call stack."""


def wide_exception(
    depth: int = 40,
    *,
    payload: str = "x" * 256,
) -> BaseException:
    """
    Raise and catch an exception with a *depth*-frame call stack.

    Every frame holds three bulky local variables derived from *payload*,
    which makes the rendered traceback grow both in the number of frames and
    in per-frame width.  The caught exception -- with its traceback intact --
    is returned instead of propagating.
    """

    def level(remaining: int) -> None:
        """Recurse *remaining* times, keeping bulky locals on each frame."""
        # Named locals survive on the frame and show up when a formatter is
        # asked to render frame locals.  They are bundled and referenced so
        # the values are kept without being optimized away.
        frame_locals = (
            payload,
            payload.upper(),
            payload[::-1],
        )
        if remaining == 0:
            raise WideStackError(
                "wide-root " + "z" * 256 + str(len(frame_locals))
            )
        level(remaining - 1)

    try:
        level(depth)
    except WideStackError as error:
        return error

    msg = "wide_exception() should always return a caught exception"
    raise AssertionError(msg)


def chained_exception(
    length: int = 12,
    *,
    message_width: int = 200,
    implicit: bool = False,
) -> BaseException:
    """
    Build a cause chain of *length* exceptions.

    The deepest exception is a :class:`ValueError`; every wrapping link is a
    :class:`RuntimeError`.  Each message is padded to *message_width*
    characters so that the chain's rendered size grows with *length*.  When
    *implicit* is false, the links are connected explicitly with ``raise ...
    from ...``, otherwise via implicit exception chaining (``__context__``).
    """
    padding = ("a" * message_width, "b" * message_width)

    def build_link(index: int) -> BaseException:
        """Return the exception for chain link *index*."""
        if index == 0:
            return ValueError(f"chain-root-{index} {padding[index % 2]}")

        inner = build_link(index - 1)
        message = f"chain-link-{index} {padding[index % 2]}"
        if implicit:
            # Re-raising *inner* keeps it active; constructing the wrapper
            # inside the handler links it implicitly through __context__.
            try:
                raise inner
            except BaseException:  # noqa: BLE001
                return _implicit_link(RuntimeError(message))
        wrapped = RuntimeError(message)
        wrapped.__cause__ = inner
        return wrapped

    return build_link(length - 1)


def _implicit_link(exc: BaseException) -> BaseException:
    """
    Return *exc* after the interpreter has attached any active exception as
    its implicit ``__context__``.
    """
    try:
        raise exc
    except BaseException as raised:  # noqa: BLE001
        return raised


def rendered_size(
    value: Any, serializer: Callable[..., str | bytes] = json.dumps
) -> int:
    """
    Return the UTF-8 byte size of *value* as it is embedded in a JSON event.

    This mirrors the budgeted renderer's own measurement: a top-level string
    is serialized *with* its surrounding quotes, so no extra margin is added
    here.
    """
    rendered = serializer(value)
    if isinstance(rendered, str):
        return len(rendered.encode("utf-8"))
    return len(rendered)


def chained_wide_exception(
    links: int = 6,
    *,
    depth: int = 15,
    width: int = 150,
) -> BaseException:
    """
    Build a cause chain where every link carries a real multi-frame traceback.

    The deepest link raises from a *depth*-frame call stack; each wrapping
    link is raised ``from`` the previous one with a padded message.  The
    resulting structured traceback therefore has *links* sizable stacks,
    which exercises every reduction level from frame capping down to keeping
    only the root-cause stack.
    """

    def dive(remaining: int) -> None:
        """
        Build a *remaining*-frame traceback before raising the root error.
        """
        frame_pad = "q" * width
        if remaining == 0:
            raise ValueError("root " + "r" * width + frame_pad)
        dive(remaining - 1)

    current: BaseException | None = None
    for index in range(links):
        try:
            if current is None:
                dive(depth)
            else:
                raise RuntimeError(
                    f"link-{index} " + "s" * width
                ) from current
        except (RuntimeError, ValueError) as wrapped:
            current = wrapped

    assert current is not None
    return current
