# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Processors and helpers specific to the :mod:`logging` module from the `Python
standard library <https://docs.python.org/>`_.

See also :doc:`structlog's standard library support <standard-library>`.
"""

from __future__ import annotations


__lazy_modules__ = [
    "asyncio",
    "logging.handlers",
    "threading",
    "traceback",
    "warnings",
]

import asyncio
import contextvars
import functools
import logging
import logging.handlers
import sys
import threading
import traceback
import warnings

from collections.abc import (
    Callable,
    Collection,
    Iterable,
    Mapping,
    Sequence,
)
from functools import partial
from typing import Any, cast


if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


from . import _config
from ._base import BoundLoggerBase
from ._frames import _find_first_app_frame_and_name, _format_stack
from ._log_levels import LEVEL_TO_NAME, NAME_TO_LEVEL, add_log_level
from .contextvars import (
    _ASYNC_CALLING_STACK,
    _ASYNC_CALLING_THREAD,
    merge_contextvars,
)
from .exceptions import DropEvent
from .processors import StackInfoRenderer
from .typing import (
    Context,
    EventDict,
    ExcInfo,
    Processor,
    ProcessorReturnValue,
    WrappedLogger,
)


__all__ = [
    "BoundLogger",
    "ExtraAdder",
    "LoggerFactory",
    "PositionalArgumentsFormatter",
    "ProcessorFormatter",
    "QUEUE_ENVELOPE_KEY",
    "QUEUE_ENVELOPE_VERSION",
    "QUEUE_UNAPPROVED_KEY",
    "QueueFormatter",
    "QueueHandler",
    "QueueListener",
    "QueueProcessorFormatter",
    "SafeQueueHandler",
    "SafeQueueListener",
    "add_log_level",
    "add_log_level_number",
    "add_logger_name",
    "exception_to_queue",
    "filter_by_level",
    "get_logger",
    "group_by_correlation_id",
    "merge_by_correlation_id",
    "merge_events_by_correlation_id",
    "recreate_defaults",
    "render_to_log_args_and_kwargs",
    "render_to_log_kwargs",
    "sanitize_for_queue",
    "wrap_for_queue",
]


def recreate_defaults(*, log_level: int | None = logging.NOTSET) -> None:
    """
    Recreate defaults on top of standard library's logging.

    The output looks the same, but goes through `logging`.

    As with vanilla defaults, the backwards-compatibility guarantees don't
    apply to the settings applied here.

    Args:
        log_level:
            If `None`, don't configure standard library logging **at all**.

            Otherwise configure it to log to `sys.stdout` at *log_level*
            (``logging.NOTSET`` being the default).

            If you need more control over `logging`, pass `None` here and
            configure it yourself.

    .. versionadded:: 22.1.0
    .. versionchanged:: 23.3.0 Added `add_logger_name`.
    .. versionchanged:: 25.1.0 Added `PositionalArgumentsFormatter`.
    """
    if log_level is not None:
        kw = {"force": True}

        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=log_level,
            **kw,  # type: ignore[call-overload]
        )

    _config.reset_defaults()
    _config.configure(
        processors=[
            PositionalArgumentsFormatter(),  # handled by native loggers
            merge_contextvars,
            add_log_level,
            add_logger_name,
            StackInfoRenderer(),
            _config._BUILTIN_DEFAULT_PROCESSORS[-2],  # TimeStamper
            _config._BUILTIN_DEFAULT_PROCESSORS[-1],  # ConsoleRenderer
        ],
        wrapper_class=BoundLogger,
        logger_factory=LoggerFactory(),
    )


_SENTINEL = object()


class _FixedFindCallerLogger(logging.Logger):
    """
    Change the behavior of `logging.Logger.findCaller` to cope with
    *structlog*'s extra frames.
    """

    def findCaller(
        self, stack_info: bool = False, stacklevel: int = 1
    ) -> tuple[str, int, str, str | None]:
        """
        Finds the first caller frame outside of structlog so that the caller
        info is populated for wrapping stdlib.

        This logger gets set as the default one when using LoggerFactory.
        """
        sinfo: str | None
        # stdlib logging passes stacklevel=1 from log methods like .warning(),
        # but we've already skipped those frames by ignoring "logging", so we
        # need to adjust stacklevel down by 1. We need to manually drop
        # logging frames, because there's cases where we call logging methods
        # from within structlog and the stacklevel offsets don't work anymore.
        adjusted_stacklevel = max(0, stacklevel - 1) if stacklevel else None
        f, _name = _find_first_app_frame_and_name(
            ["logging"], stacklevel=adjusted_stacklevel
        )
        sinfo = _format_stack(f) if stack_info else None

        return f.f_code.co_filename, f.f_lineno, f.f_code.co_name, sinfo


class BoundLogger(BoundLoggerBase):
    """
    Python Standard Library version of `structlog.BoundLogger`.

    Works exactly like the generic one except that it takes advantage of
    knowing the logging methods in advance.

    Use it like::

        structlog.configure(
            wrapper_class=structlog.stdlib.BoundLogger,
        )

    It also contains a bunch of properties that pass-through to the wrapped
    `logging.Logger` which should make it work as a drop-in replacement.

    .. versionadded:: 23.1.0
       Async variants `alog()`, `adebug()`, `ainfo()`, and so forth.

    .. versionchanged:: 24.2.0
        Callsite parameters are now also collected by
        `structlog.processors.CallsiteParameterAdder` for async log methods.
    """

    _logger: logging.Logger

    def bind(self, **new_values: Any) -> Self:
        """
        Return a new logger with *new_values* added to the existing ones.
        """
        return super().bind(**new_values)

    def unbind(self, *keys: str) -> Self:
        """
        Return a new logger with *keys* removed from the context.

        Raises:
            KeyError: If the key is not part of the context.
        """
        return super().unbind(*keys)

    def try_unbind(self, *keys: str) -> Self:
        """
        Like :meth:`unbind`, but best effort: missing keys are ignored.

        .. versionadded:: 18.2.0
        """
        return super().try_unbind(*keys)

    def new(self, **new_values: Any) -> Self:
        """
        Clear context and binds *initial_values* using `bind`.

        Only necessary with dict implementations that keep global state like
        those wrapped by `structlog.threadlocal.wrap_dict` when threads
        are reused.
        """
        return super().new(**new_values)

    def debug(self, event: str | None = None, *args: Any, **kw: Any) -> Any:
        """
        Process event and call `logging.Logger.debug` with the result.
        """
        return self._proxy_to_logger("debug", event, *args, **kw)

    def info(self, event: str | None = None, *args: Any, **kw: Any) -> Any:
        """
        Process event and call `logging.Logger.info` with the result.
        """
        return self._proxy_to_logger("info", event, *args, **kw)

    def warning(self, event: str | None = None, *args: Any, **kw: Any) -> Any:
        """
        Process event and call `logging.Logger.warning` with the result.
        """
        return self._proxy_to_logger("warning", event, *args, **kw)

    warn = warning

    def error(self, event: str | None = None, *args: Any, **kw: Any) -> Any:
        """
        Process event and call `logging.Logger.error` with the result.
        """
        return self._proxy_to_logger("error", event, *args, **kw)

    def critical(self, event: str | None = None, *args: Any, **kw: Any) -> Any:
        """
        Process event and call `logging.Logger.critical` with the result.
        """
        return self._proxy_to_logger("critical", event, *args, **kw)

    def fatal(self, event: str | None = None, *args: Any, **kw: Any) -> Any:
        """
        Process event and call `logging.Logger.critical` with the result.
        """
        return self._proxy_to_logger("critical", event, *args, **kw)

    def exception(
        self, event: str | None = None, *args: Any, **kw: Any
    ) -> Any:
        """
        Process event and call `logging.Logger.exception` with the result,
        after setting ``exc_info`` to `True` if it's not already set.
        """
        kw.setdefault("exc_info", True)
        return self._proxy_to_logger("exception", event, *args, **kw)

    def log(
        self, level: int, event: str | None = None, *args: Any, **kw: Any
    ) -> Any:
        """
        Process *event* and call the appropriate logging method depending on
        *level*.
        """
        return self._proxy_to_logger(LEVEL_TO_NAME[level], event, *args, **kw)

    def _proxy_to_logger(
        self,
        method_name: str,
        event: str | None = None,
        *event_args: str,
        **event_kw: Any,
    ) -> Any:
        """
        Propagate a method call to the wrapped logger.

        This is the same as the superclass implementation, except that
        it also preserves positional arguments in the ``event_dict`` so
        that the stdlib's support for format strings can be used.
        """
        if event_args:
            event_kw["positional_args"] = event_args

        return super()._proxy_to_logger(method_name, event=event, **event_kw)

    # Pass-through attributes and methods to mimic the stdlib's logger
    # interface.

    @property
    def name(self) -> str:
        """
        Returns :attr:`logging.Logger.name`
        """
        return self._logger.name

    @property
    def level(self) -> int:
        """
        Returns :attr:`logging.Logger.level`
        """
        return self._logger.level

    @property
    def parent(self) -> Any:
        """
        Returns :attr:`logging.Logger.parent`
        """
        return self._logger.parent

    @property
    def propagate(self) -> bool:
        """
        Returns :attr:`logging.Logger.propagate`
        """
        return self._logger.propagate

    @property
    def handlers(self) -> Any:
        """
        Returns :attr:`logging.Logger.handlers`
        """
        return self._logger.handlers

    @property
    def disabled(self) -> int:
        """
        Returns :attr:`logging.Logger.disabled`
        """
        return self._logger.disabled

    def setLevel(self, level: int) -> None:
        """
        Calls :meth:`logging.Logger.setLevel` with unmodified arguments.
        """
        self._logger.setLevel(level)

    def findCaller(
        self, stack_info: bool = False, stacklevel: int = 1
    ) -> tuple[str, int, str, str | None]:
        """
        Calls :meth:`logging.Logger.findCaller` with unmodified arguments.
        """
        # No need for stacklevel-adjustments since we're within structlog and
        # our frames are ignored unconditionally.
        return self._logger.findCaller(
            stack_info=stack_info, stacklevel=stacklevel
        )

    def makeRecord(
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: str,
        args: tuple[Any, ...],
        exc_info: ExcInfo,
        func: str | None = None,
        extra: Any = None,
    ) -> logging.LogRecord:
        """
        Calls :meth:`logging.Logger.makeRecord` with unmodified arguments.
        """
        return self._logger.makeRecord(
            name, level, fn, lno, msg, args, exc_info, func=func, extra=extra
        )

    def handle(self, record: logging.LogRecord) -> None:
        """
        Calls :meth:`logging.Logger.handle` with unmodified arguments.
        """
        self._logger.handle(record)

    def addHandler(self, hdlr: logging.Handler) -> None:
        """
        Calls :meth:`logging.Logger.addHandler` with unmodified arguments.
        """
        self._logger.addHandler(hdlr)

    def removeHandler(self, hdlr: logging.Handler) -> None:
        """
        Calls :meth:`logging.Logger.removeHandler` with unmodified arguments.
        """
        self._logger.removeHandler(hdlr)

    def hasHandlers(self) -> bool:
        """
        Calls :meth:`logging.Logger.hasHandlers` with unmodified arguments.

        Exists only in Python 3.
        """
        return self._logger.hasHandlers()

    def callHandlers(self, record: logging.LogRecord) -> None:
        """
        Calls :meth:`logging.Logger.callHandlers` with unmodified arguments.
        """
        self._logger.callHandlers(record)

    def getEffectiveLevel(self) -> int:
        """
        Calls :meth:`logging.Logger.getEffectiveLevel` with unmodified
        arguments.
        """
        return self._logger.getEffectiveLevel()

    def isEnabledFor(self, level: int) -> bool:
        """
        Calls :meth:`logging.Logger.isEnabledFor` with unmodified arguments.
        """
        return self._logger.isEnabledFor(level)

    def is_enabled_for(self, level: int) -> bool:
        """
        A snake_case alias of `isEnabledFor` for compatibility with
        `structlog.typing.FilteringBoundLogger`.

        .. note::

           This method is more complex than the native `is_enabled_for` since
           it supports standard library-only features like
           :attr:`logging.Logger.disabled` while the native one only compares
           log levels.

        .. versionadded:: 26.1.0
        """
        return self._logger.isEnabledFor(level)

    def get_effective_level(self) -> int:
        """
        A snake_case alias of `getEffectiveLevel` for compatibility with
        `structlog.typing.FilteringBoundLogger`.

        .. versionadded:: 26.1.0
        """
        return self._logger.getEffectiveLevel()

    def getChild(self, suffix: str) -> logging.Logger:
        """
        Calls :meth:`logging.Logger.getChild` with unmodified arguments.
        """
        return self._logger.getChild(suffix)

    # Non-Standard Async
    async def _dispatch_to_sync(
        self,
        meth: Callable[..., Any],
        event: str,
        args: tuple[Any, ...],
        kw: dict[str, Any],
    ) -> None:
        """
        Merge contextvars and log using the sync logger in a thread pool.
        """
        # Capture thread-specific info before handing off to the executor.
        thread_token = _ASYNC_CALLING_THREAD.set(
            (threading.get_ident(), threading.current_thread().name)
        )
        scs_token = _ASYNC_CALLING_STACK.set(sys._getframe().f_back.f_back)  # type: ignore[union-attr, arg-type, unused-ignore]
        ctx = contextvars.copy_context()

        try:
            await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: ctx.run(lambda: meth(event, *args, **kw)),
            )
        finally:
            _ASYNC_CALLING_STACK.reset(scs_token)
            _ASYNC_CALLING_THREAD.reset(thread_token)

    async def adebug(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `debug()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(self.debug, event, args, kw)

    async def ainfo(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `info()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(self.info, event, args, kw)

    async def awarning(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `warning()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(self.warning, event, args, kw)

    async def aerror(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `error()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(self.error, event, args, kw)

    async def acritical(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `critical()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(self.critical, event, args, kw)

    async def afatal(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `critical()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(self.critical, event, args, kw)

    async def aexception(self, event: str, *args: Any, **kw: Any) -> None:
        """
        Log using `exception()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        # To make `log.exception("foo") work, we have to check if the user
        # passed an explicit exc_info and if not, supply our own.
        if kw.get("exc_info", True) is True and kw.get("exception") is None:
            kw["exc_info"] = sys.exc_info()

        await self._dispatch_to_sync(self.exception, event, args, kw)

    async def alog(
        self, level: Any, event: str, *args: Any, **kw: Any
    ) -> None:
        """
        Log using `log()`, but asynchronously in a separate thread.

        .. versionadded:: 23.1.0
        """
        await self._dispatch_to_sync(partial(self.log, level), event, args, kw)


def get_logger(*args: Any, **initial_values: Any) -> BoundLogger:
    """
    Only calls `structlog.get_logger`, but has the correct type hints.

    .. warning::

       Does **not** check whether -- or ensure that -- you've configured
       *structlog* for standard library :mod:`logging`!

       See :doc:`standard-library` for details.

    .. versionadded:: 20.2.0
    """
    return _config.get_logger(*args, **initial_values)


class AsyncBoundLogger:
    """
    Wraps a `BoundLogger` & exposes its logging methods as ``async`` versions.

    This approach has turned out to be a mistake and the class has been
    deprecated in 23.1.0. Use the regular `BoundLogger` with its a-prefixed
    methods instead.

    .. versionadded:: 20.2.0
    .. versionchanged:: 20.2.0 fix _dispatch_to_sync contextvars usage
    .. deprecated:: 23.1.0
       Use the regular `BoundLogger` with its a-prefixed methods instead.
    .. versionchanged:: 23.3.0
        Callsite parameters are now also collected for async log methods.
    """

    __slots__ = ("_loop", "sync_bl")

    #: The wrapped synchronous logger. It is useful to be able to log
    #: synchronously occasionally.
    sync_bl: BoundLogger

    _executor = None
    _bound_logger_factory = BoundLogger

    def __init__(
        self,
        logger: logging.Logger,
        processors: Iterable[Processor],
        context: Context,
        *,
        # Only as an optimization for binding!
        _sync_bl: Any = None,  # *vroom vroom* over purity.
        _loop: Any = None,
    ):
        if _sync_bl:
            self.sync_bl = _sync_bl
            self._loop = _loop

            return

        self.sync_bl = self._bound_logger_factory(
            logger=logger, processors=processors, context=context
        )
        self._loop = asyncio.get_running_loop()

    # Instances would've been correctly recognized as such, however the class
    # not and we need the class in `structlog.configure()`.
    @property
    def _context(self) -> Context:
        return self.sync_bl._context

    def bind(self, **new_values: Any) -> Self:
        return self.__class__(
            # logger, processors and context are within sync_bl. These
            # arguments are ignored if _sync_bl is passed. *vroom vroom* over
            # purity.
            logger=None,  # type: ignore[arg-type]
            processors=(),
            context={},
            _sync_bl=self.sync_bl.bind(**new_values),
            _loop=self._loop,
        )

    def new(self, **new_values: Any) -> Self:
        return self.__class__(
            # c.f. comment in bind
            logger=None,  # type: ignore[arg-type]
            processors=(),
            context={},
            _sync_bl=self.sync_bl.new(**new_values),
            _loop=self._loop,
        )

    def unbind(self, *keys: str) -> Self:
        return self.__class__(
            # c.f. comment in bind
            logger=None,  # type: ignore[arg-type]
            processors=(),
            context={},
            _sync_bl=self.sync_bl.unbind(*keys),
            _loop=self._loop,
        )

    def try_unbind(self, *keys: str) -> Self:
        return self.__class__(
            # c.f. comment in bind
            logger=None,  # type: ignore[arg-type]
            processors=(),
            context={},
            _sync_bl=self.sync_bl.try_unbind(*keys),
            _loop=self._loop,
        )

    async def _dispatch_to_sync(
        self,
        meth: Callable[..., Any],
        event: str,
        args: tuple[Any, ...],
        kw: dict[str, Any],
    ) -> None:
        """
        Merge contextvars and log using the sync logger in a thread pool.
        """
        # Capture thread-specific info before handing off to the executor.
        thread_token = _ASYNC_CALLING_THREAD.set(
            (threading.get_ident(), threading.current_thread().name)
        )
        scs_token = _ASYNC_CALLING_STACK.set(sys._getframe().f_back.f_back)  # type: ignore[union-attr, arg-type, unused-ignore]
        ctx = contextvars.copy_context()

        try:
            await asyncio.get_running_loop().run_in_executor(
                self._executor,
                lambda: ctx.run(lambda: meth(event, *args, **kw)),
            )
        finally:
            _ASYNC_CALLING_STACK.reset(scs_token)
            _ASYNC_CALLING_THREAD.reset(thread_token)

    async def debug(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.debug, event, args, kw)

    async def info(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.info, event, args, kw)

    async def warning(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.warning, event, args, kw)

    async def warn(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.warning, event, args, kw)

    async def error(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.error, event, args, kw)

    async def critical(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.critical, event, args, kw)

    async def fatal(self, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(self.sync_bl.critical, event, args, kw)

    async def exception(self, event: str, *args: Any, **kw: Any) -> None:
        # To make `log.exception("foo") work, we have to check if the user
        # passed an explicit exc_info and if not, supply our own.
        ei = kw.pop("exc_info", None)
        if ei is None and kw.get("exception") is None:
            ei = sys.exc_info()

        kw["exc_info"] = ei

        await self._dispatch_to_sync(self.sync_bl.exception, event, args, kw)

    async def log(self, level: Any, event: str, *args: Any, **kw: Any) -> None:
        await self._dispatch_to_sync(
            partial(self.sync_bl.log, level), event, args, kw
        )


class LoggerFactory:
    """
    Build a standard library logger when an *instance* is called.

    Sets a custom logger using :func:`logging.setLoggerClass` so variables in
    log format are expanded properly.

    >>> from structlog import configure
    >>> from structlog.stdlib import LoggerFactory
    >>> configure(logger_factory=LoggerFactory())

    Args:
        ignore_frame_names:
            When guessing the name of a logger, skip frames whose names *start*
            with one of these.  For example, in pyramid applications you'll
            want to set it to ``["venusian", "pyramid.config"]``. This argument
            is called *additional_ignores* in other APIs throughout
            *structlog*.
    """

    def __init__(self, ignore_frame_names: list[str] | None = None):
        self._ignore = ignore_frame_names
        logging.setLoggerClass(_FixedFindCallerLogger)

    def __call__(self, *args: Any) -> logging.Logger:
        """
        Deduce the caller's module name and create a stdlib logger.

        If an optional argument is passed, it will be used as the logger name
        instead of guesswork.  This optional argument would be passed from the
        :func:`structlog.get_logger` call.  For example
        ``structlog.get_logger("foo")`` would cause this method to be called
        with ``"foo"`` as its first positional argument.

        .. versionchanged:: 0.4.0
            Added support for optional positional arguments.  Using the first
            one for naming the constructed logger.
        """
        if args:
            return logging.getLogger(args[0])

        # We skip all frames that originate from within structlog or one of the
        # configured names.
        _, name = _find_first_app_frame_and_name(self._ignore)

        return logging.getLogger(name)


class PositionalArgumentsFormatter:
    """
    Apply stdlib-like string formatting to the ``event`` key.

    If the ``positional_args`` key in the event dict is set, it must
    contain a tuple that is used for formatting (using the ``%s`` string
    formatting operator) of the value from the ``event`` key.  This works
    in the same way as the stdlib handles arguments to the various log
    methods: if the tuple contains only a single `dict` argument it is
    used for keyword placeholders in the ``event`` string, otherwise it
    will be used for positional placeholders.

    ``positional_args`` is populated by `structlog.stdlib.BoundLogger` or
    can be set manually.

    The *remove_positional_args* flag can be set to `False` to keep the
    ``positional_args`` key in the event dict; by default it will be
    removed from the event dict after formatting a message.
    """

    remove_positional_args: bool

    def __init__(self, remove_positional_args: bool = True) -> None:
        self.remove_positional_args = remove_positional_args

    def __call__(
        self, _: WrappedLogger, __: str, event_dict: EventDict
    ) -> EventDict:
        args = event_dict.get("positional_args")

        # Mimic the formatting behaviour of the stdlib's logging module, which
        # accepts both positional arguments and a single dict argument. The
        # "single dict" check is the same one as the stdlib's logging module
        # performs in LogRecord.__init__().
        if args:
            if len(args) == 1 and isinstance(args[0], dict) and args[0]:
                args = args[0]

            event_dict["event"] %= args

        if self.remove_positional_args and args is not None:
            del event_dict["positional_args"]

        return event_dict


def filter_by_level(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """
    Check whether logging is configured to accept messages from this log level.

    Should be the first processor if stdlib's filtering by level is used so
    possibly expensive processors like exception formatters are avoided in the
    first place.

    >>> import logging
    >>> from structlog.stdlib import filter_by_level
    >>> logging.basicConfig(level=logging.WARN)
    >>> logger = logging.getLogger()
    >>> filter_by_level(logger, 'warn', {})
    {}
    >>> filter_by_level(logger, 'debug', {})
    Traceback (most recent call last):
    ...
    DropEvent
    """
    if (
        # We can't use logger.isEnabledFor() because it's always disabled when
        # a log entry is in flight on Python 3.14 and later,
        not logger.disabled
        and NAME_TO_LEVEL[method_name] >= logger.getEffectiveLevel()
    ):
        return event_dict

    raise DropEvent


def add_log_level_number(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """
    Add the log level number to the event dict.

    Log level numbers map to the log level names. The Python stdlib uses them
    for filtering logic. This adds the same numbers so users can leverage
    similar filtering. Compare::

       level in ("warning", "error", "critical")
       level_number >= 30

    The mapping of names to numbers is in
    ``structlog.stdlib._log_levels._NAME_TO_LEVEL``.

    .. versionadded:: 18.2.0
    """
    event_dict["level_number"] = NAME_TO_LEVEL[method_name]

    return event_dict


def add_logger_name(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """
    Add the logger name to the event dict.
    """
    record = event_dict.get("_record")
    if record is None:
        event_dict["logger"] = logger.name
    else:
        event_dict["logger"] = record.name
    return event_dict


_LOG_RECORD_KEYS = logging.LogRecord(
    "name", 0, "pathname", 0, "msg", (), None
).__dict__.keys()


class ExtraAdder:
    """
    Add extra attributes of `logging.LogRecord` objects to the event
    dictionary.

    This processor can be used for adding data passed in the ``extra``
    parameter of the `logging` module's log methods to the event dictionary.

    Args:
        allow:
            An optional collection of attributes that, if present in
            `logging.LogRecord` objects, will be copied to event dictionaries.

            If ``allow`` is None all attributes of `logging.LogRecord` objects
            that do not exist on a standard `logging.LogRecord` object will be
            copied to event dictionaries.

    .. versionadded:: 21.5.0
    """

    __slots__ = ("_copier",)

    def __init__(self, allow: Collection[str] | None = None) -> None:
        self._copier: Callable[[EventDict, logging.LogRecord], None]
        if allow is not None:
            # The contents of allow is copied to a new list so that changes to
            # the list passed into the constructor does not change the
            # behaviour of this processor.
            self._copier = functools.partial(self._copy_allowed, [*allow])
        else:
            self._copier = self._copy_all

    def __call__(
        self, logger: logging.Logger, name: str, event_dict: EventDict
    ) -> EventDict:
        record: logging.LogRecord | None = event_dict.get("_record")
        if record is not None:
            self._copier(event_dict, record)
        return event_dict

    @classmethod
    def _copy_all(
        cls, event_dict: EventDict, record: logging.LogRecord
    ) -> None:
        for key, value in record.__dict__.items():
            if key not in _LOG_RECORD_KEYS:
                event_dict[key] = value

    @classmethod
    def _copy_allowed(
        cls,
        allow: Collection[str],
        event_dict: EventDict,
        record: logging.LogRecord,
    ) -> None:
        for key in allow:
            if key in record.__dict__:
                event_dict[key] = record.__dict__[key]


LOG_KWARG_NAMES = ("exc_info", "stack_info", "stacklevel")


def render_to_log_args_and_kwargs(
    _: logging.Logger, __: str, event_dict: EventDict
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """
    Render ``event_dict`` into positional and keyword arguments for
    `logging.Logger` logging methods.
    See `logging.Logger.debug` method for keyword arguments reference.

    The ``event`` field is passed in the first positional argument, positional
    arguments from ``positional_args`` field are passed in subsequent positional
    arguments, keyword arguments are extracted from the *event_dict* and the
    rest of the *event_dict* is added as ``extra``.

    This allows you to defer formatting to `logging`.

    .. versionadded:: 25.1.0
    """
    args = (event_dict.pop("event"), *event_dict.pop("positional_args", ()))

    kwargs = {
        kwarg_name: event_dict.pop(kwarg_name)
        for kwarg_name in LOG_KWARG_NAMES
        if kwarg_name in event_dict
    }
    if event_dict:
        kwargs["extra"] = event_dict

    return args, kwargs


def render_to_log_kwargs(
    _: logging.Logger, __: str, event_dict: EventDict
) -> EventDict:
    """
    Render ``event_dict`` into keyword arguments for `logging.Logger` logging
    methods.
    See `logging.Logger.debug` method for keyword arguments reference.

    The ``event`` field is translated into ``msg``, keyword arguments are
    extracted from the *event_dict* and the rest of the *event_dict* is added as
    ``extra``.

    This allows you to defer formatting to `logging`.

    .. versionadded:: 17.1.0
    .. versionchanged:: 22.1.0
       ``exc_info``, ``stack_info``, and ``stacklevel`` are passed as proper
       kwargs and not put into ``extra``.
    .. versionchanged:: 24.2.0
       ``stackLevel`` corrected to ``stacklevel``.
    """
    return {
        "msg": event_dict.pop("event"),
        "extra": event_dict,
        **{
            kw: event_dict.pop(kw)
            for kw in LOG_KWARG_NAMES
            if kw in event_dict
        },
    }


class ProcessorFormatter(logging.Formatter):
    r"""
    Call *structlog* processors on `logging.LogRecord`\s.

    This is an implementation of a `logging.Formatter` that can be used to
    format log entries from both *structlog* and `logging`.

    Its static method `wrap_for_formatter` must be the final processor in
    *structlog*'s processor chain.

    Please refer to :ref:`processor-formatter` for examples.

    Args:
        foreign_pre_chain:
            If not `None`, it is used as a processor chain that is applied to
            **non**-*structlog* log entries before the event dictionary is
            passed to *processors*. (default: `None`)

        processors:
            A chain of *structlog* processors that is used to process **all**
            log entries. The last one must render to a `str` which then gets
            passed on to `logging` for output.

            Compared to *structlog*'s regular processor chains, there's a few
            differences:

            - The event dictionary contains two additional keys:

              #. ``_record``: a `logging.LogRecord` that either was created
                  using `logging` APIs, **or** is a wrapped *structlog* log
                  entry created by `wrap_for_formatter`.

              #. ``_from_structlog``: a `bool` that indicates whether or not
                 ``_record`` was created by a *structlog* logger.

              Since you most likely don't want ``_record`` and
              ``_from_structlog`` in your log files,  we've added the static
              method `remove_processors_meta` to ``ProcessorFormatter`` that
              you can add just before your renderer.

            - Since this is a `logging` *formatter*, raising
              `structlog.DropEvent` will crash your application.

        keep_exc_info:
            ``exc_info`` on `logging.LogRecord`\ s is added to the
            ``event_dict`` and removed afterwards. Set this to ``True`` to keep
            it on the `logging.LogRecord`. (default: False)

        keep_stack_info:
            Same as *keep_exc_info* except for ``stack_info``. (default: False)

        logger:
            Logger which we want to push through the *structlog* processor
            chain. This parameter is necessary for some of the processors like
            `filter_by_level`. (default: None)

        pass_foreign_args:
            If True, pass a foreign log record's ``args`` attribute to the
            ``event_dict`` under ``positional_args`` key. (default: False)

        processor:
            A single *structlog* processor used for rendering the event
            dictionary before passing it off to `logging`. Must return a `str`.
            The event dictionary does **not** contain ``_record`` and
            ``_from_structlog``.

            This parameter exists for historic reasons. Please use *processors*
            instead.

        use_get_message:
            If True, use ``record.getMessage`` to get a fully rendered log
            message, otherwise use ``str(record.msg)``. (default: True)

    Raises:
        TypeError: If both or neither *processor* and *processors* are passed.

    .. versionadded:: 17.1.0
    .. versionadded:: 17.2.0 *keep_exc_info* and *keep_stack_info*
    .. versionadded:: 19.2.0 *logger*
    .. versionadded:: 19.2.0 *pass_foreign_args*
    .. versionadded:: 21.3.0 *processors*
    .. deprecated:: 21.3.0
       *processor* (singular) in favor of *processors* (plural). Removal is not
       planned.
    .. versionadded:: 23.3.0 *use_get_message*
    """

    processors: Sequence[Processor]
    foreign_pre_chain: Sequence[Processor] | None
    keep_exc_info: bool
    keep_stack_info: bool
    logger: logging.Logger | None
    pass_foreign_args: bool
    use_get_message: bool

    def __init__(
        self,
        processor: Processor | None = None,
        processors: Sequence[Processor] | None = (),
        foreign_pre_chain: Sequence[Processor] | None = None,
        keep_exc_info: bool = False,
        keep_stack_info: bool = False,
        logger: logging.Logger | None = None,
        pass_foreign_args: bool = False,
        use_get_message: bool = True,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        fmt = kwargs.pop("fmt", "%(message)s")
        super().__init__(*args, fmt=fmt, **kwargs)  # type: ignore[misc]

        if processor and processors:
            msg = (
                "The `processor` and `processors` arguments are mutually"
                " exclusive."
            )
            raise TypeError(msg)

        if processor is not None:
            self.processors = (self.remove_processors_meta, processor)
        elif processors:
            self.processors = processors
        else:
            msg = "Either `processor` or `processors` must be passed."
            raise TypeError(msg)

        self.foreign_pre_chain = foreign_pre_chain
        self.keep_exc_info = keep_exc_info
        self.keep_stack_info = keep_stack_info
        self.logger = logger
        self.pass_foreign_args = pass_foreign_args
        self.use_get_message = use_get_message

    def format(self, record: logging.LogRecord) -> str:
        """
        Extract *structlog*'s `event_dict` from ``record.msg`` and format it.

        *record* has been patched by `wrap_for_formatter` first though, so the
         type isn't quite right.
        """
        # Make a shallow copy of the record to let other handlers/formatters
        # process the original one
        record = logging.makeLogRecord(record.__dict__)

        logger = getattr(record, "_logger", _SENTINEL)
        meth_name = getattr(record, "_name", "__structlog_sentinel__")

        ed: ProcessorReturnValue
        if logger is not _SENTINEL and meth_name != "__structlog_sentinel__":
            # Both attached by wrap_for_formatter
            if self.logger is not None:
                logger = self.logger
            meth_name = cast(str, record._name)  # type:ignore[attr-defined]

            # We need to copy because it's possible that the same record gets
            # processed by multiple logging formatters. LogRecord.getMessage
            # would transform our dict into a str.
            ed = cast(dict[str, Any], record.msg).copy()
            ed["_record"] = record
            ed["_from_structlog"] = True
        else:
            logger = self.logger
            meth_name = record.levelname.lower()
            ed = {
                "event": (
                    record.getMessage()
                    if self.use_get_message
                    else str(record.msg)
                ),
                "_record": record,
                "_from_structlog": False,
            }

            if self.pass_foreign_args:
                ed["positional_args"] = record.args

            record.args = ()

            # Add stack-related attributes to the event dict
            if record.exc_info:
                ed["exc_info"] = record.exc_info
            if record.stack_info:
                ed["stack_info"] = record.stack_info

            # Non-structlog allows to run through a chain to prepare it for the
            # final processor (e.g. adding timestamps and log levels).
            for proc in self.foreign_pre_chain or ():
                ed = cast(EventDict, proc(logger, meth_name, ed))

        # If required, unset stack-related attributes on the record copy so
        # that the base implementation doesn't append stacktraces to the
        # output.
        if not self.keep_exc_info:
            record.exc_text = None
            record.exc_info = None
        if not self.keep_stack_info:
            record.stack_info = None

        for p in self.processors:
            ed = p(logger, meth_name, ed)  # type: ignore[arg-type]

        if not isinstance(ed, str):
            warnings.warn(
                "The last processor in ProcessorFormatter.processors must "
                f"return a string, but {self.processors[-1]} returned a "
                f"{type(ed)} instead.",
                category=RuntimeWarning,
                stacklevel=1,
            )
            ed = cast(str, ed)

        record.msg = ed

        return super().format(record)

    @staticmethod
    def wrap_for_formatter(
        logger: logging.Logger, name: str, event_dict: EventDict
    ) -> tuple[tuple[EventDict], dict[str, dict[str, Any]]]:
        """
        Wrap *logger*, *name*, and *event_dict*.

        The result is later unpacked by `ProcessorFormatter` when formatting
        log entries.

        Use this static method as the renderer (in other words, final
        processor) if you want to use `ProcessorFormatter` in your `logging`
        configuration.
        """
        return (event_dict,), {"extra": {"_logger": logger, "_name": name}}

    @staticmethod
    def wrap_for_queue(
        logger: logging.Logger, name: str, event_dict: EventDict
    ) -> tuple[tuple[EventDict], dict[str, dict[str, Any]]]:
        """
        Wrap *logger*, *name*, and *event_dict* for the queue handoff.

        Alias for `QueueHandler.wrap_for_queue`.

        .. versionadded:: 26.2.0
        """
        return QueueHandler.wrap_for_queue(logger, name, event_dict)

    @staticmethod
    def remove_processors_meta(
        _: WrappedLogger, __: str, event_dict: EventDict
    ) -> EventDict:
        """
        Remove ``_record`` and ``_from_structlog`` from *event_dict*.

        These keys are added to the event dictionary, before
        `ProcessorFormatter`'s *processors* are run.

        .. versionadded:: 21.3.0
        """
        del event_dict["_record"]
        del event_dict["_from_structlog"]

        return event_dict


QUEUE_ENVELOPE_KEY = "_queue"
"""
Key under which `QueueHandler` stores its stable metadata.

The event dictionary itself is kept flat and unchanged -- apart from the
allowed-values filtering -- so that approved structured data survives the
process boundary without being turned into a string.
"""

QUEUE_ENVELOPE_VERSION = 1
"""
Version of the queue envelope written by `QueueHandler`.
"""

QUEUE_UNAPPROVED_KEY = "__structlog_unapproved__"
"""
Key of the placeholder for values that were not approved for the queue.
"""

_CORRELATION_ID_KEY = "correlation_id"
_DEFAULT_CORRELATION_ID_KEYS = ("correlation_id", "request_id", "trace_id")
_QUEUE_UNAPPROVED = {
    "kind": "unapproved",
}
_MISSING = object()

_SAFE_SCALAR_TYPES = (str, int, float, bool, type(None))
_SAFE_CONTAINER_TYPES = (dict, list, tuple)


def _type_name(value: Any) -> str:
    """
    Return a stable name for *value*'s type without invoking user code.
    """
    tp = type(value)
    try:
        name = type.__getattribute__(tp, "__name__")
    except Exception:  # noqa: BLE001
        name = "object"

    return name if isinstance(name, str) else "object"


def _unapproved(value: Any) -> dict[str, Any]:
    """
    Return a JSON-safe, stable placeholder for an unapproved value.

    Notably, neither ``str()`` nor ``repr()`` is called on *value*.
    """
    return {QUEUE_UNAPPROVED_KEY: _type_name(value)}


def _safe_str(value: str) -> str:
    """
    Return a plain ``str`` from *value* without calling an overridden
    ``__str__``.
    """
    return str.__getitem__(value, slice(None))


def _safe_int(value: int) -> int:
    return int.__int__(value)


def _safe_float(value: float) -> float:
    return float.__float__(value)


def _safe_bool(value: bool) -> bool:
    return bool.__bool__(value)


def _safe_items(value: dict[Any, Any]) -> Iterable[tuple[Any, Any]]:
    return dict.items(value)


def _safe_mapping_key(key: Any) -> str | None:
    """
    Return a string key for *key*, if it's an approved primitive.
    """
    if isinstance(key, str):
        return _safe_str(key)
    if isinstance(key, bool):
        return "true" if _safe_bool(key) else "false"
    if isinstance(key, int):
        return str(_safe_int(key))
    if isinstance(key, float):
        return str(_safe_float(key))
    if key is None:
        return "null"

    return None


def _safe_iter(value: list[Any] | tuple[Any, ...]) -> Iterable[Any]:
    if isinstance(value, list):
        return list.__iter__(value)

    return tuple.__iter__(value)


def sanitize_for_queue(
    value: Any,
    *,
    allow: Mapping[type, Callable[[Any], Any]] | None = None,
    max_depth: int = 16,
    max_items: int = 1000,
    max_string: int | None = 65536,
) -> Any:
    """
    Return a queue-safe copy of *value*.

    Only approved, structured values cross the queue:

    - ``None``, `bool`, `int`, `float`, and `str` are passed as plain
      built-in types.
    - ``bytes`` are decoded using ``utf-8`` with the ``replace`` error
      handler.
    - `dict` and `list` / `tuple` are copied recursively. Unapproved keys are
      dropped; values that aren't recursively approved are replaced with a
      stable placeholder.
    - Everything else is replaced with a placeholder that only contains the
      type name.

    The placeholder is a plain dictionary like
    ``{"__structlog_unapproved__": "Type"}``. No ``str()`` or ``repr()`` is
    ever called on an unapproved value, so custom formatting hooks can't run
    accidentally -- not even while handling queue errors.

    Args:
        value:
            The value to sanitize.

        allow:
            An optional mapping of types to converters for otherwise
            unapproved values. The converter receives the value and must
            return JSON-safe data. This is the explicit approval mechanism.

        max_depth:
            Maximum nesting depth. Deeper values are replaced with a
            truncation placeholder.

        max_items:
            Maximum number of items copied from a container. Surplus items are
            dropped and a truncation placeholder is appended.

        max_string:
            Maximum length of strings. Longer strings are truncated. `None`
            disables truncation.

    Returns:
        A plain, JSON-safe copy of *value*.

    .. versionadded:: 26.2.0
    """
    if max_depth < 1:
        msg = "'max_depth' must be at least 1"
        raise ValueError(msg)
    if max_items < 1:
        msg = "'max_items' must be at least 1"
        raise ValueError(msg)

    allowed = allow or {}
    seen: set[int] = set()

    def _sanitize(value: Any, depth: int) -> Any:
        # Exact types first; their base methods don't run user code.
        if value is None:
            return None
        if isinstance(value, bool):
            return _safe_bool(value)
        if isinstance(value, int):
            return _safe_int(value)
        if isinstance(value, float):
            return _safe_float(value)
        if isinstance(value, str):
            plain_str = _safe_str(value)
            if max_string is not None and len(plain_str) > max_string:
                return plain_str[:max_string]

            return plain_str
        if isinstance(value, bytes):
            return bytes.decode(value, "utf-8", "replace")

        converter = allowed.get(type(value))
        if converter is not None:
            try:
                return _sanitize(converter(value), depth)
            except Exception:  # noqa: BLE001
                return _unapproved(value)

        if depth >= max_depth:
            return {"__structlog_truncated__": "max-depth"}

        if isinstance(value, dict):
            identity = id(value)
            if identity in seen:
                return {"__structlog_truncated__": "cycle"}
            seen.add(identity)
            rv: dict[str, Any] = {}
            try:
                for index, (key, item) in enumerate(_safe_items(value)):
                    if index >= max_items:
                        rv["__structlog_truncated__"] = "max-items"
                        break
                    safe_key = _safe_mapping_key(key)
                    if safe_key is None:
                        continue
                    rv[safe_key] = _sanitize(item, depth + 1)
            finally:
                seen.discard(identity)

            return rv

        if isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in seen:
                return {"__structlog_truncated__": "cycle"}
            seen.add(identity)
            rv_list: list[Any] = []
            try:
                for index, item in enumerate(_safe_iter(value)):
                    if index >= max_items:
                        rv_list.append(
                            {"__structlog_truncated__": "max-items"}
                        )
                        break
                    rv_list.append(_sanitize(item, depth + 1))
            finally:
                seen.discard(identity)

            return rv_list

        return _unapproved(value)

    return _sanitize(value, 0)


def _exception_type_name(exc_type: type[BaseException]) -> str:
    try:
        name = type.__getattribute__(exc_type, "__name__")
    except Exception:  # noqa: BLE001
        name = "BaseException"

    return name if isinstance(name, str) else "BaseException"


def _safe_exception_args(exc: BaseException) -> tuple[Any, ...]:
    """
    Return exception args without triggering a custom ``args`` property.
    """
    try:
        descriptor = vars(BaseException)["args"]
        args = descriptor.__get__(exc, type(exc))
    except Exception:  # noqa: BLE001
        return ()

    return tuple(args) if isinstance(args, tuple) else ()


def _safe_exception_message(args: tuple[Any, ...]) -> Any:
    """
    Return a useful message only if it can be produced from approved values.

    ``BaseException.__str__`` formats the arguments with ``str()`` -- but the
    arguments are already approved at this point, so it's safe to use them
    directly.
    """
    if not args:
        return ""

    first = args[0]
    if type(first) in (str, int, float, bool):
        return _safe_str(first) if isinstance(first, str) else first

    if len(args) == 1:
        return _unapproved(first)

    return _unapproved(args)


def _safe_frames(exc: BaseException, max_frames: int) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    tb: Any
    try:
        descriptor = vars(BaseException)["__traceback__"]
        tb = descriptor.__get__(exc, type(exc))
    except Exception:  # noqa: BLE001
        tb = None
    while tb is not None and len(frames) < max_frames:
        frame = tb.tb_frame
        code = frame.f_code
        frames.append(
            {
                "filename": _safe_str(code.co_filename),
                "lineno": _safe_int(tb.tb_lineno),
                "name": _safe_str(code.co_name),
            }
        )
        tb = tb.tb_next

    return frames


def _exception_descriptor(
    exc: BaseException, name: str, *, default: Any = None
) -> Any:
    """
    Read an exception attribute using the base descriptor, if possible.

    This avoids custom ``__getattr__`` implementations on exceptions.
    """
    descriptor = vars(BaseException).get(name)
    if descriptor is None:
        return default

    try:
        return descriptor.__get__(exc, type(exc))
    except Exception:  # noqa: BLE001
        return default


def _exception_group_children(
    exc: BaseException,
) -> Iterable[BaseException] | None:
    """
    Return an exception group's direct children without custom iteration.
    """
    try:
        from builtins import BaseExceptionGroup  # noqa: PLC0415
    except ImportError:  # pragma: no cover
        return None

    if not isinstance(exc, BaseExceptionGroup):
        return None

    descriptor = vars(BaseExceptionGroup)["exceptions"]
    try:
        children = descriptor.__get__(exc, type(exc))
    except Exception:  # noqa: BLE001
        return None

    return children if isinstance(children, (list, tuple)) else None


def _exception_to_queue(
    exc_type: type[BaseException],
    exc: BaseException,
    *,
    max_frames: int,
    seen: set[int],
) -> dict[str, Any]:
    rv: dict[str, Any] = {
        "exc_type": _exception_type_name(exc_type),
        "frames": _safe_frames(exc, max_frames),
    }
    args = _safe_exception_args(exc)
    if args:
        rv["exc_args"] = sanitize_for_queue(list(args))
    rv["exc_value"] = _safe_exception_message(args)

    group = _exception_group_children(exc)
    if group is not None and id(exc) not in seen:
        seen.add(id(exc))
        branches = []
        for child in group:
            if not isinstance(child, BaseException):
                continue
            branch = _exception_to_queue(
                type(child),
                child,
                max_frames=max_frames,
                seen=seen,
            )
            branch.setdefault("is_cause", False)
            branches.append(branch)
        rv["exceptions"] = branches

    return rv


def exception_to_queue(
    exc_info: ExcInfo, *, max_frames: int = 32
) -> list[dict[str, Any]]:
    """
    Convert an exception to a structured, queue-safe representation.

    Unlike `structlog.tracebacks.ExceptionDictTransformer`, this function never
    calls ``str()`` or ``repr()`` on exception arguments or local variables.
    Exception arguments that aren't approved primitives are represented by the
    same stable placeholder that `sanitize_for_queue` uses.

    Args:
        exc_info:
            A tuple as returned by `sys.exc_info`.

        max_frames:
            Maximum number of frames per exception.

    Returns:
        A list of exception dictionaries, including chained exceptions and
        exception groups.

    .. versionadded:: 26.2.0
    """
    exc_type, exc, _ = exc_info
    if exc is None:
        return []

    result: list[dict[str, Any]] = []
    group_seen: set[int] = set()
    chain_seen: set[int] = set()
    current_type: type[BaseException] = exc_type or type(exc)
    current: BaseException | None = exc
    is_cause = False
    while current is not None and id(current) not in chain_seen:
        chain_seen.add(id(current))
        entry = _exception_to_queue(
            current_type, current, max_frames=max_frames, seen=group_seen
        )
        entry["is_cause"] = is_cause
        result.append(entry)

        cause = _exception_descriptor(current, "__cause__")
        if cause is not None:
            current, current_type, is_cause = cause, type(cause), True
            continue

        context = _exception_descriptor(current, "__context__")
        suppressed = _exception_descriptor(
            current, "__suppress_context__", default=False
        )
        if context is not None and not suppressed:
            current, current_type = context, type(context)
            continue

        break

    # Like `traceback`, report the outermost exception first; following
    # ``__cause__`` / ``__context__`` already walks from the outside in.
    return result


class QueueHandler(logging.handlers.QueueHandler):
    """
    A `logging.handlers.QueueHandler` that enqueues plain, restricted
    dictionaries instead of `logging.LogRecord` objects.

    This is the producer side of the optional queue handoff for *structlog*'s
    standard library integration. Use it together with `QueueListener` and --
    ideally -- `ProcessorFormatter`.

    The regular queue handler runs `LogRecord.getMessage()` before pickling,
    which turns dictionaries and custom objects into strings. Depending on the
    path that either loses the structured data or invokes a user-defined
    ``__str__`` on untrusted objects. This handler instead:

    - keeps the event as a flat dictionary,
    - copies only approved values and replaces the rest with a stable
      placeholder that contains just the type name,
    - embeds a fixed `QUEUE_ENVELOPE_KEY` metadata dictionary with the
      envelope version, level, logger name, and correlation ID,
    - stores exceptions in a structured form that never stringifies
      unapproved arguments, and
    - overrides `handleError` so even error reporting doesn't inspect or
      stringify the record's message and arguments.

    The queue therefore always sees JSON-safe dictionaries, regardless of
    whether a plain dictionary, an event with unapproved values, or an
    exception record was logged.

    Args:
        queue:
            The queue to enqueue into. Standard `queue.Queue` and
            `multiprocessing.Queue` instances work.

        processors:
            Optional *structlog* processors to run against the event
            dictionary before it's sanitized. They must return a dictionary
            or a string/bytes event. Exceptions raised by them are handed to
            `handleError`.

        correlation_id_key:
            The event / record attribute that carries the correlation ID. For
            convenience, ``request_id`` and ``trace_id`` are used as fallbacks
            when ``correlation_id`` is absent.

        allow:
            An optional mapping of types to converters that are explicitly
            approved for the queue. See `sanitize_for_queue`.

        max_depth, max_items, max_string:
            Limits used by `sanitize_for_queue`.

        serializer:
            An optional callable that receives the sanitized envelope and
            returns the final queue item. By default, the plain dictionary is
            enqueued. Since it only ever sees sanitized data, it can't invoke
            user-defined formatting hooks.

    .. versionadded:: 26.2.0
    """

    queue: Any

    def __init__(
        self,
        queue: Any,
        *,
        processors: Sequence[Processor] = (),
        correlation_id_key: str = _CORRELATION_ID_KEY,
        allow: Mapping[type, Callable[[Any], Any]] | None = None,
        max_depth: int = 16,
        max_items: int = 1000,
        max_string: int | None = 65536,
        serializer: Callable[[dict[str, Any]], Any] | None = None,
        max_frames: int = 32,
    ) -> None:
        super().__init__(queue)
        self.processors = tuple(processors)
        self.correlation_id_key = correlation_id_key
        self.correlation_id_keys = _DEFAULT_CORRELATION_ID_KEYS
        self.allow = allow
        self.max_depth = max_depth
        self.max_items = max_items
        self.max_string = max_string
        self.serializer = serializer
        self.max_frames = max_frames

    @staticmethod
    def wrap_for_queue(
        logger: logging.Logger, name: str, event_dict: EventDict
    ) -> tuple[tuple[EventDict], dict[str, dict[str, Any]]]:
        """
        Wrap *logger*, *name*, and *event_dict* for `QueueHandler`.

        This is equivalent to `ProcessorFormatter.wrap_for_formatter` and is
        provided as a discoverable final processor for queue setups.

        .. versionadded:: 26.2.0
        """
        return (event_dict,), {"extra": {"_logger": logger, "_name": name}}

    def _event_dict(self, record: logging.LogRecord) -> dict[str, Any]:
        msg = record.msg
        event_dict = dict.copy(msg) if isinstance(msg, dict) else {}

        # `structlog.stdlib.BoundLogger` passes positional arguments in
        # `extra.positional_args` when used with `wrap_for_queue`.
        if isinstance(event_dict.get("positional_args"), tuple):
            event_dict["positional_args"] = list(
                event_dict["positional_args"]
            )

        # Preserve approved structured data that was passed through `extra`.
        for key, value in record.__dict__.items():
            if key in _LOG_RECORD_KEYS or key in (
                "_logger",
                "_name",
                "_record",
                "_from_structlog",
                "_queue_envelope",
            ):
                continue
            if key == "exc_info":
                # Rendered below from `record.exc_info`, never copied raw.
                continue
            event_dict.setdefault(key, value)

        if isinstance(msg, dict):
            method_name = getattr(record, "_name", record.levelname.lower())
            logger = getattr(record, "_logger", None)
            if logger is None:
                logger = logging.getLogger(record.name)
            for proc in self.processors:
                processed = proc(logger, method_name, event_dict)
                if isinstance(processed, Mapping):
                    event_dict = dict(processed)
                elif isinstance(processed, tuple) and len(processed) == 2:
                    # `wrap_for_formatter` / `wrap_for_queue` style result.
                    args, kwargs = processed
                    if args and isinstance(args[0], Mapping):
                        event_dict = dict(args[0])
                    else:
                        event_dict = {}
                    extra = kwargs.get("extra")
                    if isinstance(extra, Mapping):
                        for key, value in extra.items():
                            if isinstance(key, str) and key not in (
                                "_logger",
                                "_name",
                            ):
                                event_dict.setdefault(key, value)
                elif isinstance(processed, (str, bytes, bytearray)):
                    event_dict = {"event": processed}
                else:
                    event_dict = {"event": _unapproved(processed)}
        elif "event" not in event_dict:
            event_dict["event"] = self._format_plain_message(record)

        return event_dict

    def _format_plain_message(self, record: logging.LogRecord) -> Any:
        msg = record.msg
        args = record.args
        if not args:
            return msg

        safe_args = _safe_positional_args(args)
        if safe_args is _MISSING:
            return msg

        try:
            return msg % safe_args
        except Exception:  # noqa: BLE001
            return msg

    def _find_correlation_id(
        self, record: logging.LogRecord, event_dict: Mapping[str, Any]
    ) -> Any:
        keys = (self.correlation_id_key, *self.correlation_id_keys)
        for key in keys:
            if key in event_dict:
                return event_dict[key]
            if key in record.__dict__:
                return record.__dict__[key]

        return _MISSING

    def prepare(self, record: logging.LogRecord) -> dict[str, Any]:
        """
        Build the restricted dictionary that is actually enqueued.
        """
        try:
            event_dict = self._event_dict(record)
        except Exception:  # noqa: BLE001
            event_dict = {"event": _unapproved(record.msg)}

        envelope = sanitize_for_queue(
            event_dict,
            allow=self.allow,
            max_depth=self.max_depth,
            max_items=self.max_items,
            max_string=self.max_string,
        )
        if not isinstance(envelope, dict):
            envelope = {"event": envelope}

        correlation_id = self._find_correlation_id(record, event_dict)
        if correlation_id is _MISSING:
            safe_correlation_id = None
        else:
            safe_correlation_id = sanitize_for_queue(
                correlation_id,
                allow=self.allow,
                max_depth=1,
                max_items=self.max_items,
                max_string=self.max_string,
            )
        if not isinstance(
            safe_correlation_id, (str, int, float, bool, type(None))
        ):
            # Keep grouping predictable even if the correlation ID itself
            # wasn't approved.
            safe_correlation_id = None

        envelope.setdefault(self.correlation_id_key, safe_correlation_id)

        exception: list[dict[str, Any]] | None = None
        if record.exc_info:
            try:
                exc_info = cast(ExcInfo, record.exc_info)
                exception = exception_to_queue(
                    exc_info, max_frames=self.max_frames
                )
            except Exception:  # noqa: BLE001
                exc_type, exc_value, _ = cast(ExcInfo, record.exc_info)
                exception = [
                    {
                        "exc_type": _exception_type_name(
                            exc_type or BaseException
                        ),
                        "exc_value": _unapproved(exc_value),
                        "frames": [],
                        "is_cause": False,
                    }
                ]

        if exception is not None:
            envelope.pop("exc_info", None)
            envelope.pop("stack_info", None)
            envelope["exception"] = exception

        envelope[QUEUE_ENVELOPE_KEY] = {
            "version": QUEUE_ENVELOPE_VERSION,
            "level": _safe_str(record.levelname).lower(),
            "logger": _safe_str(record.name),
            "correlation_id": safe_correlation_id,
            "is_structlog": isinstance(record.msg, dict),
        }

        return envelope

    def enqueue(self, record: Any) -> None:
        if self.serializer is not None:
            record = self.serializer(record)

        self.queue.put_nowait(record)

    def handleError(self, record: logging.LogRecord) -> None:
        """
        Report an error without touching the record's message or arguments.

        The default implementation formats and prints ``record.msg`` and
        ``record.args``. That would be a second, unguarded path for
        unapproved objects to be turned into strings. This override only
        prints the exception and the callsite -- never the event data.

        .. versionadded:: 26.2.0
        """
        if not logging.raiseExceptions or sys.stderr is None:
            return

        exc_type, exc_value, exc_tb = sys.exc_info()
        try:
            sys.stderr.write("--- Logging error ---\n")
            if exc_type is not None:
                traceback.print_exception(
                    exc_type, exc_value, exc_tb, None, sys.stderr
                )
            sys.stderr.write(
                f"Logged from file {record.filename}, line {record.lineno}\n"
            )
        except OSError:  # pragma: no cover
            pass


def _safe_positional_args(args: Any) -> Any:
    """
    Return positional arguments if formatting them can't run user code.
    """
    if isinstance(args, tuple):
        if all(type(arg) in _SAFE_SCALAR_TYPES for arg in args):
            return tuple(
                sanitize_for_queue(arg) for arg in tuple.__iter__(args)
            )
        return _MISSING

    if isinstance(args, dict):
        if all(
            type(key) in (str, int, float, bool, type(None))
            and type(value) in _SAFE_SCALAR_TYPES
            for key, value in dict.items(args)
        ):
            return {
                sanitize_for_queue(key): sanitize_for_queue(value)
                for key, value in dict.items(args)
            }
        return _MISSING

    return _MISSING


class QueueListener(logging.handlers.QueueListener):
    """
    Consumer side of the queue handoff for *structlog*'s standard library
    integration.

    It accepts the dictionaries produced by `QueueHandler` and reconstructs
    `logging.LogRecord` objects that `ProcessorFormatter` recognizes as
    *structlog* entries. The original envelope is available as
    ``record._queue_envelope`` and the correlation ID as
    ``record.correlation_id``.

    `logging.LogRecord` instances (for example from other handlers that use
    the regular queue handler) are passed through unchanged.

    Args:
        queue:
            The queue to read from.

        *handlers:
            Handlers that process the reconstructed records.

        respect_handler_level:
            Passed to `logging.handlers.QueueListener`.

        correlation_id_key:
            Key of the correlation ID in the envelope's metadata.

    .. versionadded:: 26.2.0
    """

    def __init__(
        self,
        queue: Any,
        *handlers: logging.Handler,
        respect_handler_level: bool = False,
        correlation_id_key: str = _CORRELATION_ID_KEY,
    ) -> None:
        super().__init__(
            queue,
            *handlers,
            respect_handler_level=respect_handler_level,
        )
        self.correlation_id_key = correlation_id_key

    def prepare(self, record: Any) -> Any:
        if not isinstance(record, dict):
            return super().prepare(record)

        metadata = record.get(QUEUE_ENVELOPE_KEY)
        if not isinstance(metadata, dict):
            metadata = {}

        level_name = metadata.get("level")
        level = NAME_TO_LEVEL.get(level_name, logging.INFO) if isinstance(
            level_name, str
        ) else logging.INFO
        logger_name = metadata.get("logger")
        if not isinstance(logger_name, str):
            logger_name = "structlog.queue"

        event = {
            key: value
            for key, value in record.items()
            if key != QUEUE_ENVELOPE_KEY
        }
        log_record = logging.LogRecord(
            logger_name,
            level,
            "<queue>",
            0,
            event,
            (),
            None,
        )
        log_record._queue_envelope = record
        log_record.correlation_id = metadata.get(self.correlation_id_key)
        log_record._logger = logging.getLogger(logger_name)
        fallback_method = level_name if isinstance(level_name, str) else "info"
        log_record._name = metadata.get("method_name", fallback_method)

        return super().prepare(log_record)


class QueueFormatter(ProcessorFormatter):
    """
    `ProcessorFormatter` that also accepts `QueueListener` records.

    Since `QueueListener` prepares records the same way
    `ProcessorFormatter.wrap_for_formatter` does, the regular
    `ProcessorFormatter` works too. This subclass exists as a discoverable,
    queue-specific name and adds the correlation ID to the event dictionary
    when a processor didn't already do so.

    Args:
        correlation_id_key:
            Key of the correlation ID in the event dictionary.

        *args, **kwargs:
            Passed to `ProcessorFormatter`.

    .. versionadded:: 26.2.0
    """

    def __init__(
        self,
        *args: Any,
        correlation_id_key: str = _CORRELATION_ID_KEY,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.correlation_id_key = correlation_id_key

    def format(self, record: logging.LogRecord) -> str:
        correlation_id = getattr(record, "correlation_id", None)
        if (
            correlation_id is not None
            and isinstance(record.msg, dict)
            and self.correlation_id_key not in record.msg
        ):
            record = logging.makeLogRecord(record.__dict__)
            msg = record.msg
            if isinstance(msg, dict):
                msg = dict.copy(msg)
                msg[self.correlation_id_key] = correlation_id
                record.msg = msg

        return super().format(record)


def group_by_correlation_id(
    events: Iterable[Mapping[str, Any]],
    *,
    correlation_id_key: str = _CORRELATION_ID_KEY,
    include_missing: bool = False,
) -> dict[Any, list[Mapping[str, Any]]]:
    """
    Group queue envelopes by their correlation ID.

    Args:
        events:
            The envelopes read from the queue.

        correlation_id_key:
            Top-level key of the correlation ID, with a fallback to the
            `QUEUE_ENVELOPE_KEY` metadata.

        include_missing:
            If `True`, events without a correlation ID are grouped under
            `None`.

    Returns:
        A dictionary mapping correlation IDs to the envelopes that belong to
        them.

    .. versionadded:: 26.2.0
    """
    groups: dict[Any, list[Mapping[str, Any]]] = {}
    for event in events:
        correlation_id = event.get(correlation_id_key)
        if correlation_id is None:
            metadata = event.get(QUEUE_ENVELOPE_KEY)
            if isinstance(metadata, dict):
                correlation_id = metadata.get(correlation_id_key)
        if correlation_id is None and not include_missing:
            continue
        groups.setdefault(correlation_id, []).append(event)

    return groups


def merge_by_correlation_id(
    events: Iterable[Mapping[str, Any]],
    *,
    correlation_id_key: str = _CORRELATION_ID_KEY,
) -> dict[Any, dict[str, Any]]:
    """
    Merge queue envelopes that share a correlation ID.

    Fields are merged shallowly; later events win on conflicts. The
    correlation ID is always present in the result and the `QUEUE_ENVELOPE_KEY`
    metadata is taken from the first event.

    .. versionadded:: 26.2.0
    """
    merged: dict[Any, dict[str, Any]] = {}
    for correlation_id, group in group_by_correlation_id(
        events, correlation_id_key=correlation_id_key
    ).items():
        result: dict[str, Any] = {}
        for event in group:
            for key, value in event.items():
                if key == QUEUE_ENVELOPE_KEY:
                    result.setdefault(key, value)
                else:
                    result[key] = value
        result.setdefault(correlation_id_key, correlation_id)
        merged[correlation_id] = result

    return merged


def wrap_for_queue(
    logger: logging.Logger, name: str, event_dict: EventDict
) -> tuple[tuple[EventDict], dict[str, dict[str, Any]]]:
    """
    Wrap *logger*, *name*, and *event_dict* for `QueueHandler`.

    A module-level convenience alias for `QueueHandler.wrap_for_queue`.

    .. versionadded:: 26.2.0
    """
    return QueueHandler.wrap_for_queue(logger, name, event_dict)


# Descriptive aliases for discoverability.  The names follow the standard
# library's queue handlers.
SafeQueueHandler = QueueHandler
SafeQueueListener = QueueListener
QueueProcessorFormatter = QueueFormatter
merge_events_by_correlation_id = merge_by_correlation_id
