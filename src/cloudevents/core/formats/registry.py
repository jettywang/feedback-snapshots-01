"""Content-type registry for CloudEvents formats."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Callable

from cloudevents.core.formats.json import JSONFormat

FormatFactory = Callable[[], Any]


def normalize_content_type(content_type: str | None) -> str | None:
    """Return the media type without parameters and in lower case."""

    if content_type is None:
        return None
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type or None


class FormatRegistry:
    """Map CloudEvents/transport content types to format instances.

    The same format instance may be registered under several content types.
    Registration never causes a receive to try another representation after
    the selected format's decode callback fails.
    """

    def __init__(
        self,
        formats: Mapping[str, Any] | None = None,
        *,
        include_defaults: bool = True,
        default_format: Any | None = None,
    ) -> None:
        self._formats: dict[str, Any] = {}
        self.default_format = default_format

        if include_defaults:
            json_format = JSONFormat()
            self.register_format(
                json_format,
                JSONFormat.CONTENT_TYPE,
                JSONFormat.DEFAULT_CONTENT_TYPE,
                overwrite=False,
            )
            if self.default_format is None:
                self.default_format = json_format

        if formats:
            for content_type, event_format in formats.items():
                self.register(content_type, event_format)

    @classmethod
    def coerce(
        cls,
        registry: FormatRegistry | Mapping[str, Any] | None,
    ) -> FormatRegistry:
        if registry is None:
            return default_format_registry
        if isinstance(registry, FormatRegistry):
            return registry
        if isinstance(registry, Mapping):
            return cls(formats=registry)
        raise TypeError("registry must be a FormatRegistry or content-type mapping")

    def register_format(
        self,
        event_format: Any,
        *content_types: str,
        overwrite: bool = True,
    ) -> Any:
        types = tuple(content_types)
        if not types:
            get_content_type = getattr(event_format, "get_content_type", None)
            if get_content_type is None:
                raise ValueError(
                    "content_types are required for a format without get_content_type()"
                )
            types = (get_content_type(),)

        for content_type in types:
            normalized = normalize_content_type(content_type)
            if normalized is None:
                raise ValueError("Cannot register an empty content type")
            if not overwrite and normalized in self._formats:
                continue
            self._formats[normalized] = event_format
        return event_format

    def register(
        self,
        first: str | Any | None = None,
        second: Any | None = None,
        *rest: Any,
        content_types: tuple[str, ...] | list[str] | None = None,
        overwrite: bool = True,
    ) -> Any:
        """Register ``format`` or act as a content-type decorator.

        Supported calls include::

            registry.register("application/x+ce", event_format)
            registry.register(event_format)
            registry.register(event_format, "application/x+ce", "application/x")

            @registry.register("application/x+ce")
            class CustomFormat: ...
        """

        if isinstance(first, str):
            if second is None:
                content_type = first

                def decorator(event_format: Any) -> Any:
                    self.register(content_type, event_format, overwrite=overwrite)
                    return event_format

                return decorator

            return self.register_format(second, first, overwrite=overwrite)

        if first is None:
            raise TypeError("register() requires a format or content type")

        types: list[str] = []
        for value in (second, *rest):
            if isinstance(value, str):
                types.append(value)
        if content_types:
            types.extend(content_types)
        return self.register_format(first, *types, overwrite=overwrite)

    def add(self, content_type: str, event_format: Any) -> Any:
        return self.register_format(event_format, content_type)

    def get(
        self,
        content_type: str | None,
        default: Any | None = None,
    ) -> Any | None:
        normalized = normalize_content_type(content_type)
        if normalized is None:
            return self.default_format if default is None else default

        event_format = self._formats.get(normalized)
        if event_format is not None:
            return event_format

        # Structured syntax suffixes, e.g. application/cloudevents+json,
        # can reuse a format registered for the suffix representation.
        main_type, separator, subtype = normalized.partition("/")
        if separator and "+" in subtype:
            suffix = subtype.rsplit("+", 1)[1]
            suffix_type = f"{main_type}/{suffix}"
            event_format = self._formats.get(suffix_type)
            if event_format is not None:
                return event_format

        if normalized.endswith("+json"):
            return self._formats.get(JSONFormat.CONTENT_TYPE) or self._formats.get(
                JSONFormat.DEFAULT_CONTENT_TYPE
            )

        if default is not None:
            return default
        return self.default_format

    def get_for_content_type(
        self, content_type: str | None, default: Any | None = None
    ) -> Any | None:
        return self.get(content_type, default)

    def __getitem__(self, content_type: str) -> Any:
        event_format = self.get(content_type)
        if event_format is None:
            raise KeyError(content_type)
        return event_format

    def __setitem__(self, content_type: str, event_format: Any) -> None:
        self.register(content_type, event_format)

    def __contains__(self, content_type: object) -> bool:
        if not isinstance(content_type, str):
            return False
        return normalize_content_type(content_type) in self._formats

    @property
    def content_types(self) -> tuple[str, ...]:
        return tuple(self._formats)


default_format_registry = FormatRegistry()
# A short, explicit alias for callers that prefer a module-level registry.
format_registry = default_format_registry


def register_format(event_format: Any, *content_types: str) -> Any:
    return default_format_registry.register_format(event_format, *content_types)


def get_format(content_type: str | None, default: Any | None = None) -> Any | None:
    return default_format_registry.get(content_type, default)
