"""Helpers for masking values inside JSON documents by path.

The paths used by :func:`auditlog.registry.AuditlogModelRegistry.register` are
small, predictable JSON paths relative to a ``JSONField`` value.  Supported
forms include ``credentials.api_key``, ``vendors[*].access_token`` and
``vendors[0].access_token``.  Bracket notation with a quoted key can be used
for keys that contain dots, for example ``credentials["api.key"]``.
"""

from __future__ import annotations

import ast
import copy
from collections.abc import Iterable, Mapping
from typing import Any

MASKED_JSON_VALUE = "***"
MASKED_JSON_VALUE_CHANGED = "*** [changed]"


class JSONPathError(ValueError):
    """Raised when a JSON path cannot be parsed."""


def parse_json_path(path: str) -> list[tuple[str, Any]]:
    """Parse a JSON path into a list of tokens.

    A token is either ``("key", name)``, ``("index", number)`` or
    ``("wildcard", None)``.  An empty path, or ``$``, addresses the whole
    document and therefore returns an empty token list.
    """
    if not isinstance(path, str):
        raise JSONPathError(f"JSON path must be a string, got {type(path).__name__}")

    raw = path.strip()
    if raw in ("", "$"):
        return []

    pos = 0
    if raw.startswith("$"):
        pos = 1
        if pos < len(raw) and raw[pos] == ".":
            pos += 1

    tokens: list[tuple[str, Any]] = []
    expecting_key = True

    while pos < len(raw):
        char = raw[pos]

        if char == ".":
            if expecting_key:
                raise JSONPathError(f"Unexpected '.' in JSON path {path!r}")
            expecting_key = True
            pos += 1
            continue

        if char == "[":
            end = _find_closing_bracket(raw, pos, path)
            content = raw[pos + 1 : end].strip()
            if not content:
                raise JSONPathError(f"Empty brackets in JSON path {path!r}")

            if content == "*":
                tokens.append(("wildcard", None))
            elif _is_integer(content):
                tokens.append(("index", int(content)))
            elif content[0] in "\"'" and content[-1] == content[0]:
                try:
                    key = ast.literal_eval(content)
                except (SyntaxError, ValueError) as exc:
                    raise JSONPathError(
                        f"Invalid quoted key {content!r} in JSON path {path!r}"
                    ) from exc
                if not isinstance(key, str):
                    raise JSONPathError(
                        f"Quoted bracket keys must be strings in JSON path {path!r}"
                    )
                tokens.append(("key", key))
            else:
                tokens.append(("key", content))

            expecting_key = False
            pos = end + 1
            continue

        if not expecting_key:
            raise JSONPathError(
                f"Expected '.' or '[' between path components in {path!r}"
            )

        start = pos
        while pos < len(raw) and raw[pos] not in ".[]":
            pos += 1

        key = raw[start:pos]
        if not key:
            raise JSONPathError(f"Empty path component in JSON path {path!r}")
        tokens.append(("key", key))
        expecting_key = False

    if expecting_key:
        raise JSONPathError(f"Trailing '.' in JSON path {path!r}")

    return tokens


def _find_closing_bracket(path: str, start: int, original: str) -> int:
    quote: str | None = None
    escaped = False
    for index in range(start + 1, len(path)):
        char = path[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "]":
            return index
    raise JSONPathError(f"Unclosed bracket in JSON path {original!r}")


def _is_integer(value: str) -> bool:
    return value.isdigit() or (value.startswith("-") and value[1:].isdigit())


def mask_json_value(value: Any, paths: Iterable[str]) -> Any:
    """Return a copy of ``value`` with every matching JSON path masked.

    Ordinary keys keep their original values and Python types.  A matched
    value (including a complete subtree) is replaced with
    :data:`MASKED_JSON_VALUE`, so no part of a secret is retained.
    """
    masked = _materialize(copy.deepcopy(value))
    for path in paths:
        tokens = parse_json_path(path)
        masked = _mask_node(masked, tokens)
    return masked


def _mask_node(node: Any, tokens: list[tuple[str, Any]]) -> Any:
    if not tokens:
        return MASKED_JSON_VALUE

    kind, argument = tokens[0]
    remainder = tokens[1:]

    if kind == "key":
        if isinstance(node, Mapping) and argument in node:
            updated = dict(node)
            updated[argument] = _mask_node(updated[argument], remainder)
            return updated
        return node

    if kind == "index":
        if isinstance(node, (list, tuple)):
            items = list(node)
            index = argument if argument >= 0 else len(items) + argument
            if 0 <= index < len(items):
                items[index] = _mask_node(items[index], remainder)
                return items
        return node

    if kind == "wildcard" and isinstance(node, (list, tuple)):
        return [_mask_node(item, remainder) for item in node]

    return node


def split_json_path_reference(reference: str) -> tuple[str, str]:
    """Split ``field.path.to.value`` into ``("field", "path.to.value")``."""
    if not isinstance(reference, str):
        raise JSONPathError(
            f"JSON path reference must be a string, got {type(reference).__name__}"
        )

    raw = reference.strip()
    if raw.startswith("$."):
        raw = raw[2:]
    elif raw.startswith("$"):
        raw = raw[1:]
    if raw.startswith("["):
        raise JSONPathError(f"Missing field name in JSON path reference {reference!r}")

    separators = [i for i in (raw.find("."), raw.find("[")) if i >= 0]
    if not separators:
        return raw, ""

    split_at = min(separators)
    field_name = raw[:split_at]
    remainder = raw[split_at:]
    if remainder.startswith("."):
        remainder = remainder[1:]
    if not field_name:
        raise JSONPathError(f"Missing field name in JSON path reference {reference!r}")
    return field_name, remainder


def normalize_mask_json_paths(spec: Any) -> dict[str, list[str]]:
    """Normalize registration input into ``{field_name: [path, ...]}``.

    Accepted forms are a mapping of field names to one path or a list of
    paths (for example ``{"payload": ["vendors[*].token"]}``) or an iterable
    of ``field.path`` references (for example
    ``["payload.vendors[*].token"]``).
    """
    if spec is None:
        return {}

    normalized: dict[str, list[str]] = {}

    def add(field_name: Any, path: Any) -> None:
        if not isinstance(field_name, str) or not field_name:
            raise JSONPathError("JSON mask paths must name a model field")
        if isinstance(path, str):
            paths = [path]
        elif isinstance(path, Iterable) and not isinstance(path, Mapping):
            paths = list(path)
        else:
            raise JSONPathError(
                f"JSON mask paths for field {field_name!r} must be strings"
            )

        bucket = normalized.setdefault(field_name, [])
        for item in paths:
            if not isinstance(item, str):
                raise JSONPathError(
                    f"JSON mask path for field {field_name!r} must be a string"
                )
            bucket.append(item)

    if isinstance(spec, Mapping):
        for key, value in spec.items():
            if isinstance(key, str) and ("." in key or "[" in key):
                raise JSONPathError(
                    f"Ambiguous JSON mask path mapping {key!r}: map model field "
                    "names to paths, or use an iterable of 'field.path' strings"
                )
            add(key, value)
        return normalized

    if isinstance(spec, str):
        spec = [spec]

    if not isinstance(spec, Iterable):
        raise JSONPathError(
            "JSON mask paths must be a mapping, a string, or an iterable of strings"
        )

    for reference in spec:
        field_name, path = split_json_path_reference(reference)
        add(field_name, path)

    return normalized


def _normalize_negative_index(index: int, length: int) -> int:
    return index + length if index < 0 else index


def _expand_matches(node: Any, tokens: list[tuple[str, Any]], prefix=()):
    """Yield ``(concrete_tokens, value)`` for every match of ``tokens`` in node."""
    if not tokens:
        yield prefix, node
        return

    kind, argument = tokens[0]
    remainder = tokens[1:]

    if kind == "key":
        if isinstance(node, Mapping) and argument in node:
            yield from _expand_matches(
                node[argument], remainder, prefix + (("key", argument),)
            )
        return

    if kind == "index":
        if isinstance(node, (list, tuple)):
            index = _normalize_negative_index(argument, len(node))
            if 0 <= index < len(node):
                yield from _expand_matches(
                    node[index], remainder, prefix + (("index", index),)
                )
        return

    if kind == "wildcard" and isinstance(node, (list, tuple)):
        for index, item in enumerate(node):
            yield from _expand_matches(item, remainder, prefix + (("index", index),))


def _set_concrete_value(
    node: Any, tokens: tuple[tuple[str, Any], ...], value: Any
) -> Any:
    if not tokens:
        return value

    _kind, argument = tokens[0]
    node[argument] = _set_concrete_value(node[argument], tokens[1:], value)
    return node


def _materialize(node: Any) -> Any:
    """Convert tuples to lists so masked output is valid JSON."""
    if isinstance(node, tuple):
        return [_materialize(item) for item in node]
    if isinstance(node, list):
        return [_materialize(item) for item in node]
    if isinstance(node, Mapping):
        return {key: _materialize(value) for key, value in node.items()}
    return node


def mask_json_value_pair(
    old_value: Any, new_value: Any, paths: Iterable[str]
) -> tuple[Any, Any]:
    """Mask two versions of a JSON document while keeping changes visible.

    Every matched value is replaced with :data:`MASKED_JSON_VALUE`.  When the
    value at a matched path differs between the two documents, the new side
    uses :data:`MASKED_JSON_VALUE_CHANGED`.  That way an investigator can tell
    a secret was updated without either value being retained.  Removed and
    added values remain distinguishable because the key or list item is
    absent on one side.
    """
    masked_old = _materialize(copy.deepcopy(old_value))
    masked_new = _materialize(copy.deepcopy(new_value))

    decisions: dict[tuple[tuple[str, Any], ...], tuple[bool, bool, bool]] = {}

    for path in paths:
        tokens = parse_json_path(path)
        old_matches = dict(_expand_matches(old_value, tokens))
        new_matches = dict(_expand_matches(new_value, tokens))

        for concrete in old_matches.keys() | new_matches.keys():
            old_present = concrete in old_matches
            new_present = concrete in new_matches
            changed = (
                old_present
                and new_present
                and old_matches[concrete] != new_matches[concrete]
            )
            decisions[concrete] = (old_present, new_present, changed)

    # Apply deeper paths first; a shorter path that contains another one wins.
    for concrete in sorted(decisions, key=len, reverse=True):
        old_present, new_present, changed = decisions[concrete]
        if old_present:
            masked_old = _set_concrete_value(
                masked_old, concrete, MASKED_JSON_VALUE
            )
        if new_present:
            marker = MASKED_JSON_VALUE_CHANGED if changed else MASKED_JSON_VALUE
            masked_new = _set_concrete_value(masked_new, concrete, marker)

    return masked_old, masked_new
