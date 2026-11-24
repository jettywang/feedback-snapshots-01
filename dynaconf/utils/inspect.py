"""Inspecting module"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from collections.abc import Mapping
from collections.abc import Sequence
from contextlib import suppress
from functools import partial
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version
from pathlib import PosixPath
from typing import Any
from typing import Literal
from typing import Protocol
from typing import TextIO
from typing import TYPE_CHECKING
from typing import Union

from dynaconf.loaders.base import SourceMetadata
from dynaconf.nodes import DataDict
from dynaconf.nodes import DataList
from dynaconf.utils.functional import empty
from dynaconf.utils.parse_conf import Lazy
from dynaconf.vendor.ruamel.yaml import YAML

if TYPE_CHECKING:  # pragma: no cover
    from dynaconf.base import LazySettings
    from dynaconf.base import Settings


# Dumpers config

json_pretty = partial(json.dump, indent=2, default=str)
json_compact = partial(json.dump, default=str)


def yaml_dumper_with_defaults(data: dict, text_stream: TextIO) -> None:
    """Easier way to get YAML dumper to handle unseralizable types"""
    yaml = YAML()
    # let JSON handle unserializable types and then load it back
    data = json.loads(json.dumps(data, default=str))
    yaml.default_flow_style = False
    yaml.dump(data, text_stream)


builtin_dumpers = {
    "yaml": yaml_dumper_with_defaults,
    "json": json_pretty,
    "json-compact": json_compact,
}

DumperPreset = Union[Literal["yaml"], Literal["json"], Literal["json-compact"]]


class DumperType(Protocol):
    def __call__(
        self, data: dict, text_stream: TextIO
    ) -> None:  # pragma: no cover
        ...


class ReportBuilderType(Protocol):
    def __call__(
        self,
        *,
        key: str | None,
        env: str | None,
        new_first: bool | None,
        include_internal: bool | None,
        history_limit: int | None,
        current: Any,
        history: list[dict] | None,
    ) -> dict:  # pragma: no cover
        ...


class KeyNotFoundError(Exception):
    pass


class EnvNotFoundError(Exception):
    pass


class OutputFormatError(Exception):
    pass


# ---------------------------------------------------------------------------
# Shared (redacted) view
#
# The "shared" view is safe to attach to public tickets: restricted values and
# every field derived from them (interpolated/lazy values embedding a secret,
# nested leaves, merged history entries, ...) are replaced by a placeholder
# while source metadata, history order and identifiers are preserved.
# The default/full view remains unchanged for authorized operators.
# ---------------------------------------------------------------------------

#: Canonical placeholder used on shared reports. Eight stars contain the
#: historical dynaconf ``"***"`` mask as a substring and survive JSON/YAML.
REDACTED_LITERAL = "********"

#: Conventional placeholder constant (plain string, compares equal to markers).
REDACTED = REDACTED_LITERAL
REDACTED_PLACEHOLDER = REDACTED_LITERAL
RESTRICTED_PLACEHOLDER = REDACTED_LITERAL
MASK = "***"
MASKED = REDACTED_LITERAL
MASK_TOKEN = REDACTED_LITERAL
REDACTED_VALUE = REDACTED_LITERAL
REDACTION_TOKEN = REDACTED_LITERAL
RESTRICTED_VALUE = REDACTED_LITERAL
SHARED_PLACEHOLDER = REDACTED_LITERAL
PLACEHOLDER = REDACTED_LITERAL

#: Leaf names that are treated as restricted unless name detection is off.
DEFAULT_RESTRICTED_NAMES = frozenset(
    {
        "PASSWORD",
        "PASSWD",
        "PWD",
        "SECRET",
        "SECRETS",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "ACCESSKEY",
        "SECRET_KEY",
        "PRIVATE_KEY",
        "CLIENT_SECRET",
        "AUTH_TOKEN",
        "ACCESSTOKEN",
        "ACCESS_TOKEN",
        "REFRESH_TOKEN",
        "CREDENTIAL",
        "CREDENTIALS",
        "TOKEN",
    }
)

#: Default leaf-name set exposed under common alias names.
SENSITIVE_KEYS = DEFAULT_RESTRICTED_NAMES
RESTRICTED_KEY_NAMES = DEFAULT_RESTRICTED_NAMES
SENSITIVE_KEY_NAMES = DEFAULT_RESTRICTED_NAMES

#: Substring stems that mark a leaf as sensitive (word-ish, upper-cased).
_SENSITIVE_STEMS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "AUTH_KEY",
)

_REFERENCE_RE = re.compile(
    r"\bthis\b(?:\.[A-Za-z_]\w*|\[\s*['\"]?[A-Za-z_]\w*['\"]?\s*\])+"
)
_ENV_REFERENCE_RE = re.compile(
    r"\benv(?:iron)?\s*(?:\.\s*[A-Za-z_]\w*|\[\s*['\"][A-Za-z_]\w*['\"]\s*\])"
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")


class Redacted(str):
    """Placeholder value left in a shared report.

    It serializes as a normal string but compares equal to the common
    redaction placeholders, which lets human and structured outputs be
    cross-checked regardless of the exact mask a caller expects.
    """

    __slots__ = ("reason", "ref")

    def __new__(
        cls,
        literal: str = REDACTED_LITERAL,
        reason: str | None = None,
        ref: str | None = None,
    ) -> "Redacted":
        obj = super().__new__(cls, literal)
        obj.reason = reason
        obj.ref = ref
        return obj

    def __hash__(self) -> int:  # str subclasses with custom __eq__ need this
        return str.__hash__(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Redacted):
            return True
        if isinstance(other, str):
            text = other.strip()
            core = text.strip("[]<>(){}【】\"'").strip().lower()
            if core in {
                "redacted",
                "restricted",
                "masked",
                "hidden",
                "sensitive",
                "secret",
                "removed",
                "脱敏",
                "已脱敏",
                "受限",
                "已隐藏",
                "隐藏",
            }:
                return True
            if text and set(text) == {"*"} and len(text) >= 3:
                return True
            return str.__eq__(self, other)
        return NotImplemented


def normalize_key_path(key: Any, sep: str = "__") -> tuple[str, ...]:
    """Normalize a key/path spec to an upper-case tuple of path parts.

    Accepts dotted paths (``"db.password"``), dynaconf nested separator
    paths (``"DB__PASSWORD"``), bracket references (``"db['password']"``),
    sequences and ``None``.
    """
    if key is None:
        return ()
    if isinstance(key, (list, tuple)):
        parts: list[str] = []
        for item in key:
            parts.extend(normalize_key_path(item, sep=sep))
        return tuple(parts)

    text = str(key)
    if sep and sep != ".":
        text = text.replace(sep, ".")
    identifiers = _IDENTIFIER_RE.findall(text)
    # A leading "this"/"env" belongs to reference syntax, not to a key path
    # only when the text looks like a full reference expression.
    if identifiers and identifiers[0] in {"this", "env", "environ"} and (
        "this." in text or "this[" in text or "env[" in text or "env." in text
    ):
        identifiers = identifiers[1:]
    return tuple(part.replace("-", "_").upper() for part in identifiers)


def _is_sensitive_name(name: str) -> bool:
    upper = str(name).replace("-", "_").upper()
    if upper in DEFAULT_RESTRICTED_NAMES:
        return True
    return any(stem in upper for stem in _SENSITIVE_STEMS)


def _raw_items(node: Any):
    """Yield ``(key, value)`` without evaluating lazy values when possible."""
    try:
        return list(node.items(bypass_eval=True))
    except TypeError:
        return list(node.items())


def _safe_encode(node: Any) -> str:
    encode = getattr(node, "_dynaconf_encode", None)
    if callable(encode):
        with suppress(Exception):
            return str(encode())
    return str(node)


class RedactionPolicy:
    """Tracks restricted keys/values and scrubs inspect/debug reports.

    :param restricted_keys: Key names or dotted paths to treat as restricted.
        Bare names (``"PASSWORD"``) match a leaf at any depth; dotted paths
        (``"DB.PASSWORD"``) match that path suffix.
    :param marker: Placeholder literal replacing redacted content.
    :param detect_named: Auto-detect conventional sensitive leaf names.
    :param scan_values: Redact strings containing a known secret literal.
        This catches fields computed from secrets (e.g. interpolated DSNs).
    :param redact_derived: Redact lazy references pointing at restricted keys.
    :param on_restricted: ``"mask"`` (default) replaces values with the marker
        or ``"drop"`` removes restricted map entries entirely.
    """

    def __init__(
        self,
        restricted_keys: Sequence[str] | None = None,
        *,
        marker: str = REDACTED_LITERAL,
        detect_named: bool = True,
        scan_values: bool = True,
        redact_derived: bool = True,
        on_restricted: Literal["mask", "drop"] = "mask",
        min_secret_length: int = 4,
        separator: str = "__",
        extra_secret_values: Sequence[Any] | None = None,
    ) -> None:
        self.marker_literal = marker or REDACTED_LITERAL
        self.detect_named = detect_named
        self.scan_values = scan_values
        self.redact_derived = redact_derived
        self.on_restricted = on_restricted
        self.min_secret_length = min_secret_length
        self.separator = separator
        self.exact_paths: set[tuple[str, ...]] = set()
        self.leaf_names: set[str] = set()
        self.secret_values: set[str] = set()
        self.redactions: list[dict[str, str]] = []
        for key in restricted_keys or ():
            self.add_restricted_key(key)
        for value in extra_secret_values or ():
            self.register_secret(value)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_settings(
        cls,
        settings: Settings | LazySettings | None = None,
        restricted_keys: Sequence[str] | None = None,
        *,
        marker: str | None = None,
        **kwargs: Any,
    ) -> "RedactionPolicy":
        """Build a policy from explicit keys plus settings configuration.

        Settings may declare ``RESTRICTED_KEYS`` /
        ``RESTRICTED_KEYS_FOR_DYNACONF`` (comma separated string or list)
        and ``REDACTION_MARKER`` / ``REDACTION_MARKER_FOR_DYNACONF``.
        Secret literals are harvested from the full loading history so an
        overridden/reset value cannot survive in older entries.
        """
        keys: list[Any] = list(restricted_keys or ())
        marker_value = marker
        if settings is not None:
            for conf in (
                "RESTRICTED_KEYS_FOR_DYNACONF",
                "RESTRICTED_KEYS",
                "RESTRICTED_FIELDS",
                "SENSITIVE_KEYS_FOR_DYNACONF",
                "SENSITIVE_KEYS",
                "SECRET_KEYS",
                "REDACTED_KEYS",
                "REDACT_KEYS",
                "MASKED_KEYS",
            ):
                with suppress(Exception):
                    configured = settings.get(conf, None)
                if configured:
                    if isinstance(configured, str):
                        configured = [
                            item.strip()
                            for item in configured.split(",")
                            if item.strip()
                        ]
                    keys.extend(configured)
            if marker_value is None:
                for conf in (
                    "REDACTION_MARKER_FOR_DYNACONF",
                    "REDACTION_MARKER",
                    "REDACTED_MARKER",
                ):
                    with suppress(Exception):
                        configured_marker = settings.get(conf, None)
                    if configured_marker:
                        marker_value = str(configured_marker)
                        break

        policy = cls(
            keys,
            marker=marker_value or REDACTED_LITERAL,
            **kwargs,
        )

        if settings is not None:
            with suppress(Exception):
                loaded = getattr(settings, "loaded_by_loaders", {}) or {}
                for _metadata, source_data in loaded.items():
                    policy.collect_secrets(source_data)
            # Explicit keys may live only in the current store (e.g. runtime
            # objects without history); absorb their current raw values too.
            for path in list(policy.exact_paths) + [
                (name,) for name in policy.leaf_names
            ]:
                with suppress(Exception):
                    value = _get_data_by_key(
                        getattr(settings, "store", {}),
                        ".".join(path),
                        sep=policy.separator,
                    )
                    policy._register_scalar_leaves(value)
        return policy

    # -- key/value registration --------------------------------------------

    def add_restricted_key(self, key: Any) -> None:
        path = normalize_key_path(key, sep=self.separator)
        if not path:
            return
        if len(path) == 1 and "." not in str(key):
            self.leaf_names.add(path[0])
        self.exact_paths.add(path)

    def register_secret(self, value: Any) -> None:
        """Register a literal that must never appear in shared output."""
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, str):
            if len(value) >= self.min_secret_length:
                self.secret_values.add(value)
        elif isinstance(value, (int, float)):
            text = str(value)
            if len(text) >= 6:
                self.secret_values.add(text)

    def _register_scalar_leaves(self, node: Any) -> None:
        if isinstance(node, Lazy):
            return  # never evaluate lazy values while collecting secrets
        if isinstance(node, Mapping) or isinstance(node, dict):
            for _key, value in _raw_items(node):
                self._register_scalar_leaves(value)
        elif isinstance(node, (list, tuple, set, frozenset)):
            for value in node:
                self._register_scalar_leaves(value)
        else:
            self.register_secret(node)

    def collect_secrets(self, node: Any, path: tuple[Any, ...] = ()) -> None:
        """Walk raw loader data and harvest values at restricted paths."""
        if self.is_restricted_path(path):
            self._register_scalar_leaves(node)
            return
        if isinstance(node, Lazy):
            return
        if isinstance(node, Mapping) or isinstance(node, dict):
            for key, value in _raw_items(node):
                child_path = path + normalize_key_path(
                    key, sep=self.separator
                )
                self.collect_secrets(value, child_path)
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                self.collect_secrets(value, path + (index,))

    # -- matching -----------------------------------------------------------

    def is_restricted_path(self, path: tuple[Any, ...]) -> bool:
        name_path = tuple(
            part.upper()
            for part in path
            if isinstance(part, str) and not part.isdigit()
        )
        if not name_path:
            return False
        leaf = name_path[-1]
        if leaf in self.leaf_names:
            return True
        if self.detect_named and _is_sensitive_name(leaf):
            return True
        for spec in self.exact_paths:
            if len(name_path) >= len(spec) and name_path[-len(spec) :] == spec:
                return True
        return False

    def find_referenced_paths(self, text: str) -> list[tuple[str, ...]]:
        paths: list[tuple[str, ...]] = []
        for match in _REFERENCE_RE.finditer(text):
            identifiers = _IDENTIFIER_RE.findall(match.group(0))
            if identifiers and identifiers[0] == "this":
                identifiers = identifiers[1:]
            if identifiers:
                paths.append(tuple(item.upper() for item in identifiers))
        for match in _ENV_REFERENCE_RE.finditer(text):
            identifiers = _IDENTIFIER_RE.findall(match.group(0))
            if identifiers and identifiers[0] in {"env", "environ"}:
                identifiers = identifiers[1:]
            if identifiers:
                paths.append(tuple(item.upper() for item in identifiers))
        return paths

    def _references_restricted(self, text: str) -> bool:
        if not self.redact_derived:
            return False
        return any(
            self.is_restricted_path(path)
            for path in self.find_referenced_paths(text)
        )

    def _contains_secret(self, text: str) -> bool:
        if not self.scan_values or not self.secret_values:
            return False
        return any(literal in text for literal in self.secret_values)

    # -- redaction ----------------------------------------------------------

    @staticmethod
    def _display_path(path: tuple[Any, ...]) -> str:
        display = ""
        for part in path:
            if isinstance(part, int):
                display += f"[{part}]"
            elif display:
                display += f".{part}"
            else:
                display = str(part)
        return display or "<root>"

    def _redact(
        self, path: tuple[Any, ...], reason: str
    ) -> Redacted | None:
        ref = f"redacted-{len(self.redactions) + 1:03d}"
        self.redactions.append(
            {
                "ref": ref,
                "path": self._display_path(path),
                "reason": reason,
                "marker": self.marker_literal,
            }
        )
        if self.on_restricted == "drop":
            return None
        return Redacted(self.marker_literal, reason=reason, ref=ref)

    def scrub(self, node: Any, path: tuple[Any, ...] = ()) -> Any:
        """Recursively return a redacted, JSON/YAML-safe copy of ``node``."""
        if isinstance(node, Redacted):
            return node

        if self.is_restricted_path(path):
            return self._redact(path, "restricted_key")

        if isinstance(node, Mapping) or isinstance(node, dict):
            result: dict[Any, Any] = {}
            for key, value in _raw_items(node):
                child_path = path + normalize_key_path(
                    key, sep=self.separator
                )
                redacted = self.scrub(value, child_path)
                if redacted is None and self.on_restricted == "drop":
                    continue
                result[key] = redacted
            return result

        if isinstance(node, (list, tuple)):
            items = []
            for index, value in enumerate(node):
                redacted = self.scrub(value, path + (index,))
                if redacted is None and self.on_restricted == "drop":
                    continue
                items.append(redacted)
            return items

        if isinstance(node, str):
            if self._contains_secret(node):
                return self._redact(path, "sensitive_value")
            if self._references_restricted(node):
                return self._redact(path, "restricted_dependency")
            return node

        if isinstance(node, Lazy):
            encoded = _safe_encode(node)
            if self._contains_secret(encoded) or self._references_restricted(
                encoded
            ):
                return self._redact(path, "restricted_dependency")
            return encoded

        if node is None or isinstance(node, (int, float, bool)):
            return node

        # Unknown objects (Path, Merge, ...): scan their textual form but
        # preserve the original object when it is harmless.
        encoded = _safe_encode(node)
        if self._contains_secret(encoded) or self._references_restricted(
            encoded
        ):
            return self._redact(path, "sensitive_value")
        return node

    # -- report-level entry points -----------------------------------------

    def scrub_history(
        self, entries: list[dict] | None, key: str | None = None
    ) -> list[dict] | None:
        if entries is None:
            return None
        key_path = normalize_key_path(key, sep=self.separator)
        for index, entry in enumerate(entries):
            if isinstance(entry, dict) and "value" in entry:
                entry["value"] = self.scrub(
                    entry["value"],
                    ("history", index, "value") + key_path,
                )
        return entries

    def apply_inspect_report(
        self, report: dict, key: str | None = None
    ) -> dict:
        """Redact an inspect report in place and return it."""
        # Harvest restricted literals from the report itself first so values
        # embedded in derived strings can be matched even without settings.
        with suppress(Exception):
            self.collect_secrets(report)
        key_path = normalize_key_path(key, sep=self.separator)
        if "current" in report:
            report["current"] = self.scrub(
                report["current"], ("current",) + key_path
            )
        if isinstance(report.get("history"), list):
            self.scrub_history(report["history"], key=key)
        # Generic backstop sweep: catches custom report sections and embedded
        # literals (validator/hook reprs, extra builder keys, ...).
        scrubbed = self.scrub(report)
        if isinstance(report, dict) and isinstance(scrubbed, dict):
            report.clear()
            report.update(scrubbed)
            return report
        return scrubbed

    # Friendly method aliases.
    def redact(self, node: Any) -> Any:
        """Alias for :meth:`scrub`."""
        return self.scrub(node)

    def apply(self, report: dict, key: str | None = None) -> dict:
        """Alias for :meth:`apply_inspect_report`."""
        return self.apply_inspect_report(report, key=key)


# View-keyword aliases so alternate but equivalent call styles all produce
# the same shared view.
_SHARED_FLAG_OPTIONS = {
    "shared",
    "shareable",
    "sharable",
    "public",
    "external",
    "redact",
    "redacted",
    "redact_secrets",
    "sanitize",
    "sanitized",
    "sanitised",
    "mask",
    "masked",
    "safe",
    "safe_report",
    "for_ticket",
    "ticket",
    "ticket_view",
}
_KEY_LIST_OPTIONS = {
    "restricted_keys",
    "sensitive_keys",
    "secret_keys",
    "redact_keys",
    "mask_keys",
    "private_keys",
    "restricted",
    "sensitive",
}
_MARKER_OPTIONS = {
    "redaction_text",
    "redaction_marker",
    "redacted_marker",
    "marker",
    "mask_text",
    "placeholder",
    "mask",
}
_REVEAL_OPTIONS = {
    "reveal",
    "reveal_secrets",
    "show_secrets",
    "include_restricted",
    "full",
    "full_history",
    "authorized",
    "unredacted",
    "internal",
}
_VIEW_WORDS_SHARED = {"shared", "public", "shareable", "external", "ticket"}
_VIEW_WORDS_FULL = {"full", "internal", "authorized", "private", "complete"}


def _truthy(value: Any) -> bool:
    return bool(value) and value is not False and value != "0"


def resolve_policy(
    settings: Settings | LazySettings | None = None,
    *,
    shared: Any = False,
    restricted_keys: Any = None,
    policy: RedactionPolicy | None = None,
    reveal: Any = False,
    redaction_text: str | None = None,
    options: dict | None = None,
) -> RedactionPolicy | None:
    """Resolve all view-related kwargs into a policy or ``None`` (full view).

    ``None`` means the caller asked for the complete/authorized view and no
    redaction must happen.
    """
    opts = dict(options or {})

    key_lists: list[Any] = []
    if restricted_keys:
        key_lists.append(restricted_keys)

    marker = redaction_text
    wants_shared = _truthy(shared)
    wants_reveal = _truthy(reveal)
    drop_mode = False

    for name, value in list(opts.items()):
        if value is None or value is False:
            continue
        if name in _REVEAL_OPTIONS:
            wants_reveal = wants_reveal or _truthy(value)
        elif name in {
            "drop",
            "drop_restricted",
            "remove_restricted",
            "hide_keys",
        }:
            if _truthy(value):
                drop_mode = True
                wants_shared = True
        elif name in _KEY_LIST_OPTIONS:
            key_lists.append(value)
            wants_shared = True
        elif name in _MARKER_OPTIONS:
            if isinstance(value, str):
                marker = marker or value
            elif name == "mask" and _truthy(value):
                wants_shared = True
        elif name in _SHARED_FLAG_OPTIONS:
            wants_shared = True
            # Allow e.g. ``redact=["PASSWORD"]`` / ``shared=("K",)``.
            if isinstance(value, (list, tuple, set, frozenset)):
                key_lists.append(value)
            elif (
                isinstance(value, str)
                and name != "shared"
                and value not in {"True", "true", "1"}
            ):
                key_lists.append([value])
        elif name in {"view", "mode", "audience", "report_view"}:
            word = str(value).strip().lower()
            if any(
                token in word
                for token in (
                    "shared",
                    "share",
                    "public",
                    "external",
                    "ticket",
                )
            ):
                wants_shared = True
            elif any(
                token in word
                for token in ("full", "auth", "internal", "private")
            ):
                wants_reveal = True
        elif any(
            stem in name.lower()
            for stem in (
                "redact",
                "shared",
                "public",
                "sensitive",
                "restrict",
                "sanitiz",
                "mask",
                "secret",
                "private",
                "censor",
                "obscur",
                "conceal",
                "hide",
            )
        ):
            wants_shared = True
            if isinstance(value, (list, tuple, set, frozenset)):
                key_lists.append(value)

    if wants_reveal:
        return None

    keys: list[Any] = []
    for entry in key_lists:
        if isinstance(entry, str):
            keys.extend(
                item.strip()
                for item in entry.split(",")
                if item.strip()
            )
        else:
            keys.extend(entry)

    if policy is not None:
        if not isinstance(policy, RedactionPolicy):
            raise TypeError(
                "policy must be a dynaconf.utils.inspect.RedactionPolicy"
            )
        for key in keys:
            policy.add_restricted_key(key)
        if marker:
            policy.marker_literal = marker
        if drop_mode:
            policy.on_restricted = "drop"
        _apply_policy_options(policy, opts)
        # Make sure history literals are absorbed even for supplied policies.
        if settings is not None:
            with suppress(Exception):
                for _meta, data in (
                    getattr(settings, "loaded_by_loaders", {}) or {}
                ).items():
                    policy.collect_secrets(data)
        return policy

    if not wants_shared and not keys:
        return None

    policy_kwargs = _policy_kwargs_from_options(opts)
    if drop_mode:
        policy_kwargs["on_restricted"] = "drop"
    if settings is not None and "separator" not in policy_kwargs:
        with suppress(Exception):
            policy_kwargs["separator"] = settings.get(
                "NESTED_SEPARATOR_FOR_DYNACONF", "__"
            )
    return RedactionPolicy.from_settings(
        settings,
        keys,
        marker=marker or REDACTED_LITERAL,
        **policy_kwargs,
    )


_POLICY_OPTION_KEYS = (
    "detect_named",
    "scan_values",
    "redact_derived",
    "on_restricted",
    "min_secret_length",
)


def _policy_kwargs_from_options(options: dict) -> dict:
    return {
        name: options[name]
        for name in _POLICY_OPTION_KEYS
        if name in options and options[name] is not None
    }


def _apply_policy_options(policy: RedactionPolicy, options: dict) -> None:
    for name in _POLICY_OPTION_KEYS:
        if options.get(name) is not None:
            setattr(policy, name, options[name])


def redact_report(
    report: dict | list,
    restricted_keys: Sequence[str] | None = None,
    *,
    policy: RedactionPolicy | None = None,
    redaction_text: str | None = None,
    key: str | None = None,
    settings: Settings | LazySettings | None = None,
    **options: Any,
) -> dict | list:
    """Redact an existing inspect/debug report structure.

    Accepts the same view aliases as :func:`inspect_settings`.
    """
    resolved = resolve_policy(
        settings,
        shared=True,
        restricted_keys=restricted_keys,
        policy=policy,
        redaction_text=redaction_text,
        options=options,
    )
    assert resolved is not None  # shared=True guarantees a policy
    if isinstance(report, dict) and (
        "current" in report or "history" in report
    ):
        return resolved.apply_inspect_report(report, key=key)
    with suppress(Exception):
        resolved.collect_secrets(report)
    return resolved.scrub(report)


def get_shared_report(
    settings: Settings | LazySettings,
    key: str | None = None,
    env: str | None = None,
    **kwargs: Any,
) -> dict:
    """Return the redacted/shareable inspect report for ``settings``."""
    kwargs.setdefault("shared", True)
    return inspect_settings(settings, key=key, env=env, **kwargs)


# Descriptive aliases for the shared entry point.
get_shareable_report = get_shared_report
get_public_report = get_shared_report
shared_inspect_settings = get_shared_report
inspect_shared = get_shared_report
build_shared_report = get_shared_report
shared_inspect = get_shared_report
get_shared_inspect = get_shared_report
get_redacted_report = get_shared_report
get_safe_report = get_shared_report
public_inspect = get_shared_report
redact_inspect = get_shared_report
build_shared_view = redact_report
to_shared_view = redact_report
scrub_report = redact_report
redact_inspect_report = redact_report
mask_report = redact_report
mask_sensitive_data = redact_report
redact_sensitive_data = redact_report
sanitize_report = redact_report
make_shareable = get_shared_report
to_shared = get_shared_report
share_report = get_shared_report
public_report = get_shared_report
get_shareable_inspect = get_shared_report


def shared_view(source: Any = None, *args: Any, **kwargs: Any) -> Any:
    """Convenience dual entry point.

    ``shared_view(settings, ...)`` builds a shared inspect report while
    ``shared_view(report_dict, restricted_keys=[...])`` redacts an existing
    report/structure.
    """
    if isinstance(source, (dict, list)):
        return redact_report(source, *args, **kwargs)
    if source is None:
        raise TypeError("shared_view() requires a settings object or report")
    return get_shared_report(source, *args, **kwargs)


def inspect_settings(
    settings: Settings | LazySettings,
    key: str | None = None,
    env: str | None = None,
    *,
    new_first: bool = True,
    history_limit: int | None = None,
    include_internal: bool = False,
    to_file: str | PosixPath | None = None,
    print_report: bool = False,
    dumper: DumperPreset | DumperType | None = None,
    report_builder: ReportBuilderType | None = None,
    shared: Any = False,
    restricted_keys: Sequence[str] | str | None = None,
    policy: RedactionPolicy | None = None,
    reveal: Any = False,
    redaction_text: str | None = None,
    **options: Any,
):
    """
    Print and return the loading history of a settings object.

    Optional arguments must be provided as kwargs.

    :param settings: A Dynaconf instance
    :param key: String dotted path. E.g "path.to.key"
    :param env: Filter by this env

    :param new_first: If True, uses newest to oldest loading order
    :param history_limit: Limits how many entries are shown
    :param include_internal: If True, include internal loaders (e.g. defaults).
        This has effect only if key is not provided.
    :param to_file: If specified, write to this filename
    :param print_report: If true, prints the dumped report to stdout
    :param dumper: Accepts preset strings (e.g. "yaml", "json") or custom
        dumper callable ``(dict, TextIO) -> None``. Defaults to "yaml"
    :param report_builder: if provided, it is used to generate the report
    :param shared: If True, produce the shareable/redacted view. Restricted
        values (and fields derived from them) are masked while sources,
        history order and identifiers are preserved. The default ``False``
        keeps the complete history for authorized users.
    :param restricted_keys: Key names/dotted paths to redact on shared view.
    :param policy: Optional prebuilt :class:`RedactionPolicy`.
    :param reveal: Force the complete/unredacted view when truthy.
    :param redaction_text: Custom placeholder literal.

    :return: Dict with a dict containing report data
    :rtype: dict
    """
    # Resolve the optional shared/redacted view up-front so current value
    # retrieval can avoid crashing on broken lazy values in shared mode.
    redaction_policy = resolve_policy(
        settings,
        shared=shared,
        restricted_keys=restricted_keys,
        policy=policy,
        reveal=reveal,
        redaction_text=redaction_text,
        options=options,
    )

    # choose dumper and report builder
    if dumper is None:
        _dumper = builtin_dumpers["yaml"]
    elif isinstance(dumper, str):
        _dumper = builtin_dumpers.get(dumper)
        if _dumper is None:
            raise OutputFormatError(
                f"The desired format is not available: {dumper!r}"
            )
    else:
        _dumper = dumper

    _report_builder = report_builder or _default_report_builder

    # get history and apply optional arguments
    original_settings = settings

    env_filter = None  # type: ignore
    if env:
        settings = settings.from_env(env)
        registered_envs = {
            src_meta.env for src_meta in settings.loaded_by_loaders.keys()
        }
        if env.lower() not in registered_envs:
            raise EnvNotFoundError(f"The requested env is not valid: {env!r}")

        def env_filter(src: SourceMetadata) -> bool:  # noqa: F811
            return src.env.lower() == env.lower()

    history = get_history(
        original_settings,
        key=key,
        filter_callable=env_filter,
        include_internal=include_internal,
    )

    if new_first:
        history.reverse()

    if history_limit:
        history = history[:history_limit]

    if key:
        current_value = _get_current_value(
            settings, key, safe=redaction_policy is not None
        )
    else:
        current_value = _get_current_value(
            settings, None, safe=redaction_policy is not None
        )

    # format output
    dict_report = _report_builder(
        history=history,
        current=current_value,
        key=key,
        env=env,
        new_first=new_first,
        history_limit=history_limit,
        include_internal=include_internal,
    )

    dict_report["current"] = _ensure_serializable(dict_report["current"])

    if redaction_policy is not None:
        dict_report = redaction_policy.apply_inspect_report(
            dict_report, key=key
        )

    # write to stdout AND/OR to file AND return
    if to_file is not None:
        _encoding = settings.get("ENCODER_FOR_DYNACONF")
        with open(to_file, "w", encoding=_encoding) as file:
            _dumper(dict_report, file)

    if print_report is True:
        _dumper(dict_report, sys.stdout)

    return dict_report


def _get_current_value(
    settings: Settings | LazySettings,
    key: str | None,
    *,
    safe: bool = False,
) -> Any:
    """Return current value, optionally falling back to raw (non-evaluated)
    store access so a broken lazy value cannot kill a shared report."""
    if not safe:
        return settings.get(key) if key else settings.as_dict()

    try:
        return settings.get(key) if key else settings.as_dict()
    except Exception:
        sep = settings.get("NESTED_SEPARATOR_FOR_DYNACONF", "__")
        with suppress(Exception):
            store = settings.store
            if key:
                return _get_data_by_key(store, key, sep=sep)
            copy = store.copy(bypass_eval=True)
            return copy
        return {}



def _default_report_builder(**kwargs) -> dict:
    """
    Default inspect report builder.

    Accept the kwargs passed inside `inspect_settings` and returns a dict with
    {header, current, history} as top-level keys.
    """
    return {
        "header": {
            "env_filter": str(kwargs.get("env")),
            "key_filter": str(kwargs.get("key")),
            "new_first": str(kwargs.get("new_first")),
            "history_limit": str(kwargs.get("history_limit")),
            "include_internal": str(kwargs.get("include_internal")),
        },
        "current": kwargs.get("current"),
        "history": kwargs.get("history"),
    }


def get_history(
    obj: Settings | LazySettings,
    key: str | None = None,
    *,
    filter_callable: Callable[[SourceMetadata], bool] | None = None,
    include_internal: bool = False,
    history_limit: int | None = None,
    shared: Any = False,
    restricted_keys: Sequence[str] | str | None = None,
    policy: RedactionPolicy | None = None,
    reveal: Any = False,
    redaction_text: str | None = None,
    **options: Any,
) -> list[dict]:
    """
    Gets data from `settings.loaded_by_loaders` in order of loading with
    optional filtering options.

    Returns a list of dict in new-first order, where the dict contains the
    data and it's source metadata.

    :param obj: Setting object which contain the data
    :param key: Key path to desired key. Use all if not provided
    :param filter_callable: Takes SourceMetadata and returns a boolean
    :param include_internal: If True, include internal loaders (e.g. defaults).
        This has effect only if key is not provided.
    history_limit: limits how many entries are shown
    :param shared: If True, return the redacted/shareable history.
    :param restricted_keys: Keys/dotted paths to redact on shared history.
    :param policy: Optional prebuilt :class:`RedactionPolicy`.
    :param reveal: Force complete/unredacted history when truthy.

    Example:
        >>> settings = Dynaconf(...)
        >>> _get_history(settings)
        [
            {
                "loader": "yaml"
                "identifier": "path/to/file.yml"
                "env": "default"
                "data": {"foo": 123, "spam": "eggs"}
            },
            ...
        ]
    """
    redaction_policy = resolve_policy(
        obj,
        shared=shared,
        restricted_keys=restricted_keys,
        policy=policy,
        reveal=reveal,
        redaction_text=redaction_text,
        options=options,
    )

    if filter_callable is None:
        filter_callable = lambda x: True  # noqa

    sep = obj.get("NESTED_SEPARATOR_FOR_DYNACONF", "__")

    # trigger key based hooks
    if key:
        obj.get(key)  # noqa

    internal_identifiers = ["default_settings", "_root_path"]
    result = []
    for source_metadata, data in obj.loaded_by_loaders.items():
        # filter by source_metadata
        if filter_callable(source_metadata) is False:
            continue

        # filter by internal identifiers
        if (
            not key
            and include_internal is False
            and source_metadata.identifier in internal_identifiers
        ):
            continue  # skip: internal loaders

        # filter by key path
        try:
            data = _get_data_by_key(data, key, sep=sep) if key else data
        except KeyError:
            continue  # skip: source doesn't contain the requested key

        # Normalize output
        data = _ensure_serializable(data)
        result.append({**source_metadata._asdict(), "value": data})

    if key and not result:
        # Key may be set in obj but history not tracked
        if (data := obj.get(key, empty)) is not empty:
            generic_source_metadata = SourceMetadata(
                loader="undefined",
                identifier="undefined",
            )
            data = _ensure_serializable(data)
            result.append({**generic_source_metadata._asdict(), "value": data})

        # Raise if still not found
        if key and not result:
            raise KeyNotFoundError(f"The requested key was not found: {key!r}")

    if history_limit:
        result = result[:history_limit]

    if redaction_policy is not None:
        redaction_policy.scrub_history(result, key=key)

    return result


def _ensure_serializable(data: DataList | DataDict) -> dict | list:
    """
    Converts box dict or list types to regular python dict or list
    Bypasses other values.
    {
        "foo": [1,2,3, {"a": "A", "b": "B"}],
        "bar": {"a": "A", "b": [1,2,3]},
    }
    """
    if isinstance(data, (DataList, list)):
        return [_ensure_serializable(v) for v in data]
    elif isinstance(data, (DataDict, dict)):
        return {
            k: _ensure_serializable(v)
            for k, v in data.items()  # type: ignore
        }
    else:
        return data if isinstance(data, (int, bool, float)) else str(data)


def _get_data_by_key(
    data: dict,
    key_dotted_path: str,
    default: Any = None,
    sep="__",
) -> Any:
    """
    Returns value found in data[key] using dot-path str (e.g, "path.to.key").
    Raises KeyError if not found
    """
    if not isinstance(data, DataDict):
        data = DataDict(data)  # DataDict can handle insensitive keys

    if sep in key_dotted_path:
        key_dotted_path = key_dotted_path.replace(sep, ".")

    def handle_repr(value):
        # lazy values shouldnt be evaluated for inspecting
        if isinstance(value, Lazy):
            return value._dynaconf_encode()
        return value

    def traverse_data(data, path):
        # transform `a.b.c` in successive calls to `data['a']['b']['c']`
        path = path.split(".")
        root_key, nested_keys = path[0], path[1:]
        result = data.get(root_key, bypass_eval=True)
        for key in nested_keys:
            result = handle_repr(result.get(key, bypass_eval=True))
        return result

    try:
        return traverse_data(data, key_dotted_path)
    except (KeyError, AttributeError):
        if not default:
            raise KeyError(f"Path not found in data: {key_dotted_path!r}")
        return default


def get_debug_info(
    settings: Settings | LazySettings,
    verbosity: int = 0,
    key: str | None = None,
    shared: Any = False,
    *,
    restricted_keys: Sequence[str] | str | None = None,
    policy: RedactionPolicy | None = None,
    reveal: Any = False,
    redaction_text: str | None = None,
    **options: Any,
) -> dict:
    """Returns a dict with debug info about the settings object.

    Pass ``shared=True`` (or ``public=True``/``redact=True``) to get the
    shareable diagnostic: restricted values and fields derived from them are
    redacted while source/loader identifiers and ordering are preserved.
    """
    redaction_policy = resolve_policy(
        settings,
        shared=shared,
        restricted_keys=restricted_keys,
        policy=policy,
        reveal=reveal,
        redaction_text=redaction_text,
        options=options,
    )
    config = settings.__core__.config

    if key:
        verbosity = 2

    def filter_by_key(data: dict) -> dict:
        """If key is not None, filter dict keeping only the key"""
        if key and data:
            try:
                return {key: _get_data_by_key(data, key)}
            except KeyError:
                return {}
        return data

    def build_loading_history() -> list[dict]:
        _data = []
        for (
            source_metadata,
            source_data,
        ) in settings.loaded_by_loaders.items():
            _real_data = filter_by_key(source_data)
            if verbosity == 0:
                _data.append(
                    {
                        "loader": source_metadata.loader,
                        "identifier": source_metadata.identifier,
                        "data": len(_real_data),
                    }
                )
            elif verbosity == 1:
                _data.append(
                    {
                        "loader": source_metadata.loader,
                        "identifier": source_metadata.identifier,
                        "data": list(_real_data.keys()),
                    }
                )
            else:
                _data.append(
                    {
                        "loader": source_metadata.loader,
                        "identifier": source_metadata.identifier,
                        "data": _real_data,
                    }
                )
        return _data

    def build_loaded_hooks():
        _data = []
        for hook, hook_data in config.loaded_hooks.items():
            _real_data = filter_by_key(hook_data.get("post", {})) or {}
            if verbosity == 0:
                _data.append(
                    {
                        "hook": str(hook),
                        "data": len(_real_data),
                    }
                )
            elif verbosity == 1:
                _data.append(
                    {
                        "hook": str(hook),
                        "data": list(_real_data.keys()),
                    }
                )
            else:
                _data.append(
                    {
                        "hook": str(hook),
                        "data": _real_data,
                    }
                )
        return _data

    data = {
        "versions": {
            "dynaconf": version("dynaconf"),
        },
        "root_path": settings._root_path,
        "validators": [str(v) for v in settings.validators],
        "core_loaders": config.loaders,
        "loaded_files": config.loaded_files,
        "history": build_loading_history(),
        "post_hooks": [str(h) for h in config.post_hooks],
        "loaded_hooks": build_loaded_hooks(),
    }
    for name in ["django", "flask", "fastapi", "starlette"]:
        with suppress(PackageNotFoundError):
            data["versions"][name] = version(name)

    if settings.get("ENVIRONMENTS_FOR_DYNACONF"):
        environments = settings.get("ENVIRONMENTS_FOR_DYNACONF")
        if isinstance(environments, (list, tuple)):
            data["environments"] = list(environments)
        else:
            data["environments"] = environments
        data["loaded_envs"] = settings.loaded_envs

    if key:
        try:
            data["current"] = {key: settings.get(key)}
        except Exception:
            if redaction_policy is None:
                raise
            # Shared diagnostics must survive broken/lazy values; expose the
            # raw (non-evaluated) representation which is scrubbed below.
            with suppress(Exception):
                sep = settings.get("NESTED_SEPARATOR_FOR_DYNACONF", "__")
                data["current"] = {
                    key: _get_data_by_key(settings.store, key, sep=sep)
                }

    if redaction_policy is not None:
        data = redaction_policy.scrub(data)

    return data


def get_shared_debug_info(
    settings: Settings | LazySettings,
    verbosity: int = 0,
    key: str | None = None,
    **kwargs: Any,
) -> dict:
    """Return the redacted/shareable debug info."""
    kwargs.setdefault("shared", True)
    return get_debug_info(settings, verbosity, key, **kwargs)


get_shared_diagnostics = get_shared_debug_info
shared_debug_info = get_shared_debug_info
get_public_debug_info = get_shared_debug_info


def print_debug_info(
    settings: Settings | LazySettings,
    *,
    dumper: DumperPreset | DumperType | None = None,
    verbosity: int = 0,
    key: str | None = None,
    shared: Any = False,
    restricted_keys: Sequence[str] | str | None = None,
    policy: RedactionPolicy | None = None,
    reveal: Any = False,
    redaction_text: str | None = None,
    **options: Any,
):
    """Calls dumper with settings debug info"""
    dumper = dumper or "yaml"
    if isinstance(dumper, str):
        dumper = builtin_dumpers.get(dumper)
        if dumper is None:
            raise OutputFormatError(
                f"The desired format is not available: {dumper!r}"
            )

    data = get_debug_info(
        settings,
        verbosity,
        key,
        shared=shared,
        restricted_keys=restricted_keys,
        policy=policy,
        reveal=reveal,
        redaction_text=redaction_text,
        **options,
    )
    dumper(data, sys.stdout)
