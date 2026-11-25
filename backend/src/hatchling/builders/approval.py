from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

#: A membership was added to the build data.
OPERATION_ADD = "add"
#: An existing membership was moved to a different distribution path.
OPERATION_RELOCATE = "relocate"
#: A membership was removed from the build data.
OPERATION_CLEAN = "clean"

OPERATIONS = frozenset((OPERATION_ADD, OPERATION_RELOCATE, OPERATION_CLEAN))

# Build data fields that are mappings of a source path to a distribution path.
GUARDED_MAPPING_FIELDS = frozenset(
    ("force_include", "force_include_editable", "shared_data", "shared_scripts", "extra_metadata")
)
# Build data fields that are plain lists of membership patterns.
GUARDED_LIST_FIELDS = frozenset(("artifacts", "sbom_files"))
GUARDED_FIELDS = frozenset(GUARDED_MAPPING_FIELDS | GUARDED_LIST_FIELDS)


def normalize_member_path(path: str) -> str:
    """Normalize a distribution path so approvals match regardless of platform separators."""
    return str(path).replace(os.sep, "/").strip("/")


class HookApprovalError(PermissionError):
    """Raised when a managed build hook modifies membership that was not approved for the target."""


@dataclass(frozen=True)
class HookOperation:
    """A single membership modification attempted by a build hook."""

    hook: str
    field: str
    kind: str
    source: str
    path: str
    managed: bool
    applied: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "hook": self.hook,
            "field": self.field,
            "kind": self.kind,
            "source": self.source,
            "path": self.path,
            "managed": self.managed,
            "applied": self.applied,
        }


@dataclass
class BuildReceipt:
    """The record of everything a single target build's hooks did to its membership."""

    target: str
    version: str
    status: str = "success"
    error: str | None = None
    operations: list[HookOperation] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)

    @property
    def applied_operations(self) -> list[HookOperation]:
        return [operation for operation in self.operations if operation.applied]

    @property
    def denied_operations(self) -> list[HookOperation]:
        return [operation for operation in self.operations if not operation.applied]

    def operations_for(self, hook_name: str) -> list[HookOperation]:
        return [operation for operation in self.operations if operation.hook == hook_name]

    def mark_failed(self, error: BaseException) -> None:
        self.status = "failed"
        self.error = str(error) or error.__class__.__name__

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "version": self.version,
            "status": self.status,
            "error": self.error,
            "operations": [operation.as_dict() for operation in self.operations],
            "result": self.result,
        }


class ApprovalPolicy:
    """The membership changes that a managed hook is permitted to make for a given target."""

    def __init__(
        self,
        *,
        add: tuple[tuple[str, str | None], ...] = (),
        relocate: tuple[tuple[str, str | None], ...] = (),
        clean: tuple[tuple[str, str | None], ...] = (),
    ) -> None:
        self._rules: dict[str, tuple[tuple[str, str | None], ...]] = {
            OPERATION_ADD: add,
            OPERATION_RELOCATE: relocate,
            OPERATION_CLEAN: clean,
        }

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> ApprovalPolicy:
        approvals = config.get("approvals", {})
        if not isinstance(approvals, Mapping):
            message = "Hook option `approvals` must be a table"
            raise TypeError(message)

        buckets: dict[str, tuple[tuple[str, str | None], ...]] = {}
        for kind in OPERATIONS:
            entries = approvals.get(kind, [])
            if not isinstance(entries, list):
                message = f"Hook approval `{kind}` must be an array"
                raise TypeError(message)

            rules: list[tuple[str, str | None]] = []
            for index, entry in enumerate(entries, 1):
                if isinstance(entry, str):
                    if not entry:
                        message = f"Hook approval `{kind}` entry #{index} cannot be an empty string"
                        raise ValueError(message)
                    rules.append((normalize_member_path(entry), None))
                elif isinstance(entry, Mapping):
                    raw_path = entry.get("path")
                    if not isinstance(raw_path, str) or not raw_path:
                        message = f"Hook approval `{kind}` entry #{index} requires a non-empty `path` string"
                        raise ValueError(message)

                    raw_source = entry.get("source")
                    if raw_source is not None and not isinstance(raw_source, str):
                        message = f"Hook approval `{kind}` entry #{index} option `source` must be a string"
                        raise TypeError(message)

                    source = normalize_member_path(raw_source) if raw_source else None
                    rules.append((normalize_member_path(raw_path), source))
                else:
                    message = f"Hook approval `{kind}` entry #{index} must be a string or a table"
                    raise TypeError(message)

            buckets[kind] = tuple(rules)

        return cls(add=buckets[OPERATION_ADD], relocate=buckets[OPERATION_RELOCATE], clean=buckets[OPERATION_CLEAN])

    def allows(self, kind: str, *, source: str, path: str) -> bool:
        normalized_source = normalize_member_path(source)
        normalized_path = normalize_member_path(path)
        source_basename = normalized_source.rsplit("/", 1)[-1]
        for rule_path, rule_source in self._rules[kind]:
            if rule_path != normalized_path:
                continue

            # A rule without a source constraint matches any source. Otherwise the source must match either the
            # full normalized source or, for generated files living in temporary/absolute locations, its basename.
            if rule_source is None or rule_source in {normalized_source, source_basename}:
                return True

        return False


class ApprovalController:
    """Coordinates the active hook, its policy and the receipt for one target build."""

    def __init__(self, target: str, version: str, policies: Mapping[str, ApprovalPolicy]) -> None:
        self.receipt = BuildReceipt(target=target, version=version)
        self._policies = dict(policies)
        self.current_hook = ""

    def gate(self, field: str, kind: str, *, source: str, path: str) -> None:
        hook_name = self.current_hook
        managed = hook_name in self._policies
        normalized_source = normalize_member_path(source)
        normalized_path = normalize_member_path(path)
        allowed = (not managed) or self._policies[hook_name].allows(kind, source=source, path=path)

        self.receipt.operations.append(
            HookOperation(
                hook=hook_name,
                field=field,
                kind=kind,
                source=normalized_source,
                path=normalized_path,
                managed=managed,
                applied=allowed,
            )
        )

        if not allowed:
            message = (
                f"Managed build hook `{hook_name}` is not approved to {kind} `{normalized_path}` "
                f"in field `{field}` for target `{self.receipt.target}`"
            )
            raise HookApprovalError(message)


class ApprovedList(list):
    def __init__(self, field: str, controller: ApprovalController, values: Iterable[Any]) -> None:
        super().__init__(values)
        self.__field = field
        self.__controller = controller

    def __record(self, kind: str, value: Any) -> None:
        text = str(value)
        self.__controller.gate(self.__field, kind, source=text, path=text)

    def append(self, value: Any) -> None:
        self.__record(OPERATION_ADD, value)
        super().append(value)

    def extend(self, iterable: Iterable[Any]) -> None:
        for value in list(iterable):
            self.__record(OPERATION_ADD, value)
        super().extend(iterable)

    def insert(self, index: int, value: Any) -> None:
        self.__record(OPERATION_ADD, value)
        super().insert(index, value)

    def remove(self, value: Any) -> None:
        self.__record(OPERATION_CLEAN, value)
        super().remove(value)

    def pop(self, index: int = -1) -> Any:  # type: ignore[override]
        value = self[index]
        self.__record(OPERATION_CLEAN, value)
        return super().pop(index)

    def clear(self) -> None:
        for value in list(self):
            self.__record(OPERATION_CLEAN, value)
        super().clear()

    def __iadd__(self, other: Iterable[Any]) -> ApprovedList:  # type: ignore[override]
        self.extend(other)
        return self

    def __setitem__(self, index: Any, value: Any) -> None:
        if isinstance(index, slice):
            for old_value in self[index]:
                self.__record(OPERATION_CLEAN, old_value)
            for new_value in value:
                self.__record(OPERATION_ADD, new_value)
        else:
            self.__record(OPERATION_CLEAN, self[index])
            self.__record(OPERATION_ADD, value)

        super().__setitem__(index, value)

    def __delitem__(self, index: Any) -> None:
        if isinstance(index, slice):
            for old_value in self[index]:
                self.__record(OPERATION_CLEAN, old_value)
        else:
            self.__record(OPERATION_CLEAN, self[index])

        super().__delitem__(index)


class ApprovedMapping(dict):
    def __init__(self, field: str, controller: ApprovalController, values: Mapping[str, str]) -> None:
        super().__init__(values)
        self.__field = field
        self.__controller = controller

    def __record(self, kind: str, source: str, path: str) -> None:
        self.__controller.gate(self.__field, kind, source=source, path=path)

    def __setitem__(self, source: str, path: str) -> None:
        if source in self:
            if self[source] != path:
                self.__record(OPERATION_RELOCATE, source, path)
        else:
            self.__record(OPERATION_ADD, source, path)

        super().__setitem__(source, path)

    def __delitem__(self, source: str) -> None:
        self.__record(OPERATION_CLEAN, source, self[source])
        super().__delitem__(source)

    def pop(self, source: str, *default: Any) -> Any:
        if source in self:
            # Gate before mutating so a denial leaves the mapping untouched.
            self.__record(OPERATION_CLEAN, source, self[source])
        return super().pop(source, *default)

    def popitem(self) -> tuple[str, str]:
        source, path = super().popitem()
        try:
            self.__record(OPERATION_CLEAN, source, path)
        except BaseException:
            # Roll back so a denied popitem restores the original state.
            super().__setitem__(source, path)
            raise
        return source, path

    def clear(self) -> None:
        # Gate every removal before any mutation so a single denial aborts the whole operation.
        for source, path in list(self.items()):
            self.__record(OPERATION_CLEAN, source, path)
        super().clear()

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        if args:
            if len(args) > 1:
                message = "update expected at most 1 argument"
                raise TypeError(message)
            candidate = args[0]
            items = candidate.items() if hasattr(candidate, "items") else candidate
        else:
            items = ()

        for source, path in list(items):
            self[source] = path

        for source, path in kwargs.items():
            self[source] = path

    def setdefault(self, source: str, default: str | None = None) -> str:  # type: ignore[override]
        if source not in self:
            self[source] = default if default is not None else ""
        return self[source]


class ManagedBuildData(dict):
    """A build data mapping whose membership fields enforce per-target hook approvals."""

    def __init__(self, raw: Mapping[str, Any], controller: ApprovalController) -> None:
        super().__init__()
        self.__controller = controller
        for key, value in raw.items():
            self[key] = value

    @property
    def controller(self) -> ApprovalController:
        return self.__controller

    def __wrap(self, key: str, value: Any) -> Any:
        if key in GUARDED_MAPPING_FIELDS and not isinstance(value, ApprovedMapping):
            return ApprovedMapping(key, self.__controller, value)

        if key in GUARDED_LIST_FIELDS and not isinstance(value, ApprovedList):
            return ApprovedList(key, self.__controller, value)

        return value

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, self.__wrap(key, value))

    def snapshot(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {}
        for key in GUARDED_FIELDS:
            if key in self:
                value = self[key]
                snapshot[key] = dict(value) if isinstance(value, dict) else list(value)

        return snapshot
