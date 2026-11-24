"""
Controlled-extension policy for a CloudEvents event catalogue.

The SDK validates *syntax* (lower-case alphanumeric names, required attributes,
version-specific attributes).  It does not know which extensions are approved.
This module adds that decision as a pure function so the same logic can run in
producers, gateways, and CI, and so every decision can be logged as a record.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

# CloudEvents spec: lower-case ASCII letters and digits, at least one char.
# The SDK imposes the same rule with re.match(r"^[a-z0-9]+$", name).
_SYNTAX = re.compile(r"^[a-z0-9]+$")

# Attributes owned by the CloudEvents spec per specversion.  These are never
# "extensions", even when a sender puts them in an envelope of another version.
SPEC_ATTRIBUTES: dict[str, frozenset[str]] = {
    "1.0": frozenset(
        {
            "id",
            "source",
            "type",
            "specversion",
            "datacontenttype",
            "dataschema",
            "subject",
            "time",
        }
    ),
    "0.3": frozenset(
        {
            "id",
            "source",
            "type",
            "specversion",
            "datacontenttype",
            "datacontentencoding",
            "schemaurl",
            "subject",
            "time",
        }
    ),
}

# A version-owned attribute only means something in its own envelope version.
# In any other version it is, at best, an unknown custom attribute.
# name -> (owning specversion, successor name in the other version)
VERSION_ATTRIBUTE_ALIASES: dict[str, tuple[str, str | None]] = {
    "schemaurl": ("0.3", "dataschema"),
    "datacontentencoding": ("0.3", None),  # removed in 1.0, no successor
    "dataschema": ("1.0", "schemaurl"),
}


class Mode(str, Enum):
    """Rollout stage.  Every mode still emits a decision record."""

    OBSERVE = "observe"  # classify only; never gate
    SHADOW = "shadow"  # classify + compute would_accept; never gate
    ENFORCE = "enforce"  # reject anything whose would_accept is False


class ExtensionStatus(str, Enum):
    ADMITTED = "admitted"
    ALIASED = "aliased"
    LEGACY_QUARANTINED = "legacy-quarantined"
    VERSION_MISMATCH = "version-mismatch"
    UNKNOWN = "unknown"
    INVALID_SYNTAX = "invalid-syntax"
    RESERVED = "reserved"
    TYPE_DRIFT = "type-drift"
    UNSUPPORTED_BINDING = "unsupported-binding"


@dataclass(frozen=True)
class ExtensionSpec:
    """One catalogue entry.  A name can have different rules per specversion."""

    canonical_name: str
    owner: str
    versions: frozenset[str]
    value_types: frozenset[type]
    required: bool = False
    deprecated_in: str | None = None
    aliases: Mapping[str, str] | None = None

    def normalise(self, name: str) -> str:
        aliases = self.aliases or {}
        return aliases.get(name, name)


@dataclass(frozen=True)
class Decision:
    """An auditable outcome.  One record per extension, per stage.

    ``record_kind`` is deliberately separate from ``status`` so version drift
    and unknown extensions can be routed to different queues/owners.
    """

    stage: str
    specversion: str
    binding: str
    observed_name: str
    canonical_name: str | None
    status: ExtensionStatus
    record_kind: str
    would_accept: bool
    accepted: bool
    reason: str


class Catalogue:
    """Version-aware allow-list with alias migration and quarantine."""

    def __init__(
        self,
        extensions: list[ExtensionSpec],
        *,
        quarantined: Mapping[str, str] | None = None,
    ) -> None:
        self._by_name: dict[str, ExtensionSpec] = {}
        for spec in extensions:
            self._by_name[spec.canonical_name] = spec
            for alias in (spec.aliases or {}):
                self._by_name[alias] = spec
        # quarantined maps historical name -> replacement canonical name
        self._quarantined = dict(quarantined or {})

    def lookup(self, name: str) -> ExtensionSpec | None:
        return self._by_name.get(name)

    def evaluate(
        self,
        name: str,
        value: Any,
        specversion: str,
        *,
        binding: str,
        stage: str,
        mode: Mode = Mode.ENFORCE,
    ) -> Decision:
        """Classify one attribute name/value pair and apply the rollout mode.

        The classification is always computed so observe/shadow stages can
        compare decisions with enforce before anything is rejected.
        """

        def make(
            status: ExtensionStatus,
            reason: str,
            canonical: str | None = None,
            would_accept: bool = False,
            record_kind: str = "extension",
        ) -> Decision:
            return Decision(
                stage=stage,
                specversion=specversion,
                binding=binding,
                observed_name=name,
                canonical_name=canonical,
                status=status,
                record_kind=record_kind,
                would_accept=would_accept,
                accepted=True if mode is not Mode.ENFORCE else would_accept,
                reason=reason,
            )

        if name in SPEC_ATTRIBUTES.get(specversion, frozenset()):
            return make(
                ExtensionStatus.RESERVED,
                "name is a spec attribute for this specversion",
                canonical=name,
                record_kind="reserved",
            )

        if name in ("data", "data_base64"):
            return make(
                ExtensionStatus.RESERVED,
                "data envelope field",
                canonical=name,
                record_kind="reserved",
            )

        # Version-owned attributes placed in the wrong envelope.
        if name in VERSION_ATTRIBUTE_ALIASES:
            owner_version, successor = VERSION_ATTRIBUTE_ALIASES[name]
            if specversion != owner_version:
                target = successor or "drop"
                return make(
                    ExtensionStatus.VERSION_MISMATCH,
                    f"'{name}' belongs to specversion {owner_version}; "
                    f"for {specversion} expected {target}",
                    canonical=successor,
                    record_kind="version",
                )

        # Historical names are classified as legacy before syntax so they get
        # their own record stream and a rewrite target.  The SDK still cannot
        # construct these names; ingest adapters must rewrite them first.
        if name in self._quarantined:
            return make(
                ExtensionStatus.LEGACY_QUARANTINED,
                f"historical name; migrate to '{self._quarantined[name]}'",
                canonical=self._quarantined[name],
                would_accept=False,
                record_kind="legacy-extension",
            )

        if not name or not _SYNTAX.match(name):
            return make(
                ExtensionStatus.INVALID_SYNTAX,
                "SDK requires [a-z0-9]+; uppercase, '-', '_' are rejected",
                record_kind="invalid-syntax",
            )

        spec = self.lookup(name)
        if spec is None:
            return make(
                ExtensionStatus.UNKNOWN,
                "not in catalogue",
                record_kind="unknown-extension",
            )

        canonical = spec.normalise(name)
        if specversion not in spec.versions:
            return make(
                ExtensionStatus.VERSION_MISMATCH,
                f"extension is registered for {sorted(spec.versions)}, "
                f"not {specversion}",
                canonical=canonical,
                record_kind="version",
            )

        if not isinstance(value, tuple(spec.value_types)):
            return make(
                ExtensionStatus.TYPE_DRIFT,
                f"value type {type(value).__name__} is not allowed "
                f"({[t.__name__ for t in spec.value_types]}); binary bindings "
                "stringify, so cross-binding consumers drift",
                canonical=canonical,
                record_kind="type-drift",
            )

        if canonical != name:
            return make(
                ExtensionStatus.ALIASED,
                f"mapped '{name}' -> '{canonical}'",
                canonical=canonical,
                would_accept=True,
            )
        return make(
            ExtensionStatus.ADMITTED,
            "catalogue hit",
            canonical=canonical,
            would_accept=True,
        )
