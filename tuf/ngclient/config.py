# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Configuration options for ``Updater`` class."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Flag, unique
from typing import TYPE_CHECKING

from tuf.api.exceptions import EnvelopePolicyError

if TYPE_CHECKING:
    from collections.abc import Iterable


@unique
class EnvelopeType(Flag):
    """Configures deserialization and verification mode of TUF metadata.

    Args:
        METADATA: Traditional canonical JSON -based TUF Metadata.
        SIMPLE: Dead Simple Signing Envelope. (experimental)
    """

    METADATA = 1
    SIMPLE = 2


@dataclass(frozen=True)
class EnvelopeRule:
    """Selects exactly one envelope type for a role and version range.

    ``min_version`` is inclusive and ``max_version`` is inclusive; ``None``
    means the range is unbounded in that direction. A rule covers metadata
    only for the named role: there is no wildcard or implicit fallback.

    Args:
        role: Role name, e.g. "root" or "role1".
        envelope_type: The only envelope type allowed in this range.
        min_version: First metadata version covered by the rule.
        max_version: Last metadata version covered by the rule, or ``None``.

    Raises:
        ValueError: Invalid role, version range or envelope type.
    """

    role: str
    envelope_type: EnvelopeType
    min_version: int = 1
    max_version: int | None = None

    def __post_init__(self) -> None:
        if not self.role:
            raise ValueError("role must not be empty")
        if self.envelope_type not in (
            EnvelopeType.METADATA,
            EnvelopeType.SIMPLE,
        ):
            raise ValueError(
                "envelope_type must be EnvelopeType.METADATA or "
                "EnvelopeType.SIMPLE"
            )
        if self.min_version < 1:
            raise ValueError("min_version must be at least 1")
        if self.max_version is not None and self.max_version < self.min_version:
            raise ValueError("max_version must be >= min_version")

    def contains(self, version: int) -> bool:
        """Return whether ``version`` is in the rule's version range."""
        if version < self.min_version:
            return False
        return self.max_version is None or version <= self.max_version


class EnvelopeMigrationPolicy:
    """Caller-configured role/version based envelope migration policy.

    The policy is the only source of truth for envelope selection while a
    migration is active: for every loaded role version exactly one envelope
    type must be selected. There is no "try the other format on parse failure"
    behavior. A role/version that no rule covers, or that multiple rules
    cover, raises ``EnvelopePolicyError``.

    Args:
        rules: Envelope rules. Rules for the same role must not overlap.

    Raises:
        ValueError: ``rules`` is empty or contains overlapping rules.
    """

    def __init__(self, rules: Iterable[EnvelopeRule]) -> None:
        rules = list(rules)
        if not rules:
            raise ValueError("at least one envelope rule is required")

        by_role: dict[str, list[EnvelopeRule]] = {}
        for rule in rules:
            if not isinstance(rule, EnvelopeRule):
                raise TypeError("rules must contain EnvelopeRule instances")
            by_role.setdefault(rule.role, []).append(rule)

        for role, role_rules in by_role.items():
            ordered = sorted(role_rules, key=lambda r: r.min_version)
            previous: EnvelopeRule | None = None
            for rule in ordered:
                if previous is not None and (
                    previous.max_version is None
                    or rule.min_version <= previous.max_version
                ):
                    raise ValueError(
                        f"Overlapping envelope rules for role '{role}'"
                    )
                previous = rule

        self._rules = {role: tuple(rs) for role, rs in by_role.items()}

    def envelope_type_for(self, role: str, version: int) -> EnvelopeType:
        """Return the only envelope type allowed for ``role`` and ``version``.

        Args:
            role: Metadata role name.
            version: Metadata version.

        Raises:
            EnvelopePolicyError: No rule (or more than one rule) covers the
                role and version.
        """
        matches = [
            rule for rule in self._rules.get(role, ()) if rule.contains(version)
        ]
        if len(matches) != 1:
            detail = (
                "no migration rule covers this role and version"
                if not matches
                else "multiple migration rules cover this role and version"
            )
            raise EnvelopePolicyError(role, version, detail=detail)

        return matches[0].envelope_type


@dataclass
class UpdaterConfig:
    """Used to store ``Updater`` configuration.

    Args:
        max_root_rotations: Maximum number of root rotations.
        max_delegations: Maximum number of delegations.
        root_max_length: Maximum length of a root metadata file.
        timestamp_max_length: Maximum length of a timestamp metadata file.
        snapshot_max_length: Maximum length of a snapshot metadata file.
        targets_max_length: Maximum length of a targets metadata file.
        prefix_targets_with_hash: When `consistent snapshots
            <https://theupdateframework.github.io/specification/latest/#consistent-snapshots>`_
            are used, target download URLs are formed by prefixing the filename
            with a hash digest of file content by default. This can be
            overridden by setting ``prefix_targets_with_hash`` to ``False``.
        envelope_type: Configures deserialization and verification mode of TUF
            metadata. Per default, it is treated as traditional canonical JSON
            -based TUF Metadata.
        envelope_migration: Caller-configured role/version based envelope
            policy. When set, it selects the only allowed envelope type for
            every loaded metadata version; ``envelope_type`` must be left at
            its default value.
        app_user_agent: Application user agent, e.g. "MyApp/1.0.0". This will be
            prefixed to ngclient user agent when the default fetcher is used.
    """

    max_root_rotations: int = 256
    max_delegations: int = 32
    root_max_length: int = 512000  # bytes
    timestamp_max_length: int = 16384  # bytes
    snapshot_max_length: int = 2000000  # bytes
    targets_max_length: int = 5000000  # bytes
    prefix_targets_with_hash: bool = True
    envelope_type: EnvelopeType = EnvelopeType.METADATA
    envelope_migration: EnvelopeMigrationPolicy | None = None
    app_user_agent: str | None = None
