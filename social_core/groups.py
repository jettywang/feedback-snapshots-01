"""Framework-independent extraction and mapping of external memberships.

Membership synchronization is a three-way merge between locally assigned
groups, the memberships a provider reports now, and the grants a provider
recorded earlier.  The grant records keep ``provider`` and ``source`` so a
provider can remove only its own grants.  Records persisted before provenance
was recorded are reported separately and never modified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.utils import module_member

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

GroupTarget = str | int
"""A local group identifier, as accepted in ``GROUPS_MAP`` values."""

GroupSource = tuple[str, str]
"""A provider name and its membership source, such as a SAML IdP name."""

LEGACY_GROUP_SYNC = "legacy"
"""Keep the integration's previous behavior; do not sync groups in core."""

MANAGED_GROUP_SYNC = "managed"
"""Remove only grants recorded for the authenticating provider and source."""

GROUP_SYNC_MODES = (LEGACY_GROUP_SYNC, MANAGED_GROUP_SYNC)


@dataclass(frozen=True)
class GroupGrant:
    """One recorded grant of a local group by one provider source.

    ``provider`` and ``source`` are ``None`` for legacy records whose
    provenance was not recorded.  Legacy grants appear in
    :attr:`GroupSyncPlan.unidentified` and are never changed by synchronization.
    """

    target: GroupTarget
    provider: str | None
    source: str | None

    @property
    def identified(self) -> bool:
        """Return whether the record names both the provider and its source."""
        return bool(self.provider) and self.source is not None

    @property
    def group_source(self) -> GroupSource | None:
        """Return the provenance of an identified grant."""
        provider, source = self.provider, self.source
        if not provider or source is None:
            return None
        return provider, source


@dataclass(frozen=True)
class GroupSyncPlan:
    """Changes for one provider source, computed before storage is touched."""

    provider: str
    source: str
    desired: frozenset[GroupTarget]
    managed: frozenset[GroupTarget]
    additions: frozenset[GroupTarget]
    revocations: frozenset[GroupTarget]
    withheld_revocations: frozenset[GroupTarget]
    preserved: tuple[GroupGrant, ...]
    unidentified: tuple[GroupGrant, ...]
    partial: bool


def active_group_source(
    backend: BaseAuth[object], response: Mapping[str, Any]
) -> GroupSource:
    """Return the provenance used for grants recorded during this login."""
    provider = backend.name
    source = backend.get_group_source(response)
    if not isinstance(provider, str) or not provider or not isinstance(source, str):
        raise AuthConfigurationError(
            backend,
            "Group synchronization requires provider and source names",
            code="invalid_setting",
            parameter="group source",
            stage="pipeline",
        )
    return provider, source


def _valid_target(target: object) -> bool:
    return (
        not isinstance(target, bool)
        and isinstance(target, str | int)
        and (not isinstance(target, str) or bool(target))
    )


def normalize_group_grants(
    backend: BaseAuth[object], grants: Iterable[object]
) -> tuple[GroupGrant, ...]:
    """Validate storage records without trusting their concrete type."""
    normalized: dict[GroupGrant, None] = {}
    for grant in grants:
        target = getattr(grant, "target", None)
        provider = getattr(grant, "provider", None)
        source = getattr(grant, "source", None)
        if not _valid_target(target):
            raise AuthConfigurationError(
                backend,
                "Invalid local group grant target",
                code="invalid_setting",
                parameter="group storage",
                stage="pipeline",
            )
        if not (provider is None or isinstance(provider, str)) or not (
            source is None or isinstance(source, str)
        ):
            raise AuthConfigurationError(
                backend,
                "Invalid local group grant provenance",
                code="invalid_setting",
                parameter="group storage",
                stage="pipeline",
            )
        normalized[
            GroupGrant(cast("GroupTarget", target), provider or None, source)
        ] = None
    return tuple(normalized)


def group_complete(backend: BaseAuth[object], response: Mapping[str, Any]) -> bool:
    """Return whether the current membership list is a complete snapshot.

    Completeness defaults to false so an incomplete or truncated list never
    revokes access by omission.  Providers whose claim is a full snapshot must
    set ``GROUPS_COMPLETE`` (or a per-IdP equivalent), or override
    ``get_group_complete()``, before synchronization treats an absent group as
    an explicit revocation.
    """
    configured = backend.get_group_setting("GROUPS_COMPLETE", response, None)
    if configured is not None:
        if not isinstance(configured, bool):
            raise AuthConfigurationError(
                backend,
                code="invalid_setting",
                parameter="GROUPS_COMPLETE",
                stage="pipeline",
            )
        return configured
    complete = backend.get_group_complete(response)
    if not isinstance(complete, bool):
        raise AuthConfigurationError(
            backend,
            code="invalid_setting",
            parameter="GROUPS_COMPLETE",
            stage="pipeline",
        )
    return complete


def group_sync_mode(backend: BaseAuth[object], response: Mapping[str, Any]) -> str:
    """Resolve and validate the opt-in synchronization mode."""
    mode = backend.get_group_setting("GROUPS_SYNC_MODE", response, LEGACY_GROUP_SYNC)
    if not isinstance(mode, str) or mode not in GROUP_SYNC_MODES:
        raise AuthConfigurationError(
            backend,
            code="invalid_setting",
            parameter="GROUPS_SYNC_MODE",
            stage="pipeline",
        )
    return mode


def configured_group_key(backend: BaseAuth[object]) -> str | None:
    """Validate the configured literal claim name before accessing claims."""
    key = backend.setting("GROUPS_KEY")
    if key is not None and (not isinstance(key, str) or not key):
        raise AuthConfigurationError(
            backend, code="invalid_setting", parameter="GROUPS_KEY", stage="pipeline"
        )
    return key


def check_group_overage(
    backend: BaseAuth[object], response: Mapping[str, Any], key: str
) -> None:
    """Never use an incomplete Entra group claim as an authoritative list."""
    if key != "groups":
        return
    claim_names = response.get("_claim_names", {})
    if not isinstance(claim_names, dict):
        raise AuthResponseError(
            backend, code="invalid_claim", claim="_claim_names", stage="user_info"
        )
    if "hasgroups" in response or "groups" in claim_names:
        raise AuthResponseError(
            backend,
            "Group membership exceeds the token limit",
            code="invalid_claim",
            claim="groups",
            stage="user_info",
        )


def read_groups(
    backend: BaseAuth[object],
    response: Mapping[str, Any],
    key: str,
    *,
    missing_as_empty: object = False,
    singleton: bool = False,
) -> list[str]:
    """Read an explicitly selected claim without conflating missing and empty."""
    if not isinstance(key, str) or not key:
        raise AuthConfigurationError(
            backend, code="invalid_setting", parameter="GROUPS_KEY", stage="pipeline"
        )
    if not isinstance(missing_as_empty, bool):
        raise AuthConfigurationError(
            backend,
            code="invalid_setting",
            parameter="GROUPS_MISSING_AS_EMPTY",
            stage="pipeline",
        )
    check_group_overage(backend, response, key)
    if key not in response:
        if missing_as_empty:
            return []
        raise AuthResponseError(
            backend, code="missing_claim", claim=key, stage="user_info"
        )
    value = response[key]
    if singleton and isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or any(
        not isinstance(group, str) or not group for group in value
    ):
        raise AuthResponseError(
            backend, code="invalid_claim", claim=key, stage="user_info"
        )
    return list(dict.fromkeys(value))


def validate_group_mapping(
    backend: BaseAuth[object], mapping: Any
) -> dict[str, list[str | int]]:
    """Validate portable mapping syntax; strategies validate local target types."""
    if not isinstance(mapping, dict) or any(
        not isinstance(key, str)
        or not key
        or not isinstance(targets, list)
        or any(
            isinstance(target, bool)
            or not isinstance(target, (str, int))
            or (isinstance(target, str) and not target)
            for target in targets
        )
        for key, targets in mapping.items()
    ):
        raise AuthConfigurationError(
            backend, code="invalid_setting", parameter="GROUPS_MAP", stage="pipeline"
        )
    return mapping


def group_sync_targets(
    backend: BaseAuth[object],
    groups: list[str] | None,
    response: dict[str, Any],
    *,
    allow_shared: bool = False,
) -> tuple[set[str | int], set[str | int]]:
    """Resolve managed/desired targets and reject competing provider ownership.

    Set ``allow_shared`` when provenance is recorded for every grant.  Then
    several sources may grant the same local group, and removing one source's
    grant leaves the others intact.
    """
    mapping = validate_group_mapping(
        backend, backend.get_group_setting("GROUPS_MAP", response, {})
    )
    if not mapping:
        return set(), set()
    if groups is None:
        raise AuthConfigurationError(
            backend,
            code="missing_setting",
            parameter="group extraction",
            stage="pipeline",
        )
    managed = {target for targets in mapping.values() for target in targets}
    desired = {target for group in groups for target in mapping.get(group, [])}
    if allow_shared:
        return desired, managed
    active_owner = (backend.name, backend.get_group_source(response))
    owners: dict[str | int, tuple[str, str]] = dict.fromkeys(managed, active_owner)
    backends = [backend]
    for path in backend.strategy.get_backends():
        backend_class = module_member(path)
        if issubclass(backend_class, BaseAuth) and backend_class.name != backend.name:
            backends.append(backend_class(backend.strategy))
    for candidate in backends:
        for source, candidate_mapping in candidate.get_group_mappings():
            candidate_mapping = validate_group_mapping(candidate, candidate_mapping)
            owner = (candidate.name, source)
            for targets in candidate_mapping.values():
                for target in targets:
                    if target in owners and owners[target] != owner:
                        raise AuthConfigurationError(
                            backend,
                            "A local group is managed by multiple identity providers",
                            code="invalid_setting",
                            parameter="GROUPS_MAP",
                            stage="pipeline",
                        )
                    owners[target] = owner
    return desired, managed


def plan_group_sync(
    backend: BaseAuth[object],
    groups: list[str] | None,
    response: dict[str, Any],
    grants: Iterable[object],
) -> GroupSyncPlan:
    """Compute one source's grant changes without modifying storage.

    Absence of a group in an incomplete snapshot is not evidence of
    revocation, so those candidates are reported in ``withheld_revocations``.
    Grants without provenance are reported in ``unidentified`` and never
    changed.
    """
    desired, managed = group_sync_targets(backend, groups, response, allow_shared=True)
    provider, source = active_group_source(backend, response)
    records = normalize_group_grants(backend, grants)
    complete = group_complete(backend, response)
    active: GroupSource = (provider, source)
    ours = {grant.target for grant in records if grant.group_source == active}
    additions = desired - ours
    absent = ours - desired
    revocations = absent if complete else set()
    withheld = set() if complete else absent
    preserved = tuple(
        grant
        for grant in records
        if grant.identified and grant.group_source != active and grant.target in absent
    )
    unidentified = tuple(grant for grant in records if not grant.identified)
    return GroupSyncPlan(
        provider=provider,
        source=source,
        desired=frozenset(desired),
        managed=frozenset(managed),
        additions=frozenset(additions),
        revocations=frozenset(revocations),
        withheld_revocations=frozenset(withheld),
        preserved=preserved,
        unidentified=unidentified,
        partial=not complete,
    )
