"""Metadata-only retention inventory helpers for KV v2.

The helpers in this module intentionally use only the KV v2 metadata endpoints
(``read_secret_metadata`` and, for mount discovery, ``list_secrets``).  They
never call ``read_secret`` or ``read_secret_version`` and therefore cannot
place secret values in an audit report.
"""

from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from hvac import exceptions
from hvac.api.secrets_engines.kv_v2 import DEFAULT_MOUNT_POINT


class VersionStatus(str, Enum):
    """The state of one KV v2 version as reported by its metadata."""

    ACCESSIBLE = "accessible"
    SOFT_DELETED = "soft_deleted"
    DESTROYED = "destroyed"
    UNVERIFIABLE = "unverifiable"


class UnverifiableReason(str, Enum):
    """Why a version entry could not be classified safely."""

    MISSING_DESTROYED = "missing_destroyed"
    INVALID_DESTROYED = "invalid_destroyed"
    MISSING_DELETION_TIME = "missing_deletion_time"
    INVALID_DELETION_TIME = "invalid_deletion_time"
    INVALID_VERSION_METADATA = "invalid_version_metadata"


class MetadataAccessStatus(str, Enum):
    """Status for a metadata read or a mount discovery operation."""

    OK = "ok"
    FORBIDDEN = "forbidden"
    UNAUTHORIZED = "unauthorized"
    NOT_FOUND = "not_found"
    INVALID_REQUEST = "invalid_request"
    VAULT_ERROR = "vault_error"
    MALFORMED_METADATA = "malformed_metadata"
    UNEXPECTED_ERROR = "unexpected_error"

    LIST_FORBIDDEN = "list_forbidden"
    LIST_UNAUTHORIZED = "list_unauthorized"
    LIST_NOT_FOUND = "list_not_found"
    LIST_INVALID_REQUEST = "list_invalid_request"
    LIST_VAULT_ERROR = "list_vault_error"
    LIST_MALFORMED_METADATA = "list_malformed_metadata"
    LIST_UNEXPECTED_ERROR = "list_unexpected_error"


@dataclass(frozen=True)
class RetentionPolicy:
    """Rules used to decide which existing versions belong in the inventory.

    ``max_versions`` is an optional explicit cap.  When it is omitted, a
    positive ``max_versions`` value from the secret's own metadata is used.  A
    zero or missing metadata value means that no cap can be verified from
    metadata alone, so all non-destroyed versions are reported.

    Soft-deleted versions still exist and can be undeleted, so they are in the
    inventory by default.  They remain distinguishable through their status.
    """

    max_versions: Optional[int] = None
    include_soft_deleted: bool = True

    def __post_init__(self):
        if self.max_versions is not None:
            if (
                isinstance(self.max_versions, bool)
                or not isinstance(self.max_versions, int)
                or self.max_versions < 1
            ):
                raise ValueError("max_versions must be a positive integer or None")


@dataclass(frozen=True)
class VersionRecord:
    """One classified version entry.  No secret data is retained here."""

    version: int
    status: VersionStatus
    reason: Optional[UnverifiableReason] = None


@dataclass(frozen=True)
class PathResult:
    """Metadata results for one secret path."""

    path: str
    access_status: MetadataAccessStatus
    versions: Tuple[VersionRecord, ...] = ()
    retained_versions: Tuple[int, ...] = ()
    accessible_versions: Tuple[int, ...] = ()
    labels: Mapping[str, Any] = field(default_factory=dict)
    effective_max_versions: Optional[int] = None
    error_type: Optional[str] = None

    @property
    def verifiable(self) -> bool:
        """Whether metadata for this path was read and shaped correctly."""

        return self.access_status is MetadataAccessStatus.OK


@dataclass(frozen=True)
class RetentionReport:
    """A sanitized, metadata-only retention report."""

    mount_point: str
    policy: RetentionPolicy
    paths: Tuple[PathResult, ...]

    @property
    def inventory(self) -> Dict[str, Tuple[int, ...]]:
        """The minimal ``path -> existing versions`` inventory."""

        return {
            result.path: result.retained_versions
            for result in self.paths
            if result.access_status is MetadataAccessStatus.OK
        }

    @property
    def accessible(self) -> Dict[str, Tuple[int, ...]]:
        """Versions that are present and currently readable without undelete."""

        return {
            result.path: result.accessible_versions
            for result in self.paths
            if result.access_status is MetadataAccessStatus.OK
        }

    @property
    def unverifiable(self) -> Tuple[Dict[str, Any], ...]:
        """One entry for every path or version that could not be verified."""

        issues: List[Dict[str, Any]] = []
        for result in self.paths:
            if result.access_status is not MetadataAccessStatus.OK:
                issue = {
                    "path": result.path,
                    "status": result.access_status.value,
                }
                if result.error_type is not None:
                    issue["error_type"] = result.error_type
                issues.append(issue)
            for record in result.versions:
                if record.status is VersionStatus.UNVERIFIABLE:
                    issues.append(
                        {
                            "path": result.path,
                            "version": record.version,
                            "status": record.status.value,
                            "reason": record.reason.value
                            if record.reason is not None
                            else None,
                        }
                    )
        return tuple(issues)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the report without raw metadata or unapproved labels."""

        report = {
            "mount_point": self.mount_point,
            "policy": {
                "max_versions": self.policy.max_versions,
                "include_soft_deleted": self.policy.include_soft_deleted,
            },
            "inventory": {
                path: list(versions) for path, versions in self.inventory.items()
            },
            "accessible": {
                path: list(versions) for path, versions in self.accessible.items()
            },
            "paths": [],
            "unverifiable": [dict(issue) for issue in self.unverifiable],
        }

        for result in self.paths:
            path_data = {
                "path": result.path,
                "status": result.access_status.value,
                "versions": [],
                "labels": dict(result.labels),
            }
            if result.effective_max_versions is not None:
                path_data["effective_max_versions"] = result.effective_max_versions
            if result.error_type is not None:
                path_data["error_type"] = result.error_type

            for record in result.versions:
                version_data = {
                    "version": record.version,
                    "status": record.status.value,
                }
                if record.reason is not None:
                    version_data["reason"] = record.reason.value
                path_data["versions"].append(version_data)

            report["paths"].append(path_data)

        return report


class KvV2RetentionAuditor:
    """Build a minimal retention inventory from KV v2 metadata only.

    :param client: An ``hvac.Client`` instance, an object exposing
        ``secrets.kv.v2``, or a ``KvV2``-compatible object.
    :param mount_point: The KV v2 mount path, using the same ``mount_point``
        convention as :class:`hvac.api.secrets_engines.kv_v2.KvV2`.
    :param approved_custom_metadata_keys: Custom metadata keys that may appear
        in the report.  All other custom metadata is discarded.
    :param policy: Optional retention policy.  Defaults to
        :class:`RetentionPolicy`.
    """

    def __init__(
        self,
        client: Any,
        mount_point: str = DEFAULT_MOUNT_POINT,
        approved_custom_metadata_keys: Optional[Iterable[str]] = None,
        policy: Optional[RetentionPolicy] = None,
    ):
        if not isinstance(mount_point, str) or not mount_point.strip("/"):
            raise ValueError("mount_point must be a non-empty path string")

        self._kv = self._resolve_kv_v2(client)
        self.mount_point = mount_point.strip("/")
        self.policy = policy if policy is not None else RetentionPolicy()
        self.approved_custom_metadata_keys = self._normalize_label_keys(
            approved_custom_metadata_keys
        )

    @staticmethod
    def _resolve_kv_v2(client: Any) -> Any:
        try:
            kv_v2 = client.secrets.kv.v2
        except AttributeError:
            kv_v2 = client

        if not callable(getattr(kv_v2, "read_secret_metadata", None)):
            raise TypeError(
                "client must expose read_secret_metadata via client.secrets.kv.v2 "
                "or directly"
            )
        return kv_v2

    @staticmethod
    def _normalize_label_keys(keys: Optional[Iterable[str]]) -> Tuple[str, ...]:
        if keys is None:
            return ()
        if isinstance(keys, str):
            keys = (keys,)

        normalized = []
        for key in keys:
            if not isinstance(key, str) or not key:
                raise ValueError(
                    "approved_custom_metadata_keys must be non-empty strings"
                )
            if key not in normalized:
                normalized.append(key)
        return tuple(normalized)

    def audit(self, paths: Iterable[str]) -> RetentionReport:
        """Audit an explicit collection of secret paths.

        Only ``read_secret_metadata`` is called for each path, so callers can
        allow exactly the metadata endpoint in their Vault policy.
        """

        if isinstance(paths, str):
            paths = (paths,)

        normalized_paths = []
        for path in paths:
            normalized = self._normalize_path(path)
            if normalized not in normalized_paths:
                normalized_paths.append(normalized)

        results = tuple(self._read_path(path) for path in normalized_paths)
        return RetentionReport(
            mount_point=self.mount_point,
            policy=self.policy,
            paths=results,
        )

    def audit_paths(self, paths: Iterable[str]) -> RetentionReport:
        """Alias for :meth:`audit`."""

        return self.audit(paths)

    def audit_mount(self, root: str = "") -> RetentionReport:
        """Discover secret paths with metadata LIST calls, then audit them.

        ``list_secrets`` targets ``/{mount_point}/metadata/{path}`` and is a
        metadata-only operation.  Discovery failures are reported as
        ``list_*`` statuses instead of being mixed with metadata-read errors.
        """

        if not callable(getattr(self._kv, "list_secrets", None)):
            raise TypeError("client does not expose list_secrets for mount discovery")

        root = self._normalize_root(root)
        discovered, discovery_issues = self._discover_paths(root)
        results = list(discovery_issues)
        results.extend(self._read_path(path) for path in discovered)

        return RetentionReport(
            mount_point=self.mount_point,
            policy=self.policy,
            paths=tuple(results),
        )

    def _read_path(self, path: str) -> PathResult:
        try:
            response = self._kv.read_secret_metadata(
                path=path,
                mount_point=self.mount_point,
            )
        except exceptions.Forbidden as exc:
            return self._error_result(path, MetadataAccessStatus.FORBIDDEN, exc)
        except exceptions.Unauthorized as exc:
            return self._error_result(path, MetadataAccessStatus.UNAUTHORIZED, exc)
        except exceptions.InvalidPath as exc:
            return self._error_result(path, MetadataAccessStatus.NOT_FOUND, exc)
        except exceptions.InvalidRequest as exc:
            return self._error_result(path, MetadataAccessStatus.INVALID_REQUEST, exc)
        except exceptions.VaultError as exc:
            return self._error_result(path, MetadataAccessStatus.VAULT_ERROR, exc)
        except Exception as exc:  # noqa: BLE001 - report, do not abort the audit
            return self._error_result(path, MetadataAccessStatus.UNEXPECTED_ERROR, exc)

        data = response.get("data") if isinstance(response, MappingABC) else None
        if not isinstance(data, MappingABC):
            return self._malformed_result(path)

        raw_versions = data.get("versions")
        if not isinstance(raw_versions, MappingABC):
            return self._malformed_result(path)

        versions = []
        for raw_version, version_metadata in raw_versions.items():
            version = self._parse_version_number(raw_version)
            if version is None:
                return self._malformed_result(path)
            versions.append(self._classify_version(version, version_metadata))
        versions.sort(key=lambda record: record.version)

        effective_max_versions = self._effective_max_versions(data)
        retained_versions = self._retained_versions(versions, effective_max_versions)
        accessible_versions = tuple(
            record.version
            for record in versions
            if record.status is VersionStatus.ACCESSIBLE
        )

        return PathResult(
            path=path,
            access_status=MetadataAccessStatus.OK,
            versions=tuple(versions),
            retained_versions=retained_versions,
            accessible_versions=accessible_versions,
            labels=self._approved_labels(data),
            effective_max_versions=effective_max_versions,
        )

    @staticmethod
    def _normalize_path(path: Any) -> str:
        if not isinstance(path, str):
            raise ValueError("path must be a string")
        normalized = path.strip("/")
        if not normalized:
            raise ValueError("path must be a non-empty string")
        return normalized

    @staticmethod
    def _normalize_root(root: Any) -> str:
        if not isinstance(root, str):
            raise ValueError("root must be a string")
        return root.strip("/")

    @staticmethod
    def _join_path(parent: str, child: str) -> str:
        parent = parent.strip("/")
        child = child.strip("/")
        if parent and child:
            return f"{parent}/{child}"
        return parent or child

    @staticmethod
    def _parse_version_number(raw_version: Any) -> Optional[int]:
        if isinstance(raw_version, bool):
            return None
        try:
            version = int(raw_version)
        except (TypeError, ValueError):
            return None
        if version < 1 or str(version) != str(raw_version):
            return None
        return version

    @staticmethod
    def _classify_version(version: int, metadata: Any) -> VersionRecord:
        if not isinstance(metadata, MappingABC):
            return VersionRecord(
                version=version,
                status=VersionStatus.UNVERIFIABLE,
                reason=UnverifiableReason.INVALID_VERSION_METADATA,
            )

        if "destroyed" not in metadata:
            return VersionRecord(
                version=version,
                status=VersionStatus.UNVERIFIABLE,
                reason=UnverifiableReason.MISSING_DESTROYED,
            )

        destroyed = metadata["destroyed"]
        if not isinstance(destroyed, bool):
            return VersionRecord(
                version=version,
                status=VersionStatus.UNVERIFIABLE,
                reason=UnverifiableReason.INVALID_DESTROYED,
            )

        if destroyed:
            return VersionRecord(version=version, status=VersionStatus.DESTROYED)

        if "deletion_time" not in metadata:
            return VersionRecord(
                version=version,
                status=VersionStatus.UNVERIFIABLE,
                reason=UnverifiableReason.MISSING_DELETION_TIME,
            )

        deletion_time = metadata["deletion_time"]
        if deletion_time is None:
            deletion_time = ""
        if not isinstance(deletion_time, str):
            return VersionRecord(
                version=version,
                status=VersionStatus.UNVERIFIABLE,
                reason=UnverifiableReason.INVALID_DELETION_TIME,
            )

        return VersionRecord(
            version=version,
            status=VersionStatus.SOFT_DELETED
            if deletion_time
            else VersionStatus.ACCESSIBLE,
        )

    def _effective_max_versions(self, data: Mapping[str, Any]) -> Optional[int]:
        if self.policy.max_versions is not None:
            return self.policy.max_versions

        raw_max_versions = data.get("max_versions")
        if (
            isinstance(raw_max_versions, int)
            and not isinstance(raw_max_versions, bool)
            and raw_max_versions > 0
        ):
            return raw_max_versions
        return None

    def _retained_versions(
        self,
        versions: Sequence[VersionRecord],
        effective_max_versions: Optional[int],
    ) -> Tuple[int, ...]:
        ordered_versions = sorted(versions, key=lambda record: record.version)
        if effective_max_versions is not None:
            ordered_versions = ordered_versions[-effective_max_versions:]

        retained = [
            record
            for record in ordered_versions
            if record.status is VersionStatus.ACCESSIBLE
            or (
                record.status is VersionStatus.SOFT_DELETED
                and self.policy.include_soft_deleted
            )
        ]

        return tuple(sorted(record.version for record in retained))

    def _approved_labels(self, data: Mapping[str, Any]) -> Dict[str, Any]:
        if not self.approved_custom_metadata_keys:
            return {}

        custom_metadata = data.get("custom_metadata")
        if not isinstance(custom_metadata, MappingABC):
            return {}

        labels = {}
        for key in self.approved_custom_metadata_keys:
            if key not in custom_metadata:
                continue
            value = custom_metadata[key]
            if value is None or isinstance(value, (str, bool, int, float)):
                labels[key] = value
        return labels

    @staticmethod
    def _error_result(
        path: str, status: MetadataAccessStatus, exc: Exception
    ) -> PathResult:
        return PathResult(
            path=path,
            access_status=status,
            error_type=type(exc).__name__,
        )

    @staticmethod
    def _malformed_result(path: str) -> PathResult:
        return PathResult(
            path=path,
            access_status=MetadataAccessStatus.MALFORMED_METADATA,
        )

    def _discover_paths(self, root: str) -> Tuple[List[str], List[PathResult]]:
        secrets: List[str] = []
        issues: List[PathResult] = []
        visited = set()
        seen_secrets = set()

        def walk(folder: str) -> None:
            if folder in visited:
                return
            visited.add(folder)

            try:
                response = self._kv.list_secrets(
                    path=folder,
                    mount_point=self.mount_point,
                )
            except exceptions.Forbidden as exc:
                issues.append(
                    self._error_result(folder, MetadataAccessStatus.LIST_FORBIDDEN, exc)
                )
                return
            except exceptions.Unauthorized as exc:
                issues.append(
                    self._error_result(
                        folder, MetadataAccessStatus.LIST_UNAUTHORIZED, exc
                    )
                )
                return
            except exceptions.InvalidPath as exc:
                issues.append(
                    self._error_result(folder, MetadataAccessStatus.LIST_NOT_FOUND, exc)
                )
                return
            except exceptions.InvalidRequest as exc:
                issues.append(
                    self._error_result(
                        folder, MetadataAccessStatus.LIST_INVALID_REQUEST, exc
                    )
                )
                return
            except exceptions.VaultError as exc:
                issues.append(
                    self._error_result(
                        folder, MetadataAccessStatus.LIST_VAULT_ERROR, exc
                    )
                )
                return
            except Exception as exc:  # noqa: BLE001 - report, do not abort discovery
                issues.append(
                    self._error_result(
                        folder, MetadataAccessStatus.LIST_UNEXPECTED_ERROR, exc
                    )
                )
                return

            data = response.get("data") if isinstance(response, MappingABC) else None
            keys = data.get("keys") if isinstance(data, MappingABC) else None
            if not isinstance(keys, list):
                issues.append(
                    PathResult(
                        path=folder,
                        access_status=MetadataAccessStatus.LIST_MALFORMED_METADATA,
                    )
                )
                return

            for key in keys:
                if not isinstance(key, str):
                    issues.append(
                        PathResult(
                            path=folder,
                            access_status=MetadataAccessStatus.LIST_MALFORMED_METADATA,
                        )
                    )
                    continue

                if key.endswith("/"):
                    walk(self._join_path(folder, key[:-1]))
                    continue

                secret_path = self._join_path(folder, key)
                if secret_path not in seen_secrets:
                    seen_secrets.add(secret_path)
                    secrets.append(secret_path)

        walk(root)
        return secrets, issues


def audit_kv_v2_retention(
    client: Any,
    paths: Iterable[str],
    mount_point: str = DEFAULT_MOUNT_POINT,
    approved_custom_metadata_keys: Optional[Iterable[str]] = None,
    policy: Optional[RetentionPolicy] = None,
) -> RetentionReport:
    """Convenience wrapper for :class:`KvV2RetentionAuditor`."""

    return KvV2RetentionAuditor(
        client=client,
        mount_point=mount_point,
        approved_custom_metadata_keys=approved_custom_metadata_keys,
        policy=policy,
    ).audit(paths)


__all__ = (
    "KvV2RetentionAuditor",
    "MetadataAccessStatus",
    "PathResult",
    "RetentionPolicy",
    "RetentionReport",
    "UnverifiableReason",
    "VersionRecord",
    "VersionStatus",
    "audit_kv_v2_retention",
)
