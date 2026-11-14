# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data model for dependency admission plans."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .exceptions import DependencyDeclarationError

if TYPE_CHECKING:
    from tuf.api.metadata import TargetFile

SHA256 = "sha256"


@dataclass(frozen=True)
class DependencyRequirement:
    """One entry of a target's ``custom.dependencies`` list.

    Attributes:
        path: Target path inside the repository (relative to targets base URL).
        sha256: Pinned SHA-256 digest of the acceptable target content.
        optional: When true, a target that no role publishes may be skipped;
            signature failures must never be treated as "not present".
        required_by: Target path of the package declaring this requirement.
    """

    path: str
    sha256: str
    optional: bool
    required_by: str

    @staticmethod
    def from_custom(
        raw: object, required_by: str
    ) -> DependencyRequirement:
        """Parse one ``custom.dependencies`` entry.

        Raises:
            DependencyDeclarationError: The entry does not have the expected
                shape or value types.
        """
        if not isinstance(raw, dict):
            raise DependencyDeclarationError(
                f"dependency entry of {required_by!r} must be an object, "
                f"got {type(raw).__name__}"
            )
        path = raw.get("path")
        digest = raw.get("sha256")
        optional = raw.get("optional", False)
        if not isinstance(path, str) or not path:
            raise DependencyDeclarationError(
                f"dependency of {required_by!r} has invalid 'path': {path!r}"
            )
        if not isinstance(digest, str) or not digest:
            raise DependencyDeclarationError(
                f"dependency {path!r} of {required_by!r} has invalid "
                f"'sha256': {digest!r}"
            )
        if not isinstance(optional, bool):
            raise DependencyDeclarationError(
                f"dependency {path!r} of {required_by!r} has invalid "
                f"'optional': {optional!r}"
            )
        return DependencyRequirement(path, digest, optional, required_by)


@dataclass(frozen=True)
class TargetAuthorization:
    """Evidence of how a target path was admitted through TUF.

    The information is produced by the standard Updater target lookup
    (pre-order walk of the delegation graph, including terminating
    delegations): only the role that actually answers the lookup is
    recorded. A package merely mentioning a path in its own ``custom``
    section never produces an authorization.

    Attributes:
        role: Name of the targets role whose signed metadata contains the
            ``TargetFile`` (``"targets"`` for the top-level role).
        parent_role: Role that delegated to ``role`` (``"root"`` for the
            top-level targets role). The delegation chain is what ties the
            signature back to the bootstrap root.
        targetfile: Snapshot-pinned, signature-verified ``TargetFile``.
        targetfile_version: Version of the targets metadata role that
            published the target, as pinned by the snapshot.
    """

    role: str
    parent_role: str
    targetfile: TargetFile
    targetfile_version: int

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable description of the authorization."""
        return {
            "role": self.role,
            "parent_role": self.parent_role,
            "targets_metadata_version": self.targetfile_version,
            "length": self.targetfile.length,
            "hashes": dict(self.targetfile.hashes),
        }


@dataclass
class PlannedPackage:
    """One authenticated package in the resolved closure."""

    path: str
    sha256: str
    optional: bool
    requirements: list[DependencyRequirement] = field(default_factory=list)
    authorization: TargetAuthorization | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable description of the package node."""
        result: dict[str, Any] = {
            "path": self.path,
            "sha256": self.sha256,
            "optional": self.optional,
            "authorization": (
                self.authorization.to_dict()
                if self.authorization is not None
                else None
            ),
        }
        if self.optional and self.authorization is None:
            result["status"] = "skipped-optional-not-published"
        else:
            result["status"] = "admitted"
        return result


@dataclass(frozen=True)
class InstallationPlan:
    """A fully admitted, ready-to-install dependency closure.

    Instances are only constructed after every node in the closure has been
    authenticated against the same client snapshot, so an installation order
    exists and no conflicting requirement survived.

    Attributes:
        root_path: Path of the package the caller asked to install.
        install_order: Target paths in stable topological order: every
            dependency is installed before its dependents.
        packages: Admitted packages keyed by target path.
        snapshot_version: Snapshot metadata version shared by all lookups.
        consistent_snapshot: Value of the root ``consistent_snapshot`` flag.
    """

    root_path: str
    install_order: list[str]
    packages: dict[str, PlannedPackage]
    snapshot_version: int
    consistent_snapshot: bool

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable description of the whole plan."""
        return {
            "root_path": self.root_path,
            "snapshot_version": self.snapshot_version,
            "consistent_snapshot": self.consistent_snapshot,
            "install_order": list(self.install_order),
            "packages": [
                self.packages[path].to_dict() for path in self.install_order
            ],
            "skipped_optional": sorted(
                path
                for path, package in self.packages.items()
                if package.authorization is None
            ),
        }
