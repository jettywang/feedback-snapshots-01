# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Batch admission planning for TUF-distributed package dependencies.

The planner turns the dependency closure of one root package into an
:class:`InstallationPlan` that is safe to hand to a (separate) installer:

* Every target is authorized through the standard
  :class:`~tuf.ngclient.Updater` target lookup, i.e. the same pre-order walk
  of the delegation graph (with terminating delegations and signature
  verification) that a single-target client would perform. A package writing
  another path into its own ``custom.dependencies`` section does not grant
  itself any publication rights for that path.
* All lookups happen against one single client snapshot: the same
  ``Updater`` instance performs one ``refresh()`` and then serves every
  lookup, so the plan can never mix metadata versions.
* The pinned SHA-256 of every requirement is checked against the signed
  repository metadata, never against data fetched from the repository.
  Target files themselves are never downloaded.
* Missing required dependencies, digest mismatches, dependency cycles and
  conflicting requirements for the same path all fail the entire plan. An
  optional dependency may only be skipped when no role publishes it; a
  signature or metadata failure on an optional dependency still fails.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from tuf.api import exceptions
from tuf.api.metadata import Root, TargetFile, Targets
from tuf.ngclient import Updater

from .exceptions import (
    DependencyCycleError,
    DependencyDeclarationError,
    DependencyHashMismatchError,
    RepositoryAdmissionError,
    RequiredDependencyMissingError,
    SamePathConflictError,
)
from .models import (
    SHA256,
    DependencyRequirement,
    InstallationPlan,
    PlannedPackage,
    TargetAuthorization,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tuf.ngclient.config import UpdaterConfig
    from tuf.ngclient.fetcher import FetcherInterface


class AuthenticatedUpdater(Updater):
    """Updater that also reports which role authorized a target.

    ``get_authorized_targetinfo`` mirrors
    :meth:`Updater._preorder_depth_first_walk` exactly, including terminating
    delegation handling and the ``max_delegations`` bound, but returns the
    role name and parent role in addition to the ``TargetFile``. The actual
    metadata loading, snapshot pinning and signature verification remain
    entirely implemented by python-tuf.
    """

    def get_authorized_targetinfo(
        self, target_path: str
    ) -> tuple[TargetFile, str, str] | None:
        """Look up ``target_path`` and return it with its signing role.

        Returns ``None`` when no role in the delegation graph publishes the
        path. Any signature, snapshot or download failure propagates as the
        corresponding :mod:`tuf.api.exceptions` error so that callers can
        distinguish "not published" from "published but broken".
        """
        if Targets.type not in self._trusted_set:
            self.refresh()

        delegations_to_visit: list[tuple[str, str]] = [
            (Targets.type, Root.type)
        ]
        visited_role_names: set[str] = set()

        while (
            len(visited_role_names) <= self.config.max_delegations
            and len(delegations_to_visit) > 0
        ):
            role_name, parent_role = delegations_to_visit.pop(-1)
            if role_name in visited_role_names:
                continue

            targets = self._load_targets(role_name, parent_role)
            target = targets.targets.get(target_path)
            if target is not None:
                return target, role_name, parent_role

            visited_role_names.add(role_name)

            if targets.delegations is not None:
                child_roles_to_visit: list[tuple[str, str]] = []
                for child_name, terminating in (
                    targets.delegations.get_roles_for_target(target_path)
                ):
                    child_roles_to_visit.append((child_name, role_name))
                    if terminating:
                        delegations_to_visit = []
                        break
                child_roles_to_visit.reverse()
                delegations_to_visit.extend(child_roles_to_visit)

        return None

    def targets_role_version(self, role: str) -> int:
        """Return the snapshot-pinned metadata version of targets ``role``."""
        metainfo = self._trusted_set.snapshot.meta.get(f"{role}.json")
        if metainfo is None:
            raise RepositoryAdmissionError(
                f"snapshot does not pin targets role {role!r}"
            )
        return metainfo.version

    @property
    def snapshot_version(self) -> int:
        """Version of the snapshot every lookup is pinned to."""
        return self._trusted_set.snapshot.version

    @property
    def consistent_snapshot(self) -> bool:
        """Root ``consistent_snapshot`` flag of the loaded repository."""
        return bool(self._trusted_set.root.consistent_snapshot)


class DependencyPlanner:
    """Build installation plans for a package graph stored as TUF targets.

    Args:
        updater: An :class:`AuthenticatedUpdater` bound to the repository.
            ``refresh()`` is called exactly once (lazily on the first lookup)
            and the resulting snapshot backs every subsequent lookup.
    """

    def __init__(self, updater: AuthenticatedUpdater) -> None:
        self._updater = updater
        self._packages: dict[str, PlannedPackage] = {}

    def plan(self, root_path: str) -> InstallationPlan:
        """Admit the full dependency closure of ``root_path``.

        Raises:
            PlannerError: Any admission failure. On failure no plan is
                returned: partially resolved nodes stay internal to the
                planner and are never exposed.
        """
        self._packages = {}
        # The root is a mandatory requirement even if some dependency later
        # refers to it as optional: optionality never removes requirements.
        self._resolve(root_path, optional=False, required_by=None)
        self._assert_complete()
        order = self._stable_topological_order(root_path)
        return InstallationPlan(
            root_path=root_path,
            install_order=order,
            packages=self._packages,
            snapshot_version=self._updater.snapshot_version,
            consistent_snapshot=self._updater.consistent_snapshot,
        )

    def _resolve(
        self, path: str, optional: bool, required_by: str | None
    ) -> None:
        existing = self._packages.get(path)
        if existing is not None:
            # A required edge makes an otherwise-optional node mandatory.
            if not optional:
                existing.optional = False
            return

        package = PlannedPackage(path=path, sha256="", optional=optional)
        # Reserve the node before recursion so that back edges are detectable.
        self._packages[path] = package

        target_info = self._lookup(path, optional, required_by)
        if target_info is None:
            # Only reachable for optional dependencies: a required target not
            # published by any role raises inside _lookup instead.
            package.authorization = None
            return

        targetfile, role, parent_role = target_info
        self._check_digest(path, targetfile, required_by)
        package.sha256 = targetfile.hashes[SHA256]
        package.authorization = TargetAuthorization(
            role=role,
            parent_role=parent_role,
            targetfile=targetfile,
            targetfile_version=self._updater.targets_role_version(role),
        )
        package.requirements = self._read_requirements(path, targetfile)

        for requirement in sorted(package.requirements, key=lambda r: r.path):
            self._resolve(
                requirement.path,
                requirement.optional,
                required_by=path,
            )

    def _lookup(
        self, path: str, optional: bool, required_by: str | None
    ) -> tuple[TargetFile, str, str] | None:
        try:
            target_info = self._updater.get_authorized_targetinfo(path)
        except exceptions.DownloadHTTPError as error:
            if error.status_code == 404 and optional:
                return None
            raise RepositoryAdmissionError(
                f"target lookup for {path!r} failed: {error}"
            ) from error
        except (exceptions.RepositoryError, exceptions.DownloadError) as error:
            # Unsigned/malformed metadata, bad snapshot, transport failures:
            # never equivalent to "not published", even for optional deps.
            raise RepositoryAdmissionError(
                f"target lookup for {path!r} failed: {error}"
            ) from error

        if target_info is None:
            if optional:
                return None
            raise RequiredDependencyMissingError(
                required_by if required_by is not None else "<root>", path
            )
        return target_info

    def _check_digest(
        self,
        path: str,
        targetfile: TargetFile,
        required_by: str | None,
    ) -> None:
        actual = targetfile.hashes.get(SHA256)
        if actual is None:
            raise RepositoryAdmissionError(
                f"repository metadata for {path!r} carries no sha256 digest"
            )
        declared = self._declared_digest(path)
        if declared is not None and declared != actual:
            raise DependencyHashMismatchError(
                required_by if required_by is not None else "<root>",
                path,
                declared,
                actual,
            )

    def _declared_digest(self, path: str) -> str | None:
        """Find the digest pinned for ``path`` in any parsed requirement."""
        for package in self._packages.values():
            for requirement in package.requirements:
                if requirement.path == path:
                    return requirement.sha256
        return None

    def _read_requirements(
        self, path: str, targetfile: TargetFile
    ) -> list[DependencyRequirement]:
        custom = targetfile.custom
        if custom is None:
            return []
        if not isinstance(custom, dict):
            raise DependencyDeclarationError(
                f"target {path!r} has a non-object 'custom' field"
            )
        raw_dependencies = custom.get("dependencies", [])
        if not isinstance(raw_dependencies, list):
            raise DependencyDeclarationError(
                f"target {path!r} has a non-list 'custom.dependencies' field"
            )
        requirements = [
            DependencyRequirement.from_custom(raw, path)
            for raw in raw_dependencies
        ]
        self._register_requirements(path, requirements)
        return requirements

    def _register_requirements(
        self,
        owner: str,
        requirements: list[DependencyRequirement],
    ) -> None:
        """Reject two requirements pinning one path to different digests."""
        for requirement in requirements:
            for other_owner, other in self._iter_requirements():
                if (
                    other.path == requirement.path
                    and other.sha256 != requirement.sha256
                ):
                    raise SamePathConflictError(
                        requirement.path, other_owner, owner
                    )

    def _iter_requirements(
        self,
    ) -> Iterator[tuple[str, DependencyRequirement]]:
        for package in self._packages.values():
            for requirement in package.requirements:
                yield package.path, requirement

    def _assert_complete(self) -> None:
        for package in self._packages.values():
            if package.authorization is None and not package.optional:
                raise RequiredDependencyMissingError("<root>", package.path)

    def _stable_topological_order(self, root_path: str) -> list[str]:
        # Edges point from a package to its dependencies. Kahn's algorithm with
        # alphabetically ordered ready nodes makes the order deterministic and
        # independent of dictionary iteration order. Skipped optional packages
        # are not part of the installable graph.
        nodes = [
            path
            for path, package in self._packages.items()
            if package.authorization is not None
        ]
        indegree: dict[str, int] = {path: 0 for path in nodes}
        dependents: dict[str, list[str]] = {path: [] for path in nodes}
        for package in self._packages.values():
            if package.authorization is None:
                continue
            unique_deps = {req.path for req in package.requirements}
            for dep_path in unique_deps:
                dependency = self._packages.get(dep_path)
                if dependency is None or dependency.authorization is None:
                    # Skipped or absent optional dependency: not an edge.
                    continue
                indegree[package.path] += 1
                dependents[dep_path].append(package.path)

        ready = deque(
            sorted(path for path, deg in indegree.items() if deg == 0)
        )
        order: list[str] = []
        while ready:
            path = ready.popleft()
            order.append(path)
            for dependent in sorted(dependents[path]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    ready.append(dependent)

        if len(order) != len(indegree):
            unresolved = sorted(
                path for path, degree in indegree.items() if degree > 0
            )
            raise DependencyCycleError(self._find_cycle(unresolved, root_path))
        return order

    def _find_cycle(
        self, unresolved: list[str], root_path: str
    ) -> list[str]:
        # Follow dependency edges among unresolved nodes to extract one cycle.
        edges = {
            package.path: {
                req.path
                for req in package.requirements
                if req.path in unresolved
            }
            for package in self._packages.values()
            if package.path in unresolved
        }
        start = root_path if root_path in edges else unresolved[0]
        stack = [start]
        on_stack = {start}
        visited: set[str] = set()

        def walk(node: str) -> list[str] | None:
            for neighbor in sorted(edges.get(node, ())):
                if neighbor in on_stack:
                    cycle = stack[stack.index(neighbor) :]
                    cycle.append(neighbor)
                    return cycle
                if neighbor in visited:
                    continue
                stack.append(neighbor)
                on_stack.add(neighbor)
                found = walk(neighbor)
                if found is not None:
                    return found
                stack.pop()
                on_stack.discard(neighbor)
                visited.add(neighbor)
            return None

        cycle = walk(start)
        return cycle if cycle is not None else [*unresolved, unresolved[0]]


def create_planner(
    metadata_dir: str,
    metadata_base_url: str,
    target_base_url: str,
    bootstrap: bytes,
    fetcher: FetcherInterface | None = None,
    config: UpdaterConfig | None = None,
) -> DependencyPlanner:
    """Construct a planner over a freshly bootstrapped TUF client.

    Target download URLs are configured but never used: the planner only
    consumes metadata. ``bootstrap`` is the embedded trusted root.
    """
    updater = AuthenticatedUpdater(
        metadata_dir,
        metadata_base_url,
        target_dir=None,
        target_base_url=target_base_url,
        fetcher=fetcher,
        config=config,
        bootstrap=bootstrap,
    )
    return DependencyPlanner(updater)
