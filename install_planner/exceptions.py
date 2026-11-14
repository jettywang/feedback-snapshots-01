# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Exceptions raised by the dependency admission planner."""

from __future__ import annotations


class PlannerError(Exception):
    """Base class for all planner failures.

    A planner failure is always fatal for the whole plan: no partial
    installation plan is returned to the caller.
    """


class DependencyDeclarationError(PlannerError):
    """A ``custom.dependencies`` declaration is malformed."""


class RequiredDependencyMissingError(PlannerError):
    """A required dependency is not authorized by any role in the repository.

    An optional dependency that is simply not present is skipped instead.
    """

    def __init__(self, required_by: str, path: str) -> None:
        super().__init__(
            f"required dependency {path!r} of {required_by!r} is not "
            "published by any delegated targets role"
        )
        self.required_by = required_by
        self.path = path


class DependencyHashMismatchError(PlannerError):
    """The SHA-256 pinned in a declaration does not match repository metadata.

    The pinned digest is compared against the digest carried in the signed
    ``TargetFile`` returned by the TUF target lookup: the declaration never
    gets to define what content is acceptable.
    """

    def __init__(
        self, required_by: str, path: str, expected: str, actual: str
    ) -> None:
        super().__init__(
            f"sha256 mismatch for {path!r} (required by {required_by!r}): "
            f"declared {expected}, repository metadata attests {actual}"
        )
        self.required_by = required_by
        self.path = path
        self.expected = expected
        self.actual = actual


class SamePathConflictError(PlannerError):
    """Two requirements pin the same target path to different content."""

    def __init__(self, path: str, first_by: str, second_by: str) -> None:
        super().__init__(
            f"conflicting requirements for {path!r}: {first_by!r} and "
            f"{second_by!r} pin different sha256 digests"
        )
        self.path = path
        self.first_by = first_by
        self.second_by = second_by


class DependencyCycleError(PlannerError):
    """The dependency graph contains a cycle."""

    def __init__(self, cycle: list[str]) -> None:
        super().__init__(f"dependency cycle detected: {' -> '.join(cycle)}")
        self.cycle = cycle


class RepositoryAdmissionError(PlannerError):
    """Target lookup failed for a repository-side reason.

    Examples are unsigned or malformed delegated metadata, and HTTP failures
    while fetching metadata. A missing target (HTTP 404) is handled
    separately: it is only acceptable for an optional dependency.
    """
