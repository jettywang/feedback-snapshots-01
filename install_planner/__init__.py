# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF dependency admission planner (planning only, never installs)."""

from __future__ import annotations

from .exceptions import (
    DependencyCycleError,
    DependencyDeclarationError,
    DependencyHashMismatchError,
    PlannerError,
    RepositoryAdmissionError,
    RequiredDependencyMissingError,
    SamePathConflictError,
)
from .models import (
    DependencyRequirement,
    InstallationPlan,
    PlannedPackage,
    TargetAuthorization,
)
from .planner import AuthenticatedUpdater, DependencyPlanner, create_planner

__all__ = [
    "AuthenticatedUpdater",
    "DependencyCycleError",
    "DependencyDeclarationError",
    "DependencyHashMismatchError",
    "DependencyPlanner",
    "DependencyRequirement",
    "InstallationPlan",
    "PlannedPackage",
    "PlannerError",
    "RepositoryAdmissionError",
    "RequiredDependencyMissingError",
    "SamePathConflictError",
    "TargetAuthorization",
    "create_planner",
]
