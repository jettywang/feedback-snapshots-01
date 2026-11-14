# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline fork analysis over two observation packages.

The entry point :func:`analyze_fork` takes two
:class:`~tuf.forensics.observation.ObservationPackage` instances and decides
whether the evidence is sufficient to prove that the publisher signed
conflicting content.

Evidence handling rules:

* Each package is authenticated independently. If either fails, the result is
  :data:`~tuf.forensics.evidence.ForkStatus.INCONCLUSIVE`: a tampered package
  can never be presented as proof of publisher misbehavior.
* Packages for different roles or different versions cannot be a same-version
  conflict and are reported as
  :data:`~tuf.forensics.evidence.ForkStatus.REFUTED` with a reason.
* Content is compared on the canonical JSON form of the signed payload. JSON
  whitespace, signature ordering and additional valid signatures therefore do
  not count as forks.
* Only when both packages authenticate, share role and version, and differ in
  canonical payload content is a fork
  :data:`~tuf.forensics.evidence.ForkStatus.PROVEN`.
"""

from __future__ import annotations

from typing import Any

from tuf.forensics.evidence import (
    ConflictFields,
    ForkReport,
    ForkStatus,
    ObservationVerdict,
    RefutationReason,
)
from tuf.forensics.observation import ObservationPackage


def _diff_paths(
    first: Any, second: Any, prefix: tuple[str | int, ...] = ()
) -> list[tuple[str | int, ...]]:
    paths: list[tuple[str | int, ...]] = []
    if isinstance(first, dict) and isinstance(second, dict):
        for key in sorted(set(first) | set(second)):
            path = (*prefix, key)
            if key not in first or key not in second:
                paths.append(path)
            else:
                paths.extend(_diff_paths(first[key], second[key], path))
    elif isinstance(first, list) and isinstance(second, list):
        if len(first) != len(second):
            paths.append(prefix)
        else:
            for index, (first_item, second_item) in enumerate(
                zip(first, second, strict=True)
            ):
                paths.extend(
                    _diff_paths(
                        first_item, second_item, (*prefix, index)
                    )
                )
    elif first != second:
        paths.append(prefix)
    return paths


def _resolve_path(
    data: dict[str, Any], path: tuple[str | int, ...]
) -> Any:
    current: Any = data
    for segment in path:
        current = current[segment]
    return current


def _path_to_string(path: tuple[str | int, ...]) -> str:
    result = ""
    for segment in path:
        if isinstance(segment, int):
            result += f"[{segment}]"
        else:
            result = segment if not result else f"{result}.{segment}"
    return result


def analyze_fork(
    first: ObservationPackage, second: ObservationPackage
) -> ForkReport:
    """Determine whether two observations prove a publisher fork.

    Args:
        first: First independently collected observation package.
        second: Second independently collected observation package.

    Returns:
        A :class:`~tuf.forensics.evidence.ForkReport` whose status
        distinguishes proven forks, refuted fork hypotheses and inconclusive
        (insufficient) evidence.
    """
    first_verdict = first.verify()
    second_verdict = second.verify()

    if not first_verdict.authenticated or not second_verdict.authenticated:
        return ForkReport(
            status=ForkStatus.INCONCLUSIVE,
            first=first_verdict,
            second=second_verdict,
        )

    if first.envelope_type is not second.envelope_type:
        message = (
            "Observation packages use different signature semantics "
            f"({first.envelope_type.name} vs {second.envelope_type.name}): "
            "they cannot be compared as same-semantics observations"
        )
        first_verdict.errors.append(message)
        second_verdict.errors.append(message)
        return ForkReport(
            status=ForkStatus.INCONCLUSIVE,
            first=first_verdict,
            second=second_verdict,
        )

    if first.role != second.role:
        return ForkReport(
            status=ForkStatus.REFUTED,
            first=first_verdict,
            second=second_verdict,
            refutation_reason=RefutationReason.DIFFERENT_ROLE,
        )

    if first.version != second.version:
        return ForkReport(
            status=ForkStatus.REFUTED,
            first=first_verdict,
            second=second_verdict,
            refutation_reason=RefutationReason.DIFFERENT_VERSION,
        )

    if first.canonical_payload() == second.canonical_payload():
        return ForkReport(
            status=ForkStatus.REFUTED,
            first=first_verdict,
            second=second_verdict,
            refutation_reason=RefutationReason.SAME_CANONICAL_CONTENT,
        )

    first_dict = first.payload_dict()
    second_dict = second.payload_dict()
    raw_paths = _diff_paths(first_dict, second_dict)
    conflict = ConflictFields(
        field_paths=[_path_to_string(path) for path in raw_paths],
        first_values={
            _path_to_string(path): _resolve_path(first_dict, path)
            for path in raw_paths
        },
        second_values={
            _path_to_string(path): _resolve_path(second_dict, path)
            for path in raw_paths
        },
    )
    return ForkReport(
        status=ForkStatus.PROVEN,
        first=first_verdict,
        second=second_verdict,
        conflict_fields=conflict,
    )
