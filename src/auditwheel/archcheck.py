"""Pre-repair admission check for dependency architectures.

When CI repairs wheels for several architectures on a single machine, the
host architecture is not a reliable signal: a dependency resolved through
the linker paths may silently belong to a different architecture than the
wheel being repaired.  This module implements a configurable gate that
runs *before* any source file is grafted into the wheel and verifies that
every candidate dependency really matches the declared target
architecture.

For every candidate dependency a :class:`DependencyArchRecord` is
produced which keeps the three architecture sources separate:

- ``wheel_tag_arch``: the architecture parsed from the wheel file name
  (the WHEEL tags),
- ``elf_arch``: the architecture read from the dependency's own ELF
  header,
- ``target_arch``: the declared target architecture (``--plat`` or the
  wheel's own architecture).

Compatible aliases (e.g. an ``x86_64_v2`` library knowingly grafted into
an ``x86_64`` wheel) are rejected unless explicitly approved through
``allowed_aliases``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from elftools.common.exceptions import ELFError

from auditwheel.lddtree import LIBPYTHON_RE, get_elf_platform

if TYPE_CHECKING:
    from pathlib import Path

    from auditwheel.architecture import Architecture
    from auditwheel.policy import ExternalReference

logger = logging.getLogger(__name__)


class ArchDecision(Enum):
    """Outcome of the admission check for a single dependency."""

    ACCEPT = "accept"
    ALIAS = "alias"
    REJECT = "reject"


@dataclass(frozen=True)
class DependencyArchRecord:
    """Architecture admission record for one candidate dependency."""

    soname: str
    path: Path
    wheel_tag_arch: Architecture | None
    elf_arch: Architecture | None
    target_arch: Architecture
    decision: ArchDecision
    reason: str


def decide_architecture(
    elf_arch: Architecture | None,
    target_arch: Architecture,
    allowed_aliases: frozenset[tuple[Architecture, Architecture]],
) -> tuple[ArchDecision, str]:
    """Decide whether a dependency with ``elf_arch`` may be grafted into a
    wheel targeting ``target_arch``.

    Exact (or strictly compatible, i.e. subset) matches are accepted.
    Anything else is rejected unless the ``(elf_arch, target_arch)`` pair
    has been explicitly approved in ``allowed_aliases``.
    """
    if elf_arch is None:
        return ArchDecision.REJECT, "could not determine the ELF architecture"
    if elf_arch == target_arch or elf_arch.is_subset(target_arch):
        return ArchDecision.ACCEPT, f"ELF architecture {elf_arch} matches target {target_arch}"
    if (elf_arch, target_arch) in allowed_aliases:
        return (
            ArchDecision.ALIAS,
            f"ELF architecture {elf_arch} approved as an alias of target {target_arch}",
        )
    return (
        ArchDecision.REJECT,
        f"ELF architecture {elf_arch} does not match target {target_arch}",
    )


def _read_elf_architecture(path: Path) -> Architecture | None:
    try:
        platform = get_elf_platform(path)
    except (ELFError, OSError):
        return None
    try:
        extended = platform.extended_architecture
    except ValueError:
        return None
    return extended if extended is not None else platform.baseline_architecture


def check_dependency_architectures(
    external_refs_by_fn: dict[Path, dict[str, ExternalReference]],
    abi: str,
    *,
    wheel_tag_arch: Architecture | None,
    target_arch: Architecture,
    allowed_aliases: frozenset[tuple[Architecture, Architecture]] = frozenset(),
) -> list[DependencyArchRecord]:
    """Check every candidate dependency against the target architecture.

    Returns one :class:`DependencyArchRecord` per distinct candidate
    dependency, in deterministic order.  Dependencies that could not be
    located (``src_path is None``) and libpython references (which are
    removed, not grafted) are skipped.
    """
    candidates: dict[Path, str] = {}
    for external_refs in external_refs_by_fn.values():
        for soname, src_path in external_refs[abi].libs.items():
            if src_path is None or LIBPYTHON_RE.match(soname):
                continue
            candidates.setdefault(src_path, soname)

    records: list[DependencyArchRecord] = []
    for src_path in sorted(candidates):
        soname = candidates[src_path]
        elf_arch = _read_elf_architecture(src_path)
        decision, reason = decide_architecture(elf_arch, target_arch, allowed_aliases)
        record = DependencyArchRecord(
            soname=soname,
            path=src_path,
            wheel_tag_arch=wheel_tag_arch,
            elf_arch=elf_arch,
            target_arch=target_arch,
            decision=decision,
            reason=reason,
        )
        records.append(record)
        log = logger.warning if decision is ArchDecision.REJECT else logger.info
        log(
            "dependency architecture check: %s %s (wheel tag: %s, ELF: %s, target: %s)",
            decision.value.upper(),
            src_path,
            wheel_tag_arch,
            elf_arch,
            target_arch,
        )
    return records


def enforce_dependency_architectures(records: list[DependencyArchRecord]) -> None:
    """Raise a :class:`ValueError` if any record was rejected."""
    rejected = [r for r in records if r.decision is ArchDecision.REJECT]
    if not rejected:
        return
    details = "\n".join(
        f"  {r.soname} ({r.path}): {r.reason}"
        f" [wheel tag: {r.wheel_tag_arch}, ELF: {r.elf_arch}, target: {r.target_arch}]"
        for r in rejected
    )
    msg = (
        "Cannot repair wheel, the following dependencies do not match the "
        f"target architecture:\n{details}\n"
        "Use --allow-arch-alias ELF_ARCH:TARGET_ARCH to explicitly approve "
        "a compatible alias, or fix the linker paths so dependencies are "
        "resolved for the target architecture."
    )
    raise ValueError(msg)
