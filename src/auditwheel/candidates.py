"""Offline comparison of replacement library candidates for a wheel.

Security teams may supply more than one patched replacement for a shared
library; some builds only run on a newer platform.  This module compares those
candidates offline against the wheel's *actual* symbol requirements and reports
which publication tags (e.g. ``manylinux_2_17_x86_64``) can still be kept.

A target policy is retainable only when at least one candidate satisfies all
of the following for every replaced library:

* it carries patch evidence covering the target policy;
* it exports every symbol the wheel really imports from that library, with the
  exact symbol version the wheel requires;
* the candidate itself can run on the target policy (its own versioned symbol
  requirements fit within the policy).

Candidates may cover different policies: an older platform can be left to a
candidate with independent evidence instead of being sacrificed because another
candidate only supports a newer platform.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditwheel.elfutils import elf_exported_symbols, elf_symbol_versions
from auditwheel.error import AuditwheelError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from auditwheel.policy import Policy, WheelPolicies

logger = logging.getLogger(__name__)

MANIFEST_VERSION = 1
MANIFEST_KIND = "auditwheel-candidate-manifest"


class CandidateError(AuditwheelError):
    """The replacement-library manifest is malformed."""


@dataclass(frozen=True)
class PatchEvidence:
    """Offline proof that a candidate library may be used for a policy."""

    policy: str
    reference: str
    checksum: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"policy": self.policy, "reference": self.reference}
        if self.checksum is not None:
            result["checksum"] = self.checksum
        return result


@dataclass(frozen=True)
class LibraryCandidate:
    """A replacement build for one external shared library."""

    path: Path
    soname: str
    patch_evidence: tuple[PatchEvidence, ...]
    sha256: str | None = None
    variant: str | None = None
    digest_verified: bool = True
    # Filled in once the policy table is available.
    runtime_policy: Policy | None = None
    runtime_symbols: Mapping[str, set[str]] | None = None
    evidence_policies: tuple[Policy, ...] = ()

    def evidence_for(self, policy: Policy) -> PatchEvidence | None:
        """Return evidence explicitly naming ``policy`` (by name or alias)."""
        names = {policy.name, *policy.aliases}
        for evidence in self.patch_evidence:
            if evidence.policy in names:
                return evidence
        return None

    def covers(self, policy: Policy) -> PatchEvidence | None:
        """Return evidence that covers ``policy``.

        Evidence recorded for a policy that is at least as compatible (higher
        priority) also covers newer targets: a library validated for
        ``manylinux_2_17`` is usable on ``manylinux_2_28`` as well.  Evidence
        for a newer target never covers an older, more compatible one.
        """
        exact = self.evidence_for(policy)
        if exact is not None:
            return exact
        if len(self.evidence_policies) == len(self.patch_evidence):
            for evidence, evidence_policy in zip(
                self.patch_evidence, self.evidence_policies, strict=True
            ):
                if evidence_policy.priority >= policy.priority:
                    return evidence
        return None

    def verify_digest(self) -> bool:
        """Check the offline manifest digest against the candidate bytes."""
        if self.sha256 is None:
            return True
        expected = self.sha256.lower()
        if expected.startswith("sha256:"):
            expected = expected[len("sha256:") :]
        actual = hashlib.sha256(self.path.read_bytes()).hexdigest()
        return actual == expected

    def label(self) -> str:
        return self.variant or self.path.name


@dataclass(frozen=True)
class CandidateManifest:
    """All candidates supplied for one wheel run, keyed by library soname."""

    candidates: Mapping[str, tuple[LibraryCandidate, ...]]
    base_dir: Path = field(default_factory=lambda: Path())

    @classmethod
    def from_dict(cls, data: Any, *, base_dir: Path) -> CandidateManifest:  # noqa: ANN401
        if not isinstance(data, dict):
            msg = "candidate manifest must be a JSON object"
            raise CandidateError(msg)
        if data.get("version") != MANIFEST_VERSION:
            msg = f"unsupported candidate manifest version: {data.get('version')!r}"
            raise CandidateError(msg)
        if data.get("kind", MANIFEST_KIND) != MANIFEST_KIND:
            msg = f"unsupported candidate manifest kind: {data.get('kind')!r}"
            raise CandidateError(msg)

        raw_candidates = data.get("candidates")
        if not isinstance(raw_candidates, list):
            msg = "candidate manifest needs a 'candidates' list"
            raise CandidateError(msg)

        candidates: dict[str, list[LibraryCandidate]] = {}
        for index, entry in enumerate(raw_candidates):
            candidate = _parse_candidate(entry, index=index, base_dir=base_dir)
            candidates.setdefault(candidate.soname, []).append(candidate)

        if not candidates:
            msg = "candidate manifest does not list any candidates"
            raise CandidateError(msg)
        return cls({soname: tuple(items) for soname, items in candidates.items()}, base_dir)

    @property
    def sonames(self) -> tuple[str, ...]:
        return tuple(sorted(self.candidates))

    def for_soname(self, soname: str) -> tuple[LibraryCandidate, ...]:
        return self.candidates.get(soname, ())


def load_manifest(path: Path) -> CandidateManifest:
    """Load and validate a candidate manifest from ``path``."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as err:
        msg = f"cannot read candidate manifest {path}: {err}"
        raise CandidateError(msg) from err
    except json.JSONDecodeError as err:
        msg = f"candidate manifest {path} is not valid JSON: {err}"
        raise CandidateError(msg) from err
    return CandidateManifest.from_dict(data, base_dir=path.parent)


def _parse_candidate(entry: Any, *, index: int, base_dir: Path) -> LibraryCandidate:  # noqa: ANN401
    if not isinstance(entry, dict):
        msg = f"candidate #{index} must be a JSON object"
        raise CandidateError(msg)
    soname = entry.get("soname")
    if not isinstance(soname, str) or not soname:
        msg = f"candidate #{index} needs a non-empty 'soname'"
        raise CandidateError(msg)
    path_value = entry.get("path")
    if not isinstance(path_value, str) or not path_value:
        msg = f"candidate {soname!r} needs a non-empty 'path'"
        raise CandidateError(msg)

    path = Path(path_value)
    if not path.is_absolute():
        path = base_dir / path
    path = path.resolve()
    if not path.is_file():
        msg = f"candidate {soname!r} points at a missing file: {path}"
        raise CandidateError(msg)

    raw_evidence = entry.get("patch_evidence")
    if not isinstance(raw_evidence, list) or not raw_evidence:
        msg = f"candidate {soname!r} needs at least one patch evidence record"
        raise CandidateError(msg)
    evidence = []
    for raw in raw_evidence:
        if not isinstance(raw, dict):
            msg = f"candidate {soname!r} has malformed patch evidence"
            raise CandidateError(msg)
        policy = raw.get("policy")
        reference = raw.get("reference")
        checksum = raw.get("checksum")
        if not isinstance(policy, str) or not policy:
            msg = f"candidate {soname!r} patch evidence needs a 'policy'"
            raise CandidateError(msg)
        if not isinstance(reference, str) or not reference:
            msg = f"candidate {soname!r} patch evidence needs a 'reference'"
            raise CandidateError(msg)
        if checksum is not None and not isinstance(checksum, str):
            msg = f"candidate {soname!r} patch evidence has a malformed 'checksum'"
            raise CandidateError(msg)
        evidence.append(PatchEvidence(policy, reference, checksum))

    sha256 = entry.get("sha256")
    if sha256 is not None and not isinstance(sha256, str):
        msg = f"candidate {soname!r} has a malformed 'sha256'"
        raise CandidateError(msg)
    variant = entry.get("variant")
    if variant is not None and not isinstance(variant, str):
        msg = f"candidate {soname!r} has a malformed 'variant'"
        raise CandidateError(msg)

    return LibraryCandidate(
        path=path,
        soname=soname,
        patch_evidence=tuple(evidence),
        sha256=sha256,
        variant=variant,
    )


@dataclass(frozen=True)
class SymbolRequirement:
    """One real symbol the wheel imports from an external library."""

    soname: str
    symbol: str
    version: str

    def as_dict(self) -> dict[str, str]:
        return {"soname": self.soname, "symbol": self.symbol, "version": self.version}


@dataclass(frozen=True)
class VersionConflict:
    """A symbol whose required version is not exported by a candidate."""

    soname: str
    symbol: str
    required_version: str
    provided_versions: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "soname": self.soname,
            "symbol": self.symbol,
            "required_version": self.required_version,
            "provided_versions": list(self.provided_versions),
        }


@dataclass(frozen=True)
class SymbolComparison:
    """Comparison of one library's actual requirements with one candidate."""

    soname: str
    candidate: LibraryCandidate
    missing_symbols: tuple[SymbolRequirement, ...]
    version_conflicts: tuple[VersionConflict, ...]

    @property
    def satisfies_symbols(self) -> bool:
        return not self.missing_symbols and not self.version_conflicts

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.candidate.path),
            "variant": self.candidate.variant,
            "digest_verified": self.candidate.digest_verified,
            "satisfies_symbols": self.satisfies_symbols,
            "missing_symbols": [req.as_dict() for req in self.missing_symbols],
            "version_conflicts": [c.as_dict() for c in self.version_conflicts],
        }


@dataclass(frozen=True)
class LibraryComparison:
    soname: str
    required: tuple[SymbolRequirement, ...]
    comparisons: tuple[SymbolComparison, ...]

    def closest_failure(self) -> SymbolComparison | None:
        return min(
            self.comparisons,
            key=lambda c: (len(c.missing_symbols), len(c.version_conflicts)),
            default=None,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "soname": self.soname,
            "required_symbols": [req.as_dict() for req in self.required],
            "candidates": [c.as_dict() for c in self.comparisons],
        }


@dataclass(frozen=True)
class PolicyVerdict:
    """Outcome for one publication policy."""

    policy: str
    priority: int
    retained: bool
    reason: str
    within_baseline: bool = False
    candidates: tuple[str, ...] = ()
    blocked_by: tuple[str, ...] = ()
    missing_symbols: tuple[SymbolRequirement, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "priority": self.priority,
            "retained": self.retained,
            "within_baseline": self.within_baseline,
            "reason": self.reason,
            "candidates": list(self.candidates),
            "blocked_by": list(self.blocked_by),
            "missing_symbols": [req.as_dict() for req in self.missing_symbols],
        }


@dataclass(frozen=True)
class CandidateReport:
    baseline_policy: str
    policies: tuple[PolicyVerdict, ...]
    libraries: tuple[LibraryComparison, ...]

    @property
    def retained(self) -> tuple[PolicyVerdict, ...]:
        return tuple(p for p in self.policies if p.retained)

    @property
    def dropped(self) -> tuple[PolicyVerdict, ...]:
        return tuple(p for p in self.policies if not p.retained)

    @property
    def best_retained(self) -> PolicyVerdict | None:
        retained = [p for p in self.policies if p.retained]
        return max(retained, key=lambda p: p.priority, default=None)

    @property
    def baseline_covered(self) -> bool:
        """Whether a tag at least as compatible as the baseline is retained."""
        baseline = next(p for p in self.policies if p.policy == self.baseline_policy)
        return any(p.retained and p.priority >= baseline.priority for p in self.policies)

    @property
    def baseline_regressions(self) -> tuple[PolicyVerdict, ...]:
        """Originally supported tags that no candidate can be published for."""
        return tuple(p for p in self.dropped if p.within_baseline)

    @property
    def reclaimed(self) -> tuple[PolicyVerdict, ...]:
        """Older tags made reachable by a candidate with independent evidence."""
        return tuple(p for p in self.retained if not p.within_baseline)

    @property
    def unreachable(self) -> tuple[PolicyVerdict, ...]:
        """Older tags neither already supported nor reclaimed by a candidate."""
        return tuple(p for p in self.dropped if not p.within_baseline)

    def as_dict(self) -> dict[str, Any]:
        best = self.best_retained
        return {
            "version": 1,
            "baseline_tag": self.baseline_policy,
            "baseline_covered": self.baseline_covered,
            "best_retained_tag": best.policy if best else None,
            "retained_tags": [p.policy for p in self.retained],
            "reclaimed_tags": [p.policy for p in self.reclaimed],
            "dropped_tags": [p.policy for p in self.baseline_regressions],
            "unreachable_tags": [p.policy for p in self.unreachable],
            "policies": [p.as_dict() for p in self.policies],
            "libraries": [lib.as_dict() for lib in self.libraries],
        }


def compare_library(
    soname: str,
    *,
    imported_symbols: Mapping[str, Mapping[str, set[str]]],
    candidates: tuple[LibraryCandidate, ...],
) -> LibraryComparison:
    requirements = tuple(
        SymbolRequirement(soname, symbol, version)
        for symbol, versions in sorted(imported_symbols.get(soname, {}).items())
        for version in sorted(versions)
    )
    comparisons = []
    for candidate in candidates:
        exported = elf_exported_symbols(candidate.path)
        missing: list[SymbolRequirement] = []
        conflicts: list[VersionConflict] = []
        for requirement in requirements:
            if requirement.symbol in exported.get(requirement.version, set()):
                continue
            versions_for_symbol = tuple(
                sorted(
                    version for version, names in exported.items() if requirement.symbol in names
                )
            )
            if not versions_for_symbol:
                missing.append(requirement)
            else:
                conflicts.append(
                    VersionConflict(
                        soname,
                        requirement.symbol,
                        requirement.version,
                        versions_for_symbol,
                    )
                )
        comparisons.append(SymbolComparison(soname, candidate, tuple(missing), tuple(conflicts)))
    return LibraryComparison(soname, requirements, tuple(comparisons))


def _merge_imports(
    imported_symbols: Mapping[str, Mapping[str, Mapping[str, set[str]]]],
) -> dict[str, dict[str, set[str]]]:
    merged: dict[str, dict[str, set[str]]] = {}
    for per_file in imported_symbols.values():
        for soname, symbols in per_file.items():
            merged.setdefault(soname, {})
            for symbol, versions in symbols.items():
                merged[soname].setdefault(symbol, set()).update(versions)
    return merged


def _with_runtime_policy(
    candidate: LibraryCandidate,
    policies: WheelPolicies,
) -> LibraryCandidate:
    runtime_symbols, _ = elf_symbol_versions(candidate.path)
    runtime_policy = policies.versioned_symbols_policy(runtime_symbols)
    evidence_policies = [
        _resolve_evidence_policy(evidence.policy, policies, candidate)
        for evidence in candidate.patch_evidence
    ]
    return LibraryCandidate(
        path=candidate.path,
        soname=candidate.soname,
        patch_evidence=candidate.patch_evidence,
        sha256=candidate.sha256,
        variant=candidate.variant,
        digest_verified=candidate.verify_digest(),
        runtime_policy=runtime_policy,
        runtime_symbols=runtime_symbols,
        evidence_policies=tuple(evidence_policies),
    )


def _resolve_evidence_policy(
    name: str,
    policies: WheelPolicies,
    candidate: LibraryCandidate,
) -> Policy:
    """Resolve a manifest policy name to this machine's policy table.

    Full names (``manylinux_2_17_x86_64``) and aliases are accepted, as is the
    architecture-less base (``manylinux_2_17``) when it maps unambiguously.
    """
    try:
        return policies.get_policy_by_name(name)
    except LookupError:
        pass
    matches = [
        policy
        for policy in policies
        if policy is not policies.linux and policy.name.startswith(f"{name}_")
    ]
    if len(matches) == 1:
        return matches[0]
    logger.warning(
        "candidate %s has patch evidence for unknown or ambiguous policy %r",
        candidate.label(),
        name,
    )
    return policies.linux


def _runtime_fits(candidate: LibraryCandidate, policy: Policy) -> bool:
    assert candidate.runtime_policy is not None  # noqa: S101
    # A candidate validated on an older/more compatible policy also runs on a
    # newer target.  Policy priorities decrease as the platform gets newer.
    return candidate.runtime_policy.priority >= policy.priority


def _target_policies(policies: WheelPolicies) -> list[Policy]:
    """Every publication policy except the generic ``linux`` tag, newest first.

    The wheel is compatible with the baseline tag and every newer tag, so all
    policies are evaluated; ``PolicyVerdict.within_baseline`` marks the tags the
    wheel could already be published for before any replacement.
    """
    return [policy for policy in policies if policy is not policies.linux]


def compare_candidates(
    *,
    policies: WheelPolicies,
    manifest: CandidateManifest,
    imported_symbols: Mapping[str, Mapping[str, Mapping[str, set[str]]]],
    baseline_policy: Policy,
    residual_policy: Policy | None = None,
    constraint_policies: tuple[Policy, ...] | None = None,
    required_sonames: set[str] | None = None,
) -> CandidateReport:
    """Compare every candidate against the wheel's real requirements.

    ``imported_symbols`` maps each ELF file name to
    ``{library: {symbol: {version, ...}}}``; entries are merged per library.
    ``residual_policy`` is the oldest policy the wheel's non-replaced
    requirements still allow; tags older than it are never reported as
    retained.  ``constraint_policies`` are additional non-replaced constraints
    (UCS2, PyFPE, ISA extensions, blacklisted symbols) folded into the same
    floor.  ``required_sonames`` limits the comparison to libraries the wheel
    actually depends on.  When omitted, every candidate soname is compared.
    """
    merged = _merge_imports(imported_symbols)

    if required_sonames is None:
        sonames = list(manifest.sonames)
    else:
        sonames = sorted(required_sonames & set(manifest.sonames))
        for soname in sorted(set(manifest.sonames) - set(sonames)):
            logger.warning("candidate for %r is not needed by this wheel", soname)
        if not sonames:
            msg = (
                "candidate manifest lists no library this wheel imports "
                f"(manifest: {', '.join(manifest.sonames)})"
            )
            raise CandidateError(msg)

    if residual_policy is None:
        # Requirements from libraries that are *not* replaced still bound the
        # wheel: replacement candidates cannot make an older tag honest when a
        # library left in place already needs something newer.
        residual_symbols = {
            library: set().union(*symbols.values())
            for library, symbols in merged.items()
            if library not in set(sonames)
        }
        # The strictest remaining requirement wins; policy priorities decrease
        # as the platform gets newer, so ``min`` selects it.
        residual_policy = min(
            (
                policies.versioned_symbols_policy(residual_symbols),
                *(constraint_policies or ()),
            )
        )

    libraries = []
    for soname in sonames:
        evaluated = tuple(
            _with_runtime_policy(candidate, policies) for candidate in manifest.for_soname(soname)
        )
        libraries.append(compare_library(soname, imported_symbols=merged, candidates=evaluated))

    verdicts: list[PolicyVerdict] = []
    for policy in _target_policies(policies):
        if policy.priority > residual_policy.priority:
            # Older than what the wheel itself still needs; replacement
            # candidates for external libraries cannot make that tag honest.
            verdicts.append(
                PolicyVerdict(
                    policy.name,
                    policy.priority,
                    False,
                    "wheel's remaining requirements already need a newer policy",
                    within_baseline=policy.priority <= baseline_policy.priority,
                    blocked_by=(residual_policy.name,),
                )
            )
            continue
        retained_by: list[str] = []
        blocked_libraries: list[str] = []
        blocked_details: list[LibraryComparison] = []
        missing: list[SymbolRequirement] = []
        evidence_gaps: list[str] = []
        runtime_gaps: list[str] = []
        for library in libraries:
            if not library.required and not library.comparisons:
                continue
            usable = [
                comparison
                for comparison in library.comparisons
                if comparison.satisfies_symbols
                and comparison.candidate.digest_verified
                and comparison.candidate.covers(policy) is not None
                and _runtime_fits(comparison.candidate, policy)
            ]
            if usable:
                retained_by.extend(c.candidate.label() for c in usable)
                continue
            blocked_libraries.append(library.soname)
            blocked_details.append(library)
            symbol_ok = [
                c
                for c in library.comparisons
                if c.satisfies_symbols and c.candidate.digest_verified
            ]
            if not symbol_ok:
                closest = library.closest_failure()
                if closest is not None:
                    missing.extend(closest.missing_symbols)
                    missing.extend(
                        SymbolRequirement(c.soname, c.symbol, c.required_version)
                        for c in closest.version_conflicts
                    )
                else:
                    missing.extend(library.required)
            elif any(
                c.candidate.runtime_policy is not None and not _runtime_fits(c.candidate, policy)
                for c in symbol_ok
            ):
                # The candidate provides the symbols, but only runs on a newer
                # platform than the target policy allows.
                runtime_gaps.append(
                    ", ".join(
                        f"{c.candidate.label()} requires {c.candidate.runtime_policy.name}"  # type: ignore[union-attr]
                        for c in symbol_ok
                    )
                )
            else:
                evidence_gaps.append(library.soname)

        if not blocked_libraries:
            verdicts.append(
                PolicyVerdict(
                    policy.name,
                    policy.priority,
                    True,
                    "candidate evidence and symbols satisfy the policy",
                    within_baseline=policy.priority <= baseline_policy.priority,
                    candidates=tuple(_dedupe(retained_by)),
                )
            )
        elif missing:
            verdicts.append(
                PolicyVerdict(
                    policy.name,
                    policy.priority,
                    False,
                    "no candidate provides the required symbols",
                    within_baseline=policy.priority <= baseline_policy.priority,
                    blocked_by=tuple(_dedupe(blocked_libraries)),
                    missing_symbols=tuple(missing),
                )
            )
        elif runtime_gaps:
            verdicts.append(
                PolicyVerdict(
                    policy.name,
                    policy.priority,
                    False,
                    "candidate only runs on a newer platform",
                    within_baseline=policy.priority <= baseline_policy.priority,
                    blocked_by=tuple(_dedupe(runtime_gaps)),
                )
            )
        elif any(
            not comparison.candidate.digest_verified
            for library in blocked_details
            for comparison in library.comparisons
        ):
            verdicts.append(
                PolicyVerdict(
                    policy.name,
                    policy.priority,
                    False,
                    "candidate checksum does not match the manifest",
                    within_baseline=policy.priority <= baseline_policy.priority,
                    blocked_by=tuple(_dedupe(blocked_libraries)),
                )
            )
        else:
            verdicts.append(
                PolicyVerdict(
                    policy.name,
                    policy.priority,
                    False,
                    "candidate has no patch evidence for this policy",
                    within_baseline=policy.priority <= baseline_policy.priority,
                    blocked_by=tuple(_dedupe(evidence_gaps or blocked_libraries)),
                )
            )

    return CandidateReport(baseline_policy.name, tuple(verdicts), tuple(libraries))


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return tuple(seen)


def required_sonames(
    manifest: CandidateManifest,
    external_libs: Iterable[str],
    imported_symbols: Mapping[str, Mapping[str, Mapping[str, set[str]]]] | None = None,
) -> set[str]:
    """Return the manifest sonames that the wheel actually imports.

    ``external_libs`` is the set of DT_NEEDED sonames resolved for the wheel;
    ``imported_symbols`` is the per-ELF import map, which also works for wheels
    analyzed offline without a full library search path.
    """
    libs = set(external_libs)
    if imported_symbols:
        for per_file in imported_symbols.values():
            libs.update(per_file)
    result = {soname for soname in manifest.sonames if soname in libs}
    for soname in manifest.sonames:
        base = soname.split(".so")[0] + ".so"
        if any(lib != soname and lib.split(".so")[0] + ".so" == base for lib in libs):
            result.add(soname)
    return result
