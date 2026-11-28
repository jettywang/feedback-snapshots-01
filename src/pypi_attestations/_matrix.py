"""Release-matrix verification for `pypi-attestations`.

This module is NOT a public API, and is not considered stable.

A release ledger ("matrix") records the version/platform combinations that a
release is expected to contain. Matrix verification is deliberately stricter
than single-artifact verification: every target is resolved from an actual
build artifact, and every artifact must carry complete evidence of its own.
This prevents a single signed attestation from being interpreted as approval
for an entire release.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

import packaging.utils
import packaging.version
import sigstore.errors
from annotated_types import MinLen  # noqa: TCH002
from packaging.utils import parse_sdist_filename, parse_wheel_filename
from pydantic import BaseModel, field_validator, model_validator
from pydantic_core import ValidationError
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

from pypi_attestations._impl import (
    Attestation,
    AttestationError,
    Distribution,
    VerificationError,
    _check_dist_filename,
)

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable

    from sigstore.verify.policy import VerificationPolicy


_EVIDENCE_SUFFIXES = (".publish.attestation", ".slsa.attestation")


def _platform_tags(filename: str) -> frozenset[str]:
    """Return the platform tags encoded in a wheel filename."""
    _, _, _, tags = parse_wheel_filename(filename)
    return frozenset(tag.platform for tag in tags)


def _name_and_version(
    filename: str,
) -> tuple[packaging.utils.NormalizedName, packaging.version.Version]:
    """Return the normalized name and version encoded in a distribution filename."""
    if filename.endswith(".whl"):
        name, version, _, _ = parse_wheel_filename(filename)
    else:
        name, version = parse_sdist_filename(filename)
    return name, version


class ReleaseTarget(BaseModel):
    """One expected artifact in a release ledger.

    A target is a (version, platform) slot rather than a filename. The
    actual artifact is discovered by parsing build filenames, so a ledger
    cannot vouch for a build that was never produced.
    """

    platform: str | None = None
    """
    The wheel platform tag this target expects, e.g. `manylinux2014_x86_64`.

    This is `None` for the source distribution, which is platform independent.
    """

    reason: str | None = None
    """
    Why this target is an approved omission.

    An approved target without an artifact does not fail the release, but it
    is still reported as uncovered so the reason is preserved.
    """

    @field_validator("platform")
    @classmethod
    def _validate_platform(cls, v: str | None) -> str | None:
        if v == "":
            raise ValueError("platform must be a non-empty string or null")
        return v

    def matches(self, dist: Distribution) -> bool:
        """Return whether `dist` fills this target's slot."""
        if self.platform is None:
            return not dist.name.endswith(".whl")
        return dist.name.endswith(".whl") and self.platform in _platform_tags(dist.name)


class ReleaseMatrix(BaseModel):
    """The release ledger for one package version."""

    version: Literal[1] = 1
    """
    The matrix format's version, which is always 1.
    """

    name: str
    """
    The package name that every target must belong to.
    """

    release: str
    """
    The distribution version (for example `1.2.3`) shared by every target.
    """

    targets: Annotated[list[ReleaseTarget], MinLen(1)]
    """
    The (version, platform) combinations expected for this release.
    """

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        return str(packaging.utils.canonicalize_name(v))

    @field_validator("release")
    @classmethod
    def _validate_release(cls, v: str) -> str:
        return str(packaging.version.Version(v))

    @model_validator(mode="after")
    def _validate_targets(self) -> ReleaseMatrix:
        seen: set[str | None] = set()
        for target in self.targets:
            if target.platform in seen:
                raise ValueError(f"duplicate platform target: {target.platform!r}")
            seen.add(target.platform)
        return self


class TargetResult(BaseModel):
    """The outcome for one release target."""

    platform: str | None
    """
    The platform slot that was checked.
    """

    artifact: str | None = None
    """
    The artifact that filled this slot, if any.
    """

    admitted: bool = False
    """
    Whether this target was admitted.
    """

    reason: str | None = None
    """
    Why the target was not admitted.
    """

    approved_omission: bool = False
    """
    Whether this is an approved, intentionally absent target.
    """


class MatrixResult(BaseModel):
    """The result of checking a release matrix."""

    name: str
    """
    The package name from the matrix.
    """

    release: str
    """
    The release version from the matrix.
    """

    results: list[TargetResult]
    """
    One result per target, in matrix order.
    """

    unattested: list[str]
    """
    Artifacts present on disk but lacking complete, valid evidence.
    """

    unplanned: list[str]
    """
    Artifacts present on disk that no target claimed.
    """

    @property
    def failed(self) -> bool:
        """Return whether the release is not fully accounted for."""
        if self.unattested:
            return True
        return any(not result.admitted and not result.approved_omission for result in self.results)

    @property
    def admitted(self) -> list[TargetResult]:
        """Return the admitted targets."""
        return [result for result in self.results if result.admitted]

    @property
    def uncovered(self) -> list[TargetResult]:
        """Return the targets not covered by complete evidence."""
        return [result for result in self.results if not result.admitted]

    def format_report(self) -> str:
        """Render a human-readable summary for the CLI."""
        lines = [f"Release matrix: {self.name} {self.release}"]

        lines.append("Admitted targets:")
        if self.admitted:
            for result in self.admitted:
                lines.append(f"  OK   {result.platform or 'sdist'}: {result.artifact}")
        else:
            lines.append("  (none)")

        lines.append("Uncovered targets:")
        if self.uncovered:
            for result in self.uncovered:
                label = result.platform or "sdist"
                suffix = " (approved omission)" if result.approved_omission else ""
                lines.append(f"  MISS {label}{suffix}: {result.reason}")
        else:
            lines.append("  (none)")

        if self.unattested:
            lines.append("Artifacts without complete evidence:")
            for artifact in self.unattested:
                lines.append(f"  - {artifact}")

        if self.unplanned:
            lines.append("Artifacts not in the matrix:")
            for artifact in self.unplanned:
                lines.append(f"  - {artifact}")

        return "\n".join(lines)


class ReleaseMatrixVerifier:
    """Check a release matrix against a directory of build artifacts."""

    def __init__(self, matrix: ReleaseMatrix) -> None:
        """Initialize the verifier."""
        self._matrix = matrix

    @property
    def matrix(self) -> ReleaseMatrix:
        """Return the matrix under verification."""
        return self._matrix

    @classmethod
    def from_file(cls, path: Path) -> ReleaseMatrixVerifier:
        """Load a release matrix from a JSON file."""
        try:
            return cls(ReleaseMatrix.model_validate_json(path.read_bytes()))
        except ValidationError as e:
            raise AttestationError(f"invalid release matrix: {e}") from e
        except OSError as e:
            raise AttestationError(f"could not read release matrix: {e}") from e

    @staticmethod
    def _evidence_paths(artifact: Path) -> list[Path]:
        return [Path(f"{artifact}{suffix}") for suffix in _EVIDENCE_SUFFIXES]

    def _verify_artifact(
        self,
        target: ReleaseTarget,
        artifact: Path,
        policy: VerificationPolicy,
        *,
        verifier: Callable[[Attestation, Distribution], None] | None,
        sigstore_verifier: Verifier | None,
        staging: bool,
        offline: bool,
    ) -> str | None:
        evidence = [path for path in self._evidence_paths(artifact) if path.is_file()]
        if not evidence:
            return "no attestation found"

        dist = Distribution.from_file(artifact)
        if not target.matches(dist):
            return f"artifact does not match platform {target.platform!r}"

        failures: list[str] = []
        for evidence_path in evidence:
            try:
                attestation = Attestation.model_validate_json(evidence_path.read_bytes())
            except ValidationError as e:
                failures.append(f"{evidence_path.name}: invalid attestation: {e}")
                continue

            # Bind the evidence to the artifact before any cryptographic check:
            # an attestation for one artifact must never cover another one.
            binding_error = _evidence_binding_error(attestation, dist)
            if binding_error is not None:
                failures.append(f"{evidence_path.name}: {binding_error}")
                continue

            try:
                if verifier is not None:
                    verifier(attestation, dist)
                else:
                    attestation.verify(
                        policy,
                        dist,
                        staging=staging,
                        offline=offline,
                        verifier=sigstore_verifier,
                    )
            except (AttestationError, sigstore.errors.Error) as e:
                failures.append(f"{evidence_path.name}: {e}")

        if failures:
            return "incomplete evidence: " + "; ".join(failures)
        return None

    def _matches_file(self, target: ReleaseTarget, filename: str) -> bool:
        try:
            name, version = _name_and_version(filename)
        except ValueError:
            return False

        if name != self._matrix.name:
            return False
        if version != packaging.version.Version(self._matrix.release):
            return False

        if target.platform is None:
            return not filename.endswith(".whl")
        return filename.endswith(".whl") and target.platform in _platform_tags(filename)

    def verify(
        self,
        artifact_dir: Path,
        policy: VerificationPolicy,
        *,
        verifier: Callable[[Attestation, Distribution], None] | None = None,
        staging: bool = False,
        offline: bool = False,
        trusted_root: Path | None = None,
    ) -> MatrixResult:
        """Verify the matrix against artifacts in `artifact_dir`.

        Each target is resolved by scanning `artifact_dir` for artifacts whose
        parsed name, version, and platform match. Every matching artifact must
        carry complete evidence of its own; evidence belonging to a different
        artifact never admits a target.

        `verifier` overrides the cryptographic verification step. It receives
        an attestation and the distribution it must cover, and must raise
        `AttestationError` on failure. It is intended for offline tests; by
        default `Attestation.verify` is used.

        `trusted_root` points at a Sigstore trusted-root JSON file. When set,
        signatures are checked against that root instead of the production or
        staging TUF repository, which makes self-contained demos verifiable
        offline.
        """
        sigstore_verifier = (
            _trusted_root_verifier(trusted_root) if trusted_root is not None else None
        )

        artifacts = sorted(
            path for path in artifact_dir.iterdir() if path.is_file() and _is_dist(path.name)
        )

        results: list[TargetResult] = []
        unattested: list[str] = []
        claimed: set[str] = set()

        for target in self._matrix.targets:
            candidates = [
                path
                for path in artifacts
                if path.name not in claimed and self._matches_file(target, path.name)
            ]

            if not candidates:
                if target.reason is not None:
                    results.append(
                        TargetResult(
                            platform=target.platform,
                            admitted=False,
                            reason=target.reason,
                            approved_omission=True,
                        )
                    )
                else:
                    results.append(
                        TargetResult(
                            platform=target.platform,
                            admitted=False,
                            reason="missing artifact for this target",
                        )
                    )
                continue

            if len(candidates) > 1:
                names = ", ".join(path.name for path in candidates)
                results.append(
                    TargetResult(
                        platform=target.platform,
                        admitted=False,
                        reason=f"ambiguous artifacts for this target: {names}",
                    )
                )
                continue

            artifact = candidates[0]
            claimed.add(artifact.name)

            try:
                reason = self._verify_artifact(
                    target,
                    artifact,
                    policy,
                    verifier=verifier,
                    sigstore_verifier=sigstore_verifier,
                    staging=staging,
                    offline=offline,
                )
            except OSError as e:
                reason = f"could not read artifact: {e}"

            if reason is not None:
                unattested.append(artifact.name)
                results.append(
                    TargetResult(
                        platform=target.platform,
                        artifact=artifact.name,
                        admitted=False,
                        reason=reason,
                    )
                )
                continue

            results.append(
                TargetResult(platform=target.platform, artifact=artifact.name, admitted=True)
            )

        unplanned = sorted(path.name for path in artifacts if path.name not in claimed)

        return MatrixResult(
            name=self._matrix.name,
            release=self._matrix.release,
            results=results,
            unattested=sorted(set(unattested)),
            unplanned=unplanned,
        )


def _trusted_root_verifier(trusted_root: Path) -> Verifier:
    """Build a Sigstore verifier pinned to a local trusted-root file."""
    try:
        root = TrustedRoot.from_file(str(trusted_root))
        return Verifier(trusted_root=root)
    except (ValidationError, sigstore.errors.Error) as err:
        raise VerificationError(f"invalid trusted root: {err}") from err


def _is_dist(filename: str) -> bool:
    """Return whether `filename` is a valid distribution filename."""
    try:
        _check_dist_filename(filename)
    except ValueError:
        return False
    return True


def _evidence_binding_error(attestation: Attestation, dist: Distribution) -> str | None:
    """Check that an attestation's statement names `dist` and its digest.

    This is a structural, non-cryptographic check. It exists so that an
    otherwise-valid attestation for a different artifact cannot be reused
    to cover a target. Signature and identity checks still run afterwards.
    """
    try:
        statement = attestation.statement
        subjects = statement.get("subject") or []
    except (ValueError, AttributeError) as e:
        return f"invalid statement: {e}"

    if len(subjects) != 1:
        return f"expected exactly one subject, got {len(subjects)}"

    subject = subjects[0]
    subject_name = subject.get("name")
    if not subject_name:
        return "attestation subject is missing a name"

    try:
        # Compare parsed distribution names so an equivalent wheel tag order
        # (for example a compressed platform tag set) still binds correctly.
        if _check_dist_filename(subject_name) != _check_dist_filename(dist.name):
            return f"attestation subject is {subject_name!r}, expected {dist.name!r}"
    except ValueError as e:
        return f"invalid attestation subject: {e}"

    digest = (subject.get("digest") or {}).get("sha256")
    if digest != dist.digest:
        return "attestation subject digest does not match artifact digest"

    return None


__all__ = [
    "MatrixResult",
    "ReleaseMatrix",
    "ReleaseMatrixVerifier",
    "ReleaseTarget",
    "TargetResult",
]
