"""Check grafted libraries against a reviewed patch attestation.

The attestation is an offline JSON document describing, per SONAME, which
library build was reviewed.  It intentionally records both the resolved path
and the content hash: two distributions may ship a library with the same
SONAME and even the same version but only one of them carries the reviewed
patch.  A backport keeps the upstream version number, so it has to be
explicitly marked as a backport in order to distinguish it from an unpatched
build with an identical version.

Libraries are reported in two scopes:

``external``
    A library auditwheel is about to copy ("graft") into the wheel.
``bundled``
    A library that already ships inside the wheel.

The scope is part of the report so reviewers do not confuse a system
dependency with a vendored one.  Content or location changes invalidate a
reviewed candidate; the new build must be re-reviewed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditwheel.lddtree import LIBPYTHON_RE

if TYPE_CHECKING:
    from auditwheel.wheel_abi import WheelAbIInfo, WheelBundledLibrary

logger = logging.getLogger(__name__)

ATTESTATION_VERSION = 1
REPORT_VERSION = 1

_ACCEPTED = frozenset({"approved", "approved-backport"})
_SCOPE_ORDER = {"external": 0, "bundled": 1}


class PatchAttestationError(ValueError):
    """Raised when a patch attestation document is malformed."""


class PatchCoverageError(ValueError):
    """Raised when the selected libraries are not covered by the attestation."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PatchAttestationError(message)


def _optional_str(value: Any, field_name: str) -> str | None:  # noqa: ANN401
    if value is None:
        return None
    _require(isinstance(value, str) and value != "", f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class PatchCandidate:
    """One reviewed build of a library."""

    soname: str
    candidate_id: str
    path: str | None
    sha256: str | None
    backport: bool
    ext_version: str | None
    upstream_version: str | None
    patch: str | None
    reviewed: bool = True


@dataclass(frozen=True)
class PatchAttestation:
    """A reviewed patch attestation loaded from a JSON document."""

    source: Path
    candidates: dict[str, tuple[PatchCandidate, ...]]

    @classmethod
    def load(cls, path: Path) -> PatchAttestation:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as e:
            msg = f"cannot read {path}: {e}"
            raise PatchAttestationError(msg) from e
        except json.JSONDecodeError as e:
            msg = f"invalid JSON in {path}: {e}"
            raise PatchAttestationError(msg) from e

        _require(isinstance(payload, dict), "attestation must be a JSON object")
        _require(
            payload.get("version") == ATTESTATION_VERSION,
            f"unsupported attestation version: {payload.get('version')!r}",
        )
        patches = payload.get("patches")
        _require(isinstance(patches, list), "'patches' must be a list")

        candidates: dict[str, tuple[PatchCandidate, ...]] = {}
        seen_ids: set[str] = set()
        for index, entry in enumerate(patches):
            _require(isinstance(entry, dict), f"patches[{index}] must be an object")
            soname = entry.get("soname")
            _require(
                isinstance(soname, str) and soname != "",
                f"patches[{index}].soname must be a non-empty string",
            )
            _require(soname not in candidates, f"duplicate SONAME in attestation: {soname}")
            raw_candidates = entry.get("candidates")
            _require(
                isinstance(raw_candidates, list) and bool(raw_candidates),
                f"patches[{index}].candidates must be a non-empty list",
            )

            parsed: list[PatchCandidate] = []
            for candidate_index, raw in enumerate(raw_candidates):
                prefix = f"patches[{index}].candidates[{candidate_index}]"
                _require(isinstance(raw, dict), f"{prefix} must be an object")
                candidate_path = _optional_str(raw.get("path"), f"{prefix}.path")
                candidate_sha = _optional_str(raw.get("sha256"), f"{prefix}.sha256")
                _require(
                    candidate_path is not None or candidate_sha is not None,
                    f"{prefix} must provide 'path' and/or 'sha256'",
                )
                if candidate_sha is not None:
                    _require(
                        len(candidate_sha) == 64
                        and all(c in "0123456789abcdef" for c in candidate_sha),
                        f"{prefix}.sha256 must be a lowercase hex SHA-256 digest",
                    )
                candidate_id = _optional_str(raw.get("id"), f"{prefix}.id")
                if candidate_id is None:
                    candidate_id = f"{soname}#{candidate_index + 1}"
                _require(candidate_id not in seen_ids, f"duplicate candidate id: {candidate_id}")
                seen_ids.add(candidate_id)

                backport = raw.get("backport", False)
                _require(isinstance(backport, bool), f"{prefix}.backport must be a boolean")
                reviewed = raw.get("reviewed", True)
                _require(isinstance(reviewed, bool), f"{prefix}.reviewed must be a boolean")
                parsed.append(
                    PatchCandidate(
                        soname=soname,
                        candidate_id=candidate_id,
                        path=candidate_path,
                        sha256=candidate_sha,
                        backport=backport,
                        ext_version=_optional_str(raw.get("ext_version"), f"{prefix}.ext_version"),
                        upstream_version=_optional_str(
                            raw.get("upstream_version"), f"{prefix}.upstream_version"
                        ),
                        patch=_optional_str(raw.get("patch"), f"{prefix}.patch"),
                        reviewed=reviewed,
                    )
                )
            candidates[soname] = tuple(parsed)

        return cls(source=path.resolve(), candidates=candidates)

    def for_soname(self, soname: str) -> tuple[PatchCandidate, ...]:
        return self.candidates.get(soname, ())


@dataclass
class LibraryVerdict:
    """The outcome of checking one selected library against the attestation."""

    soname: str
    scope: str
    selected_path: str | None
    selected_sha256: str | None
    status: str
    reason: str
    functions: list[str] = field(default_factory=list)
    candidate_id: str | None = None
    candidate_path: str | None = None
    backport: bool = False
    ext_version: str | None = None
    upstream_version: str | None = None
    patch: str | None = None
    attested: bool = False
    member: str | None = None
    shadowed: bool = False

    @property
    def accepted(self) -> bool:
        return self.status in _ACCEPTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "soname": self.soname,
            "scope": self.scope,
            "functions": sorted(set(self.functions)),
            "selected_path": self.selected_path,
            "selected_sha256": self.selected_sha256,
            "status": self.status,
            "accepted": self.accepted,
            "reason": self.reason,
            "attested": self.attested,
            "shadowed": self.shadowed,
            "candidate": (
                None
                if self.candidate_id is None
                else {
                    "id": self.candidate_id,
                    "path": self.candidate_path,
                    "backport": self.backport,
                    "ext_version": self.ext_version,
                    "upstream_version": self.upstream_version,
                    "patch": self.patch,
                }
            ),
        }


@dataclass
class DeliveredLibrary:
    """A library file that ended up in the repaired wheel.

    ``copied_sha256`` is taken right after copying the approved source, before
    auditwheel rewrites SONAME/RPATH.  ``final_sha256`` is taken after those
    rewrites.  The archive hash must match ``final_sha256``, and the copied
    bytes must match the approved source.
    """

    soname: str
    scope: str
    member: str
    selected_sha256: str | None
    final_sha256: str
    modified: bool
    copied_sha256: str | None = None


@dataclass
class CoverageReport:
    """Patch coverage for one wheel."""

    wheel: str
    policy: str
    attestation: str | None
    require_patch_coverage: bool
    libraries: list[LibraryVerdict]
    repaired: dict[str, Any] | None = None

    @property
    def failed_libraries(self) -> list[LibraryVerdict]:
        failed = []
        for verdict in self.libraries:
            if verdict.accepted:
                continue
            if verdict.status == "uncovered":
                if self.require_patch_coverage and verdict.scope == "external":
                    failed.append(verdict)
                continue
            if verdict.attested:
                failed.append(verdict)
        return failed

    @property
    def coverage_complete(self) -> bool:
        return all(
            verdict.attested
            for verdict in self.libraries
            if verdict.scope == "external"
        )

    @property
    def passed(self) -> bool:
        return not self.failed_libraries

    def verdict_for(self, soname: str, scope: str) -> LibraryVerdict | None:
        return next(
            (v for v in self.libraries if v.soname == soname and v.scope == scope),
            None,
        )

    def _summary(self) -> dict[str, int]:
        summary = {
            "selected": len(self.libraries),
            "approved": 0,
            "approved_backport": 0,
            "unapproved": 0,
            "stale": 0,
            "rejected": 0,
            "unresolved": 0,
            "uncovered": 0,
            "conflict": 0,
        }
        for verdict in self.libraries:
            key = verdict.status.replace("-", "_")
            if key in summary:
                summary[key] += 1
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": REPORT_VERSION,
            "wheel": self.wheel,
            "policy": self.policy,
            "attestation": self.attestation,
            "require_patch_coverage": self.require_patch_coverage,
            "coverage_complete": self.coverage_complete,
            "passed": self.passed,
            "summary": self._summary(),
            "libraries": [
                v.to_dict()
                for v in sorted(
                    self.libraries, key=lambda v: (v.soname, _SCOPE_ORDER.get(v.scope, 9))
                )
            ],
            "repaired": self.repaired,
        }

    def failure_message(self) -> str:
        lines = []
        for verdict in self.failed_libraries:
            lines.append(f"  {verdict.soname} [{verdict.scope}] {verdict.status}: {verdict.reason}")
        return "\n".join(lines)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")


@dataclass(frozen=True)
class _SelectedFile:
    scope: str
    path: Path | None
    sha256: str | None
    member: str | None


@dataclass
class _Selection:
    soname: str
    scope: str
    files: list[_SelectedFile] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    shadowed: bool = False


def _collect_selections(
    wheel_abi: WheelAbIInfo,
    policy_name: str,
) -> list[_Selection]:
    selections: dict[tuple[str, str], _Selection] = {}

    def selection_for(soname: str, scope: str) -> _Selection:
        return selections.setdefault((soname, scope), _Selection(soname, scope))

    def add_external(soname: str, path: Path | None, function: str) -> None:
        selection = selection_for(soname, "external")
        selection.functions.append(function)
        if path is None:
            selection.files.append(_SelectedFile("external", None, None, None))
            return
        resolved = path.resolve()
        selection.files.append(_SelectedFile("external", resolved, None, None))

    for fn, refs_by_policy in wheel_abi.full_external_refs.items():
        refs = refs_by_policy.get(policy_name)
        if refs is None:
            continue
        # ``full_external_refs`` is keyed by the absolute staging path; report
        # the member path a reviewer sees inside the wheel.
        function = fn.name
        for soname, library_path in refs.libs.items():
            # libpython is removed from the wheel, never grafted.
            if LIBPYTHON_RE.match(soname):
                continue
            add_external(soname, library_path, function)

    for soname, bundled_entries in getattr(wheel_abi, "bundled_libs", {}).items():
        selection = selection_for(soname, "bundled")
        for entry in bundled_entries:
            selection.files.append(
                _SelectedFile("bundled", None, entry.sha256, entry.member)
            )

    # A SONAME that is both required externally and present in the wheel is
    # resolved from the wheel at runtime. Flag that explicitly so a reviewer
    # does not mistake the external entry for the file that ships.
    external_sonames = {soname for soname, scope in selections if scope == "external"}
    bundled_sonames = {soname for soname, scope in selections if scope == "bundled"}
    for soname in sorted(bundled_sonames & external_sonames):
        selections[(soname, "external")].shadowed = True

    for (soname, scope), selection in selections.items():
        del soname, scope
        if not selection.functions:
            selection.functions.append("<bundled in wheel>")

    return list(selections.values())


def _resolve_candidate_path(candidate: PatchCandidate, base_dir: Path) -> Path | None:
    if candidate.path is None:
        return None
    path = Path(candidate.path)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _evaluate_candidate(
    candidate: PatchCandidate,
    base_dir: Path,
    selected_file: _SelectedFile,
    selected_sha256: str | None,
) -> tuple[str, str] | None:
    selected_path = selected_file.path
    candidate_path = _resolve_candidate_path(candidate, base_dir)

    path_match = False
    if candidate_path is not None and selected_path is not None:
        try:
            path_match = candidate_path.samefile(selected_path)
        except OSError:
            path_match = candidate_path == selected_path.resolve()

    if selected_file.member is not None and candidate.path is not None:
        member = candidate.path.replace("\\", "/").removeprefix("./")
        path_match = path_match or member == selected_file.member

    sha_match = candidate.sha256 is not None and selected_sha256 == candidate.sha256
    if not path_match and not sha_match:
        return None

    if not candidate.reviewed:
        return "rejected", "candidate is marked as not reviewed"
    if candidate.sha256 is None:
        return "approved", "matched by path; attestation has no content hash"
    if not sha_match:
        return "stale", "file content changed since review"

    if candidate.backport:
        missing = [
            name
            for name, value in (
                ("patch", candidate.patch),
                ("ext_version", candidate.ext_version),
                ("upstream_version", candidate.upstream_version),
            )
            if value is None
        ]
        if missing:
            return "stale", f"backport attestation missing {', '.join(missing)}"
        if candidate.ext_version != candidate.upstream_version:
            return (
                "stale",
                "backport must keep the upstream version; "
                f"attestation has {candidate.ext_version} != {candidate.upstream_version}",
            )
        return "approved-backport", f"reviewed backport {candidate.patch}"

    if (
        candidate.ext_version is not None
        and candidate.upstream_version is not None
        and candidate.ext_version != candidate.upstream_version
    ):
        return (
            "stale",
            "version changed without a backport attestation: "
            f"{candidate.ext_version} != {candidate.upstream_version}",
        )
    if (
        candidate.patch is not None
        and candidate.ext_version is not None
        and candidate.ext_version == candidate.upstream_version
    ):
        return (
            "stale",
            "a patch was applied without changing the version; "
            "mark the candidate as a backport to assert the reviewed patch",
        )
    return "approved", "reviewed library content matches"


def _evaluate_selection(
    selection: _Selection,
    attestation: PatchAttestation | None,
    require_patch_coverage: bool,
    shadowed: bool = False,
) -> LibraryVerdict:
    attested_candidates = () if attestation is None else attestation.for_soname(selection.soname)
    attested = bool(attested_candidates)

    unique: dict[tuple[str | None, str | None, str | None], _SelectedFile] = {}
    for entry in selection.files:
        key = (
            None if entry.path is None else str(entry.path),
            entry.sha256,
            entry.member,
        )
        unique[key] = entry
    files = list(unique.values())

    base: dict[str, Any] = {
        "soname": selection.soname,
        "scope": selection.scope,
        "selected_path": None,
        "selected_sha256": None,
        "functions": selection.functions,
        "attested": attested,
        "shadowed": shadowed,
    }

    if not files:
        return LibraryVerdict(**base, status="unresolved", reason="library was not resolved")

    if len(files) > 1:
        locations = ", ".join(
            str(f.path) if f.path is not None else str(f.member) for f in files
        )
        return LibraryVerdict(
            **base,
            status="conflict",
            reason=f"SONAME resolves to multiple files: {locations}",
        )

    selected = files[0]
    selected_sha256 = selected.sha256
    if selected_sha256 is None and selected.path is not None and selected.path.is_file():
        selected_sha256 = sha256_file(selected.path)
    base.update(
        {
            "selected_path": (
                str(selected.path) if selected.path is not None else selected.member
            ),
            "selected_sha256": selected_sha256,
            "member": selected.member,
        }
    )

    if not attested:
        reason = "no patch attestation entry for this SONAME"
        if require_patch_coverage and selection.scope == "external":
            reason += "; required patch coverage is missing"
        return LibraryVerdict(**base, status="uncovered", reason=reason)

    if selected_sha256 is None:
        return LibraryVerdict(
            **base,
            status="unresolved",
            reason="attested library could not be resolved on disk",
        )

    matches: list[tuple[str, str, PatchCandidate]] = []
    for candidate in attested_candidates:
        evaluated = _evaluate_candidate(
            candidate, attestation.source.parent, selected, selected_sha256
        )
        if evaluated is not None:
            status, reason = evaluated
            matches.append((status, reason, candidate))

    accepted = [m for m in matches if m[0] in _ACCEPTED]
    if len(accepted) == 1 and len(matches) == 1:
        status, reason, candidate = accepted[0]
        return LibraryVerdict(
            **base,
            status=status,
            reason=reason,
            candidate_id=candidate.candidate_id,
            candidate_path=candidate.path,
            backport=candidate.backport,
            ext_version=candidate.ext_version,
            upstream_version=candidate.upstream_version,
            patch=candidate.patch,
        )
    if len(accepted) > 1:
        ids = ", ".join(m[2].candidate_id for m in accepted)
        return LibraryVerdict(
            **base,
            status="conflict",
            reason=f"multiple reviewed candidates match: {ids}",
        )
    if matches:
        priority = {"rejected": 0, "stale": 1, "conflict": 2}
        status, reason, candidate = min(matches, key=lambda m: priority.get(m[0], 3))
        return LibraryVerdict(
            **base,
            status=status,
            reason=reason,
            candidate_id=candidate.candidate_id,
            candidate_path=candidate.path,
            backport=candidate.backport,
            ext_version=candidate.ext_version,
            upstream_version=candidate.upstream_version,
            patch=candidate.patch,
        )
    return LibraryVerdict(
        **base,
        status="unapproved",
        reason="selected library is not any of the reviewed candidates "
        "(path and content hash differ)",
    )


def evaluate_graft_plan(
    wheel_abi: WheelAbIInfo,
    policy_name: str,
    attestation: PatchAttestation | None,
    require_patch_coverage: bool = False,
) -> CoverageReport:
    """Evaluate the exact library selection auditwheel is about to graft.

    ``policy_name`` must be the policy whose ``libs`` mapping ``repair_wheel``
    consumes, i.e. ``abis[0]``.
    """
    selections = _collect_selections(wheel_abi, policy_name)
    verdicts = [
        _evaluate_selection(
            selection, attestation, require_patch_coverage, selection.shadowed
        )
        for selection in selections
    ]
    wheel = getattr(wheel_abi, "wheel_path", None)
    return CoverageReport(
        wheel="" if wheel is None else wheel.name,
        policy=policy_name,
        attestation=None if attestation is None else str(attestation.source),
        require_patch_coverage=require_patch_coverage,
        libraries=verdicts,
    )


def verify_delivered_libraries(
    report: CoverageReport,
    output_wheel: Path,
    delivered: list[DeliveredLibrary],
) -> bool:
    """Confirm that the files packed in ``output_wheel`` are the approved ones.

    The wheel archive is the source of truth: every delivered library is
    re-hashed from the archive instead of trusting the staging directory.
    """
    by_key = {(entry.soname, entry.scope): entry for entry in delivered}
    results: list[dict[str, Any]] = []
    all_ok = True

    with zipfile.ZipFile(output_wheel) as zf:
        names = set(zf.namelist())
        for verdict in sorted(
            report.libraries,
            key=lambda v: (v.soname, _SCOPE_ORDER.get(v.scope, 9)),
        ):
            if verdict.scope != "external" or not verdict.accepted:
                continue
            entry = by_key.get((verdict.soname, verdict.scope))
            result: dict[str, Any] = {
                "soname": verdict.soname,
                "scope": verdict.scope,
                "candidate_id": verdict.candidate_id,
                "member": None if entry is None else entry.member,
                "delivered": False,
            }
            if entry is None:
                result["reason"] = "approved library is missing from the repaired wheel"
                all_ok = False
                results.append(result)
                continue
            if entry.member not in names:
                result["reason"] = "approved library is missing from the repaired wheel"
                all_ok = False
                results.append(result)
                continue

            archive_sha256 = hashlib.sha256(zf.read(entry.member)).hexdigest()
            result["sha256"] = archive_sha256
            result["modified"] = entry.modified
            if (
                entry.copied_sha256 is not None
                and verdict.selected_sha256 is not None
                and entry.copied_sha256 != verdict.selected_sha256
            ):
                result["reason"] = "grafted copy differs from the approved source content"
                all_ok = False
            elif archive_sha256 != entry.final_sha256:
                result["reason"] = "packed file differs from the verified grafted copy"
                all_ok = False
            elif entry.modified:
                result["delivered"] = True
                result["reason"] = (
                    "packed file matches the approved source after auditwheel "
                    "rewrote SONAME/RPATH"
                )
            elif verdict.selected_sha256 is not None and archive_sha256 != verdict.selected_sha256:
                result["reason"] = "packed file differs from the approved source content"
                all_ok = False
            else:
                result["delivered"] = True
                result["reason"] = "packed file matches the approved library"
            results.append(result)

    for entry in delivered:
        verdict = next(
            (
                v
                for v in report.libraries
                if v.soname == entry.soname and v.scope == entry.scope
            ),
            None,
        )
        if verdict is None or not verdict.accepted:
            all_ok = False
            results.append(
                {
                    "soname": entry.soname,
                    "scope": entry.scope,
                    "candidate_id": None if verdict is None else verdict.candidate_id,
                    "member": entry.member,
                    "delivered": False,
                    "reason": "grafted library has no accepted patch verdict",
                }
            )

    report.repaired = {"passed": all_ok, "libraries": results}
    return all_ok
