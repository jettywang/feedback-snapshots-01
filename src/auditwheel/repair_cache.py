"""Content-addressed records for ``auditwheel repair`` results.

The key is derived from what ``repair_wheel`` actually consumes rather than
from the command line which produced it: the input wheel bytes, the resolved
external libraries, the effective policy catalogue, the concrete ELF patcher,
and the output-affecting options.  Search paths are not part of the key; they
only explain *how* a library was found.  The absolute source path is kept
separate because it can leak into the SBOM.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditwheel.hashfile import hashfile
from auditwheel.lddtree import LIBPYTHON_RE

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from auditwheel.patcher import ElfPatcher
    from auditwheel.policy import Policy, WheelPolicies
    from auditwheel.wheel_abi import WheelAbIInfo

CACHE_SCHEMA = 1
DEFAULT_REVIEW_DAYS = 90
_RECORDS_DIR = "records"
_ALIASES_DIR = "aliases"
_ARTIFACTS_DIR = "artifacts"
_SBOM_SUFFIX = "/sboms/auditwheel.cdx.json"


class RepairCacheError(Exception):
    """Base class for repair cache errors."""


class RepairCacheCollision(RepairCacheError):
    """One key produced two different reproducible output wheels."""


@dataclass(frozen=True)
class LibraryIdentity:
    """Identity of one library which ``repair_wheel`` would graft.

    ``source_path`` is provenance only and is excluded from
    :meth:`RepairInputs.cache_key`.  The basename is included because
    ``repair.copylib`` derives the grafted soname from it.
    """

    soname: str
    source_name: str | None
    content_sha256: str | None
    source_path: str | None = field(default=None, compare=False)

    def proof(self) -> dict[str, Any]:
        return {
            "soname": self.soname,
            "source_name": self.source_name,
            "content_sha256": self.content_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        result = self.proof()
        result["source_path"] = self.source_path
        return result


@dataclass(frozen=True)
class WheelExternal:
    """External references of one wheel-relative ELF file."""

    wheel_path: str
    libraries: tuple[LibraryIdentity, ...]

    def proof(self) -> dict[str, Any]:
        return {
            "wheel_path": self.wheel_path,
            "libraries": [
                library.proof() for library in sorted(self.libraries, key=lambda item: item.soname)
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "wheel_path": self.wheel_path,
            "libraries": [
                library.to_dict()
                for library in sorted(self.libraries, key=lambda item: item.soname)
            ],
        }


@dataclass(frozen=True)
class PolicyIdentity:
    """The effective policy catalogue used to analyse and name the wheel."""

    libc: str
    architecture: str
    fingerprint: str
    policies: tuple[str, ...]

    def proof(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class PatcherIdentity:
    """The concrete ELF rewriter, not just its command-line name."""

    variant: str
    tool: str
    platform: str

    def proof(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class StripIdentity:
    """The binary used by ``repair_wheel(strip=True)``, if any."""

    tool: str

    def proof(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class RepairInputs:
    """Everything which can change the result of one ``repair_wheel`` call."""

    wheel_filename: str
    wheel_sha256: str
    externals: tuple[WheelExternal, ...]
    target_abis: tuple[str, ...]
    policy: PolicyIdentity
    patcher: PatcherIdentity
    lib_sdir: str
    update_tags: bool
    strip: bool
    strip_tool: StripIdentity
    zip_compression_level: int
    implementation: str
    source_date_epoch: str | None = None
    zlib_version: str | None = None
    sbom_environment: str = "unspecified"
    schema: int = CACHE_SCHEMA

    def __post_init__(self) -> None:
        if not self.target_abis:
            msg = "target_abis must contain at least one platform tag"
            raise ValueError(msg)
        if self.zlib_version is None:
            object.__setattr__(self, "zlib_version", zlib.ZLIB_VERSION)
        if not self.strip:
            # The strip tool cannot influence a run which does not strip.
            object.__setattr__(self, "strip_tool", StripIdentity("unused"))

    @property
    def target_policy(self) -> str:
        """The policy whose external references are actually grafted."""
        return self.target_abis[0]

    def proof(self) -> dict[str, Any]:
        """Fields which affect repair behaviour, excluding provenance."""
        return {
            "schema": self.schema,
            "implementation": self.implementation,
            "wheel_filename": self.wheel_filename,
            "wheel_sha256": self.wheel_sha256,
            "externals": [item.proof() for item in _sorted_externals(self.externals)],
            "target_abis": list(self.target_abis),
            "policy": self.policy.proof(),
            "patcher": self.patcher.proof(),
            "lib_sdir": self.lib_sdir,
            "update_tags": self.update_tags,
            "strip": self.strip,
            "strip_tool": self.strip_tool.proof(),
            "zip_compression_level": self.zip_compression_level,
            "source_date_epoch": self.source_date_epoch,
            "zlib_version": self.zlib_version,
            "sbom_environment": self.sbom_environment,
        }

    def cache_key(self) -> str:
        """Key for the repair semantics: same key means same patch result."""
        return _sha256_text(_canonical_json(self.proof()))

    def provenance(self) -> dict[str, Any]:
        """Path provenance which may leak into an SBOM component ``bom-ref``.

        ``sboms.create_sbom_for_wheel`` hashes ``str(filepath)`` for every
        grafted library, so relocating an identical library normally changes
        the output bytes when an SBOM is emitted.
        """
        return {
            "wheel_filename": self.wheel_filename,
            "externals": [
                {
                    "wheel_path": item.wheel_path,
                    "libraries": [
                        {
                            "soname": library.soname,
                            "source_path": library.source_path,
                        }
                        for library in sorted(
                            item.libraries,
                            key=lambda library: library.soname,
                        )
                        if library.source_path is not None
                    ],
                }
                for item in _sorted_externals(self.externals)
            ],
        }

    def provenance_key(self) -> str:
        return _sha256_text(_canonical_json([self.cache_key(), self.provenance()]))

    def to_dict(self) -> dict[str, Any]:
        result = self.proof()
        result["externals"] = [item.to_dict() for item in _sorted_externals(self.externals)]
        result["cache_key"] = self.cache_key()
        result["provenance_key"] = self.provenance_key()
        return result


@dataclass(frozen=True)
class Approval:
    """An approval of a repair report for one platform tag.

    ``release`` scopes the approval.  A new release must pass its own
    release identifier to :meth:`RepairCache.lookup`; an approval granted for
    an older release remains queryable but cannot authorise the new one.
    """

    platform: str
    approved_at: str
    approver: str
    note: str | None = None
    release: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class RepairRecord:
    """One immutable repair result record."""

    record_key: str
    cache_key: str
    created_at: str
    review_after: str
    status: str
    proof: dict[str, Any]
    inputs: dict[str, Any]
    output: dict[str, Any]
    approvals: tuple[Approval, ...] = ()
    supersedes: str | None = None
    superseded_by: str | None = None
    artifact_path: str | None = None
    notes: str | None = None
    revision: int = 1
    schema: int = CACHE_SCHEMA

    @property
    def wheel_filename(self) -> str:
        return str(self.inputs["wheel_filename"])

    @property
    def target_abis(self) -> tuple[str, ...]:
        return tuple(self.inputs["target_abis"])

    @property
    def sbom_emitted(self) -> bool:
        return bool(self.output.get("sbom_emitted", False))

    def approval_for(
        self,
        platform: str,
        *,
        release: str | None = None,
        approved_after: datetime | None = None,
    ) -> Approval | None:
        for approval in self.approvals:
            if approval.platform != platform:
                continue
            if release is not None and approval.release != release:
                continue
            if approved_after is not None and _parse_datetime(
                approval.approved_at,
            ) < _utcnow(approved_after):
                continue
            return approval
        return None

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        result["approvals"] = [approval.to_dict() for approval in self.approvals]
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RepairRecord:
        approvals = tuple(Approval(**item) for item in data.get("approvals", ()))
        return cls(
            record_key=str(data["record_key"]),
            cache_key=str(data["cache_key"]),
            created_at=str(data["created_at"]),
            review_after=str(data["review_after"]),
            status=str(data["status"]),
            proof=dict(data["proof"]),
            inputs=dict(data["inputs"]),
            output=dict(data["output"]),
            approvals=approvals,
            supersedes=data.get("supersedes"),
            superseded_by=data.get("superseded_by"),
            artifact_path=data.get("artifact_path"),
            notes=data.get("notes"),
            revision=int(data.get("revision", 1)),
            schema=int(data.get("schema", CACHE_SCHEMA)),
        )


@dataclass(frozen=True)
class MigrationRecord:
    """Evidence that a relocated library set is output-equivalent.

    This is deliberately a separate record: it does not approve anything and
    it only applies to one provenance key.  ``evidence`` must name how the
    equivalence was established, for example ``sbom_absent`` or
    ``byte-identical-output``.
    """

    record_key: str
    canonical_key: str
    verified_at: str
    verified_output_sha256: str
    evidence: str
    source_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        result["source_paths"] = list(self.source_paths)
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MigrationRecord:
        return cls(
            record_key=str(data["record_key"]),
            canonical_key=str(data["canonical_key"]),
            verified_at=str(data["verified_at"]),
            verified_output_sha256=str(data["verified_output_sha256"]),
            evidence=str(data["evidence"]),
            source_paths=tuple(data.get("source_paths", ())),
        )


@dataclass(frozen=True)
class ReuseDecision:
    """The answer to "may this repair result be reused?"."""

    reusable: bool
    cache_key: str
    reason: str
    record: RepairRecord | None = None
    artifact_path: Path | None = None
    migration: MigrationRecord | None = None

    def explain(self) -> str:
        if self.record is None:
            return f"{self.cache_key}: {self.reason}"
        return (
            f"{self.cache_key}: {self.reason} "
            f"(created {self.record.created_at}, review after {self.record.review_after})"
        )


@dataclass(frozen=True)
class Invalidation:
    """One reason a previous record cannot be reused."""

    kind: str
    changed: tuple[str, ...]
    retained: tuple[str, ...]
    recheck: tuple[str, ...]


_RETAINED: dict[str, tuple[str, ...]] = {
    "dependency_resolution": (
        "previous per-soname library content SHA-256 and source basename",
        "previous source paths as provenance only",
        "previous wheel SHA-256 and the approved platform reports",
    ),
    "target_policy": (
        "previous policy fingerprint and the target ABI/alias list",
        "previous symbol, blacklist, UCS and ISA policy decisions",
        "previous approvals; they remain queryable but do not authorise a new publish",
    ),
    "patcher_tool": (
        "previous patcher variant, tool identity and platform",
        "previous output digest for comparison",
        "previous approval records as historical evidence",
    ),
    "input_wheel": (
        "previous wheel filename and SHA-256",
        "previous report and approvals as historical evidence",
    ),
    "repair_options": (
        "previous option values, strip tool identity and output digest",
        "previous approvals as historical evidence",
    ),
    "sbom_environment": (
        "previous SBOM environment fingerprint and emitted SBOM digest",
        "previous approvals as historical evidence",
    ),
}

_RECHECK: dict[str, tuple[str, ...]] = {
    "dependency_resolution": (
        "run `auditwheel show <wheel>` or `analyze_wheel_abi(...)` again",
        "compare each resolved library path and SHA-256 against the record",
        "confirm `--exclude`, `--ldpaths` and AUDITWHEEL_LD_LIBRARY_PATH were intentional",
        "call `capture_repair_inputs(...)` after re-resolution and compare cache keys",
    ),
    "target_policy": (
        "re-run the `main_repair.execute` gates: sym_policy, ucs_policy, "
        "blacklist_policy, machine_policy",
        "inspect `WheelPolicies.get_policy_by_name(target)` and `get_replace_platforms`",
        "compare the effective `PolicyIdentity.fingerprint`",
    ),
    "patcher_tool": (
        "call `ElfPatcher.get_patcher(variant, platform)` and read `tool_identity`",
        "verify the executable behind `patchelf` or `lief-patchelf`",
        "re-run the stand-in repair and compare the output SHA-256",
    ),
    "input_wheel": (
        "fetch the exact wheel again and verify its SHA-256",
        "run `auditwheel show <wheel>`",
    ),
    "repair_options": (
        "compare `--lib-sdir`, `--no-update-tags`, `--strip`, "
        "`--zip-compression-level` and SOURCE_DATE_EPOCH",
        "re-run `repair_wheel` with the current option values",
    ),
    "sbom_environment": (
        "call `identify_sbom_environment` on the grafted library paths",
        "compare package purls with the recorded SBOM components",
        "re-run `create_sbom_for_wheel` and compare the SBOM digest",
    ),
}


def capture_repair_inputs(
    wheel_abi: WheelAbIInfo,
    wheel_path: Path,
    *,
    abis: Sequence[str],
    lib_sdir: str,
    update_tags: bool,
    strip: bool,
    zip_compression_level: int,
    patcher: ElfPatcher,
    implementation: str | None = None,
    source_date_epoch: str | None = None,
    strip_tool: str | None = None,
    sbom_environment: str | None = None,
) -> RepairInputs:
    """Capture the inputs which actually drive :func:`repair_wheel`.

    Only the external references for ``abis[0]`` are captured: that is the
    single map ``repair_wheel`` reads.  The other policy maps are already
    summarised by :class:`PolicyIdentity` and the selected ``abis``.
    """
    if not abis:
        msg = "abis must contain at least one platform tag"
        raise ValueError(msg)

    target_policy = abis[0]
    externals: list[WheelExternal] = []
    for wheel_relative_path, references_by_policy in sorted(
        wheel_abi.full_external_refs.items(),
        key=lambda item: item[0].as_posix(),
    ):
        reference = references_by_policy.get(target_policy)
        if reference is None:
            msg = (
                f"no external reference information for {target_policy!r} "
                f"while capturing {wheel_relative_path}"
            )
            raise ValueError(msg)

        libraries: list[LibraryIdentity] = []
        for soname, source in sorted(reference.libs.items()):
            if source is None:
                if not LIBPYTHON_RE.match(soname):
                    msg = (
                        f"cannot cache an unresolvable library {soname!r} "
                        f"for {wheel_relative_path}"
                    )
                    raise ValueError(msg)
                # repair_wheel removes libpython dependencies instead of
                # grafting them, so there is no file identity to hash.
                libraries.append(LibraryIdentity(soname, None, None))
                continue

            with source.open("rb") as file_handle:
                digest = hashfile(file_handle)
            libraries.append(
                LibraryIdentity(
                    soname=soname,
                    source_name=source.name,
                    content_sha256=digest,
                    source_path=str(source),
                ),
            )
        externals.append(
            WheelExternal(
                wheel_path=wheel_relative_path.as_posix(),
                libraries=tuple(libraries),
            ),
        )

    with wheel_path.open("rb") as file_handle:
        wheel_sha256 = hashfile(file_handle)

    source_paths = [
        library.source_path
        for external in externals
        for library in external.libraries
        if library.source_path is not None
    ]
    return RepairInputs(
        wheel_filename=wheel_path.name,
        wheel_sha256=wheel_sha256,
        externals=tuple(externals),
        target_abis=tuple(abis),
        policy=identify_policies(wheel_abi.policies),
        patcher=identify_patcher(patcher),
        lib_sdir=lib_sdir,
        update_tags=update_tags,
        strip=strip,
        strip_tool=identify_strip_tool(strip=strip, tool=strip_tool),
        zip_compression_level=zip_compression_level,
        implementation=implementation or _implementation_version(),
        source_date_epoch=(
            source_date_epoch
            if source_date_epoch is not None
            else os.environ.get("SOURCE_DATE_EPOCH")
        ),
        sbom_environment=(
            sbom_environment
            if sbom_environment is not None
            else identify_sbom_environment(source_paths)
        ),
    )


def identify_policies(policies: WheelPolicies) -> PolicyIdentity:
    """Return a deterministic identity for the effective policy catalogue."""
    payload = {
        "libc": policies.libc.value,
        "architecture": policies.architecture.value,
        "musl_policy": getattr(policies, "_musl_policy", None),
        "policies": [_policy_payload(policy) for policy in policies],
    }
    return PolicyIdentity(
        libc=policies.libc.value,
        architecture=policies.architecture.value,
        fingerprint=_sha256_text(_canonical_json(payload)),
        policies=tuple(policy.name for policy in policies),
    )


def identify_patcher(patcher: ElfPatcher) -> PatcherIdentity:
    return PatcherIdentity(
        variant=str(getattr(patcher, "variant", "unknown")),
        tool=str(patcher.tool_identity),
        platform=str(patcher.platform),
    )


def identify_sbom_environment(filepaths: Sequence[str]) -> str:
    """Fingerprint the package metadata which ``create_sbom_for_wheel`` sees.

    The SBOM names the packages owning each grafted library via
    ``whichprovides``.  An OS update can change those purls without changing
    any library byte, so this is a repair input, not just reporting metadata.
    """
    if not filepaths:
        return "no-libraries"
    try:
        from auditwheel._vendor.whichprovides import whichprovides
    except ImportError:  # pragma: no cover - vendored module is shipped
        return "unavailable"
    try:
        packages = whichprovides(list(filepaths))
    except Exception:  # noqa: BLE001 - package databases are unreliable
        return "unavailable"
    if not packages:
        return "no-provider"
    purls = sorted({provided.purl for provided in packages.values()})
    return f"sha256:{_sha256_text(_canonical_json(purls))}"


def identify_strip_tool(*, strip: bool, tool: str | None = None) -> StripIdentity:
    """Identify the ``strip`` implementation when stripping is requested."""
    if not strip:
        return StripIdentity("unused")
    if tool is None:
        executable = shutil.which("strip")
        if executable is None:
            return StripIdentity("strip:not-found")
        try:
            with Path(executable).open("rb") as file_handle:
                digest = hashfile(file_handle)
        except OSError:
            return StripIdentity(f"strip:{executable}")
        return StripIdentity(f"strip:{executable}:sha256:{digest}")
    return StripIdentity(tool)


class RepairCache:
    """Append-only, content-addressed store of repair records."""

    def __init__(
        self,
        root: Path,
        *,
        review_days: int = DEFAULT_REVIEW_DAYS,
        store_artifacts: bool = False,
    ) -> None:
        if review_days < 0:
            msg = "review_days must be non-negative"
            raise ValueError(msg)
        self.root = root
        self.review_days = review_days
        self.store_artifacts = store_artifacts

    @property
    def records_dir(self) -> Path:
        return self.root / _RECORDS_DIR

    @property
    def aliases_dir(self) -> Path:
        return self.root / _ALIASES_DIR

    def record(
        self,
        inputs: RepairInputs,
        output_wheel: Path,
        *,
        approvals: Iterable[Approval] = (),
        notes: str | None = None,
        now: datetime | None = None,
    ) -> RepairRecord:
        """Store one successful repair.  Repeating an identical repair is a no-op."""
        now = _utcnow(now)
        record_key = inputs.provenance_key()
        output = _output_identity(output_wheel)

        existing = self.get_by_record_key(record_key)
        if existing is not None and existing.status == "verified":
            # Without SOURCE_DATE_EPOCH the zip timestamps come from "now", so
            # byte identity is not expected.  With it, a digest mismatch means
            # the recorded inputs do not fully describe the repair.
            if (
                inputs.source_date_epoch is not None
                and existing.output["sha256"] != output["sha256"]
            ):
                msg = (
                    f"record key {record_key} already produced "
                    f"{existing.output['sha256']}, refusing {output['sha256']}"
                )
                raise RepairCacheCollision(msg)
            return existing
        if existing is not None and existing.status == "superseded":
            msg = (
                f"record {record_key} is superseded by {existing.superseded_by}; "
                "inspect it via query() and record a fresh repair"
            )
            raise RepairCacheError(msg)
        # Expired and revoked records stay queryable, but a fresh successful
        # repair is allowed to add a new version under the same key.

        artifact_path = None
        if self.store_artifacts:
            artifact_path = self._store_artifact(record_key, output_wheel)

        record = RepairRecord(
            record_key=record_key,
            cache_key=inputs.cache_key(),
            created_at=now.isoformat(),
            review_after=(now + timedelta(days=self.review_days)).isoformat(),
            status="verified",
            proof=inputs.proof(),
            inputs=inputs.to_dict(),
            output=output,
            approvals=tuple(approvals),
            artifact_path=artifact_path,
            notes=notes,
        )
        return self._write_record(record)

    def record_migration(
        self,
        inputs: RepairInputs,
        canonical: RepairRecord | str,
        *,
        verified_output_sha256: str,
        evidence: str,
        now: datetime | None = None,
    ) -> MigrationRecord:
        """Record that a relocated library set was verified output-equivalent.

        Use this only after actually comparing the outputs (or proving that no
        SBOM was emitted).  The alias is scoped to one provenance key and
        cannot be reused if the library bytes, policies, or patcher change.
        """
        canonical_record = self._require(canonical) if isinstance(canonical, str) else canonical
        if canonical_record.cache_key != inputs.cache_key():
            msg = (
                "migration must point at a record with the same repair semantics "
                f"({canonical_record.cache_key} != {inputs.cache_key()})"
            )
            raise ValueError(msg)
        if canonical_record.output.get("sbom_emitted"):
            # The SBOM component ``bom-ref`` is sha256(str(library_path)).
            # A relocated library therefore changes the output wheel, so a
            # migration record would assert something false.  Re-run repair.
            msg = (
                "cannot migrate a record whose output contains an SBOM: "
                "relocating a library changes its bom-ref, re-run repair and "
                "record the new output"
            )
            raise ValueError(msg)
        if verified_output_sha256 != canonical_record.output.get("sha256"):
            msg = (
                "migration evidence must match the canonical output digest: "
                f"{verified_output_sha256} != {canonical_record.output.get('sha256')}"
            )
            raise ValueError(msg)
        if inputs.source_date_epoch is None:
            msg = (
                "cannot certify byte equivalence without SOURCE_DATE_EPOCH; "
                "re-run repair and record the new output"
            )
            raise ValueError(msg)

        existing_migration = self.get_migration(inputs.provenance_key())
        if (
            existing_migration is not None
            and existing_migration.canonical_key != canonical_record.cache_key
        ):
            msg = (
                f"provenance key {inputs.provenance_key()} is already linked to "
                f"{existing_migration.canonical_key}"
            )
            raise RepairCacheError(msg)

        migration = MigrationRecord(
            record_key=inputs.provenance_key(),
            canonical_key=canonical_record.cache_key,
            verified_at=_utcnow(now).isoformat(),
            verified_output_sha256=verified_output_sha256,
            evidence=evidence,
            source_paths=tuple(
                library.source_path
                for external in _sorted_externals(inputs.externals)
                for library in external.libraries
                if library.source_path is not None
            ),
        )
        self._write(self._alias_path(migration.record_key), migration.to_dict())
        return migration

    def lookup(
        self,
        inputs: RepairInputs,
        *,
        platform: str | None = None,
        release: str | None = None,
        approved_after: datetime | None = None,
        now: datetime | None = None,
        require_artifact: bool = False,
    ) -> ReuseDecision:
        """Return whether ``inputs`` may reuse an existing record.

        An old approval is never implicitly promoted to a new release: pass
        the new ``release`` identifier (and optionally ``approved_after``)
        so that only an approval granted for that release is accepted.
        """
        now = _utcnow(now)
        cache_key = inputs.cache_key()
        record_key = inputs.provenance_key()

        record = self.get_by_record_key(record_key)
        migration = None
        if record is None:
            migration = self.get_migration(record_key)
            if migration is not None:
                record = self.get(migration.canonical_key)
            if record is None:
                canonical = self.get(cache_key)
                reason = (
                    "identical repair semantics but different library provenance; "
                    "record a verified migration before reuse "
                    "(SBOM bom-refs hash source paths)"
                    if canonical is not None
                    else "no record for these repair inputs"
                )
                return ReuseDecision(False, cache_key, reason, canonical)

        if record.status != "verified":
            return ReuseDecision(
                False,
                cache_key,
                f"record status is {record.status!r}",
                record,
                migration=migration,
            )

        if now >= _parse_datetime(record.review_after):
            return ReuseDecision(
                False,
                cache_key,
                "review interval expired",
                record,
                migration=migration,
            )

        if (
            platform is not None
            and record.approval_for(
                platform,
                release=release,
                approved_after=approved_after,
            )
            is None
        ):
            scope = f" and release {release!r}" if release is not None else ""
            return ReuseDecision(
                False,
                cache_key,
                f"no approval for platform {platform!r}{scope} on this record",
                record,
                migration=migration,
            )

        artifact_path = self._artifact_location(record)
        if require_artifact and artifact_path is None:
            return ReuseDecision(
                False,
                cache_key,
                "artifact was not stored",
                record,
                migration=migration,
            )

        return ReuseDecision(
            True,
            cache_key,
            "verified record is still fresh",
            record,
            artifact_path,
            migration,
        )

    def get(self, cache_key: str) -> RepairRecord | None:
        """Return the newest verified record for a repair-semantics key."""
        matches = [
            record for record in self.query(status="verified") if record.cache_key == cache_key
        ]
        return matches[-1] if matches else None

    def get_by_record_key(self, record_key: str) -> RepairRecord | None:
        """Return the newest recorded version for a provenance key."""
        versions = self.history(record_key)
        return versions[-1] if versions else None

    def history(self, record_key: str) -> list[RepairRecord]:
        """Return every recorded version for a provenance key, oldest first."""
        return [record for _, record in self._versions(record_key)]

    def _versions(self, record_key: str) -> list[tuple[Path, RepairRecord]]:
        record_dir = self._record_dir(record_key)
        versions = [
            (path, RepairRecord.from_dict(json.loads(path.read_text(encoding="utf-8"))))
            for path in record_dir.glob("*.json")
        ]
        versions.sort(key=lambda item: (item[1].created_at, item[1].revision))
        return versions

    def get_migration(self, record_key: str) -> MigrationRecord | None:
        path = self._alias_path(record_key)
        if not path.is_file():
            return None
        return MigrationRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def query(
        self,
        *,
        package: str | None = None,
        platform: str | None = None,
        wheel_sha256: str | None = None,
        status: str | None = None,
    ) -> list[RepairRecord]:
        """Query historical records, including expired and superseded ones."""
        records: list[RepairRecord] = []
        if not self.records_dir.is_dir():
            return records
        for record_dir in sorted(self.records_dir.iterdir()):
            if not record_dir.is_dir():
                continue
            versions = self._versions(record_dir.name)
            if not versions:
                continue
            record = versions[-1][1]
            if package is not None and not record.wheel_filename.startswith(package):
                continue
            if platform is not None and not _record_matches_platform(record, platform):
                continue
            if wheel_sha256 is not None and record.inputs.get("wheel_sha256") != wheel_sha256:
                continue
            if status is not None and record.status != status:
                continue
            records.append(record)
        return sorted(records, key=lambda item: item.created_at)

    def approve(
        self,
        record_key: str,
        *,
        platform: str,
        approver: str,
        note: str | None = None,
        release: str | None = None,
        now: datetime | None = None,
    ) -> RepairRecord:
        """Attach a platform approval; the record stays queryable afterwards."""
        record = self._require(record_key)
        approval = Approval(
            platform=platform,
            approved_at=_utcnow(now).isoformat(),
            approver=approver,
            note=note,
            release=release,
        )
        updated = dataclasses.replace(record, approvals=(*record.approvals, approval))
        return self._transition(updated)

    def revoke(self, record_key: str, *, reason: str | None = None) -> RepairRecord:
        """Force a record out of reuse while keeping it queryable."""
        record = self._require(record_key)
        updated = dataclasses.replace(
            record,
            status="revoked",
            notes=reason or record.notes,
        )
        return self._transition(updated)

    def supersede(self, old_key: str, new_key: str) -> RepairRecord:
        """Mark old evidence as superseded without hiding it from queries."""
        old = self._require(old_key)
        new = self._require(new_key)
        old_updated = dataclasses.replace(old, status="superseded", superseded_by=new_key)
        new_updated = dataclasses.replace(new, supersedes=old_key)
        self._transition(old_updated)
        return self._transition(new_updated)

    def expire_due(self, *, now: datetime | None = None) -> list[RepairRecord]:
        """Mark every record past ``review_after`` as expired."""
        now = _utcnow(now)
        return [
            self._transition(dataclasses.replace(record, status="expired"))
            for record in self.query(status="verified")
            if now >= _parse_datetime(record.review_after)
        ]

    def explain_mismatch(
        self,
        previous: RepairRecord | RepairInputs,
        current: RepairInputs,
    ) -> tuple[Invalidation, ...]:
        """Explain why ``current`` cannot reuse ``previous``.

        Returns one entry per affected input family.  The retained material is
        still available from the old record; the recheck entry names the code
        or command which must run again before a new approval.
        """
        # Round-trip the stored proof so lists loaded from JSON compare equal
        # to tuples produced in memory.
        previous_proof = json.loads(
            _canonical_json(
                previous.proof if isinstance(previous, RepairRecord) else previous.proof(),
            )
        )
        current_proof = json.loads(_canonical_json(current.proof()))
        invalidations: list[Invalidation] = []

        for kind, fields in _INVALIDATION_FIELDS.items():
            changed = tuple(
                field_name
                for field_name in fields
                if previous_proof.get(field_name) != current_proof.get(field_name)
            )
            if changed:
                invalidations.append(
                    Invalidation(
                        kind=kind,
                        changed=changed,
                        retained=_RETAINED[kind],
                        recheck=_RECHECK[kind],
                    ),
                )
        return tuple(invalidations)

    def _record_dir(self, record_key: str) -> Path:
        return self.records_dir / record_key

    def _write_record(self, record: RepairRecord) -> RepairRecord:
        """Append a new immutable repair version; return the stored record."""
        previous = self._versions(record.record_key)
        revision = max((item.revision for _, item in previous), default=0) + 1
        stored = dataclasses.replace(record, revision=revision)
        path = self._record_dir(record.record_key) / (f"{stored.created_at}-{revision:04d}.json")
        self._write(path, stored.to_dict())
        return stored

    def _transition(self, record: RepairRecord) -> RepairRecord:
        """Rewrite the newest version to record a status/approval transition."""
        versions = self._versions(record.record_key)
        if not versions:
            msg = f"no repair record for {record.record_key}"
            raise KeyError(msg)
        path, current = versions[-1]
        stored = dataclasses.replace(record, revision=current.revision)
        self._write(path, stored.to_dict())
        return stored

    def _alias_path(self, record_key: str) -> Path:
        return self.aliases_dir / f"{record_key}.json"

    def _require(self, record_key: str) -> RepairRecord:
        record = self.get_by_record_key(record_key)
        if record is None:
            msg = f"no repair record for {record_key}"
            raise KeyError(msg)
        return record

    def _store_artifact(self, record_key: str, output_wheel: Path) -> str:
        destination = self.root / _ARTIFACTS_DIR / record_key / output_wheel.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists() or _sha256_file(destination) != _sha256_file(output_wheel):
            destination.write_bytes(output_wheel.read_bytes())
        return str(destination.relative_to(self.root))

    def _artifact_location(self, record: RepairRecord) -> Path | None:
        if record.artifact_path is None:
            return None
        path = self.root / record.artifact_path
        return path if path.is_file() else None

    @staticmethod
    def _write(path: Path, data: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f"{path.suffix}.tmp")
        temporary.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)


_INVALIDATION_FIELDS: dict[str, tuple[str, ...]] = {
    "dependency_resolution": ("externals",),
    "target_policy": ("target_abis", "policy"),
    "patcher_tool": ("patcher",),
    "input_wheel": ("wheel_filename", "wheel_sha256"),
    "repair_options": (
        "lib_sdir",
        "update_tags",
        "strip",
        "strip_tool",
        "zip_compression_level",
        "source_date_epoch",
        "zlib_version",
        "implementation",
        "schema",
    ),
    "sbom_environment": ("sbom_environment",),
}


def wheel_contains_sbom(wheel_path: Path) -> bool:
    """Return whether a wheel carries ``auditwheel``'s CycloneDX SBOM."""
    with zipfile.ZipFile(wheel_path) as archive:
        return any(name.endswith(_SBOM_SUFFIX) for name in archive.namelist())


def _policy_payload(policy: Policy) -> dict[str, Any]:
    return {
        "name": policy.name,
        "aliases": list(policy.aliases),
        "priority": policy.priority,
        "symbol_versions": {
            key: sorted(value) for key, value in sorted(policy.symbol_versions.items())
        },
        "whitelist": sorted(policy.whitelist),
        "blacklist": {key: sorted(value) for key, value in sorted(policy.blacklist.items())},
    }


def _sorted_externals(externals: tuple[WheelExternal, ...]) -> list[WheelExternal]:
    return sorted(externals, key=lambda item: item.wheel_path)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    with path.open("rb") as file_handle:
        return hashfile(file_handle)


def _output_identity(output_wheel: Path) -> dict[str, Any]:
    return {
        "filename": output_wheel.name,
        "sha256": _sha256_file(output_wheel),
        "size": output_wheel.stat().st_size,
        "sbom_emitted": wheel_contains_sbom(output_wheel),
    }


def _implementation_version() -> str:
    try:
        return metadata.version("auditwheel")
    except metadata.PackageNotFoundError:
        return "unknown"


def _utcnow(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _record_matches_platform(record: RepairRecord, platform: str) -> bool:
    return platform in record.target_abis or any(
        approval.platform == platform for approval in record.approvals
    )
