"""Optional provenance evidence for ``auditwheel repair``.

The provenance document is a JSON sidecar written next to a repaired wheel.
It links three things that are otherwise hard to follow after a repair has
renamed a grafted library:

* the members of the input wheel and their digests,
* every external DT_NEEDED reference exactly as resolved for each referrer,
* the members of the output wheel, the renames and ELF rewrite operations.

Filesystem paths that live inside the repair workspace are stored relative to
the document directory.  Files outside the workspace are recorded by basename
and digest.  Member paths are stored as wheel-member names.  The document can
therefore be moved together with the workspace without rewriting machine
specific absolute paths, while the source and output wheel digests remain
independently verifiable.

The feature is opt-in: callers pass ``provenance_path`` to
:func:`auditwheel.repair.repair_wheel` or use ``auditwheel repair
--provenance``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import os
import zipfile
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile

from auditwheel.hashfile import hashfile

if TYPE_CHECKING:
    from auditwheel.patcher import ElfPatcher

SCHEMA_NAME = "auditwheel-provenance"
SCHEMA_VERSION = 1
DIGEST_ALGORITHM = "sha256"


@dataclasses.dataclass(frozen=True)
class MemberRecord:
    """One file inside a wheel."""

    name: str
    size: int
    sha256: str
    kind: str
    needed: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
            "kind": self.kind,
        }
        if self.needed:
            result["dt_needed"] = list(self.needed)
        return result


@dataclasses.dataclass(frozen=True)
class SourceRecord:
    """A file read from the host filesystem while repairing."""

    path: Path
    sha256: str
    size: int


@dataclasses.dataclass
class ReferenceRecord:
    id: str
    referrer: str
    referrer_sha256: str
    referrer_needed: tuple[str, ...]
    soname: str
    status: str
    policy: str
    source: SourceRecord | None
    graft_id: str | None = None


@dataclasses.dataclass
class GraftRecord:
    id: str
    source: SourceRecord
    original_soname: str
    new_soname: str
    member: str
    referrer: str
    reference_id: str
    created: bool


@dataclasses.dataclass
class StepRecord:
    seq: int
    operation: str
    member: str | None
    details: dict[str, object] = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "step": self.seq,
            "operation": self.operation,
        }
        if self.member is not None:
            result["member"] = self.member
        result.update(self.details)
        return result


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as f:
        return hashfile(f)


def _elf_needed(data: bytes) -> tuple[str, ...]:
    try:
        with io.BytesIO(data) as stream:
            elf = ELFFile(stream)
            section = elf.get_section_by_name(".dynamic")
            if not isinstance(section, DynamicSection):
                return ()
            return tuple(
                tag.needed
                for tag in section.iter_tags()
                if tag.entry.d_tag == "DT_NEEDED"  # type: ignore[attr-defined]
            )
    except (ELFError, KeyError, ValueError):
        return ()


def _snapshot_wheel(path: Path) -> list[MemberRecord]:
    records: list[MemberRecord] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            with zf.open(info) as stream:
                prefix = stream.read(4)
                if prefix == b"\x7fELF":
                    data = prefix + stream.read()
                    digest = _sha256_bytes(data)
                    kind = "elf"
                    needed = _elf_needed(data)
                else:
                    hasher = hashlib.sha256()
                    hasher.update(prefix)
                    for chunk in iter(lambda: stream.read(65536), b""):
                        hasher.update(chunk)
                    digest = hasher.hexdigest()
                    kind = "file"
                    needed = ()
            records.append(
                MemberRecord(
                    name=info.filename,
                    size=info.file_size,
                    sha256=digest,
                    kind=kind,
                    needed=needed,
                )
            )
    return sorted(records, key=lambda record: record.name)


class _RecordingPatcher:
    """Delegate to a patcher and record the operations that were requested."""

    def __init__(self, inner: ElfPatcher, recorder: ProvenanceRecorder) -> None:
        self._inner = inner
        self._recorder = recorder

    def remove_needed(self, file_name: Path, *sonames: str) -> None:
        self._inner.remove_needed(file_name, *sonames)
        self._recorder.record_step(
            "remove_needed",
            file_name,
            {"sonames": list(sonames)},
        )

    def replace_needed(self, file_name: Path, *old_new_pairs: tuple[str, str]) -> None:
        self._inner.replace_needed(file_name, *old_new_pairs)
        self._recorder.record_step(
            "replace_needed",
            file_name,
            {"pairs": [list(pair) for pair in old_new_pairs]},
        )

    def set_soname(self, file_name: Path, new_so_name: str) -> None:
        self._inner.set_soname(file_name, new_so_name)
        self._recorder.record_step(
            "set_soname",
            file_name,
            {"new_soname": new_so_name},
        )

    def set_rpath(self, file_name: Path, rpath: str) -> None:
        self._inner.set_rpath(file_name, rpath)
        self._recorder.record_step("set_rpath", file_name, {"rpath": rpath})

    def get_rpath(self, file_name: Path) -> str:
        return self._inner.get_rpath(file_name)

    def clear_rpath(self, file_name: Path) -> None:
        self._inner.clear_rpath(file_name)
        self._recorder.record_step("clear_rpath", file_name)

    def update_elf_path(self, old_file_name: Path, new_file_name: Path) -> None:
        self._inner.update_elf_path(old_file_name, new_file_name)
        self._recorder.record_relocation(old_file_name, new_file_name)

    def apply_updates(self) -> None:
        pending = getattr(self._inner, "_updates", {})
        count = len(pending) if isinstance(pending, dict) else 0
        self._inner.apply_updates()
        self._recorder.record_step("apply_elf_updates", None, {"files": count})

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


class ProvenanceRecorder:
    """Collect repair evidence and write a relocatable JSON sidecar."""

    def __init__(
        self,
        *,
        wheel_path: Path,
        abis: list[str],
        lib_sdir: str,
        strip: bool,
        update_tags: bool,
        workspace_root: Path | None,
    ) -> None:
        self.wheel_path = wheel_path
        self.abis = list(abis)
        self.lib_sdir = lib_sdir
        self.strip = strip
        self.update_tags = update_tags
        self.workspace_root = (
            workspace_root.resolve() if workspace_root is not None else None
        )
        self.input_members: list[MemberRecord] = _snapshot_wheel(wheel_path)
        self._input_by_name = {member.name: member for member in self.input_members}
        self._wheel_root: Path | None = None
        self._references: list[ReferenceRecord] = []
        self._grafts: list[GraftRecord] = []
        self._steps: list[StepRecord] = []
        self._relocations: dict[str, str] = {}
        self._source_cache: dict[Path, SourceRecord] = {}
        self._graft_by_key: dict[tuple[str, str], GraftRecord] = {}
        self._step_members: dict[int, str] = {}
        self._tag_update: dict[str, object] | None = None
        self._sbom_members: list[str] = []
        self.graft_directory: str | None = None
        self._reference_seq = 0
        self._graft_seq = 0
        self._step_seq = 0

    # ------------------------------------------------------------------
    # Member and path helpers
    # ------------------------------------------------------------------
    def bind(self, wheel_root: Path) -> None:
        """Remember the temporary directory where the wheel was extracted."""
        self._wheel_root = wheel_root.resolve()

    def set_graft_directory(self, dest_dir: Path) -> None:
        self.graft_directory = f"{self.member_name(dest_dir)}/"

    def member_name(self, path: Path) -> str:
        """Return the wheel-member name for a path in the extracted wheel."""
        raw = Path(path)
        if not raw.is_absolute():
            base = self._wheel_root if self._wheel_root is not None else Path.cwd()
            raw = base / raw
        normalised = Path(os.path.normpath(raw))
        if self._wheel_root is not None:
            try:
                return normalised.relative_to(self._wheel_root).as_posix()
            except ValueError:
                pass
        return normalised.name

    def _member_sha256(self, name: str) -> str:
        member = self._input_by_name.get(name)
        return member.sha256 if member is not None else ""

    def _needed_for(self, name: str) -> tuple[str, ...]:
        member = self._input_by_name.get(name)
        return member.needed if member is not None else ()

    def _source_info(self, path: Path) -> SourceRecord:
        resolved = path.resolve()
        cached = self._source_cache.get(resolved)
        if cached is not None:
            return cached
        record = SourceRecord(
            path=resolved,
            sha256=sha256_file(resolved),
            size=resolved.stat().st_size,
        )
        self._source_cache[resolved] = record
        return record

    def _resolve_workspace_root(self, document_path: Path, output_wheel: Path) -> Path:
        if self.workspace_root is not None:
            return self.workspace_root
        candidates = [
            Path(os.path.abspath(self.wheel_path)),
            Path(os.path.abspath(output_wheel)),
            Path(os.path.abspath(document_path.parent)),
        ]
        try:
            common = Path(os.path.commonpath([str(path) for path in candidates]))
        except ValueError:
            common = Path.cwd()
        self.workspace_root = common
        return common

    def _path_payload(self, path: Path, document_dir: Path) -> dict[str, object]:
        target = Path(os.path.abspath(path))
        assert self.workspace_root is not None
        try:
            workspace_relative = Path(os.path.relpath(target, self.workspace_root))
        except ValueError:
            workspace_relative = Path(target.name)
        if workspace_relative.parts and workspace_relative.parts[0] == "..":
            # Files outside the workspace (for example system libraries) are
            # identified by basename and digest only.  A path relative to the
            # document would still point at this machine and would not survive
            # moving the workspace.
            return {
                "path": target.name,
                "basename": target.name,
                "scope": "external",
            }
        try:
            relative = os.path.relpath(target, Path(os.path.abspath(document_dir)))
        except ValueError:
            relative = target.name
        return {
            "path": Path(relative).as_posix(),
            "basename": target.name,
            "scope": "workspace",
        }

    # ------------------------------------------------------------------
    # Recording API used by repair.py
    # ------------------------------------------------------------------
    def wrap_patcher(self, patcher: ElfPatcher) -> ElfPatcher:
        return _RecordingPatcher(patcher, self)  # type: ignore[return-value]

    def reference(
        self,
        referrer: Path,
        soname: str,
        source_path: Path | None,
        *,
        status: str,
        policy: str,
    ) -> str:
        self._reference_seq += 1
        ref_id = f"ref-{self._reference_seq:04d}"
        name = self.member_name(referrer)
        source = self._source_info(source_path) if source_path is not None else None
        self._references.append(
            ReferenceRecord(
                id=ref_id,
                referrer=name,
                referrer_sha256=self._member_sha256(name),
                referrer_needed=self._needed_for(name),
                soname=soname,
                status=status,
                policy=policy,
                source=source,
            )
        )
        return ref_id

    def graft(
        self,
        *,
        reference_id: str,
        referrer: Path,
        soname: str,
        source_path: Path,
        new_soname: str,
        new_path: Path,
        created: bool,
    ) -> str:
        source = self._source_info(source_path)
        member = self.member_name(new_path)
        key = (source.sha256, new_soname)
        existing = self._graft_by_key.get(key)
        if existing is not None:
            graft_id = existing.id
            self.record_step(
                "reuse_graft",
                new_path,
                {
                    "reference": reference_id,
                    "graft": graft_id,
                    "new_soname": new_soname,
                },
            )
        else:
            self._graft_seq += 1
            graft_id = f"graft-{self._graft_seq:04d}"
            existing = GraftRecord(
                id=graft_id,
                source=source,
                original_soname=soname,
                new_soname=new_soname,
                member=member,
                referrer=self.member_name(referrer),
                reference_id=reference_id,
                created=created,
            )
            self._grafts.append(existing)
            self._graft_by_key[key] = existing
            if created:
                self.record_step(
                    "copy_library",
                    new_path,
                    {
                        "reference": reference_id,
                        "graft": graft_id,
                        "source_basename": source_path.name,
                        "new_soname": new_soname,
                    },
                )
            else:
                self.record_step(
                    "reuse_graft",
                    new_path,
                    {
                        "reference": reference_id,
                        "graft": graft_id,
                        "new_soname": new_soname,
                    },
                )
        for ref in self._references:
            if ref.id == reference_id:
                ref.graft_id = graft_id
                break
        return graft_id

    def set_reference_status(self, reference_id: str, status: str) -> None:
        for reference in self._references:
            if reference.id == reference_id:
                reference.status = status
                return

    def record_step(
        self,
        operation: str,
        member: Path | str | None,
        details: dict[str, object] | None = None,
    ) -> None:
        self._step_seq += 1
        if member is None:
            member_name: str | None = None
        elif isinstance(member, Path):
            member_name = self.member_name(member)
        else:
            member_name = member
        self._steps.append(
            StepRecord(
                seq=self._step_seq,
                operation=operation,
                member=member_name,
                details=details or {},
            )
        )
        if member_name is not None:
            self._step_members[self._step_seq] = member_name

    def record_relocation(self, old_path: Path, new_path: Path) -> None:
        old_member = self.member_name(old_path)
        new_member = self.member_name(new_path)
        self._relocations[old_member] = new_member
        self.record_step(
            "relocate_member",
            old_member,
            {"to": new_member},
        )
        relocation_seq = self._step_seq
        # Steps that were recorded before the move against the pre-move path
        # (for example strip_symbols) follow the member to its new name.  The
        # relocation step itself keeps the source name.
        for seq, member in self._step_members.items():
            if seq != relocation_seq and member == old_member:
                self._step_members[seq] = new_member

    def record_shim(self, old_path: Path, new_path: Path) -> None:
        old_member = self.member_name(old_path)
        new_member = self.member_name(new_path)
        self._relocations[old_member] = new_member
        self.record_step(
            "write_script_shim",
            old_member,
            {"binary_member": new_member},
        )
        shim_seq = self._step_seq
        self.record_step(
            "relocate_member",
            new_member,
            {"from": old_member},
        )
        relocation_seq = self._step_seq
        # Earlier ELF rewrites were recorded against the script's original
        # path; the binary they refer to now lives at the new member.  The
        # shim write itself stays attached to the original script path.
        for seq, member in self._step_members.items():
            if seq not in {shim_seq, relocation_seq} and member == old_member:
                self._step_members[seq] = new_member

    def record_tag_update(
        self,
        *,
        before: str,
        after: str,
        abis: list[str],
        removed_platforms: list[str],
        update_tags: bool,
    ) -> None:
        self._tag_update = {
            "enabled": update_tags,
            "before": before,
            "after": after,
            "abis": list(abis),
            "removed_platforms": list(removed_platforms),
        }
        self.record_step(
            "retag_wheel",
            None,
            {
                "before": before,
                "after": after,
                "abis": list(abis),
                "removed_platforms": list(removed_platforms),
            },
        )

    def record_sbom(self, member: str) -> None:
        self._sbom_members.append(member)

    # ------------------------------------------------------------------
    # Document construction
    # ------------------------------------------------------------------
    def _step_owner(self, step: StepRecord) -> str | None:
        return self._step_members.get(step.seq, step.member)

    def _step_payload(self, step: StepRecord) -> dict[str, object]:
        owner = self._step_owner(step)
        payload = step.as_dict()
        if owner is not None:
            payload["member"] = owner
        return payload

    def _step_belongs(
        self,
        step: StepRecord,
        reference: ReferenceRecord,
        graft: GraftRecord | None,
        repaired_referrer: str,
    ) -> bool:
        member = self._step_owner(step)
        if member is None:
            return False
        step_reference = step.details.get("reference")
        if step_reference is not None and step_reference != reference.id:
            return False
        if member in {reference.referrer, repaired_referrer}:
            if step.operation == "replace_needed":
                pairs = step.details.get("pairs", [])
                if isinstance(pairs, list):
                    return any(
                        isinstance(pair, list) and pair and pair[0] == reference.soname
                        for pair in pairs
                    )
            elif step.operation == "remove_needed":
                sonames = step.details.get("sonames", [])
                return isinstance(sonames, list) and reference.soname in sonames
            return True
        return graft is not None and member == graft.member

    def build_document(self, output_wheel: Path, document_path: Path) -> dict[str, object]:
        document_dir = document_path.parent
        output_members = _snapshot_wheel(output_wheel)
        output_by_name = {member.name: member for member in output_members}
        grafts_by_id = {graft.id: graft for graft in self._grafts}

        reference_documents: list[dict[str, object]] = []
        for reference in self._references:
            graft = grafts_by_id.get(reference.graft_id) if reference.graft_id else None
            repaired_referrer = self._relocations.get(reference.referrer, reference.referrer)
            repaired_source = output_by_name.get(repaired_referrer)
            repaired_member = output_by_name.get(graft.member) if graft is not None else None
            source_document: dict[str, object] | None = None
            if reference.source is not None:
                source_document = {
                    **self._path_payload(reference.source.path, document_dir),
                    "sha256": reference.source.sha256,
                    "size": reference.source.size,
                }
            steps = [
                step.seq
                for step in self._steps
                if self._step_belongs(step, reference, graft, repaired_referrer)
            ]
            reference_documents.append(
                {
                    "id": reference.id,
                    "referrer": {
                        "member": reference.referrer,
                        "sha256": reference.referrer_sha256,
                        "dt_needed": list(reference.referrer_needed),
                    },
                    "repaired_referrer": (
                        {
                            "member": repaired_referrer,
                            "sha256": repaired_source.sha256,
                            "size": repaired_source.size,
                        }
                        if repaired_source is not None
                        else None
                    ),
                    "soname": reference.soname,
                    "policy": reference.policy,
                    "status": reference.status,
                    "source": source_document,
                    "graft": reference.graft_id,
                    "repaired_member": (
                        {
                            "member": repaired_member.name,
                            "sha256": repaired_member.sha256,
                            "size": repaired_member.size,
                        }
                        if repaired_member is not None
                        else None
                    ),
                    "rewrite_steps": steps,
                }
            )

        graft_documents: list[dict[str, object]] = []
        for graft in self._grafts:
            member = output_by_name.get(graft.member)
            graft_documents.append(
                {
                    "id": graft.id,
                    "source": {
                        **self._path_payload(graft.source.path, document_dir),
                        "sha256": graft.source.sha256,
                        "size": graft.source.size,
                    },
                    "original_soname": graft.original_soname,
                    "new_soname": graft.new_soname,
                    "repaired_member": (
                        {
                            "member": member.name,
                            "sha256": member.sha256,
                            "size": member.size,
                        }
                        if member is not None
                        else {
                            "member": graft.member,
                            "sha256": None,
                            "size": None,
                        }
                    ),
                    "created": graft.created,
                    "first_reference": graft.reference_id,
                    "references": [
                        reference.id
                        for reference in self._references
                        if reference.graft_id == graft.id
                    ],
                    "rewrite_steps": [
                        step.seq
                        for step in self._steps
                        if self._step_owner(step) == graft.member
                    ],
                }
            )

        repaired_member_index: dict[str, object] = {}
        for graft in self._grafts:
            repaired_member_index[graft.member] = {
                "kind": "graft",
                "graft": graft.id,
                "input_members": [],
                "references": [
                    reference.id
                    for reference in self._references
                    if reference.graft_id == graft.id
                ],
                "rewrite_steps": [
                    step.seq
                    for step in self._steps
                    if self._step_owner(step) == graft.member
                ],
            }
        for reference in self._references:
            repaired_referrer = self._relocations.get(
                reference.referrer, reference.referrer
            )
            if repaired_referrer not in output_by_name:
                continue
            entry = repaired_member_index.setdefault(
                repaired_referrer,
                {
                    "kind": "referrer",
                    "graft": None,
                    "input_members": [],
                    "references": [],
                    "rewrite_steps": [],
                },
            )
            assert isinstance(entry, dict)
            entry_ids = entry["references"]
            assert isinstance(entry_ids, list)
            if reference.id not in entry_ids:
                entry_ids.append(reference.id)
            input_members = entry["input_members"]
            assert isinstance(input_members, list)
            if reference.referrer not in input_members:
                input_members.append(reference.referrer)
            step_ids = entry["rewrite_steps"]
            assert isinstance(step_ids, list)
            for step in self._steps:
                if (
                    self._step_owner(step) in {reference.referrer, repaired_referrer}
                    and step.seq not in step_ids
                ):
                    step_ids.append(step.seq)
        soname_index: dict[str, list[str]] = {}
        for reference in self._references:
            soname_index.setdefault(reference.soname, []).append(reference.id)
        referrer_index: dict[str, object] = {}
        for reference in self._references:
            repaired = self._relocations.get(reference.referrer, reference.referrer)
            referrer_index.setdefault(reference.referrer, [])  # type: ignore[union-attr]
            referrer_index.setdefault(repaired, [])  # type: ignore[union-attr]
            ids = referrer_index[reference.referrer]  # type: ignore[index]
            assert isinstance(ids, list)
            if reference.id not in ids:
                ids.append(reference.id)

        direct_index: dict[str, dict[str, object]] = {}
        for reference in self._references:
            repaired_referrer = self._relocations.get(
                reference.referrer, reference.referrer
            )
            key = f"{repaired_referrer}|{reference.soname}"
            graft = grafts_by_id.get(reference.graft_id) if reference.graft_id else None
            direct_index[key] = {
                "reference": reference.id,
                "source": (
                    self._path_payload(reference.source.path, document_dir)
                    if reference.source is not None
                    else None
                ),
                "graft": reference.graft_id,
                "repaired_member": graft.member if graft is not None else None,
            }

        return {
            "schema": SCHEMA_NAME,
            "version": SCHEMA_VERSION,
            "generated_by": {
                "name": "auditwheel",
                "version": metadata.version("auditwheel"),
            },
            "generated_at": datetime.now(UTC).isoformat(),
            "digest": {"algorithm": DIGEST_ALGORITHM},
            "paths": {
                "base": "document-directory",
                "style": "posix",
                "workspace": ".",
            },
            "repair": {
                "abis": self.abis,
                "policy": self.abis[0] if self.abis else None,
                "lib_sdir": self.lib_sdir,
                "strip": self.strip,
                "update_tags": self.update_tags,
                "graft_directory": self.graft_directory,
            },
            "input_wheel": {
                "name": self.wheel_path.name,
                **self._path_payload(self.wheel_path, document_dir),
                "sha256": sha256_file(self.wheel_path),
                "size": self.wheel_path.stat().st_size,
                "members": [member.as_dict() for member in self.input_members],
            },
            "output_wheel": {
                "name": output_wheel.name,
                **self._path_payload(output_wheel, document_dir),
                "sha256": sha256_file(output_wheel),
                "size": output_wheel.stat().st_size,
                "members": [member.as_dict() for member in output_members],
            },
            "tag_update": self._tag_update,
            "references": reference_documents,
            "grafts": graft_documents,
            "rewrite_steps": [self._step_payload(step) for step in self._steps],
            "index": {
                "repaired_members": repaired_member_index,
                "referrers": referrer_index,
                "sonames": soname_index,
                "repaired_references": direct_index,
                "sbom_members": sorted(self._sbom_members),
            },
        }

    def write(self, output_wheel: Path, requested_path: Path) -> Path:
        """Write the provenance document and return its final path."""
        if requested_path.suffix.lower() == ".json":
            document_path = requested_path
        else:
            document_path = requested_path / f"{output_wheel.name}.provenance.json"
        document_path.parent.mkdir(parents=True, exist_ok=True)
        self._resolve_workspace_root(document_path, output_wheel)
        document = self.build_document(output_wheel, document_path)
        document_path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return document_path


def explain_member(document: dict[str, object], member: str) -> dict[str, object]:
    """Resolve a repaired wheel member to its input and rewrite chain."""
    index = document.get("index", {})
    if not isinstance(index, dict):
        return {"member": member, "found": False}
    repaired_members = index.get("repaired_members", {})
    if not isinstance(repaired_members, dict):
        return {"member": member, "found": False}
    entry = repaired_members.get(member)
    if not isinstance(entry, dict):
        return {"member": member, "found": False}
    document_references = document.get("references", [])
    if not isinstance(document_references, list):
        document_references = []
    references_by_id = {
        reference.get("id"): reference
        for reference in document_references
        if isinstance(reference, dict)
    }
    document_steps = document.get("rewrite_steps", [])
    if not isinstance(document_steps, list):
        document_steps = []
    steps_by_seq = {
        step.get("step"): step
        for step in document_steps
        if isinstance(step, dict)
    }
    entry_references = entry.get("references", [])
    if not isinstance(entry_references, list):
        entry_references = []
    references = [
        references_by_id[reference_id]
        for reference_id in entry_references
        if reference_id in references_by_id
    ]
    entry_steps = entry.get("rewrite_steps", [])
    if not isinstance(entry_steps, list):
        entry_steps = []
    step_ids: list[int] = []
    for step_id in entry_steps:
        if isinstance(step_id, int) and step_id in steps_by_seq and step_id not in step_ids:
            step_ids.append(step_id)
    for reference in references:
        reference_steps = reference.get("rewrite_steps", [])
        if not isinstance(reference_steps, list):
            continue
        for step_id in reference_steps:
            if isinstance(step_id, int) and step_id in steps_by_seq and step_id not in step_ids:
                step_ids.append(step_id)
    return {
        "member": member,
        "found": True,
        "kind": entry.get("kind"),
        "graft": entry.get("graft"),
        "input_members": [
            {
                "member": reference["referrer"]["member"],
                "sha256": reference["referrer"]["sha256"],
            }
            for reference in references
        ],
        "references": references,
        "rewrite_steps": [steps_by_seq[step_id] for step_id in sorted(step_ids)],
    }


def _check_members(
    label: str,
    entry: object,
    actual_members: dict[str, MemberRecord],
    problems: list[str],
) -> None:
    if not isinstance(entry, dict):
        return
    recorded = entry.get("members", [])
    if not isinstance(recorded, list):
        problems.append(f"{label} members are not a list")
        return
    recorded_names: set[str] = set()
    for member in recorded:
        if not isinstance(member, dict):
            continue
        name = member.get("name")
        if not isinstance(name, str):
            continue
        recorded_names.add(name)
        actual = actual_members.get(name)
        if actual is None:
            problems.append(f"{label} member missing: {name}")
        elif actual.sha256 != member.get("sha256"):
            problems.append(f"{label} member digest mismatch: {name}")
        elif actual.size != member.get("size"):
            problems.append(f"{label} member size mismatch: {name}")
    for extra in sorted(set(actual_members) - recorded_names):
        problems.append(f"{label} member not recorded: {extra}")


def verify_provenance(
    document_path: Path,
    *,
    input_wheel: Path | None = None,
    output_wheel: Path | None = None,
) -> list[str]:
    """Recompute the digests in a provenance document.

    Returns a list of human readable problems.  An empty list means the
    document is internally consistent and the referenced wheel files (when
    supplied or resolvable) match their recorded digests.
    """
    document = json.loads(document_path.read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA_NAME or document.get("version") != SCHEMA_VERSION:
        return [f"unsupported provenance document: {document_path}"]
    problems: list[str] = []
    base = document_path.parent

    def check_wheel(key: str, supplied: Path | None) -> Path | None:
        entry = document.get(key)
        if not isinstance(entry, dict):
            problems.append(f"missing {key} entry")
            return None
        if supplied is not None:
            wheel_path = supplied
        else:
            recorded = entry.get("path")
            if not isinstance(recorded, str):
                problems.append(f"{key} has no relative path")
                return None
            wheel_path = base / recorded
        if not wheel_path.is_file():
            problems.append(f"{key} file not found: {wheel_path}")
            return None
        digest = sha256_file(wheel_path)
        if digest != entry.get("sha256"):
            problems.append(f"{key} digest mismatch")
        size = wheel_path.stat().st_size
        if size != entry.get("size"):
            problems.append(f"{key} size mismatch")
        return wheel_path

    for graft in document.get("grafts", []):
        if not isinstance(graft, dict):
            continue
        source = graft.get("source")
        if not isinstance(source, dict) or source.get("scope") != "workspace":
            continue
        recorded = source.get("path")
        if not isinstance(recorded, str):
            continue
        source_path = base / recorded
        if not source_path.is_file():
            problems.append(f"graft source not found: {recorded}")
        elif sha256_file(source_path) != source.get("sha256"):
            problems.append(f"graft source digest mismatch: {recorded}")

    input_path = check_wheel("input_wheel", input_wheel)
    output_path = check_wheel("output_wheel", output_wheel)
    if input_path is not None:
        members = {member.name: member for member in _snapshot_wheel(input_path)}
        _check_members("input", document.get("input_wheel", {}), members, problems)
    if output_path is not None:
        members = {member.name: member for member in _snapshot_wheel(output_path)}
        _check_members("output", document.get("output_wheel", {}), members, problems)
        for graft in document.get("grafts", []):
            if not isinstance(graft, dict):
                continue
            repaired = graft.get("repaired_member")
            if not isinstance(repaired, dict):
                continue
            member_name = repaired.get("member")
            actual = members.get(member_name) if isinstance(member_name, str) else None
            if actual is None:
                problems.append(f"grafted member missing: {repaired.get('member')}")
            elif actual.sha256 != repaired.get("sha256"):
                problems.append(f"grafted member digest mismatch: {repaired.get('member')}")
    return problems
