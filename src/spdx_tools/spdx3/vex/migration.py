# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Migration manifest for components converted from SPDX 2.x documents.

Components bumped from an old SPDX document keep full element IDs inside the SPDX 3 payload, but
the VEX verification needs an explicit, auditable list of which branches came from the legacy
document and which of them are ready to be associated with VEX statements. Entries without a
version cannot be matched against a fix branch and stay pending; entries without integrity
evidence are marked as well so that the verifier never treats an unsupported claim as verified.
"""
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional

import yaml

from spdx_tools.spdx3.model.software.package import Package
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.vex.verification import branch_key_for_package

MIGRATED_SPDX2 = "migrated-spdx2"
NATIVE_SPDX3 = "spdx3-native"


class MigrationStatus(Enum):
    ASSOCIABLE = auto()
    PENDING_VERSION = auto()
    PENDING_EVIDENCE = auto()


@dataclass
class MigrationEntry:
    component_spdx_id: str
    name: Optional[str]
    package_version: Optional[str]
    branch_key: str
    origin: str
    status: MigrationStatus
    package_url: Optional[str] = None
    has_integrity_evidence: bool = False
    note: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "component_spdx_id": self.component_spdx_id,
            "name": self.name,
            "package_version": self.package_version,
            "branch_key": self.branch_key,
            "origin": self.origin,
            "status": self.status.name,
            "package_url": self.package_url,
            "has_integrity_evidence": self.has_integrity_evidence,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "MigrationEntry":
        return cls(
            component_spdx_id=data["component_spdx_id"],
            name=data.get("name"),
            package_version=data.get("package_version"),
            branch_key=data["branch_key"],
            origin=data["origin"],
            status=MigrationStatus[data["status"]],
            package_url=data.get("package_url"),
            has_integrity_evidence=data.get("has_integrity_evidence", False),
            note=data.get("note"),
        )


@dataclass
class MigrationManifest:
    entries: List[MigrationEntry] = field(default_factory=list)

    def origin_map(self) -> Dict[str, str]:
        return {entry.component_spdx_id: entry.origin for entry in self.entries}

    def associable_ids(self) -> List[str]:
        return [
            entry.component_spdx_id
            for entry in self.entries
            if entry.status == MigrationStatus.ASSOCIABLE
        ]

    def pending_ids(self) -> List[str]:
        return [
            entry.component_spdx_id
            for entry in self.entries
            if entry.status != MigrationStatus.ASSOCIABLE
        ]

    def to_dict(self) -> Dict:
        return {"entries": [entry.to_dict() for entry in self.entries]}

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=True)

    @classmethod
    def from_dict(cls, data: Dict) -> "MigrationManifest":
        return cls(entries=[MigrationEntry.from_dict(entry) for entry in data.get("entries", [])])

    @classmethod
    def from_yaml(cls, serialized: str) -> "MigrationManifest":
        loaded = yaml.safe_load(serialized) or {}
        return cls.from_dict(loaded)


def _entry_for_package(
    package: Package, origin: str, note: Optional[str] = None
) -> MigrationEntry:
    has_evidence = bool(package.verified_using)
    if not package.package_version:
        status = MigrationStatus.PENDING_VERSION
    elif not has_evidence:
        status = MigrationStatus.PENDING_EVIDENCE
    else:
        status = MigrationStatus.ASSOCIABLE
    return MigrationEntry(
        component_spdx_id=package.spdx_id,
        name=package.name,
        package_version=package.package_version,
        branch_key=branch_key_for_package(package),
        origin=origin,
        status=status,
        package_url=package.package_url,
        has_integrity_evidence=has_evidence,
        note=note,
    )


def build_migration_manifest(
    payload: Payload,
    migrated_component_ids: Optional[List[str]] = None,
) -> MigrationManifest:
    """Build the manifest for a payload.

    When ``migrated_component_ids`` is given, exactly those packages are treated as legacy
    components. Otherwise every package is assumed to have been bumped from SPDX 2.x. Packages not
    listed as migrated are recorded as native SPDX 3 components so that the origin of every branch
    stays explicit.
    """
    migrated = set(migrated_component_ids) if migrated_component_ids is not None else None
    entries: List[MigrationEntry] = []
    for element in payload.get_full_map().values():
        if not isinstance(element, Package):
            continue
        if migrated is None or element.spdx_id in migrated:
            origin = MIGRATED_SPDX2
            note = "converted from SPDX 2.x document"
        else:
            origin = NATIVE_SPDX3
            note = "authored in SPDX 3"
        entries.append(_entry_for_package(element, origin, note))
    return MigrationManifest(entries=sorted(entries, key=lambda entry: entry.branch_key))


def build_migration_manifest_from_spdx2_document(
    document,
    payload: Payload,
    document_namespace: Optional[str] = None,
) -> MigrationManifest:
    """Build the manifest from an SPDX 2 document together with its bumped payload.

    The SPDX 2 package IDs are expanded with the document namespace, matching the IDs created by
    ``bump_spdx_document``, so that legacy components can be associated even though their payload
    IDs changed during the conversion.
    """
    namespace = document_namespace or document.creation_info.document_namespace
    migrated_ids = [f"{namespace}#{package.spdx_id}" for package in document.packages]
    return build_migration_manifest(payload, migrated_component_ids=migrated_ids)
