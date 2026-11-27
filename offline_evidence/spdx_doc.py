"""Minimal SPDX-2.3 document construction helpers used by the fixture builder."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    ExternalDocumentRef,
    Package,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.writer.write_anything import write_file

from .digest import hash_file


def make_document(namespace: str, name: str, external_refs: Optional[List[ExternalDocumentRef]] = None) -> Document:
    creation_info = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=name,
        data_license="CC0-1.0",
        document_namespace=namespace,
        creators=[Actor(ActorType.TOOL, "offline-evidence-fixture-builder")],
        created=datetime(2026, 11, 28, tzinfo=timezone.utc),
        external_document_refs=external_refs or [],
    )
    document = Document(creation_info)
    package = Package(
        name=f"{name}-described-package",
        spdx_id="SPDXRef-Package",
        download_location="NOASSERTION",
    )
    document.packages = [package]
    document.relationships = [
        Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-Package")
    ]
    return document


def external_ref(ref_id: str, uri: str, path: Path, algorithm: ChecksumAlgorithm) -> ExternalDocumentRef:
    return ExternalDocumentRef(
        document_ref_id=ref_id,
        document_uri=uri,
        checksum=Checksum(algorithm, hash_file(path, algorithm)),
    )


def write_document(document: Document, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_file(document, str(path), validate=False)
