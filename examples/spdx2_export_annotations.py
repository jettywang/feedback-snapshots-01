#  SPDX-FileCopyrightText: 2026 spdx contributors
#
#  SPDX-License-Identifier: Apache-2.0
from datetime import datetime
from os import path

from spdx_tools.spdx.annotation_export import (
    AnnotationExportPolicy,
    export_annotations_for_sharing,
    extract_stable_id,
    find_original_annotations,
    write_annotation_audit_file,
)
from spdx_tools.spdx.model import Actor, ActorType, Annotation, AnnotationType, Document
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

# This example demonstrates how to export a shareable SPDX document where investigation annotations
# that contain internal material are replaced by a minimal view plus a stable audit reference.

input_path = path.join(path.dirname(__file__), "..", "tests", "spdx", "data", "SPDXLite.spdx")
document: Document = parse_file(input_path)

public_annotation = Annotation(
    "SPDXRef-spdxtools",
    AnnotationType.OTHER,
    Actor(ActorType.PERSON, "Public Reviewer", "public@example.com"),
    datetime(2024, 1, 1),
    "Reviewed against the published advisory.",
)
internal_annotation = Annotation(
    "SPDXRef-spdxtools",
    AnnotationType.REVIEW,
    Actor(ActorType.PERSON, "Incident Team", "incident@example.com"),
    datetime(2024, 2, 3),
    "Internal investigation: host db-17 leaked credentials.",
)
document.annotations = [public_annotation, internal_annotation]

# Select which annotations are restricted. Public annotations are copied unchanged.
policy = AnnotationExportPolicy(restricted_annotator_names=frozenset({"Incident Team"}))
result = export_annotations_for_sharing(document, policy)

# The shared document still points at the same package, but the restricted comment is gone.
shared_annotation = result.document.annotations[1]
stable_id = extract_stable_id(shared_annotation.annotation_comment)
assert shared_annotation.spdx_id == internal_annotation.spdx_id
assert stable_id is not None
assert "db-17" not in shared_annotation.annotation_comment
assert result.document.annotations[0] == public_annotation

# The shared document is a valid SPDX document and can be converted to any supported format.
write_file(result.document, "shared_document.spdx.json", validate=True)

# The audit mapping is internal-only. It points back to the original record and must not be shared.
write_annotation_audit_file(result.audit_entries, "annotations.audit.json")

# Internal audit can map the shared annotation back to the original record.
original = find_original_annotations(document, stable_id)[0]
assert original.annotation_comment == internal_annotation.annotation_comment
