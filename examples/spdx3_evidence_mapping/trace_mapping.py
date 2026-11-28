#!/usr/bin/env python3
"""Trace an SPDX 2.x -> SPDX 3.0.0 migration with the library's real bumper.

Usage:
    python examples/spdx3_evidence_mapping/trace_mapping.py \
        --input examples/spdx3_evidence_mapping/sample-01-traceable.spdx \
        --outdir examples/spdx3_evidence_mapping/output --strict

For every input package/file/snippet/relationship/annotation/external document
reference this script records what bump_spdx_document() emitted, which fields
the bumper itself reported as dropped, and classifies each source assertion as
one-to-one, aggregated, dangling or lost. The JSON-LD is produced with the same
writer used by the pyspdxtools3 CLI.
"""
import argparse
import json
import os
import re
import sys
from contextlib import redirect_stderr
from io import StringIO

from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload

RELATIONSHIP_CLASSES = ("Relationship", "SoftwareDependencyRelationship")
# SPDX 2 dependency-of types are swapped by the bumper; see relationship.py
DEPENDENCY_OF_TYPES = {
    RelationshipType.DEPENDENCY_OF,
    RelationshipType.BUILD_DEPENDENCY_OF,
    RelationshipType.DEV_DEPENDENCY_OF,
    RelationshipType.RUNTIME_DEPENDENCY_OF,
    RelationshipType.TEST_DEPENDENCY_OF,
    RelationshipType.PROVIDED_DEPENDENCY_OF,
    RelationshipType.OPTIONAL_DEPENDENCY_OF,
}
# The tag-value parser infers this relation from File placement (parser.py:606)
INFERRED_TYPES = {("Package", "CONTAINS", "File")}


def resolve_spdx_id(spdx_id, namespace, external_refs):
    """Resolve an SPDX 2 ID to the IRI a spec-correct SPDX 3 migration needs."""
    if ":" not in spdx_id:
        return f"{namespace}#{spdx_id}"
    prefix, local_id = spdx_id.split(":", 1)
    for ref in external_refs:
        if ref.document_ref_id == prefix:
            return f"{ref.document_uri}#{local_id}"
    return None


def type_name(element):
    return type(element).__name__


def relationships(elements):
    return {
        spdx_id: element
        for spdx_id, element in elements.items()
        if type_name(element) in RELATIONSHIP_CLASSES
    }


def record(checks, mapping, kind, source_id, target_id, status, category, note):
    checks.append(
        {
            "kind": kind,
            "source_id": source_id,
            "target_id": target_id,
            "status": status,
            "category": category,
            "note": note,
        }
    )
    if status != "INFO":
        mapping.append(
            {
                "source_kind": kind,
                "source_id": source_id,
                "target_id": target_id,
                "status": status,
                "category": category,
                "note": note,
            }
        )


def analyse(input_path, outdir, label):
    document = parse_file(input_path)
    namespace = document.creation_info.document_namespace
    external_refs = document.creation_info.external_document_refs

    diagnostics = StringIO()
    with redirect_stderr(diagnostics):
        payload = bump_spdx_document(document)
    elements = payload.get_full_map()
    emitted_relationships = relationships(elements)

    os.makedirs(outdir, exist_ok=True)
    out_base = os.path.join(outdir, label)
    write_payload(payload, out_base)

    checks = []
    mapping = []
    lines = [
        f"SPDX 2 -> 3 migration trace: {label}",
        f"input: {input_path}",
        f"namespace: {namespace}",
        f"jsonld: {out_base}.jsonld",
        "",
        "== INPUT ELEMENTS ==",
    ]
    for package in document.packages:
        lines.append(f"package   {package.spdx_id}  name={package.name!r}")
    for spdx_file in document.files:
        lines.append(f"file      {spdx_file.spdx_id}  name={spdx_file.name!r}")
    for snippet in document.snippets:
        lines.append(f"snippet   {snippet.spdx_id}  file={snippet.file_spdx_id}")

    lines += ["", "== EMITTED ELEMENTS =="]
    for spdx_id, element in elements.items():
        lines.append(f"{type_name(element):32} {spdx_id}")

    # ---- node identity -------------------------------------------------
    lines += ["", "== NODE ID MAPPING =="]
    for kind, source_elements in (
        ("package", document.packages),
        ("file", document.files),
        ("snippet", document.snippets),
    ):
        for source in source_elements:
            expected = resolve_spdx_id(source.spdx_id, namespace, external_refs)
            emitted = elements.get(expected) if expected else None
            ok = emitted is not None and type_name(emitted).lower().endswith(kind)
            status = "one-to-one" if ok else "missing"
            record(
                checks, mapping, kind, source.spdx_id, expected, status, "identity",
                type_name(emitted) if emitted else "",
            )
            lines.append(f"{kind:8} {source.spdx_id:40} -> {expected!r}  {'MATCH' if ok else 'MISSING'}")

    # element count guard: catches silent overwrite / renumbering collisions
    for kind, source_elements, target_class in (
        ("package", document.packages, "Package"),
        ("file", document.files, "File"),
        ("snippet", document.snippets, "Snippet"),
    ):
        emitted_count = sum(1 for element in elements.values() if type_name(element) == target_class)
        ok = emitted_count >= len(source_elements)
        record(
            checks,
            mapping,
            kind,
            f"<count:{kind}>",
            str(emitted_count),
            "one-to-one" if ok else "lost",
            "count",
            f"input={len(source_elements)} emitted={emitted_count}",
        )
        flag = "OK" if ok else "LOSS"
        lines.append(f"count    {kind:8} input={len(source_elements)} emitted={emitted_count}  {flag}")

    # ---- relationships -------------------------------------------------
    lines += ["", "== RELATIONSHIP MAPPING =="]
    for counter, rel in enumerate(document.relationships):
        source_from = resolve_spdx_id(rel.spdx_element_id, namespace, external_refs)
        source_to = (
            resolve_spdx_id(rel.related_spdx_element_id, namespace, external_refs)
            if isinstance(rel.related_spdx_element_id, str)
            else None
        )
        expected_from, expected_to = source_from, source_to
        expected_type = rel.relationship_type.name
        swapped = rel.relationship_type in DEPENDENCY_OF_TYPES and source_to is not None
        if swapped:
            expected_from, expected_to = source_to, source_from
            expected_type = "DEPENDS_ON"

        failure = None
        hit = None
        if expected_to is None:
            failure = ("not-asserted", "related element is NOASSERTION/NONE")
        elif expected_to not in elements and ":" in str(rel.related_spdx_element_id):
            failure = ("external-target-unresolved", f"target {expected_to!r} is not in the payload")
        else:
            for emitted in emitted_relationships.values():
                if emitted.from_element == expected_from and emitted.relationship_type.name == expected_type:
                    if emitted.to == [expected_to]:
                        hit = emitted
                        break
                    if expected_to in emitted.to:
                        unresolved = [target for target in emitted.to if target not in elements]
                        if unresolved:
                            failure = (
                                "merge-contamination",
                                f"target present but merged with unresolved {unresolved}",
                            )
                        else:
                            hit = emitted
                        break
                if emitted.from_element == source_from and expected_from != source_from:
                    failure = (
                        "direction-not-swapped",
                        f"emitted {emitted.spdx_id} keeps {source_from} {expected_type}",
                    )
                    break

        if hit is not None:
            exact = hit.to == [expected_to]
            status = "one-to-one" if exact else "aggregated"
            record(
                checks, mapping, "relationship", f"{counter}:{rel.spdx_element_id} {rel.relationship_type.name} "
                f"{rel.related_spdx_element_id}", hit.spdx_id, status, "relationship",
                f"emitted {hit.from_element} {hit.relationship_type.name} {hit.to}",
            )
            lines.append(
                f"[{counter}] {rel.spdx_element_id} {rel.relationship_type.name} {rel.related_spdx_element_id}"
                f"  ->  {hit.spdx_id} {hit.from_element} {hit.relationship_type.name} {hit.to}  [{status}]"
            )
        else:
            if failure is None and source_to:
                overlapping = [
                    emitted for emitted in emitted_relationships.values()
                    if emitted.from_element == expected_from and emitted.relationship_type.name == expected_type
                ]
                if overlapping:
                    targets = [target for emitted in overlapping for target in emitted.to]
                    failure = (
                        "merge-overwrite",
                        f"same group exists but {expected_to!r} is absent; emitted targets={targets} "
                        f"(a previously emitted target can be duplicated instead)",
                    )
            category, note = failure if failure else ("missing", "no matching emitted relationship")
            record(
                checks, mapping, "relationship", f"{counter}:{rel.spdx_element_id} {rel.relationship_type.name} "
                f"{rel.related_spdx_element_id}", None, "lost", category,
                f"{note}; expected {expected_from} {expected_type} [{expected_to}]",
            )
            lines.append(
                f"[{counter}] {rel.spdx_element_id} {rel.relationship_type.name} {rel.related_spdx_element_id}"
                f"  ->  {category}: {note}"
            )

    # ---- annotations ---------------------------------------------------
    lines += ["", "== ANNOTATION MAPPING =="]
    for counter, annotation in enumerate(document.annotations):
        emitted_id = f"{namespace}#SPDXRef-Annotation-{counter}"
        emitted = elements.get(emitted_id)
        source_subject = annotation.spdx_id
        expected_subject = resolve_spdx_id(source_subject, namespace, external_refs)
        if emitted is None:
            record(
                checks, mapping, "annotation", f"{counter}:{source_subject}", None, "lost", "missing",
                "annotation element absent",
            )
            lines.append(f"[{counter}] {source_subject} -> MISSING ({emitted_id})")
            continue
        subject_ok = emitted.subject == expected_subject
        subject_category = "subject" if subject_ok else (
            "external-subject-unresolved" if ":" in source_subject else "subject-mismatch"
        )
        record(
            checks, mapping, "annotation", f"{counter}:{source_subject}", emitted_id,
            "one-to-one" if subject_ok else "lost", subject_category,
            f"subject {emitted.subject!r}, expected {expected_subject!r}",
        )
        annotator = annotation.annotator
        attributions = list(emitted.creation_info.created_by or []) + list(emitted.creation_info.created_using or [])
        token = annotator.name.replace(" ", "")
        annotator_ok = any(token in str(value) for value in attributions)
        record(
            checks, mapping, "annotation", f"{counter}:annotator:{annotator.actor_type.name}:{annotator.name}",
            emitted_id, "one-to-one" if annotator_ok else "lost", "annotator-attribution",
            f"created_by={emitted.creation_info.created_by} created_using={emitted.creation_info.created_using}",
        )
        lines.append(
            f"[{counter}] {source_subject} -> {emitted_id} subject={emitted.subject!r} "
            f"type={emitted.annotation_type.name} created_by={emitted.creation_info.created_by} "
            f"created_using={emitted.creation_info.created_using}"
        )

    # ---- external document references ---------------------------------
    lines += ["", "== EXTERNAL DOCUMENT REFERENCES =="]
    spdx_document = elements.get(f"{namespace}#SPDXRef-DOCUMENT")
    for ref in external_refs:
        namespace_ok = any(
            entry.prefix == ref.document_ref_id and entry.namespace == ref.document_uri + "#"
            for entry in spdx_document.namespaces
        )
        import_id = f"{ref.document_ref_id}:SPDXRef-DOCUMENT"
        import_entry = next((entry for entry in spdx_document.imports if entry.external_id == import_id), None)
        record(checks, mapping, "external-document-ref", ref.document_ref_id, f"{ref.document_uri}#",
               "one-to-one" if namespace_ok else "lost", "namespace-map", f"document_uri={ref.document_uri}")
        record(checks, mapping, "external-document-ref", ref.document_ref_id, import_id,
               "one-to-one" if import_entry else "lost", "external-map",
               f"verified_using={[type(h).__name__ for h in (import_entry.verified_using if import_entry else [])]}")
        lines.append(
            f"{ref.document_ref_id}: {ref.document_uri} checksum={ref.checksum.algorithm.name}:"
            f"{ref.checksum.value} -> NamespaceMap(namespace={ref.document_uri}#), ExternalMap({import_id!r})"
        )

    # ---- package external references ----------------------------------
    lines += ["", "== PACKAGE EXTERNAL REFERENCES =="]
    for package in document.packages:
        emitted = elements.get(resolve_spdx_id(package.spdx_id, namespace, external_refs))
        for ref in package.external_references:
            where = None
            if emitted is not None:
                if getattr(emitted, "package_url", None) == ref.locator:
                    where = "package_url"
                elif any(identifier.identifier == ref.locator for identifier in emitted.external_identifier):
                    where = "external_identifier"
                elif any(ref.locator in reference.locator for reference in emitted.external_reference):
                    where = "external_reference"
            status = "one-to-one" if where else "lost"
            category = "package-url-promotion" if where == "package_url" else (
                "external-ref" if where else "silent-drop"
            )
            record(checks, mapping, "external-ref", f"{package.spdx_id}:{ref.reference_type}:{ref.locator}",
                   where, status, category, f"comment={ref.comment!r}")
            lines.append(f"{package.spdx_id:30} {ref.reference_type:16} {ref.locator:55} -> {where or 'DROPPED'}")

    # ---- licenses / copyright / snippet linkage -----------------------
    lines += ["", "== LICENSE / COPYRIGHT / SNIPPET RETENTION =="]
    for package in document.packages:
        emitted = elements.get(resolve_spdx_id(package.spdx_id, namespace, external_refs))
        for source_name, target_name in (
            ("license_concluded", "concluded_license"),
            ("license_declared", "declared_license"),
        ):
            source_value = getattr(package, source_name)
            target_value = getattr(emitted, target_name, None) if emitted else None
            retained = source_value is None or target_value is not None
            record(checks, mapping, "license", f"{package.spdx_id}:{source_name}", target_name,
                   "one-to-one" if retained else "lost", "license", f"{source_value} -> {target_value}")
            lines.append(f"{package.spdx_id:30} {source_name:20} {str(source_value):28} -> {target_value}")
        retained = package.copyright_text is None or (
            isinstance(package.copyright_text, str) and emitted is not None and emitted.copyright_text is not None
        )
        record(checks, mapping, "copyright", package.spdx_id, "copyright_text",
               "one-to-one" if retained else "lost", "copyright", repr(package.copyright_text))
    for spdx_file in document.files:
        emitted = elements.get(resolve_spdx_id(spdx_file.spdx_id, namespace, external_refs))
        source_value = spdx_file.license_concluded
        target_value = getattr(emitted, "concluded_license", None) if emitted else None
        retained = source_value is None or target_value is not None
        record(checks, mapping, "license", f"{spdx_file.spdx_id}:license_concluded", "concluded_license",
               "one-to-one" if retained else "lost", "license", f"{source_value} -> {target_value}")
        lines.append(f"{spdx_file.spdx_id:30} license_concluded      {str(source_value):28} -> {target_value}")
    for snippet in document.snippets:
        emitted = elements.get(resolve_spdx_id(snippet.spdx_id, namespace, external_refs))
        linked = getattr(emitted, "file_spdx_id", None) is not None if emitted else False
        record(checks, mapping, "snippet", snippet.spdx_id, getattr(emitted, "spdx_id", None),
               "one-to-one" if linked else "lost", "snippet-file-link", f"file_spdx_id={snippet.file_spdx_id}")
        lines.append(f"{snippet.spdx_id:30} file_spdx_id           {snippet.file_spdx_id} -> not represented")

    # ---- dangling references ------------------------------------------
    lines += ["", "== DANGLING REFERENCES =="]
    dangling = 0
    for spdx_id, element in elements.items():
        if type_name(element) in RELATIONSHIP_CLASSES:
            targets = [element.from_element, *element.to]
        elif type_name(element) == "Annotation":
            targets = [element.subject]
        else:
            continue
        for target in targets:
            if target not in elements:
                dangling += 1
                record(checks, mapping, "dangling", spdx_id, target, "lost", "dangling", "target not in payload")
                lines.append(f"{spdx_id} -> {target} NOT IN PAYLOAD")
    if not dangling:
        lines.append("none")

    # ---- parser provenance --------------------------------------------
    raw = open(input_path, encoding="utf-8").read()
    raw_relationship_count = len(re.findall(r"(?m)^Relationship:", raw))
    inferred = len(document.relationships) - raw_relationship_count
    record(checks, mapping, "provenance", "<parser>", str(len(document.relationships)), "INFO", "parser-inference",
           f"raw Relationship: lines={raw_relationship_count}, parsed={len(document.relationships)}")
    lines += [
        "",
        "== PARSER PROVENANCE ==",
        f"raw 'Relationship:' lines: {raw_relationship_count}; parsed relationships: {len(document.relationships)}",
        f"relationships added by the tag-value parser itself: {inferred} (File placement under a Package)",
        "",
        "== DIAGNOSTICS EMITTED BY THE BUMPER (stderr) ==",
    ]
    lines.extend(diagnostics.getvalue().splitlines())
    lines.append("")

    # ---- summary -------------------------------------------------------
    statuses = {}
    for item in checks:
        statuses[(item["status"], item["category"])] = statuses.get((item["status"], item["category"]), 0) + 1
    failures = [item for item in checks if item["status"] == "lost"]
    lines += ["", "== SUMMARY =="]
    for (status, category), count in sorted(statuses.items()):
        lines.append(f"{status:11} {category:28} {count}")
    lines.append(f"source assertions: {sum(1 for i in checks if i['status'] != 'INFO')}  lost: {len(failures)}")
    for item in failures:
        lines.append(f"LOST {item['category']}: {item['source_id']} -> {item['target_id']} ({item['note']})")

    report_path = out_base + ".trace.txt"
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    with open(out_base + ".mapping.json", "w", encoding="utf-8") as handle:
        json.dump({"input": input_path, "label": label, "mapping": mapping, "checks": checks}, handle, indent=2)
    return failures, report_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--label", default=None)
    parser.add_argument("--strict", action="store_true", help="exit 1 when any source assertion is lost")
    args = parser.parse_args()

    label = args.label or os.path.splitext(os.path.basename(args.input))[0]
    failures, report_path = analyse(args.input, args.outdir, label)
    print(f"wrote {report_path}; lost={len(failures)}")
    return 1 if (args.strict and failures) else 0


if __name__ == "__main__":
    sys.exit(main())
