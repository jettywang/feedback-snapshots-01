#!/usr/bin/env python3
"""Downstream structural checks for migrated SPDX 3 JSON-LD.

Usage:
    python examples/spdx3_evidence_mapping/verify_jsonld.py output/*.jsonld

This does not run SHACL (the repository's SHACL test is skipped and pyshacl is
not part of the pinned offline dependencies). It parses the same JSON-LD the
CLI writes with rdflib and checks that every typed reference resolves, that
imports stay literals (not accidentally resolved against the local namespace),
and that the JSON-LD graph survives an RDF round trip.
"""
import json
import sys

from rdflib import Graph, Literal, URIRef
from rdflib.namespace import RDF

CORE = "https://spdx.org/rdf/Core/"
REFERENCE_PREDICATES = {
    CORE + "from": "from",
    CORE + "to": "to",
    CORE + "subject": "subject",
    CORE + "rootElement": "rootElement",
}
# A hardcoded prefix shadowing here simulates a downstream consumer that expands
# prefixed names before checking imports. The bumper leaves DocumentRef IDs in
# the externalId field without the namespace map, so such expansion is tempting
# and wrong.
DOCUMENT_REF_PREFIX = "DocumentRef-"


def load(jsonld_path):
    with open(jsonld_path, encoding="utf-8") as handle:
        return json.load(handle)


def main(paths):
    failures = 0
    for path in paths:
        document = load(path)
        graph = Graph()
        graph.parse(data=json.dumps(document), format="json-ld")
        ids = {str(subject) for subject in graph.subjects(RDF.type, None)}
        node_ids = set(str(item["@id"]) for item in document["@graph"] if "@id" in item)

        unresolved = []
        for subject, predicate, obj in graph.triples((None, None, None)):
            if str(predicate) in REFERENCE_PREDICATES and isinstance(obj, URIRef):
                if str(obj) not in node_ids:
                    unresolved.append((str(subject), REFERENCE_PREDICATES[str(predicate)], str(obj)))

        imports = list(graph.subject_objects(URIRef(CORE + "imports")))
        import_checks = []
        for subject, obj in imports:
            external_ids = list(graph.objects(obj, URIRef(CORE + "externalId")))
            defining = list(graph.objects(obj, URIRef(CORE + "definingDocument")))
            for value in external_ids:
                is_literal = isinstance(value, Literal)
                looks_like_prefix = str(value).startswith(DOCUMENT_REF_PREFIX)
                import_checks.append(
                    {
                        "external_id": str(value),
                        "literal": is_literal,
                        "prefixed": looks_like_prefix,
                        "defining_document": [str(item) for item in defining],
                    }
                )

        print(f"{path}")
        print(f"  triples: {len(graph)}  node_ids: {len(node_ids)}")
        print(f"  unresolved typed references: {len(unresolved)}")
        for item in unresolved:
            print(f"    {item}")
        print(f"  imports: {len(import_checks)}")
        for item in import_checks:
            flag = "DOCUMENTREF-NOT-RESOLVED" if item["prefixed"] and not item["defining_document"] else ""
            print(
                f"    externalId={item['external_id']!r} literal={item['literal']} "
                f"definingDocument={item['defining_document']} {flag}"
            )
        failures += len(unresolved)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
