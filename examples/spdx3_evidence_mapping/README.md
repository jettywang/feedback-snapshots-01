# SPDX 2 -> SPDX 3 evidence mapping (incident triage)

This directory records what the library's migration code (`bump_spdx_document()`
in `src/spdx_tools/spdx3/bump_from_spdx2/`) actually preserves when an SPDX 2.x
software bill of materials is promoted to the SPDX 3.0.0 prototype model, and
what has to be kept from the original document to stay evidentiary.

It is deliberately run against the real bumper, not against a description of it.
The two commands below reproduce every table and trace in `MAPPING.md`.

```sh
# 1. migrate each sample and classify every source assertion
for f in examples/spdx3_evidence_mapping/sample-0*; do
  .venv/bin/python examples/spdx3_evidence_mapping/trace_mapping.py \
    --input "$f" --outdir examples/spdx3_evidence_mapping/output
done

# 2. downstream RDF check of the JSON-LD the CLI would write
.venv/bin/python examples/spdx3_evidence_mapping/verify_jsonld.py \
  examples/spdx3_evidence_mapping/output/*.jsonld
```

`trace_mapping.py` calls `parse_file()` followed by `bump_spdx_document()`, so it
also captures the tag-value parser's own additions (see limitation P1). For a
CLI-equivalent run use `pyspdxtools3 --infile <file> -o <stem>`; it writes the
same JSON-LD through the same writer.

## Files

| file | purpose |
| --- | --- |
| `MAPPING.md` | evidence mapping and limitations, the reviewable deliverable |
| `sample-01-traceable.spdx` | positive case: package/file/relationship/annotation survive one-to-one |
| `sample-02-requires-original.spdx` | negative case: dependency direction, external targets, tool annotation, licenses |
| `sample-03-snippet.spdx` | snippet identity survives but `file_spdx_id` does not |
| `sample-04-relationship-merge.json` | two `DESCRIBES` merge and one target is duplicated while the other is lost |
| `sample-05-id-collision.spdx` | tool annotator shares an id with the document's tool, attribution is dropped |
| `trace_mapping.py` | per-assertion tracer, writes `*.trace.txt` and `*.mapping.json` |
| `verify_jsonld.py` | downstream rdflib check for unresolved typed references and literal imports |
| `output/` | generated JSON-LD, traces and machine-readable mappings |

## Result in one line

Nodes keep stable, namespace-scoped IRIs; external document references keep
their namespace map and verification hash; annotations keep subject, statement
and date for local (person/organization) annotators. Everything that depends on
the *edge* between nodes (dependency direction, cross-document targets,
annotation attribution for tools, license and copyright content) needs the
original SPDX 2 document to be reconstructed.
