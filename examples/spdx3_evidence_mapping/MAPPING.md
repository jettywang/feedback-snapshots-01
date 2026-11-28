# SPDX 2 -> 3 migration: evidence mapping and limitations

Scope: SPDX 2.3 tag-value and JSON input promoted to the SPDX 3.0.0 model by
`spdx_tools.spdx3.bump_from_spdx2.spdx_document.bump_spdx_document()` at commit
`4e32d2f`. Every statement below was observed by running that function; file and
line references point at the code path that produces the behaviour.

How to review:

- `README.md` has the two offline reproduction commands.
- `output/sample-0N-*.trace.txt` is the human-readable per-assertion trace.
- `output/sample-0N-*.mapping.json` is the same data as machine-readable JSON.
- `sample-0N-*.spdx[*]` are the inputs; `output/sample-0N-*.jsonld` are the migrated graphs.

The migration is one-way: the library at this commit only writes SPDX 3
(`README.md:23`), so a reviewer cannot round-trip SPDX 3 back to the original
SPDX 2 document with the same tool.

## 1. Map overview

### 1.1 What can be traced one-to-one

| SPDX 2 source | SPDX 3 target | How it is produced |
| --- | --- | --- |
| Package | `software:Package`, IRI `<documentNamespace>#<SPDXID>` | `get_full_element_spdx_id()` in `src/spdx_tools/spdx/spdx_element_utils.py:31` |
| File | `software:File`, same IRI rule | `bump_file()` in `bump_from_spdx2/file.py:16` |
| Snippet | `software:Snippet`, same IRI rule | `bump_snippet()` in `bump_from_spdx2/snippet.py:20` |
| Document | `core:SpdxDocument` at `<namespace>#SPDXRef-DOCUMENT` | `bump_creation_info()` in `bump_from_spdx2/creation_info.py:16` |
| Package checksum | `Hash` in `verified_using` | `bump_checksum()` in `bump_from_spdx2/checksum.py:9` |
| `PackageSupplier` / `PackageOriginator` (Actor, not NOASSERTION) | `supplied_by` / `originated_by` -> `Person`/`Organization`/`Tool` | `bump_package()` in `bump_from_spdx2/package.py:44-51` |
| `ExternalDocumentRef` | `NamespaceMap` (prefix, `uri + "#"`) and `ExternalMap` (`external_id="<DocumentRef>:SPDXRef-DOCUMENT"`, SHA1 in `verified_using`) | `bump_external_document_ref()` in `bump_from_spdx2/external_document_ref.py:11` |
| Document-level `DESCRIBES` | `SpdxDocument.root_element` | `bump_spdx_document()` in `bump_from_spdx2/spdx_document.py:25-30` |
| Annotation by Person/Organization | `core:Annotation` with `subject`, `statement`, `annotation_type`, `creation_info.created` | `bump_annotation()` in `bump_from_spdx2/annotation.py:14` |
| Locally resolved relationship | `Relationship`, IRI `#SPDXRef-Relationship-<index>` | `bump_relationship()` in `bump_from_spdx2/relationship.py:172` |
| `ExternalRef` type `purl` / `cpe22Type` / `cpe23Type` / `swid` / `swh` / `gitoid` | `ExternalIdentifier` (or `Package.package_url` for the single bare purl) | `bump_external_package_ref()` in `bump_from_spdx2/package.py:134` |
| `ExternalRef` type `advisory` / `fix` | `ExternalReference` (`SECURITY_ADVISORY` / `SECURITY_FIX`) | `external_ref_type_map` in `bump_from_spdx2/package.py:117` |

### 1.2 What is aggregated

These sources still have evidence in SPDX 3, but the original assertion can no
longer be recovered from the SPDX 3 graph alone.

| SPDX 2 source | SPDX 3 target | Consequence |
| --- | --- | --- |
| Several `DESCRIBES` from one element to several targets | one `Relationship` with several `to` values | the 1:1 edge is only recoverable with the original `Relationship:` lines; `bump_from_spdx2/relationship.py:235` |
| Several dependency kinds (e.g. `DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`) from the same element | one `DEPENDS_ON` relationship, qualifiers `scope`/`conditionality`/`linkage` | **only if the bumper does not mis-handle the swap**, see D1 |
| Annotation authors sharing a name | one `Person`/`Organization`/`Tool` element by synthesized `SPDXRef-Actor-<name>-<email>` | the original SPDX 2 actor string is not stored verbatim |
| Creator list | `created_by` (people/organizations) and `created_using` (tools) | the split is by actor type, not by source order |
| `PackageCopyrightText` / `FileCopyrightText` as `NOASSERTION` | `None` | "explicitly no assertion" and "not present" become indistinguishable; `bump_from_spdx2/package.py:57-61`, `file.py:36-40` |
| `PackageHomepage: NOASSERTION` | `None` | same ambiguity, `bump_from_spdx2/package.py:109`, via `handle_no_assertion_or_none` |
| `DownloadLocation: NOASSERTION` | `None` | same ambiguity, `bump_from_spdx2/package.py:42` |

### 1.3 What is lost

The bumper itself prints one of these to stderr when it knows it is dropping a
field; the rest are silent. The trace files mark them `lost`.

| ID | Lost source | Code path | Observed in |
| --- | --- | --- | --- |
| D1 | `DEPENDENCY_OF` and related dependency-of types: the swap is overwritten, producing a **self-dependency** | `bump_from_spdx2/relationship.py:184-208` (`from_element` reset at line 196) | sample-02 |
| D2 | Relationship target in another document: left as `<localNamespace>#DocumentRef-x:SPDXRef-y` instead of the external namespace | `bump_from_spdx2/relationship.py:202` | sample-01, sample-02 |
| D3 | Annotation subject in another document: same wrong local prefix | `bump_from_spdx2/annotation.py:46` | sample-02 |
| D4 | Root element in another document: same wrong local prefix | `bump_from_spdx2/spdx_document.py:26` | sample-02 |
| D5 | Tool annotator: annotation is created but the tool is never put in `created_using`; it inherits the document's creation_info or has none, so the tool is not attributed | `bump_from_spdx2/annotation.py:29-38` | sample-02, sample-05 |
| D6 | Relationship merge: when one member has a comment, the uncommented members overwrite the merged target list, duplicating one target and dropping another | `bump_from_spdx2/relationship.py:235-259` | sample-04 |
| D7 | `maven-central`, `npm`, `nuget`, `bower`, `url` external references: dropped silently because their map value is `None` | `bump_from_spdx2/package.py:117-155` | sample-02 |
| D8 | Unknown `ExternalRef` types (e.g. `OTHER`): dropped **with** a stderr message | `bump_from_spdx2/package.py:141-148` | probe |
| D9 | `license_concluded`, `license_declared`, `license_info_in_*`, `license_comment` for every package/file/snippet | not called by `bump_package`/`bump_file`/`bump_snippet`; `bump_license_expression()` exists but has no caller | all samples |
| D10 | `ExtractedLicensingInfo` (custom license text) | never iterated in `bump_spdx_document()` | sample-01, sample-02 |
| D11 | `Snippet.file_spdx_id` (snippet -> file link); only byte/line range survive | `bump_from_spdx2/snippet.py:36` | sample-03 |
| D12 | `PackageVerificationCode` | `bump_from_spdx2/package.py:53` | probe |
| D13 | `PackageFileName`, `FilesAnalyzed`, `PackageLicenseInfoFromFiles`, `PackageLicenseComment` | `bump_from_spdx2/package.py:43,52,62-66` | all |
| D13b | `PackageHomepage: NOASSERTION` | `bump_from_spdx2/package.py:109`, via `handle_no_assertion_or_none` | probe |
| D14 | `FileType`, `Notice`, `Contributors`, `LicenseInfoInFile`, `FileLicenseComment` | `bump_from_spdx2/file.py:33-35,41-45` | all |
| D15 | `CreationInfo.creator_comment`, `LicenseListVersion` | `bump_from_spdx2/creation_info.py:34-38` (LicenseListVersion) and not read (creator_comment) | probe |
| D16 | Synthesized-node collision: a user element whose SPDXID is `SPDXRef-Relationship-<n>` or `SPDXRef-Annotation-<n>` is overwritten by the synthesized element | `bump_from_spdx2/relationship.py:178`, `annotation.py:21`, `Payload.add_element` in `spdx3/payload.py:15` | probe |
| D17 | `ExternalMap.external_id` stays the SPDX 2 token `DocumentRef-x:SPDXRef-y`, not an absolute IRI; the document-level import has no `defining_document`, element imports set it to another token | `bump_from_spdx2/external_document_ref.py:14`, `package.py:35-40` | sample-01, sample-02 |

### 1.4 What needs the original document

For incident evidence, keep the SPDX 2 original (or a hash-sealed copy) whenever
any of these matter:

- the direction of a dependency (`A DEPENDENCY_OF B` is not `A DEPENDS_ON A`);
- an assertion whose subject or target is in another SBOM (`DocumentRef-...`);
- who made an annotation when the annotator is a tool;
- what license was concluded/declared, or what custom license text was attached;
- which file a snippet came from;
- the exact spelling of an actor or an external reference that the mapper split,
  merged or dropped.

## 2. Small inputs and outputs

### 2.1 Positive case: `sample-01-traceable.spdx`

Input (abridged):

```text
DocumentNamespace: https://example.com/spdxdocs/incident-001
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-app
Relationship: SPDXRef-Package-app CONTAINS SPDXRef-File-main
PackageName: app
SPDXID: SPDXRef-Package-app
ExternalRef: PACKAGE-MANAGER purl pkg:generic/app@1.2.3
ExternalRef: SECURITY cpe23Type cpe:2.3:a:acme:app:1.2.3:...
Annotator: Person: Alice Analyst (alice@example.com)
AnnotationDate: 2026-11-02T00:00:00Z
AnnotationComment: <text>Reviewed against incident report IR-42; package is affected.</text>
AnnotationType: REVIEW
SPDXREF: SPDXRef-Package-app
```

Output (abridged, from `output/sample-01-traceable.trace.txt` and `.jsonld`):

```text
package  SPDXRef-Package-app -> 'https://example.com/spdxdocs/incident-001#SPDXRef-Package-app'  MATCH
file     SPDXRef-File-main   -> 'https://example.com/spdxdocs/incident-001#SPDXRef-File-main'    MATCH
[0] DOCUMENT DESCRIBES Package-app -> Relationship-0 DOCUMENT DESCRIBES ['...#SPDXRef-Package-app'] [one-to-one]
[2] Package-app CONTAINS File-main -> Relationship-2 Package-app CONTAINS ['...#SPDXRef-File-main'] [one-to-one]
[0] Annotation subject='...#SPDXRef-Package-app' type=REVIEW created_by=['...#SPDXRef-Actor-AliceAnalyst-alice@example.com']
    statement='Reviewed against incident report IR-42; package is affected.'
purl  -> package_url
cpe23 -> external_identifier
```

This proves the positive chain: package identity, file identity, a local
`CONTAINS` edge and a person's review annotation all survive with matching IRIs
and text.

### 2.2 Negative case: `sample-02-requires-original.spdx`

Input (abridged):

```text
ExternalDocumentRef: DocumentRef-upstream https://upstream.example/sbom/component-4.0 SHA1: aa11...
Relationship: SPDXRef-Package-service DEPENDENCY_OF SPDXRef-Package-vendorlib
Relationship: SPDXRef-DOCUMENT DESCRIBES DocumentRef-upstream:SPDXRef-Package-crypto
Annotator: Tool: vuln-correlator-2.1
AnnotationComment: <text>Automated match: CVE-2026-1234 maps to service 4.0.1.</text>
SPDXREF: SPDXRef-Package-service
```

Output (from `output/sample-02-requires-original.trace.txt`):

```text
[1] Package-service DEPENDENCY_OF Package-vendorlib
    -> direction-not-swapped: emitted Relationship-1 keeps Package-service DEPENDS_ON ['...#SPDXRef-Package-service']
[2] DOCUMENT DESCRIBES DocumentRef-upstream:SPDXRef-Package-crypto
    -> external-target-unresolved: target 'https://upstream.example/sbom/component-4.0#SPDXRef-Package-crypto' is not in payload
[0] annotation by TOOL vuln-correlator-2.1
    -> created_by=['...#SPDXRef-Actor-BobResponder-bob@example.com']
       created_using=['...#SPDXRef-Actor-fixture-writer-1.0']  (document writer, not the annotator)
maven-central org.example:service:4.0.1 -> DROPPED
license_concluded Apache-2.0 -> None
license_declared  Apache-2.0 -> None
```

This proves the negative chain: the dependency edge becomes a self-cycle, the
cross-document target is unresolvable, the tool annotation is attributed to the document's
writer instead of itself, and
licenses and one external reference disappear. None of these are recoverable
from the SPDX 3 output; the original SPDX 2 lines are required.

### 2.3 Merge case: `sample-04-relationship-merge.json`

Two `DESCRIBES` from `SPDXRef-DOCUMENT`, the second carrying a comment. The
expected merged relationship is
`DOCUMENT DESCRIBES [Package-alpha, Package-beta]`. Actual output:

```text
Relationship-0 DOCUMENT DESCRIBES ['SPDXRef-Package-alpha']  (duplicated)
Relationship-1 DOCUMENT DESCRIBES ['SPDXRef-Package-alpha']
Package-beta is absent; the comment is gone.
```

The comment-bearing member is added to the payload on its own, then the
uncommented member overwrites the merged target list with only its own target.
The trace reports `merge-overwrite` for Package-beta and flags the duplicated
Package-alpha.

### 2.4 Downstream check

`verify_jsonld.py` parses the writer's JSON-LD with rdflib (115 triples for
sample-01) and reports every typed reference whose target is not a node in the
graph. For sample-01 it reports one unresolved `core:to`; for sample-02 it
reports three unresolved references (`rootElement`, `subject`, `to`) and renders
`ExternalMap.externalId` as a literal with no `definingDocument`.

## 3. Limitations of this review

- **Prototype target.** The code writes the SPDX 3.0.0 model shipped with this
  repository. Field names and UML/OWL shapes changed after 3.0.0; results are
  not a statement about later SPDX 3 releases.
- **No SHACL run.** The repository's own SHACL test is `@pytest.mark.skip` and
  says validation currently fails (`tests/spdx3/validation/json_ld/test_shacl_validation.py:11`,
  `src/spdx_tools/spdx3/writer/json_ld/process.md:29`). `pyshacl` is not in
  `.feedback/requirements.txt` and the sandbox denied the package index, so the
  downstream check here is structural (rdflib), not SHACL conformance.
- **Parser additions are included.** The tag-value parser synthesizes
  `Package CONTAINS File` from file placement (`src/spdx_tools/spdx/parser/tagvalue/parser.py:606`).
  sample-02 has four explicit `Relationship:` lines but five parsed
  relationships. Any count-based evidence audit must account for this before
  blaming the bumper.
- **Whitespace-only inputs.** The samples are hand-written to exercise specific
  code paths; they are not production SBOMs. The pinned baseline
  (`tests/spdx3/bump`, 52 passed) was not modified.
- **Synthesized IDs are positional.** `SPDXRef-Relationship-<index>` and
  `SPDXRef-Annotation-<index>` depend on input order (probe: reordering two
  relationships swaps `Relationship-0`/`Relationship-1`). They are stable for a
  fixed input, not across edits.
- **Cross-document identity.** Namespace-scoped IRIs keep two documents' local
  `SPDXRef-Package` distinct (probe: `doc-a#SPDXRef-Package` vs
  `doc-b#SPDXRef-Package`). Do not compare bare SPDX 2 IDs across documents.
- **Not tested here.** RDF/XML, YAML and XML serializers; snippets with
  `SnippetFromFileSPDXID` pointing outside the document; annotations on
  `SpdxDocument` itself. These should be spot-checked before relying on them.

## 4. Operator checklist

1. Keep the SPDX 2 original, its namespace and a SHA-256 of the file alongside
   the SPDX 3 output; without it the `lost` rows above cannot be reconstructed.
2. Before treating SPDX 3 edges as evidence, resolve every `core:to`,
   `core:subject`, `core:rootElement` against the node set; a `DocumentRef-`
   substring inside a local namespace IRI is a bug, not a link.
3. Do not trust a dependency edge whose source equals its target; check the
   original `DEPENDENCY_OF` line.
4. Do not cite tool annotations from SPDX 3 alone; `created_using` does not identify the
   annotation's tool (it is empty or points at the document's writer).
5. Do not cite licenses from SPDX 3 alone; concluded/declared fields and custom
   license text are absent.
6. Re-derive counts from the raw `Relationship:` lines, not from the parsed
   model, when arguing completeness.
