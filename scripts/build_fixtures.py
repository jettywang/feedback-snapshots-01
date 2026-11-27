"""Generate a reproducible offline SPDX evidence-store fixture set.

Layout produced under fixtures/:
  manifests/   root manifests (one JSON, one Tag-Value) + SHA-256 sidecars
  offline/     externally referenced SPDX documents and supporting bytes

The bytes are written first and checksummed from disk, so every claimed digest
is a real digest of an actual file; the negative cases are created by tampering
or by deleting a file after its digest has been captured.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from spdx_tools.spdx.model import ChecksumAlgorithm  # noqa: E402

from offline_evidence.digest import hash_file  # noqa: E402
from offline_evidence.spdx_doc import external_ref, make_document, write_document  # noqa: E402

FIX = ROOT / "fixtures"
OFFLINE = FIX / "offline"
MANIFESTS = FIX / "manifests"


def write_sidecar(path: Path) -> None:
    digest = hash_file(path, ChecksumAlgorithm.SHA256)
    Path(str(path) + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")


def main() -> None:
    for folder in (OFFLINE, MANIFESTS):
        folder.mkdir(parents=True, exist_ok=True)

    # --- Phase 1: leaf documents that have no outgoing external refs ---
    component_a = OFFLINE / "component-a.spdx.json"
    write_document(make_document("https://example.org/spdx/component-a", "component-a"), component_a)

    component_b = OFFLINE / "component-b.spdx.json"
    write_document(make_document("https://example.org/spdx/component-b", "component-b"), component_b)

    mirror_a = OFFLINE / "mirror" / "component-a.spdx.json"
    mirror_a.parent.mkdir(parents=True, exist_ok=True)
    # Byte-identical copy: two aliases (different paths) must converge on one node.
    mirror_a.write_bytes(component_a.read_bytes())

    # Same basename as component-a but *different bytes* -> name collision case.
    other_a = OFFLINE / "other-vendor" / "component-a.spdx.json"
    write_document(make_document("https://other-vendor.example/component-a", "other-component-a"), other_a)

    # Tampered target: capture the good digest, then overwrite with new bytes.
    tampered = OFFLINE / "tampered-lib.spdx.json"
    write_document(make_document("https://example.org/spdx/tampered-lib", "tampered-lib"), tampered)
    tampered_original_sha1 = hash_file(tampered, ChecksumAlgorithm.SHA1)
    write_document(
        make_document("https://example.org/spdx/tampered-lib", "tampered-lib-replaced"), tampered
    )
    assert hash_file(tampered, ChecksumAlgorithm.SHA1) != tampered_original_sha1

    # Renamed original: digest still discoverable despite a different filename.
    renamed = OFFLINE / "renamed" / "lib-moved.spdx.json"
    write_document(make_document("https://example.org/spdx/renamed-lib", "renamed-lib"), renamed)

    # --- Phase 2: chain document references component-b ---
    dep_chain = OFFLINE / "dep-chain.spdx.json"
    chain_doc = make_document(
        "https://example.org/spdx/dep-chain",
        "dep-chain",
        external_refs=[
            external_ref(
                "DocumentRef-libbeta",
                "component-b.spdx.json",
                component_b,
                ChecksumAlgorithm.SHA1,
            )
        ],
    )
    write_document(chain_doc, dep_chain)

    # Capture digests for the missing-file edge before "losing" the file.
    missing_target = OFFLINE / "gone-lib.spdx.json"
    write_document(make_document("https://example.org/spdx/gone-lib", "gone-lib"), missing_target)
    gone_sha1 = hash_file(missing_target, ChecksumAlgorithm.SHA1)
    missing_target.unlink()

    # Tag-Value external document refs only carry SHA1 in this tool version, so
    # every external ref uses SHA1 to keep the JSON and Tag-Value edge sets identical.
    from spdx_tools.spdx.model import Checksum, ExternalDocumentRef  # noqa: E402

    root_refs = [
        # Same original, two aliases -> converge on one content node.
        external_ref("DocumentRef-alpha", "component-a.spdx.json", component_a, ChecksumAlgorithm.SHA1),
        external_ref("DocumentRef-alpha-alias", "mirror/component-a.spdx.json", mirror_a,
                     ChecksumAlgorithm.SHA1),
        # Same basename exists twice; the claimed digest selects the right bytes.
        external_ref("DocumentRef-collision", "other-vendor/component-a.spdx.json", other_a,
                     ChecksumAlgorithm.SHA1),
        # Referenced path now holds wrong bytes: claim the pre-tamper digest.
        ExternalDocumentRef(
            document_ref_id="DocumentRef-gamma",
            document_uri="tampered-lib.spdx.json",
            checksum=Checksum(ChecksumAlgorithm.SHA1, tampered_original_sha1),
        ),
        # Recovered purely by digest under an unexpected filename.
        external_ref("DocumentRef-epsilon", "renamed/lib-expected.spdx.json", renamed,
                     ChecksumAlgorithm.SHA1),
        # Transitive edge source.
        external_ref("DocumentRef-chain", "dep-chain.spdx.json", dep_chain, ChecksumAlgorithm.SHA1),
    ]

    # File absent from the offline directory -> missing evidence.
    root_refs.insert(
        4,
        ExternalDocumentRef(
            document_ref_id="DocumentRef-delta",
            document_uri="gone-lib.spdx.json",
            checksum=Checksum(ChecksumAlgorithm.SHA1, gone_sha1),
        ),
    )
    # Network identifier that cannot be dereferenced offline.
    root_refs.append(
        ExternalDocumentRef(
            document_ref_id="DocumentRef-zeta",
            document_uri="https://upstream.example/spdx/remote-lib.spdx.json",
            checksum=Checksum(ChecksumAlgorithm.SHA1, "a" * 40),
        )
    )
    # Algorithm that the local runtime cannot compute -> unprovable edge.
    root_refs.append(
        ExternalDocumentRef(
            document_ref_id="DocumentRef-eta",
            document_uri="renamed/lib-moved.spdx.json",
            checksum=Checksum(ChecksumAlgorithm.MD4, "0" * 32),
        )
    )

    json_root = MANIFESTS / "root-manifest.spdx.json"
    tag_root = MANIFESTS / "root-manifest.spdx"

    # The Tag-Value parser in this tool release only round-trips SHA1 external
    # document refs, so the Tag-Value manifest carries the SHA1 subset while JSON
    # keeps every edge including the locally-uncomputable MD4 one.
    tag_refs = [ref for ref in root_refs if ref.checksum.algorithm == ChecksumAlgorithm.SHA1]
    for path, refs in ((json_root, root_refs), (tag_root, tag_refs)):
        document = make_document(
            "https://example.org/spdx/incident-root",
            "incident-root-manifest",
            external_refs=refs,
        )
        write_document(document, path)
        write_sidecar(path)

    print(f"fixtures written under {FIX}")


if __name__ == "__main__":
    main()
