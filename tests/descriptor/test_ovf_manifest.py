from __future__ import annotations

import hashlib
from io import BytesIO, StringIO

import pytest

from dissect.hypervisor.descriptor.ovf import OVF
from dissect.hypervisor.descriptor.ovf_manifest import (
    ManifestStatus,
    OVFManifest,
    verify_ovf_manifest,
)
from dissect.hypervisor.exceptions import ManifestError

DISK_ONE = b"disk image one - almost identical content"
DISK_TWO = b"disk image two - almost identical content"
NVRAM_DATA = b"small nvram export payload"


def make_ovf(hrefs: dict[str, str]) -> OVF:
    files = "\n".join(f'    <File ovf:id="{file_id}" ovf:href="{href}"/>' for file_id, href in hrefs.items())
    xml = f"""<?xml version="1.0"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1">
  <References>
{files}
  </References>
  <DiskSection>
    <Info>Disks</Info>
  </DiskSection>
</Envelope>
"""
    return OVF(StringIO(xml))


def hexdigest(algorithm: str, data: bytes) -> str:
    return hashlib.new(algorithm, data).hexdigest()


def make_manifest(lines: list[tuple[str, str, bytes]], extra: list[str] | None = None) -> str:
    text = "\n".join(f"{algorithm.upper()} ({name}) = {digest.hex()}" for algorithm, name, digest in lines)
    if extra:
        text += "\n" + "\n".join(extra)
    return text + "\n"


def result_by_name(result: object) -> dict[str, object]:
    return {file_result.name: file_result for file_result in result.files}


def build_export() -> tuple[OVF, str, dict[str, BytesIO]]:
    # The NVRAM name contains spaces and parentheses and is percent-encoded in
    # the OVF href but stored verbatim in the manifest.
    ovf = make_ovf(
        {
            "file1": "disk1.vmdk",
            "file2": "disk2.vmdk",
            "file3": "nvram%20%281%29.nvram",
        }
    )
    manifest = make_manifest(
        [
            ("sha256", "disk1.vmdk", hashlib.sha256(DISK_ONE).digest()),
            ("sha256", "disk2.vmdk", hashlib.sha256(DISK_TWO).digest()),
            ("sha256", "nvram (1).nvram", hashlib.sha256(NVRAM_DATA).digest()),
        ],
        extra=[f"SHA256 (export.ovf) = {hexdigest('sha256', b'ovf descriptor')}"],
    )
    candidates = {
        "disk1.vmdk": BytesIO(DISK_ONE),
        "disk2.vmdk": BytesIO(DISK_TWO),
        "nvram (1).nvram": BytesIO(NVRAM_DATA),
    }
    return ovf, manifest, candidates


def test_verify_manifest_links_similar_disks_and_encoded_name() -> None:
    ovf, manifest, candidates = build_export()

    result = verify_ovf_manifest(ovf, manifest, candidates)

    assert result.verified is True
    assert bool(result) is True
    assert {file_result.name for file_result in result.files} == {
        "disk1.vmdk",
        "disk2.vmdk",
        "nvram (1).nvram",
    }
    assert all(file_result.status is ManifestStatus.VERIFIED for file_result in result.files)
    # The OVF self entry is present in the manifest but not referenced by the OVF.
    assert result.unreferenced_manifest_entries == ("export.ovf",)
    assert result.unreferenced_candidates == ()

    by_name = result_by_name(result)
    disk_one = by_name["disk1.vmdk"]
    assert disk_one.actual == disk_one.expected
    # Two similar disks must stay linked to their own digest, not each other's.
    assert by_name["disk1.vmdk"].expected != by_name["disk2.vmdk"].expected


def test_manifest_parsed_object_reuses_entries() -> None:
    ovf, manifest, candidates = build_export()
    parsed = OVFManifest(manifest)

    result = parsed.verify(ovf, candidates)

    assert result.verified is True
    assert len(parsed.entries["disk1.vmdk"]) == 1


def test_swapping_same_named_files_fails_entire_group() -> None:
    ovf, manifest, _ = build_export()
    swapped = {
        "disk1.vmdk": BytesIO(DISK_TWO),
        "disk2.vmdk": BytesIO(DISK_ONE),
        "nvram (1).nvram": BytesIO(NVRAM_DATA),
    }

    result = verify_ovf_manifest(ovf, manifest, swapped)

    assert result.verified is False
    by_name = result_by_name(result)
    assert by_name["disk1.vmdk"].status is ManifestStatus.DIGEST_MISMATCH
    assert by_name["disk2.vmdk"].status is ManifestStatus.DIGEST_MISMATCH
    assert by_name["nvram (1).nvram"].status is ManifestStatus.VERIFIED


def test_conflicting_duplicate_manifest_entries_fail() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    manifest = make_manifest(
        [
            ("sha256", "disk1.vmdk", hashlib.sha256(DISK_ONE).digest()),
            ("sha256", "disk1.vmdk", hashlib.sha256(b"tampered").digest()),
        ]
    )

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is False
    assert result.files[0].status is ManifestStatus.CONFLICTING_ENTRIES
    assert "sha256" in result.files[0].detail


def test_identical_duplicate_manifest_entries_verify() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    digest = hashlib.sha256(DISK_ONE).digest()
    manifest = make_manifest(
        [
            ("sha256", "disk1.vmdk", digest),
            ("sha256", "disk1.vmdk", digest),
        ]
    )

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is True
    assert result.files[0].status is ManifestStatus.VERIFIED


def test_multiple_algorithms_must_all_match() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    manifest = make_manifest(
        [
            ("sha1", "disk1.vmdk", hashlib.sha1(DISK_ONE).digest()),
            ("sha256", "disk1.vmdk", hashlib.sha256(DISK_ONE).digest()),
        ]
    )

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is True
    assert {entry.algorithm for entry in result.files[0].expected} == {"sha1", "sha256"}


def test_missing_candidate_keeps_group_unverified() -> None:
    ovf, manifest, candidates = build_export()
    del candidates["disk2.vmdk"]

    result = verify_ovf_manifest(ovf, manifest, candidates)

    assert result.verified is False
    by_name = result_by_name(result)
    assert by_name["disk2.vmdk"].status is ManifestStatus.MISSING_CANDIDATE
    assert by_name["disk1.vmdk"].status is ManifestStatus.VERIFIED


def test_missing_manifest_entry_fails() -> None:
    ovf, manifest, candidates = build_export()
    lines = [
        line
        for line in manifest.splitlines()
        if "disk1.vmdk" not in line
    ]

    result = verify_ovf_manifest(ovf, "\n".join(lines) + "\n", candidates)

    assert result.verified is False
    assert result_by_name(result)["disk1.vmdk"].status is ManifestStatus.MISSING_FROM_MANIFEST


def test_unknown_algorithm_is_not_verified() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    manifest = make_manifest([("frobnicate512", "disk1.vmdk", b"\x00" * 16)])

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is False
    file_result = result.files[0]
    assert file_result.status is ManifestStatus.UNSUPPORTED_ALGORITHM
    assert "frobnicate512" in file_result.detail
    # Parsing the unknown algorithm must not raise; the entry stays recorded.
    assert OVFManifest(manifest).entries["disk1.vmdk"][0].algorithm == "frobnicate512"


def test_unknown_algorithm_with_mismatched_known_digest_reports_mismatch() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    manifest = make_manifest(
        [
            ("sha256", "disk1.vmdk", hashlib.sha256(b"other").digest()),
            ("frobnicate512", "disk1.vmdk", b"\x00" * 16),
        ]
    )

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is False
    assert result.files[0].status is ManifestStatus.DIGEST_MISMATCH


def test_encoded_href_without_encoded_candidate_key_is_not_auto_resolved() -> None:
    ovf = make_ovf({"file3": "nvram%20%281%29.nvram"})
    manifest = make_manifest([("sha256", "nvram (1).nvram", hashlib.sha256(NVRAM_DATA).digest())])
    # The caller supplies the percent-encoded name instead of the decoded one:
    # no host directory lookup may silently resolve it.
    candidates = {"nvram%20%281%29.nvram": BytesIO(NVRAM_DATA)}

    result = verify_ovf_manifest(ovf, manifest, candidates)

    assert result.verified is False
    assert result.files[0].status is ManifestStatus.MISSING_CANDIDATE
    assert result.unreferenced_candidates == ("nvram%20%281%29.nvram",)


def test_unreferenced_candidates_are_reported() -> None:
    ovf, manifest, candidates = build_export()
    candidates["extra.iso"] = BytesIO(b"bonus image")

    result = verify_ovf_manifest(ovf, manifest, candidates)

    assert result.verified is True
    assert result.unreferenced_candidates == ("extra.iso",)


def test_malformed_manifest_raises() -> None:
    with pytest.raises(ManifestError, match="Malformed manifest entry"):
        OVFManifest("SHA256 this is not a manifest line\n")


def test_empty_ovf_references_never_verify() -> None:
    ovf = make_ovf({})
    manifest = make_manifest([("sha256", "disk1.vmdk", hashlib.sha256(DISK_ONE).digest())])

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is False
    assert result.files == ()


def test_manifest_accepts_binary_stream_and_chunks_content() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    payload = b"x" * (3 * 1024 * 1024)
    manifest_fh = BytesIO(
        make_manifest([("sha256", "disk1.vmdk", hashlib.sha256(payload).digest())]).encode()
    )

    result = verify_ovf_manifest(ovf, OVFManifest(manifest_fh), {"disk1.vmdk": BytesIO(payload)})

    assert result.verified is True


def test_manifest_accepts_uppercase_algorithm_and_digest() -> None:
    ovf = make_ovf({"file1": "disk1.vmdk"})
    manifest = f"SHA256 (disk1.vmdk) = {hexdigest('sha256', DISK_ONE).upper()}\n"

    result = verify_ovf_manifest(ovf, manifest, {"disk1.vmdk": BytesIO(DISK_ONE)})

    assert result.verified is True
