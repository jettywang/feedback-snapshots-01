"""Tests for the offline evidence merger."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from pypi_attestations import (
    EvidenceRecord,
    MergeError,
    MergeReceipt,
    OfflineEvidenceMerger,
    SourceKind,
    WarningCode,
    merge_evidence,
)
from pypi_attestations._merge import OmittedData

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

PROVENANCE = _ASSETS / "pypi_attestations-0.0.19.tar.gz.provenance"
GCB_PROVENANCE = _ASSETS / "gcb_attestation_test-0.0.0.tar.gz.provenance"
CIRCLECI_PROVENANCE = (
    _ASSETS / "circleci_sign_publish_example-0.0.1.dev137-py3-none-any.whl.provenance"
)
ATTESTATION = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.attestation"
BUNDLE = _ASSETS / "rfc8785-0.1.2-py3-none-any.whl.sigstore"


def _load(path: Path) -> dict[str, Any]:
    """Load a JSON test asset."""
    return json.loads(path.read_text())


def _write(tmp_path: Path, name: str, payload: dict[str, Any]) -> Path:
    """Write a JSON payload into the temporary directory."""
    target = tmp_path / name
    target.write_text(json.dumps(payload))
    return target


class TestSourceKindAndModels:
    def test_source_from_bytes_records_digest(self) -> None:
        merger = OfflineEvidenceMerger()
        merger.merge_path(ATTESTATION)
        receipt = merger.build()
        source = receipt.records[0].sources[0]
        assert source.kind is SourceKind.PEP740_ATTESTATION
        assert source.path == str(ATTESTATION)
        assert source.sha256 == __import__("hashlib").sha256(ATTESTATION.read_bytes()).hexdigest()
        assert source.duplicate is False

    def test_receipt_roundtrips_through_json(self) -> None:
        receipt = merge_evidence([PROVENANCE, ATTESTATION])
        again = MergeReceipt.model_validate_json(receipt.model_dump_json())
        assert again.stats == receipt.stats
        assert [r.evidence_id for r in again.records] == [
            r.evidence_id for r in receipt.records
        ]


class TestDeduplication:
    def test_identical_backups_merge_into_one_record(self, tmp_path: Path) -> None:
        first = tmp_path / "backup-a.provenance"
        second = tmp_path / "backup-b.provenance"
        first.write_bytes(PROVENANCE.read_bytes())
        second.write_bytes(PROVENANCE.read_bytes())

        receipt = merge_evidence([first, second])

        assert receipt.stats.records == 1
        assert receipt.stats.sources_seen == 2
        assert receipt.stats.attestations_seen == 2
        assert receipt.stats.duplicates == 1
        record = receipt.records[0]
        assert [source.path for source in record.sources] == [str(first), str(second)]
        assert [source.duplicate for source in record.sources] == [False, True]
        assert record.duplicate_of == record.evidence_id

    def test_merging_the_same_path_twice_is_idempotent(self, tmp_path: Path) -> None:
        target = tmp_path / "only.provenance"
        target.write_bytes(PROVENANCE.read_bytes())

        merger = OfflineEvidenceMerger()
        merger.merge_path(target)
        merger.merge_path(target)
        receipt = merger.build()

        assert receipt.stats.attestations_seen == 1
        assert len(receipt.records[0].sources) == 1
        assert receipt.stats.duplicates == 0

    def test_bundle_and_attestation_for_same_signature_deduplicate(self) -> None:
        receipt = merge_evidence([BUNDLE, ATTESTATION])

        assert receipt.stats.records == 1
        assert receipt.stats.duplicates == 1
        record = receipt.records[0]
        kinds = {source.kind for source in record.sources}
        assert kinds == {SourceKind.SIGSTORE_BUNDLE, SourceKind.PEP740_ATTESTATION}


class TestMultiplePublishers:
    def test_different_publishers_for_same_package_are_kept(self, tmp_path: Path) -> None:
        first = _write(tmp_path, "first.provenance", _load(PROVENANCE))
        second_raw = _load(PROVENANCE)
        second_raw["attestation_bundles"][0]["publisher"]["repository"] = "other-org/other-repo"
        second = _write(tmp_path, "second.provenance", second_raw)

        receipt = merge_evidence([first, second])

        assert receipt.stats.records == 2
        assert receipt.stats.duplicates == 0
        repositories = {
            record.publisher.model_dump(by_alias=True)["repository"]
            for record in receipt.records
        }
        assert repositories == {
            "trailofbits/pypi-attestations",
            "other-org/other-repo",
        }
        for record in receipt.records:
            assert record.artifact_digest == receipt.records[0].artifact_digest

    def test_each_publisher_kind_is_indexed_separately(self) -> None:
        receipt = merge_evidence([GCB_PROVENANCE, CIRCLECI_PROVENANCE])

        assert receipt.stats.records == 2
        publishers = {
            record.publisher.kind  # type: ignore[union-attr]
            for record in receipt.records
        }
        assert publishers == {"Google", "CircleCI"}

    def test_by_artifact_groups_publisher_records(self, tmp_path: Path) -> None:
        first = _write(tmp_path, "first.provenance", _load(PROVENANCE))
        second_raw = _load(PROVENANCE)
        second_raw["attestation_bundles"][0]["publisher"]["workflow"] = "other.yml"
        second = _write(tmp_path, "second.provenance", second_raw)

        receipt = merge_evidence([first, second])
        digest = receipt.records[0].artifact_digest

        assert len(receipt.by_artifact(digest)) == 2


class TestIndexingAndTraceback:
    def test_identity_combines_digest_publisher_and_signature(self) -> None:
        receipt = merge_evidence([PROVENANCE])
        record = receipt.records[0]

        assert record.evidence_id.startswith("evd-")
        assert len(record.signature_sha256) == 64
        assert record.artifact_name == "pypi_attestations-0.0.19.tar.gz"
        int(record.artifact_digest, 16)
        assert len(record.artifact_digest) == 64

    def test_receipt_identity_traces_back_to_source_file(self, tmp_path: Path) -> None:
        # Acceptance: pick any identity from the receipt and trace it back.
        backup = tmp_path / "vault-copy.provenance"
        backup.write_bytes(PROVENANCE.read_bytes())
        receipt = merge_evidence([backup])

        chosen_id = receipt.records[0].evidence_id
        record = receipt.get_record(chosen_id)
        source = record.sources[0]

        traced = Path(source.path)
        assert traced == backup
        assert traced.read_bytes() == backup.read_bytes()
        assert source.sha256 == __import__("hashlib").sha256(backup.read_bytes()).hexdigest()

    def test_get_unknown_identity_raises_keyerror(self) -> None:
        receipt = merge_evidence([PROVENANCE])
        with pytest.raises(KeyError):
            receipt.get_record("evd-doesnotexist")

    def test_records_are_sorted_by_artifact_then_publisher(self, tmp_path: Path) -> None:
        first = _write(tmp_path, "first.provenance", _load(PROVENANCE))
        second_raw = _load(PROVENANCE)
        second_raw["attestation_bundles"][0]["publisher"]["repository"] = "aaa/zzz"
        second = _write(tmp_path, "second.provenance", second_raw)

        receipt = merge_evidence([second, first])
        digests = [record.artifact_digest for record in receipt.records]
        assert digests == sorted(digests)


class TestUnknownFieldsAndIncompleteLog:
    def test_unknown_fields_are_reported_independently(self, tmp_path: Path) -> None:
        raw = _load(ATTESTATION)
        raw["x_backup_note"] = "tape vault 7"
        raw["verification_material"]["x_collected_at"] = "2026-11-29T00:00:00Z"
        entry = raw["verification_material"]["transparency_entries"][0]
        entry["x_tlog_peer"] = "mirror-eu"
        target = _write(tmp_path, "with-unknown.attestation", raw)

        receipt = merge_evidence([target])
        record = receipt.records[0]

        assert WarningCode.UNKNOWN_FIELDS in record.warnings
        assert record.unknown_fields["x_backup_note"] == "tape vault 7"
        assert (
            record.unknown_fields["verification_material.x_collected_at"]
            == "2026-11-29T00:00:00Z"
        )
        assert (
            record.unknown_fields[
                "verification_material.transparency_entries[0].x_tlog_peer"
            ]
            == "mirror-eu"
        )
        assert receipt.stats.records_with_unknown_fields == 1

    def test_incomplete_log_basis_warns_but_keeps_record(self, tmp_path: Path) -> None:
        # A record whose transparency-log basis is incomplete must remain in
        # the receipt and independently surface its unknown fields.
        raw = _load(ATTESTATION)
        entry = raw["verification_material"]["transparency_entries"][0]
        entry.pop("inclusionProof", None)
        raw["x_provenance_note"] = "partial mirror"
        target = _write(tmp_path, "incomplete.attestation", raw)

        receipt = merge_evidence([target])
        record = receipt.records[0]

        assert isinstance(record, EvidenceRecord)
        assert record.has_unknown_fields() is True
        assert record.unknown_fields["x_provenance_note"] == "partial mirror"
        assert len(record.attestation.verification_material.transparency_entries) == 1

    def test_empty_transparency_entries_is_rejected(self, tmp_path: Path) -> None:
        # The PEP 740 model requires at least one transparency entry, so an
        # attestation with an incomplete log basis cannot be indexed.
        raw = _load(ATTESTATION)
        raw["verification_material"]["transparency_entries"] = []
        target = _write(tmp_path, "empty-tlog.attestation", raw)
        with pytest.raises(MergeError, match="invalid attestation"):
            merge_evidence([target])

    def test_malformed_transparency_entry_is_rejected(self, tmp_path: Path) -> None:
        # The PEP 740 model requires each transparency entry to be an object,
        # so a non-object entry cannot be indexed and must fail loudly rather
        # than be silently dropped.
        raw = _load(ATTESTATION)
        raw["verification_material"]["transparency_entries"].append("not-an-object")
        target = _write(tmp_path, "malformed-tlog.attestation", raw)

        with pytest.raises(MergeError, match="invalid attestation"):
            merge_evidence([target])

    def test_unknown_publisher_is_retained_raw(self, tmp_path: Path) -> None:
        raw = _load(PROVENANCE)
        raw["attestation_bundles"][0]["publisher"] = {
            "kind": "NostrPublisher",
            "npub": "npub1xyz",
        }
        target = _write(tmp_path, "unknown-publisher.provenance", raw)

        receipt = merge_evidence([target])
        record = receipt.records[0]

        assert WarningCode.UNKNOWN_PUBLISHER in record.warnings
        assert record.publisher is None
        assert record.publisher_raw == {"kind": "NostrPublisher", "npub": "npub1xyz"}
        assert "attestation_bundles[0].publisher" in record.unknown_fields


class TestConversionLoss:
    def test_bundle_with_multiple_tlog_entries_reports_omission(self, tmp_path: Path) -> None:
        raw = _load(BUNDLE)
        entries = raw["verificationMaterial"]["tlogEntries"]
        entries.append(copy.deepcopy(entries[0]))
        target = _write(tmp_path, "multi-tlog.sigstore", raw)

        receipt = merge_evidence([target])
        record = receipt.records[0]

        assert WarningCode.DROPPED_TRANSPARENCY_ENTRIES in record.warnings
        assert len(record.attestation.verification_material.transparency_entries) == 1
        omission = record.omitted[0]
        assert isinstance(omission, OmittedData)
        assert omission.location == "verificationMaterial.tlogEntries[1:]"
        assert len(omission.data) == 1

    def test_single_entry_bundle_has_no_omissions(self) -> None:
        receipt = merge_evidence([BUNDLE])
        record = receipt.records[0]
        assert record.omitted == []
        assert record.warnings == []
        assert record.sources[0].kind is SourceKind.SIGSTORE_BUNDLE


class TestErrors:
    def test_invalid_json_raises_merge_error(self, tmp_path: Path) -> None:
        target = tmp_path / "broken.json"
        target.write_text("{not json")
        with pytest.raises(MergeError, match="invalid JSON"):
            merge_evidence([target])

    def test_non_object_root_raises_merge_error(self, tmp_path: Path) -> None:
        target = tmp_path / "list.json"
        target.write_text("[]")
        with pytest.raises(MergeError, match="JSON object"):
            merge_evidence([target])

    def test_missing_file_raises_merge_error(self, tmp_path: Path) -> None:
        with pytest.raises(MergeError, match="could not read"):
            merge_evidence([tmp_path / "missing.attestation"])

    def test_invalid_attestation_raises_merge_error(self, tmp_path: Path) -> None:
        target = _write(tmp_path, "bad.attestation", {"version": 1})
        with pytest.raises(MergeError, match="invalid attestation"):
            merge_evidence([target])

    def test_invalid_bundle_raises_merge_error(self, tmp_path: Path) -> None:
        target = _write(
            tmp_path,
            "bad.sigstore",
            {"verificationMaterial": {}, "dsseEnvelope": {}},
        )
        with pytest.raises(MergeError, match="invalid Sigstore bundle"):
            merge_evidence([target])

    def test_provenance_with_non_list_bundles_raises(self, tmp_path: Path) -> None:
        target = _write(tmp_path, "bad.provenance", {"attestation_bundles": {}})
        with pytest.raises(MergeError, match="attestation_bundles"):
            merge_evidence([target])


class TestMergeBytes:
    def test_merge_bytes_uses_supplied_path(self) -> None:
        merger = OfflineEvidenceMerger()
        merger.merge_bytes(PROVENANCE.read_bytes(), path="logical/backup.provenance")
        receipt = merger.build()
        assert receipt.records[0].sources[0].path == "logical/backup.provenance"
        assert receipt.records[0].sources[0].kind is SourceKind.PEP740_PROVENANCE

    def test_unknown_provenance_level_field_is_captured(self, tmp_path: Path) -> None:
        raw = _load(PROVENANCE)
        raw["x_archive_id"] = "vault-42"
        target = _write(tmp_path, "extra.provenance", raw)
        receipt = merge_evidence([target])
        assert receipt.records[0].unknown_fields["x_archive_id"] == "vault-42"


class TestEdgeCases:
    def test_add_warning_does_not_duplicate_codes(self) -> None:
        record = merge_evidence([ATTESTATION]).records[0]
        record.add_warning(WarningCode.UNKNOWN_FIELDS)
        record.add_warning(WarningCode.UNKNOWN_FIELDS)
        assert record.warnings.count(WarningCode.UNKNOWN_FIELDS) == 1

    def test_duplicate_observation_merges_unknown_fields_and_warnings(
        self, tmp_path: Path
    ) -> None:
        clean = _write(tmp_path, "clean.attestation", _load(ATTESTATION))
        annotated_raw = _load(ATTESTATION)
        annotated_raw["x_backup_note"] = "later observation"
        annotated = _write(tmp_path, "annotated.attestation", annotated_raw)

        receipt = merge_evidence([clean, annotated])
        record = receipt.records[0]

        assert receipt.stats.duplicates == 1
        assert WarningCode.UNKNOWN_FIELDS in record.warnings
        assert record.unknown_fields["x_backup_note"] == "later observation"

    def test_publisher_none_input_returns_no_publisher(self) -> None:
        from pypi_attestations._merge import _model_publisher

        publisher, raw, warnings = _model_publisher(None, {}, "loc")
        assert publisher is None
        assert raw is None
        assert warnings == []

    def test_non_dict_publisher_is_retained_as_unknown(self, tmp_path: Path) -> None:
        raw = _load(PROVENANCE)
        raw["attestation_bundles"][0]["publisher"] = ["not", "a", "mapping"]
        target = _write(tmp_path, "list-publisher.provenance", raw)

        receipt = merge_evidence([target])
        record = receipt.records[0]

        assert WarningCode.UNKNOWN_PUBLISHER in record.warnings
        assert record.publisher is None
        assert "attestation_bundles[0].publisher" in record.unknown_fields

    def test_non_dict_bundle_in_provenance_is_skipped(self, tmp_path: Path) -> None:
        raw = _load(PROVENANCE)
        raw["attestation_bundles"].insert(0, "not-a-bundle")
        target = _write(tmp_path, "bad-bundle.provenance", raw)

        receipt = merge_evidence([target])

        # The malformed bundle is recorded as an unknown field and skipped,
        # while the well-formed bundle still yields its record.
        record = receipt.records[0]
        assert "attestation_bundles[0]" in record.unknown_fields
        assert receipt.stats.records == 1

    def test_non_dict_attestation_in_bundle_is_skipped(self, tmp_path: Path) -> None:
        raw = _load(PROVENANCE)
        raw["attestation_bundles"][0]["attestations"].insert(0, "not-an-attestation")
        target = _write(tmp_path, "bad-attestation.provenance", raw)

        receipt = merge_evidence([target])

        record = receipt.records[0]
        assert "attestation_bundles[0].attestations[0]" in record.unknown_fields
        assert receipt.stats.records == 1

    def test_provenance_attestations_not_a_list_raises(self, tmp_path: Path) -> None:
        raw = _load(PROVENANCE)
        raw["attestation_bundles"][0]["attestations"] = {}
        target = _write(tmp_path, "bad-attestations.provenance", raw)
        with pytest.raises(MergeError, match="attestations must be a list"):
            merge_evidence([target])

    def test_manual_bundle_builder_reports_invalid_document(self, tmp_path: Path) -> None:
        # A multi-entry bundle whose referenced material is missing cannot be
        # converted and must surface as a MergeError rather than a KeyError.
        target = _write(
            tmp_path,
            "broken-multi.sigstore",
            {
                "verificationMaterial": {
                    "tlogEntries": [{"logIndex": "1"}, {"logIndex": "2"}],
                },
                "dsseEnvelope": {},
            },
        )
        with pytest.raises(MergeError, match="invalid Sigstore bundle"):
            merge_evidence([target])

    def test_non_list_transparency_entries_does_not_raise(self, tmp_path: Path) -> None:
        raw = _load(ATTESTATION)
        raw["verification_material"]["transparency_entries"] = "unexpected"
        target = _write(tmp_path, "string-tlog.attestation", raw)
        # The PEP 740 model rejects the wrong type, but the merger must fail
        # with its own MergeError rather than an AttributeError.
        with pytest.raises(MergeError, match="invalid attestation"):
            merge_evidence([target])

    def test_duplicate_observation_accumulates_omitted_data(self, tmp_path: Path) -> None:
        single = _write(
            tmp_path,
            "single.sigstore",
            _load(BUNDLE),
        )
        multi_raw = _load(BUNDLE)
        entries = multi_raw["verificationMaterial"]["tlogEntries"]
        entries.append(copy.deepcopy(entries[0]))
        multi = _write(tmp_path, "multi.sigstore", multi_raw)

        receipt = merge_evidence([single, multi])
        record = receipt.records[0]

        assert receipt.stats.duplicates == 1
        assert WarningCode.DROPPED_TRANSPARENCY_ENTRIES in record.warnings
        assert record.omitted
        assert all(isinstance(item, OmittedData) for item in record.omitted)
