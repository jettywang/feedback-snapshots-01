from __future__ import annotations

from typing import BinaryIO

from dissect.fve.bde.bde import BDE
from dissect.fve.bde.c_bde import FVE_STATE
from dissect.fve.bde.status import (
    AccessLevel,
    ConversionPhase,
    SectorDisposition,
    assess_volume,
    iter_status_records,
    observe_sectors,
    read_metadata_status,
)

RECOVERY_PARTIAL = "131450-120197-153989-250338-511368-495572-680944-381546"


def test_suspended_is_ciphertext_but_openable_without_credential(bde_suspended: BinaryIO) -> None:
    """Suspended volumes keep ciphertext on disk yet expose a clear-key protector.

    This is the combination a naive UI mislabels as "unencrypted": the bytes are ciphertext, but no
    external secret is required to recover the FVEK.
    """
    bde = BDE(bde_suspended)
    status = assess_volume(bde)

    # Metadata still claims a steady encrypted volume; it is not a decrypted volume.
    assert status.metadata.current_state == FVE_STATE.ENCRYPTED.name
    assert status.metadata.conversion_phase == ConversionPhase.ENCRYPTED_STEADY
    assert status.metadata.has_clear_key is True
    assert status.metadata.has_secret_protector is False

    # Access is possible without any user-supplied credential.
    assert status.access.level == AccessLevel.OPEN_WITHOUT_CREDENTIAL
    assert status.access.openable_without_external_credential is True
    assert status.access.unlock_path == "clear_key"

    # Even while locked, the high-entropy virtualized header sector proves ciphertext on disk.
    assert status.evidence.ciphertext_confirmed is True
    assert status.evidence.plaintext_confirmed is False
    assert status.evidence.decrypted_view_available is False

    header = next(o for o in status.evidence.observations if o.logical_sector == 0)
    assert header.disposition == SectorDisposition.ENCRYPTED
    assert header.raw_equals_decrypted_view is None


def test_suspended_clear_key_upgrades_evidence_to_key_dependent(bde_suspended: BinaryIO) -> None:
    bde = BDE(bde_suspended)
    bde.unlock_with_clear_key()
    status = assess_volume(bde)

    assert status.evidence.decrypted_view_available is True
    # With the FVEK available, raw zeros inside encrypted runs are demonstrably ciphertext-backed.
    assert status.evidence.unknown_sectors_observed == 0
    assert status.evidence.encrypted_sectors_observed >= 1
    for observation in status.evidence.observations:
        if observation.disposition == SectorDisposition.ENCRYPTED:
            assert observation.raw_equals_decrypted_view is False


def test_decrypted_volume_is_plaintext_and_has_no_fvek(bde_decrypted: BinaryIO) -> None:
    bde = BDE(bde_decrypted)
    status = assess_volume(bde)

    assert status.metadata.current_state == FVE_STATE.DECRYPTED.name
    assert status.metadata.conversion_phase == ConversionPhase.DECRYPTED_STEADY
    assert status.metadata.fvek_type == "NONE"
    assert status.metadata.has_clear_key is False

    assert status.access.level == AccessLevel.OPEN_WITHOUT_CREDENTIAL
    assert status.access.unlock_path == "plaintext_volume"

    assert status.evidence.ciphertext_confirmed is False
    assert status.evidence.plaintext_confirmed is True
    ntfs = next(o for o in status.evidence.observations if o.plaintext_signature == "NTFS")
    assert ntfs.disposition == SectorDisposition.PLAINTEXT
    assert ntfs.raw_equals_decrypted_view is True


def test_paused_partial_volume_mixes_ciphertext_and_plaintext(bde_win7_partial: BinaryIO) -> None:
    bde = BDE(bde_win7_partial)
    status = assess_volume(bde)

    metadata = read_metadata_status(bde)
    assert metadata.current_state == FVE_STATE.PAUSED.name
    assert metadata.next_state == FVE_STATE.DECRYPTED.name
    assert metadata.conversion_phase == ConversionPhase.PAUSED
    # A paused volume can carry both a clear key and secret protectors at once.
    assert metadata.has_clear_key is True
    assert metadata.has_secret_protector is True

    assert status.access.level == AccessLevel.OPEN_WITHOUT_CREDENTIAL
    assert status.evidence.ciphertext_confirmed is True
    assert status.evidence.plaintext_confirmed is True

    # The StateOffset watermark is the boundary: below it encrypted, above it plaintext.
    boundary = metadata.state_offset_sector
    evidence = observe_sectors(bde, [0, boundary - 1, boundary, boundary + 1])
    by_sector = {o.logical_sector: o.disposition for o in evidence.observations}
    assert by_sector[0] == SectorDisposition.ENCRYPTED
    assert by_sector[boundary - 1] == SectorDisposition.ENCRYPTED
    assert by_sector[boundary] == SectorDisposition.PLAINTEXT
    assert by_sector[boundary + 1] == SectorDisposition.PLAINTEXT


def test_locked_eow_partial_needs_credential_but_plaintext_regions_still_readable(
    bde_eow_partial: BinaryIO,
) -> None:
    bde = BDE(bde_eow_partial)
    status = assess_volume(bde)

    # No clear key: encrypted regions genuinely require a secret.
    assert status.metadata.has_clear_key is False
    assert status.metadata.has_secret_protector is True
    assert status.access.level == AccessLevel.REQUIRES_EXTERNAL_CREDENTIAL
    assert status.access.openable_without_external_credential is False

    # But absence of a passphrase does not make the whole volume unreadable: plaintext EOW chunks
    # (including the NTFS header) are confirmed by direct reads.
    assert status.evidence.plaintext_confirmed is True
    assert any(o.plaintext_signature == "NTFS" for o in status.evidence.observations)


def test_missing_passphrase_is_reported_as_not_assessed_not_unreadable(bde_aes_128: BinaryIO) -> None:
    """Without credentials we must not invert the burden of proof into 'volume unreadable'."""
    bde = BDE(bde_aes_128)
    status = assess_volume(bde, sectors=[16])

    assert status.metadata.has_secret_protector is True
    assert status.access.level == AccessLevel.REQUIRES_EXTERNAL_CREDENTIAL
    # The locked classifier still locates the encrypted run rather than failing.
    assert status.evidence.observations[0].disposition in (
        SectorDisposition.ENCRYPTED,
        SectorDisposition.UNKNOWN,
    )


def test_status_serializes_and_emits_records(bde_suspended: BinaryIO) -> None:
    bde = BDE(bde_suspended)
    status = assess_volume(bde)

    payload = status.to_dict()
    assert set(payload) == {"summary", "metadata", "access", "observed_evidence"}
    assert payload["metadata"]["current_state"] == "ENCRYPTED"

    records = list(iter_status_records(status))
    assert len(records) == len(status.evidence.observations)
    assert all("current_state" in record and "disposition" in record for record in records)
