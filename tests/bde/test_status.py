from __future__ import annotations

import json
from typing import BinaryIO

from dissect.fve.bde import bde


def test_status_suspended(bde_suspended: BinaryIO) -> None:
    """Ciphertext remains, yet the clear key opens it without a secret."""
    bde_obj = bde.BDE(bde_suspended)
    assert not bde_obj.unlocked

    status = bde_obj.status()

    assert status.metadata.current == "encrypted"
    assert status.metadata.next == "encrypted"
    assert status.ciphertext.declared == "present"
    assert status.ciphertext.conclusion == "present"
    assert status.access.openable is True
    assert status.access.without_external_credentials is True
    assert status.access.requires_credential is False
    assert status.access.readable is True
    assert status.conversion.phase == "none"
    assert status.sector_map.encrypted_sectors > 0
    assert status.sector_map.plaintext_sectors == 0
    assert status.state == "suspended"

    # Building a status report must not unlock the original object.
    assert not bde_obj.unlocked

    display = status.to_dict()["display"]
    assert display["still_ciphertext"] is True
    assert display["openable_now"] is True
    assert display["openable_without_credentials"] is True


def test_status_paused_partial(bde_win7_partial: BinaryIO) -> None:
    """PAUSED to DECRYPTED: one part is still ciphertext, one part plaintext."""
    bde_obj = bde.BDE(bde_win7_partial)
    status = bde_obj.status()

    assert status.metadata.current == "paused"
    assert status.metadata.next == "decrypted"
    assert status.conversion.paused is True
    assert status.conversion.active is False
    assert status.conversion.direction == "decrypting"
    assert status.conversion.watermark_source == "state_offset"
    assert status.conversion.watermark_sector == bde_obj.information.state_offset // bde_obj.sector_size

    assert status.sector_map.partial is True
    assert status.sector_map.encrypted_sectors > 0
    assert status.sector_map.plaintext_sectors > 0
    assert status.ciphertext.declared == "partial"
    assert status.ciphertext.conclusion == "partial"

    assert status.access.openable is True
    assert status.access.without_external_credentials is True
    assert status.state == "paused"


def test_status_eow_partial_locked(bde_eow_partial: BinaryIO) -> None:
    """Metadata says ENCRYPTED, but the EOW bitmap has both states; no credential is supplied."""
    bde_obj = bde.BDE(bde_eow_partial)
    status = bde_obj.status()

    assert status.metadata.current == "encrypted"
    assert status.metadata.next == "encrypted"

    assert bde_obj.eow_information is not None
    assert status.sector_map.partial is True
    assert status.sector_map.encrypted_sectors > 0
    assert status.sector_map.plaintext_sectors > 0
    assert status.ciphertext.declared == "partial"
    assert status.ciphertext.observed is None  # no key available
    assert status.ciphertext.conclusion == "partial"
    assert status.ciphertext.confirmed is False
    assert status.conversion.phase == "layout_partial"

    # A missing credential must not be reported as "unreadable".
    assert status.access.openable is None
    assert status.access.readable is None
    assert status.access.requires_credential is True
    assert status.access.without_external_credentials is False
    assert status.state == "partially_encrypted_credential_required"

    # Unlocking with the passphrase must change the observed evidence, not the layout.
    bde_obj.unlock_with_passphrase("password12!@")
    unlocked = bde_obj.status()
    assert unlocked.state == "partially_encrypted_openable"
    assert unlocked.sector_map.partial is True
    assert unlocked.ciphertext.observed == "partial"
    assert unlocked.ciphertext.confirmed is True
    assert unlocked.access.readable is True


def test_status_decrypted(bde_decrypted: BinaryIO) -> None:
    """A fully decrypted volume has no ciphertext and needs no credential."""
    bde_obj = bde.BDE(bde_decrypted)
    status = bde_obj.status()

    assert status.metadata.current == "decrypted"
    assert status.metadata.next == "decrypted"
    assert status.sector_map.encrypted_sectors == 0
    assert status.sector_map.plaintext_sectors > 0
    assert status.ciphertext.declared == "none"
    assert status.ciphertext.conclusion == "none"
    assert status.access.openable is True
    assert status.access.without_external_credentials is True
    assert status.access.requires_credential is False
    assert status.conversion.phase == "none"
    assert status.state == "decrypted"


def test_status_without_verification(bde_suspended: BinaryIO) -> None:
    """``verify=False`` still classifies from metadata and layout, but reports no observation."""
    bde_obj = bde.BDE(bde_suspended)
    status = bde_obj.status(verify=False)

    assert status.sector_map.evidence is None
    assert status.ciphertext.observed is None
    assert status.ciphertext.declared == "present"
    assert status.access.without_external_credentials is True
    assert status.state == "suspended"


def test_status_unknown_protector_does_not_claim_unreadable(bde_aes_128: BinaryIO) -> None:
    """A passphrase-only volume without a supplied passphrase is unknown, not proven unreadable."""
    bde_obj = bde.BDE(bde_aes_128)
    status = bde_obj.status()

    assert status.metadata.current == "encrypted"
    assert status.ciphertext.conclusion == "present"
    assert status.access.openable is None
    assert status.access.readable is None
    assert status.access.requires_credential is True
    assert status.state == "encrypted_credential_required"

    bde_obj.unlock_with_passphrase("password12!@")
    unlocked = bde_obj.status()
    assert unlocked.access.openable is True
    assert unlocked.access.readable is True
    assert unlocked.ciphertext.confirmed is True


def test_status_is_json_serialisable(bde_suspended: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_suspended)
    result = bde_obj.status().to_dict()

    json.dumps(result)
    assert result["ciphertext"]["conclusion"] == "present"
    assert result["access"]["without_external_credentials"] is True
    assert result["display"]["state"] == "suspended"
    assert result["metadata"]["current"] == "encrypted"
    assert any("clear" in line.lower() for line in result["explanation"])


def test_status_explain_separates_metadata_and_observation(bde_win7_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_win7_partial)
    status = bde_obj.status()
    explanation = status.explain()

    assert any(line.startswith("Metadata reports") for line in explanation)
    assert any(line.startswith("Ciphertext declared") for line in explanation)
    assert any(line.startswith("Ciphertext observed") for line in explanation)
    assert any("These facts are compatible" in line for line in explanation)


def test_status_layout_runs_available_when_locked(bde_aes_128: BinaryIO) -> None:
    """The layout can be inspected without a key; it is metadata, not proof."""
    bde_obj = bde.BDE(bde_aes_128)
    assert not bde_obj.unlocked

    stream = bde_obj.open_layout()
    assert stream.encrypted is True
    assert stream.cipher is None

    runs = list(bde_obj.iter_runs(0, bde_obj.information.state_offset))
    assert runs
    assert all(run_type in (stream.RUN_ENCRYPTED, stream.RUN_SPARSE, stream.RUN_PLAIN) for run_type, _, _ in runs)
    assert sum(count for _, _, count in runs) == bde_obj.information.state_offset // bde_obj.sector_size

    # The run map is metadata: reading it did not unlock the volume or create a cipher.
    assert not bde_obj.unlocked
    assert stream.cipher is None


def test_status_tpm_only_is_not_credential_required(bde_suspended: BinaryIO) -> None:
    """A TPM-only volume is machine-bound, not proof that a user secret is required."""
    from dissect.fve.bde import status as status_module

    bde_obj = bde.BDE(bde_suspended)
    protectors = (status_module.Protector(identifier="tpm", priority=0x100, kinds=("TPM",), machine_bound=True),)

    access = status_module._access(bde_obj, protectors, None, None)

    assert access.requires_credential is False
    assert access.without_external_credentials is None
    assert access.openable is None
    assert access.readable is None
