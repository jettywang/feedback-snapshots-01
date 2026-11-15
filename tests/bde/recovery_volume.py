"""In-memory, deterministic BitLocker (BDE) volume builder for recovery-password tests.

The builder produces a minimal but fully valid BDE v2 information/dataset that the
public :class:`dissect.fve.bde.bde.BDE` parser accepts. It deliberately uses small,
fixed local material (no on-disk image) so individual layers of the
``unlock_with_recovery_password`` path can be broken one at a time.

The nested datum layout mirrors a real volume:

    VOLUME_MASTER_KEY_INFO (recovery protector)
        PROPERTY STRETCH_KEY          (salt for the recovery key stretching)
        PROPERTY AES_CCM_ENCRYPTED_KEY (wraps the VMK, authenticated with AES-CCM)
    FULL_VOLUME_ENCRYPTION_KEY
        AES_CCM_ENCRYPTED_KEY         (wraps the FVEK, authenticated with the VMK)
    VALIDATION
        AES_CCM_ENCRYPTED_KEY         (SHA-256 of the information buffer, keyed by VMK)
"""

from __future__ import annotations

import hashlib
import struct
from binascii import crc32
from io import BytesIO
from uuid import UUID

from Crypto.Cipher import AES

from dissect.fve.bde import c_bde
from dissect.fve.bde.c_bde import CIPHER_MAP
from dissect.fve.bde.key import derive_recovery_key, stretch
from dissect.fve.crypto import create_cipher

# Fixed, locally generated test material. This is a recovery password that passes every
# textual and group checksum rule; only the on-disk wrapping/datum material is mutated.
RECOVERY_PASSWORD = "284867-596541-514998-422114-660297-261613-215424-199408"

INFO_OFFSET = 0x2000
SECTOR_SIZE = 512
# A sector beyond the 128-sector information region, kept in the fully encrypted region.
DATA_SECTOR = 256
KNOWN_PLAINTEXT = b"KNOWN-PLAINTEXT!" + b"\x5a" * (SECTOR_SIZE - 16)

RECOVERY_IDENTIFIER = UUID("3c116b76-c67b-484e-b439-ce2ed68b561e")
SECOND_RECOVERY_IDENTIFIER = UUID("6dd54bcd-633d-4836-9ebc-44fa02f1776d")
UNKNOWN_IDENTIFIER = UUID("00000000-0000-0000-0000-000000000000")

# Distinct fixed salts/nonces so the two recovery protectors derive different stretch keys.
VMK_MATERIAL = (
    (RECOVERY_IDENTIFIER, b"\x01" * 16, b"\x11" * 12),
    (SECOND_RECOVERY_IDENTIFIER, b"\x02" * 16, b"\x12" * 12),
)
FVEK_NONCE = b"\x22" * 12
INTEGRITY_NONCE = b"\x33" * 12

# Deterministic, clearly non-secret key bytes used purely as known test material.
VMK_KEY = bytes(range(32))
FVEK_KEY = bytes(range(10, 42))
FVEK_TYPE = c_bde.FVE_KEY_TYPE.AES_XTS_128


def _datum(role: int, type_: int, payload: bytes, flags: int = 0) -> bytes:
    return struct.pack("<HHHH", 8 + len(payload), role, type_, flags) + payload


def _aes_ccm_seal(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=16)
    return cipher.encrypt_and_digest(plaintext)


def _key_datum(key_type: int, key_material: bytes) -> bytes:
    return _datum(
        c_bde.FVE_DATUM_ROLE.PROPERTY, c_bde.FVE_DATUM_TYPE.KEY, struct.pack("<HH", key_type, 0) + key_material
    )


def _recovery_vmk_datum(
    identifier: UUID,
    salt: bytes,
    nonce: bytes,
    *,
    corrupt_authentication: bool = False,
) -> tuple[bytes, bytes]:
    """Build one recovery VMK datum, returning (datum, derived_stretch_key)."""
    stretch_key = stretch(derive_recovery_key(RECOVERY_PASSWORD), salt)

    stretch_datum = _datum(
        c_bde.FVE_DATUM_ROLE.PROPERTY,
        c_bde.FVE_DATUM_TYPE.STRETCH_KEY,
        struct.pack("<HH", c_bde.FVE_KEY_TYPE.STRETCH_KEY, 0) + salt,
    )

    ciphertext, mac = _aes_ccm_seal(stretch_key, nonce, _key_datum(c_bde.FVE_KEY_TYPE.VMK, VMK_KEY))
    if corrupt_authentication:
        # Keep the recovery password text and key derivation valid; only break the AES-CCM
        # authentication tag that guards the wrapped VMK.
        mac = bytes([mac[0] ^ 0xFF]) + mac[1:]

    encrypted_datum = _datum(
        c_bde.FVE_DATUM_ROLE.PROPERTY,
        c_bde.FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY,
        nonce + mac + ciphertext,
    )

    info_payload = (
        identifier.bytes_le
        + struct.pack("<QHH", 0, 0, c_bde.FVE_KEY_PROTECTOR.RECOVERY_PASSWORD)
        + stretch_datum
        + encrypted_datum
    )
    vmk_datum = _datum(
        c_bde.FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO,
        c_bde.FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO,
        info_payload,
    )
    return vmk_datum, stretch_key


def build_volume(
    *,
    recovery_protectors: int = 1,
    corrupt_vmk_identifier: UUID | None = None,
    corrupt_fvek_datum: bool = False,
) -> tuple[BytesIO, dict[str, bytes | str]]:
    """Construct a minimal in-memory BDE v2 volume and its known secret material.

    The returned dictionary holds the known plaintext secrets so tests can assert none of them
    leak into logs or failure messages.

    Args:
        recovery_protectors: Number of recovery password VMKs to embed (1 or 2).
        corrupt_vmk_identifier: When set, corrupt this protector's wrapped-VMK AES-CCM tag so the
            named protector fails authentication while the recovery password and its derivation
            stay fully valid.
        corrupt_fvek_datum: When ``True``, mutate the FVEK ciphertext after correctly wrapping the
            VMK, so VMK authentication succeeds but unboxing the FVEK fails.
    """
    vmk_datums = []
    stretch_keys = []
    for identifier, salt, nonce in VMK_MATERIAL[:recovery_protectors]:
        datum, stretch_key = _recovery_vmk_datum(
            identifier,
            salt,
            nonce,
            corrupt_authentication=identifier == corrupt_vmk_identifier,
        )
        vmk_datums.append(datum)
        stretch_keys.append(stretch_key)

    fvek_ciphertext, fvek_mac = _aes_ccm_seal(VMK_KEY, FVEK_NONCE, _key_datum(FVEK_TYPE, FVEK_KEY))
    if corrupt_fvek_datum:
        # The VMK (and therefore its authentication) stays valid; only the inner FVEK key
        # datum becomes undecryptable/unauthentic.
        fvek_ciphertext = bytes([fvek_ciphertext[0] ^ 0xFF]) + fvek_ciphertext[1:]

    fvek_datum = _datum(
        c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        c_bde.FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY,
        FVEK_NONCE + fvek_mac + fvek_ciphertext,
    )

    datums = b"".join(vmk_datums) + fvek_datum
    start_offset = len(c_bde.c_bde.FVE_DATASET)
    end_offset = start_offset + len(datums)
    dataset = (
        struct.pack("<IIII", end_offset, 1, start_offset, end_offset)
        + b"\x00" * 16
        + struct.pack("<IHHQ", 0, FVEK_TYPE, 0, 0)
        + datums
    )

    information_body = b"-FVE-FS-" + struct.pack(
        "<HHHH", (64 + len(dataset)) >> 4, 2, c_bde.FVE_STATE.ENCRYPTED, c_bde.FVE_STATE.ENCRYPTED
    )
    # StateOffset 0 and no virtualized sectors keep the data sector in a plain encrypted run.
    information_body += struct.pack("<QII", 0, 0, 0)
    information_body += struct.pack("<QQQ", INFO_OFFSET, 0, 0)
    information_body += struct.pack("<Q", 0)
    information_buffer = information_body + dataset

    integrity_inner = _key_datum(c_bde.FVE_KEY_TYPE.HASH_256, hashlib.sha256(information_buffer).digest())
    integrity_ciphertext, integrity_mac = _aes_ccm_seal(VMK_KEY, INTEGRITY_NONCE, integrity_inner)
    integrity_datum = _datum(
        c_bde.FVE_DATUM_ROLE.PROPERTY,
        c_bde.FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY,
        INTEGRITY_NONCE + integrity_mac + integrity_ciphertext,
    )

    information_blob = information_buffer + struct.pack("<HHI", 8, 2, crc32(information_buffer)) + integrity_datum

    boot_sector = bytearray(SECTOR_SIZE)
    boot_sector[0:3] = b"\xeb\x52\x90"
    boot_sector[3:11] = b"-FVE-FS-"
    struct.pack_into("<H", boot_sector, 11, SECTOR_SIZE)
    boot_sector[13] = 8
    guid_offset = 0x100
    boot_sector[guid_offset : guid_offset + 16] = c_bde.INFORMATION_OFFSET_GUID.bytes_le
    struct.pack_into("<QQQ", boot_sector, guid_offset + 16, INFO_OFFSET, 0, 0)

    volume_size = (DATA_SECTOR + 1) * SECTOR_SIZE
    volume = BytesIO(bytes(boot_sector) + b"\x00" * (volume_size - SECTOR_SIZE))
    volume.seek(INFO_OFFSET)
    volume.write(information_blob)

    cipher = create_cipher(CIPHER_MAP[FVEK_TYPE], FVEK_KEY, sector_size=SECTOR_SIZE, iv_sector_size=SECTOR_SIZE)
    encrypted_sector = cipher.encrypt(KNOWN_PLAINTEXT, DATA_SECTOR)
    volume.seek(DATA_SECTOR * SECTOR_SIZE)
    volume.write(encrypted_sector)
    volume.seek(0)

    secrets = {
        "recovery_password": RECOVERY_PASSWORD,
        "vmk": VMK_KEY,
        "fvek": FVEK_KEY,
        "stretch_keys": b"".join(stretch_keys),
    }
    return volume, secrets
