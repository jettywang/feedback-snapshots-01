from __future__ import annotations

import contextlib
import struct
from io import BytesIO
from typing import BinaryIO

import pytest
from Crypto.Cipher import AES

from dissect.fve.bde import bde, c_bde, is_bde_volume
from dissect.fve.bde.information import AesCcmEncryptedDatum, Datum, KeyDatum
from tests._util import open_file, open_file_gz


def _key_datum_bytes(
    key_type: c_bde.FVE_KEY_TYPE,
    data: bytes,
    role: c_bde.FVE_DATUM_ROLE = c_bde.FVE_DATUM_ROLE.PROPERTY,
    type_: c_bde.FVE_DATUM_TYPE = c_bde.FVE_DATUM_TYPE.KEY,
) -> bytes:
    """Construct the raw bytes of a small, structurally valid KeyDatum."""
    return struct.pack("<HHHHHH", 12 + len(data), role, type_, 0, key_type, 0) + data


def _key_datum(
    key_type: c_bde.FVE_KEY_TYPE,
    data: bytes,
    role: c_bde.FVE_DATUM_ROLE = c_bde.FVE_DATUM_ROLE.PROPERTY,
    type_: c_bde.FVE_DATUM_TYPE = c_bde.FVE_DATUM_TYPE.KEY,
) -> KeyDatum:
    """Construct a small KeyDatum, always parsing it as a key regardless of the encoded type."""
    return KeyDatum(BytesIO(_key_datum_bytes(key_type, data, role, type_)))


def _seal_bytes(datum: bytes, key: bytes, role: c_bde.FVE_DATUM_ROLE) -> bytes:
    """Wrap raw datum bytes in a dummy AES-CCM encrypted key datum."""
    nonce = b"\x00" * 12
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    ciphertext, mac = cipher.encrypt_and_digest(datum)

    payload = nonce + mac + ciphertext
    return struct.pack("<HHHH", 8 + len(payload), role, c_bde.FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY, 0) + payload


def _seal(datum: bytes, key: bytes, role: c_bde.FVE_DATUM_ROLE) -> AesCcmEncryptedDatum:
    """Wrap raw datum bytes in a dummy AES-CCM encrypted key datum."""
    return Datum.from_bytes(_seal_bytes(datum, key, role))


def _unlocked_vmk() -> tuple[bytes, KeyDatum]:
    """Return the VMK material and datum of a known AES-256 volume."""
    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh).unlock_with_passphrase("password12!@")
        return bde_obj._vmk, bde_obj._vmk_datum


def _verify_crypto_stream(bde_obj: bde.BDE) -> None:
    stream = bde_obj.open()
    assert stream.read(512)[3:11] == b"NTFS    "

    # 0x2000 is outside the Vista plain text and the default Bitlocker 2 virtualized region
    stream.seek(0x2000)
    assert stream.read(512)[:8] == b"FILE0\x00\x03\x00"


def _verify_passphrase_crypto(test_file: BinaryIO, passphrase: str, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_passphrase()
    bde_obj.unlock_with_passphrase(passphrase)
    assert bde_obj.unlocked

    assert isinstance(bde_obj._fvek_datum, KeyDatum)
    assert isinstance(bde_obj._fvek, bytes)
    assert isinstance(bde_obj._vmk_datum, KeyDatum)
    assert isinstance(bde_obj._vmk, bytes)

    _verify_crypto_stream(bde_obj)


def _verify_recovery_password_crypto(
    test_file: BinaryIO, recovery_password: str, fvek_type: c_bde.FVE_KEY_TYPE
) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password(recovery_password)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_bek_crypto(test_file: BinaryIO, bek_file: BinaryIO, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    assert bde_obj.has_bek()
    bde_obj.unlock_with_bek(bek_file)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_external_key_crypto(test_file: BinaryIO, external_key: str, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    bde_obj.unlock_with_external_key(bytes.fromhex(external_key))
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def _verify_raw_key_crypto(test_file: BinaryIO, raw_key: bytes, fvek_type: c_bde.FVE_KEY_TYPE) -> None:
    bde_obj = bde.BDE(test_file)

    assert bde_obj.encrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.ENCRYPTED
    assert bde_obj.information.dataset.fvek_type == fvek_type
    assert not bde_obj.unlocked

    bde_obj.unlock_with_fvek(raw_key)
    assert bde_obj.unlocked

    _verify_crypto_stream(bde_obj)


def test_bde_basic(bde_aes_128: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_aes_128)

    assert bde_obj.sector_size == 512
    assert bde_obj.version == 2

    assert len(bde_obj._available_information) == len(bde_obj._valid_information) == 3

    dataset = bde_obj.information.dataset
    assert len(dataset.data) == 4
    assert bde_obj.description() == "DESKTOP-QNI1MMF TestVolume 10/8/2021"

    assert bde_obj.reserved_regions() == [(69504, 128), (69632, 16), (84528, 128), (99544, 128)]


def test_bde_decrypted(bde_decrypted: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_decrypted)

    assert bde_obj.decrypted
    assert bde_obj.information.current_state == bde_obj.information.next_state == c_bde.FVE_STATE.DECRYPTED
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert not stream.encrypted
    assert stream.read(512)[3:11] == b"NTFS    "


def test_bde_suspended(bde_suspended: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_suspended)

    assert bde_obj.has_clear_key()
    bde_obj.unlock_with_clear_key()

    stream = bde_obj.open()
    assert stream.encrypted
    assert stream.read(512)[3:11] == b"NTFS    "


@pytest.mark.parametrize(
    ("test_file", "passphrase", "key_type"),
    [
        ("_data/bde/aes_128.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_128),
        ("_data/bde/aes_256.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_256),
        ("_data/bde/aes_128_diffuser.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER),
        ("_data/bde/aes_256_diffuser.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER),
        ("_data/bde/aes-xts_128.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_XTS_128),
        ("_data/bde/aes-xts_256.bin.gz", "password12!@", c_bde.FVE_KEY_TYPE.AES_XTS_256),
    ],
)
def test_bde_passphrase(test_file: str, passphrase: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_passphrase_crypto(fh, passphrase, key_type)


@pytest.mark.parametrize(
    ("test_file", "recovery", "key_type"),
    [
        (
            "_data/bde/recovery_password.bin.gz",
            "284867-596541-514998-422114-660297-261613-215424-199408",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_recovery(test_file: str, recovery: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_recovery_password_crypto(fh, recovery, key_type)


@pytest.mark.parametrize(
    ("test_file", "bek_file", "key_type"),
    [
        (
            "_data/bde/recovery_key.bin.gz",
            "_data/bde/recovery_key.bek",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/startup_key.bin.gz",
            "_data/bde/startup_key.bek",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_bek(test_file: str, bek_file: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
        contextlib.contextmanager(open_file)(bek_file) as bek_fh,
    ):
        _verify_bek_crypto(fh, bek_fh, key_type)


@pytest.mark.parametrize(
    ("test_file", "external_key", "key_type"),
    [
        (
            "_data/bde/recovery_key.bin.gz",
            "48a608e5cd6f2112e4b390e38a086a5ec62a1a014afaf092c9117630deecd805",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/startup_key.bin.gz",
            "7a70ca1ab390e00daf4d72c217c42bf67a39db94d76214733ae56acb1c5dd814",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
    ],
)
def test_bde_external_key(test_file: str, external_key: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
    ):
        _verify_external_key_crypto(fh, external_key, key_type)


@pytest.mark.parametrize(
    ("test_file", "raw_key", "key_type"),
    [
        (
            "_data/bde/aes_128.bin.gz",
            "84c3a3157e5f21dee140005220bc940e",
            c_bde.FVE_KEY_TYPE.AES_128,
        ),
        (
            "_data/bde/aes_256.bin.gz",
            "dd3885ef9948c8dc6ad1b54a6c4a4b6fb74b44d1d9775ac7ed186c35f1b59022",
            c_bde.FVE_KEY_TYPE.AES_256,
        ),
        (
            "_data/bde/aes_128_diffuser.bin.gz",
            "10730f695df62a49cd3aa1b1c9ae3edf2229c338a3740830e2b19d2b83f9cada268af0e0613921085edc89e1b804de354fd265acf4e5c410b47764bb9565666b",
            c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER,
        ),
        (
            "_data/bde/aes_256_diffuser.bin.gz",
            "3a600625f8fd5cc506cf8b30c8ca0600cc32f0c6b54c140789f7518c4fb5c71ba272f34f1a920d5be247298b5d233ce6199023c24d0aefec28717232f9894d1f",
            c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER,
        ),
        (
            "_data/bde/aes-xts_128.bin.gz",
            "4eb949c473f0edfc379ad041670ddb9c4da0abdb4482a2c8bb47250493aa1ed5",
            c_bde.FVE_KEY_TYPE.AES_XTS_128,
        ),
        (
            "_data/bde/aes-xts_256.bin.gz",
            "c74002df41f5eadeee2549fc009233a2a510726ce08736aba2f84a52ac6e7bbc56b8a824a4dc26cf9c4c2926386319d17427998e045ebfdc789e328e0dc97da4",
            c_bde.FVE_KEY_TYPE.AES_XTS_256,
        ),
    ],
)
def test_bde_raw_key(test_file: str, raw_key: str, key_type: c_bde.FVE_KEY_TYPE) -> None:
    """Test BDE unlocking using a FVEK key."""
    key = bytes.fromhex(raw_key)

    # Test if unlocking with valid FVEK works
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_raw_key_crypto(fh, key, key_type)

    # Test if unlocking with invalid FVEK fails
    with (
        contextlib.contextmanager(open_file_gz)(test_file) as fh,
        pytest.raises(ValueError, match="Unable to unlock with FVEK, no plaintext filesystem found"),
    ):
        _verify_raw_key_crypto(fh, len(key) * b"\x00", key_type)


def test_bde_vista(bde_vista: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_vista)

    assert bde_obj.version == 1

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password("517506-503998-044583-576191-587004-635965-501270-087802")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    bde_obj.fh.seek(0)

    patched_sector = bytearray(bde_obj.fh.read(512))
    bde_sector = stream.read(512)

    patched_sector[0x03:0x0B] = b"NTFS    "
    patched_sector[0x38:0x40] = struct.pack("<Q", bde_obj.information.header.Mft2StartLcn)

    assert bde_sector == patched_sector


def test_bde_win7_partial(bde_win7_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_win7_partial)

    assert bde_obj.version == 2

    assert bde_obj.has_recovery_password()
    bde_obj.unlock_with_recovery_password("131450-120197-153989-250338-511368-495572-680944-381546")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert list(stream._iter_runs(bde_obj.information.state_offset - 512, 1024)) == [
        (stream.RUN_ENCRYPTED, 2234023, 1),
        (stream.RUN_PLAIN, 2234024, 1),
    ]


def test_bde_eow_partial(bde_eow_partial: BinaryIO) -> None:
    bde_obj = bde.BDE(bde_eow_partial)

    assert bde_obj.version == 2
    assert bde_obj.eow_information

    assert bde_obj.has_passphrase()
    bde_obj.unlock_with_passphrase("password12!@")
    assert bde_obj.unlocked

    stream = bde_obj.open()
    assert list(stream._iter_runs(0x2202000, 0x800000 * 33)) == [
        (0, 69648, 233328),
        (2, 302976, 128),
        (0, 303104, 98304),
        (3, 401408, 135040),
        (2, 536448, 128),
        (3, 536576, 73744),
    ]


def test_is_bde_volume(bde_aes_128: BinaryIO) -> None:
    assert is_bde_volume(bde_aes_128)


def test_bde_wrong_keys() -> None:
    """Test that wrong keys raise a sensible error message."""
    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_128.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        with pytest.raises(ValueError, match="Unable to unlock with given passphrase"):
            bde_obj.unlock_with_passphrase("wrongpassword")

        with pytest.raises(ValueError, match="Unable to unlock with given recovery password"):
            bde_obj.unlock_with_recovery_password("000000-000000-000000-000000-000000-000000-000000-000000")

    with (
        contextlib.contextmanager(open_file_gz)("_data/bde/recovery_key.bin.gz") as fh,
        contextlib.contextmanager(open_file)("_data/bde/startup_key.bek") as bek_fh,
    ):
        bde_obj = bde.BDE(fh)

        with pytest.raises(ValueError, match="Unable to unlock with BEK"):
            bde_obj.unlock_with_bek(bek_fh)


def _read_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    stream.seek(offset)
    return stream.read(size)


def test_bde_key_material_sizes() -> None:
    """The configured algorithm determines the exact FVEK material size."""
    assert {
        c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER: 64,
        c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER: 64,
        c_bde.FVE_KEY_TYPE.AES_128: 16,
        c_bde.FVE_KEY_TYPE.AES_256: 32,
        c_bde.FVE_KEY_TYPE.AES_XTS_128: 32,
        c_bde.FVE_KEY_TYPE.AES_XTS_256: 64,
    } == c_bde.FVE_KEY_MATERIAL_SIZE


@pytest.mark.parametrize(
    ("key_type", "key_size"),
    [
        (c_bde.FVE_KEY_TYPE.AES_128, 16),
        (c_bde.FVE_KEY_TYPE.AES_256, 32),
        (c_bde.FVE_KEY_TYPE.AES_XTS_128, 32),
        (c_bde.FVE_KEY_TYPE.AES_XTS_256, 64),
        (c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER, 64),
        (c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER, 64),
    ],
)
def test_bde_key_datum_validate(key_type: c_bde.FVE_KEY_TYPE, key_size: int) -> None:
    """A key datum is only valid with the exact type and material size that is expected."""
    datum = _key_datum(key_type, bytes(key_size))
    datum.validate(key_type, key_size)

    with pytest.raises(ValueError, match="role"):
        _key_datum(key_type, bytes(key_size), role=c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY).validate(
            key_type, key_size
        )

    with pytest.raises(ValueError, match="type"):
        _key_datum(key_type, bytes(key_size), type_=c_bde.FVE_DATUM_TYPE.USE_KEY).validate(key_type, key_size)

    with pytest.raises(ValueError, match="key type"):
        _key_datum(c_bde.FVE_KEY_TYPE.VMK, bytes(key_size)).validate(key_type, key_size)

    with pytest.raises(ValueError, match="size"):
        _key_datum(key_type, bytes(key_size - 1)).validate(key_type, key_size)

    with pytest.raises(ValueError, match="size"):
        _key_datum(key_type, bytes(key_size + 1)).validate(key_type, key_size)


@pytest.mark.parametrize(
    "role",
    [
        c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY,
        c_bde.FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO,
        c_bde.FVE_DATUM_ROLE.STARTUP_KEY,
    ],
)
def test_bde_unlock_wrong_key_datum_role(role: c_bde.FVE_DATUM_ROLE) -> None:
    """A same-length KeyDatum with the wrong role is rejected before unsealing the FVEK."""
    vmk, _ = _unlocked_vmk()

    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        with pytest.raises(ValueError, match="Invalid VMK: Invalid key datum role"):
            bde_obj.unlock(_key_datum(c_bde.FVE_KEY_TYPE.VMK, vmk, role=role))

        assert not bde_obj.unlocked


@pytest.mark.parametrize(
    "key_type",
    [c_bde.FVE_KEY_TYPE.AES_XTS_256, c_bde.FVE_KEY_TYPE.AES_XTS_128, c_bde.FVE_KEY_TYPE.AES_256],
)
def test_bde_unlock_wrong_vmk_key_type(key_type: c_bde.FVE_KEY_TYPE) -> None:
    """A VMK with the same 32 byte length but another key type is rejected."""
    vmk, _ = _unlocked_vmk()

    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        with pytest.raises(ValueError, match="Invalid VMK: Invalid key type"):
            bde_obj.unlock(_key_datum(key_type, vmk))

        assert not bde_obj.unlocked


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_bde_unlock_wrong_vmk_size(size: int) -> None:
    """A VMK with incomplete or superfluous key material is rejected."""
    vmk, _ = _unlocked_vmk()

    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        with pytest.raises(ValueError, match="Invalid VMK"):
            bde_obj.unlock(_key_datum(c_bde.FVE_KEY_TYPE.VMK, (vmk + bytes(64))[:size]))

        assert not bde_obj.unlocked


def test_bde_unlock_rejects_wrong_fvek_algorithm() -> None:
    """An FVEK that unseals with the VMK but has the wrong algorithm is rejected."""
    vmk, vmk_datum = _unlocked_vmk()

    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)

        # Same 32 byte length, wrong AES-XTS-128 algorithm for this AES-256 volume
        fvek = _key_datum_bytes(c_bde.FVE_KEY_TYPE.AES_XTS_128, bytes(32))
        encrypted_fvek = _seal(fvek, vmk, c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY)
        bde_obj.information.dataset.data = [encrypted_fvek]

        with pytest.raises(ValueError, match="Invalid FVEK: Invalid key type"):
            bde_obj.unlock(vmk_datum)

        assert not bde_obj.unlocked


@pytest.mark.parametrize(
    ("key_type", "role", "size", "match"),
    [
        (c_bde.FVE_KEY_TYPE.AES_256, c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY, 32, "datum role"),
        (c_bde.FVE_KEY_TYPE.AES_256, c_bde.FVE_DATUM_ROLE.PROPERTY, 16, "material size"),
        (c_bde.FVE_KEY_TYPE.AES_256, c_bde.FVE_DATUM_ROLE.PROPERTY, 33, "material size"),
        (c_bde.FVE_KEY_TYPE.AES_XTS_128, c_bde.FVE_DATUM_ROLE.PROPERTY, 32, "type:"),
    ],
)
def test_bde_raw_fvek_rejects_mismatched_datum(
    key_type: c_bde.FVE_KEY_TYPE, role: c_bde.FVE_DATUM_ROLE, size: int, match: str
) -> None:
    """The direct FVEK entry checks role and algorithm of a supplied key datum as well."""
    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        with pytest.raises(ValueError, match=f"Unable to unlock with FVEK, Invalid key {match}"):
            bde_obj.unlock_with_fvek(_key_datum(key_type, bytes(size), role=role))

        assert not bde_obj.unlocked


@pytest.mark.parametrize("size", [0, 15, 31, 33, 64])
def test_bde_raw_fvek_rejects_wrong_size(size: int) -> None:
    """The direct FVEK entry rejects material that does not match the configured algorithm."""
    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        with pytest.raises(ValueError, match="Unable to unlock with FVEK, invalid AES_256 key material size"):
            bde_obj.unlock_with_fvek(bytes(size))

        assert not bde_obj.unlocked


@pytest.mark.parametrize(
    ("test_file", "raw_key"),
    [
        ("_data/bde/aes_128.bin.gz", "84c3a3157e5f21dee140005220bc940e"),
        (
            "_data/bde/aes_256.bin.gz",
            "dd3885ef9948c8dc6ad1b54a6c4a4b6fb74b44d1d9775ac7ed186c35f1b59022",
        ),
        (
            "_data/bde/aes_128_diffuser.bin.gz",
            "10730f695df62a49cd3aa1b1c9ae3edf2229c338a3740830e2b19d2b83f9cada268af0e0613921085edc89e1b804de354fd265acf4e5c410b47764bb9565666b",
        ),
        (
            "_data/bde/aes_256_diffuser.bin.gz",
            "3a600625f8fd5cc506cf8b30c8ca0600cc32f0c6b54c140789f7518c4fb5c71ba272f34f1a920d5be247298b5d233ce6199023c24d0aefec28717232f9894d1f",
        ),
        (
            "_data/bde/aes-xts_128.bin.gz",
            "4eb949c473f0edfc379ad041670ddb9c4da0abdb4482a2c8bb47250493aa1ed5",
        ),
        (
            "_data/bde/aes-xts_256.bin.gz",
            "c74002df41f5eadeee2549fc009233a2a510726ce08736aba2f84a52ac6e7bbc56b8a824a4dc26cf9c4c2926386319d17427998e045ebfdc789e328e0dc97da4",
        ),
    ],
)
def test_bde_vmk_and_raw_fvek_read_same_bytes(test_file: str, raw_key: str) -> None:
    """The VMK path and the explicit raw FVEK path read the same known plaintext bytes."""
    passphrase = "password12!@"
    reads = [(0, 512), (0x2000, 512), (0x10000, 1024)]

    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        bde_obj = bde.BDE(fh).unlock_with_passphrase(passphrase)
        assert bde_obj.vmk_authenticated

        with bde_obj.open() as stream:
            from_vmk = [_read_at(stream, *read) for read in reads]

    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        bde_obj = bde.BDE(fh)
        bde_obj.unlock_with_fvek(bytes.fromhex(raw_key))
        assert not bde_obj.vmk_authenticated
        assert bde_obj._vmk is None

        with bde_obj.open() as stream:
            from_fvek = [_read_at(stream, *read) for read in reads]

    assert from_vmk == from_fvek
    assert from_vmk[0][3:11] == b"NTFS    "


def test_bde_vista_unlocked_but_not_vmk_authenticated() -> None:
    """A Vista volume has no encrypted integrity check, so unlocking with a VMK is not authenticated."""
    with contextlib.contextmanager(open_file_gz)("_data/bde/vista.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        bde_obj.unlock_with_recovery_password("517506-503998-044583-576191-587004-635965-501270-087802")

        assert bde_obj.unlocked
        assert not bde_obj.information.has_integrity_check
        assert not bde_obj.vmk_authenticated


@pytest.mark.parametrize(("declared", "available"), [(44, 20), (44, 43), (44, 45)])
def test_bde_unsealed_datum_must_match_declared_size(declared: int, available: int) -> None:
    """An unsealed datum must consume exactly the bytes it declares, rejecting truncation and trailing data."""
    vmk = bytes(range(32))
    raw = struct.pack(
        "<HHHHHH",
        declared,
        c_bde.FVE_DATUM_ROLE.PROPERTY,
        c_bde.FVE_DATUM_TYPE.KEY,
        0,
        c_bde.FVE_KEY_TYPE.VMK,
        0,
    ) + bytes(available - 12)
    sealed = _seal_bytes(raw, vmk, c_bde.FVE_DATUM_ROLE.PROPERTY)

    with pytest.raises(ValueError, match="declared size"):
        Datum.from_bytes(sealed).unbox(vmk)


def test_bde_key_datum_rejects_truncated_material() -> None:
    """A key datum that declares more material than it contains is rejected."""
    datum = KeyDatum(BytesIO(_key_datum_bytes(c_bde.FVE_KEY_TYPE.VMK, bytes(20))[:-4]))

    with pytest.raises(ValueError, match="declared size"):
        datum.validate(c_bde.FVE_KEY_TYPE.VMK, 32)


def test_bde_unlock_rejects_unauthenticated_vmk() -> None:
    """A raw VMK that does not pass the Information integrity check is rejected before unsealing the FVEK."""
    vmk, _ = _unlocked_vmk()

    with contextlib.contextmanager(open_file_gz)("_data/bde/aes_256.bin.gz") as fh:
        bde_obj = bde.BDE(fh)
        with pytest.raises(ValueError, match="VMK does not authenticate the Information integrity check"):
            bde_obj.unlock(bytes(len(vmk)))

        assert not bde_obj.unlocked


def _vmk_info_datum(inner: bytes, priority: c_bde.FVE_KEY_PROTECTOR) -> KeyDatum:
    """Build a VmkInfoDatum with a single nested AES-CCM encrypted key property."""
    header = struct.pack("<16sQHH", b"\x00" * 16, 0, 0, priority)
    size = 8 + len(header) + len(inner)
    raw = struct.pack(
        "<HHHH",
        size,
        c_bde.FVE_DATUM_ROLE.VOLUME_MASTER_KEY_INFO,
        c_bde.FVE_DATUM_TYPE.VOLUME_MASTER_KEY_INFO,
        0,
    )
    return Datum.from_bytes(raw + header + inner)


@pytest.mark.parametrize(
    ("key_type", "role", "type_", "size", "match"),
    [
        (c_bde.FVE_KEY_TYPE.AES_XTS_128, c_bde.FVE_DATUM_ROLE.PROPERTY, c_bde.FVE_DATUM_TYPE.KEY, 32, "key type"),
        (c_bde.FVE_KEY_TYPE.VMK, c_bde.FVE_DATUM_ROLE.FULL_VOLUME_ENCRYPTION_KEY, c_bde.FVE_DATUM_TYPE.KEY, 32, "role"),
        (c_bde.FVE_KEY_TYPE.VMK, c_bde.FVE_DATUM_ROLE.PROPERTY, c_bde.FVE_DATUM_TYPE.USE_KEY, 32, "not a key"),
        (c_bde.FVE_KEY_TYPE.VMK, c_bde.FVE_DATUM_ROLE.PROPERTY, c_bde.FVE_DATUM_TYPE.KEY, 16, "material size"),
    ],
)
def test_bde_vmk_decrypt_rejects_wrong_datum(
    key_type: c_bde.FVE_KEY_TYPE, role: c_bde.FVE_DATUM_ROLE, type_: c_bde.FVE_DATUM_TYPE, size: int, match: str
) -> None:
    """A VMK protector only unseals to a 32 byte VMK key datum."""
    protector_key = bytes(range(32))
    inner = _seal_bytes(_key_datum_bytes(key_type, bytes(size), role=role, type_=type_), protector_key, role)
    vmk_info = _vmk_info_datum(inner, c_bde.FVE_KEY_PROTECTOR.PASSPHRASE)

    with pytest.raises(ValueError, match=match):
        vmk_info.decrypt(protector_key)


def test_bde_vmk_decrypt_accepts_vmk() -> None:
    """A VMK protector unseals a valid VMK key datum."""
    protector_key = bytes(range(32))
    inner = _key_datum_bytes(c_bde.FVE_KEY_TYPE.VMK, bytes(range(32)))
    sealed = _seal_bytes(inner, protector_key, c_bde.FVE_DATUM_ROLE.PROPERTY)
    vmk_info = _vmk_info_datum(sealed, c_bde.FVE_KEY_PROTECTOR.PASSPHRASE)

    datum = vmk_info.decrypt(protector_key)
    assert isinstance(datum, KeyDatum)
    assert datum.key_type == c_bde.FVE_KEY_TYPE.VMK
    assert datum.data == bytes(range(32))
