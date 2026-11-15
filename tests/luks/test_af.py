from __future__ import annotations

import contextlib
import hashlib
import io
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.fve.crypto import create_cipher
from dissect.fve.luks import af
from dissect.fve.luks.luks import LUKS
from tests._util import absolute_path, open_file_gz

if TYPE_CHECKING:
    from collections.abc import Sequence

DIGEST_SIZES = {"sha1": 20, "sha256": 32, "sha512": 64}

LUKS1_HEADER_SIZE = 1024
LUKS1_KEYBLOCK_OFFSET = 208
LUKS1_KEYBLOCK_SIZE = 48
LUKS1_KEYBLOCK_STRIPES_OFFSET = 44
LUKS1_FIRST_KEYSLOT_SECTOR = 8
SECTOR_SIZE = 512
LUKS_KEY_ENABLED = 0x00AC71F3


def _reference_hash(data: bytes, hash_name: str, iv: int) -> bytes:
    return hashlib.new(hash_name, (iv & 0xFFFFFFFF).to_bytes(4, "big") + data).digest()


def _reference_diffuse(data: bytes, hash_name: str) -> bytes:
    digest_size = DIGEST_SIZES[hash_name]
    result = bytearray(len(data))
    passes, remainder = divmod(len(data), digest_size)

    for i in range(passes):
        offset = i * digest_size
        result[offset : offset + digest_size] = _reference_hash(data[offset : offset + digest_size], hash_name, i)

    if remainder:
        result[passes * digest_size :] = _reference_hash(data[len(data) - remainder :], hash_name, passes)[:remainder]

    return bytes(result)


def _reference_merge(data: bytes, block_size: int, block_num: int, hash_name: str) -> bytes:
    assert block_size * block_num == len(data)
    tmp = bytes(block_size)

    for i in range(block_num - 1):
        block = data[i * block_size : (i + 1) * block_size]
        tmp = _reference_diffuse(bytes(a ^ b for a, b in zip(block, tmp, strict=True)), hash_name)

    last = data[(block_num - 1) * block_size : block_num * block_size]
    return bytes(a ^ b for a, b in zip(last, tmp, strict=True))


def _compose_stripes(volume_key: bytes, block_size: int, block_num: int, hash_name: str, seed: int) -> bytes:
    stripes = [bytes((seed + i * 13 + j) % 256 for j in range(block_size)) for i in range(block_num - 1)]
    tmp = bytes(block_size)

    for stripe in stripes:
        tmp = _reference_diffuse(bytes(a ^ b for a, b in zip(stripe, tmp, strict=True)), hash_name)

    stripes.append(bytes(a ^ b for a, b in zip(volume_key, tmp, strict=True)))
    return b"".join(stripes)


def _build_luks1(
    passphrases: Sequence[bytes],
    volume_key: bytes,
    hash_name: str,
    key_size: int,
    stripes: int,
    cipher: str,
    payload: bytes,
    key_material_keys: Sequence[bytes] | None = None,
) -> bytes:
    key_material_keys = key_material_keys or [volume_key] * len(passphrases)
    assert len(key_material_keys) == len(passphrases)

    cipher_name, _, cipher_tail = cipher.partition("-")
    cipher_mode = cipher_tail.partition("-")[0]
    payload_offset = SECTOR_SIZE * 64
    header = bytearray(LUKS1_HEADER_SIZE)

    header[0:6] = b"LUKS\xba\xbe"
    header[6:8] = (1).to_bytes(2, "big")
    header[8 : 8 + len(cipher_name)] = cipher_name.encode()
    header[40 : 40 + len(cipher_mode)] = cipher_mode.encode()
    header[72 : 72 + len(hash_name)] = hash_name.encode()
    header[104:108] = (payload_offset // SECTOR_SIZE).to_bytes(4, "big")
    header[108:112] = key_size.to_bytes(4, "big")
    header[132:164] = b"\x20" * 32
    header[164:168] = (1000).to_bytes(4, "big")
    header[168:204] = b"12345678-1234-5678-1234-567812345678"
    header[112:132] = hashlib.pbkdf2_hmac(hash_name, volume_key, header[132:164], 1000, 20)

    for i in range(8):
        base = LUKS1_KEYBLOCK_OFFSET + i * LUKS1_KEYBLOCK_SIZE
        header[base : base + LUKS1_KEYBLOCK_SIZE] = bytes(LUKS1_KEYBLOCK_SIZE)

    image = bytearray(payload_offset + len(payload))
    image[:LUKS1_HEADER_SIZE] = header

    next_sector = LUKS1_FIRST_KEYSLOT_SECTOR
    for i, (passphrase, material_key) in enumerate(zip(passphrases, key_material_keys, strict=True)):
        salt = bytes([0x10 + i]) * 32
        derived_key = hashlib.pbkdf2_hmac(hash_name, passphrase, salt, 1000, key_size)
        key_material = bytearray(_compose_stripes(material_key, key_size, stripes, hash_name, seed=0x5A + i))
        create_cipher(cipher, derived_key, key_size * 8).encrypt(key_material, 0, key_material)

        base = LUKS1_KEYBLOCK_OFFSET + i * LUKS1_KEYBLOCK_SIZE
        struct.pack_into(">I", image, base, LUKS_KEY_ENABLED)
        struct.pack_into(">I", image, base + 4, 1000)
        image[base + 8 : base + 40] = salt
        struct.pack_into(">I", image, base + 40, next_sector)
        struct.pack_into(">I", image, base + 44, stripes)

        offset = next_sector * SECTOR_SIZE
        image[offset : offset + len(key_material)] = key_material
        next_sector += (len(key_material) + SECTOR_SIZE - 1) // SECTOR_SIZE

    assert next_sector * SECTOR_SIZE <= payload_offset

    encrypted_payload = bytearray(payload)
    create_cipher(cipher, volume_key, key_size * 8).encrypt(encrypted_payload, 0, encrypted_payload)
    image[payload_offset:] = encrypted_payload
    return bytes(image)


def _set_stripes(image: bytearray, keyslot: int, stripes: int) -> None:
    base = LUKS1_KEYBLOCK_OFFSET + keyslot * LUKS1_KEYBLOCK_SIZE + LUKS1_KEYBLOCK_STRIPES_OFFSET
    struct.pack_into(">I", image, base, stripes)


class _ReadTracker(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads: list[tuple[int, int]] = []

    def read(self, size: int = -1) -> bytes:
        start = self.tell()
        data = super().read(size)
        self.reads.append((start, start + len(data)))
        return data


PAYLOAD = b"".join(bytes([i]) * SECTOR_SIZE for i in range(4))


@pytest.mark.parametrize(
    ("hash_name", "size", "expected"),
    [
        ("sha1", 20, "84e066de1e0d3544386085dd64a6451af137c6f0"),
        ("sha1", 24, "84e066de1e0d3544386085dd64a6451af137c6f02ff19c81"),
        ("sha256", 32, "bff51a6d513395979e3a870c8483769a5a70002e6e32c146c53e1d2edc467002"),
        (
            "sha256",
            48,
            "bff51a6d513395979e3a870c8483769a5a70002e6e32c146c53e1d2edc4670028ecaf6406c66033f21aff4f5bb3d6ae2",
        ),
        ("sha512", 16, "5af0cc565253d18674eee4dd51f4c736"),
        (
            "sha512",
            64,
            "869cc83600f8597faf8985fa9944a1469dfae3008244dc3ff56a7c80d5aa5a9c56391b50271c3e45a57d4400e2159e29e727a1dc88830370614855c5a1b36f57",
        ),
        (
            "sha512",
            80,
            "869cc83600f8597faf8985fa9944a1469dfae3008244dc3ff56a7c80d5aa5a9c56391b50271c3e45a57d4400e2159e29e727a1dc88830370614855c5a1b36f5708a30503b649cd3245abfe06f9b53b77",
        ),
    ],
    ids=[
        "sha1-divisible",
        "sha1-remainder",
        "sha256-divisible",
        "sha256-remainder",
        "sha512-remainder-smaller-than-digest",
        "sha512-divisible",
        "sha512-remainder",
    ],
)
def test_diffuse_known_answers(hash_name: str, size: int, expected: str) -> None:
    assert af.diffuse(bytes(range(size)), hash_name).hex() == expected


@pytest.mark.parametrize(
    ("hash_name", "key_size", "stripes", "expected"),
    [
        ("sha1", 16, 2, "8cd6a384944df3ba75dddcc4da2db6ff"),
        ("sha1", 16, 5, "1486df95b04acd833bfc73dd4a1e22ca"),
        ("sha1", 24, 3, "586c106d81ac816584fa0aff0f7069d34c884559fb78f65d"),
        ("sha1", 32, 3, "60bbdd81b29404e5f7631469b8412ae5153655c23e5503a23418423454f2d6ae"),
        (
            "sha1",
            64,
            2,
            "c4a1249d5a4873037029cf9628eb0b55a16694a32269b60e26da3809e8ddf681709f880f4dffcb9b38a055efa912f715dd2a642d52d8bf497c16791afbfdb236",
        ),
        ("sha256", 16, 4, "065eb2018f534cb6241a654a98b285ed"),
        ("sha256", 32, 1, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        ("sha256", 32, 2, "9fd4384e7516b3b0b613ad27a8ae58b56a41321d5a07f771fd072715e07b4e3d"),
        ("sha256", 32, 3, "2ec9dd1c376c60c2a1048733968915ec517b026e72b9bb588b696969840225ec"),
        (
            "sha256",
            48,
            2,
            "8fc4285e6506a3a0a603bd37b8be48a51a31426d2a7787018d775765900b3e4dde9ba4133833556879f6aeaee76034bd",
        ),
        (
            "sha256",
            64,
            2,
            "ffb4582e1576d3d0d673cd47c8ce38d50a21527d3a6797119d674775801b2e5dd34e6c6c9ff003d02a66429c7bef2a9a39376a7597fe0379553ea45eab73ee36",
        ),
        ("sha512", 16, 5, "5550e2e649c9e30d6747e44d3b90e54b"),
        ("sha512", 32, 3, "23bef7b78890e8fb5b76212657d8a46999ba9d76dab8c1996139d80002f580a1"),
        (
            "sha512",
            64,
            1,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        ),
        (
            "sha512",
            64,
            2,
            "c6dd8a7544bd1f38e7c0cfb1d509ef09cdabb153d6118a68ad3326db89f704c33658793343795822cd142e6b8e78f0469756d3affcf6750719312fbeddce1128",
        ),
        (
            "sha512",
            64,
            4,
            "a0fa1e0f978e928c46c8af782dd1e80bd1f9590f9867f5b8f94a434026a80b380f74bdb99054fe7f28c0dbca8b699d1ea0dfc5ba11901153cbd73e8183c937c3",
        ),
    ],
    ids=[
        "sha1-key16-stripes2",
        "sha1-key16-stripes5",
        "sha1-key24-stripes3",
        "sha1-key32-stripes3",
        "sha1-key64-stripes2",
        "sha256-key16-stripes4",
        "sha256-key32-stripes1",
        "sha256-key32-stripes2",
        "sha256-key32-stripes3",
        "sha256-key48-stripes2",
        "sha256-key64-stripes2",
        "sha512-key16-stripes5",
        "sha512-key32-stripes3",
        "sha512-key64-stripes1",
        "sha512-key64-stripes2",
        "sha512-key64-stripes4",
    ],
)
def test_merge_known_answers(hash_name: str, key_size: int, stripes: int, expected: str) -> None:
    data = bytes(range(key_size * stripes))
    assert af.merge(data, key_size, stripes, hash_name).hex() == expected


def test_merge_with_extra_bytes_ignores_surplus() -> None:
    core = bytes(range(64))
    extra = b"\xaa\xbb"
    assert af.merge(core + extra, 32, 2, "sha256") == af.merge(core, 32, 2, "sha256")


def test_merge_rejects_truncated_buffer() -> None:
    with pytest.raises(ValueError, match="Unexpected input buffer size"):
        af.merge(bytes(31), 16, 2, "sha256")


@pytest.mark.parametrize(
    ("hash_name", "key_size", "stripes", "cipher"),
    [
        pytest.param("sha1", 16, 5, "aes-ecb", id="sha1-key16-stripes5"),
        pytest.param("sha256", 16, 7, "aes-ecb", id="sha256-key16-stripes7"),
        pytest.param("sha256", 32, 3, "aes-ecb", id="sha256-key32-stripes3"),
        pytest.param("sha512", 32, 4, "aes-ecb", id="sha512-key32-stripes4"),
        pytest.param("sha512", 64, 2, "aes-xts-plain64", id="sha512-key64-stripes2-xts"),
    ],
)
def test_synthetic_luks1_unlock_decrypts_payload(hash_name: str, key_size: int, stripes: int, cipher: str) -> None:
    volume_key = bytes((i * 7 + 3) % 256 for i in range(key_size))
    image = _build_luks1([b"password"], volume_key, hash_name, key_size, stripes, cipher, PAYLOAD)

    luks = LUKS(io.BytesIO(image))
    assert not luks.unlocked
    luks.unlock_with_passphrase(b"password")

    assert luks._active_volume_key == volume_key
    assert luks.open().read() == PAYLOAD


def test_unlock_rejects_merged_key_with_wrong_digest() -> None:
    volume_key = bytes(range(16))
    wrong_key = bytes([0xA5]) * 16
    image = _build_luks1([b"password"], volume_key, "sha1", 16, 32, "aes-ecb", PAYLOAD, key_material_keys=[wrong_key])

    luks = LUKS(io.BytesIO(image))
    with pytest.raises(ValueError, match="No valid keyslot found"):
        luks.unlock_with_passphrase(b"password", 0)
    assert not luks.unlocked

    keyslot = luks.metadata.keyslots[0]
    luks.fh.seek(keyslot.area.offset)
    area = luks.fh.read(keyslot.key_size * keyslot.af.stripes)
    derived_key = hashlib.pbkdf2_hmac("sha1", b"password", keyslot.kdf.salt, keyslot.kdf.iterations, keyslot.key_size)
    decrypted = create_cipher(keyslot.area.encryption, derived_key, keyslot.area.key_size * 8).decrypt(area)
    merged = _reference_merge(decrypted, keyslot.key_size, keyslot.af.stripes, keyslot.af.hash)

    assert merged == wrong_key
    with pytest.raises(ValueError, match="Invalid volume key"):
        luks.unlock(merged, 0)
    assert not luks.unlocked


def test_merge_rejects_zero_stripes() -> None:
    with pytest.raises(ValueError, match="Invalid number of blocks"):
        af.merge(b"", 16, 0, "sha256")


def test_merge_rejects_zero_block_size() -> None:
    with pytest.raises(ValueError, match="Invalid block size"):
        af.merge(b"", 0, 1, "sha256")


def test_unlock_rejects_zero_stripes() -> None:
    image = bytearray(_build_luks1([b"password"], bytes(range(16)), "sha1", 16, 32, "aes-ecb", PAYLOAD))
    _set_stripes(image, 0, 0)

    luks = LUKS(io.BytesIO(image))
    with pytest.raises(ValueError, match="No valid keyslot found"):
        luks.unlock_with_passphrase(b"password", 0)
    assert not luks.unlocked


def test_unlock_rejects_surplus_stripe_count() -> None:
    image = bytearray(_build_luks1([b"password"], bytes(range(16)), "sha1", 16, 32, "aes-ecb", PAYLOAD))
    _set_stripes(image, 0, 33)

    luks = LUKS(io.BytesIO(image))
    with pytest.raises(ValueError, match="No valid keyslot found"):
        luks.unlock_with_passphrase(b"password", 0)
    assert not luks.unlocked


def test_unlock_rejects_truncated_stripe_area() -> None:
    image = _build_luks1([b"password"], bytes(range(16)), "sha1", 16, 32, "aes-ecb", PAYLOAD)
    slot_end = LUKS1_FIRST_KEYSLOT_SECTOR * SECTOR_SIZE + 16 * 32

    luks = LUKS(io.BytesIO(image[: slot_end - 64]))
    with pytest.raises(ValueError, match="No valid keyslot found"):
        luks.unlock_with_passphrase(b"password", 0)
    assert not luks.unlocked


def test_wrong_stripes_do_not_read_adjacent_keyslot() -> None:
    image = bytearray(_build_luks1([b"slot0", b"slot1"], bytes(range(16)), "sha1", 16, 32, "aes-ecb", PAYLOAD))
    slot0_offset = LUKS1_FIRST_KEYSLOT_SECTOR * SECTOR_SIZE
    slot1_offset = slot0_offset + 16 * 32
    _set_stripes(image, 0, 33)

    tracker = _ReadTracker(bytes(image))
    luks = LUKS(tracker)
    tracker.reads.clear()

    with pytest.raises(ValueError, match="overlap"):
        luks.unlock_with_passphrase(b"slot0", 0)

    assert not luks.unlocked
    assert all(not (start < slot1_offset and end > slot0_offset + 16 * 32) for start, end in tracker.reads)
    assert all(start < slot1_offset for start, _ in tracker.reads)


def test_real_luks1_sample_decrypts_exact_bytes() -> None:
    fixture = absolute_path("_data/luks1/sha1.bin.gz")
    before = hashlib.sha256(fixture.read_bytes()).digest()

    with contextlib.contextmanager(open_file_gz)("_data/luks1/sha1.bin.gz") as fh:
        luks = LUKS(fh)
        luks.unlock_with_passphrase("password")

        assert luks.find_segment(luks._active_keyslot_id).encryption == "aes-ecb"
        assert luks.open().read() == PAYLOAD

    assert hashlib.sha256(fixture.read_bytes()).digest() == before
