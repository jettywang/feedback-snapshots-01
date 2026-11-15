from __future__ import annotations

import contextlib
import gzip
import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.fve.bde import bde
from dissect.fve.crypto import elephant
from tests._util import absolute_path, open_file_gz
from tests.crypto import elephant_reference

if TYPE_CHECKING:
    from collections.abc import Iterator

KEY_128 = bytes.fromhex(
    "10730f695df62a49cd3aa1b1c9ae3edf2229c338a3740830e2b19d2b83f9cada"
    "268af0e0613921085edc89e1b804de354fd265acf4e5c410b47764bb9565666b"
)
KEY_256 = bytes.fromhex(
    "3a600625f8fd5cc506cf8b30c8ca0600cc32f0c6b54c140789f7518c4fb5c71b"
    "a272f34f1a920d5be247298b5d233ce6199023c24d0aefec28717232f9894d1f"
)
KEY_128_EBOIV = bytes.fromhex("84c3a3157e5f21dee140005220bc940e")

DIFFUSER_128 = "_data/bde/aes_128_diffuser.bin.gz"
DIFFUSER_256 = "_data/bde/aes_256_diffuser.bin.gz"
EBOIV_128 = "_data/bde/aes_128.bin.gz"

# Physical sectors holding logical sectors 0 and 1 of the diffuser fixtures. The volume
# header and boot code live in a virtualized block at the end of the volume.
VIRTUALIZED_OFFSET = 0x298A000 // 512

KNOWN_PLAINTEXT = {
    ("128", 0x0): "d94ac3b56f5307afa9350882f9b5d84401d1eac2dc0a27300376c2e5c80172d8",
    ("128", 0x200): "9432dd3acac64964d714f7c3424f05fb76e60d831581fd1b451ca7a5e8bdc454",
    ("128", 0x2000): "6b9fcc3ae0ec88c2f2e426c794e59f85ea916f8f9ca0ed4f9c49cf0697986541",
    ("256", 0x0): "d62b8dfa4eb68d5507bc446cb34cd1d5bc1a2425c2dd609c9920c5ec9d87308d",
    ("256", 0x200): "9432dd3acac64964d714f7c3424f05fb76e60d831581fd1b451ca7a5e8bdc454",
    ("256", 0x2000): "15f82117d3df79ea7e6b0ddd12d5f1ab73c49ef34b71c75e0d52db3ecafab37f",
}

UNALIGNED_READS = [
    (
        "128",
        0x1F0,
        544,
        "6e7839f0fde182f372cf448dafba5aca28cffce3d90292724678f8391481fce6",
    ),
    (
        "128",
        0x2005,
        123,
        "d874a4237c59aa5fa20c9b944fb70fd6f6a694b3cbb5232b2e7a289f9baaabdd",
    ),
    (
        "128",
        0x20F0,
        528,
        "646f456027e96d34152412709282fdb81409be36687e6e389f78a4059a6c1bd9",
    ),
    (
        "128",
        0x1FF0,
        512,
        "88a8ac3dd9c5b06fc1f105cdb60377432b5ffae21a6a424fd87a98a246b50180",
    ),
    (
        "128",
        0x3FF0,
        48,
        "85b47dee5491d93504e427b8f310a9bcb07fd6d21d226fe4b0465d79d2c4e5b5",
    ),
    (
        "256",
        0x1F0,
        544,
        "6e7839f0fde182f372cf448dafba5aca28cffce3d90292724678f8391481fce6",
    ),
    (
        "256",
        0x2005,
        123,
        "2cc51cd197c8d0a52b26931b030d5722fff4a920f2089eb707ba6b701074359f",
    ),
    (
        "256",
        0x20F0,
        528,
        "057e4ae27e9dd31197ea073eb79bc0717b50ac18ddfba9bdca3a263f5f945c42",
    ),
    (
        "256",
        0x1FF0,
        512,
        "63cc4792ac927d4c43718f24f4c193cb49ad500a1a754d0ad0971e072ad80435",
    ),
    (
        "256",
        0x3FF0,
        48,
        "85b47dee5491d93504e427b8f310a9bcb07fd6d21d226fe4b0465d79d2c4e5b5",
    ),
]

WRONG_KEY_STREAMS = [
    (
        "128_zero_diffuser",
        "128",
        KEY_128[:32] + bytes(16) + KEY_128[48:],
        {
            0x0: "8f35ebed32156292770da70a06605267ee72c04b86f0da5a007ff54d7578f032",
            0x200: "31c3b06a1a88b0579b617bad39eb625f92bc41ee0950bbd9565fbc84d28390a0",
            0x2000: "a94fd80dfb78d71dd507206b91a353542096f71a47760566a6940bfbe036a677",
        },
    ),
    (
        "128_swapped_segments",
        "128",
        KEY_128[32:48] + KEY_128[16:32] + KEY_128[0:16] + KEY_128[48:],
        {
            0x0: "7d07e16629f77237fe652671647bf831254e3fdb41124608f7e0008a817db6e0",
            0x200: "98d2434f6088f31d929bed37d683b8bf79c498dd99aa265c56b0c587f17c112e",
            0x2000: "441a0adad8924adb6a24e3f9b01233cf853e9bf37b2d15a558048d7175e8590f",
        },
    ),
    (
        "128_offset_segments",
        "128",
        KEY_128[16:32] + bytes(16) + KEY_128[48:64] + bytes(16),
        {
            0x0: "c6642f0c18a6e4929dc950a71f8930c3dc138c2987d80a73c777191c351eb1ea",
            0x200: "f7f2b6ab2ad51286043c2890579cd58fc74e656d73371900679c4e190927a397",
            0x2000: "2a1d5f75bdb413fd7c05dfb3feb7893e0ae8d4a5bc15850957efc01f3160b155",
        },
    ),
    (
        "256_zero_diffuser",
        "256",
        KEY_256[:32] + bytes(32),
        {
            0x0: "70af0bc7f1e098c1230c90b8486bf9e327f20015db2aa895695a9a31e289f0ef",
            0x200: "72f01d47a93275dd1af29c411448a137eba583eab7236e1faaf68e4db78c1d0e",
            0x2000: "9abc70774c0047fa5350523d005b436b4c9405b89d1892ecb51fd8d449bf2cd6",
        },
    ),
    (
        "256_swapped_segments",
        "256",
        KEY_256[32:64] + KEY_256[0:32],
        {
            0x0: "721c5474e2009986c1684173532073371437a39d12326aa37239a7e0caa87d3e",
            0x200: "1d500f55e02320fa10c009d7f36c7e23560cc300356f7fc2662ff27523cdc05f",
            0x2000: "28124e33dd19401316f3115c9431f23544e5fd09be2eb5224c950b0817971443",
        },
    ),
]

WRONG_DIFFUSION_STREAMS = [
    (
        "128_wrong_direction",
        "128",
        "wrong_direction",
        {
            0x0: "2081a35d33eac638bf45b671322c87c137b4e6a4df97242d003b90cbda49fc58",
            0x200: "c1faa7246977d5bdbc4fda96e924881ceccac956ac1069c8d9e2144f95822bfc",
            0x2000: "af3da8d9dc4a05acb244e0825d06dffae9c45de530a56246c2c5a2c8e71939b8",
        },
    ),
    (
        "128_wrong_order",
        "128",
        "wrong_order",
        {
            0x0: "51334e09766dee1be94e82473467246fa7a5dc327d5e4d61aaef0cfa5b91137a",
            0x200: "03fe1261f79144a298408b4a26a80014454e05f4e0231935e33075579aa6dcce",
            0x2000: "ed4bd8b3a08dd40fd9a4390110332b4f8e62f375637ebeab90d984edad177767",
        },
    ),
    (
        "256_wrong_direction",
        "256",
        "wrong_direction",
        {
            0x0: "96a7b14b1b2c537cfb9d0bc33cc6e7db533e5c2819a5f2068a161f6fad2db928",
            0x200: "4db38ab9ae8bec0865a454132dcb8f34df16904e7b6345d8c3f1a289603047e7",
            0x2000: "6605b525436e5f2baa9b70c9c8ff09064d26a221292fadedfdf2ae22ae3a0fb0",
        },
    ),
    (
        "256_wrong_order",
        "256",
        "wrong_order",
        {
            0x0: "b4d713642f470a6b7e4354d0b9dbe32536b1006f4921313e8a69b290fbf5f27b",
            0x200: "8e0d3c273779425e7a992f5b6ad57eae408437124ff03faea919d0bbc4e1e38a",
            0x2000: "d3c521465ec753f710706b0eec50fc57ec97adbc7702d0bde3fcf18fcb7281a6",
        },
    ),
]


def _key_size(label: str) -> int:
    return 128 if label == "128" else 256


def _fixture(label: str) -> str:
    return DIFFUSER_128 if label == "128" else DIFFUSER_256


@contextlib.contextmanager
def _open_volume(filename: str, key: bytes, *, raw_key: bool = False) -> Iterator[bde.BDE]:
    with contextlib.contextmanager(open_file_gz)(filename) as fh:
        volume = bde.BDE(fh)
        if raw_key:
            volume._fvek_type = volume.information.dataset.fvek_type
            volume._fvek = key
        else:
            volume.unlock_with_fvek(key)
        yield volume


def _read_physical_sector(volume: bde.BDE, sector: int) -> bytes:
    volume.fh.seek(sector * volume.sector_size)
    return volume.fh.read(volume.sector_size)


@pytest.mark.parametrize(
    ("label", "offset", "digest"),
    [(label, offset, digest) for (label, offset), digest in KNOWN_PLAINTEXT.items()],
    ids=[f"{label}-{offset:#x}" for (label, offset) in KNOWN_PLAINTEXT],
)
def test_bde_elephant_known_plaintext_stream(label: str, offset: int, digest: str) -> None:
    key = KEY_128 if label == "128" else KEY_256
    key_size = _key_size(label)
    physical_sector = VIRTUALIZED_OFFSET + offset // 512 if offset < 0x2000 else offset // 512

    with _open_volume(_fixture(label), key) as volume:
        stream = volume.open()

        assert hashlib.sha256(stream.readoffset(offset, 512)).hexdigest() == digest

        # Independently derive the same result from the raw fixture bytes.
        raw = _read_physical_sector(volume, physical_sector)
        expected = elephant_reference.decrypt_sector(key, physical_sector, raw, key_size)

        assert hashlib.sha256(expected).hexdigest() == digest
        assert stream.readoffset(offset, 512) == expected


def test_bde_elephant_same_content_different_location() -> None:
    """Two logical sectors with identical zeros must still use their own sector material."""
    with _open_volume(DIFFUSER_128, KEY_128) as volume:
        stream = volume.open()

        first = stream.readoffset(0x1200, 512)
        second = stream.readoffset(0x1400, 512)

        assert first == second == bytes(512)

        # These logical sectors are virtualized to physical sectors 85081 and 85082.
        first_raw = _read_physical_sector(volume, VIRTUALIZED_OFFSET + 9)
        second_raw = _read_physical_sector(volume, VIRTUALIZED_OFFSET + 10)

        assert first_raw != second_raw
        assert elephant_reference.decrypt_sector(KEY_128, VIRTUALIZED_OFFSET + 9, first_raw) == bytes(512)
        assert elephant_reference.decrypt_sector(KEY_128, VIRTUALIZED_OFFSET + 10, second_raw) == bytes(512)

        # Decrypting the first raw sector with the second sector number must not produce zeros.
        mismatch = elephant_reference.decrypt_sector(KEY_128, VIRTUALIZED_OFFSET + 10, first_raw)

        assert hashlib.sha256(mismatch).hexdigest() == (
            "635d1fbfbd87caec09d7f6b7bbb6ce41ada0a72aa5c448ed2cc92ddcaee2138c"
        )
        assert mismatch != bytes(512)


@pytest.mark.parametrize(
    ("label", "offset", "length", "digest"),
    UNALIGNED_READS,
    ids=[f"{label}-{offset:#x}-{length}" for label, offset, length, _ in UNALIGNED_READS],
)
def test_bde_elephant_unaligned_reads(label: str, offset: int, length: int, digest: str) -> None:
    key = KEY_128 if label == "128" else KEY_256

    with _open_volume(_fixture(label), key) as volume:
        result = volume.open().readoffset(offset, length)

        assert len(result) == length
        assert hashlib.sha256(result).hexdigest() == digest


def test_bde_elephant_unaligned_crosses_virtualized_boundary() -> None:
    """A read spanning the virtualized block boundary must use the right sector numbers."""
    with _open_volume(DIFFUSER_128, KEY_128) as volume:
        stream = volume.open()

        result = stream.readoffset(0x1FF0, 512)

        assert hashlib.sha256(result).hexdigest() == (
            "88a8ac3dd9c5b06fc1f105cdb60377432b5ffae21a6a424fd87a98a246b50180"
        )
        assert result[-16:].hex() == "08100000000000000810000000000000"

        # The last 16 bytes come from logical sector 16, which is physical sector 16,
        # while the first bytes come from virtualized logical sector 15.
        assert stream.readoffset(0x2000, 16).hex() == "46494c4530000300e022100000000000"
        assert stream.readoffset(0x1FF0, 16) == bytes(16)


@pytest.mark.parametrize(
    ("name", "label", "wrong_key", "expected"),
    WRONG_KEY_STREAMS,
    ids=[v[0] for v in WRONG_KEY_STREAMS],
)
def test_bde_elephant_wrong_key_segments(name: str, label: str, wrong_key: bytes, expected: dict[int, str]) -> None:
    key = KEY_128 if label == "128" else KEY_256

    with _open_volume(_fixture(label), key, raw_key=True) as volume:
        volume._fvek = wrong_key
        stream = volume.open()

        for offset, digest in expected.items():
            result = stream.readoffset(offset, 512)

            assert hashlib.sha256(result).hexdigest() == digest

        assert stream.readoffset(0, 11) != b"\xebR\x90NTFS    "
        assert stream.readoffset(0x2000, 5) != b"FILE0"


@pytest.mark.parametrize(
    ("name", "label", "mode", "expected"),
    WRONG_DIFFUSION_STREAMS,
    ids=[v[0] for v in WRONG_DIFFUSION_STREAMS],
)
def test_bde_elephant_wrong_diffusion_direction(
    name: str,
    label: str,
    mode: str,
    expected: dict[int, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = KEY_128 if label == "128" else KEY_256

    with _open_volume(_fixture(label), key) as volume:
        if mode == "wrong_direction":
            monkeypatch.setattr(elephant, "diffuser_a_decrypt", elephant.diffuser_a_encrypt)
            monkeypatch.setattr(elephant, "diffuser_b_decrypt", elephant.diffuser_b_encrypt)
        else:
            original_a_decrypt = elephant.diffuser_a_decrypt
            original_b_decrypt = elephant.diffuser_b_decrypt
            monkeypatch.setattr(elephant, "diffuser_a_decrypt", original_b_decrypt)
            monkeypatch.setattr(elephant, "diffuser_b_decrypt", original_a_decrypt)

        stream = volume.open()

        for offset, digest in expected.items():
            result = stream.readoffset(offset, 512)

            assert hashlib.sha256(result).hexdigest() == digest

        assert stream.readoffset(0, 11) != b"\xebR\x90NTFS    "
        assert stream.readoffset(0x2000, 5) != b"FILE0"


@pytest.mark.parametrize(
    ("filename", "key"),
    [(DIFFUSER_128, KEY_128), (DIFFUSER_256, KEY_256)],
    ids=["128", "256"],
)
def test_bde_elephant_wrong_data_key_rejected(filename: str, key: bytes) -> None:
    with (
        contextlib.contextmanager(open_file_gz)(filename) as fh,
        pytest.raises(ValueError, match="Unable to unlock with FVEK"),
    ):
        bde.BDE(fh).unlock_with_fvek(bytes(len(key)))


def test_bde_elephant_non_diffuser_mode_does_not_use_elephant() -> None:
    with _open_volume(EBOIV_128, KEY_128_EBOIV) as volume:
        stream = volume.open()

        assert type(stream.cipher.iv_mode).__name__ == "EBOIV"
        assert hashlib.sha256(stream.readoffset(0, 512)).hexdigest() == (
            "330ae9824fdd919fbe5c0eb7f48c9f9df2a002557eb5daa2f8be93d25f4dccc5"
        )
        assert hashlib.sha256(stream.readoffset(0x2000, 512)).hexdigest() == (
            "f39627a6beaad0a958b1d40ec70280fe14369420974c4a1ebec0af558c58dc2f"
        )
        assert stream.readoffset(0, 11) == b"\xebR\x90NTFS    "
        assert stream.readoffset(0x2000, 5) == b"FILE0"

        # Explicitly forcing the Elephant compatibility path on the same ciphertext
        # must not accidentally reproduce the known plaintext.
        volume._fvek = KEY_128_EBOIV + bytes(48)
        volume._fvek_type = bde.c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER
        forced = volume.open()

        assert type(forced.cipher.iv_mode).__name__ == "Elephant"
        assert hashlib.sha256(forced.readoffset(0, 512)).hexdigest() == (
            "2a50748f826793afc74b3ba7a4af5dda85477c653925e9f2c539bde3d8e858c7"
        )
        assert hashlib.sha256(forced.readoffset(0x2000, 512)).hexdigest() == (
            "3e88f28acaabf6042fa991bc15af838e41a272963ebbc2663470219eab34af6a"
        )
        assert forced.readoffset(0, 11) != b"\xebR\x90NTFS    "
        assert forced.readoffset(0x2000, 5) != b"FILE0"


def test_bde_elephant_cipher_map_separation() -> None:
    assert bde.CIPHER_MAP[bde.c_bde.FVE_KEY_TYPE.AES_128_DIFFUSER] == "aes-cbc-128-elephant"
    assert bde.CIPHER_MAP[bde.c_bde.FVE_KEY_TYPE.AES_256_DIFFUSER] == "aes-cbc-256-elephant"
    assert bde.CIPHER_MAP[bde.c_bde.FVE_KEY_TYPE.AES_128] == "aes-cbc-128-eboiv"
    assert bde.CIPHER_MAP[bde.c_bde.FVE_KEY_TYPE.AES_256] == "aes-cbc-256-eboiv"


def _load_raw(filename: str, sector: int) -> bytes:
    with gzip.open(absolute_path(filename), "rb") as fh:
        fh.seek(sector * 512)
        return fh.read(512)


def test_bde_elephant_reference_matches_fixture_raw_sectors() -> None:
    """The independent reference, not the implementation diffuser, produces fixture plaintext."""
    for label, key in (("128", KEY_128), ("256", KEY_256)):
        filename = _fixture(label)
        base = VIRTUALIZED_OFFSET
        for logical, expected in (
            (0, KNOWN_PLAINTEXT[(label, 0x0)]),
            (1, KNOWN_PLAINTEXT[(label, 0x200)]),
        ):
            raw = _load_raw(filename, base + logical)
            plain = elephant_reference.decrypt_sector(key, base + logical, raw, _key_size(label))

            assert hashlib.sha256(plain).hexdigest() == expected

        raw = _load_raw(filename, 16)
        plain = elephant_reference.decrypt_sector(key, 16, raw, _key_size(label))

        assert plain[:5] == b"FILE0"
        assert hashlib.sha256(plain).hexdigest() == KNOWN_PLAINTEXT[(label, 0x2000)]
