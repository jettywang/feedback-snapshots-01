from __future__ import annotations

import zlib
from io import BytesIO

import pytest

from dissect.fve.crypto import create_cipher
from dissect.fve.veracrypt.c_veracrypt import c_veracrypt
from dissect.fve.veracrypt.key import Pkcs5HmacSha512
from dissect.fve.veracrypt.veracrypt import (
    HeaderCandidate,
    VeraCrypt,
    is_veracrypt_volume,
    standard_header_offsets,
    verify_header,
)
from dissect.util.stream import MappingStream
from tests._util import absolute_path


@pytest.mark.parametrize(
    ("mode", "type", "value", "valid"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "password",
            True,
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "invalid-password",
            False,
            id="aes256-sha512-passphrase-invalid",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_passphrase",
            "password",
            True,
            id="aes256-sha256-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_header_key",
            bytes.fromhex(
                "5c20ecc54e499c16306781f9b300df9688ecc9221d4d9cc62af91466eed82646b3f26c3d4c647438b2b6da10ad256f29de8dca90aee8224e69621c39df3d81a7"
            ),
            True,
            id="aes256-sha512-header-key",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_header_key",
            bytes.fromhex(
                "964a320efd767801d19ab7585a1f3c000f491799979f4515b1f3b6860f244b6cd4c0482d0f6c8605f129f7ca74f06e18a624ed043d474a6c0d2452d0a5181022"
            ),
            True,
            id="aes256-sha256-header-key",
        ),
        pytest.param(
            "aes256-sha256",
            "unlock_with_header_key",
            b"\x00" * 64,
            False,
            id="aes256-sha256-header-key-invalid",
        ),
    ],
)
def test_veracrypt_file_container(mode: str, type: str, value: str | bytes, valid: bool) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (amd64, Windows) file-based container."""
    file = absolute_path(f"_data/veracrypt/{mode}.hc")
    assert is_veracrypt_volume(file.open("rb"))

    vc = VeraCrypt(file.open("rb"))
    assert not vc.unlocked
    assert not vc.is_system

    if not valid:
        with pytest.raises(ValueError, match=r"^Unable to decrypt using provided (passphrase|header keys)$"):
            getattr(vc, type)(value)
        return

    getattr(vc, type)(value)
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"

    stream = vc.open()
    assert b"FAT12" in stream.read(512)


@pytest.mark.parametrize(
    ("mode", "type", "value"),
    [
        pytest.param(
            "aes256-sha512",
            "unlock_with_passphrase",
            "password",
            id="aes256-sha512-passphrase",
        ),
        pytest.param(
            "aes256-sha512",
            "unlock_with_header_key",
            bytes.fromhex(
                "9b390d357149246a1ef0766d9b327dbb422631211f6ef37f722238d4a2b5fcaf9361c57d774c386baf806c4cb5097ee455997363a65c3eb684e8bc9ad3ee11e6"
            ),
            id="aes256-sha512-header-key",
        ),
    ],
)
def test_veracrypt_system_partition(mode: str, type: str, value: str) -> None:
    """Test if we can decrypt a VeraCrypt 1.26.24 (64-bit, Windows) system partition."""
    # Mock Disk and Volume and prepare stream with correct offsets.
    file = absolute_path(f"_data/veracrypt/{mode}.system")

    stream = MappingStream(size=31744 + 512 + 64)
    stream.add(offset=0, size=31744, fh=BytesIO(b"\x01" * 31744))
    stream.add(offset=0x7C00, size=512 + 64, fh=BytesIO(file.read_bytes() + (64 * b"\x01")))

    vc = VeraCrypt(stream, is_system=True)  # type: ignore
    getattr(vc, type)(value)

    assert vc.is_system
    assert vc.unlocked
    assert vc.header
    assert vc.header.magic == b"VERA"
    assert vc.cipher == "aes-xts-256-plain64"
    assert vc.version == 5
    assert vc.client_version == 267
    assert vc.size == 0xFC4600000  # 63 GB


class CountingStream(BytesIO):
    """A read-only BytesIO that records the byte ranges read from it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads: list[tuple[int, int]] = []
        self.writes = 0

    def read(self, size: int | None = -1) -> bytes:  # type: ignore[override]
        start = self.tell()
        data = super().read(size)
        self.reads.append((start, len(data)))
        return data

    def write(self, data: bytes) -> int:  # type: ignore[override]
        self.writes += 1
        raise AssertionError("the test stream must not be written to")


def build_header(
    *,
    master_key: bytes,
    salt: bytes,
    data_offset: int,
    data_size: int,
    volume_size: int | None = None,
    hidden_volume_size: int = 0,
    passphrase: str = "password",
    version: int = 5,
    sector_size: int = 512,
    flags: int = 0,
    crc32: bytes | None = None,
    crc32_decrypted: bytes | None = None,
) -> bytes:
    """Build a valid encrypted VeraCrypt header (64 byte salt + 512 byte ciphertext).

    The key-area CRC is written first, because the volume-header CRC covers the bytes
    that contain it.
    """
    header = c_veracrypt.VolumeHeader()
    header.magic = b"VERA"
    header.version = version
    header.client_version = 267
    header.hidden_volume_size = hidden_volume_size
    header.volume_size = volume_size if volume_size is not None else data_size
    header.mk_scope_offset = data_offset
    header.mk_scope_size = data_size
    header.flags = flags
    header.sector_size = sector_size
    header.reserved_1 = bytes(16)
    header.reserved_2 = bytes(120)
    header.master_keys = master_key + bytes(256 - len(master_key))

    raw = bytearray(bytes(header))
    raw[8:12] = crc32 if crc32 is not None else zlib.crc32(raw[192:448]).to_bytes(4, "big")
    raw[188:192] = crc32_decrypted if crc32_decrypted is not None else zlib.crc32(raw[:188]).to_bytes(4, "big")

    keys = Pkcs5HmacSha512(passphrase, salt).derive(None)
    ciphertext = create_cipher("aes-xts-256-plain64", keys).encrypt(bytes(raw) + bytes(64), 0)
    return salt + bytes(ciphertext)


def decrypt_header(blob: bytes, passphrase: str = "password") -> bytearray:
    """Decrypt a header blob (salt + ciphertext) back into the 512-byte plaintext block."""
    keys = Pkcs5HmacSha512(passphrase, blob[:64]).derive(None)
    return bytearray(create_cipher("aes-xts-256-plain64", keys).decrypt(blob[64:], 0))


def encrypt_header(plaintext: bytes, salt: bytes, passphrase: str = "password") -> bytes:
    """Encrypt a 512-byte header plaintext block into a header blob."""
    keys = Pkcs5HmacSha512(passphrase, salt).derive(None)
    return salt + bytes(create_cipher("aes-xts-256-plain64", keys).encrypt(plaintext, 0))


def encrypt_area(stream: BytesIO, offset: int, plaintext: bytes, key: bytes) -> None:
    """Encrypt known plaintext into an area using the same XTS tweak as the decrypting stream."""
    ciphertext = create_cipher("aes-xts-256-plain64", key).encrypt(plaintext, offset // 512)
    stream.seek(offset)
    stream.write(ciphertext)


OUTER_KEY = bytes(range(64))
HIDDEN_KEY = bytes(range(64, 128))
OUTER_PLAINTEXT = (b"OUTER-VOLUME-CONTENT-" * 1024)[:0x20000]
HIDDEN_PLAINTEXT = (b"HIDDEN-VOLUME-CONTENT-" * 1024)[:0x10000]


def make_dual_volume() -> tuple[CountingStream, bytes, bytes]:
    """Build a synthetic image with an outer and a hidden volume header at distinct offsets."""
    outer_header = build_header(
        master_key=OUTER_KEY,
        salt=b"o" * 64,
        data_offset=0x20000,
        data_size=len(OUTER_PLAINTEXT),
        hidden_volume_size=len(HIDDEN_PLAINTEXT),
    )
    hidden_header = build_header(
        master_key=HIDDEN_KEY,
        salt=b"h" * 64,
        data_offset=0x40000,
        data_size=len(HIDDEN_PLAINTEXT),
        hidden_volume_size=len(HIDDEN_PLAINTEXT),
        flags=0x2,
    )

    image = BytesIO(bytes(0x50000))
    image.seek(0)
    image.write(outer_header)
    image.seek(0x10000)
    image.write(hidden_header)
    encrypt_area(image, 0x20000, OUTER_PLAINTEXT, OUTER_KEY)
    encrypt_area(image, 0x40000, HIDDEN_PLAINTEXT, HIDDEN_KEY)

    return CountingStream(image.getvalue()), outer_header, hidden_header


def test_explicit_hidden_header_selection() -> None:
    """Both headers verify independently and the selected hidden header supplies key and range."""
    stream, _, _ = make_dual_volume()
    outer = HeaderCandidate(0, "outer")
    hidden = HeaderCandidate(0x10000, "hidden")

    vc = VeraCrypt(stream, header_candidates=[outer, hidden])
    verifications = vc.verify("password")

    assert [verification.valid for verification in verifications] == [True, True]
    assert [verification.offset for verification in verifications] == [0, 0x10000]
    assert [verification.data_range for verification in verifications] == [
        (0x20000, 0x20000 + len(OUTER_PLAINTEXT)),
        (0x40000, 0x40000 + len(HIDDEN_PLAINTEXT)),
    ]
    assert verifications[0].key == OUTER_KEY
    assert verifications[1].key == HIDDEN_KEY

    selected = vc.select_header(hidden)
    assert selected.kind == "hidden"
    assert vc.key == HIDDEN_KEY
    assert vc.data_offset == 0x40000
    assert vc.data_size == len(HIDDEN_PLAINTEXT)

    assert vc.open().read(len(HIDDEN_PLAINTEXT)) == HIDDEN_PLAINTEXT


def test_explicit_outer_header_selection() -> None:
    """Selecting the outer header never borrows the hidden header's key or range."""
    stream, _, _ = make_dual_volume()
    vc = VeraCrypt(stream, header_candidates=[HeaderCandidate(0, "outer"), HeaderCandidate(0x10000, "hidden")])
    vc.verify("password")
    vc.select_header("outer")

    assert vc.key == OUTER_KEY
    assert vc.data_offset == 0x20000
    assert vc.data_size == len(OUTER_PLAINTEXT)
    assert vc.open().read(len(OUTER_PLAINTEXT)) == OUTER_PLAINTEXT


def test_selection_order_does_not_change_results() -> None:
    """Reversing candidate order does not change per-header identity or data ranges."""
    stream, _, _ = make_dual_volume()
    forward = VeraCrypt(stream, header_candidates=[(0, "outer"), (0x10000, "hidden")]).verify("password")
    reverse = VeraCrypt(stream, header_candidates=[(0x10000, "hidden"), (0, "outer")]).verify("password")

    assert {(v.kind, v.data_range) for v in forward} == {(v.kind, v.data_range) for v in reverse}
    assert {(v.kind, v.key) for v in forward} == {(v.kind, v.key) for v in reverse}


def test_wrong_passphrase_does_not_activate_any_header() -> None:
    """A passphrase that fails every candidate leaves no key or data range behind."""
    stream, _, _ = make_dual_volume()
    vc = VeraCrypt(stream, header_candidates=[(0, "outer"), (0x10000, "hidden")])

    with pytest.raises(ValueError, match=r"^Unable to decrypt using provided passphrase$"):
        vc.unlock_with_passphrase("wrong-password")

    assert not vc.unlocked
    assert vc.key is None
    assert vc.data_offset is None
    assert all(not verification.valid for verification in vc.verifications)
    assert all(verification.data_range is None for verification in vc.verifications)


def test_multiple_valid_headers_require_explicit_selection() -> None:
    """Ambiguous validity is refused instead of silently choosing the outer volume."""
    stream, _, _ = make_dual_volume()
    vc = VeraCrypt(stream, header_candidates=[(0, "outer"), (0x10000, "hidden")])

    with pytest.raises(ValueError, match="select one explicitly"):
        vc.unlock_with_passphrase("password")

    assert not vc.unlocked


def test_damaged_backup_header_is_reported_without_affecting_primary() -> None:
    """A damaged backup header keeps its own identity and does not borrow the primary result."""
    stream, _, _ = make_dual_volume()
    primary = HeaderCandidate(0, "primary")
    backup = HeaderCandidate(0x10000, "backup")

    # Corrupt only the backup's stored key-area CRC, leaving its magic intact.
    backup_blob = build_header(master_key=HIDDEN_KEY, salt=b"b" * 64, data_offset=0x40000, data_size=0x10000)
    raw = decrypt_header(backup_blob)
    raw[8:12] = (int.from_bytes(raw[8:12], "big") ^ 0xFFFFFFFF).to_bytes(4, "big")
    image = bytearray(stream.getvalue())
    image[0x10000 : 0x10000 + 576] = encrypt_header(bytes(raw), b"b" * 64)
    stream = CountingStream(bytes(image))

    vc = VeraCrypt(stream, header_candidates=[primary, backup])
    verifications = vc.verify("password")

    assert verifications[0].valid
    assert verifications[0].key == OUTER_KEY
    assert not verifications[1].valid
    assert verifications[1].key is None
    assert verifications[1].data_range is None
    assert "CRC32 mismatch" in verifications[1].describe()

    with pytest.raises(ValueError, match="Selected header is not valid"):
        vc.select_header(backup)


def test_overlapping_data_ranges_are_reported() -> None:
    """Partially overlapping data ranges are surfaced per header instead of being silently merged."""
    outer_header = build_header(master_key=OUTER_KEY, salt=b"o" * 64, data_offset=0x20000, data_size=0x20000)
    overlapping_header = build_header(master_key=HIDDEN_KEY, salt=b"h" * 64, data_offset=0x30000, data_size=0x20000)
    image = BytesIO(bytes(0x50000))
    image.seek(0)
    image.write(outer_header)
    image.seek(0x10000)
    image.write(overlapping_header)

    vc = VeraCrypt(image, header_candidates=[(0, "outer"), (0x10000, "hidden")])
    verifications = vc.verify("password")

    assert all(verification.valid for verification in verifications)
    assert any("partially overlaps" in warning for warning in verifications[0].warnings)
    assert any("partially overlaps" in warning for warning in verifications[1].warnings)


def test_header_validation_is_read_only() -> None:
    """Verification only reads the two header blocks and never writes to the stream."""
    stream, _, _ = make_dual_volume()
    vc = VeraCrypt(stream, header_candidates=[(0, "outer"), (0x10000, "hidden")])
    vc.verify("password")
    vc.select_header("hidden")
    vc.open().read(512)

    assert stream.writes == 0
    # Header reads stay within the salt and 512-byte header blocks at the given offsets.
    header_reads = [read for read in stream.reads if read[0] in (0, 0x10000)]
    assert all(length <= 576 for _, length in header_reads)


def test_header_key_selection_matches_passphrase() -> None:
    """A raw header key produces the same verified header identity as a passphrase."""
    stream, _, _ = make_dual_volume()
    header_key = Pkcs5HmacSha512("password", b"h" * 64).derive(None)

    vc = VeraCrypt(stream, header_candidates=[(0, "outer"), (0x10000, "hidden")])
    vc.verify(header_key=header_key)
    hidden = vc.select_header("hidden")

    assert hidden.valid
    assert hidden.kdf == "header-key"
    assert hidden.key == HIDDEN_KEY
    assert vc.open().read(len(HIDDEN_PLAINTEXT)) == HIDDEN_PLAINTEXT


def test_invalid_synthetic_header_is_rejected_even_with_valid_magic() -> None:
    """A header with a valid VERA magic but a bad key-area CRC does not provide a key."""
    bad = build_header(
        master_key=OUTER_KEY,
        salt=b"x" * 64,
        data_offset=0x20000,
        data_size=0x10000,
        crc32=b"\x00\x00\x00\x00",
    )
    stream = BytesIO(bad + bytes(0x30000))

    verification = verify_header(stream, HeaderCandidate(0, "outer"), passphrase="password")

    assert not verification.valid
    assert verification.key is None
    assert "master key area CRC32 mismatch" in verification.describe()


def test_standard_header_offsets_are_read_only_locations() -> None:
    """The geometry helper reports standard locations but does not inspect the volume."""
    offsets = standard_header_offsets(0x400000)

    assert offsets == {
        "primary": 0,
        "hidden": 0x10000,
        "backup": 0x3E0000,
        "hidden_backup": 0x3F0000,
    }


def test_real_primary_and_backup_headers_keep_their_own_identity() -> None:
    """A real container's primary and backup headers verify separately and report their own offset."""
    file = absolute_path("_data/veracrypt/aes256-sha512.hc")
    size = file.stat().st_size
    offsets = standard_header_offsets(size)

    vc = VeraCrypt(
        file.open("rb"),
        header_candidates=[
            HeaderCandidate(offsets["primary"], "primary"),
            HeaderCandidate(offsets["backup"], "backup"),
        ],
    )
    verifications = vc.verify("password")

    assert [verification.kind for verification in verifications] == ["primary", "backup"]
    assert [verification.offset for verification in verifications] == [offsets["primary"], offsets["backup"]]
    assert all(verification.valid for verification in verifications)
    assert verifications[0].data_range == verifications[1].data_range

    vc.select_header("backup")
    assert vc.header_offset == offsets["backup"]
    assert b"FAT12" in vc.open().read(512)


def test_hidden_data_range_covering_another_header_is_rejected() -> None:
    """A data range that would cover another supplied header block is refused, not silently used."""
    # The first header declares a data range that covers the second header's block.
    covering = build_header(master_key=HIDDEN_KEY, salt=b"h" * 64, data_offset=0x20000, data_size=0x10000)
    # The second header sits inside the first header's declared data range, but its own
    # data range starts after all supplied header blocks.
    covered = build_header(master_key=OUTER_KEY, salt=b"o" * 64, data_offset=0x40000, data_size=0x10000)

    image = BytesIO(bytes(0x60000))
    image.seek(0x10000)
    image.write(covering)
    image.seek(0x28000)
    image.write(covered)

    vc = VeraCrypt(
        image,
        header_candidates=[HeaderCandidate(0x10000, "covering"), HeaderCandidate(0x28000, "covered")],
    )
    verifications = vc.verify("password")

    assert not verifications[0].valid
    assert verifications[0].key is None
    assert "overlaps header at 0x28000" in verifications[0].describe()

    assert verifications[1].valid
    assert verifications[1].key == OUTER_KEY

    with pytest.raises(ValueError, match="Selected header is not valid"):
        vc.select_header("covering")


def test_unknown_version_and_sector_size_are_rejected() -> None:
    """Plausible magic is insufficient: unsupported version or sector size fails validation."""
    bad_version = build_header(master_key=OUTER_KEY, salt=b"v" * 64, data_offset=0x20000, data_size=0x10000, version=9)
    bad_sector = build_header(
        master_key=OUTER_KEY, salt=b"s" * 64, data_offset=0x20000, data_size=0x10000, sector_size=1000
    )

    version_result = verify_header(BytesIO(bad_version + bytes(0x30000)), 0, passphrase="password")
    sector_result = verify_header(BytesIO(bad_sector + bytes(0x30000)), 0, passphrase="password")

    assert not version_result.valid
    assert "unsupported header version 9" in version_result.describe()
    assert not sector_result.valid
    assert "invalid sector size 1000" in sector_result.describe()


def test_single_valid_candidate_still_requires_explicit_selection() -> None:
    """When several candidates were supplied, one valid result is verified but not auto-selected."""
    stream, _, _ = make_dual_volume()
    primary = HeaderCandidate(0, "outer")
    missing = HeaderCandidate(0x30000, "hidden")

    vc = VeraCrypt(stream, header_candidates=[primary, missing])
    with pytest.raises(ValueError, match="select one explicitly"):
        vc.unlock_with_passphrase("password")

    assert not vc.unlocked
    assert vc.key is None
    assert vc.verifications[0].valid
    assert not vc.verifications[1].valid

    vc.select_header("outer")
    assert vc.open().read(len(OUTER_PLAINTEXT)) == OUTER_PLAINTEXT


def test_truncated_header_is_rejected() -> None:
    """A candidate that cannot supply a full salt and header fails without exposing a key."""
    stream, _, _ = make_dual_volume()
    verification = verify_header(stream, HeaderCandidate(0x4FFFF, "truncated"), passphrase="password")

    assert not verification.valid
    assert verification.key is None
    assert verification.data_range is None
    assert "truncated header" in verification.describe()


def test_select_header_by_offset() -> None:
    """Selection can use the exact offset without ambiguity."""
    stream, _, _ = make_dual_volume()
    vc = VeraCrypt(stream, header_candidates=[(0, "outer"), (0x10000, "hidden")])
    vc.verify("password")

    selected = vc.select_header(0x10000)

    assert selected.kind == "hidden"
    assert vc.header_offset == 0x10000
    assert vc.open().read(len(HIDDEN_PLAINTEXT)) == HIDDEN_PLAINTEXT


def test_only_caller_specified_location_is_read() -> None:
    """Verification reads the caller's candidate, not the default primary header."""
    stream, _, _ = make_dual_volume()
    vc = VeraCrypt(stream, header_candidates=[HeaderCandidate(0x10000, "hidden")])

    verifications = vc.verify("password")

    assert len(verifications) == 1
    assert verifications[0].valid
    assert verifications[0].offset == 0x10000
    # Every read stays inside the 576-byte block at the requested offset.
    assert all(0x10000 <= start <= 0x10000 + 576 - length for start, length in stream.reads)


def test_header_key_from_another_header_is_rejected() -> None:
    """A header key that belongs to a different salt must not validate this header."""
    stream, _, _ = make_dual_volume()
    hidden_header_key = Pkcs5HmacSha512("password", b"h" * 64).derive(None)

    vc = VeraCrypt(stream, header_candidates=[HeaderCandidate(0, "outer")])
    with pytest.raises(ValueError, match=r"^Unable to decrypt using provided header keys$"):
        vc.unlock_with_header_key(hidden_header_key)

    assert not vc.unlocked
    assert vc.key is None
