from __future__ import annotations

import base64
import hashlib
import io
from typing import BinaryIO

import pytest

from dissect.fve.crypto import create_cipher
from dissect.fve.crypto.util import xor
from dissect.fve.luks.af import diffuse, merge
from dissect.fve.luks.luks import LUKS
from dissect.fve.luks.metadata import Metadata

KEY_SIZE = 16
AF_STRIPES = 32
AF_HASH = "sha256"
AREA_SIZE = KEY_SIZE * AF_STRIPES
ITERATIONS = 1000

VOLUME_KEY = bytes(range(16))
OTHER_KEY = bytes(range(16, 32))

PASSPHRASE_0 = b"passphrase-zero"
PASSPHRASE_1 = b"passphrase-one"

KEK_SALT_0 = b"k" * 16
KEK_SALT_1 = b"K" * 16
DIGEST_SALT_0 = b"d" * 16
DIGEST_SALT_1 = b"D" * 16

KEYSLOT_AREA_OFFSET_0 = 0x1000
KEYSLOT_AREA_OFFSET_1 = 0x2000
SEGMENT_OFFSET_0 = 0x10000
SEGMENT_OFFSET_1 = 0x20000

PLAINTEXT_0 = bytes([0xAA] * 512)
PLAINTEXT_1 = bytes([0xBB] * 512)


def _b64(buf: bytes) -> str:
    return base64.b64encode(buf).decode()


def _derive_kek(passphrase: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt, ITERATIONS, KEY_SIZE)


def _digest_value(volume_key: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", volume_key, salt, ITERATIONS, 32)


def _af_split(secret: bytes) -> bytes:
    """Deterministically AF-split a secret, the inverse of :func:`dissect.fve.luks.af.merge`."""
    blocks = [hashlib.sha256(f"af-block-{i}".encode()).digest()[:KEY_SIZE] for i in range(AF_STRIPES - 1)]
    tmp = bytearray(KEY_SIZE)
    for block in blocks:
        xor(block, tmp, tmp)
        tmp[:] = diffuse(bytes(tmp), AF_HASH)
    last = bytearray(KEY_SIZE)
    xor(secret, bytes(tmp), last)
    result = b"".join([*blocks, bytes(last)])
    assert merge(result, KEY_SIZE, AF_STRIPES, AF_HASH) == secret
    return result


def _keyslot(area_offset: int, kek_salt: bytes) -> dict:
    return {
        "type": "luks2",
        "key_size": str(KEY_SIZE),
        "af": {"type": "luks1", "stripes": str(AF_STRIPES), "hash": AF_HASH},
        "area": {
            "type": "raw",
            "offset": str(area_offset),
            "size": str(AREA_SIZE),
            "encryption": "aes-ecb",
            "key_size": str(KEY_SIZE),
        },
        "kdf": {"type": "pbkdf2", "hash": "sha256", "iterations": str(ITERATIONS), "salt": _b64(kek_salt)},
    }


def _digest(keyslots: list[int], segments: list[int], volume_key: bytes, salt: bytes) -> dict:
    return {
        "type": "pbkdf2",
        "keyslots": [str(keyslot) for keyslot in keyslots],
        "segments": [str(segment) for segment in segments],
        "hash": "sha256",
        "iterations": str(ITERATIONS),
        "salt": _b64(salt),
        "digest": _b64(_digest_value(volume_key, salt)),
    }


def _segment(offset: int, type: str = "crypt") -> dict:
    return {
        "type": type,
        "offset": str(offset),
        "size": "512",
        "iv_tweak": "0",
        "encryption": "aes-ecb",
        "sector_size": "512",
    }


def _metadata(
    keyslots: list[tuple[int, dict]], digests: list[tuple[int, dict]], segments: list[tuple[int, dict]]
) -> dict:
    return {
        "keyslots": {str(idx): obj for idx, obj in keyslots},
        "digests": {str(idx): obj for idx, obj in digests},
        "segments": {str(idx): obj for idx, obj in segments},
        "tokens": {},
        "config": {"json_size": "12288", "keyslots_size": "4194304"},
    }


def _make_fh() -> BinaryIO:
    """Build a fake volume with two keyslot areas and two data segments."""
    buf = bytearray(SEGMENT_OFFSET_1 + 512)

    split_key = _af_split(VOLUME_KEY)
    kek_0 = _derive_kek(PASSPHRASE_0, KEK_SALT_0)
    kek_1 = _derive_kek(PASSPHRASE_1, KEK_SALT_1)
    buf[KEYSLOT_AREA_OFFSET_0 : KEYSLOT_AREA_OFFSET_0 + AREA_SIZE] = create_cipher("aes-ecb", kek_0, 128).encrypt(
        split_key
    )
    buf[KEYSLOT_AREA_OFFSET_1 : KEYSLOT_AREA_OFFSET_1 + AREA_SIZE] = create_cipher("aes-ecb", kek_1, 128).encrypt(
        split_key
    )

    buf[SEGMENT_OFFSET_0 : SEGMENT_OFFSET_0 + 512] = create_cipher("aes-ecb", VOLUME_KEY, 128).encrypt(PLAINTEXT_0)
    buf[SEGMENT_OFFSET_1 : SEGMENT_OFFSET_1 + 512] = create_cipher("aes-ecb", OTHER_KEY, 128).encrypt(PLAINTEXT_1)

    return io.BytesIO(bytes(buf))


def _make_luks(metadata_obj: dict) -> LUKS:
    luks = LUKS.__new__(LUKS)
    luks.fh = _make_fh()
    luks.metadata = Metadata.from_dict(metadata_obj)
    luks._active_volume_key = None
    luks._active_keyslot_id = None
    luks._active_chain = None
    return luks


def _single_chain_metadata() -> dict:
    return _metadata(
        keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
        digests=[(0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0))],
        segments=[(0, _segment(SEGMENT_OFFSET_0))],
    )


def test_single_chain() -> None:
    """A normal keyslot -> digest -> segment chain unlocks and reads its segment."""
    luks = _make_luks(_single_chain_metadata())

    luks.unlock_with_passphrase(PASSPHRASE_0)

    assert luks.unlocked
    assert luks._active_chain.digest_id == 0
    assert luks._active_chain.segment_id == 0
    assert luks.open().read(512) == PLAINTEXT_0


def test_single_chain_with_volume_key() -> None:
    """Unlocking directly with the volume key resolves the same chain."""
    luks = _make_luks(_single_chain_metadata())

    luks.unlock(VOLUME_KEY, 0)

    assert luks.open().read(512) == PLAINTEXT_0


def test_single_chain_wrong_passphrase() -> None:
    luks = _make_luks(_single_chain_metadata())

    with pytest.raises(ValueError, match="No valid keyslot found"):
        luks.unlock_with_passphrase(b"wrong-passphrase")

    assert not luks.unlocked


def test_shared_digest_multiple_keyslots() -> None:
    """Multiple keyslots sharing one digest and segment is a legitimate relation."""
    metadata = _metadata(
        keyslots=[
            (0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0)),
            (1, _keyslot(KEYSLOT_AREA_OFFSET_1, KEK_SALT_1)),
        ],
        digests=[(0, _digest([0, 1], [0], VOLUME_KEY, DIGEST_SALT_0))],
        segments=[(0, _segment(SEGMENT_OFFSET_0))],
    )

    for passphrase, keyslot_id in [(PASSPHRASE_0, 0), (PASSPHRASE_1, 1)]:
        luks = _make_luks(metadata)
        luks.unlock_with_passphrase(passphrase)

        assert luks._active_keyslot_id == keyslot_id
        assert luks.open().read(512) == PLAINTEXT_0


@pytest.mark.parametrize("reverse", [False, True], ids=["matching-first", "matching-last"])
def test_non_matching_digest_cannot_vouch_for_other_segment(reverse: bool) -> None:
    """A digest the volume key does not verify against must not grant its segment.

    The keyslot is referenced by two digests; only the one for segment 0 matches the
    volume key. Regardless of metadata order, the opened stream must read segment 0.
    """
    digests = [
        (0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0)),
        (1, _digest([0], [1], OTHER_KEY, DIGEST_SALT_1)),
    ]
    segments = [(0, _segment(SEGMENT_OFFSET_0)), (1, _segment(SEGMENT_OFFSET_1))]
    if reverse:
        digests.reverse()
        segments.reverse()

    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=digests,
            segments=segments,
        )
    )

    luks.unlock_with_passphrase(PASSPHRASE_0)

    assert luks._active_chain.digest_id == 0
    assert luks._active_chain.segment_id == 0
    assert luks.open().read(512) == PLAINTEXT_0


@pytest.mark.parametrize("reverse", [False, True], ids=["normal-order", "reversed-order"])
def test_conflicting_digests_are_ambiguous(reverse: bool) -> None:
    """A key verifying against digests for different segments is an explicit ambiguity."""
    digests = [
        (0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0)),
        (1, _digest([0], [1], VOLUME_KEY, DIGEST_SALT_1)),
    ]
    segments = [(0, _segment(SEGMENT_OFFSET_0)), (1, _segment(SEGMENT_OFFSET_1))]
    if reverse:
        digests.reverse()
        segments.reverse()

    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=digests,
            segments=segments,
        )
    )

    with pytest.raises(ValueError, match="Ambiguous volume key for keyslot 0"):
        luks.unlock(VOLUME_KEY, 0)

    with pytest.raises(ValueError, match="Ambiguous"):
        luks.unlock_with_passphrase(PASSPHRASE_0)

    assert not luks.unlocked


def test_digest_with_multiple_segments_is_ambiguous() -> None:
    """A digest mapping one keyslot to multiple segments cannot pick a layout."""
    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=[(0, _digest([0], [0, 1], VOLUME_KEY, DIGEST_SALT_0))],
            segments=[(0, _segment(SEGMENT_OFFSET_0)), (1, _segment(SEGMENT_OFFSET_1))],
        )
    )

    with pytest.raises(ValueError, match="Ambiguous volume key for keyslot 0"):
        luks.unlock(VOLUME_KEY, 0)

    with pytest.raises(ValueError, match="Ambiguous segment for keyslot 0"):
        luks.find_segment(0)


def test_dangling_segment_reference_is_ignored() -> None:
    """A digest dangling to a missing segment still resolves via its valid segment."""
    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=[(0, _digest([0], [7, 0], VOLUME_KEY, DIGEST_SALT_0))],
            segments=[(0, _segment(SEGMENT_OFFSET_0))],
        )
    )

    luks.unlock_with_passphrase(PASSPHRASE_0)

    assert luks._active_chain.segment_id == 0
    assert luks.open().read(512) == PLAINTEXT_0


def test_only_dangling_segment_reference_is_unbound() -> None:
    """A keyslot whose only digest dangles to a missing segment has no complete chain."""
    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=[(0, _digest([0], [7], VOLUME_KEY, DIGEST_SALT_0))],
            segments=[(0, _segment(SEGMENT_OFFSET_0))],
        )
    )

    with pytest.raises(ValueError, match="not bound to any digest and segment"):
        luks.unlock(VOLUME_KEY, 0)


def test_digest_referencing_unknown_keyslot_is_ignored() -> None:
    """A digest referencing a non-existent keyslot does not disturb valid chains."""
    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=[
                (0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0)),
                (1, _digest([7], [0], OTHER_KEY, DIGEST_SALT_1)),
            ],
            segments=[(0, _segment(SEGMENT_OFFSET_0))],
        )
    )

    luks.unlock_with_passphrase(PASSPHRASE_0)

    assert luks._active_chain.digest_id == 0
    assert luks.open().read(512) == PLAINTEXT_0


def test_unbound_keyslot() -> None:
    """A keyslot not referenced by any digest cannot unlock."""
    luks = _make_luks(
        _metadata(
            keyslots=[
                (0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0)),
                (1, _keyslot(KEYSLOT_AREA_OFFSET_1, KEK_SALT_1)),
            ],
            digests=[(0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0))],
            segments=[(0, _segment(SEGMENT_OFFSET_0))],
        )
    )

    with pytest.raises(ValueError, match="No digest found for keyslot 1"):
        luks.find_digest(1)

    with pytest.raises(ValueError, match="not bound to any digest and segment"):
        luks.unlock(VOLUME_KEY, 1)

    with pytest.raises(ValueError, match="not bound to any digest and segment"):
        luks.unlock_with_passphrase(PASSPHRASE_1)


def test_find_digest_ambiguous() -> None:
    """A keyslot referenced by multiple digests has no single digest."""
    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=[
                (0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0)),
                (1, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_1)),
            ],
            segments=[(0, _segment(SEGMENT_OFFSET_0))],
        )
    )

    with pytest.raises(ValueError, match="Ambiguous digest for keyslot 0"):
        luks.find_digest(0)

    # Both digests verify and agree on the segment, so unlocking is still unambiguous
    luks.unlock(VOLUME_KEY, 0)
    assert luks.open().read(512) == PLAINTEXT_0


def test_unsupported_segment_layout() -> None:
    """A verified chain with an unsupported segment type cannot open a stream."""
    luks = _make_luks(
        _metadata(
            keyslots=[(0, _keyslot(KEYSLOT_AREA_OFFSET_0, KEK_SALT_0))],
            digests=[(0, _digest([0], [0], VOLUME_KEY, DIGEST_SALT_0))],
            segments=[(0, _segment(SEGMENT_OFFSET_0, type="linear"))],
        )
    )

    luks.unlock(VOLUME_KEY, 0)

    with pytest.raises(NotImplementedError, match="Unsupported segment type"):
        luks.open()
