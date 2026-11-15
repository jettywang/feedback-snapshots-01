from __future__ import annotations

import hashlib
from typing import Callable

import pytest

from dissect.fve.crypto import create_cipher, elephant
from tests.crypto import elephant_reference


def test_crypto_elephant_diffuser_a() -> None:
    buffer = bytearray(b"a" * 512)
    view = memoryview(buffer)

    elephant.diffuser_a_encrypt(view, 512)

    assert hashlib.sha256(buffer).hexdigest() == "f58aa15c1219f893c4ed355d363d8f831bcc0c4a82c6bbffcca321aada9e86ec"

    elephant.diffuser_a_decrypt(view, 512)

    assert buffer == b"a" * 512


def test_crypto_elephant_diffuser_b() -> None:
    buffer = bytearray(b"a" * 512)
    view = memoryview(buffer)

    elephant.diffuser_b_encrypt(view, 512)

    assert hashlib.sha256(buffer).hexdigest() == "1d5a51ae0d0b6309f1f8661376af9ebd880b1274601f6841f5aaeb5273580133"

    elephant.diffuser_b_decrypt(view, 512)

    assert buffer == b"a" * 512


# Fixed vectors below were produced by the short independent reference in tests/crypto/elephant_reference.py.
# The reference itself is anchored to the public SHA-256 constants above, so these vectors do not depend on
# the implementation under test to generate their own expected answers.

KEY_128 = bytes.fromhex(
    "10730f695df62a49cd3aa1b1c9ae3edf2229c338a3740830e2b19d2b83f9cada"
    "268af0e0613921085edc89e1b804de354fd265acf4e5c410b47764bb9565666b"
)
KEY_256 = bytes.fromhex(
    "3a600625f8fd5cc506cf8b30c8ca0600cc32f0c6b54c140789f7518c4fb5c71b"
    "a272f34f1a920d5be247298b5d233ce6199023c24d0aefec28717232f9894d1f"
)
FORWARD_64 = bytes(range(64))
REVERSE_64 = bytes(range(63, -1, -1))
FORWARD_512 = bytes(range(256)) * 2
REVERSE_512 = bytes(range(255, -1, -1)) * 2

STAGE_VECTORS = [
    (
        "a_encrypt",
        elephant.diffuser_a_encrypt,
        FORWARD_64,
        (
            "9f7954528929fcc01cfe66302d30d0331baf4fd4ba83ea1fd8c64a1c0e47d6fc"
            "20f515635b2c32c419d79bf266afa3a665c0d6ab7746c6b2f1c602e798f69bda"
        ),
    ),
    (
        "a_decrypt",
        elephant.diffuser_a_decrypt,
        REVERSE_64,
        (
            "c295c60c7266e5c3d473e9aec657eecd0e8eec79b9b6aa57cffe0111e4bf22b0"
            "e20438e8930c66cd500834a0e9323d2e88c46c95cd6ce39f8cad895a4858e413"
        ),
    ),
    (
        "b_encrypt",
        elephant.diffuser_b_encrypt,
        FORWARD_64,
        (
            "d278e577df69eea48438756744f5d2baf605d67c751457960eb9afbbae92dbc7"
            "94eb8a45565750310572913f6a91b3a9147684c90ad1c90ea52baba2f83e624b"
        ),
    ),
    (
        "b_decrypt",
        elephant.diffuser_b_decrypt,
        REVERSE_64,
        (
            "0423ffe610e506050debfdeed6a29c1efc756ee2721bcf964c7e5450c53a1ece"
            "b5192cb1389173d83e8f23295be72d998cf990851945ffd4f6f7ab1e69043b75"
        ),
    ),
]

STAGE_512_VECTORS = [
    (
        "a_encrypt",
        elephant.diffuser_a_encrypt,
        FORWARD_512,
        "b719507d74076ba8a9450e0df55d561189de58652b5e289cdf5d51b4f6b7c021",
        "fd2842dd7d10c6dd61f11bd6d78aa7c4",
        "04a58670fc2410cf24022ed373d2c49f",
    ),
    (
        "a_decrypt",
        elephant.diffuser_a_decrypt,
        REVERSE_512,
        "41a0732e23ffb1d817bd3f356e9acd4cdf7f2c2af8228b60b57d662b118e1e84",
        "161df5c84751f9d94cc5110131fc3c5c",
        "4f0f3b2c6e3bb2effd03374e811b815e",
    ),
    (
        "b_encrypt",
        elephant.diffuser_b_encrypt,
        FORWARD_512,
        "9277a3790ae69449b25ecc5c48d7a99e6d331cb0215230dc4570291b067ddd5e",
        "c228d673f9a62c480b0eb21e149d9092",
        "c1058be7935c2fc8898ced514b391490",
    ),
    (
        "b_decrypt",
        elephant.diffuser_b_decrypt,
        REVERSE_512,
        "c875288c2aed965926583d297f10247b325712a661341f1da1c6722422b5d48f",
        "f30c050d17fe3f1aaaf731297249bbc3",
        "7153aa8b84241e67de0373490046813c",
    ),
]

FULL_SECTOR_VECTORS = [
    (
        128,
        0,
        "551c45182fa47b96d71064503ff72cc2c89e15e507ce6c4520f120962d28372e",
        "e74826353899c689523dcc6cbe92698e",
        "36942dc0c6b93787bab27a2498ef1321",
    ),
    (
        128,
        16,
        "9a4886bec97204eef4af03be7606348c990649ad6ac1321d88f91d2242e5341d",
        "88db4607e0d9935c739cc83a93eb5a28",
        "c14b5b80b883504a7533ac733ec84796",
    ),
    (
        128,
        32,
        "fe6fa5e15eeb0d42394b26dff69a4f608bf22d9df4f8dca59e77c559a1d42526",
        "68ef03bf59bc13ad2d121fdbc7519753",
        "8029297458c9194ee137b49b5929792a",
    ),
    (
        128,
        85072,
        "64aacba413f66b4bcec5a535eb6dea3e544dd83ed8e8510d2bfc1a37781ac19d",
        "b65581fc2a26a92fff58cb8c5900de8a",
        "c3f6782fc046a38b4916b22e43c6500a",
    ),
    (
        128,
        0x123456,
        "9c4bc098dac702489ad81695ad73bad23ab677fa10e61977499050b1bff7fd37",
        "bddc80c474881d08cccd916d1d78e345",
        "a52e268a8b4ccffc836de7006586ac1d",
    ),
    (
        256,
        0,
        "a2be78e5fd53c113f102f6f7e98625ef794063aa6c0dfa5c75584a7a91ffabfc",
        "be5e08f37248931a808d95af1b6c8f10",
        "f604508648b48af46d209a522400cc5e",
    ),
    (
        256,
        16,
        "f53a65ddd6fe2f38cc6ab8065686c8b3b088906cbd0e2c2ed7028010485aeb31",
        "f1cd196c9e02e0bc29c6d82b5b860433",
        "6d62f8e9c51a3ce4289f81bd806d136f",
    ),
    (
        256,
        32,
        "c4aec5e969475fdd110e3ce9f843cf8088515b4b2c70282aca3a1df541ea992a",
        "5e50c4cecbd0166d295e8bfe947aa339",
        "2946fda9e60eff0b6a58561a7c5ea789",
    ),
    (
        256,
        85072,
        "65f6857990fde2377cc82712a7befe530986c09f098d3489087837596342a1ae",
        "ddcfe57d583373be42bdbcb0d9867f02",
        "b7a604ebea35b64a6515663b28da2bc8",
    ),
    (
        256,
        0x123456,
        "273ffff4a0e7cf848f5d0c4de30b1320361b2f64158f9f63ee0571f1a7551da7",
        "88cd8b55f95693f3a1674d65d1f2977b",
        "4543b676f8697223480f71f5c39a7fea",
    ),
]

WRONG_KEY_DECRYPT_VECTORS = [
    (
        128,
        KEY_128,
        KEY_128[:32] + bytes(16) + KEY_128[48:],
        "a0799ae105a1086a47593c569b18f1dea48abe7401cc666d350591a6f05f1fa7",
        "a464a40fad76c559a5b9bfcae1250bcc",
    ),
    (
        128,
        KEY_128,
        KEY_128[32:48] + KEY_128[16:32] + KEY_128[0:16] + KEY_128[48:],
        "f21f60868b8ae80ebbbccb518aaa0802c9367f119ac09e744bdd95d2be39df6a",
        "5eb13e3d8d5f4f9b50b5a5a0b833fe05",
    ),
    (
        128,
        KEY_128,
        KEY_128[16:32] + bytes(16) + KEY_128[48:64] + bytes(16),
        "aadec63981f54e2ccd6733448006d15b81d405bf2751287521bca78ce502e819",
        "7cc2ea09a8e35af4addfc253424fe333",
    ),
    (
        256,
        KEY_256,
        KEY_256[:32] + bytes(32),
        "a386242c47a7b3d7ea0a2bb29360d90b9b08165aa97e69b1dd265e3f65fda484",
        "2195ca1bd2800433972ae103a6614f9d",
    ),
    (
        256,
        KEY_256,
        KEY_256[32:64] + KEY_256[0:32],
        "a8a05e5dfc999d17997e107ffcf4a55c4a5ba9e46e613f99da17c23e457bac52",
        "1a2cfae9f1aa41520c6c55314943fa93",
    ),
]


def _apply(func: Callable[[memoryview, int], None], data: bytes) -> bytes:
    buffer = bytearray(data)
    func(memoryview(buffer), len(data))
    return bytes(buffer)


def test_elephant_reference_matches_public_constants() -> None:
    assert hashlib.sha256(elephant_reference.diffuser_a_encrypt(b"a" * 512)).hexdigest() == (
        "f58aa15c1219f893c4ed355d363d8f831bcc0c4a82c6bbffcca321aada9e86ec"
    )
    assert hashlib.sha256(elephant_reference.diffuser_b_encrypt(b"a" * 512)).hexdigest() == (
        "1d5a51ae0d0b6309f1f8661376af9ebd880b1274601f6841f5aaeb5273580133"
    )


@pytest.mark.parametrize(
    ("name", "func", "data", "expected"),
    STAGE_VECTORS,
    ids=[v[0] for v in STAGE_VECTORS],
)
def test_crypto_elephant_stage_vectors_64(
    name: str, func: Callable[[memoryview, int], None], data: bytes, expected: str
) -> None:
    assert _apply(func, data).hex() == expected


@pytest.mark.parametrize(
    ("name", "func", "data", "digest", "head", "tail"),
    STAGE_512_VECTORS,
    ids=[v[0] for v in STAGE_512_VECTORS],
)
def test_crypto_elephant_stage_vectors_512(
    name: str,
    func: Callable[[memoryview, int], None],
    data: bytes,
    digest: str,
    head: str,
    tail: str,
) -> None:
    result = _apply(func, data)

    assert hashlib.sha256(result).hexdigest() == digest
    assert result[:16].hex() == head
    assert result[-16:].hex() == tail


@pytest.mark.parametrize(("encrypt", "decrypt"), [(elephant.diffuser_a_encrypt, elephant.diffuser_a_decrypt)])
def test_crypto_elephant_stage_a_roundtrip(encrypt: Callable[..., None], decrypt: Callable[..., None]) -> None:
    assert _apply(decrypt, _apply(encrypt, FORWARD_512)) == FORWARD_512


@pytest.mark.parametrize(("encrypt", "decrypt"), [(elephant.diffuser_b_encrypt, elephant.diffuser_b_decrypt)])
def test_crypto_elephant_stage_b_roundtrip(encrypt: Callable[..., None], decrypt: Callable[..., None]) -> None:
    assert _apply(decrypt, _apply(encrypt, FORWARD_512)) == FORWARD_512


@pytest.mark.parametrize(
    ("key_size", "sector", "digest", "head", "tail"),
    FULL_SECTOR_VECTORS,
    ids=[f"{v[0]}-{v[1]}" for v in FULL_SECTOR_VECTORS],
)
def test_crypto_elephant_full_sector_vectors(key_size: int, sector: int, digest: str, head: str, tail: str) -> None:
    key = KEY_128 if key_size == 128 else KEY_256
    cipher = create_cipher(f"aes-cbc-{key_size}-elephant", key)

    ciphertext = cipher.encrypt(FORWARD_512, sector)

    assert hashlib.sha256(ciphertext).hexdigest() == digest
    assert ciphertext[:16].hex() == head
    assert ciphertext[-16:].hex() == tail

    assert create_cipher(f"aes-cbc-{key_size}-elephant", key).decrypt(ciphertext, sector) == FORWARD_512


def test_crypto_elephant_same_plaintext_different_sector_number() -> None:
    for key_size, key in ((128, KEY_128), (256, KEY_256)):
        cipher = create_cipher(f"aes-cbc-{key_size}-elephant", key)

        ciphertext_16 = cipher.encrypt(FORWARD_512, 16)
        ciphertext_32 = create_cipher(f"aes-cbc-{key_size}-elephant", key).encrypt(FORWARD_512, 32)

        assert ciphertext_16 != ciphertext_32

        wrong_sector = create_cipher(f"aes-cbc-{key_size}-elephant", key).decrypt(ciphertext_16, 32)
        expected = (
            "08beff67d13b7dc6208b1a39ceeb08f1a85230f2da9f4198e4d7ceabdb9f61f3"
            if key_size == 128
            else "43bd8072b4dcb9f7d790feb42b61b9052cf0a7789a92abaf7e76f7761ec6e9f0"
        )
        assert hashlib.sha256(wrong_sector).hexdigest() == expected
        assert wrong_sector != FORWARD_512


@pytest.mark.parametrize(
    ("key_size", "key", "wrong_key", "digest", "head"),
    WRONG_KEY_DECRYPT_VECTORS,
    ids=[f"{v[0]}-{i}" for i, v in enumerate(WRONG_KEY_DECRYPT_VECTORS)],
)
def test_crypto_elephant_wrong_key_material(
    key_size: int, key: bytes, wrong_key: bytes, digest: str, head: str
) -> None:
    ciphertext = create_cipher(f"aes-cbc-{key_size}-elephant", key).encrypt(FORWARD_512, 16)

    wrong = create_cipher(f"aes-cbc-{key_size}-elephant", wrong_key).decrypt(ciphertext, 16)

    assert hashlib.sha256(wrong).hexdigest() == digest
    assert wrong[:16].hex() == head
    assert wrong != FORWARD_512
