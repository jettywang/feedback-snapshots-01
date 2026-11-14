import hashlib

import pytest

from .bip32 import (
    PathError,
    HARDENED,
    MAINNET_PRIVATE,
    MAINNET_PUBLIC,
    TESTNET_PRIVATE,
    TESTNET_PUBLIC,
    DepthOverflowError,
    ExtendedKey,
    ExtendedKeyParseError,
    ExtendedPrivateKey,
    ExtendedPublicKey,
    HardenedDerivationError,
    InvalidChildKey,
    InvalidExtendedKeyError,
    UnknownVersionError,
    master_from_seed,
    parse_path,
)
from . import bip32
from .errors import MalformedPointError
from .keys import SigningKey

SEED1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
SEED2 = bytes.fromhex(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
    "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
)
SEED3 = bytes.fromhex(
    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac"
    "ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
)
SEED4 = bytes.fromhex(
    "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"
)

VECTORS = [
    (
        SEED1,
        [
            (
                "m",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqji"
                "ChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2"
                "gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ),
            (
                "m/0'",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4"
                "cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP"
                "6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            ),
            (
                "m/0'/1",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSx"
                "qu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFH"
                "KkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            ),
            (
                "m/0'/1/2'",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWm"
                "T7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgq"
                "FJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            ),
            (
                "m/0'/1/2'/2",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Ty"
                "h8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJ"
                "AyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            ),
            (
                "m/0'/1/2'/2/1000000000",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8k"
                "mHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNT"
                "EcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            ),
        ],
    ),
    (
        SEED2,
        [
            (
                "m",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso"
                "3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSC"
                "Gu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            ),
            (
                "m/0",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT"
                "3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGm"
                "XUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            ),
            (
                "m/0/2147483647'",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYE"
                "eEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ8"
                "5ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            ),
            (
                "m/0/2147483647'/1",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd"
                "25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5Ew"
                "VvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz"
                "7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJ"
                "bZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw"
                "7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLF"
                "bdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
            ),
        ],
    ),
    (
        SEED3,
        [
            (
                "m",
                "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7"
                "KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhR"
                "oP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            ),
            (
                "m/0'",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu"
                "2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrAD"
                "WgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
            ),
        ],
    ),
    (
        SEED4,
        [
            (
                "m",
                "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7f"
                "RDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuy"
                "u5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
            ),
            (
                "m/0'",
                "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALm"
                "PXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xf"
                "FEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            ),
            (
                "m/0'/1'",
                "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJ"
                "eHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d8"
                "8n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
            ),
        ],
    ),
]


@pytest.mark.parametrize("seed,cases", VECTORS)
def test_official_bip32_vectors(seed, cases):
    master = master_from_seed(seed)
    for path, expected_private, expected_public in cases:
        node = master.derive_path(path)
        assert node.to_base58() == expected_private
        assert node.neuter().to_base58() == expected_public
        assert ExtendedPrivateKey.from_base58(expected_private) == node
        assert ExtendedPublicKey.from_base58(expected_public) == node.neuter()
        assert (
            node.to_bytes()
            == ExtendedKey.from_base58(expected_private).to_bytes()
        )


def test_derived_private_key_signs_for_derived_public_key():
    node = master_from_seed(SEED1).derive_path("m/0'/1")
    message = b"offline signing service"
    signature = node.private_key.sign_deterministic(
        message, hashfunc=hashlib.sha256
    )
    assert node.public_key.verify(signature, message, hashfunc=hashlib.sha256)


def _set_digest(monkeypatch, digest):
    def fake_hmac(key, data):
        return digest

    monkeypatch.setattr(bip32, "_hmac_sha512", fake_hmac)


def test_private_derivation_invalid_il_raises_and_does_not_retry(monkeypatch):
    from .curves import SECP256k1

    parent = master_from_seed(SEED1)
    bad_digest = SECP256k1.order.to_bytes(32, "big") + b"\x5a" * 32
    calls = []

    def fake_hmac(key, data):
        calls.append(data)
        return bad_digest

    monkeypatch.setattr(bip32, "_hmac_sha512", fake_hmac)
    with pytest.raises(InvalidChildKey) as excinfo:
        parent.derive(7)
    assert excinfo.value.index == 7
    assert "I_L >= curve order" in str(excinfo.value)
    assert len(calls) == 1
    assert calls[0][-4:] == b"\x00\x00\x00\x07"


def test_private_derivation_zero_child_raises(monkeypatch):
    from .curves import SECP256k1

    parent = master_from_seed(SEED1)
    tweak = (
        SECP256k1.order - parent.private_key.privkey.secret_multiplier
    ) % (SECP256k1.order)
    _set_digest(monkeypatch, tweak.to_bytes(32, "big") + b"\x00" * 32)
    with pytest.raises(InvalidChildKey) as excinfo:
        parent.derive(0)
    assert excinfo.value.index == 0
    assert "zero" in str(excinfo.value)


def test_public_derivation_invalid_il_raises_without_index_change(monkeypatch):
    from .curves import SECP256k1

    parent = master_from_seed(SEED1).neuter()
    _set_digest(
        monkeypatch, SECP256k1.order.to_bytes(32, "big") + b"\x00" * 32
    )
    with pytest.raises(InvalidChildKey) as excinfo:
        parent.derive(9)
    assert excinfo.value.index == 9
    assert "I_L >= curve order" in str(excinfo.value)
    assert parent.child_number == 0


def test_public_derivation_infinity_raises(monkeypatch):
    from .curves import SECP256k1

    private_parent = master_from_seed(SEED1)
    parent = private_parent.neuter()
    tweak = (
        -private_parent.private_key.privkey.secret_multiplier
    ) % SECP256k1.order
    _set_digest(monkeypatch, tweak.to_bytes(32, "big") + b"\x00" * 32)
    with pytest.raises(InvalidChildKey) as excinfo:
        parent.derive(11)
    assert excinfo.value.index == 11
    assert "infinity" in str(excinfo.value)


def test_master_invalid_il_raises(monkeypatch):
    from .curves import SECP256k1

    _set_digest(
        monkeypatch, SECP256k1.order.to_bytes(32, "big") + b"\x00" * 32
    )
    with pytest.raises(InvalidExtendedKeyError):
        master_from_seed(SEED1)

    _set_digest(monkeypatch, b"\x00" * 64)
    with pytest.raises(InvalidExtendedKeyError):
        master_from_seed(SEED1)


def test_non_hardened_private_and_public_paths_agree():
    master = master_from_seed(SEED1)
    private_child = master.derive_path("m/0/1/2/1000000000")
    public_child = master.neuter().derive_path("m/0/1/2/1000000000")
    assert private_child.neuter() == public_child
    assert private_child.public_key == public_child.public_key
    assert private_child.chain_code == public_child.chain_code
    assert private_child.parent_fingerprint == public_child.parent_fingerprint


def test_public_derivation_rejects_hardened_without_bit_clearing():
    master = master_from_seed(SEED1)
    public = master.neuter()
    for index in (HARDENED, HARDENED + 1, 0xFFFFFFFF):
        with pytest.raises(HardenedDerivationError) as excinfo:
            public.derive(index)
        assert excinfo.value.index == index
        assert "hardened" in str(excinfo.value)
    # Clearing the hardened bit is a different derivation, never a fallback.
    assert public.derive(0) != public
    assert public.derive(0) != public.derive(1)


def test_public_derive_path_rejects_hardened_component():
    public = master_from_seed(SEED1).neuter()
    with pytest.raises(HardenedDerivationError):
        public.derive_path("m/0/1'")
    with pytest.raises(HardenedDerivationError):
        public.derive_path("m/0H/1")


def test_hardened_private_path_matches_official_prefix():
    master = master_from_seed(SEED1)
    assert master.derive_path("m/0'").child_number == HARDENED
    assert master.derive_path("m/0'").neuter().to_base58().startswith("xpub")


def test_parse_path_accepts_markers_and_relative_paths():
    assert parse_path("m") == ()
    assert parse_path("m/0'/1/2h/3H") == (
        HARDENED,
        1,
        HARDENED + 2,
        HARDENED + 3,
    )
    assert parse_path("0'/1") == (HARDENED, 1)
    assert parse_path("0") == (0,)
    assert parse_path("M/0") == (0,)
    with pytest.raises(PathError):
        parse_path("")


@pytest.mark.parametrize(
    "path",
    [
        "m/",
        "m//0",
        "/0",
        "m/0''",
        "m/0'h",
        "m/+1",
        "m/-1",
        "m/1.0",
        "m/ 1",
        "m/1 ",
        "m/0x10",
        "m/2147483648",
        "m/4294967296",
        "m/'",
        "m/1\N{REGIONAL INDICATOR SYMBOL LETTER A}",
    ],
)
def test_parse_path_rejects_malformed_components(path):
    with pytest.raises(PathError):
        parse_path(path)


def test_parse_path_rejects_absolute_path_on_non_root():
    node = master_from_seed(SEED1).derive(0)
    with pytest.raises(PathError):
        node.derive_path("m/1")
    assert node.derive_path("1") != node


def test_parse_path_integer_iterables_allow_full_range():
    assert parse_path([0, 1, HARDENED, 0xFFFFFFFF]) == (
        0,
        1,
        HARDENED,
        0xFFFFFFFF,
    )
    with pytest.raises(ValueError):
        parse_path([0x100000000])


def test_derive_rejects_out_of_range_index():
    node = master_from_seed(SEED1)
    for index in (-1, 0x100000000, 1.5, True):
        with pytest.raises((ValueError, TypeError)):
            node.derive(index)


def test_depth_overflow_is_explicit():
    node = master_from_seed(SEED1)
    deep = node
    digest = b"\x01" * 64
    original = bip32._hmac_sha512
    bip32._hmac_sha512 = lambda key, data: digest
    try:
        while deep.depth < 255:
            deep = deep.derive(0)
        assert deep.depth == 255
        with pytest.raises(DepthOverflowError):
            deep.derive(0)
        with pytest.raises(DepthOverflowError):
            deep.neuter().derive(0)
    finally:
        bip32._hmac_sha512 = original


def test_master_requires_seed_length_in_bip32_range():
    for seed in (b"", b"\x00" * 15, b"\x00" * 65):
        with pytest.raises(ValueError):
            master_from_seed(seed)
    assert master_from_seed(b"\x00" * 16).depth == 0
    assert master_from_seed(b"\x00" * 64).depth == 0


def test_master_seed_accepts_bytes_like_and_rejects_text():
    assert master_from_seed(bytearray(SEED1)) == master_from_seed(SEED1)
    assert master_from_seed(memoryview(SEED1)) == master_from_seed(SEED1)
    with pytest.raises(TypeError):
        master_from_seed("not bytes")


def test_testnet_versions_and_round_trip():
    master = master_from_seed(SEED1, network="testnet")
    assert master.version == TESTNET_PRIVATE
    assert master.neuter().version == TESTNET_PUBLIC
    assert master.to_base58().startswith("tprv")
    assert master.neuter().to_base58().startswith("tpub")
    assert ExtendedPrivateKey.from_base58(master.to_base58()) == master
    assert (
        ExtendedPublicKey.from_base58(master.neuter().to_base58())
        == master.neuter()
    )
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedPrivateKey.from_base58(master.neuter().to_base58())
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedPublicKey.from_base58(master.to_base58())
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedPrivateKey.from_bytes(master.neuter().to_bytes())
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedPublicKey.from_bytes(master.to_bytes())

    with pytest.raises(ValueError):
        master_from_seed(SEED1, network="regtest")
    with pytest.raises(ValueError):
        ExtendedPublicKey(master.public_key, b"\x00" * 32, "unknown")


def test_network_is_preserved_across_derivation_and_neutering():
    master = master_from_seed(SEED1, network="testnet")
    child = master.derive_path("m/0/1")
    assert child.network == "testnet"
    assert child.neuter().network == "testnet"
    assert child.neuter().derive(2).network == "testnet"


def test_public_key_parsing_rejects_bad_prefix_and_bad_point():
    master = master_from_seed(SEED1).neuter()
    payload = master.to_bytes()
    for key_data in (
        b"\x04" + b"\x11" * 32,
        b"\x01" + b"\x11" * 32,
        b"\x02" + b"\x00" * 31 + b"\x07",
    ):
        broken = payload[:45] + key_data
        with pytest.raises(InvalidExtendedKeyError):
            ExtendedKey.from_bytes(broken)


def test_private_payload_prefix_and_scalar_range():
    master = master_from_seed(SEED1)
    payload = master.to_bytes()
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(payload[:45] + b"\x01" + payload[46:])
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(payload[:45] + b"\x00" + b"\x00" * 32)
    n = __import__("ecdsa").curves.SECP256k1.order
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(payload[:45] + b"\x00" + n.to_bytes(32, "big"))


def test_private_version_with_public_payload_is_rejected():
    master = master_from_seed(SEED1)
    private_payload = master.to_bytes()
    public_payload = master.neuter().to_bytes()
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(private_payload[:45] + public_payload[45:])
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(
            public_payload[:45] + b"\x00" + private_payload[46:]
        )


def test_unknown_version_is_rejected():
    payload = bytearray(master_from_seed(SEED1).to_bytes())
    payload[0:4] = b"\x01\x02\x03\x04"
    with pytest.raises(UnknownVersionError):
        ExtendedKey.from_bytes(bytes(payload))


def test_depth_zero_consistency_checks():
    master = master_from_seed(SEED1)
    payload = bytearray(master.to_bytes())
    payload[4] = 0
    payload[5:9] = b"\x00\x00\x00\x01"
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(bytes(payload))

    payload = bytearray(master.to_bytes())
    payload[4] = 0
    payload[9:13] = b"\x00\x00\x00\x01"
    with pytest.raises(InvalidExtendedKeyError):
        ExtendedKey.from_bytes(bytes(payload))

    with pytest.raises(InvalidExtendedKeyError):
        ExtendedPrivateKey(
            master.private_key.privkey.secret_multiplier,
            b"\x00" * 32,
            depth=0,
            parent_fingerprint=b"\x00\x00\x00\x01",
        )


def test_bad_checksum_and_base58_errors():
    master = master_from_seed(SEED1)
    encoded = master.to_base58()
    with pytest.raises(ExtendedKeyParseError):
        ExtendedKey.from_base58(
            encoded[:-1] + ("2" if encoded[-1] != "2" else "3")
        )
    with pytest.raises(ExtendedKeyParseError):
        ExtendedKey.from_base58("0" + encoded)
    with pytest.raises(ExtendedKeyParseError):
        ExtendedKey.from_base58("1")
    with pytest.raises(ExtendedKeyParseError):
        ExtendedKey.from_bytes(master.to_bytes()[:-1])
    with pytest.raises(ExtendedKeyParseError):
        ExtendedKey.from_bytes(master.to_bytes() + b"\x00")


def test_constructor_validation():
    master = master_from_seed(SEED1)
    with pytest.raises(ValueError):
        ExtendedPrivateKey(0, b"\x00" * 32)
    with pytest.raises(ValueError):
        ExtendedPrivateKey(1, b"\x00" * 31)
    with pytest.raises(ValueError):
        ExtendedPublicKey(master.public_key, b"\x00" * 31)
    with pytest.raises(ValueError):
        ExtendedPrivateKey(1, b"\x00" * 32, depth=256)
    with pytest.raises(ValueError):
        ExtendedPrivateKey(1, b"\x00" * 32, parent_fingerprint=b"\x00" * 3)
    with pytest.raises(ValueError):
        ExtendedPrivateKey(1, b"\x00" * 32, child_number=0x100000000)
    with pytest.raises(TypeError):
        ExtendedPublicKey(SigningKey.generate(), b"\x00" * 32)


def test_serialized_parent_fingerprint_is_locator_not_authentication():
    master = master_from_seed(SEED1)
    child = master.derive(0)
    assert child.parent_fingerprint == master.fingerprint
    assert len(master.fingerprint) == 4
    # A serialized child carries the parent's fingerprint without a signature.
    parsed = ExtendedPrivateKey.from_base58(child.to_base58())
    assert parsed.parent_fingerprint == master.fingerprint
    # Because there is no signature over the fingerprint field, changing it
    # does not make the node invalid; fingerprint is identity data, not auth.
    payload = bytearray(child.to_bytes())
    payload[5:9] = b"\xde\xad\xbe\xef"
    parsed_other = ExtendedPrivateKey.from_bytes(bytes(payload))
    assert parsed_other.fingerprint == child.fingerprint
    assert parsed_other.chain_code == child.chain_code
    assert parsed_other.private_key == child.private_key
    assert parsed_other.derive(1).public_key == child.derive(1).public_key


def test_parent_extended_public_plus_child_private_recovers_parent_private():
    """Known BIP32 risk, asserted to keep it visible in test output."""
    from .curves import SECP256k1

    master = master_from_seed(SEED1)
    parent_public = master.neuter()
    child = master.derive(42)
    child_private = child.private_key.privkey.secret_multiplier

    data = parent_public.public_key.to_string("compressed") + bip32._ser32(42)
    digest = bip32._hmac_sha512(parent_public.chain_code, data)
    tweak = int.from_bytes(digest[:32], "big")
    recovered = (child_private - tweak) % SECP256k1.order
    assert recovered == master.private_key.privkey.secret_multiplier


def test_example_permissions_are_part_of_public_api():
    master = master_from_seed(SEED1)
    watcher = master.neuter()
    signed = master.derive(1).private_key.sign_deterministic(b"payload")
    assert watcher.derive(1).public_key.verify(signed, b"payload")
    with pytest.raises(HardenedDerivationError):
        watcher.derive(HARDENED + 1)


INVALID_EXTENDED_KEYS = [
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LB"
        "pB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
        "GTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        InvalidExtendedKeyError,
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Tx"
        "nt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
        "GpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        InvalidExtendedKeyError,
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8"
        "ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
        "AzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fh"
        "ZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        InvalidExtendedKeyError,
    ),
    (
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX"
        "27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acD"
        "yL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        InvalidExtendedKeyError,
    ),
    (
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvh"
        "pebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        InvalidExtendedKeyError,
    ),
    (
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8Xnmdf"
        "HGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        UnknownVersionError,
    ),
    (
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8Xnmdf"
        "HPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        UnknownVersionError,
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
        "93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF"
        "AzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        InvalidExtendedKeyError,
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5"
        "JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        InvalidExtendedKeyError,
    ),
    (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiC"
        "hkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        ExtendedKeyParseError,
    ),
]


@pytest.mark.parametrize(
    "encoded,error",
    INVALID_EXTENDED_KEYS,
    ids=range(len(INVALID_EXTENDED_KEYS)),
)
def test_official_invalid_extended_keys(encoded, error):
    with pytest.raises(error):
        ExtendedKey.from_base58(encoded)


def test_invalid_child_does_not_consume_or_wrap_index():
    """Repeated invalid derivations keep the exact requested index."""
    master = master_from_seed(SEED1)
    original = bip32._hmac_sha512
    calls = []

    def fake_hmac(key, data):
        calls.append(data[-4:])
        return b"\xff" * 64

    bip32._hmac_sha512 = fake_hmac
    try:
        for index in (0, 1, 2):
            with pytest.raises(InvalidChildKey) as excinfo:
                master.derive(index)
            assert excinfo.value.index == index
    finally:
        bip32._hmac_sha512 = original
    assert calls == [
        bytes([0, 0, 0, 0]),
        bytes([0, 0, 0, 1]),
        bytes([0, 0, 0, 2]),
    ]


def test_child_index_is_serialized_big_endian_and_parent_links():
    master = master_from_seed(SEED1)
    child = master.derive(0x01020304)
    assert child.to_bytes()[9:13] == b"\x01\x02\x03\x04"
    assert child.to_bytes()[5:9] == master.fingerprint
    assert child.depth == master.depth + 1
    assert child.chain_code != master.chain_code
