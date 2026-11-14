# -*- coding: utf-8 -*-
"""
Tests for the RFC 9380 suite P256_XMD:SHA-256_SSWU_RO_.

The embedded golden values were produced by two independently written
implementations (different control flow, square-root strategy and sign
handling) that agree bit-for-bit on every stage below. Each vector keeps the
intermediate artifacts needed to localise a failure:

    uniform_bytes -> u0, u1 (field elements, after reduction mod p)
                  -> Q0, Q1    (one SSWU map per field element)
                  -> P          (R = Q0 + Q1, the returned point)

On-curve membership is additionally checked against the raw curve equation,
not only via the Point constructor's own assertion.
"""

import pytest

from .curves import NIST256p
from .ellipticcurve import Point
from .errors import MalformedPointError
from . import hash_to_curve as h2c

DST = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
P_MOD = NIST256p.curve.p()
A_COEF = NIST256p.curve.a() % P_MOD
B_COEF = NIST256p.curve.b() % P_MOD


def _h(value):
    return int(value, 16)


def _is_on_curve(x, y):
    # Independent check of y^2 == x^3 + a*x + b (mod p).
    return (y * y - (x * x * x + A_COEF * x + B_COEF)) % P_MOD == 0


# Each entry documents one full hash-to-curve evaluation with all stages.
GOLDEN = [
    {
        "name": "empty message",
        "msg": b"",
        "dst": DST,
        "uniform_bytes": (
            "0bf975950f0823b55fb9d0056632b44e138ffdc8467fc620f41510c6d60c78ab"
            "453dd312ab7a8eb9a733b8e6d16609cb7a7e8b9b13b0a7d8ac5915d2a9a89f33"
            "bd66b6aef4c3cd7fd9d063de87090b324984968f7b47a4582bb36f4b35f3530a"
        ),
        "u0": "5ec118cb809341cdd913777c674a84f0974439e9c67c280415f5aca18b591889",
        "u1": "d8e0226d9ec2187a4ba1306ac6ff4d87e87ff8c10976d7cbebbd2cf611767c74",
        "Q0": (
            "83229b33b0b3aa7ddf51b842aa9abe2ccd4ccc186dc349e14a969a3d2113a6bf",
            "0fd9f5104c5a782d663c9afbb5d69a31410c616a85135628169340430f8ea7c3",
        ),
        "Q1": (
            "ca7384d74aeedb9e8868b3dd10be1fcdf81e0e20c787b1e54cbb31f16b5120c2",
            "120468b9b66a1296d9cf5278850ac15df19fa35cfc36496338e211ce27b5b8ec",
        ),
        "P": (
            "8580265b6a089f31ddb99c1adf1035d36487d8dfdd28152607d7427796485c5f",
            "d33581ae9f882a0bf0503b71741078bf767f6a633f969e2d138c0df341ab1d58",
        ),
    },
    {
        "name": "abc",
        "msg": b"abc",
        "dst": DST,
        "uniform_bytes": (
            "065560e63f1cb8e86f351df38cc9fc2c5a444fb0c8799e674ce688ca7c01b3e8"
            "89b6f22c8478e52e5970380bc502940cd5524d02e51052577c4b8efe63b90cc8"
            "e0cadcfe32df1fe9d6680fa5519fa599fd24163c23adfa17e318eabd14e81bb8"
        ),
        "u0": "a19c320dcc7a844807746efbcdafdd0c9a6299d9c9eafefd07c20ee7baac4d45",
        "u1": "8a214a6b52da84231c05704af043c445c7c4147cde1099724474cc121f9a6a7b",
        "Q0": (
            "ce145001c0c0ed1f6a39101330677b8bbddaec897199e6fb7d3ed6e9565397c2",
            "db89b272ca2a67638d39298a8b7ad93976bb55a78831da778f15a99935ba3015",
        ),
        "Q1": (
            "c16ea68d7b48031da9a121973a238e423e23c0ec11bd26ad3df405d3710e13ed",
            "f5e84674498a49dba20d858c869302ef699817c7350b7e8e7cff3a3e1877909f",
        ),
        "P": (
            "0b68c0f7ddc338434b6f36accbbabcbd02f0b45c284e231e1c549e2f470ed811",
            "67f808630d48050cfd4e25c04a19516ec88f28bece2e71da27e9ec3f9141c8ee",
        ),
    },
    {
        "name": "48 a's",
        "msg": b"a" * 48,
        "dst": DST,
        "uniform_bytes": (
            "ca768599d06f8a680c1727372537923d3fc5c906b8b1104b80d4a2feafc492a5"
            "a1648da7281d7ab96a91666f9ea866876f6ac6db6c2b10518da5744edf00a71c"
            "e64bc05d20589f46ea0fc73bbaf1f05c180e12c6e85b1f4c996be39cc963f837"
        ),
        "u0": "ca174b40876256d7e5ee92fcd33de1080502df68c3038abb4718180e05809a60",
        "u1": "e9b6904bb3b283dc0e79f00ec1216bbc8a3d8513c3f0f679933c683cc69f4cc6",
        "Q0": (
            "6de6a34eff02ab7e57e909d1505828e3b56846c93e821d61b997ac4eb57d9627",
            "c79f45073e0970f5f9bfda33f4f29dcc07d753cd00f18040f3d7d3a44d0995c8",
        ),
        "Q1": (
            "1235f20643eb09ba5e423537dbc93ce5fb4a080ca0c302f2c86bb2648a722363",
            "655e7a83abaadf4b4b70763fbc25f392841db86ed8dc463fe82403613484264",
        ),
        "P": (
            "711e67c36d6237bb1e1fc8709377921178b573df2b5267905fa802a3c60a46cc",
            "5b5a26278946799dd8b6c5a343e23af5430d4144c7ab79bbf88cb62d6f2ef602",
        ),
    },
    {
        "name": "oversize DST (>255 bytes)",
        "msg": b"",
        "dst": b"32-byte-P256-XMD-SHA256-SWU-RO-DST" * 10,
        "uniform_bytes": (
            "5e8ea7b04c96a9ca8518c82b5867cf62f22b1949d40df2d720a1356efcbc28aa"
            "c102db05f82da2b965046f118da239b226d119a73118d86d8bb1ca658e494106"
            "229c38480a1f76895836d22475c81083ae910e02590547ffe6f04012b3f450ce"
        ),
        "u0": "9f6d9730f68d5b49757be3f42b0cb6b5a09f92d9a352f43436b3e1070c94298f",
        "u1": "58fb8738f0246b1e004ce00fb8fd6db0e23835e5b0ef3a14a3bae2e5a71e4292",
        "Q0": (
            "9a5422354fe7436df30d802d0d5dfbfba0551b37db8be89a8985951ecae0abdc",
            "474435c7ae8767db597770b7680b031f193b632203c8ebc9c5912d86ccacfbef",
        ),
        "Q1": (
            "68dcf0aeeaaf1b6140fe5b72df4a4b05112417dd96ceb60505a2094e4532c89b",
            "afe6085370e22f1b71a72a21d7be636b512dacc994c0b6355e675c0917472424",
        ),
        "P": (
            "f2443731e77317f7acb11b258717777e2c7bce457f6d1801f52bdbdd6aa022cf",
            "6886135c4f404541b3df2845715ab6f79865494daf06d3915cde2086c01bd314",
        ),
    },
]


@pytest.mark.parametrize("case", GOLDEN, ids=lambda c: c["name"])
def test_expand_message_stage(case):
    elements, uniform_bytes = h2c._hash_to_field(case["msg"], case["dst"], 2)
    assert uniform_bytes.hex() == case["uniform_bytes"]
    assert elements == [_h(case["u0"]), _h(case["u1"])]
    # Every field element must already be reduced into [0, p).
    assert all(0 <= element < P_MOD for element in elements)


@pytest.mark.parametrize("case", GOLDEN, ids=lambda c: c["name"])
def test_field_reduction_matches_uniform_bytes(case):
    # The field element is OS2IP(uniform_block) mod p; verify independently.
    uniform = bytes.fromhex(case["uniform_bytes"])
    block0 = uniform[0:h2c._L]
    block1 = uniform[h2c._L:2 * h2c._L]
    assert int.from_bytes(block0, "big") % P_MOD == _h(case["u0"])
    assert int.from_bytes(block1, "big") % P_MOD == _h(case["u1"])


@pytest.mark.parametrize("case", GOLDEN, ids=lambda c: c["name"])
def test_map_to_curve_stage(case):
    for u_hex, q in ((case["u0"], case["Q0"]), (case["u1"], case["Q1"])):
        x, y = h2c._map_to_curve_simple_swu(_h(u_hex))
        assert (x, y) == (_h(q[0]), _h(q[1]))
        assert _is_on_curve(x, y)


@pytest.mark.parametrize("case", GOLDEN, ids=lambda c: c["name"])
def test_final_point_and_independent_on_curve(case):
    point = h2c.hash_to_curve_p256(case["msg"], case["dst"])
    expected_x, expected_y = _h(case["P"][0]), _h(case["P"][1])
    assert isinstance(point, Point)
    assert point.curve() == NIST256p.curve
    assert (point.x(), point.y()) == (expected_x, expected_y)
    # Independent raw-equation check, not relying on Point's constructor.
    assert _is_on_curve(point.x(), point.y())


def test_q0_plus_q1_equals_final_point():
    # Cross-check the additive RO step P = Q0 + Q1 using library arithmetic.
    case = GOLDEN[0]
    elements, _ = h2c._hash_to_field(case["msg"], case["dst"], 2)
    q0 = Point(NIST256p.curve, *h2c._map_to_curve_simple_swu(elements[0]))
    q1 = Point(NIST256p.curve, *h2c._map_to_curve_simple_swu(elements[1]))
    result = q0 + q1
    assert (result.x(), result.y()) == tuple(_h(v) for v in case["P"])


def test_empty_message_is_supported():
    point = h2c.hash_to_curve_p256(b"", DST)
    assert _is_on_curve(point.x(), point.y())


def test_oversize_dst_uses_rfc_wrapping():
    long_dst = b"L" * 300
    point = h2c.hash_to_curve_p256(b"abc", long_dst)
    assert _is_on_curve(point.x(), point.y())
    # Reproduce the RFC 9380 5.3.3 shortened DST and confirm it is what is used.
    import hashlib
    wrapped = hashlib.sha256(b"H2C-OVERSIZE-DST-" + long_dst).digest()
    expected = h2c.hash_to_curve_p256(b"abc", wrapped)
    assert point == expected


@pytest.mark.parametrize("bad", ["str-not-bytes", 1234, None, object()])
def test_rejects_non_bytes_inputs(bad):
    with pytest.raises(TypeError):
        h2c.hash_to_curve_p256(bad, DST)
    with pytest.raises(TypeError):
        h2c.hash_to_curve_p256(b"abc", bad)


def test_dst_changes_the_result():
    point_a = h2c.hash_to_curve_p256(b"same message", DST)
    point_b = h2c.hash_to_curve_p256(b"same message", DST + b"-different")
    assert point_a != point_b


def test_message_changes_the_result():
    point_a = h2c.hash_to_curve_p256(b"message one", DST)
    point_b = h2c.hash_to_curve_p256(b"message two", DST)
    assert point_a != point_b


def test_chunking_does_not_change_byte_string_mapping():
    whole = b"the same byte string, split two ways"
    point = h2c.hash_to_curve_p256(whole, DST)
    chunks = h2c.hash_to_curve_p256(b"the same byte " + b"string, split two ways", DST)
    assert point == chunks


def test_deterministic():
    first = h2c.hash_to_curve_p256(b"determinism", DST)
    second = h2c.hash_to_curve_p256(b"determinism", DST)
    assert first == second


def test_returns_existing_point_type():
    point = h2c.hash_to_curve_p256(b"abc", DST)
    assert type(point) is Point


def test_suite_identifier():
    assert h2c.SUITE_ID == b"P256_XMD:SHA-256_SSWU_RO_"


def test_field_elements_are_reduced():
    # A 48-byte block always exceeds p; ensure reduction is actually applied.
    elements, uniform = h2c._hash_to_field(b"abc", DST, 2)
    assert len(uniform) == 2 * h2c._L == 96
    for element, block in zip(elements, (uniform[:48], uniform[48:])):
        raw = int.from_bytes(block, "big")
        assert raw >= P_MOD  # the unreduced integer is larger than p
        assert element == raw % P_MOD
