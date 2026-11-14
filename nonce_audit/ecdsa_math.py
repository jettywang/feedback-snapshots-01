"""ECDSA 签名验证与 nonce 重用推导（纯离线算术）。"""

from __future__ import annotations

from dataclasses import dataclass

from ecdsa import rfc6979
from math import gcd

from ecdsa.numbertheory import inverse_mod

from .curves import CurveInfo, point_is_infinity, scalar_multiply


@dataclass(frozen=True)
class Signature:
    r: int
    s: int


def is_low_s(s: int, order: int) -> bool:
    return s <= order // 2


def normalize_low_s(s: int, order: int) -> int:
    """返回 low-S 规范形式（不修改原值，只用于比较/分组）。"""
    return s if is_low_s(s, order) else order - s


def valid_scalar(value: int, order: int) -> bool:
    return 1 <= value < order


def verify_signature(
    info: CurveInfo, z: int, sig: Signature, public_point
) -> bool:
    """标准 ECDSA 验证，r/s 越界或分母不可逆都返回 False，不抛异常。"""
    order = info.order
    if not (valid_scalar(sig.r, order) and valid_scalar(sig.s, order)):
        return False
    s_inv = strict_inverse(sig.s, order)
    if s_inv is None:
        return False
    u1 = (z * s_inv) % order
    u2 = (sig.r * s_inv) % order
    point = u1 * info.curve.generator + u2 * public_point
    if point_is_infinity(point):
        return False
    return point.x() % order == sig.r


def sign_with_k(
    info: CurveInfo, private_key: int, z: int, k: int
) -> Signature:
    """用调用方指定的 nonce k 生成 ECDSA 签名（用于合成故障样本）。"""
    order = info.order
    if not valid_scalar(private_key, order):
        raise ValueError("私钥标量越界")
    if not valid_scalar(k, order):
        raise ValueError("nonce k 越界")
    point = scalar_multiply(info, k)
    if point_is_infinity(point):
        raise ValueError("k*G 为无穷远点，无法签名")
    r = point.x() % order
    if r == 0:
        raise ValueError("r 为 0，请更换 k")
    s = (inverse_mod(k, order) * (z + private_key * r)) % order
    if s == 0:
        raise ValueError("s 为 0，请更换 k")
    return Signature(r, s)


def deterministic_k(
    info: CurveInfo, private_key: int, digest: bytes, hash_func
) -> int:
    """RFC 6979 确定性 k，供健康对照样本使用。"""
    return rfc6979.generate_k(info.order, private_key, hash_func, digest)


@dataclass(frozen=True)
class DerivedCandidate:
    """一对签名在给定 s 方向组合下推导出的候选秘密。"""

    k: int
    d: int
    s1_orientation: str  # "as-is" 或 "flipped"
    s2_orientation: str


def derive_candidates(
    info: CurveInfo,
    z1: int,
    sig1: Signature,
    z2: int,
    sig2: Signature,
):
    """枚举两条同 r 签名在 4 种 s 方向组合下的 (k, d) 候选。

    ECDSA: s = k^-1 (z + d r) (mod n)
      同 r 意味着共享同一个点 R，因此共享 k 或 n-k；
      两条签名的 s 都可能因 low-S 规范化被取反。
      对方向 e1, e2 ∈ {+1, -1}，令 S_i = e_i * s_i:
        d = (S2*z1 - S1*z2) / (r*(S1 - S2)) (mod n)
        k = (z1 + d*r) / S1                  (mod n)
    分母不可逆时跳过该组合并记录原因，由调用方汇总。
    """
    order = info.order
    r = sig1.r
    candidates = []
    invertible = True

    for orient1, s1 in (("as-is", sig1.s), ("flipped", (-sig1.s) % order)):
        for orient2, s2 in (("as-is", sig2.s), ("flipped", (-sig2.s) % order)):
            denom_d = (r * (s1 - s2)) % order
            inv_denom = strict_inverse(denom_d, order)
            inv_s1 = strict_inverse(s1, order)
            if inv_denom is None or inv_s1 is None:
                invertible = False
                continue
            d = ((s2 * z1 - s1 * z2) * inv_denom) % order
            k = ((z1 + d * r) * inv_s1) % order
            if not valid_scalar(d, order) or not valid_scalar(k, order):
                continue
            candidates.append(
                DerivedCandidate(
                    k=k,
                    d=d,
                    s1_orientation=orient1,
                    s2_orientation=orient2,
                )
            )
    return candidates, invertible


def strict_inverse(value: int, modulus: int):
    """返回 value 在模 modulus 下的逆；不可逆（gcd != 1）时返回 None。"""
    value %= modulus
    if value == 0 or gcd(value, modulus) != 1:
        return None
    return inverse_mod(value, modulus)
