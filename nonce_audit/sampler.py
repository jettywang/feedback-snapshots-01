"""合成故障样本生成器（仅用于授权测试与自检）。

所有私钥在本地由种子化 RNG 生成，样本文件默认不写入私钥；
--emit-private 仅用于本地交叉验证，输出文件应按敏感材料管理。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from ecdsa import SigningKey

from .curves import CurveInfo, key_fingerprint, truncate_digest
from .ecdsa_math import (
    Signature,
    deterministic_k,
    is_low_s,
    normalize_low_s,
    sign_with_k,
)


def _z(digest: bytes, order: int) -> int:
    return truncate_digest(digest, order)


@dataclass
class GeneratedKey:
    sk: SigningKey
    fingerprint: str
    private_scalar: int


def make_key(info: CurveInfo, rng: random.Random) -> GeneratedKey:
    sk = SigningKey.generate(curve=info.curve, entropy=rng.randbytes)
    return GeneratedKey(
        sk=sk,
        fingerprint=key_fingerprint(sk.get_verifying_key()),
        private_scalar=sk.privkey.secret_multiplier,
    )


def digest_of(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def _entry(record_id: str, info: CurveInfo, key: GeneratedKey, digest: bytes,
           sig: Signature) -> dict:
    vk = key.sk.get_verifying_key()
    point = vk.pubkey.point
    return {
        "id": record_id,
        "curve": info.name,
        "public_key": {"x": point.x(), "y": point.y()},
        "digest": digest.hex(),
        "r": sig.r,
        "s": sig.s,
    }


def build_demo_sample(rng_seed: int = 20261115) -> dict:
    """构造覆盖全部判定分支的演示样本（P-256）。"""
    from .curves import get_curve

    info = get_curve("NIST256p")
    order = info.order
    rng = random.Random(rng_seed)

    faulty = make_key(info, rng)       # A: nonce 重用故障签名器
    healthy = make_key(info, rng)      # B: RFC6979 健康签名器
    collision = make_key(info, rng)    # C: 与 A 撞 r 的不相关钥匙
    broken = make_key(info, rng)       # D: 日志摘要损坏
    stuck = make_key(info, rng)        # E: 同 k 同消息 + 不可逆分母对照

    records: list[dict] = []
    private_notes: dict[str, int] = {}

    # --- A: 固定 k 签两条不同消息（核心确认用例），第二条做 low-S 翻转 ---
    fixed_k = 1 + rng.randrange(order - 2)
    d1 = digest_of(b"faulty-message-alpha")
    d2 = digest_of(b"faulty-message-beta")
    sig_a1 = sign_with_k(info, faulty.private_scalar, _z(d1, order), fixed_k)
    sig_a2 = sign_with_k(info, faulty.private_scalar, _z(d2, order), fixed_k)
    if is_low_s(sig_a2.s, order):
        sig_a2 = Signature(sig_a2.r, order - sig_a2.s)
    records.append(_entry("A1-reused-k", info, faulty, d1, sig_a1))
    records.append(_entry("A2-reused-k-lowS", info, faulty, d2, sig_a2))

    # A1 的完全重复记录（重复日志，不应被当作新证据）
    records.append(_entry("A1-duplicate", info, faulty, d1, sig_a1))

    # 第三条同 k 不同消息，验证多配对共识
    d3 = digest_of(b"faulty-message-gamma")
    sig_a3 = sign_with_k(info, faulty.private_scalar, _z(d3, order), fixed_k)
    records.append(_entry("A3-reused-k", info, faulty, d3, sig_a3))

    # --- B: 健康签名器，RFC6979 不同 k，r 互不相同（应无告警） ---
    for idx, msg in enumerate(["ok-one", "ok-two", "ok-three"], 1):
        digest = digest_of(msg.encode())
        k = deterministic_k(
            info, healthy.private_scalar, digest, hashlib.sha256
        )
        sig = sign_with_k(info, healthy.private_scalar, _z(digest, order), k)
        records.append(_entry(f"B{idx}-healthy", info, healthy, digest, sig))

    # --- C: 独立钥匙刻意构造与 A 相同的 r（跨钥匙碰撞，不能确认） ---
    # R=k*G 与 (n-k)*G 关于 x 轴对称，x 坐标相同 → r 相同。
    r_shared = sig_a1.r
    k_c = (order - fixed_k) % order
    d4 = digest_of(b"collision-other-key-message")
    sig_c = sign_with_k(info, collision.private_scalar, _z(d4, order), k_c)
    assert sig_c.r == r_shared
    records.append(_entry("C1-cross-key-r", info, collision, d4, sig_c))

    # --- D: 真实签名有效，但日志里的摘要被篡改 → 验证失败 ---
    real_digest = digest_of(b"digest-will-be-corrupted")
    sig_d = sign_with_k(
        info,
        broken.private_scalar,
        _z(real_digest, order),
        1 + rng.randrange(order - 2),
    )
    corrupted = digest_of(b"different-thing-logged")
    records.append(_entry("D1-corrupt-digest", info, broken, corrupted, sig_d))

    # --- E: 同 k 同消息两条，其中一条 s 翻转造成"自然分母不可逆"对照 ---
    d5 = digest_of(b"stuck-same-message")
    k_e = 1 + rng.randrange(order - 2)
    sig_e1 = sign_with_k(info, stuck.private_scalar, _z(d5, order), k_e)
    sig_e2 = Signature(sig_e1.r, normalize_low_s(sig_e1.s, order))
    records.append(_entry("E1-same-msg", info, stuck, d5, sig_e1))
    records.append(_entry("E2-same-msg-flipped", info, stuck, d5, sig_e2))

    # --- F: 同 r 同钥匙但消息不同，候选 d 不匹配公钥（伪线索） ---
    # 用 A 的 r 值配一个随机 s 与随机摘要，验证必然失败 → 归为无效/不匹配。
    fake_sig = Signature(r_shared, 1 + rng.randrange(order - 1))
    fake_digest = digest_of(b"forged-looking-record")
    records.append(
        _entry("F1-mismatch-candidate", info, faulty, fake_digest, fake_sig)
    )

    private_notes.update(
        {
            "A": faulty.private_scalar,
            "B": healthy.private_scalar,
            "C": collision.private_scalar,
            "D": broken.private_scalar,
            "E": stuck.private_scalar,
            "fixed_k_A": fixed_k,
        }
    )

    payload = {
        "schema": "ecdsa-nonce-audit/v1",
        "sample_purpose": "synthetic authorized nonce-reuse test sample",
        "records": records,
    }
    return payload, private_notes
