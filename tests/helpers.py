"""测试辅助：直接用标量构造记录，避免依赖 JSON 往返。"""

from __future__ import annotations

import hashlib

from ecdsa import SigningKey

from nonce_audit.curves import key_fingerprint, truncate_digest
from nonce_audit.ecdsa_math import Signature, sign_with_k
from nonce_audit.models import Record


def make_record(record_id, info, sk, message, k=None, s_override=None,
                digest_override=None, low_s_flip=False, sign_against=None):
    order = info.order
    digest = hashlib.sha256(message).digest()
    if digest_override is not None:
        digest = digest_override
    z = truncate_digest(digest, order)
    signing_digest = sign_against if sign_against is not None else digest
    signing_z = truncate_digest(signing_digest, order)
    if k is None:
        seed_bytes = hashlib.sha256(
            message + sk.to_string()
        ).digest()
        k = 1 + (
            int.from_bytes(seed_bytes, "big") % (order - 2)
        )
    # 签名默认针对记录携带的 digest，记录自洽；
    # sign_against 可制造“签名时摘要与日志摘要不一致”的损坏样本。
    sig = sign_with_k(info, sk.privkey.secret_multiplier, signing_z, k)
    if low_s_flip:
        sig = Signature(sig.r, order - sig.s)
    if s_override is not None:
        sig = Signature(sig.r, s_override)
    vk = sk.get_verifying_key()
    return Record(
        record_id=record_id,
        curve_info=info,
        vk=vk,
        fingerprint=key_fingerprint(vk),
        z=z,
        sig=sig,
        digest_hex=digest.hex(),
        source_index=0,
        low_s=sig.s <= order // 2,
        normalized_s=min(sig.s, order - sig.s),
        raw={},
    )


def fresh_key(info, seed: int) -> SigningKey:
    import random

    rng = random.Random(seed)
    return SigningKey.generate(curve=info.curve, entropy=rng.randbytes)
