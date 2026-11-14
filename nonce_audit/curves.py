"""曲线注册表、公钥解析与 ECDSA 辅助函数。

所有运算基于 python-ecdsa 库提供的椭圆曲线算术；本模块只做离线计算。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ecdsa import NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import INFINITY, PointJacobi
from ecdsa.keys import VerifyingKey


@dataclass(frozen=True)
class CurveInfo:
    name: str
    curve: Curve

    @property
    def order(self) -> int:
        return self.curve.order

    @property
    def bit_length(self) -> int:
        return self.curve.baselen * 8


CURVES = {
    "NIST192p": CurveInfo("NIST192p", NIST192p),
    "NIST224p": CurveInfo("NIST224p", NIST224p),
    "NIST256p": CurveInfo("NIST256p", NIST256p),
    "NIST384p": CurveInfo("NIST384p", NIST384p),
    "NIST521p": CurveInfo("NIST521p", NIST521p),
    "SECP256k1": CurveInfo("SECP256k1", SECP256k1),
}

# 常见别名，方便日志直接来自其他工具命名。
ALIASES = {
    "P-192": "NIST192p",
    "P-224": "NIST224p",
    "P-256": "NIST256p",
    "P-384": "NIST384p",
    "P-521": "NIST521p",
    "secp256r1": "NIST256p",
    "secp384r1": "NIST384p",
    "secp521r1": "NIST521p",
    "secp256k1": "SECP256k1",
}


def get_curve(name: str) -> CurveInfo:
    key = name.strip()
    key = ALIASES.get(key, key)
    try:
        return CURVES[key]
    except KeyError as exc:
        supported = ", ".join(sorted(CURVES))
        raise ValueError(f"不支持的曲线 {name!r}；支持: {supported}") from exc


def truncate_digest(digest: bytes, order: int) -> int:
    """按 FIPS 186-4 取摘要最左 order.bit_length() 位得到整数 z。"""
    nbits = order.bit_length()
    z = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - nbits
    if excess > 0:
        z >>= excess
    return z


def parse_public_key(spec: dict, info: CurveInfo) -> VerifyingKey:
    """解析一条记录里的公钥描述。

    支持:
      * {"x": int/hex, "y": int/hex}
      * {"sec1": 十六进制 SEC1（压缩或非压缩）字节}
      * {"pem": PEM 字符串}
    """
    if not isinstance(spec, dict):
        raise ValueError("public_key 必须是对象")

    if "pem" in spec:
        vk = VerifyingKey.from_pem(spec["pem"])
        if vk.curve != info.curve:
            raise ValueError("PEM 公钥曲线与记录声明的曲线不一致")
        return vk

    if "sec1" in spec:
        raw = _coerce_bytes(spec["sec1"])
        vk = VerifyingKey.from_string(raw, curve=info.curve)
        return vk

    if "x" in spec and "y" in spec:
        x = _coerce_int(spec["x"])
        y = _coerce_int(spec["y"])
        point = PointJacobi(info.curve.curve, x, y, 1, order=info.order)
        return VerifyingKey.from_public_point(point, curve=info.curve)

    raise ValueError("public_key 需要包含 x/y、sec1 或 pem 之一")


def key_fingerprint(vk: VerifyingKey) -> str:
    """公钥指纹: SEC1 非压缩编码的 SHA-256 前 16 字节 hex。"""
    digest = hashlib.sha256(vk.to_string("raw")).hexdigest()
    return digest[:32]


def public_key_xy(vk: VerifyingKey) -> tuple[int, int]:
    point = vk.pubkey.point
    return point.x(), point.y()


def scalar_multiply(info: CurveInfo, scalar: int):
    return scalar * info.curve.generator


def point_is_infinity(point) -> bool:
    return point == INFINITY


def _coerce_int(value) -> int:
    if isinstance(value, bool):
        raise ValueError("布尔值不能作为坐标")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text[:2].lower() == "0x":
            return int(text, 16)
        return int(text)
    raise ValueError(f"无法把 {type(value).__name__} 解析为整数")


def _coerce_bytes(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        text = value.strip()
        return bytes.fromhex(text)
    raise ValueError(f"无法把 {type(value).__name__} 解析为字节")
