"""审计样本的记录模型与解析校验。"""

from __future__ import annotations

from dataclasses import dataclass, field

from ecdsa.keys import VerifyingKey

from .curves import (
    CurveInfo,
    get_curve,
    key_fingerprint,
    parse_public_key,
    truncate_digest,
)
from .ecdsa_math import Signature, is_low_s, normalize_low_s


class SampleFormatError(ValueError):
    """样本文件结构或字段不合法。"""


@dataclass
class Record:
    record_id: str
    curve_info: CurveInfo
    vk: VerifyingKey
    fingerprint: str
    z: int
    sig: Signature
    digest_hex: str
    source_index: int
    low_s: bool
    normalized_s: int
    raw: dict = field(repr=False, default_factory=dict)


def _coerce_int(value, field_name: str) -> int:
    if isinstance(value, bool):
        raise SampleFormatError(f"{field_name} 不能是布尔值")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16) if text[:2].lower() == "0x" else int(text)
        except ValueError as exc:
            raise SampleFormatError(f"{field_name} 不是合法整数: {value!r}") from exc
    raise SampleFormatError(f"{field_name} 必须是整数或十六进制字符串")


def _coerce_digest(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value.strip())
        except ValueError as exc:
            raise SampleFormatError("digest 不是合法十六进制") from exc
    raise SampleFormatError("digest 必须是十六进制字符串或字节")


def parse_records(payload: dict) -> list[Record]:
    """解析并校验整个样本文件，返回 Record 列表（保持输入顺序）。"""
    if not isinstance(payload, dict):
        raise SampleFormatError("样本顶层必须是 JSON 对象")
    schema = payload.get("schema", "ecdsa-nonce-audit/v1")
    if schema != "ecdsa-nonce-audit/v1":
        raise SampleFormatError(f"不支持的 schema: {schema!r}")
    entries = payload.get("records")
    if not isinstance(entries, list) or not entries:
        raise SampleFormatError("records 必须是非空数组")

    records: list[Record] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SampleFormatError(f"records[{index}] 必须是对象")
        record_id = entry.get("id")
        if not isinstance(record_id, str) or not record_id:
            raise SampleFormatError(f"records[{index}].id 必须是非空字符串")
        if record_id in seen_ids:
            raise SampleFormatError(f"记录 id 重复: {record_id}")
        seen_ids.add(record_id)

        curve_name = entry.get("curve")
        if not isinstance(curve_name, str):
            raise SampleFormatError(f"{record_id}: curve 必须是字符串")
        info = get_curve(curve_name)

        vk = parse_public_key(entry["public_key"], info)
        order = info.order
        r = _coerce_int(entry.get("r"), f"{record_id}.r")
        s = _coerce_int(entry.get("s"), f"{record_id}.s")
        if not (1 <= r < order and 1 <= s < order):
            raise SampleFormatError(f"{record_id}: r/s 超出曲线阶范围")
        sig = Signature(r, s)

        digest = _coerce_digest(entry["digest"])
        z = truncate_digest(digest, order)

        records.append(
            Record(
                record_id=record_id,
                curve_info=info,
                vk=vk,
                fingerprint=key_fingerprint(vk),
                z=z,
                sig=sig,
                digest_hex=digest.hex(),
                source_index=index,
                low_s=is_low_s(s, order),
                normalized_s=normalize_low_s(s, order),
                raw=entry,
            )
        )
    return records
