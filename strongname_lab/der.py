"""Small DER encoder/decoder used for the lab's PKCS#7 and X.509 fixtures.

Only the subset needed by Authenticode is implemented.  This module is
deliberately dependency-free so the verification path does not rely on the
same ASN.1 library that produced the fixture.
"""

from __future__ import annotations

import datetime as dt


class DerError(ValueError):
    pass


def encode_length(length: int) -> bytes:
    if length < 0:
        raise DerError("negative length")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(content)) + content


def sequence(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(items: list[bytes]) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def integer(value: int) -> bytes:
    if value < 0:
        raise DerError("negative integer not supported")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(0x02, raw)


def oid(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    if len(parts) < 2:
        raise DerError("OID needs at least two arcs")
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body.extend(reversed(chunk))
    return tlv(0x06, bytes(body))


def null() -> bytes:
    return b"\x05\x00"


def octet_string(value: bytes) -> bytes:
    return tlv(0x04, value)


def bit_string(value: bytes, unused_bits: int = 0) -> bytes:
    return tlv(0x03, bytes([unused_bits]) + value)


def boolean(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")


def bmp_string(value: str) -> bytes:
    return tlv(0x1E, value.encode("utf-16-be"))


def utc_time(value: dt.datetime) -> bytes:
    return tlv(0x17, value.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def explicit(number: int, content: bytes) -> bytes:
    return tlv(0xA0 | number, content)


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int, bytes]:
    if offset >= len(data):
        raise DerError("truncated tag")
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DerError("high-tag-number form not supported")
    if offset >= len(data):
        raise DerError("truncated length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise DerError("unsupported length encoding")
        if offset + count > len(data):
            raise DerError("truncated long length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise DerError("truncated value")
    return tag, data[offset:end], end, data[start:end]


def children(value: bytes) -> list[tuple[int, bytes, bytes]]:
    result = []
    offset = 0
    while offset < len(value):
        tag, content, offset, raw = read_tlv(value, offset)
        result.append((tag, content, raw))
    return result


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (length, next_offset) for a DER length at *offset*."""
    if offset >= len(data):
        raise DerError("truncated length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise DerError("unsupported length encoding")
        return int.from_bytes(data[offset : offset + count], "big"), offset + count
    return first, offset


def content_of(raw: bytes) -> bytes:
    """Return the content octets of a complete TLV."""
    if len(raw) < 2:
        raise DerError("truncated TLV")
    length, header_end = decode_length(raw, 1)
    if header_end + length != len(raw):
        raise DerError("length mismatch")
    return raw[header_end:]


def decode_oid(value: bytes) -> str:
    if not value:
        raise DerError("empty OID")
    first = value[0]
    parts = [first // 40, first % 40]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(number)
            number = 0
    return ".".join(str(part) for part in parts)


def decode_integer(value: bytes) -> int:
    if not value:
        raise DerError("empty integer")
    return int.from_bytes(value, "big", signed=True)


def decode_time(tag: int, value: bytes) -> dt.datetime:
    text = value.decode("ascii")
    if tag == 0x17:
        return dt.datetime.strptime(text, "%y%m%d%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    if tag == 0x18:
        return dt.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    raise DerError(f"unsupported time tag 0x{tag:02x}")


def algorithm_identifier(algorithm_oid: str) -> bytes:
    return sequence(oid(algorithm_oid), null())
