"""Minimal MS-XCA plain XPRESS (LZXPRESS) encoder, test-only.

Produces a byte stream decodable by dissect.util.lzxpress.decompress. Operations are grouped in sets of 32 behind
a little-endian 32-bit flag word (bit 31 = first operation). A cleared flag is a literal byte, a set flag a match.
Match offsets are limited to 1024 (11 bits) and match lengths to 282, which keeps every long match on the simple
0x0F nibble path and avoids the stateful 0xFF extension. Nibble bytes are collected separately and spliced into
the token stream as paired low/high bytes, exactly where the stateful decoder reads them.
"""
from __future__ import annotations

MAX_OFFSET = 1024
MAX_MATCH_LEN = 277  # largest length encodable through the 0x0F nibble + one trailing byte path


def _plan_operations(data: bytes) -> list[tuple]:
    operations: list[tuple] = []
    pos = 0
    n = len(data)
    head: dict[bytes, list[int]] = {}

    while pos < n:
        best_len = 0
        best_off = 0
        if pos + 3 <= n:
            for cand in head.get(data[pos : pos + 3], []):
                offset = pos - cand
                if offset > MAX_OFFSET:
                    continue
                max_len = min(n - pos, MAX_OFFSET, MAX_MATCH_LEN)
                length = 0
                while length < max_len and data[cand + length] == data[pos + length]:
                    length += 1
                if length > best_len:
                    best_len = length
                    best_off = offset

        head.setdefault(data[pos : pos + 3], []).append(pos)
        if best_len >= 3:
            operations.append(("M", best_off, best_len))
            for i in range(1, best_len):
                if pos + i + 3 <= n:
                    head.setdefault(data[pos + i : pos + i + 3], []).append(pos + i)
            pos += best_len
        else:
            operations.append(("L", data[pos]))
            pos += 1

    return operations


def compress(data: bytes) -> bytes:
    operations = _plan_operations(data)
    out = bytearray()
    nibble_values: list[int] = []
    # (insertion position in out, index of the paired nibble byte)
    splices: list[tuple[int, int]] = []

    for group_start in range(0, len(operations), 32):
        group = operations[group_start : group_start + 32]
        flag_offset = len(out)
        out.extend(b"\x00\x00\x00\x00")
        flags = 0

        for bit, op in enumerate(group):
            if op[0] == "L":
                out.append(op[1])
                continue

            flags |= 1 << (31 - bit)
            _, offset, length = op
            adjusted = length - 3
            token_base = (offset - 1) << 3

            if adjusted < 7:
                out.extend((token_base | adjusted).to_bytes(2, "little"))
                continue

            out.extend((token_base | 7).to_bytes(2, "little"))
            extra = adjusted - 7

            if extra <= 15:
                nibble = extra
                follow = b""
            else:
                # 0x0F nibble + one trailing byte; decoder yields length = trailing + 25
                nibble = 0x0F
                follow = bytes([extra - 15])

            nibble_index = len(nibble_values)
            if nibble_index % 2 == 0:
                splices.append((len(out), nibble_index // 2))
            nibble_values.append(nibble)
            out.extend(follow)

        out[flag_offset : flag_offset + 4] = flags.to_bytes(4, "little")

    nibble_bytes = bytearray()
    for i in range(0, len(nibble_values), 2):
        low = nibble_values[i] & 0x0F
        high = (nibble_values[i + 1] & 0x0F) if i + 1 < len(nibble_values) else 0
        nibble_bytes.append(low | (high << 4))

    for position, nibble_byte_index in reversed(splices):
        out.insert(position, nibble_bytes[nibble_byte_index])

    return bytes(out)
