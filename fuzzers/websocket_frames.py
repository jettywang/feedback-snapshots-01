#!/usr/bin/python3

# Copyright 2026 aio-libs contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Targeted fuzzing of the pure-Python WebSocket frame reader.

The input is split into independent sections so libFuzzer can shrink one
decision at a time while keeping the rest of the scenario intact:

* configuration: the negotiated permessage-deflate state and ``max_msg_size``;
* an uncompressed message sent as its own scenario;
* a fragment sequence with optional interleaved control frames, PMCE
  fragments, RSV bits, declared lengths and a truncated tail.

Both scenarios check the reader's published output against an independent
replay of the wire bytes, so a message is delivered whole or not at all. The
fragment scenario exercises the accumulated limit of a message, which is why a
run contains many small frames but never one huge frame.

The target is meant to be run with AIOHTTP_NO_EXTENSIONS=1 so it exercises
``aiohttp._websocket.reader_py`` directly.
"""

import asyncio
import sys
import zlib
from collections.abc import Iterable, Sequence

import atheris  # noqa: I900

with atheris.instrument_imports():  # type: ignore[attr-defined]
    from aiohttp._websocket.helpers import (
        PACK_LEN1,
        PACK_LEN2,
        PACK_LEN3,
        websocket_mask,
    )
    from aiohttp._websocket.models import (
        WS_DEFLATE_TRAILING,
        WebSocketError,
        WSCloseCode,
        WSMsgType,
    )
    from aiohttp._websocket.reader_py import WebSocketDataQueue, WebSocketReader

# Keep inputs tiny: decisions come from the configured limit, not from a large
# buffer, and libFuzzer's max_len should stay small too.
MAX_FRAME_PAYLOAD = 64
MAX_FRAGMENTS = 24

DATA_OPCODES = (int(WSMsgType.TEXT), int(WSMsgType.BINARY))
CONTROL_OPCODES = (int(WSMsgType.PING), int(WSMsgType.PONG), int(WSMsgType.CLOSE))

VALID_CLOSE_PAYLOAD = b"\x03\xe8"  # code 1000


class _Protocol:
    """The two hooks WebSocketDataQueue needs, without an event loop."""

    def __init__(self) -> None:
        self._reading_paused = False

    def pause_reading(self) -> None:
        self._reading_paused = True

    def resume_reading(self) -> None:
        self._reading_paused = False


def _pack_frame(
    fin: bool,
    opcode: int,
    payload: bytes,
    *,
    rsv1: bool = False,
    declared_len: int | None = None,
    mask: bytes | None = None,
) -> bytes:
    """Serialize one frame, optionally lying about its payload length."""
    first_byte = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
    length = len(payload) if declared_len is None else declared_len
    mask_bit = 0x80 if mask is not None else 0
    if length < 126:
        header = PACK_LEN1(first_byte, length | mask_bit)
    elif length < 65536:
        header = PACK_LEN2(first_byte, 126 | mask_bit, length)
    else:
        header = PACK_LEN3(first_byte, 127 | mask_bit, length)
    if mask is None:
        return header + payload
    masked = bytearray(payload)
    websocket_mask(mask, masked)
    return header + mask + masked


def _deflate(payload: bytes) -> bytes:
    """Raw DEFLATE exactly as permessage-deflate puts it on the wire."""
    compressor = zlib.compressobj(wbits=-15)
    out = compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH)
    assert out.endswith(WS_DEFLATE_TRAILING)
    return out[: -len(WS_DEFLATE_TRAILING)]


def _drain(queue: WebSocketDataQueue, loop: asyncio.AbstractEventLoop) -> list[object]:
    """Publish everything already parsed, then the terminal error, if any."""
    published: list[object] = []
    while queue._buffer:
        published.append(queue._read_from_buffer())
    if queue.exception() is not None:
        published.append(queue.exception())
    return published


def _run_scenario(
    frames: Iterable[bytes],
    *,
    max_msg_size: int,
    compress: bool,
    truncated: bool,
) -> list[object]:
    loop = asyncio.new_event_loop()
    try:
        queue = WebSocketDataQueue(_Protocol(), 1 << 16, loop=loop)
        reader = WebSocketReader(
            queue, max_msg_size, compress=compress, decode_text=False
        )
        for frame in frames:
            reader.feed_data(frame)
        if truncated:
            reader.feed_eof()
        return _drain(queue, loop)
    finally:
        loop.close()


def _is_data(item: object) -> bool:
    return getattr(item, "type", None) in (
        WSMsgType.TEXT,
        WSMsgType.BINARY,
    )


def _consume_message(
    fdp: "atheris.FuzzedDataProvider",  # type: ignore[name-defined]
    max_msg_size: int,
) -> None:
    """A single uncompressed message, independent of the fragment scenario."""
    limit = max(1, max_msg_size)
    payload = bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, MAX_FRAME_PAYLOAD)))
    opcode = DATA_OPCODES[fdp.ConsumeIntInRange(0, 1)]
    declared = None
    too_big = fdp.ConsumeBool()
    if too_big:
        # Only a declared length is inflated; no huge payload is generated.
        declared = fdp.ConsumeIntInRange(limit + 1, limit * 2)
    frame = _pack_frame(
        True,
        opcode,
        payload,
        declared_len=declared,
        mask=b"\x01\x02\x03\x04" if fdp.ConsumeBool() else None,
    )
    published = _run_scenario(
        [frame], max_msg_size=limit, compress=False, truncated=False
    )
    if too_big:
        assert not any(_is_data(item) for item in published), published
        assert any(
            isinstance(item, WebSocketError) and item.code == WSCloseCode.MESSAGE_TOO_BIG
            for item in published
        ), published
    elif len(payload) >= limit:
        # The uncompressed bound is exclusive, so a message at the limit is
        # rejected too; either way nothing may be published.
        assert not any(_is_data(item) for item in published), published
    else:
        assert len(published) == 1, published
        assert published[0].data == payload
        assert published[0].size == len(payload)


def _consume_fragments(
    fdp: "atheris.FuzzedDataProvider",  # type: ignore[name-defined]
    max_msg_size: int,
    compress: bool,
) -> None:
    """A fragmented message with optional interleaved control frames."""
    count = fdp.ConsumeIntInRange(1, MAX_FRAGMENTS)
    pieces = [
        bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, MAX_FRAME_PAYLOAD)))
        for _ in range(count)
    ]
    total = sum(len(piece) for piece in pieces)
    # PMCE was negotiated and this message opted into it: the first frame
    # carries RSV1 and the payload is deflated. A negotiated reader may also
    # see an uncompressed message, which keeps the frame bytes verbatim.
    compressed = compress and fdp.ConsumeBool()
    truncated = fdp.ConsumeBool()
    first_opcode = DATA_OPCODES[fdp.ConsumeIntInRange(0, 1)]
    interleave = fdp.ConsumeBool()

    if compressed:
        wire_pieces: Sequence[bytes] = [_deflate(b"".join(pieces))]
    else:
        wire_pieces = pieces

    frames: list[bytes] = []
    for index, wire in enumerate(wire_pieces):
        fin = index == len(wire_pieces) - 1 and not truncated
        opcode = first_opcode if index == 0 else int(WSMsgType.CONTINUATION)
        frames.append(
            _pack_frame(
                fin,
                opcode,
                wire,
                rsv1=compressed and index == 0,
                mask=b"\x04\x03\x02\x01" if fdp.ConsumeBool() else None,
            )
        )
        if interleave and index != len(wire_pieces) - 1:
            control_opcode = CONTROL_OPCODES[fdp.ConsumeIntInRange(0, 2)]
            if control_opcode == int(WSMsgType.CLOSE):
                control_payload = VALID_CLOSE_PAYLOAD
            else:
                control_payload = bytes(
                    fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4))
                )
            frames.append(_pack_frame(True, control_opcode, control_payload))

    published = _run_scenario(
        frames, max_msg_size=max_msg_size, compress=compress, truncated=truncated
    )
    errors = [item for item in published if isinstance(item, WebSocketError)]
    data = [item for item in published if _is_data(item)]
    if truncated:
        # A truncated message must never be published as a shorter message.
        assert not data, published
    elif total < max_msg_size:
        # The exact accumulated size, not a per-frame size, decides. The
        # reader's uncompressed bound is exclusive, so a message at exactly
        # max_msg_size is expected to be rejected too.
        assert not errors, published
        assert len(data) == 1, published
        assert data[0].data == b"".join(pieces)
    else:
        # At or over the limit: nothing may be published as a partial message.
        assert not data, published
        assert any(
            item.code == WSCloseCode.MESSAGE_TOO_BIG for item in errors
        ), published


def _consume_unknown_extension(
    fdp: "atheris.FuzzedDataProvider",  # type: ignore[name-defined]
    max_msg_size: int,
) -> None:
    """RSV1 on a reader that never negotiated PMCE must fail the connection."""
    payload = bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, MAX_FRAME_PAYLOAD)))
    frame = _pack_frame(
        True,
        DATA_OPCODES[fdp.ConsumeIntInRange(0, 1)],
        payload,
        rsv1=True,
    )
    published = _run_scenario(
        [frame], max_msg_size=max_msg_size, compress=False, truncated=False
    )
    assert not any(_is_data(item) for item in published), published
    assert any(
        isinstance(item, WebSocketError) and item.code == WSCloseCode.PROTOCOL_ERROR
        for item in published
    ), published


def TestOneInput(data: bytes) -> None:  # type: ignore[misc]
    fdp = atheris.FuzzedDataProvider(data)  # type: ignore[attr-defined]
    max_msg_size = fdp.ConsumeIntInRange(1, 4096)
    compress = fdp.ConsumeBool()
    scenario = fdp.ConsumeIntInRange(0, 2)
    if scenario == 0:
        _consume_message(fdp, max_msg_size)
    elif scenario == 1:
        _consume_fragments(fdp, max_msg_size, compress)
    else:
        _consume_unknown_extension(fdp, max_msg_size)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)  # type: ignore[attr-defined]
    atheris.Fuzz()  # type: ignore[attr-defined]
