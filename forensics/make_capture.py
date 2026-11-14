"""生成合成取证记录：
场景 A：两笔请求（POST 带 100-continue、HEAD）+ 一次 WebSocket 升级，
        请求 2 在响应 1 之前发出（流水化），升级后有后续协议字节。
场景 B：单笔请求，响应无长度声明、由连接关闭定界（close-delimited）。
另生成场景 A 删除中间一段证据（响应 2 头部所在段）的变体。
"""

import json
import os

OUT = os.path.join(os.path.dirname(__file__), "captures")


class StreamBuilder:
    def __init__(self):
        self.offsets = {"c2s": 0, "s2c": 0}
        self.segments = []

    def add(self, ts, direction, data: bytes):
        off = self.offsets[direction]
        self.segments.append({
            "dir": direction,
            "ts": ts,
            "offset": off,
            "data_hex": data.hex(),
        })
        self.offsets[direction] += len(data)
        return off


def build_full():
    sb = StreamBuilder()
    req1_head = (b"POST /submit HTTP/1.1\r\nHost: example.test\r\n"
                 b"Expect: 100-continue\r\nContent-Length: 11\r\n\r\n")
    req1_body = b"hello=world"
    resp1_100 = b"HTTP/1.1 100 Continue\r\n\r\n"
    req2 = b"HEAD /status HTTP/1.1\r\nHost: example.test\r\n\r\n"
    resp1 = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
             b"Content-Type: text/plain\r\n\r\nack-1")
    resp2 = (b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n"
             b"X-Note: head-only\r\n\r\n")
    req3 = (b"GET /chat HTTP/1.1\r\nHost: example.test\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n")
    resp3 = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
             b"Connection: Upgrade\r\n"
             b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
    ws_c2s = b"\x81\x85\x37\xfa\x21\x3d" + b"\x7f\x9f\x4d\x51\x58"
    ws_s2c = b"\x81\x05\x48\x65\x6c\x6c\x6f"

    sb.add(1.00, "c2s", req1_head)          # 段 0
    sb.add(1.05, "s2c", resp1_100)          # 段 1
    sb.add(1.10, "c2s", req1_body)          # 段 2
    sb.add(1.15, "c2s", req2)               # 段 3（流水化：响应 1 未回）
    sb.add(1.20, "s2c", resp1)              # 段 4
    sb.add(1.25, "s2c", resp2)              # 段 5（HEAD 响应，无正文）
    sb.add(1.30, "c2s", req3)               # 段 6（升级请求）
    sb.add(1.35, "s2c", resp3)              # 段 7（101）
    sb.add(1.40, "c2s", ws_c2s)             # 段 8（后续协议材料）
    sb.add(1.45, "s2c", ws_s2c)             # 段 9（后续协议材料）
    return {
        "capture_id": "synthetic-A-full",
        "eof": {"c2s": False, "s2c": False},
        "segments": sb.segments,
    }


def build_gapped(full):
    # 删除“中间一段证据”：响应 2（HEAD 响应）所在的 s2c 段。
    dropped = full["segments"][5]
    assert dropped["dir"] == "s2c"
    segs = [s for i, s in enumerate(full["segments"]) if i != 5]
    return {
        "capture_id": "synthetic-A-gapped",
        "note": "已删除 s2c 偏移 %d 起的一段证据" % dropped["offset"],
        "eof": {"c2s": False, "s2c": False},
        "segments": segs,
    }


def build_close_delimited():
    sb = StreamBuilder()
    sb.add(2.00, "c2s", b"GET /legacy HTTP/1.0\r\n\r\n")
    sb.add(2.05, "s2c", b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n")
    sb.add(2.10, "s2c", b"close-delimited-body-part1;")
    sb.add(2.15, "s2c", b"part2-end")
    return {
        "capture_id": "synthetic-B-close-delimited",
        "eof": {"c2s": True, "s2c": True},
        "segments": sb.segments,
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    full = build_full()
    for cap in (full, build_gapped(full), build_close_delimited()):
        path = os.path.join(OUT, cap["capture_id"] + ".json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cap, fh, ensure_ascii=False, indent=2)
        print("written", path)


if __name__ == "__main__":
    main()
