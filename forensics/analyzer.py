"""只读 HTTP 请求-响应关联分析器（基于 h11）。

输入：按时间排序的双向字节段（每段带方向、时间戳、原始流偏移）。
输出：已证明的请求-响应对、尚待补齐的范围、协议切换后的后续材料、
      以及无法判断的范围。正文不全量复制，只记录偏移、长度、SHA-256
      与前 32 字节预览。

原则：
- 每个方向用独立的 h11 连接解析，互为对端同步状态（h11 代理用法）。
- 任何截断 / 缺失 / 解析错误都终止可靠关联；绝不通过搜索 "HTTP" 字样
  重新认定边界。
- 101 协议切换后，两方向剩余字节只标为后续协议材料。
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field

import h11

C2S = "c2s"
S2C = "s2c"

PREVIEW_LEN = 32


def _headers_to_list(headers):
    return [[k.decode("latin-1"), v.decode("latin-1")] for k, v in headers.raw_items()]


def _header_get(headers, name):
    for key, value in headers.raw_items():
        if key.lower() == name:
            return value
    return None


def request_framing(headers):
    te = _header_get(headers, b"transfer-encoding")
    if te and b"chunked" in te.lower():
        return "chunked", "Transfer-Encoding: chunked"
    cl = _header_get(headers, b"content-length")
    if cl is not None:
        return "content-length", "Content-Length: %s" % cl.decode("latin-1")
    return "none", "无 Content-Length / Transfer-Encoding，请求无正文"


def response_framing(method, status, headers):
    if 100 <= status < 200 or status in (204, 304):
        return "none", "状态码 %d 按 RFC 不允许携带正文" % status
    if method == b"HEAD":
        return "none", "HEAD 响应无正文（Content-Length 仅为语义声明）"
    te = _header_get(headers, b"transfer-encoding")
    if te and b"chunked" in te.lower():
        return "chunked", "Transfer-Encoding: chunked"
    cl = _header_get(headers, b"content-length")
    if cl is not None:
        return "content-length", "Content-Length: %s" % cl.decode("latin-1")
    return "close-delimited", "无长度声明，正文由连接关闭定界"


class BodyTracker:
    """只保留摘要，不复制正文。"""

    def __init__(self):
        self.start = None
        self.end = None
        self.length = 0
        self.sha256 = hashlib.sha256()
        self.preview = bytearray()

    def add(self, data, offset):
        if not data:
            return
        if self.start is None:
            self.start = offset
        self.end = offset + len(data)
        self.length += len(data)
        self.sha256.update(data)
        if len(self.preview) < PREVIEW_LEN:
            self.preview += data[: PREVIEW_LEN - len(self.preview)]

    def report(self):
        if self.start is None:
            return {"length": 0}
        return {
            "range": [self.start, self.end],
            "length": self.length,
            "sha256": self.sha256.hexdigest(),
            "preview_hex": bytes(self.preview).hex(),
        }


@dataclass
class Message:
    kind: str  # request / informational / response
    start: int
    end: int = None
    method: str = None
    target: str = None
    status: int = None
    headers: list = field(default_factory=list)
    framing: str = None
    framing_reason: str = None
    body: BodyTracker = field(default_factory=BodyTracker)
    complete: bool = False

    def report(self):
        out = {
            "kind": self.kind,
            "range": [self.start, self.end],
            "headers": self.headers,
            "framing": self.framing,
            "framing_reason": self.framing_reason,
            "body": self.body.report(),
            "complete": self.complete,
        }
        if self.method is not None:
            out["method"] = self.method
            out["target"] = self.target
        if self.status is not None:
            out["status"] = self.status
        return out


@dataclass
class Pair:
    pair_id: int
    request: Message
    informational: list = field(default_factory=list)
    response: Message = None

    @property
    def proven(self):
        return (
            self.request.complete
            and self.response is not None
            and self.response.complete
        )


class DirState:
    """单方向解析状态。"""

    def __init__(self, name, conn):
        self.name = name
        self.conn = conn
        self.expected = 0          # 下一个期望的流偏移
        self.fed = 0               # 已喂给 h11 的字节数
        self.gapped = False        # 完整性已破坏，停止解析
        self.gap_reason = None
        self.switched = False      # 协议已切换
        self.closed = False        # 连接已关闭，不再取事件
        self.undetermined = []     # [(start, end, reason)]

    def consumed(self):
        return self.fed - len(self.conn._receive_buffer)

    def mark_undetermined(self, start, end, reason):
        if end <= start:
            return
        if self.undetermined and self.undetermined[-1][1] == start and \
                self.undetermined[-1][2] == reason:
            self.undetermined[-1] = (self.undetermined[-1][0], end, reason)
        else:
            self.undetermined.append((start, end, reason))


class Analyzer:
    def __init__(self):
        self.dirs = {
            C2S: DirState(C2S, h11.Connection(h11.SERVER)),
            S2C: DirState(S2C, h11.Connection(h11.CLIENT)),
        }
        self.pairs = []
        self.open_pairs = []       # 请求已完成、响应未完成的对
        self.current_request = None   # 正在接收的请求消息
        self.current_response = None  # 正在接收的响应消息
        self.taint_ts = None       # 首次完整性破坏的时间戳
        self.taint_reason = None
        self.switched = False
        self.post_protocol = {C2S: [], S2C: []}  # [(start, end)]
        self.errors = []

    # ---- 完整性 ----

    def _taint(self, ts, reason):
        if self.taint_ts is None:
            self.taint_ts = ts
            self.taint_reason = reason

    # ---- 主流程 ----

    def run(self, capture):
        segments = sorted(capture["segments"], key=lambda s: s["ts"])
        for seg in segments:
            self._process_segment(seg)
        eof = capture.get("eof", {})
        for name, ds in self.dirs.items():
            if eof.get(name) and not ds.gapped and not self.switched:
                ds.conn.receive_data(b"")
                self._drain(ds)
        self._finalize()

    def _process_segment(self, seg):
        name = seg["dir"]
        ds = self.dirs[name]
        data = bytes.fromhex(seg["data_hex"])
        start, end = seg["offset"], seg["offset"] + len(data)

        if self.switched:
            self._add_post_protocol(name, start, end)
            return

        if ds.gapped:
            ds.mark_undetermined(start, end, ds.gap_reason)
            return

        if start != ds.expected:
            if start > ds.expected:
                reason = "偏移不连续：期望 %d，实到 %d（缺失 %d 字节）" % (
                    ds.expected, start, start - ds.expected)
            else:
                reason = "偏移回退/重叠：期望 %d，实到 %d" % (ds.expected, start)
            ds.gapped = True
            ds.gap_reason = reason
            ds.mark_undetermined(start, end, reason)
            self._taint(seg["ts"], "%s 方向：%s" % (name, reason))
            return

        ds.expected = end
        try:
            ds.conn.receive_data(data)
        except h11.RemoteProtocolError as exc:
            ds.gapped = True
            ds.gap_reason = "协议错误：%s" % exc
            ds.mark_undetermined(start, end, ds.gap_reason)
            self._taint(seg["ts"], "%s 方向协议错误" % name)
            return
        ds.fed += len(data)
        self._drain(ds)

    def _drain(self, ds):
        # 事件可能触发对端状态推进（如流水化解暂停），循环至静默。
        progressed = True
        while progressed:
            progressed = False
            for cur in (ds, self.dirs[S2C if ds.name == C2S else C2S]):
                if cur.gapped or cur.closed or self.switched:
                    continue
                while True:
                    if cur.closed:
                        break
                    ev_start = cur.consumed()
                    try:
                        ev = cur.conn.next_event()
                    except h11.RemoteProtocolError as exc:
                        cur.gapped = True
                        cur.gap_reason = "协议错误：%s" % exc
                        cur.mark_undetermined(ev_start, cur.expected, cur.gap_reason)
                        self._taint(None, "%s 方向协议错误：%s" % (cur.name, exc))
                        break
                    ev_end = cur.consumed()
                    if ev is h11.NEED_DATA:
                        break
                    if ev is h11.PAUSED:
                        # 流水线：双方 DONE 后需显式开启下一周期；
                        # SWITCHED_PROTOCOL 等状态不得重启周期。
                        if cur.conn.our_state is h11.DONE and \
                                cur.conn.their_state is h11.DONE:
                            cur.conn.start_next_cycle()
                            continue
                        break
                    self._handle_event(cur, ev, ev_start, ev_end)
                    progressed = True
                    if self.switched:
                        break

    # ---- 事件处理 ----

    def _handle_event(self, ds, ev, start, end):
        if isinstance(ev, h11.ConnectionClosed):
            ds.closed = True
            return
        if ds.name == C2S:
            self._handle_c2s(ev, start, end)
        else:
            self._handle_s2c(ev, start, end)

    def _cross_send(self, target_name, event):
        """把对端事件同步进另一方向的 h11 状态机（代理用法）。

        h11 发送侧只接受 HTTP/1.1，版本归一化仅用于状态同步，
        不影响按原始字节解析的接收侧。
        """
        ds = self.dirs[target_name]
        try:
            if isinstance(event, h11.Request):
                headers = event.headers
                if _header_get(headers, b"host") is None:
                    # HTTP/1.0 请求可无 Host；归一化为 1.1 时补占位。
                    headers = list(headers.raw_items()) + [(b"host", b"unknown")]
                event = h11.Request(method=event.method, target=event.target,
                                    headers=headers, http_version="1.1")
            elif isinstance(event, h11.InformationalResponse):
                event = h11.InformationalResponse(
                    status_code=event.status_code, headers=event.headers,
                    http_version="1.1", reason=event.reason)
            elif isinstance(event, h11.Response):
                event = h11.Response(status_code=event.status_code,
                                     headers=event.headers,
                                     http_version="1.1", reason=event.reason)
            if ds.conn.our_state is h11.DONE and ds.conn.their_state is h11.DONE:
                ds.conn.start_next_cycle()
            ds.conn.send(event)
        except h11.LocalProtocolError as exc:
            self.errors.append("状态同步失败（%s）：%s" % (target_name, exc))

    def _handle_c2s(self, ev, start, end):
        if isinstance(ev, h11.Request):
            framing, reason = request_framing(ev.headers)
            msg = Message(
                kind="request", start=start,
                method=ev.method.decode("latin-1"),
                target=ev.target.decode("latin-1"),
                headers=_headers_to_list(ev.headers),
                framing=framing, framing_reason=reason,
            )
            self.current_request = msg
            # 立即建对：1xx（如 100 Continue）可能先于请求正文到达。
            pair = Pair(pair_id=len(self.pairs) + 1, request=msg)
            self.pairs.append(pair)
            self.open_pairs.append(pair)
            self._cross_send(S2C, ev)
        elif isinstance(ev, h11.Data):
            if self.current_request is not None:
                self.current_request.body.add(ev.data, start)
            self._cross_send(S2C, ev)
        elif isinstance(ev, h11.EndOfMessage):
            msg = self.current_request
            if msg is not None:
                msg.end = end
                msg.complete = True
                self.current_request = None
            self._cross_send(S2C, ev)
        elif isinstance(ev, h11.ConnectionClosed):
            pass

    def _handle_s2c(self, ev, start, end):
        if isinstance(ev, h11.InformationalResponse):
            if ev.status_code == 101:
                # h11 将 101 表示为 InformationalResponse 并立即切换协议，
                # 不再有 EndOfMessage；该对至此完结。
                msg = Message(
                    kind="response", start=start, status=101,
                    headers=_headers_to_list(ev.headers),
                    framing="none",
                    framing_reason="101 协议切换，无 HTTP 正文；其后为后续协议材料",
                )
                msg.end = end
                msg.complete = True
                if self.open_pairs:
                    done = self.open_pairs.pop(0)
                    done.response = msg
                self._cross_send(C2S, ev)
                self._enter_switched()
                return
            msg = Message(
                kind="informational", start=start, status=ev.status_code,
                headers=_headers_to_list(ev.headers),
                framing="none", framing_reason="1xx 无正文",
            )
            msg.end = end
            msg.complete = True
            if self.open_pairs:
                self.open_pairs[0].informational.append(msg)
            self._cross_send(C2S, ev)
        elif isinstance(ev, h11.Response):
            method = b""
            if self.open_pairs:
                method = self.open_pairs[0].request.method.encode("latin-1")
            framing, reason = response_framing(method, ev.status_code, ev.headers)
            msg = Message(
                kind="response", start=start, status=ev.status_code,
                headers=_headers_to_list(ev.headers),
                framing=framing, framing_reason=reason,
            )
            self.current_response = msg
            if self.open_pairs:
                self.open_pairs[0].response = msg
            self._cross_send(C2S, ev)
        elif isinstance(ev, h11.Data):
            if self.current_response is not None:
                self.current_response.body.add(ev.data, start)
            self._cross_send(C2S, ev)
        elif isinstance(ev, h11.EndOfMessage):
            msg = self.current_response
            if msg is not None:
                msg.end = end
                msg.complete = True
                self.current_response = None
            if self.open_pairs and self.open_pairs[0].response is not None \
                    and self.open_pairs[0].response.complete:
                done = self.open_pairs.pop(0)
                if done.response.status == 101:
                    self._enter_switched()
            self._cross_send(C2S, ev)
        elif isinstance(ev, h11.ConnectionClosed):
            pass

    def _enter_switched(self):
        self.switched = True
        for name, ds in self.dirs.items():
            ds.switched = True
            leftover = ds.conn._receive_buffer
            n = len(leftover)
            if n:
                base = ds.consumed()
                self._add_post_protocol(name, base, base + n)
                leftover.maybe_extract_at_most(n)

    def _add_post_protocol(self, name, start, end):
        ranges = self.post_protocol[name]
        if ranges and ranges[-1][1] == start:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))

    # ---- 收尾与报告 ----

    def _finalize(self):
        # 捕获结束时仍未完成的消息保持“尚待补齐”，不臆测。
        pass

    def report(self):
        proven, pending = [], []
        for pair in self.pairs:
            (proven if pair.proven else pending).append(pair)

        # 已接收但因状态机暂停（如等待缺失的响应）而未能解析的字节。
        unparsed = {}
        for name, ds in self.dirs.items():
            start = ds.consumed()
            if not ds.switched and start < ds.expected:
                reason = "字节已在捕获中，但因前序消息缺失/截断，状态机暂停解析"
                unparsed[name] = [[start, ds.expected, reason]]

        out = {
            "proven_pairs": [self._pair_report(p) for p in proven],
            "pending": [self._pair_report(p) for p in pending],
            "unparsed_buffered": unparsed,
            "post_protocol_material": {
                name: [list(r) for r in ranges]
                for name, ranges in self.post_protocol.items()
            },
            "undetermined": {
                name: [list(r) for r in ds.undetermined]
                for name, ds in self.dirs.items() if ds.undetermined
            },
            "integrity": {
                "tainted": self.taint_ts is not None,
                "first_failure_ts": self.taint_ts,
                "reason": self.taint_reason,
            },
            "sync_errors": self.errors,
        }
        return out

    def _pair_report(self, pair):
        return {
            "pair_id": pair.pair_id,
            "request": pair.request.report(),
            "informational": [m.report() for m in pair.informational],
            "response": pair.response.report() if pair.response else None,
            "missing": self._missing(pair),
        }

    @staticmethod
    def _missing(pair):
        missing = []
        if not pair.request.complete:
            missing.append("请求未完成（截断于 c2s 偏移 %s）" % pair.request.end)
        if pair.response is None:
            missing.append("未见响应起始行")
        elif not pair.response.complete:
            missing.append("响应正文未完整（%s）" % pair.response.framing_reason)
        return missing


def format_text(report):
    lines = []
    lines.append("=" * 60)
    lines.append("HTTP 取证关联报告")
    lines.append("=" * 60)

    lines.append("")
    lines.append("【已证明的请求—响应对】")
    if not report["proven_pairs"]:
        lines.append("  （无）")
    for p in report["proven_pairs"]:
        req, resp = p["request"], p["response"]
        lines.append(
            "  对 #%d  %s %s -> %d"
            % (p["pair_id"], req["method"], req["target"], resp["status"])
        )
        lines.append(
            "    请求  c2s[%d..%d)  正文定界：%s"
            % (req["range"][0], req["range"][1], req["framing_reason"])
        )
        for info in p["informational"]:
            lines.append(
                "    1xx   s2c[%d..%d)  状态 %d"
                % (info["range"][0], info["range"][1], info["status"])
            )
        lines.append(
            "    响应  s2c[%d..%d)  正文定界：%s"
            % (resp["range"][0], resp["range"][1], resp["framing_reason"])
        )
        body = resp["body"]
        if body.get("length"):
            lines.append(
                "    响应正文 %d 字节  sha256=%s…  预览=%s…"
                % (body["length"], body["sha256"][:16], body.get("preview_hex", ""))
            )

    lines.append("")
    lines.append("【尚待补齐的范围】")
    if not report["pending"] and not report["unparsed_buffered"]:
        lines.append("  （无）")
    for p in report["pending"]:
        req = p["request"]
        lines.append(
            "  对 #%d  %s %s" % (p["pair_id"], req["method"], req["target"])
        )
        for m in p["missing"]:
            lines.append("    缺：%s" % m)
    for name, ranges in report["unparsed_buffered"].items():
        for start, end, reason in ranges:
            lines.append(
                "  %s[%d..%d)  %d 字节  %s" % (name, start, end, end - start, reason)
            )

    lines.append("")
    lines.append("【协议切换后的后续协议材料】")
    ppm = report["post_protocol_material"]
    if not ppm[C2S] and not ppm[S2C]:
        lines.append("  （无）")
    for name in (C2S, S2C):
        for start, end in ppm[name]:
            lines.append("  %s[%d..%d)  %d 字节（未解析）" % (name, start, end, end - start))

    lines.append("")
    lines.append("【无法判断的部分】")
    und = report["undetermined"]
    if not und:
        lines.append("  （无）")
    for name, ranges in und.items():
        for start, end, reason in ranges:
            lines.append(
                "  %s[%d..%d)  %d 字节  原因：%s" % (name, start, end, end - start, reason)
            )
    integ = report["integrity"]
    if integ["tainted"]:
        lines.append(
            "  ※ 完整性于 ts=%s 破坏（%s），其后不做可靠关联，"
            "不以关键字搜索重新认定边界。"
            % (integ["first_failure_ts"], integ["reason"])
        )
    if report["sync_errors"]:
        lines.append("")
        lines.append("【状态同步告警】")
        for e in report["sync_errors"]:
            lines.append("  %s" % e)
    return "\n".join(lines)


def main(argv):
    with open(argv[1], "r", encoding="utf-8") as fh:
        capture = json.load(fh)
    analyzer = Analyzer()
    analyzer.run(capture)
    report = analyzer.report()
    print(format_text(report))
    out_path = argv[1] + ".report.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print("\n（JSON 报告已写入 %s）" % out_path)


if __name__ == "__main__":
    main(sys.argv)
