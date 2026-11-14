"""本地对端仿真：h2 双端 + 显式投递的内存导线。

服务器端被脚本化：请求到达（receive）与业务处理（apply，产生副作用）
是两个独立步骤，从而可以在"处理前/处理后/响应前/响应后"等不同时刻
关闭连接，精确复现客户端无法区分的状态。

副作用记录在 server.side_effects 中，测试用它校验分类结果与真实处理
情况的一致性：凡被分类为"未处理"的流，绝不能出现在副作用日志里。
"""

from __future__ import annotations

import h2.config
import h2.connection
import h2.events

from .classifier import RetryClassifier, hint_for_method


class Wire:
    """双向字节缓冲；cut 后投递静默丢弃（模拟 TCP RST 后字节消失）。"""

    def __init__(self) -> None:
        self.client_to_server = bytearray()
        self.server_to_client = bytearray()
        self.cut = False


class ClientEndpoint:
    def __init__(self, sim: Sim) -> None:
        self.sim = sim
        self.conn = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True)
        )
        self.conn.initiate_connection()
        self.classifier = RetryClassifier()
        self._unflushed: list[int] = []

    def submit(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        idempotency_key: str | None = None,
    ) -> int:
        sid = self.conn.get_next_available_stream_id()
        headers = [
            (":method", method),
            (":scheme", "https"),
            (":authority", "peer"),
            (":path", path),
        ]
        self.conn.send_headers(sid, headers)
        if body:
            self.conn.send_data(sid, body)
        self.conn.end_stream(sid)
        self.classifier.register(sid, method, hint_for_method(method, idempotency_key))
        self._unflushed.append(sid)
        return sid

    def flush(self) -> None:
        """把 h2 输出推到导线上；只有此时请求才算"送上对端"。"""
        if self.sim.wire.cut:
            return  # 连接已断：字节发不出去，未刷的流保持 NOT_SENT
        self.sim.wire.client_to_server += self.conn.data_to_send()
        for sid in self._unflushed:
            self.classifier.on_request_end(sid)
        self._unflushed.clear()

    def receive(self, data: bytes) -> None:
        events = self.conn.receive_data(data)
        for ev in events:
            if isinstance(ev, h2.events.ResponseReceived):
                self.classifier.on_response_headers(ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                self.classifier.on_response_end(ev.stream_id)
            elif isinstance(ev, h2.events.StreamReset):
                self.classifier.on_stream_reset(ev.stream_id, ev.error_code)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                self.classifier.on_goaway(ev.last_stream_id, ev.error_code)
        self.conn.data_to_send()  # 丢弃 SETTINGS ack 等回包，仿真中无需回传


class ServerEndpoint:
    def __init__(self, sim: Sim) -> None:
        self.sim = sim
        self.conn = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False)
        )
        self.conn.initiate_connection()
        self.completed_requests: set[int] = set()  # 请求已完整到达，等待处理
        self.side_effects: list[int] = []  # 已应用的写操作（业务副作用日志）
        self.responded: list[int] = []

    def receive(self, data: bytes) -> None:
        events = self.conn.receive_data(data)
        for ev in events:
            if isinstance(ev, h2.events.StreamEnded):
                self.completed_requests.add(ev.stream_id)

    def flush(self) -> None:
        if self.sim.wire.cut:
            return
        self.sim.wire.server_to_client += self.conn.data_to_send()

    # ---- 脚本化行为 ----

    def apply(self, stream_id: int) -> None:
        """模拟业务写操作：只有显式调用才产生副作用。"""
        assert stream_id in self.completed_requests, "请求未完整到达就处理？"
        self.side_effects.append(stream_id)

    def respond(self, stream_id: int, status: str = "200", body: bytes = b"ok") -> None:
        self.conn.send_headers(stream_id, [(":status", status)])
        self.conn.send_data(stream_id, body, end_stream=True)
        self.responded.append(stream_id)

    def respond_headers_only(self, stream_id: int, status: str = "200") -> None:
        self.conn.send_headers(stream_id, [(":status", status)])

    def goaway(self, last_stream_id: int, error_code: int = 0) -> None:
        self.conn.close_connection(error_code=error_code, last_stream_id=last_stream_id)

    def reset(self, stream_id: int, error_code: int) -> None:
        self.conn.reset_stream(stream_id, error_code=error_code)


class Sim:
    """一次仿真：客户端 + 脚本化服务器 + 可控断连的导线。"""

    def __init__(self) -> None:
        self.wire = Wire()
        self.client = ClientEndpoint(self)
        self.server = ServerEndpoint(self)
        # 交换 preface / SETTINGS / ack
        self.client.flush()
        self.deliver_client_to_server()
        self.server.flush()
        self.deliver_server_to_client()
        self.client.flush()
        self.deliver_client_to_server()
        self.server.flush()
        self.deliver_server_to_client()

    def deliver_client_to_server(self) -> None:
        data = bytes(self.wire.client_to_server)
        self.wire.client_to_server.clear()
        if data and not self.wire.cut:
            self.server.receive(data)

    def deliver_server_to_client(self) -> None:
        data = bytes(self.wire.server_to_client)
        self.wire.server_to_client.clear()
        if data and not self.wire.cut:
            self.client.receive(data)

    def roundtrip(self) -> None:
        """客户端刷出并投递，服务器回包也投递。"""
        self.client.flush()
        self.deliver_client_to_server()
        self.server.flush()
        self.deliver_server_to_client()

    def cut(self, reason: str = "tcp_reset") -> None:
        """模拟连接异常断开（TCP RST）：未投递的字节全部丢失。"""
        self.wire.cut = True
        self.wire.client_to_server.clear()
        self.wire.server_to_client.clear()
        self.client.classifier.on_connection_terminated(reason)
