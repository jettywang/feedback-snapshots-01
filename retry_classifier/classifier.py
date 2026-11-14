"""重试分类器核心：只消费连接上真实发生的 h2 事件，不猜测对端行为。

设计原则：
- 分类（Category）只表达"协议能证明什么"，与重试策略解耦。
- 重试动作（Action）= 分类结果 + 应用显式提供的幂等依据（IdempotencyHint）。
- POST 等无幂等依据的请求，仅因"没收到响应"绝不自动重放。
- RST_STREAM 的 REFUSED_STREAM 是对端"未处理"的显式声明，与其它错误码
  （CANCEL/INTERNAL_ERROR 等，只表示流被中止、无法证明未处理）严格区分。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

# RFC 7540 错误码（与 h2.errors.ErrorCodes 数值一致，此处独立定义避免依赖）
REFUSED_STREAM = 0x7

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"})


class IdempotencyHint(enum.Enum):
    """应用提供的幂等依据，与协议事件分开表达。"""

    SAFE_METHOD = "safe_method"  # RFC 7231 安全/幂等方法，重放不改变语义
    IDEMPOTENCY_KEY = "idempotency_key"  # 应用提供幂等键，服务端按键去重
    NONE = "none"  # 无任何依据（典型：裸 POST）


def hint_for_method(method: str, idempotency_key: str | None = None) -> IdempotencyHint:
    if idempotency_key is not None:
        return IdempotencyHint.IDEMPOTENCY_KEY
    if method.upper() in SAFE_METHODS:
        return IdempotencyHint.SAFE_METHOD
    return IdempotencyHint.NONE


class Category(enum.Enum):
    """协议能证明的处理状态。"""

    COMPLETED = "completed"  # 已收到完整响应，无需重试
    NOT_SENT = "not_sent"  # 请求字节未送上对端（连接先断）
    NOT_PROCESSED = "not_processed"  # GOAWAY 边界之外，协议保证未被处理
    REFUSED = "refused"  # RST_STREAM(REFUSED_STREAM)：对端声明未执行任何处理
    MAYBE_PROCESSED = "maybe_processed"  # 无法证明：请求可能已被执行
    PARTIAL_RESPONSE = "partial_response"  # 响应已开始但未完整：已处理、结果未送达


class Action(enum.Enum):
    DELIVER = "deliver"  # 把已完成的响应交给应用
    REPLAY = "replay"  # 可安全自动重放
    ASK_APPLICATION = "ask_application"  # 必须业务决策，禁止自动重放


@dataclass
class StreamRecord:
    stream_id: int
    method: str
    hint: IdempotencyHint
    request_end_sent: bool = False  # END_STREAM 已刷到传输层
    response_started: bool = False
    response_ended: bool = False
    reset_code: int | None = None


@dataclass(frozen=True)
class Verdict:
    stream_id: int
    category: Category
    action: Action
    reason: str


class RetryClassifier:
    """事件驱动的重试分类器。

    由 h2 事件循环喂事件；连接终止后调用 verdict()/classify_all()。
    """

    def __init__(self) -> None:
        self.streams: dict[int, StreamRecord] = {}
        self.goaways: list[tuple[int, int]] = []  # (last_stream_id, error_code)
        self.terminated_reason: str | None = None

    # ---- 事件入口 ----

    def register(self, stream_id: int, method: str, hint: IdempotencyHint) -> None:
        """请求已交给 h2 层（但未必已发到传输层）。"""
        self.streams[stream_id] = StreamRecord(stream_id, method, hint)

    def on_request_end(self, stream_id: int) -> None:
        """请求字节（含 END_STREAM）已刷到传输层。"""
        self.streams[stream_id].request_end_sent = True

    def on_response_headers(self, stream_id: int) -> None:
        self.streams[stream_id].response_started = True

    def on_response_end(self, stream_id: int) -> None:
        self.streams[stream_id].response_ended = True

    def on_stream_reset(self, stream_id: int, error_code: int) -> None:
        self.streams[stream_id].reset_code = error_code

    def on_goaway(self, last_stream_id: int, error_code: int = 0) -> None:
        self.goaways.append((last_stream_id, error_code))

    def on_connection_terminated(self, reason: str) -> None:
        self.terminated_reason = reason

    # ---- 分类 ----

    @property
    def goaway_bound(self) -> int | None:
        """有效 GOAWAY 边界：多个 GOAWAY 的 last_stream_id 取最小值。

        RFC 7540 §6.8 允许对端追加 GOAWAY 调低边界（单调不增）；
        即使对端违规调高，取最小值也是最保守（最安全）的解释。
        """
        if not self.goaways:
            return None
        return min(last for last, _ in self.goaways)

    def classify(self, stream_id: int) -> tuple[Category, str]:
        rec = self.streams[stream_id]

        if rec.response_ended:
            return Category.COMPLETED, "已收到完整响应"

        if rec.reset_code is not None:
            if rec.reset_code == REFUSED_STREAM:
                return (
                    Category.REFUSED,
                    "RST_STREAM(REFUSED_STREAM)：对端声明未执行任何应用处理",
                )
            return (
                Category.MAYBE_PROCESSED,
                f"RST_STREAM(0x{rec.reset_code:x})：仅表示流被中止，"
                "不能证明未处理，与 REFUSED_STREAM 语义不同",
            )

        if not rec.request_end_sent:
            return Category.NOT_SENT, "请求未完整送上对端连接即断开"

        bound = self.goaway_bound
        if bound is not None and stream_id > bound:
            return (
                Category.NOT_PROCESSED,
                f"stream_id {stream_id} > GOAWAY last_stream_id {bound}，"
                "协议保证对端不会处理",
            )

        if rec.response_started:
            return (
                Category.PARTIAL_RESPONSE,
                "响应已开始但未完整：请求已被处理，结果未送达",
            )

        if bound is not None:
            return (
                Category.MAYBE_PROCESSED,
                f"stream_id {stream_id} <= GOAWAY last_stream_id {bound}，"
                "对端'可能已处理'，协议无法证明",
            )
        return (
            Category.MAYBE_PROCESSED,
            "连接异常断开且未收到 GOAWAY，无法证明对端是否已处理",
        )

    @staticmethod
    def _action_for(category: Category, hint: IdempotencyHint) -> Action:
        if category is Category.COMPLETED:
            return Action.DELIVER
        if category in (Category.NOT_SENT, Category.NOT_PROCESSED, Category.REFUSED):
            # 协议/对端已证明未处理：任何方法都可安全重放
            return Action.REPLAY
        # MAYBE_PROCESSED / PARTIAL_RESPONSE：只有应用给了幂等依据才可自动重放
        if hint in (IdempotencyHint.SAFE_METHOD, IdempotencyHint.IDEMPOTENCY_KEY):
            return Action.REPLAY
        return Action.ASK_APPLICATION

    def verdict(self, stream_id: int) -> Verdict:
        rec = self.streams[stream_id]
        category, reason = self.classify(stream_id)
        return Verdict(
            stream_id=stream_id,
            category=category,
            action=self._action_for(category, rec.hint),
            reason=reason,
        )

    def classify_all(self) -> list[Verdict]:
        return [self.verdict(sid) for sid in sorted(self.streams)]
