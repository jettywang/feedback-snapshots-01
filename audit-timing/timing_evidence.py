"""
时序证据装置：用假时钟标记 structlog / logging 流水线上三个"读钟"时刻。

三个被标记的时刻（用互不相同的 epoch 浮点值，年份即可肉眼区分）：

    T1 = 1_111_111_111.111  (2005 年)  事件时刻：请求处理代码调用 log.info() 的瞬间
    T2 = 2_222_222_222.222  (2040 年)  排队时刻：logging.LogRecord 创建 / 进入队列的瞬间
    T3 = 3_333_333_333.333  (2075 年)  格式化时刻：ProcessorFormatter 处理器链运行的瞬间

假时钟的推进是"标记手段"：它证明每个时间字段在流水线的哪一站读取时钟，
而不是断言真实系统中这些站之间一定有这么大的延迟。

运行：.venv/bin/python audit-timing/timing_evidence.py
"""

from __future__ import annotations

import asyncio
import datetime as real_dt
import io
import json
import logging
import logging.handlers
import queue
import threading
import types
from unittest import mock

import structlog
import structlog.processors
from structlog.processors import TimeStamper
from structlog.stdlib import LoggerFactory, ProcessorFormatter

T_EVENT = 1_111_111_111.111
T_ENQUEUE = 2_222_222_222.222
T_FORMAT = 3_333_333_333.333

LABELS = (
    (T_EVENT, "T1(事件/调用)"),
    (T_ENQUEUE, "T2(排队/Record创建)"),
    (T_FORMAT, "T3(格式化/输出)"),
)


def label(value):
    ts = (
        real_dt.datetime.fromisoformat(value).timestamp()
        if isinstance(value, str)
        else float(value)
    )
    for t, name in LABELS:
        if abs(ts - t) < 1e-3:
            return name
    return f"未知({value!r})"


class FakeClock:
    """线程安全的可推进假时钟。"""

    def __init__(self):
        self._t = T_EVENT
        self._lock = threading.Lock()

    def time(self):
        with self._lock:
            return self._t

    def set(self, t):
        with self._lock:
            self._t = t


clock = FakeClock()


class _FakeDateTime(real_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return real_dt.datetime.fromtimestamp(clock.time(), tz=tz)


# TimeStamper 的 now() 闭包在调用时查模块全局 dt（src/structlog/processors.py:15），
# 因此替换 structlog.processors.dt 即可让 TimeStamper 读假时钟。
fake_dt = types.SimpleNamespace(
    datetime=_FakeDateTime, timezone=real_dt.timezone
)


def advance_to(t=None, *, entered=None, gate=None):
    """一个处理器：可选门闩同步，随后把时钟推进到 t（t=None 时只同步不拨钟）。"""

    def proc(logger, method_name, event_dict):
        if entered is not None:
            entered.set()
        if gate is not None:
            gate.wait(timeout=10)
        if t is not None:
            clock.set(t)
        return event_dict

    return proc


def capture_record_created(logger, method_name, event_dict):
    """把 LogRecord.created（stdlib 在记录创建时打的戳）抄进输出。"""
    record = event_dict.get("_record")
    if record is not None:
        event_dict["record_created"] = record.created
    return event_dict


class SignalHandler(logging.StreamHandler):
    def __init__(self, stream, done):
        super().__init__(stream)
        self._done = done

    def emit(self, record):
        super().emit(record)
        self._done.set()


class NonFormattingQueueHandler(logging.handlers.QueueHandler):
    """
    默认 QueueHandler.prepare() 会在**调用线程**里提前 format 并把
    record.msg 覆盖成字符串，event_dict 就此丢失（见本脚本 S3 的注释）。
    进程内 QueueListener 不需要序列化，原样入队即可。
    """

    def prepare(self, record):
        return record


def make_formatter(fmt_entered=None, fmt_gate=None, foreign_gate=False):
    # foreign_pre_chain 在 processors 之前运行；外来记录的门闩必须放这里，
    # 否则 timestamp 会在拨钟之前被打上。
    foreign_pre_chain = [
        *(
            [advance_to(T_FORMAT, entered=fmt_entered, gate=fmt_gate)]
            if foreign_gate
            else []
        ),
        # 外来（纯 stdlib）记录在这里补 timestamp —— 发生在格式化站。
        TimeStamper(fmt="iso", key="timestamp"),
    ]
    return ProcessorFormatter(
        processors=[
            # 格式化站的第一件事：把时钟推进到 T3。
            advance_to(
                T_FORMAT,
                entered=None if foreign_gate else fmt_entered,
                gate=None if foreign_gate else fmt_gate,
            ),
            capture_record_created,
            # 这一站才打的戳 = 输出时刻。
            TimeStamper(fmt="iso", key="fmt_timestamp"),
            ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=foreign_pre_chain,
    )


def configure_structlog(*, chain_entered=None, chain_gate=None):
    """主链：TimeStamper 在事件站打戳；随后推进到 T2 再移交给 logging。"""
    structlog.configure(
        processors=[
            advance_to(
                None if chain_gate else T_EVENT,
                entered=chain_entered,
                gate=chain_gate,
            ),
            TimeStamper(fmt="iso", key="timestamp"),
            # 模拟"事件处理"与"移交 logging"之间的时间流逝。
            advance_to(T_ENQUEUE),
            ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )


def report(scenario, raw_line, verdict):
    row = json.loads(raw_line)
    print(f"\n=== {scenario} ===")
    print(f"原始输出: {raw_line.strip()}")
    for key in ("timestamp", "record_created", "fmt_timestamp"):
        if key in row:
            print(f"  {key:<15} -> {label(row[key])}")
    print(f"判定: {verdict}")


def scenario_sync():
    """S1: 同步 structlog -> 直连 StreamHandler(ProcessorFormatter)。"""
    stream, done = io.StringIO(), threading.Event()
    handler = SignalHandler(stream, done)
    handler.setFormatter(make_formatter())
    logger = logging.getLogger("audit.s1")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    configure_structlog()
    clock.set(T_EVENT)
    structlog.get_logger("audit.s1").info("sync-event")

    report(
        "S1 同步直连",
        stream.getvalue(),
        "timestamp=事件时刻, record_created=排队时刻, fmt_timestamp=输出时刻",
    )
    logger.removeHandler(handler)


async def _s2_body():
    stream, done = io.StringIO(), threading.Event()
    handler = SignalHandler(stream, done)
    handler.setFormatter(make_formatter())
    logger = logging.getLogger("audit.s2")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # 门闩：主链第一个处理器在执行线程里等主线程放行（只同步、不拨钟）。
    entered, gate = threading.Event(), threading.Event()
    configure_structlog(chain_entered=entered, chain_gate=gate)

    clock.set(T_EVENT)
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(
        structlog.get_logger("audit.s2").ainfo("async-event")
    )
    # 等执行线程真正跑进处理器链，再把时钟从 T1 拨到 T2 并放行。
    await loop.run_in_executor(None, entered.wait, 10)
    clock.set(T_ENQUEUE)
    gate.set()
    await task

    report(
        "S2 structlog ainfo（后台线程池）",
        stream.getvalue(),
        "timestamp 与 record_created 都是执行线程运行时刻(T2)，不是调用时刻(T1)",
    )
    logger.removeHandler(handler)


def scenario_async_structlog():
    asyncio.run(_s2_body())


def _queue_scenario(title, name, emit, verdict, foreign_gate=False):
    q = queue.SimpleQueue()
    stream, done = io.StringIO(), threading.Event()
    fmt_entered, fmt_gate = threading.Event(), threading.Event()
    handler = SignalHandler(stream, done)
    handler.setFormatter(
        make_formatter(
            fmt_entered=fmt_entered, fmt_gate=fmt_gate,
            foreign_gate=foreign_gate,
        )
    )
    logger = logging.getLogger(name)
    logger.addHandler(NonFormattingQueueHandler(q))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    listener = logging.handlers.QueueListener(q, handler)
    listener.start()
    try:
        clock.set(T_EVENT)
        emit(logger)
        # 等监听线程开始格式化，拨到 T3 后放行。
        fmt_entered.wait(timeout=10)
        clock.set(T_FORMAT)
        fmt_gate.set()
        done.wait(timeout=10)
    finally:
        listener.stop()
    report(title, stream.getvalue(), verdict)
    logger.handlers.clear()


def scenario_queue_structlog():
    """S3: structlog -> QueueHandler -> QueueListener 后台线程格式化。"""
    configure_structlog()

    def emit(logger):
        structlog.get_logger(logger.name).info("queued-event")

    _queue_scenario(
        "S3 structlog 经 QueueListener 后台格式化",
        "audit.s3",
        emit,
        "timestamp=事件时刻(T1), record_created=入队时刻(T2), "
        "fmt_timestamp=监听线程输出时刻(T3)",
    )


def scenario_queue_plain_stdlib():
    """S4: 纯 stdlib 记录(foreign) -> QueueHandler -> QueueListener。"""

    def emit(logger):
        logger.info("foreign-event")

    _queue_scenario(
        "S4 纯 stdlib 外来记录经 QueueListener",
        "audit.s4",
        emit,
        "外来记录的 timestamp 由 foreign_pre_chain 在格式化站补打(T3)；"
        "只有 record_created 指向调用/入队时刻(T1)",
        foreign_gate=True,
    )


def main():
    patches = (
        mock.patch("time.time", clock.time),
        mock.patch.object(structlog.processors, "dt", fake_dt),
    )
    for p in patches:
        p.start()
    try:
        scenario_sync()
        scenario_async_structlog()
        scenario_queue_structlog()
        scenario_queue_plain_stdlib()
    finally:
        for p in patches:
            p.stop()
        structlog.reset_defaults()


if __name__ == "__main__":
    main()
