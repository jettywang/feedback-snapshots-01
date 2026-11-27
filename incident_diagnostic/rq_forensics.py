#!/usr/bin/env python3
"""可复跑的 RQ 作业消失事故取证实验。

三个本地运行（最终就绪队列均为空），用 fakeredis（内存存储）+ 可控时钟复现：
  A. 领取后尚未建执行实例 worker 即崩溃（作业卡在中间队列）
  B. 函数跑完并写结果，但 result_ttl 过期后结果记录消失
  C. worker-1 领取并建实例后崩溃，worker-2 经维护清理重新领取并跑完

每次运行记录：实际键变化（rq:* 全量快照）、worker 心跳、函数标记（副作用）。
运行:  .venv/bin/python incident_diagnostic/rq_forensics.py
"""
from __future__ import annotations

import importlib
import sys
import time as time_module
from contextlib import contextmanager
from datetime import datetime, timezone

import fakeredis

import rq.executions
import rq.intermediate_queue
import rq.job
import rq.queue
import rq.registry
import rq.results
import rq.utils
import rq.worker.base
from rq import Queue, Worker

from incident_diagnostic import witness_jobs
from incident_diagnostic.witness_jobs import charge_customer

# ---------------------------------------------------------------- 可控时钟


class FakeClock:
    """单一时钟源：同时驱动 fakeredis 的 TTL 与 RQ 的时间戳。"""

    def __init__(self, start: float = 1_800_000_000.0):
        self.t = float(start)

    def time(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds

    def iso(self) -> str:
        return datetime.fromtimestamp(self.t, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


CLOCK = FakeClock()


@contextmanager
def patched_clock(clock: FakeClock):
    """把 rq.* 各模块里 import 进去的 now/current_timestamp 以及 time.time 都换成本时钟。"""
    real_time = time_module.time
    real_now = rq.utils.now
    real_current_timestamp = rq.utils.current_timestamp
    fake_now = lambda: datetime.fromtimestamp(clock.time(), tz=timezone.utc)  # noqa: E731
    fake_ts = lambda: int(clock.time())  # noqa: E731

    targets = []
    for module in list(sys.modules.values()):
        name = getattr(module, '__name__', '') or ''
        if not (name == 'rq' or name.startswith('rq.')):
            continue
        if getattr(module, 'now', None) is real_now:
            targets.append((module, 'now', real_now, fake_now))
        if getattr(module, 'current_timestamp', None) is real_current_timestamp:
            targets.append((module, 'current_timestamp', real_current_timestamp, fake_ts))

    time_module.time = clock.time  # type: ignore[assignment]
    for module, attr, _real, fake in targets:
        setattr(module, attr, fake)
    try:
        yield
    finally:
        time_module.time = real_time  # type: ignore[assignment]
        for module, attr, real, _fake in targets:
            setattr(module, attr, real)


# ------------------------------------------------- 函数标记（模拟真实世界副作用）

SIDE_EFFECTS: list = witness_jobs.SIDE_EFFECTS


# ---------------------------------------------------------------- 取证记录器


def _safe_decode(raw: bytes, limit: int = 70) -> str:
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return f'<binary {len(raw)}B>'
    text = text.replace('\n', ' ')
    return text if len(text) <= limit else text[:limit] + '…'


def _maybe_decompress(text: str) -> str:
    """RQ 3.0 将结果流中的 exc_string 压缩存储，尽量还原便于阅读。"""
    import base64
    import zlib

    try:
        return zlib.decompress(base64.b64decode(text)).decode('utf-8', errors='replace')
    except Exception:
        return text


def read_value(conn, key: str, ktype: str):
    if ktype == 'list':
        return [_safe_decode(m) for m in conn.lrange(key, 0, -1)]
    if ktype == 'zset':
        return [f'{_safe_decode(m)}={int(score)}' for m, score in conn.zrange(key, 0, -1, withscores=True)]
    if ktype == 'set':
        return sorted(_safe_decode(m) for m in conn.smembers(key))
    if ktype == 'string':
        return _safe_decode(conn.get(key))
    if ktype == 'stream':
        entries = []
        for entry_id, fields in conn.xrange(key):
            rendered = {}
            for field, value in fields.items():
                name = _safe_decode(field)
                if name in ('result', 'exc_info'):
                    rendered[name] = f'<{len(value)}B>'
                elif name == 'exc_string':
                    rendered[name] = _maybe_decompress(_safe_decode(value, limit=10000))
                else:
                    rendered[name] = _safe_decode(value)
            entries.append({entry_id.decode(): rendered})
        return entries
    if ktype == 'hash':
        out = {}
        for field, value in conn.hgetall(key).items():
            name = field.decode()
            if name == 'data':
                out[name] = f'<pickle {len(value)}B>'
            else:
                out[name] = _safe_decode(value)
        return out
    return None


def take_snapshot(conn, label: str) -> dict:
    snap = {'label': label, 'clock': CLOCK.iso(), 'keys': {}, 'side_effects': list(SIDE_EFFECTS)}
    for raw_key in sorted(conn.keys('rq:*')):
        key = raw_key.decode()
        ktype = conn.type(key).decode()
        snap['keys'][key] = (ktype, conn.ttl(key), read_value(conn, key, ktype))
    return snap


def fmt_marker(marker) -> str:
    func, token, epoch = marker
    iso = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%H:%M:%S')
    return f'{func}({token})@{iso}'


def print_snapshot(snap: dict, prev: dict | None) -> None:
    print(f"\n--- [{snap['clock']}] {snap['label']}")
    markers = [fmt_marker(m) for m in snap['side_effects']]
    print(f"    函数标记(副作用): {markers or '无'}")
    prev_keys = prev['keys'] if prev else {}
    for key, (ktype, ttl, value) in sorted(snap['keys'].items()):
        mark = ' '
        if key not in prev_keys:
            mark = '+'  # 新出现的键
        elif prev_keys[key][2] != value:
            mark = '~'  # 内容变化
        print(f'    {mark} {ktype:<7} ttl={ttl:<6} {key} -> {value}')
    for key in sorted(set(prev_keys) - set(snap['keys'])):
        print(f'    - {prev_keys[key][0]:<7}         {key}  (已消失)')


def job_status_in(snap: dict, job_key: str) -> str | None:
    entry = snap['keys'].get(job_key)
    if not entry or entry[0] != 'hash':
        return None
    return entry[2].get('status')


# ---------------------------------------------------------------- 场景

QUEUE_NAME = 'emails'


def fresh_env():
    SIDE_EFFECTS.clear()
    conn = fakeredis.FakeStrictRedis(server=fakeredis.FakeServer())
    # fakeredis 不实现 INFO，RQ 会回退为 5.0.9 从而走 LPOP 路径；
    # 这里预置版本缓存，模拟生产 Redis >= 6.2 的 LMOVE(中间队列)路径。
    setattr(conn, '__rq_redis_server_version', (7, 2, 0))
    queue = Queue(QUEUE_NAME, connection=conn)
    return conn, queue


def clock_self_check(conn) -> None:
    conn.set('rq:probe', '1', ex=10)
    CLOCK.advance(11)
    assert conn.get('rq:probe') is None, '可控时钟未能驱动 fakeredis TTL'
    CLOCK.advance(-11)


def run_a() -> list[dict]:
    """A: 领取(lmove)后、建执行实例前 worker 崩溃。"""
    print('\n' + '=' * 78)
    print('运行 A：领取后尚未建执行实例，worker 崩溃（作业滞留中间队列）')
    print('=' * 78)
    conn, queue = fresh_env()
    snaps = []

    job = queue.enqueue(charge_customer, 'tok-A', result_ttl=60)
    snaps.append(take_snapshot(conn, f'入队 job={job.id[:8]}…'))

    worker1 = Worker([queue], name='worker-1', connection=conn)
    worker1.register_birth()
    worker1.heartbeat()
    snaps.append(take_snapshot(conn, 'worker-1 登记出生 + 心跳'))

    dequeued = Queue.dequeue_any([queue], None, connection=conn)
    assert dequeued is not None
    snaps.append(take_snapshot(conn, 'worker-1 领取(lmove→中间队列) 后 ***崩溃***（未建执行实例）'))

    CLOCK.advance(61)
    worker2 = Worker([queue], name='worker-2', connection=conn)
    worker2.register_birth()
    queue.intermediate_queue.cleanup(worker2, queue)
    snaps.append(take_snapshot(conn, '+61s: worker-2 上线，中间队列清理第 1 次（仅记 first_seen）'))

    CLOCK.advance(61)
    queue.intermediate_queue.cleanup(worker2, queue)
    snaps.append(take_snapshot(conn, '+61s: 中间队列清理第 2 次（>1min → 判卡死，进失败注册表）'))

    worker2.register_death()
    snaps.append(take_snapshot(conn, '终态：worker-2 登记死亡'))

    job_key = f'rq:job:{job.id}'
    assert job_status_in(snaps[-1], job_key) == 'failed'
    assert not SIDE_EFFECTS, '函数不应执行'
    assert conn.llen(queue.key) == 0
    return snaps


def run_b() -> list[dict]:
    """B: 正常跑完，result_ttl 过期后结果记录消失。"""
    print('\n' + '=' * 78)
    print('运行 B：函数跑完并写结果，result_ttl=60s 过期后结果记录消失')
    print('=' * 78)
    conn, queue = fresh_env()
    snaps = []

    job = queue.enqueue(charge_customer, 'tok-B', result_ttl=60)
    snaps.append(take_snapshot(conn, f'入队 job={job.id[:8]}… (result_ttl=60)'))

    worker = Worker([queue], name='worker-1', connection=conn)
    worker.register_birth()
    snaps.append(take_snapshot(conn, 'worker-1 登记出生'))

    dequeued = Queue.dequeue_any([queue], None, connection=conn)
    assert dequeued is not None
    job2, queue2 = dequeued
    snaps.append(take_snapshot(conn, '领取(lmove→中间队列)'))

    execution = worker.prepare_execution(job2)
    snaps.append(take_snapshot(conn, f'建执行实例 E={execution.id[:8]}…'))

    worker.perform_job(job2, queue2, execution)
    snaps.append(take_snapshot(conn, 'perform_job 成功（函数标记已写，结果已存）'))

    worker.register_death()
    snaps.append(take_snapshot(conn, 'worker-1 登记死亡（worker 键 60s 后过期）'))

    CLOCK.advance(120)
    snaps.append(take_snapshot(conn, '+120s: result_ttl 已过 → job 键/结果过期，worker 键过期'))

    queue.finished_job_registry.cleanup()
    snaps.append(take_snapshot(conn, '成功注册表清理后终态'))

    assert len(SIDE_EFFECTS) == 1, '函数应执行一次'
    assert conn.llen(queue.key) == 0
    assert not conn.exists(f'rq:job:{job.id}'), 'job 键应已过期'
    return snaps


def run_c() -> list[dict]:
    """C: worker-1 建实例后崩溃，worker-2 清理后重新领取并跑完。"""
    print('\n' + '=' * 78)
    print('运行 C：worker-1 建执行实例后崩溃，worker-2 重新领取并执行')
    print('=' * 78)
    conn, queue = fresh_env()
    snaps = []

    job = queue.enqueue(charge_customer, 'tok-C', result_ttl=3600)
    snaps.append(take_snapshot(conn, f'入队 job={job.id[:8]}…'))

    worker1 = Worker([queue], name='worker-1', connection=conn)
    worker1.register_birth()
    snaps.append(take_snapshot(conn, 'worker-1 登记出生'))

    dequeued = Queue.dequeue_any([queue], None, connection=conn)
    assert dequeued is not None
    job1, queue1 = dequeued
    snaps.append(take_snapshot(conn, 'worker-1 领取(lmove→中间队列)'))

    execution1 = worker1.prepare_execution(job1)
    snaps.append(take_snapshot(conn, f'worker-1 建执行实例 E1={execution1.id[:8]}…'))

    worker1.prepare_job_execution(job1, remove_from_intermediate_queue=True)
    snaps.append(take_snapshot(conn, 'worker-1 马厩进程已置 status=started 后 ***崩溃***（函数体未运行）'))

    CLOCK.advance(500)  # worker_ttl(420)+60 与执行实例 TTL(240) 均过期
    worker2 = Worker([queue], name='worker-2', connection=conn)
    worker2.register_birth()
    snaps.append(take_snapshot(conn, '+500s: worker-1 键已过期；worker-2 上线'))

    queue.started_job_registry.cleanup()
    snaps.append(take_snapshot(conn, 'wip 注册表清理：遗弃作业 → 失败注册表(AbandonedJobError)'))

    queue.failed_job_registry.requeue(job.id)
    snaps.append(take_snapshot(conn, '运维重新入队(requeue) → 回到就绪队列'))

    dequeued2 = Queue.dequeue_any([queue], None, connection=conn)
    assert dequeued2 is not None
    job2, queue2 = dequeued2
    execution2 = worker2.prepare_execution(job2)
    snaps.append(take_snapshot(conn, f'worker-2 重新领取 + 建执行实例 E2={execution2.id[:8]}…'))

    worker2.perform_job(job2, queue2, execution2)
    snaps.append(take_snapshot(conn, 'worker-2 perform_job 成功（函数标记=1）'))

    worker2.register_death()
    snaps.append(take_snapshot(conn, '终态：worker-2 登记死亡'))

    assert len(SIDE_EFFECTS) == 1, '函数应只执行一次（由 worker-2）'
    assert conn.llen(queue.key) == 0
    final_status = job_status_in(snaps[-1], f'rq:job:{job.id}')
    assert final_status == 'finished', final_status
    return snaps


# ---------------------------------------------------------------- 汇总


def main() -> int:
    with patched_clock(CLOCK):
        conn, _ = fresh_env()
        clock_self_check(conn)

        all_runs = {'A': run_a(), 'B': run_b(), 'C': run_c()}

    for name, snaps in all_runs.items():
        prev = None
        for snap in snaps:
            print_snapshot(snap, prev)
            prev = snap

    print('\n' + '=' * 78)
    print('三次运行对比（最终就绪队列均为空）')
    print('=' * 78)
    for name, snaps in all_runs.items():
        all_keys = [k for s in snaps for k in s['keys']]
        executions = sorted({k for k in all_keys if k.startswith('rq:execution:')})
        intermediate_seen = any(':intermediate' in k and 'first_seen' not in k for k in all_keys)
        wip_seen = any(k.startswith('rq:wip:') for k in all_keys)
        failed_seen = any(k.startswith('rq:failed:') for k in all_keys)
        markers = snaps[-1]['side_effects']
        heartbeats = {}
        for s in snaps:
            for k, (ktype, _ttl, value) in s['keys'].items():
                if ktype == 'hash' and k.startswith('rq:worker:') and isinstance(value, dict):
                    heartbeats.setdefault(k.split(':')[2], set()).add(value.get('last_heartbeat', '?'))
        print(f'\n运行 {name}:')
        print(f'  中间队列曾出现作业 : {intermediate_seen}')
        print(f'  wip 注册表曾出现   : {wip_seen}')
        print(f'  失败注册表曾出现   : {failed_seen}')
        print(f'  执行实例键数量     : {len(executions)}  {["…" + e[-12:] for e in executions]}')
        print(f'  worker 心跳记录    : {{' + ', '.join(f'{w}: {len(v)} 次' for w, v in sorted(heartbeats.items())) + '}')
        print(f'  函数标记(副作用)   : {len(markers)} 次  {[fmt_marker(m) for m in markers]}')
    print('\n全部断言通过。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
