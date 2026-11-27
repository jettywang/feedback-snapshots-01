# RQ 作业消失事故诊断手册（可复跑）

值班现象：就绪队列里没有这个作业了，但不确定它到底有没有跑过。
本手册给出可复跑的取证实验与判定规则：什么证据足以证明函数**开始过**、**结束过**、**被重新领取过**。

## 复跑方法

```bash
.venv/bin/python incident_diagnostic/rq_forensics.py
```

- 存储：`fakeredis`（纯内存，每次运行独立 `FakeServer`）。
- 时钟：`FakeClock` 同时替换 `time.time`（驱动 fakeredis TTL）与各 `rq.*` 模块里的
  `now` / `current_timestamp`（驱动心跳、注册表分数），`CLOCK.advance(n)` 即时间快进。
- 注意：fakeredis 不实现 `INFO`，RQ 会回退按 Redis 5.0.9 走 LPOP 路径；脚本预置
  `__rq_redis_server_version=(7,2,0)`，模拟生产 Redis ≥ 6.2 的 LMOVE（中间队列）路径。
- 函数标记：`incident_diagnostic/witness_jobs.py` 的 `SIDE_EFFECTS`，模拟函数在 Redis
  之外的真实副作用（扣款/发信/写库），对应生产上的业务对账记录。

## 取证模型：三类证据源

| 证据源 | 键 | 生命周期 |
|---|---|---|
| 中间队列 | `rq:queue:<q>:intermediate`（list）、`…:first_seen:<job>`（string, 24h） | LMOVE 领取时进入，horse 开始执行时 LREM 移出 |
| 执行实例 | `rq:execution:<job>:<exec>`（hash, TTL≈90s）、`rq:executions:<job>`（zset）、`rq:wip:<q>`（zset，成员为 `job:exec` 复合键）、`rq:worker:<name>`（hash, TTL=worker_ttl+60=480s）、`rq:worker:<name>:executions`（set） | 建实例时创建，正常结束时主动删除；崩溃则靠 TTL 过期 |
| 结果记录 | `rq:job:<id>`（hash：status/started_at/ended_at/worker_name）、`rq:results:<id>`（stream，TTL=result_ttl）、`rq:finished:<q>` / `rq:failed:<q>`（zset） | 成功：job 键与结果流 TTL=result_ttl（默认 500s）；失败：job 键保留约 1 年（failure_ttl） |

心跳证据：`rq:worker:<name>` 的 `last_heartbeat` 字段与键 TTL。键在且 TTL 被反复续期 = 活着；
键消失且无 `death` 字段 = 非正常死亡（TTL 自然过期）。

## 判定规则

**证明"函数开始过"（函数体真的执行了）**
- 铁证只有一条：函数标记 / 业务副作用存在。
- `status=started` + `started_at` **不够**：它由 `prepare_job_execution` 在调用函数体**之前**写入
  （运行 C 实测：崩溃时 status=started，但标记=0）。
- 执行实例键存在只证明"被领取并准备执行"，同样不等于函数体已运行。

**证明"函数结束过"**
- result_ttl 窗口内：`status=finished` + `ended_at` + 结果流 `rq:results:<id>` 中
  `type=1`（成功）条目（含 return_value、execution_id、execution_ended_at）+ `rq:finished:<q>` 成员。
- 窗口外（结果已过期）：Redis 内**无任何证据**，只剩函数标记 / 业务对账 / 应用日志。

**证明"被重新领取过"**
- 结果流中先 `type=2`（失败：`AbandonedJobError` / `stuck in intermediate queue`）后 `type=1`（成功）——
  运行 C 终态实测可见两条条目共存，是最耐久的证据（随 result_ttl 存活）。
- 生命周期内出现 >1 个 execution_id（`rq:executions:<job>`、wip 复合成员）——但实例键 TTL 短（≈90s），
  死后几分钟即消失。
- job hash 残留：`enqueued_at` 被刷新而 `created_at` 不变、遗留 `exc_info` 字段、
  最终 `worker_name` 与失败记录中的执行者不同。
- `rq:failed:<q>` 曾出现该 job 后又消失（requeue 会将其移出失败注册表）。

## 三次运行对比（实测，最终就绪队列均为空）

| 证据 | A：领取后未建实例即崩溃 | B：跑完但结果过期 | C：worker-1 崩溃，worker-2 重领 |
|---|---|---|---|
| 中间队列曾出现 | 是（滞留至清理） | 是（毫秒级，正常路径） | 是（两次：w1、w2 各一次） |
| 执行实例数 | 0 | 1 | 2 |
| wip 注册表 | 从未出现 | 出现并正常清除 | w1 的过期成员被清理，w2 的正常清除 |
| 失败注册表 | 终态在内（stuck in intermediate queue） | 从未出现 | 曾进（AbandonedJobError），requeue 后移出 |
| 结果流 | type=2（stuck） | type=1，60s 后整键过期 | type=2（abandoned）+ type=1（w2 成功） |
| 心跳 | worker-1 停在 08:00:00，键 480s 后过期 | 正常登记 death | worker-1 键过期消失；worker-2 正常 |
| 函数标记 | **0 次** | **1 次** | **1 次**（worker-2 写入） |
| 终态 job 状态 | failed（保留 1 年） | 键已过期，无迹可寻 | finished，worker_name=worker-2 |

## 证据不足的窗口：判"未知"，以及补哪项观察可区分

1. **运行 A，崩溃后 ~1 分钟内**（中间队列清理需要两次扫描、间隔 >60s 的 first_seen 宽限）：
   队列空、status=queued、无实例、标记=0 → **未知**：worker 可能已死，也可能只是
   领取与建实例之间的正常（极短）间隔。
   → 补充观察：`rq:worker:<name>` 键是否存在且 `last_heartbeat` 持续刷新（TTL 被续期）。
   心跳活着 = 慢，不是死；键消失且无 death 字段 = 已崩溃。

2. **运行 B，结果过期之后**：Redis 内零痕迹 → **未知**："跑完且结果过期"与"从未入队"
   在 Redis 里不可区分。
   → 补充观察：函数副作用 / 业务对账 / 应用日志中的任一外部记录；预防上可调大
   `result_ttl` 或外接结果归档。

3. **运行 C，worker-1 死后到重领完成前**：wip 有过期成员、status=started 停滞、
   worker 键消失、标记=0 → **未知**：崩溃点可能在函数体**之前**（本例）也可能在函数体
   **之中**（副作用已发生但 Redis 看不出）。
   → 补充观察：函数标记 / 业务对账。注意推论：若崩溃在函数体之中，重领会让函数
   **执行两次**，只有幂等键或副作用计数能暴露。

## 值班速查命令

```bash
redis-cli LLEN  rq:queue:<q>                      # 就绪队列
redis-cli LRANGE rq:queue:<q>:intermediate 0 -1   # 已领取未建实例
redis-cli ZRANGE rq:wip:<q> 0 -1 WITHSCORES       # 执行中（复合键 job:exec）
redis-cli HGETALL rq:job:<id>                     # status/worker_name/started_at/ended_at
redis-cli XRANGE rq:results:<id> - +              # 结果流：type=1 成功 / type=2 失败
redis-cli ZRANGE rq:failed:<q> 0 -1               # 失败注册表
redis-cli HGET rq:worker:<name> last_heartbeat    # 心跳
redis-cli TTL  rq:worker:<name>                   # TTL 在续期 = 活着
```
