# structlog 时间戳溯源与审计接入指南

接收端想按日志时间还原处理顺序，前提是知道每个时间字段在流水线的**哪一站**读取时钟。
本目录用一只可推进的假时钟给出可复现的时序证据：

```
.venv/bin/python audit-timing/timing_evidence.py
```

装置把三个时刻标成三个一眼可辨的 epoch 值（年份即标签）：

| 标签 | 值 | 含义 |
|---|---|---|
| T1 | 1_111_111_111.111（2005 年） | 事件时刻：请求处理代码调用 `log.info()` 的瞬间 |
| T2 | 2_222_222_222.222（2040 年） | 排队时刻：`logging.LogRecord` 创建 / 进入队列的瞬间 |
| T3 | 3_333_333_333.333（2075 年） | 格式化时刻：`ProcessorFormatter` 处理器链运行的瞬间 |

假时钟的推进是**标记手段**：证明每个字段在哪一站读钟，不断言真实系统中各站之间有多大延迟。

## 一、三个时间分别在哪一站产生

沿 structlog 源码路径，一条日志会经过三个可能读钟的站：

1. **structlog 主处理器链** — `BoundLoggerBase._process_event()`（`src/structlog/_base.py:123`）
   在调用 `log.info()` 的线程里同步执行。`TimeStamper`（`src/structlog/processors.py:470`）
   在这里打 `timestamp`。**同步路径下这就是事件（请求处理）时刻。**
   例外：`await log.ainfo(...)` 等 `a*` 方法把整条链扔进线程池
   （`src/structlog/stdlib.py:450` `_dispatch_to_sync` → `run_in_executor`），
   打戳发生在**执行线程跑起来的时刻**，相对 await 调用点的延迟无上限。

2. **stdlib 记录创建** — `logging.Logger._log` → `LogRecord.__init__` 里
   `self.created = time.time()`。发生在 structlog 链之后、仍在调用线程；
   用 `QueueHandler` 时就是**入队前一刻**，是"排队时刻"的权威来源。
   `logging.Formatter` 的 `%(asctime)s` 由 `formatTime()` 从 `record.created` 换算，
   所以 asctime 也是排队时刻，不是格式化时刻。

3. **格式化** — `ProcessorFormatter.format()`（`src/structlog/stdlib.py:1148`）
   运行它自己的 `processors`（以及外来记录的 `foreign_pre_chain`）。
   直连 handler 时紧随第 2 站；挂 `QueueListener` 时在**监听线程**、出队之后才运行，
   延迟取决于队列积压。这里的 `TimeStamper` 打的是**输出时刻**。

## 二、四个场景的时序证据

`timing_evidence.py` 的输出（每行 JSON 都是真实渲染结果）：

| 场景 | `timestamp`（主链 TimeStamper） | `record_created`（stdlib） | `fmt_timestamp`（Formatter 链 TimeStamper） |
|---|---|---|---|
| S1 同步直连 | **T1 事件** | T2 排队 | T3 输出 |
| S2 `ainfo` 后台线程池 | **T2 执行线程运行时刻**（≠ 调用时刻 T1！） | T2 | T3 输出 |
| S3 structlog + QueueListener | **T1 事件** | T2 入队 | T3 监听线程输出 |
| S4 纯 stdlib 外来记录 + QueueListener | **T3 输出**（`foreign_pre_chain` 补打） | T1 调用/入队 | T3 输出 |

关键结论：

- 同一个字段名 `timestamp`，在 S1/S3 里是事件时刻，在 S2 里漂到执行线程时刻，
  在 S4 里干脆是输出时刻。**字段名不代表语义，位置才决定语义。**
- `record.created` 永远在调用线程、入队之前打，是四条路径里唯一始终
  "不晚于排队"的时间。
- S2 证明：`a*` 异步方法下 `timestamp` 与 `record.created` 一起漂移，
  两者都无法还原请求处理的真实时刻。
- 附带发现：默认 `QueueHandler.prepare()` 会在调用线程提前 `format()`
  并把 `record.msg` 覆盖成字符串，`ProcessorFormatter` 将解不出 event_dict。
  进程内 `QueueListener` 必须像脚本里那样覆写 `prepare` 原样入队。

## 三、给审计接入者的自证方案

**目标：用日志时间还原请求处理顺序。**

### 推荐选择（按可信度排序）

1. **首选**：`TimeStamper` 放在 `structlog.configure()` 的主处理器链里，
   并**只用同步** `log.info()` 等方法（S1/S3 形态）。
   此时 `timestamp` = 请求处理时刻，可直接排序。
   若同时输出 `record.created`（或 asctime），还能自校：
   `timestamp ≤ created`，两者正常应只差微秒级。
2. **次选**（必须混用纯 stdlib 日志时）：以 `record.created` 排序，
   外来记录的 `timestamp` 字段**不要**用于排序（S4 证明它是输出时刻）。
3. **避免**：把 `TimeStamper` 只放在 `ProcessorFormatter` 的
   `processors`/`foreign_pre_chain` 里再拿它排序——那是输出顺序，不是处理顺序。
4. **避免**：用 `a*` 异步日志的 `timestamp` 还原请求时序（S2）；
   若业务必须用 `a*`，在 await 之前由请求代码自己取一个时间戳放进事件字段
   （如 `log = log.bind(request_ts=...)`），让打戳回到调用点。

### 接入方自证清单

- 静态检查：确认 `TimeStamper` 在主链而非 `ProcessorFormatter` 链；
  确认没有 `QueueHandler.prepare` 提前格式化；grep 是否使用 `ainfo`/`alog` 等。
- 动态验证：克隆 `timing_evidence.py` 的假时钟装置，接入方替换自己的
  structlog/logging 配置重跑，三个标签落位与上表一致即自证通过。
- 运行期交叉校验：对每条记录断言 `timestamp ≤ record_created ≤ fmt_timestamp`
  （同步路径）；出现 `timestamp ≈ fmt_timestamp ≫ record_created` 说明
  打戳实际发生在输出站。

## 四、旧记录缺字段时能判断到什么程度

| 旧记录里有的字段 | 能判断的 | 不能判断的 |
|---|---|---|
| 只有主链 `timestamp` 且配置可考（主链 + 同步） | 视为事件时刻，可直接排处理顺序 | 若当时用过 `a*` 方法，则该时间只是执行线程运行时刻，排序可信度降级 |
| 只有 `timestamp` 且配置不可考 | 只能给出区间：事件时刻 ≤ timestamp ≤ 输出时刻 | 无法确定它属于哪一站，不能单独用于精确排序 |
| 只有 `asctime` / `record_created` | 这是排队时刻：事件时刻 ≤ 它 ≤ 输出时刻；同步路径下与事件时刻通常只差微秒，可近似当事件时刻 | `a*` 路径下它同样漂移；与真实事件时刻的差无上限 |
| `timestamp` + `created` 都有 | 若两者接近（毫秒级内），可高置信度当作事件时刻；若差距大，说明走了异步/队列，至少能给出 `[timestamp, created]` 或 `[created, 输出]` 的区间 | 无法排除 S2 式整体漂移（两者一起晚） |
| 只有 `fmt_timestamp` / 输出侧时间 | 只能给出"事件不晚于该时刻"的上界 | 完全无法还原处理顺序，只能还原输出顺序 |
| 什么字段都没有 | 只能依赖文件内顺序 / 接收端到达顺序给出弱排序 | 无法自证；建议在接入侧补字段后重新采集 |

一句话：**缺主链 `timestamp` 时，`record_created` 是事件时刻的最佳下界代理；
缺 `created` 时，任何输出侧时间只能给上界；两者都缺，则处理顺序不可自证。**
