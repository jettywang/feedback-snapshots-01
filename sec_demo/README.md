# ContextVar 身份在 aiohttp 请求任务与 cleanup 流程中的传播核查

## 结论先行

团队的假设——“请求结束或被取消后，所有后台任务都会自动失去 ContextVar 中的身份”——**不成立**。

- `ContextVar.set()` / `reset(token)` 只作用于**当前任务自己的 context 副本**。
- `asyncio.create_task()` 在创建子任务时**复制一份 context 快照**；父任务此后的
  `set` / `reset` 不会传播到子任务。
- 因此在请求处理过程中 `create_task` 出去的后台任务，会带着 principal 的副本继续存活，
  请求任务结束、中间件 `reset`、连接关闭、甚至请求任务被取消，都不会撤销它读到的值。
- “变量在本任务里被 reset 回 None”与“其他任务的授权被撤销”是两件事；reset 一个 token
  **不能**用来证明任何其他任务已被撤权。

## aiohttp 真实代码路径核查（本仓库 4.0.0a 开发版）

1. 一条 TCP 连接对应一个长生命周期任务 `RequestHandler.start()`，在
   `connection_made()` 中创建（`aiohttp/web_protocol.py:423-430`，字段 `_task_handler`）。
   keepalive 的多个请求是这个任务里 `while` 循环的多次迭代（`web_protocol.py:744`）。
2. **每个请求**都会新建一个独立任务来执行 handler，源码注释明确写出目的：
   `# a new task is used for copy context vars (#3406)`（`web_protocol.py:792-803`，
   由提交 `9997cae4a` “Create a task per request handling (#3442)” 引入，3.4 起）。
   所以同一条 keepalive 连接上的请求之间 context 天然隔离，中间件即使只 `set` 不
   `reset`，也不会把身份泄漏给下一个请求（见场景 1、2）。
3. 注意 `request.task`（`web_request.py:270-272`）指向的是**连接级** `_task_handler`，
   工厂在 `web_protocol.py:789` 传入；handler 真正运行的“每请求任务”要用
   `asyncio.current_task()` 观测。
4. 客户端断开：
   - 默认 `handler_cancellation=False`（`web_server.py:55`、`web.py:446`）。
     `connection_lost()` 只对请求 payload 调 `_cancel()`（`web_protocol.py:450-453`，
     即让等待 body 的地方抛错），**不取消** `_task_handler`，更不会触及 handler 自己
     `create_task` 出来的任务。
   - 置 `handler_cancellation=True` 时，`connection_lost()` 才会
     `_task_handler.cancel()`（`web_protocol.py:455-456`）。这取消的是连接任务/请求
     处理链；handler 里独立 `create_task` 的子任务没有结构性父子关系，不会被连带取消。
   - 优雅停机 `shutdown()` 同样只 `await shield(self._task_handler)` 并在超时后
     `cancel()` 它（`web_protocol.py:386-399`），不跟踪业务自建任务。
5. `on_cleanup` / `cleanup_ctx`（`web_app.py:424-447`）只在**应用关闭**时运行，
   不是每请求的收尾，不能用来回收请求内创建的后台任务。

## 三种必须区分的语义

| 概念 | 含义 | 由谁决定 |
| --- | --- | --- |
| 上下文隔离 | 每个任务有独立 context 副本，互不写入 | `create_task` 的 context 复制 |
| 值被复制 | 子任务在创建瞬间拿到 principal 快照，之后父任务改动不可见 | context 复制时机 |
| 授权被撤销 | 该身份不再被允许执行特权操作 | **业务显式机制**（期限/重新验证/回收），ContextVar 本身不提供 |

reset token 只完成“把**当前** context 的这个变量恢复到 set 之前”，它既不是隔离机制，
也不是撤销机制。

## 对照实验（确定性、可运行）

无 socket、无外部身份服务、principal 为不含真实凭据的假对象；所有顺序由
`asyncio.Event` 门闩与固定次数的 `asyncio.sleep(0)` 事件循环轮转驱动，不使用随机
sleep 制造竞态。

运行演示（人类可读判定）：

```
PYTHONPATH=. python -m sec_demo.run_demo
```

运行断言测试（14 个，可重复）：

```
PYTHONPATH=. python -m pytest tests/test_sec_contextvar_identity.py \
  -c sec_demo/pytest.isolated.ini --noconftest -q
```

覆盖场景：

1. 同一 keepalive 连接的两个请求跑在不同的每请求任务里，连接任务本身从不持有身份。
2. 只 `set` 不 `reset` 的中间件依然无法跨请求任务泄漏。
3. 认证前创建的子任务复制到空 context，认证后创建的子任务复制到 principal。
4. 请求结束、连接关闭后，未完成的子任务仍能读到 principal（核心反证）。
5. 客户端断开，在 `handler_cancellation=False/True` 两种设置下，脱离的子任务都存活并保留身份。
6. handler 抛异常返回 500，子任务依旧带着身份继续运行。
7. 显式授权期限 + 执行时重新验证，以及受控后台任务的回收。

## 适合短后台工作的接入方式（`sec_demo/safe_background.py`）

- `ScopedBackgroundTasks`：为请求内创建的任务保留显式清单，在响应收尾/cleanup 时
  `await` 或 `cancel()`，杜绝静默孤儿任务；`shield=True` 仅控制取消是否向内传播，
  不影响 context 复制。
- `revalidate(now)`：在后台单元**执行时**按 principal 上的显式期限重新校验。
  ContextVar 仍可读是预期且无关紧要的，期限才决定能否执行。

## 何处必须显式授权期限或重新验证

- 任何生命周期可能超过请求的任务（队列消费、fire-and-forget、定时器、回调）。
- 在特权副作用之前（写库、调用下游、发消息）重新校验，而不是只在任务入口校验一次。
- 需要真正“撤销”时，使用可服务端失效的授权 ID / 短期票据并在执行点检查；本演示用
  进程内 `expires_at` 期限模拟这一机制，不接外部身份服务。
- 若希望请求取消时连带取消后台工作，必须自行持有任务引用并在收尾处取消——框架不会代为跟踪。

## 文件清单

- `sec_demo/harness.py`：内存传输 + 真实 `RequestHandler` 驱动台。
- `sec_demo/identity.py`：ContextVar、假 principal、两种中间件（正确 reset / 只 set）。
- `sec_demo/appbuild.py`：显式中间件链组装（与 `_build_middlewares` 同序）。
- `sec_demo/scenarios.py`：门闩、可暂停 handler、认证前/后子任务。
- `sec_demo/safe_background.py`：受控任务范围与执行时重新验证。
- `sec_demo/run_demo.py`：可运行对照演示。
- `tests/test_sec_contextvar_identity.py`：14 个确定性断言。
