# Casbin 策略更新可审计回执设计报告

> 基于本仓库 `pycasbin 2.6.1` 源码与可运行实验（`receipt_lab/`，9 个 pytest 全绿）。
> 所有结论都能在 `run_scenarios.py` 的真实输出与测试中断言复现，不引用未实测的行为。

## 1. 三种 enforcer 的真实承诺

### 1.1 先看一次 `add_policy` 在源码里的真实步骤

`casbin/internal_enforcer.py:23` 的 `_add_policy`（普通 enforcer）顺序固定为：

1. `model.has_policy(...)` 去重，已存在直接返回 `False`；
2. `adapter.add_policy(...)` 持久化（受 `auto_save` 控制）；适配器显式返回 `False` 才中止；
3. `watcher.update_for_add_policy(...)` 或退化的 `watcher.update()` 通知（受 `auto_notify_watcher` 控制）；
4. `model.add_policy(...)` 才把规则放进**本地内存模型**。

这个顺序决定了一个反直觉事实：**通知发生在本地内存提交之前**。第 3 步抛异常时，第 2 步已经落库、第 4 步不会执行。删除路径（`_remove_policy`，`internal_enforcer.py:141`）顺序相反：先改内存、再持久化、最后通知，且通知同样没有 try/except 保护。

### 1.2 三类 enforcer 各自能证明什么

| Enforcer | 并发保护 | 通知时机 | 一次成功调用能证明的 | 一次抛异常调用的真实含义 |
|---|---|---|---|---|
| `Enforcer`（普通） | 无锁 | 锁外、**本地提交前**同步调用 | 返回 `True` ⇒ 已持久化 + 已调 watcher + 本地已生效 | watcher 异常会向上抛，此时**已持久化但本地未生效**（实测 A1） |
| `SyncedEnforcer`（同步/线程安全） | `RWLockWrite` 读写锁 | 经 `_DeferredWatcher` 延迟到**写锁释放后** | 返回值为 `True` ⇒ 持锁区内已完成持久化+本地提交；通知在解锁后发生 | 通知异常在方法返回**之后**才抛（实测 A2），调用方若只 `try/except` 会误判整笔写失败 |
| `AsyncEnforcer`（异步） | 事件循环内协程序 | `await` watcher，仍在本地提交前（`async_internal_enforcer.py:126`） | `await` 成功 ⇒ 持久化 + 通知 + 本地均完成 | 与普通 enforcer 同序：异常时已持久化、本地未生效（实测 A3） |
| `DistributedEnforcer`（分布式） | 继承 `SyncedEnforcer` | `*_self` 方法**完全不发 watcher 通知** | `add_policy_self(False,...)` 只改本地内存 | 见 1.3 的真实缺陷 |

补充：`CachedEnforcer` / `SyncedCachedEnforcer` 只缓存 `enforce` 判定，不改变写入与通知语义，缓存失效是另一条需要单独取证的链路。

### 1.3 一个必须上报的真实缺陷（本版本实测）

`DistributedEnforcer.add_policy_self`（`casbin/distributed_enforcer.py:39`）在 `should_persist=True` 时访问 `self.adapter`，但它继承的 `SyncedEnforcer` 把适配器放在 `self._e` 上、本身没有 `adapter` 属性（`synced_enforcer.py` 里那个 `__getattr__` 属于内部类 `_DeferredWatcher`，不会兜底）。结果：

- 先抛 `AttributeError: 'DistributedEnforcer' object has no attribute 'adapter'`；
- 异常处理里 `"..." + e` 把字符串与异常对象拼接，再抛 `TypeError`；
- 规则既没持久化也没进本地模型。

官方 `tests/test_distributed_api.py` 只覆盖 `should_persist=False`，所以该分支长期未被发现。已由 `test_distributed_enforcer_persist_branch_is_broken_in_this_version` 固化。**结论：本版本不能依赖 `DistributedEnforcer` 的持久化分支做任何承诺。**

### 1.4 三类证据的严格边界

- **本地生效（local applied）**：唯一可信证据是调用后用 `has_policy`/`enforce` 实测，而不是返回的布尔值。布尔值只表达「这次调用触发了变更」，异常时本地状态仍可能已变（Synced）或未变（Plain/Async）。
- **持久化（durable）**：证据来自适配器侧的追加日志 + 事后回读。本实验的 `InstrumentedMemoryAdapter.journal` 即对应真实 DB 的 write-ahead/审计表。`auto_save=False` 时这一层根本不发生。
- **已通知其他节点**：`watcher.update*()` 正常返回只证明「消息已交给 broker / 回调已在本进程入队」。它**不证明**对端收到，更不证明对端生效。要证明对端，必须有对端自己产生的应用证据。

## 2. Watcher 两种形态与回执关联

### 2.1 通用信号 vs 类型化事件

- 普通 `Watcher`（`persist/watcher.py`）只有 `update()`，语义是「有东西变了，自己 `LoadPolicy()` 吧」。接收方无法知道变了哪条，只能全量重载。
- `WatcherEx`（`persist/watcher_ex.py`）增加 `update_for_add_policy / update_for_remove_policy / ...`，携带 `sec/ptype/rule`，接收方可增量应用；`WatcherUpdatable` 再补 `update_policy` 类事件。
- 关键：发送方到底走哪条，取决于运行时 `callable(getattr(watcher, "update_for_add_policy", None))`（`internal_enforcer.py:33`）。同一个 enforcer，挂不同 watcher 承诺完全不同，回执必须记录实际命中的方法。

### 2.2 三个绝不能合并的时刻

回执关联时把一次变更拆成三个独立时间点，各自有独立证据：

1. **动作提交（commit）**：发送端 adapter 日志序号 + 本地 `enforce` 探针；
2. **回调成功（callback）**：接收端 watcher 回调进入（`callback_entered`）与回调返回；
3. **远端实际应用（applied）**：接收端 `reload_finished` / `apply_finished` **之后**的 `enforce` 结果。

实验里 `ReloadGate` 把这三者显式分开。`callback_entered` 出现但 `reload_finished` 未出现时，对端 `enforce` 仍返回旧答案（场景 B1/B2 的阻塞窗口）。**「通知已发送 / 回调已进入」绝不能记成「对端已生效」。**

### 2.3 重复与倒序：诊断时仍缺什么证据

- **重复投递**：通用信号无法区分两次 `update()` 谁是谁，天然靠全量重载幂等兜底；类型化事件需要接收端维护幂等集合（实验用 `(kind,ptype,rule)` 去重，且刻意让去重发生在阻塞判断之后，使阻塞期间到达的重放仍能在开门后应用）。没有这套去重，回执无法判断一条 add 被执行了几次。
- **倒序投递**：实测 B3 中，发送端先 add 后 remove（最终应为拒绝），broker 把 remove(#2)、add(#1) 倒序送达，接收端最终 `enforce=True`，与权威存储和发送端脑裂。Casbin 事件本身**不带版本号/向量时钟**，接收端无法识别 add 已过期。此时回执能给出的诊断是：`commit` 证据与 `applied` 证据冲突，**缺失的关键证据是每条规则的单调存储版本（version/vector clock）**。在补上版本号之前，任何「集群一致」的承诺都不可证明，只能靠周期性全量 `LoadPolicy()` 收敛。
- 因此回执里应保留 `gaps[]`：凡 `notified=True` 而 `remote_applied` 无对端证据，明确标注「broker 已接收，对端应用未证明」，而不是补一个乐观状态。

## 3. 两个对照实验的实测结果

环境：两个本地 enforcer（node-a 写、node-b 收）、一个共享内存持久层（带追加日志与故障注入）、一个可控 watcher 总线（可令发布失败、重放、阻塞重载）。完整输出见 `receipt_lab/output/scenario_run.txt`，结构化回执见 `receipts.json`。

### 3.1 场景 A：写入成功但通知失败（规则 `carol,data3,read`）

| 变体 | 调用表现 | 存储日志 | node-a 本地判定 | node-b 判定 | 回执结论 |
|---|---|---|---|---|---|
| A1 普通 | **抛 RuntimeError** | seq#1 `stored` ok | `False`（模型未提交） | `False`，无任何回调 | DURABLE but local not proven |
| A2 同步 | 返回后**解锁时抛** | seq#1 `stored` ok | `True`（已提交） | `False`，无任何回调 | LOCAL + DURABLE，无远端证据 |
| A3 异步 | `await` **抛** | seq#1 `stored` ok | `False`（模型未提交） | — | DURABLE but local not proven |

要点：三者**存储都已落库**，但普通/异步 enforcer 本地模型与自己的存储发生偏离（重启重载后才会出现该规则）。运维若只看异常会去重试 add，可能制造「重复写」告警；正确做法是凭 adapter 日志序号判定为已持久化，只补偿通知与本地重载。

### 3.2 场景 B：通知重送而接收端尚未完成重载

- **B1 通用 watcher（全量重载）**：阻塞期内两次 `callback_entered`、两次 `reload_blocked`，node-b 始终 `False`；开门后接收端主动完成一次 `LoadPolicy()`，出现 `reload_finished:manual`，判定才变 `True`。证明：两条投递记录只证明送达，应用以 `reload_finished` 后的探针为准。
- **B2 类型化 WatcherEx（增量应用）**：阻塞期内首投与重放都记 `apply_blocked`；开门后一次重放走完 `apply_started→apply_finished`，判定变 `True`；之后再重放同一事件记 `duplicate_ignored`，判定保持。幂等性由接收端去重集合保证，而非 broker 保证。
- **B3 倒序**：remove(#2) 先到、add(#1) 后到，node-a=`False`（与存储一致）而 node-b=`True`（陈旧 add 最后生效）。回执能发现冲突，但在无版本号前无法自动裁决，缺失证据已在 2.3 列明。

状态时间线统一字段：`t / node / phase / event / seq / rule`，phase 取值覆盖
`callback_entered → reload_started|apply_started → reload_finished|apply_finished`，以及异常支路 `reload_blocked / apply_blocked / duplicate_ignored / gate_unblocked`。审计时按 `seq` 关联发送端事件、按 `phase` 判定证据等级。

## 4. 在已有应用里渐进接入（保留旧 API）

接入层在 `receipt_lab/integration.py`，分四步，每步都可独立上线、独立回退：

1. **零改造包装**：把 `casbin.Enforcer(...)` 换成 `AuditedEnforcer(casbin.Enforcer(...), receipt_store)`。`add_policy/remove_policy/enforce/has_policy` 等签名与返回值不变（`__getattr__` 透传），现有调用点不动；回执走独立旁路，watcher 异常**原样上抛**，不吞错、不改写原有控制流。
2. **持久层取证**：给真实 adapter 套一层记录 `op/ptype/rule/结果/单调 seq` 的装饰器（对应内存版的 `journal`），写入独立审计表。先只记录不拦截。
3. **对端探针**：注入 `peer_probe`，由对端在 `apply_finished` 后回报自己的 `enforce` 结果（或在 broker 上用 ack + 应用序号）。拿不到对端证据时，回执停在 `LOCAL + DURABLE`，不假设一致。
4. **类型化与版本号**：条件成熟再把 watcher 从 `Watcher` 升到 `WatcherEx`，并在事件里加存储单调版本；在此之前用定时全量 `LoadPolicy()` 作为最终收敛兜底，并把 B3 类脑裂显式标为「不可自动证明」。

新增能力以 `*_with_receipt()` 形式提供（返回 `(结果, ChangeReceipt)`），旧方法保持纯布尔返回；`ChangeReceipt.verdict()` 只按已掌握证据给保守措辞，`gaps[]` 列出缺口。

## 5. 不可证明的边界（明确划线）

- **broker 之外的节点**：watcher 返回正常无法证明其他节点收到，更无法证明其应用；没有对端主动回执，`remote_applied` 只能留空。
- **无版本号的乱序**：Casbin 事件不带版本/向量时钟，倒序导致的脑裂可检测、不可在回执内自动裁决（B3）。
- **`auto_save=False` / 适配器不透明**：没有 adapter 侧日志就没有持久化证据，回执只能 claim 本地生效。
- **本版本 `DistributedEnforcer` 持久化分支**：`should_persist=True` 必失败（1.3），在升级修复前不得把它纳入持久化承诺。
- **缓存层**：`enforce` 缓存命中可能滞后于策略变更，「本地模型已更新」不等于「所有在途判定已刷新」，需要缓存失效事件单独取证。
- **进程崩溃窗口**：Synced enforcer 通知在解锁后发出，若进程在解锁与通知之间崩溃，本地+持久化成立而集群无感知；这只能靠对端定时全量重载或版本对账发现，回执本身无法覆盖。

## 6. 复现方式

```bash
.venv/bin/python -m pytest receipt_lab/ -q          # 9 个语义回归测试
.venv/bin/python -m receipt_lab.run_scenarios       # 打印 A1-A3、B1-B3 全时间线
cat receipt_lab/output/receipts.json                # 结构化回执
```
