# GraphQL 订阅广播：共享结果 vs 每人计算

运行演示（在仓库根目录）：

```
ruby -Ilib broadcast-demo/broadcast_demo.rb
```

## 机制（源码位置）

- `lib/graphql/subscriptions/broadcast_analyzer.rb` — 静态分析订阅操作：只有**每个**被查询字段都是
  `broadcastable: true`（或 introspection 字段），整个操作才可广播；一个 `false` 即整体降级为逐订阅者执行。
  未设置的字段回落到 `use ..., default_broadcastable:` 的默认值。
- `lib/graphql/subscriptions/event.rb` — `Event#fingerprint`：可广播时指纹 = `topic/query指纹`
  （topic 已含字段名+参数+subscription_scope），同指纹的订阅者进同一个桶；不可广播时每个订阅者拿唯一 id。
- `lib/graphql/subscriptions/action_cable_subscriptions.rb` — `setup_stream`：同一指纹桶只 `execute_update`
  **一次**（用桶里第一个订阅者的 context），把同一个 result `deliver` 给桶内所有人。
- `lib/graphql/subscriptions.rb` — `execute_update`：非广播路径用 `read_subscription` 还原**每个订阅者自己
  保存的 context** 重新执行整条查询，因此 `update` 里的权限检查、`unsubscribe`、`NO_UPDATE` 都是逐人生效的。

## 配置决策表

| 字段/查询特征 | 配置 | 行为 | 风险 |
|---|---|---|---|
| 公开数据（行情、公告、在线人数），所有人看到相同值 | `broadcastable: true` | 同指纹桶执行 1 次，N 人收到同一 payload | 低 |
| 组内同值数据（消息正文、文档 updated_at）+ `subscription_scope` | `broadcastable: true` + `subscription_scope :current_group_id` | 组内共享 1 次执行；组间由 topic 隔离 | 后台权限变化不会自动生效（见场景 D1） |
| 观察者相关字段（`viewerCanDelete`、`isMine`、未读数） | `broadcastable: false` | 整操作降级，逐订阅者执行，各自 payload 不同 | 无共享，成本高 |
| 依赖 context 的字段（时区、IP、AB 实验、本地化） | `broadcastable: false` | 同上 | 广播会用第一个订阅者的 context 计算，值错误 |
| 受限字段（有人能看有人不能看、按人过滤的列表） | `broadcastable: false`，且权限判断放在 resolver/`update` 里 | 逐人执行，权限逐人生效 | 误标 `true` 会把第一个订阅者能看到的数据发给全组 |
| 有副作用的 resolver（计数、审计日志） | `broadcastable: false` | 广播会"优化掉"部分执行，副作用丢失 | 数据不一致 |
| 整个 schema 大多数字段可共享 | `use ..., broadcast: true, default_broadcastable: true`，例外字段标 `false` | 默认广播 | 新增字段默认进入广播，评审要跟上 |
| 想强制逐人（最保守） | 不开 `broadcast:`（默认 `false`） | 全部逐订阅者执行 | 无广播收益 |

辅助 API：`MySchema.subscriptions.broadcastable?(query_string)` 可在测试里断言某条订阅是否真的会广播。

## 演示场景（实际发送的数据）

`broadcast_demo.rb` 用纯内存后端打印每次 trigger 的**执行次数、执行所用 context、每个用户实际收到的 payload**：

- **A 公开订阅**：3 个订阅者，1 次执行（alice 的 context），3 份完全相同的 payload。
- **B 组内广播**：alice/bob 在 g1、carol 在 g2；`scope: "g1"` 触发，g1 内 1 次执行两人共享，carol 收不到（topic 含 scope）。
- **C 同形状但需每人计算**：查询加上 `viewerCanDelete`（`broadcastable: false`）后，2 次执行，alice 收到 `true`、bob 收到 `false`。
- **D1 后台权限变化（泄漏）**：bob 被移出 g1 后，广播只用 alice 的 context 执行 1 次，`update` 里的成员检查对 bob 不生效，bob 仍收到 `"g1 secrets"`。
- **D2 修复一**：权限变化时应用显式 `delete_subscription(bob 的订阅)`，之后 bob 不再收到。
- **D3 修复二**：查询保持不可广播，每人重新执行 `update`，bob 的 `unsubscribe` 生效，订阅被自动清理。

## 自定义订阅后端需要应用自己补上的保证

内置后端（ActionCable / Pro 的 Redis、Pusher、Ably）实现了下面这些语义；**自己写后端时必须逐条补齐**，否则广播会退化成安全漏洞：

1. **分桶键必须完整**：`topic`（字段+参数+`subscription_scope`）+ `Event#fingerprint`（含 query 字符串与变量的指纹）。
   只按字段名分桶会把不同参数/不同 scope/不同查询形状的订阅者混在一起，直接串数据。
2. **只有 `subscription_broadcastable` 为 true 的桶才能共享执行**；否则每个订阅者独立 `execute_update`。
   不要用查询形状相同作为共享依据——形状相同 ≠ 结果相同（场景 C）。
3. **context 还原**：`read_subscription` 必须返回该订阅者订阅时保存的 context（用户、租户、scope），
   逐人执行时权限检查才有效。广播桶用的是**第一个订阅者**的 context，这一点要在文档里明示。
4. **权限变化传播**：后端不知道你的权限模型。组成员变化、封号、租户切换时，应用要主动
   `delete_subscription`（或对不可广播订阅依赖 `update` 里的 `unsubscribe`），否则广播会把数据继续推给已失权的人（场景 D1）。
5. **`unsubscribe` / `NO_UPDATE` / `final_update` 语义**：`execute_update` 返回 nil 或标记了
   `:unsubscribed` 时，后端要清理存储、停止投递，并让传输层发送 `{more: false}`。
6. **序列化与多进程一致性**：对象序列化（`Serialize.dump/load`）后，每个进程/订阅者还原出的对象
   权限视图必须等价；广播桶跨进程共享结果时，第一个执行者的 context 决定了所有人看到的内容。
7. **传输层隔离**：`deliver` 必须只发往对应 `subscription_id` 的通道/连接；共享的是**计算结果**，
   不是投递通道。
