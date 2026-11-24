# 受控扩展目录：从 SDK 校验到治理强制

本目录说明如何在不破坏历史事件消费的前提下，把团队扩展纳入一个可审计的
CloudEvents 事件目录。所有结论都由 `matrix.py` 现场调用本仓库 SDK 得出；
`--assert` 会锁定这些行为，SDK 升级导致契约漂移时立即失败。

## 1. SDK 目前实际保证什么

SDK 只做**语法与结构**校验，不做**目录准入**。关键契约如下：

- 扩展名必须匹配 `^[a-z0-9]+$`，否则 `CloudEventValidationError`
  （`src/cloudevents/core/v1/event.py:262`，v0.3 同规则在
  `src/cloudevents/core/v03/event.py:277`）。
- `data` 是保留字段，不能作为扩展
  （`src/cloudevents/core/v1/event.py:248`）。
- 版本自有属性按 `specversion` 白名单校验：v1.0 认 `dataschema`，
  v0.3 认 `schemaurl` / `datacontentencoding`
  （`src/cloudevents/core/v1/event.py:35`、`src/cloudevents/core/v03/event.py:35`）。
- **没有**注册表、批准状态、owner、别名或弃用信息。任何合法名字都会作为
  扩展被接受并原样返回（`get_extension` 就是字典查询，
  `src/cloudevents/core/v1/event.py:295`）。
- 绑定层在反序列化时把 `ce-*` / `ce_*` / `cloudEvents_*` 头直接转成属性，
  再交给事件构造函数校验。因此**同一条历史扩展会在不同绑定下得到不同结果**。

### 两代 SDK 的差异

旧版 `cloudevents.v1` 的路径完全不同：

- 旧 HTTP 事件构造时把所有属性名转小写
  （`src/cloudevents/v1/http/event.py:61`），HTTP 头也先整体小写
  （`src/cloudevents/v1/sdk/marshaller.py:60`、`src/cloudevents/v1/conversion.py:124`）。
- 旧 SDK 的扩展是 `extensions` 字典，名字不受 `[a-z0-9]+` 限制
  （`src/cloudevents/v1/sdk/event/base.py:190`），序列化时原样展开
  （`src/cloudevents/v1/sdk/event/base.py:219`）。
- 旧 SDK 对 `time` 接受字符串；新核心要求带时区的 `datetime`，这是迁移时
  独立于扩展名的另一个适配点。

### 绑定差异（矩阵已锁定）

| 场景 | 新核心结果 | 原因 |
|---|---|---|
| structured JSON 中的 `LegacyTraceId` | 拒绝 | 不折叠大小写，直接校验 |
| HTTP binary 中的 `ce-LegacyTraceId` | 通过但变成 `legacytraceid` | 头名被 `lower()` |
| RabbitMQ binary 中的 `ce-LegacyTraceId` | 通过但变成 `legacytraceid` | 头名被 `lower()` |
| Kafka binary 中的 `ce_LegacyTraceId` | 通过但变成 `legacytraceid` | 头名被 `lower()` |
| AMQP binary 中的 `cloudEvents_LegacyTraceId` | 拒绝 | 前缀剥离后不折叠大小写 |
| 任意 binary 中的 `legacy-trace-id` | 拒绝 | 连字符不在 `[a-z0-9]+` |
| AMQP 的 int 扩展 | 保持 int | 原生类型 |
| HTTP/Kafka/Rabbit 的 int 扩展 | 变成字符串 | 头值必须字符串化 |

这不是 SDK bug，而是绑定规范与实现共同决定的“线上形状”。治理设计必须把
**绑定**作为判定维度，否则同一策略在 HTTP 与 AMQP 上会给出相反结论。

## 2. 分阶段收紧

目录条目本身就是版本化的：`ExtensionSpec` 记录 canonical 名、owner、
适用 specversion、允许的值类型、弃用版本和别名。`Catalogue.evaluate()` 是纯函数，
返回一条不可变 `Decision`。

| 阶段 | 模式 | 行为 | 退出条件 |
|---|---|---|---|
| 0 观测 | `OBSERVE` | 只分类、只记录，不拒绝 | 能按 `record_kind` 看到全量存量分布 |
| 1 影子 | `SHADOW` | 计算 `would_accept` 并与线上实际结果对比，不拒绝 | 影子拒绝集合已人工复核，且生产端有迁移计划 |
| 2 新边强制 | `ENFORCE`（producer 侧） | 生产者新事件只允许目录内扩展 | 连续一个发布周期无新增 `unknown-extension` |
| 3 消费宽限 | `ENFORCE`（consumer 侧，先用 `compat.ingest_attributes`） | 历史事件经适配器读取，未知扩展进 sidecar | 存量 topic/retention 已覆盖历史事件 |
| 4 全面强制 | `ENFORCE`（两侧） | 新老路径都拒绝未批准扩展 | 历史 topic 已过期或完成重放 |

关键原则：**摄入宽、产出严**。历史事件可以经适配器继续读，但同一形状不能
作为新事件再次发出。这样消费者不需要“理解未来”，生产端也不会把历史脏数据
固化成新契约。

### 记录分流

`Decision.record_kind` 与 `status` 分开，便于不同 owner 处理：

| record_kind | 触发 | 处理方 |
|---|---|---|
| `extension` | 目录命中/别名 | 平台目录维护者 |
| `legacy-extension` | 隔离表中的历史拼写 | 迁移负责人 |
| `invalid-syntax` | 大写/连字符/下划线 | 生产团队 + 网关 |
| `version` | `schemaurl`/`dataschema`/`datacontentencoding` 版本错位 | 协议/版本负责人 |
| `unknown-extension` | 合法但未注册 | 目录评审会 |
| `type-drift` | 值类型与目录不符（常见于 binary 字符串化） | 绑定/序列化负责人 |
| `reserved` | 用了规范字段或 `data` | 生产团队 |

版本差异和未知扩展不混在普通扩展记录里，这是本设计的硬要求。

## 3. 矩阵怎么读

运行：

```bash
python samples/extension-governance/matrix.py            # 人读表格
python samples/extension-governance/matrix.py --json     # CI 产物
python samples/extension-governance/matrix.py --mode shadow
python samples/extension-governance/matrix.py --assert   # 契约回归
```

列含义：

- `sdk`：`legacy v1` 或 `core v2`，两者都真实调用，不模拟。
- `binding`：HTTP structured / HTTP binary / Kafka / RabbitMQ / AMQP。
- `outcome`：`pass`、`rename`、`reject`、`type-drift`、`rewrite`。
- `status` / `record_kind`：目录策略的判定与应路由的记录流。
- `policy/sdk`：策略是否接受、SDK 是否实际接受，二者故意分开。
  例如 `schemaurl` 在 v1.0 中 SDK 接受但策略判为版本错位。

`matrix.py --assert` 锁定以下事实：

1. structured JSON 拒绝混合大小写；
2. HTTP/RabbitMQ/Kafka binary 折叠成小写后通过；
3. AMQP 保留混合大小写并拒绝；
4. 旧 SDK structured 会把混合大小写折叠；
5. 旧 SDK binary 保留连字符/下划线；
6. AMQP 保留 int，HTTP/Kafka/Rabbit 字符串化；
7. `schemaurl` 在 v1.0 是版本错位而非普通扩展；
8. 未知扩展有独立 `unknown-extension` 记录；
9. 摄入适配器能把历史连字符名改写为 canonical 名并被核心模型接受。

## 4. 什么时候可以切强制

不要按日期切，按证据切。建议同时满足：

- **覆盖**：影子阶段至少覆盖一个完整业务周期，且所有生产 topic/队列的
  扩展名分布已归零到“目录命中 + 已知隔离项”。
- **可归因**：每个 `unknown-extension`、`version`、`type-drift` 都有 owner
  和处置结论；不存在“先记着”的长期挂账。
- **可回放**：历史 retention 内的样本都能经 `ingest_attributes` 读出，
  且关键字段不丢；sidecar 有明确的保留期限。
- **绑定一致**：同一 canonical 扩展在四种绑定上的值类型符合目录声明；
  若目录声明 `int`，要么禁止 binary 绑定，要么在网关做类型恢复。
- **回滚开关**：生产端能以配置切回 `SHADOW`，且不需要重新部署消费者。
- **回归**：`matrix.py --assert` 与样例测试在 CI 中通过。

满足后先强制**生产端**，消费端保留适配器至少一个 retention 周期；最后再
关闭兼容读取。任何阶段发现 `shadow_disagreements > 0` 都不应前进。

## 5. 目录评审的最小字段

新增扩展时至少记录：

- canonical 名与 owner；
- 适用 `specversion`（0.3 / 1.0 可不同）；
- 允许的值类型（尤其要区分 structured 与 binary）；
- 是否允许出现在哪些绑定；
- 别名与弃用版本；
- 对应的 `record_kind` 路由和审批链接。

`policy.ExtensionSpec` 已实现前五项；后两项由 `Catalogue.evaluate()` 的
`record_kind` 与评审流程承担。
