# AMQP 双安全等级 Consumer 的连接/通道共用评审

基于本仓库 Pika 1.5.0 的真实分派与确认代码（非文档转述），用内存替身演示一侧
阻塞、主动关停、确认三种效果，给出共用边界、取舍表和最终配置建议。

复现：`python3 -m amqp_topology_review.run_scenarios`，替身实现见
`amqp_topology_review/inmemory_amqp.py`，关闭原因直接使用 `pika.exceptions` 里的
真实异常类。

## 1. Pika 分派与确认的真实结构

层级从外到内是 broker -> TCP 连接（`Connection`）-> 通道（`Channel`）-> consumer
回调。每一层拥有的状态决定了能共用什么。

- 连接级、全生命周期固定：认证身份（`PlainCredentials`/`ExternalCredentials`）、
  `virtual_host`、TLS（`ssl_options`）、心跳、帧上限、连接状态机。一个连接只在
  建连时做一次身份协商，之后所有通道都携带这同一身份
  （`pika/connection.py:1423` 的 `Connection.channel` 不接受任何身份参数）。
- 通道级、彼此独立：consumer 集合、delivery tag 计数、未确认消息表、prefetch、
  通道状态机与关闭原因。`basic_ack` 第一步就是 `_raise_if_not_open`
  （`pika/channel.py:1679`），ack/nack/reject 全部按本通道的整数 tag 在本通道内
  解析（`pika/channel.py:299`、`:530`、`:648`），不存在跨通道确认。
- 失败传播是连接级的。`WorkQueueFullError` 继承 `AMQPConnectionError`
  （`pika/exceptions.py:428`），池溢出经 `_submit_or_terminate` 调
  `connection._terminate_stream`（`pika/adapters/thread_safe_connection.py:188`、
  `pika/connection.py:2232`），一条通道的致命故障关闭整条连接及其全部兄弟通道。
  反过来，`Channel.Close` 只关一条通道，连接和其他通道保持打开
  （`pika/channel.py:1349` 的 `_on_close_from_broker`）。

两种运行模型决定“一条通道变慢”如何波及邻居：

- `BlockingConnection`：单 IOLoop 线程。投递先进每通道待处理队列，再由连接唯一的
  分派循环串行执行回调（`pika/adapters/blocking_connection.py:1555` 的
  `_on_consumer_message_delivery` 入队，`:1607` 的 `_dispatch_events` 在同一线程
  while 循环里逐条调用，`:2005` 的 `start_consuming` 驱动它）。任一通道的回调阻塞，
  该连接上所有通道的回调和心跳都停摆。
- `pika.Connection`（`thread_safe_connection`）：每条通道一个 worker 线程 + 一个有界
  队列（`_BoundedWorkPool`，`pika/adapters/thread_safe_connection.py:233`）。单条
  通道回调阻塞只停自己的 worker，IOLoop 仍可读帧、发心跳、服务其他通道；只有该通道
  队列被填满并持续 `work_queue_put_timeout` 秒，才升级为连接级终止。

## 2. 能共用到哪一层

| 资源 | 能否跨两个安全等级共用 | 代码依据 |
| -- | -- | -- |
| broker 地址、端口、TLS 策略、连接调优（心跳/frame_max/重试） | 可共用为同一份“目标参数模板” | `ConnectionParameters` 是纯数据，可复用构造 |
| 一条 TCP 连接（`Connection`） | 不建议，见安全前提 | 身份/vhost/TLS 在连接级固定，且故障与 IOLoop 是连接级 |
| 连接内的多条通道 | 同等级、同生命周期的 consumer 可共用一条连接、各开通道 | 通道状态、tag、prefetch 互相独立 |
| 一条通道（`Channel`） | 不能给两个安全等级共用 | consumer、tag、未确认表、prefetch、关闭原因都在通道内，且关闭会清掉其上全部 consumer |
| delivery tag / ack | 天然无法跨通道 | `basic_ack` 按本通道 tag 解析，通道关闭后再 ack 抛 `ChannelWrongStateError` |

结论：能安全共用的上限是“同一份连接参数模板”和“同一安全身份下、同一条连接里的多条
通道”。不同安全等级之间，连接必须分开；是否连“同一条连接上的两条通道”都不允许，取决于
下面的安全前提。

## 3. 内存替身观察到的取舍

替身用同一套拓扑分别跑 `blocking`（单连接 worker）和 `pooled`（每通道 worker），并对比
SHARED（一条连接两条通道）与 SPLIT（两条连接）。数字来自 `run_scenarios.py` 实测。

| 效果 | 拓扑/模型 | 受影响侧动作 | 观察到的另一侧行为 |
| -- | -- | -- | -- |
| 回调阻塞 | SHARED + blocking | 支付侧回调阻塞 0.4s | 遥测侧在阻塞期处理数 0，心跳在回调内为 False，投递被压约 0.41s 后才排空 |
| 回调阻塞 | SPLIT + blocking | 支付连接回调阻塞 | 遥测在自己的连接上立即处理（mid-stall = 1），心跳正常 |
| 回调阻塞 | SHARED + pooled | 支付 worker 阻塞 | 遥测有独立 worker，立即处理（=1），IOLoop 空闲、心跳 True |
| 队列溢出 | SHARED + pooled | 灌满支付通道有界队列 | `WorkQueueFullError` 关闭整条连接，遥测通道一并关闭，之后处理数不再增长 |
| 队列溢出 | SPLIT + pooled | 支付连接溢出终止 | 遥测连接与通道保持打开，继续消费（完全隔离） |
| 主动关停通道 | SHARED（两模型一致） | 支付侧 `channel.close()` | 连接仍 open，遥测通道 open 且继续收到投递（2 -> 3） |
| 主动关停连接 | SHARED | 支付侧 `connection.close()` | 遥测通道被带关（closed），再 ack 抛 `ChannelWrongStateError` |
| 主动关停连接 | SPLIT | 支付侧关自己的连接 | 遥测连接/通道保持 open，继续消费（2 -> 3） |
| 确认 | 任一拓扑 | `nack(requeue=True)` | 同一条消息在同一通道以新 tag 重投（实测 tag 1 -> 2），未确认表归零 |
| 跨通道确认 | SHARED | 用支付通道 ack 遥测通道持有的 tag | 遥测消息仍保持 unacked（通道间 tag 互不可见） |
| 通道关闭时未确认 | 任一拓扑 | 持有未 ack 消息的通道关闭 | 消息回到队列，被新通道重新投递并确认（实测收到 `tel-held-msg`） |
| 身份越权 | 模型无关 | 低权限连接上新开通道消费高权限队列 | broker 回 `ChannelClosedByBroker 403`，记录 ACCESS_REFUSED，通道关闭 |

两条最关键的观察：

- 通道级关停是干净隔离的，连接级关停和连接级故障不是。SHARED 拓扑下，一条通道自己
  `close()` 不影响邻居；但任何连接级事件（`connection.close()`、心跳超时、broker
  `Connection.Close`、池溢出）都会同时终结邻居。
- `pooled` 模型把“慢”与“故障”分开：慢只影响自己的 worker，故障（溢出）才连接级终止。
  `blocking` 模型不做这个区分，慢本身就停掉全连接的分派与心跳。

## 4. 为什么需要独立通道，以及何时必须独立连接

独立通道就够的情形（可留在同一条连接）：

- 只是需要独立的 prefetch、独立的 delivery-tag/未确认窗口、独立的 consumer 生命周期，
  且两侧身份、vhost、TLS、可用性要求相同。
- 一侧主动 `channel.close()` 不应取消另一侧的 consumer——通道关闭只清自己的 consumer。

必须独立连接的情形：

- 安全身份不同。通道无法承载与连接不同的用户/vhost/TLS 身份；想让两个等级共用一条连接，
  只能给这条连接的单一身份授予两个域的并集权限，等价于把高权限下发给低权限侧，违背最小
  权限。替身第 4 组显示低权限连接开新通道触碰高权限队列只会被 403 拒绝。
- 故障域必须隔离。连接级终止（`_terminate_stream`）、心跳超时、broker 连接关闭、
  `WorkQueueFullError` 都会带走同连接全部通道；高安全等级侧不能被低等级侧的慢消费或
  异常拖垮。
- 阻塞模型下的可用性。`BlockingConnection` 单 IOLoop 意味着一侧回调阻塞就停掉另一侧的
  分派和心跳，长时间阻塞可触发 broker 端心跳断连。两侧若都用 blocking 模型，必须分连接。

## 5. 最终配置建议

推荐：两个安全等级各用一条独立连接，每条连接内按 consumer 角色开多条通道。

- 连接 A（高安全等级，如支付结算）：独立身份、独立 vhost、独立 TLS 凭据，
  `pika.Connection`（pooled）或独立进程内的 `BlockingConnection`。
- 连接 B（低安全等级，如遥测事件）：独立身份与 vhost，同样独立连接。
- 每条连接内部：一个 consumer 角色一条通道，用 `basic_qos(prefetch_count=N)` 限制在途
  未确认数，手动 ack（`auto_ack=False`），处理成功才 `basic_ack`，失败 `basic_nack`
  或 `basic_reject`。
- 可安全共用的只有“目标参数模板”：broker host/port、TLS 版本与校验策略、心跳间隔、
  `blocked_connection_timeout`、重试次数——把它们做成两份 `ConnectionParameters` 的共享
  工厂，但 `credentials`、`virtual_host`、`ssl_options` 中的客户端凭据分别注入。
- pooled 模型显式设置 `work_queue_maxsize` 与 `work_queue_put_timeout`，让慢消费者快速、
  显式地以 `WorkQueueFullError` 失败，而不是无限堆积；为每条连接注册 on-close 回调做重连。

### 安全保证

- 最小权限：每条连接只有本等级的身份和 vhost 授权，高权限永不经过低权限连接，越权访问在
  broker 侧以 403 关闭通道（替身第 4 组已验证）。
- 故障隔离：一侧的连接级终止、心跳超时、池溢出不影响另一侧连接（替身 SPLIT 行已验证）。
- 确认完整性：手动 ack 的消息在通道异常关闭时由 broker 重投，不丢消息；ack 严格限定在本
  通道，不存在跨等级误确认（替身 3b/3c 已验证）。

### 前提与限制

- 建议成立的前提是 broker 侧为两个等级配置不同用户与 vhost 权限；若平台只能发一个身份，
  分连接在安全上不成立，应先解决授权模型。
- 分连接增加一条 TCP/TLS 会话和一份心跳/资源开销，连接数需纳入 broker 的连接上限。
- 若坚持用 `BlockingConnection`，绝不能在同一连接上混合两个等级；即便分连接，也要保证回调
  快速返回，阻塞工作应放到连接外的线程池，否则单 IOLoop 停摆会触发心跳断连。
- 替身是对 Pika 分派语义的建模，不是 broker 实测；真实重投时机、`WorkQueueFullError` 的
  30s 默认超时等数值以对接 RabbitMQ 的验收测试为准。
