# Rollbar 双项目切换：迁移判断表（请求错误 vs 后台作业）

结论先行：旧项目标记是 `Configuration#access_token`。它**不会**进入默认的队列
payload，而是在**捕获时被克隆进子 notifier 的配置**、在**发送时再从当前配置读取**。
因此“是否会误投旧项目”完全取决于一个判据——**token 是存在配置里（发送时读取），
还是被烤进了 payload（`use_payload_access_token` / `async_json_payload` 组合）**。

所有判断都由可运行探针实证：

```sh
BUNDLE_FROZEN=true .feedback/bundle-env exec ruby -Ilib -Ispec \
  tmp/rollbar_project_switch_probe.rb
# => Checks: 33  Failures: 0
```

探针保留真实入口（`Rollbar::Middleware::Rack`、`Rollbar::Delay::ActiveJob`、
`Rollbar::ActiveJob` 的 `rescue_from`），仅 stub 掉 `Notifier#do_post` 的 HTTP 发送，
记录每次发送实际使用的 token，不发起任何网络请求。

---

## 1. 旧项目标记复制到哪一层对象

| 层 / 对象 | 是否持有 access_token | 生命周期 | 配置更新后是否跟随 |
| --- | --- | --- | --- |
| `Rollbar.root_notifier.configuration`（根配置） | 是，唯一权威来源 | 进程级 | `reconfigure` 会**整体替换**为新 `Configuration`（`notifier.rb:56`） |
| 请求子 notifier（`Rollbar.scoped` 经 `Notifier#scope`） | 是，`configuration.clone` 的深拷贝（`notifier.rb:25`、`configuration.rb:192`） | 单次请求 | **否**。子 notifier 持有的是捕获时刻的快照 |
| 线程 notifier（`Thread.current[:_rollbar_notifier]`，`rollbar.rb:40`） | 是，首次访问时从根 notifier 克隆 | 线程级，懒加载并缓存 | **否**，已缓存的旧线程不跟随；新线程从新根克隆 |
| `scope_object`（`LazyStore`，请求/人员/上下文） | 否 | 单次请求 | 与 token 无关 |
| 默认异步 payload（`item.payload`，Hash） | **否**，无顶层 `access_token`（`item.rb:180`） | 队列消息 | 发送时回读当前配置 |
| `async_json_payload=true` 的字符串 payload | 默认**否** | 队列消息 | 同上，发送时回读当前配置 |
| `use_payload_access_token=true` 的 payload | **是**，顶层 `access_token` 被烤入（`item.rb:189`） | 队列消息/文件 | **否**，永远按 payload 自带 token 投递 |

关键代码事实：
- 子 notifier 复制发生在 `Notifier#initialize` 的 `parent_notifier.configuration.clone`
  （`lib/rollbar/notifier.rb:23-37`），`Configuration#initialize_copy` 做 `deep_copy`
  （`lib/rollbar/configuration.rb:192-199`），所以子配置与根配置是两个对象。
- 发送端 `Notifier#do_post` 仅在 `use_payload_access_token` 为假时加
  `X-Rollbar-Access-Token` 头，取值来自**发送时刻**的 `configuration.access_token`
  （`lib/rollbar/notifier.rb:680-693`）。
- 队列回放入口 `Notifier#process_from_async_handler`：字符串直接 `send_body`，
  Hash 则 `build_item_with_payload` 后用**当前 notifier 的 configuration** 发送
  （`lib/rollbar/notifier.rb:251-274`）。

---

## 2. 三个观察点（捕获 / 入队表示 / perform 回读）

| 观察点 | 默认（config 驱动） | `use_payload_access_token=true` |
| --- | --- | --- |
| 捕获时的子 notifier | 克隆根配置，token 在子配置里 | 同左 |
| 入队表示 | Hash（或 `async_json_payload` 时为 JSON 字符串），**无** token 字段 | 同左，但 payload 顶层带 `access_token`=旧 token |
| perform 时回读的选项 | `Rollbar.configuration.access_token`（当前/新配置）→ 投**新项目** | payload 自带 token 优先，header 被抑制 → 仍投**旧项目** |
| 切换后旧队列消息去向 | 自动跟随新配置，**可接续** | 钉死旧项目，**必须切换前排空** |

所有异步传输（`Delay::ActiveJob`、`Sidekiq`、`Resque`、`SuckerPunch`、
`Shoryuken`、`DelayedJob`、`Thread`）都是同一形态：`call(payload)` 只入队 payload，
worker 端统一调 `Rollbar.process_from_async_handler(payload)`，结论一致。

---

## 3. 迁移判断表（按实际目标 × 字段范围）

| # | 实际目标 / 现存对象 | token 所在字段范围 | 切换后行为 | 处置 |
| --- | --- | --- | --- | --- |
| 1 | 进行中的 Rack/Rails 请求（持有子 notifier） | 子 `configuration.access_token`（内存，快照） | 该请求内的报告走旧 token；请求结束即释放 | **可接续**，无需排空（请求寿命短） |
| 2 | 长生命周期线程缓存的线程 notifier | 线程 `configuration.access_token`（内存快照） | 旧线程继续用旧 token，直到线程重建/`clear_notifier!` | **建议重启 worker / 释放线程**后再切，避免长尾误投 |
| 3 | 队列中的默认异步 payload（Hash） | 无 token，仅 `data` | perform 时读新配置 → 新项目 | **可接续**，无需排空 |
| 4 | `async_json_payload=true` 的队列字符串 | 无 token | `send_body` 读新配置 → 新项目 | **可接续**，无需排空 |
| 5 | ActiveJob 传输（`config.use_active_job`）的在途作业 | args 为无 token 的 payload Hash | 新配置下 `perform` → 新项目 | **可接续**，无需排空 |
| 6 | `Rollbar::ActiveJob` rescue 产生的作业异常报告 | 无 token（job 名在 `data.body.trace.extra.job`） | 入队后随新配置发送 → 新项目 | **可接续**，无需排空 |
| 7 | `use_payload_access_token=true` 的队列/文件 payload | 顶层 `access_token`=旧 token | 永远投旧项目，配置改了也无效 | **切换前必须排空**（drain 队列 / 清文件） |
| 8 | `write_to_file=true` 写出的 payload 文件 | 默认无 token；仅当同时开 #7 才带 token | 由外部发送进程注入当前 token 读取 | 无 token 文件**可接续**；带 token 文件**必须排空** |
| 9 | payload 内业务字段（`data.*`，含 scope/request/job） | 不含 token | 与项目路由无关，原样迁移 | **可接续**，无需处理 |

判据速记：**字段里没有 token → 跟随新配置（可接续）；字段里烤了 token
（仅 `use_payload_access_token`）→ 钉死旧项目（先排空）。**

---

## 4. 双项目（请求错误 / 后台作业）安全切换步骤

1. 确认 `use_payload_access_token=false`（默认即此）。若为 true，先 drain 所有
   异步队列与 `write_to_file` 文件，再继续（对应表中 #7、#8）。
2. 不要在长驻 worker 内热替换配置并依赖旧线程生效：安排 worker/进程滚动重启，
   让线程 notifier 从新根配置重新克隆（对应 #2）。
3. 用两个 notifier 分流，而不是改全局 token。在各自入口用 `Rollbar.with_config` /
   `Rollbar.scoped` 注入对应 `access_token`：
   - 请求侧：Rack/Rails 中间件内 `Rollbar.with_config(:access_token => REQUEST_TOKEN)`。
   - 作业侧：`Rollbar::ActiveJob` rescue 与 `Delay::*` worker 内用
     `Rollbar.with_config(:access_token => JOB_TOKEN)`。
   子 notifier 在入口处克隆各自 token，互不污染根配置。
4. 默认队列 payload 不含 token，切换瞬间在途消息会按 perform 时的新配置路由，
   因此不需要为 #3–#6 停队列；只有 #7/#8 需要排空。
5. 切换后重跑探针，确认 `Checks: 33 Failures: 0`，并核对 `$sends` 中
   `header_token` 与预期项目一致。

## 5. 探针与源码对应关系

| 探针部分 | 验证内容 | 源码入口 |
| --- | --- | --- |
| Part A | token 克隆层级、reconfigure 替换、子/线程 notifier 快照 | `notifier.rb:23,56,67`、`configuration.rb:192`、`rollbar.rb:40` |
| Part B | 捕获/入队/perform 三观察点、Hash vs 字符串 vs 烤 token | `notifier.rb:251,680,896`、`item.rb:180` |
| Part C | 真实 `Delay::ActiveJob` 入队表示与跨切换 perform | `delay/active_job.rb` |
| Part D | 真实 Rack 中间件、持有子 notifier 跨切换、新错误回调 | `middleware/rack.rb`、`middleware/rails/rollbar.rb` |
| Part E | 真实 `Rollbar::ActiveJob` rescue 入口与二次发送 | `plugins/active_job.rb` |
