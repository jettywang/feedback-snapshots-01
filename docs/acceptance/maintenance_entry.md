# 维护入口：Warden 锁与失败应用接入决策

适用版本：本仓库 `Warden::VERSION = 1.2.9`（`lib/warden/version.rb`）。
结论基于当前实现与 `spec/acceptance/maintenance_entry_spec.rb` 的实测记录，
不是对 Warden 未来版本的承诺。

## 1. 结论先行

维护入口只有一个已核准身份来源 `:maint`。接入规则如下：

| 请求到达时的状态 | 继续使用已登录身份 | 明确终止请求 |
| --- | --- | --- |
| `:maint` 已有请求级策略结果或会话中的用户 | 可以，且应走 `user`/`authenticated?` 读取 | 否 |
| `:maint` 无身份 | 否 | 是，`authenticate!` 或应用 `throw(:warden, :action => ...)` |
| 其他 scope（如 `:admin`）已有会话 | **不可以**，Warden 不会替你挡 | 是，应用显式判定并终止 |
| 请求内需要新执行策略（`lock!` 之后） | 否 | 是 |

`lock!` 的语义只有一条：**本请求内不再启动新的策略**（`lib/warden/proxy.rb:353-358`）。
它不是“冻结身份”，也不是“只允许某个 scope”。因此维护入口不能只调用
`lock!` 就认为入口已经收口。

## 2. 四个执行点的核对结果

### 2.1 策略执行

- `authenticate`/`authenticate?` 先查缓存用户；没有才进 `_run_strategies_for`。
- `_run_strategies_for` 在 `@locked` 时直接返回，不执行任何策略。
- 已缓存的 `winning_strategy` 仍会被读取；`winning_strategies` 按 scope 分开缓存。
- `clear_strategies_cache!` 会清 `@winning_strategies[scope]` 与策略的 `performed?`，
  但**不清 `@users[scope]`**，所以锁后清缓存仍会返回已缓存用户（实测见记录）。
- `lock!` 不拦 `set_user`：锁后 `set_user(...)` 会写 `@users` 并持久化到
  `warden.user.<scope>.key`。这是锁最大的旁路，只能由应用避免。

### 2.2 会话恢复

- 恢复点在 `Proxy#user`（`lib/warden/proxy.rb:217-231`）：`session_serializer.fetch(scope)`
  成功后调用 `set_user(..., :event => :fetch)`。
- `lock!` 完全不参与 `user` 分支；锁后读取任何 scope 都会触发反序列化与
  `after_set_user(:fetch)`。
- 因此“先锁后读”并不限制读取范围。若入口只锁不选 scope，`:admin` 会话也会被恢复，
  并通过 `authenticated?(:admin)` 返回 true。
- 反序列化返回 nil 时，`SessionSerializer#fetch` 会删除该 key，并触发
  `after_failed_fetch`。

### 2.3 失败分派

- `authenticate!` 失败时 `throw(:warden, opts)`，`opts` 由 `_retrieve_scope_and_opts`
  合并 scope 默认值，因此带 `:scope` 与该 scope 的 `:action`。
- 应用直接 `throw(:warden, :scope => :admin)` 时，`process_unauthenticated`
  只按**默认 scope** 的 action 兜底（`lib/warden/manager.rb:113-116`），不会取
  `:admin` 的 action。实测：`/unauthenticated`，而不是 `/admin_gate`。
- 对比两种终止方式：`authenticate!` 抛出的 `opts` 来自 `scope_defaults`，
  因此带该 scope 的 action；应用裸 `throw(:warden, :scope => :admin)` 只带
  `:scope`，`process_unauthenticated` 不会据此取 `:admin` 的 action。
- `authenticate`（非 bang）失败不抛，只返回 nil；调用方若继续执行，就是静默放行。
  锁定时这个差异尤其危险：策略没跑，返回值必然是 nil。

### 2.4 响应提交

- `Manager#call` 只 `catch(:warden)`（`lib/warden/manager.rb:34`），**不 rescue
  异常**。
- 应用未捕获的异常原样上抛，不会进入 `failure_app`，`warden.options` 也不会写入。
- 失败应用自身抛异常同样上抛；`before_failure` 发生在 `PATH_INFO` 改写之后、
  失败应用调用之前。
- 下游返回 401 时：`intercept_401` 为真且未 `custom_failure!` 则改走失败应用；
  否则原样提交。403 等其他状态码一律不改写。
- `Rack::Response` 返回 401 也走同一 `handle_chain_result`，会被接管并返回数组；
  非 401 的 `Rack::Response` 原样返回。
- `result ||= {}` 使应用返回 nil 也进入失败分派（`lib/warden/manager.rb:39`）。
- 没有配置 `failure_app` 时失败分会 `raise "No Failure App provided"`，
  同样不会退回应用（`lib/warden/manager.rb:145`）。

## 3. 两种顺序的实际差异

设 `S` 为已持久化用户，`L` 为 `lock!`，`R(scope)` 为读取身份。

### 顺序 A：先核对会话，再限制策略

`R(:maint)` → `L` → 业务

- 会话在锁之前完成恢复，`after_set_user(:fetch)` 在锁定前触发。
- 锁之后即使 `clear_strategies_cache!`，`@users[:maint]` 仍在，身份继续有效。
- 若 `R(:maint)` 为空，应用可在锁定前明确终止，失败原因与身份状态一致。
- 读取范围由应用在锁定前决定；锁只保证后续不再“补登录”。

### 顺序 B：先限制策略，再决定读取范围

`L` → `R(:maint)` / `R(:admin)` → 业务

- 锁不阻止 `R`，两个 scope 都会被恢复；`:admin` 也会变成已认证。
- 锁后 `authenticate(:maint)` 返回 nil 且不抛；若调用方没检查，会静默继续。
- 锁后 `authenticate!(:maint)` 才抛 `:warden`；此时失败 action 取决于 opts，
  裸 throw 的 scope action 不会生效。
- 优点是把“不再认证”提前；缺点是**读取范围没有被限制**，只是策略被限制。

### 结论

维护入口应采用 **顺序 A 的变体**：

1. 先固定唯一核准 scope `:maint`，只读它；
2. 读到身份则继续，读不到则终止；
3. 在进入维护逻辑前调用 `lock!`，防止后续代码意外补登录；
4. 不依赖 `lock!` 去挡其他 scope，也不在锁后调用 `set_user`。

## 4. 对调用方的可实施约束

1. **单一 scope 常量**：入口只接受 `:maint`，禁止从参数、header 或
   `env['warden'].user(scope)` 的 scope 推导出其他值。若确需区分其他 scope，
   只能在 `lock!` 前显式读一次并把结果当作布尔判据，不能把 scope 继续透传。
2. **先读后锁**：身份判定和失败终止都发生在 `lock!` 之前；`lock!` 之后只做
   业务，不再认证、不再 `set_user`、不再 `clear_strategies_cache!`。
3. **用 bang 终止**：入口认证失败必须 `authenticate!` 或显式 `throw(:warden,
   :action => ..., :message => ...)`；禁止裸 `authenticate` 后继续执行。
4. **失败 action 显式传**：不要依赖 `throw(:warden, :scope => ...)` 去取该 scope
   的 action；需要专用维护页时直接传 `:action`。
5. **异常不冒充未认证**：应用异常必须由应用自己的 Rack 中间件/框架错误处理
   转成 5xx；不要把它 rescue 成 `throw(:warden)`，否则 401 会掩盖故障。
6. **响应归属**：若应用要自己提交 401/403，先 `custom_failure!` 或关闭
   `intercept_401`；否则下游 401 会被失败应用替换。
7. **锁后不复用代理**：`lock!` 是请求级状态，不能跨请求复用 `Proxy`；每个 Rack
   请求由 `Manager#call` 新建。

## 5. 拒绝方式的选择

按证据选择，而不是按状态码习惯：

- **没有身份、需要用户重新认证**：`authenticate!`，让失败应用按 scope action
  提交 401；适合浏览器入口。
- **没有身份、但这是维护窗口而非登录问题**：应用显式
  `throw(:warden, :action => :maintenance, :message => ...)`，失败应用渲染维护页；
  不要用 401 表达“系统维护”。
- **有其他 scope 的身份、但没有核准 scope 的身份**：入口不读其他 scope，
  按“无核准身份”处理；若业务确实要区分“已登录但无权限”与“完全未登录”，
  只能在 `lock!` 之前由应用显式读取它要区分的 scope，并自行承担
  `after_set_user(:fetch)` 等副作用，然后 `throw(:warden, :action => :forbidden)`
  或直接返回 403，配合 `custom_failure!`；不要交给默认失败应用，否则会变成 401。
- **应用内部错误**：让异常上抛，由应用错误处理返回 5xx；不要进入失败应用。
- **下游已经给出明确 401/403**：需要保留就 `custom_failure!` 或
  `intercept_401 = false`；需要统一入口体验才让 Warden 接管。

## 6. 只能由应用控制的边界

以下三件事 Warden 当前不会替应用做，必须由应用自己保证：

1. **核准 scope 的白名单**：`lock!` 不限制 `user(scope)`，任意 scope 都能从会话
   恢复。只有应用能决定“只读 :maint”。
2. **锁后禁止写入身份**：`set_user` 不受 `@locked` 约束，锁后仍可写入并持久化。
   只有应用能保证不在锁后调用它。
3. **异常到响应的映射**：`Manager#call` 不 rescue，未捕获异常不会进入失败应用。
   只有应用（或外层错误中间件）能决定 5xx 的提交方式。

补充：`session(scope)` 在未认证时会 `raise Warden::NotAuthenticated`，这也不是
失败分派；应用若使用它，需要自己 rescue 并决定响应。

## 7. 验收记录

- 规格：`spec/acceptance/maintenance_entry_spec.rb`（12 例，只用
  `SyntheticUser` 与 `:fake_grant`/`:fake_deny`）。
- 记录：`docs/acceptance/maintenance_entry_record.txt`。
- 运行：

```sh
BUNDLE_FROZEN=true .feedback/bundle-env exec rspec -Ilib spec/acceptance/maintenance_entry_spec.rb
```

记录中可直接对照：

- 已缓存策略：`[:state, :cached_identity, "u-maint", "u-maint"]`，且
  `strategy_run` 只有一次；`[:state, :after_clear_cache, "u-maint", []]` 说明
  清策略缓存不会清用户。
- 已持久化用户：`[:session, :deserialize, :maint, "u-maint"]` 与
  `[:hook, :after_set_user, :fetch, :maint]`，`strategy_run` 为空。
- 没有身份：`[:hook, :after_failed_fetch, :maint]` 与
  `[:hook, :before_failure, "unauthenticated", "/unauthenticated"]`，响应 401。
- 失败 action 来源：`[:state, :bang_action, "/maint_gate", "maint_gate"]` 对比
  `[:state, :bare_action, "/unauthenticated", "unauthenticated"]`。
- 顺序 B 的泄漏：`[:state, :locked_read, "u-maint", "u-admin"]`，
  `[:state, :other_authenticated?, true]`。
- 锁后写入：`[:state, :set_after_lock, "u-forced"]` 且会话出现
  `warden.user.maint.key`。
- 异常：无 `before_failure` 记录，`RuntimeError` 上抛；`Rack::Response` 401 的
  记录是 `["Array", 401, ["You Fail!"]]`，200 则保持 `Rack::Response`。
- 未认证 `session`：`[:state, :session_raised, "Warden::NotAuthenticated"]`，
  且无失败分派记录。
