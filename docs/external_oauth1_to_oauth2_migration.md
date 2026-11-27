# 外部登录适配器 OAuth 1 → OAuth 2 迁移判据

可复跑的验收测试：
`spec/controllers/sorcery_external_oauth1_to_oauth2_migration_spec.rb`

```sh
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null \
  spec/controllers/sorcery_external_oauth1_to_oauth2_migration_spec.rb
```

测试只替换提供方协议，保留真实的控制器回调与真实的本地 ActiveRecord
模型匹配。两个测试提供方位于 `spec/support/providers/`：

- `LegacyTwitter`：`include Protocols::Oauth`（OAuth 1.0，请求令牌存 session）
- `TwitterOauth2`：`include Protocols::Oauth2`（OAuth 2.0，code 流程，无状态）

两个窗口返回**相同的显示资料**（name/email 等），但返回**不同的稳定身份**
（`uid`），用以决定哪些本地绑定能接续。

## 1. 协议许可（protocol authorization）

- 两个提供方的 `oauth_version` 分别为 `1.0` 与 `2.0`。
- 旧窗口：`login_at` 把 request token / secret 写入 session，并以
  `oauth_callback` + `oauth_token` 跳转。
- 新窗口：跳转携带 `code` 流程参数，session 中**没有** request token。
- 判据：协议互不兼容，旧 session 里的 request token 无法用于新 code 流程。

## 2. 资料读取（profile read）

- 两条回调解析出的显示资料一致（`name`、`email`）。
- `uid` 不同：`OAUTH1-UID-777` → `OAUTH2-STABLE-UID-999`。
- 新提供方通过 `user_info_mapping` 把资料映射到本地 `username/email`。
- 判据：显示资料相同**不构成**接续依据，身份只看稳定 `uid`。

## 3. provider 与 uid 的绑定（binding）

本地匹配唯一入口是 `User.load_from_provider(provider, uid)`，底层为
`authentications` 表上的精确复合查询 `where(provider:, uid:).first`
（见 `lib/sorcery/adapters/active_record_adapter.rb`）。

- 当 `(provider, uid)` 精确命中既有行：接续成功，`login_from` 建立会话。
- 仅 `uid` 变化、资料相同：**不接续**，登录失败且不回写旧行。
- 仅凭同名/同邮箱：**绝不合并账号**（防止账号接管），失败时零新增行。
- `uid` 按 provider 命名空间隔离：同一 `uid` 换 provider 不命中。
- 判据：只有“同一 provider 且同一稳定 uid”的本地绑定可迁移。

## 4. 新建账号（new account creation）

无匹配绑定时走 `create_from` → `User.create_from_provider`，在
`authentications` 写入新的 `(twitter_oauth2, 新uid)`。

真实顺序（测试用事件序列断言）：
`query_binding → save_user → write_authentication`。

- 成功：新增 1 个 user + 1 条 authentication，绑定到新 `(provider, uid)`。
- `create_from` 只建账号，**不建立会话**；会话由 `login_from` 在命中绑定时建立。
- user-save 阶段写层报错：整体不产生 user/authentication，无会话。

### 已知限制：当前适配器没有真正的事务

`ActiveRecordAdapter.transaction` 的实现是 `@klass.tap(&)`
（`lib/sorcery/adapters/active_record_adapter.rb:104`），并不会开启数据库
事务；`MongoidAdapter` 同样是 `tap`。因此 authentication 写入失败时，
已保存的 user **不会回滚**，会留下孤立 user，但仍不会建立会话。

迁移含义：

- 不要假设“写失败 = 什么都没写”；运维上需准备孤立 user 的清理/对账。
- 若要原子保证，需另行包裹真实事务，这超出本迁移“只换提供方”的范围。

## 5. 用户放弃对照（abandoned consent，控制组）

- 新窗口用户拒绝授权，token 交换抛出 `OAuth2::Error`。
- 错误发生在任何 `load_from_provider` 查询与任何写入之前。
- 结果：无查询、无写入、无会话（`user_id` 为 nil）。

## 6. 何时必须保留旧回调（legacy callback coexistence）

切换期间，旧登录窗口可能已先发出 OAuth 1 请求并持有 request token。

- 旧回调（`legacy_twitter` 路由与动作）必须继续挂载，直到在途 OAuth 1
  会话（request token 生命周期）全部耗尽。
- 新 OAuth 2 提供方上线后，旧回调仍能凭旧 session 完成登录并命中旧绑定。
- 判据：两个回调并行；只有确认无在途 OAuth 1 会话后，才能下线旧回调。

## 一页纸结论

| 情形 | 查询 | 写入 | 最终会话 | 迁移结论 |
| --- | --- | --- | --- | --- |
| 同 provider + 同 uid | 命中既有行 | 无 | 已登录 | 可直接接续 |
| 资料相同、uid 变化 | 查不到 | 无 | 未登录 | 不可接续，禁止按邮箱/名合并 |
| 同 uid、不同 provider | 查不到 | 无 | 未登录 | uid 按 provider 隔离，不可接续 |
| 无任何匹配，主动新建 | 查不到 | user + authentication | 创建不登录 | 建立新 `(provider, uid)` 绑定 |
| user-save 写层失败 | 先查 | 无（报错中断） | 未登录 | 无残留 |
| authentication 写失败 | 先查 | user 已写、auth 失败 | 未登录 | 可能留孤立 user（无真实事务） |
| 用户放弃授权 | 不查询 | 无 | 未登录 | 控制组，零副作用 |
| 在途 OAuth 1 旧窗口 | 命中旧绑定 | 无 | 已登录 | 旧回调必须保留至在途会话耗尽 |
