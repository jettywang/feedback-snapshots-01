# 诊断：为什么“看到 Set-Cookie”不能记为“登录已落地”

## 结论

`Set-Cookie` 只证明**服务端在响应里尝试下发了一个会话标识**。一次登录真正落地，
需要五个状态全部成立；`Set-Cookie` 只覆盖其中第 2 步。事故复盘时把第 2 步当作
终点，就会漏掉客户端拒收（第 3 步）和服务端写失败（第 1 步）这两类故障。

## 登录落地的状态链

| # | 状态 | 发生位置 | 调用方能否独立核对 |
|---|------|----------|--------------------|
| 1 | `write_session` 持久化成功 | 服务端内部 | **不能**，只能靠服务端采集（见字段约定） |
| 2 | 响应携带 `Set-Cookie` | 响应头 | 能（抓包/网关日志即可见） |
| 3 | 客户端按 RFC 6265 接受并入库 | 客户端 | 能（客户端侧核对 Domain/Path/Secure/SameSite/Expires/大小） |
| 4 | 后续请求带回 `Cookie` 头 | 请求头 | 能（网关/服务端日志可见） |
| 5 | 服务端用该 Cookie 恢复出**同一份**会话数据 | 服务端内部 | 不能直接核对；只能通过应用层探针（如 `/whoami` 返回 `user_id`）间接确认 |

调用方能独立核对的是 2、3、4，以及 5 的应用层探针；**第 1 步和服务端存储内容
对调用方永远不可见**，这正是“看到 Set-Cookie 但登录没落地”的盲区。

## 两种后端的故障语义

### `Rack::Session::Cookie`（数据在客户端）

- 会话整体加密/编码进 cookie，服务端无状态；重启、多进程都不影响恢复。
- 恢复条件：客户端回传 cookie **且** `secrets` 未轮换到无法解密。
- 写失败形态：编码后超过 4K（`lib/rack/session/cookie.rb:271`）时
  `write_session` 返回 `nil` → **根本不发 `Set-Cookie`**，只在 `rack.errors`
  留下两行警告。应用层对此无感知，登录响应仍是 200。
- 解密失败（secret 轮换、客户端篡改）时 cookie 被静默丢弃，按新会话处理。

### `Rack::Session::Pool`（数据在服务端内存）

- cookie 里只有 sid，数据在进程内 `@pool`（`lib/rack/session/pool.rb:32`）。
- 恢复条件：**同一进程**且条目未被清除。重启、扩容、多副本负载均衡都会丢会话。
- 写失败形态一：`write_session` 返回 `false`（真实部署里对应 Redis/Memcached
  类存储宕机）→ 不发 `Set-Cookie`，`rack.errors` 留警告
  （`lib/rack/session/abstract/id.rb:397`）。
- 写失败形态二（最隐蔽）：登录时 `Set-Cookie` 正常下发、客户端也正常回传，
  但重启后池子空了，`find_session` 静默签发**新 sid** 并回种一份空会话
  （`lib/rack/session/pool.rb:46-49`）。此时第 2、3、4 步全部成立，
  响应里甚至还有新的 `Set-Cookie`——单看头部字段完全是“登录成功”的样子，
  只有第 5 步的应用层探针能戳穿。

## 最小采集字段约定

每条登录响应 + 其后一次回访请求，采集以下字段：

| 字段 | 采集点 | 能证明什么 | 不能证明什么 |
|------|--------|------------|--------------|
| `request_id` | 全链路 | 把登录响应和后续请求关联到同一次会话建立过程 | — |
| `backend` (`cookie`/`pool`) | 服务端配置 | 决定故障语义：丢会话是客户端问题还是服务端存储问题 | — |
| `write_session_result` (`ok`/`false`/`nil`) | 服务端，`commit_session` 内 | **唯一**能证明“服务端写失败”的字段（状态 1） | 客户端是否收到/接受 |
| `set_cookie.present` | 响应头 | 服务端尝试下发（状态 2） | 客户端接受、服务端已写入 |
| `set_cookie.attrs`（Domain/Path/Secure/SameSite/Expires/Max-Age/字节数） | 响应头 | 可**离线**按 RFC 6265 核对客户端是否会接受、何时回传（状态 3 的判定依据） | 客户端实际行为 |
| `session_public_id_hash`（sid 的 SHA-256 截断） | 服务端 | 两次请求是否同一会话；sid 是否被静默换发 | 会话内容（刻意不记录 sid 原文，防泄露） |
| `request.cookie_present` | 请求头 | 客户端回传了 cookie（状态 4）；拒收时恒为 `false` | 回传的是否为有效会话 |
| `session.user_id_present`（或等价业务键） | 应用层 | 恢复出了**真实会话数据**（状态 5），登录真正落地 | — |
| `rack_errors_warnings` | 服务端 `rack.errors` | Cookie 超 4K、写失败的唯一显式信号 | — |

判定规则：`登录已落地` 当且仅当同一条 `request_id` 链上
`write_session_result == ok` 且回访请求 `cookie_present == true`
且 `session.user_id_present == true` 且 `session_public_id_hash` 稳定。
`set_cookie.present` 只是必要条件，不是充分条件。

## 本地复现

`test/spec_session_login_evidence.rb`，运行：

```sh
.feedback/bundle-env exec ruby -Ilib -Itest test/spec_session_login_evidence.rb
```

覆盖两种后端的四类场景（9 个用例，每条 `[evidence]` 行即上述字段约定的一次采样）：

- **完整往返**：登录 → `Set-Cookie` → 客户端回传 → 下一次访问恢复出
  `user_id=4242` 且 sid 稳定（cookie/pool 各一）。
- **客户端拒收**：`Set-Cookie` 正常下发，但 Secure cookie 在 http 下不回传、
  或 Domain 不匹配被 jar 拒收 → 下一次访问 `user_id=nil`（cookie/pool 各两例）。
- **服务端写失败**：cookie 后端会话超 4K、pool 后端存储宕机 →
  **响应里没有 `Set-Cookie`**，`rack.errors` 留警告，下一次访问无会话。
- **pool 重启**：`Set-Cookie` 发过、cookie 也回传了，但池子已空 →
  服务端静默换发新 sid，真实会话不可恢复。
