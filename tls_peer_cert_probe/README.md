# Net::HTTP `peer_cert` 语义与 TLS 会话恢复证据手册

排查背景：业务调试发现部分请求复用了已有 TLS 状态。本目录用本机证书 +
IO 替身（`UNIXSocket.pair` 替代 `TCPSocket`，见 `probe.rb`）驱动本仓库的
Net::HTTP 走完真实握手，逐场景记录「何时验证、看到什么对端标识、是否尝试恢复」，
原始证据在 `evidence.log`（JSONL）。复现：`ruby -Ilib tls_peer_cert_probe/probe.rb`。

## 1. 源码机制（lib/net/http.rb）

- `connect` 每次重连都新建 `SSLContext` 并用当前实例变量 `set_params`
  （lib/net/http.rb:1690、lib/net/http.rb:1753）——**看起来**每次重连都套用最新验证配置。
- 但同一 `Net::HTTP` 实例会把握手产出的会话经 `session_new_cb` 缓存进 `@ssl_session`
  （lib/net/http.rb:1760），下次 `connect` 时若未过期就 `s.session = @ssl_session`
  尝试恢复（lib/net/http.rb:1784-1787）。
- `peer_cert` 只是 `@socket.io.peer_cert`（lib/net/http.rb:1623-1628）：它返回
  **当前这条 SSLSocket 所绑定的那次握手**的对端证书，不附带「何时验证过」的信息。
- 主机名检查 `post_connection_check` 只在 `connect` 内执行一次
  （lib/net/http.rb:1789-1791）；keep-alive 期间的每个请求不会再验证。

## 2. 三种场景下 peer_cert 能说明什么

### A. 首次握手（全握手）
证据：`verify_callback` 在 `start` 内触发（depth 1 = CA、depth 0 = 服务器叶子证书），
`session_reused=false`，`verify_result=0`，`peer_cert` 指纹与服务器证书一致。
- `peer_cert` 是**刚按当前 `cert_store`/`verify_mode` 验证过**的证书，且通过了
  主机名检查。这是唯一可以合规签收的形态。

### B. keep-alive / 恢复连接（复用已有 TLS 状态）
证据：keep-alive 期间 `connect_count` 不变、无任何握手事件；同实例 `finish`+`start`
后 `session_reused=true`（客户端与服务端两侧一致），**`verify_callback` 一次都没有触发**，
但 `peer_cert` 照常返回、指纹不变，`verify_result` 仍为 0。
- TLS1.2 缩写握手与 TLS1.3 PSK 恢复中，服务器**不再发送证书**，链验证、
  `verify_callback`、主机名检查全部不发生；`peer_cert` 来自客户端缓存的会话对象。
- 此时 `peer_cert` 只能说明「这条连接与当初那次全握手属于同一会话、对端持有
  同一私钥」，**不能说明按当前配置做过验证**。`verify_result=0` 是上次验证的
  残留值，不是本次的证据。

### C. 重新指定验证配置后再重连（合规陷阱）
证据：把 `cert_store` 换成**不含**签发 CA 的 STORE2 后重连，连接依然成功——
因为会话恢复跳过了整个证书验证（场景 C 日志中零 `verify_callback`）。
清掉 `@ssl_session` 强制全握手后（场景 D），同一 STORE2 立即正确拒绝：
`certificate verify failed`。
- 结论：**改了 `verify_mode`/`cert_store`/`verify_callback` 不等于生效**。
  只要 `@ssl_session` 未过期，重连就可能恢复会话，新配置被静默绕过，
  而 `peer_cert` 看起来一切正常。

## 3. 运维证据清单（什么能签收、什么不能）

可用于合规签收的证据（须同时满足）：
- 握手时刻的 `verify_callback` 记录：时间戳、`preverify_ok=true`、depth、
  每张证书的 subject/issuer/serial/SHA256 指纹（本探针 `verify_callback` 事件）。
- 该连接 `session_reused? == false`（客户端 `@socket.io.session_reused?`，
  最好与服务端日志交叉印证）。
- `peer_cert` 指纹 + SAN 与预期清单比对通过；证书在有效期内。
- `post_connection_check` 通过（Net::HTTP 在 verify_mode 非 NONE 且
  verify_hostname 时自动做，证据是 `connect` 未抛异常 + 地址匹配 SAN）。
- 协商出的 `ssl_version`/`cipher` 符合基线。

不能单独签收的证据：
- 恢复会话上的 `peer_cert` / `verify_result`：证明的是历史验证，不是本次。
- 实例上 `verify_mode`/`cert_store` 的**设定值**：设定 ≠ 已执行（见场景 C）。
- keep-alive 连接上第 N 个请求的 `peer_cert`：它反映的是连接建立时的那一次握手。

## 4. 何时必须强制重新协商（实为强制全新握手）

TLS1.3 已删除重协商，TLS1.2 重协商普遍被禁用且语义不等价——正确做法是
**关闭连接、丢弃缓存会话、重新全握手**。触发条件：
- 修改了任何验证配置（`verify_mode`、`cert_store`、`verify_callback`、`verify_hostname`）。
- 信任锚轮换、CA 吊销事件（CRL/OCSP 更新）、对端证书轮换窗口之后。
- 缓存会话年龄超过策略上限（本探针测得默认 `session.timeout=7200` 秒）。
- 执行高权限操作前，若无法拿出「本次连接全握手 + 验证通过」的证据。

Net::HTTP 没有公开的会话清除 API，可选手段：
- 换新 `Net::HTTP` 实例（最干净，推荐）；
- `finish` 后 `instance_variable_set(:@ssl_session, nil)`（依赖内部实现，脆弱）；
- 服务端侧关闭 session ticket / 缩短 ticket 生命周期，使客户端恢复尝试失败
  后自动回退全握手（本探针场景 D 即回退后正确拒绝的例证）。

## 5. 探针说明

- `probe.rb` 用 `UNIXSocket.pair` + 单例方法拦截 `setsockopt(TCP_NODELAY)`
  作为 IO 替身（`SSLSocket` 要求真实 IO 对象），不绑定任何端口；
  服务端是跑真实 OpenSSL 握手的线程内 TLS 服务器 + 最小 HTTP/1.1 应答。
- 场景：A 首次全握手（TLS1.3）→ B 同实例重连（PSK 恢复）→ C 换不信任的
  信任库再重连（恢复绕过验证）→ D 清会话强制全握手（新配置生效并拒绝）→
  E TLS1.2 对照组（结论一致）。
- `evidence.log` 中 `server_accept`/`snapshot` 的 `session_reused` 字段为
  客户端与服务端双侧的恢复结果；服务端视角的 `peer_cert_seen` 指**客户端**
  证书（本探针未启用 mTLS，故为 false）。
