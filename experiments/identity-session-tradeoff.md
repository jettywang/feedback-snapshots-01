# Keystoneauth 会话身份与目录发现取舍

基于当前工作区版本：`keystoneauth 0.1.0.dev2011`，git baseline `c3e4666`。

- 可复跑脚本：`experiments/identity_session_boundaries.py`
- 最近一次 transcript：`experiments/identity_session_transcript.json`
- 运行方式：`.venv/bin/python experiments/identity_session_boundaries.py`
- 若本地环境缺少 `requests_mock`，可使用仓库测试依赖：`.venv/bin/python -m pip install 'requests-mock>=1.2.0'`
- 默认写出 `experiments/identity_session_transcript.json`；脚本退出码为 0 表示全部不变量通过。
- 实验不访问网络、不使用真实凭据；线上请求中的身份头只记录为 `ph-token-*` 占位符。

## 结论

通用客户端可以共享 `keystoneauth1.session.Session` 的传输、重试、TLS 策略和显式传入的目录发现缓存，但不能把“当前默认身份”当成一个可在请求途中安全替换的普通变量。

- `Adapter(..., auth=X)` 和单次 `request(..., auth=X)` 都会把 plugin 绑定到该次调用；401 后的 invalidate、取新 token 和重试仍使用 `X`。
- 只有 `Session(auth=X)` 默认入口保留 `auth=None`，并在取头、发现、`invalidate()` 时反复读取当前的 `session.auth`。在 401 后替换 `session.auth`，分歧会在 invalidate 阶段变成实际身份切换，重试可能以新身份发出。
- 多身份客户端更稳妥的隔离单位是“每个操作身份一个 `Session` + 一个或多个 `Adapter`”；这些 Session 可以显式共享同一个 `discovery_cache` 字典。
- 目录/版本发现不是身份凭据。相同服务、region、interface 和版本约束最终解析到同一 discovery URL，且发现文档不随身份变化时，可以跨身份共享发现缓存。服务目录本身位于 plugin 的 `auth_ref` 中，仍按身份隔离。

## 这版代码中的状态归属

| 状态 | 位置 | 可否跨身份共享 | 说明 |
| --- | --- | --- | --- |
| 默认 auth plugin | `Session.auth`，见 `keystoneauth1/session.py:398` | 不建议在并发或在途请求中共享可变默认值 | `_auth_required(None)` 每次回退到当前 `self.auth`，见 `keystoneauth1/session.py:1385` |
| 单次 auth 参数 | `Session.request(..., auth=...)`，见 `keystoneauth1/session.py:771` | 可与共享 Session 配合 | 非 `None` 时贯穿取头、发现、invalidate 和重试 |
| Adapter 自带 auth | `Adapter(..., auth=...)`，见 `keystoneauth1/adapter.py:141` | 可以，但它是该 Adapter 的固定身份 | `_request()` 用 `kwargs.setdefault('auth', self.auth)`，单次 `auth=` 优先级更高，见 `keystoneauth1/adapter.py:246` |
| token / AccessInfo / catalog | `BaseIdentityPlugin.auth_ref` | 否 | token 缓存判断和刷新锁见 `keystoneauth1/identity/base.py:85`、`keystoneauth1/identity/base.py:125`；invalidate 清空 `auth_ref`，见 `keystoneauth1/identity/base.py:134` |
| plugin 级发现缓存 | `BaseAuthPlugin._discovery_cache`，见 `keystoneauth1/plugin.py:58` | 随 plugin，默认不跨身份 | 发现时作为显式 `cache=` 传入，见 `keystoneauth1/identity/base.py:290` |
| Session 级发现缓存 | `Session._discovery_cache`，见 `keystoneauth1/session.py:421` | 可以显式共享 | 构造参数文档明确允许多个不共享 auth plugin 的 session 共用一个 dict，见 `keystoneauth1/session.py:347` |
| HTTP 连接池/cookie | 底层 `requests.Session`，由 `Session.session` 持有 | 连接池通常可共享；cookie 需按是否身份相关判断 | 若服务端写入身份相关 cookie，或 mTLS/校验/代理不同，应拆 Session |
| 服务选择状态 | `Adapter.service_type`、`region_name`、`interface`、`version` 等 | Adapter 内共享，跨服务/region 应新建 Adapter | 代码注释把 Session 定位为全局共享对象，把 service/region 等状态定位为 client-local，见 `keystoneauth1/adapter.py:30` |
| `additional_headers`、cert、verify、timeout | Adapter/Session 配置 | 仅在身份和安全域策略相同时共享 | 特别检查可能含身份维度的默认头或客户端证书 |
| timing 记录 | `Session._api_times` | 可共享但会混合多身份审计维度 | 若要按操作身份审计，应在外层 transcript/metrics 中自行打标签 |

优先级可以压缩为：

```text
单次 request(auth=X) > Adapter(auth=X) > Session.auth
```

## 实验覆盖

脚本为每条入口构造相同的服务选择：

```text
service_type = block-storage
region_name  = RegionOne
interface    = public
```

第一个操作 `/v3/op-401` 在真实执行一次 discovery 并发出请求后返回 401；mock 回调在 KSA 进入 401 处理前替换 `session.auth`。第二个操作 `/v3/op-cache` 使用相同服务和 region，用来观察后续身份与 discovery 缓存。

最近一次本地结果：

```text
shared_session/adapter_auth:
  tokens    = A-v1, A-v2, A-v2
  discovery = miss, hit
  checks    = 5/5

shared_session/session_default:
  tokens    = A-v1, B-v2, B-v2
  discovery = miss, hit
  checks    = 5/5

shared_session/request_override:
  tokens    = O-v1, O-v2, O-v2
  discovery = miss, hit
  checks    = 5/5

shared_session/session_default_cold_replacement:
  tokens    = A-v1, B-cold-v1
  401 后无重试；后续操作才 mint B-cold-v1
  checks    = 5/5

identity_sessions/two_identities_shared_discovery_cache:
  tokens    = A-v1, A-v2, B-v1
  discovery = miss, hit
  checks    = 6/6
```

表中的 `A-v1` 等是 transcript 里的 `ph-token-A-v1` 占位符，不是 token 内容。

## 四阶段分歧点

### 1. 发起

`Session.request()` 先计算 `authenticated = bool(auth or self.auth)`，然后调用 `get_auth_headers(auth)`，见 `keystoneauth1/session.py:918`。

- Adapter 身份会在 `Adapter._request()` 中变成非 `None` 的 `auth=`。
- 单次覆盖同理，并且优先级最高。
- Session 默认入口的 `auth` 仍是 `None`；`_auth_required(None)` 此时读取 `session.auth`。

因此，默认入口没有在方法入口快照 plugin。分歧的代码条件在发起阶段已经存在，但本实验按题目要求在收到 401 后才修改默认身份，所以第一次发出的仍是原身份。

实验事件：

```text
plugin_get_headers(A, cache=hit, ph-token-A-v1)
wire_send /v3/op-401, ph-token-A-v1 -> 401
```

### 2. 目录发现

若 URL 不是完整 URL，Session 调用 `self.get_endpoint(auth, ...)`，见 `keystoneauth1/session.py:937`；随后 plugin 根据 `service_type`、`region_name`、`interface` 选择 catalog endpoint，并进入 `discover.get_discovery()`。

发现缓存依次检查：显式传入的 plugin cache、`session._discovery_cache`、当前 `session.auth._discovery_cache`，缓存键是规范化 URL 以及服务相关 version header，见 `keystoneauth1/discover.py:1737` 和 `keystoneauth1/discover.py:1768`。命中后不会新建 `Discover`，未命中才发 HTTP，并回写所有可见缓存层，见 `keystoneauth1/discover.py:1772`。

实验中第一个操作的结果是：

```text
catalog_lookup(block-storage, RegionOne, public)
wire_send GET /             # discovery document
discovery_cache = miss
```

URL 在首次发送前已经解析完成。401 重试只更新 auth header 并重新 `send(**kwargs)`，不会重新走 endpoint/discovery，见 `keystoneauth1/session.py:1127`。这解释了为什么切换身份不会在重试时自然产生一次新的目录选择。

### 3. invalidate

401 且允许 reauth 时，KSA 执行：

```python
if self.invalidate(auth):
    auth_headers = self.get_auth_headers(auth)
```

见 `keystoneauth1/session.py:1125`。`Session.invalidate(None)` 又通过 `_auth_required()` 读取“当前” `session.auth`，见 `keystoneauth1/session.py:1570`。

这是本实验中跨身份分歧成为事实的位置：

- `auth=A` 非 `None`：调用 `A.invalidate()`，A 的缓存 token 被清空。
- Session 默认入口且已把 `session.auth` 从 A 改成 B：调用的是 `B.invalidate()`；原始发送者 A 反而没有被 invalidate。
- 如果 B 已有缓存 token，`BaseIdentityPlugin.invalidate()` 返回 `True`，KSA 认为可以重试。
- 如果 B 是冷 plugin、`auth_ref is None`，invalidate 返回 `False`，KSA 不会取新 header，也不会重试；调用方拿到原 401。实验的 cold replacement 用例固定了这个边界。

### 4. 重试

invalidate 成功后，Session 再次调用 `get_auth_headers(auth)` 并更新同一组 headers，然后重发，见 `keystoneauth1/session.py:1129`。

- Adapter 身份：重试占位符为 `ph-token-A-v2`。
- 单次覆盖：重试占位符为 `ph-token-O-v2`。
- Session 默认且中途换成热 B：重试占位符为 `ph-token-B-v2`。这是危险的“操作以新身份重试”信号。
- 第二个操作继续反映默认值变化：Adapter/单次覆盖仍是原显式身份；裸 Session/Adapter 默认请求则使用 B。

## 共用 Session 与按身份划分 Session

### 可以共用一个 Session 的情况

满足以下条件时，一个共享 Session 不会因身份串线：

1. 每个多身份操作都通过 `Adapter(auth=...)` 或单次 `auth=...` 显式绑定 plugin。
2. 不在请求途中替换 `session.auth`；最好把 `Session.auth` 只当作单一稳定默认值或完全不设置。
3. 所有身份共享相同的 CA/verify、client cert、代理、额外默认头、cookie 策略和限流策略。
4. 接受 timing、连接池等共享运行时状态；审计标签由通用客户端外层按身份记录。

这时 Session 是传输和缓存共享单位，plugin 是身份状态单位。显式 plugin 甚至可以被多个请求共用；`BaseIdentityPlugin.get_access()` 有锁保护 token 刷新。

### 应按身份划分 Session 的情况

出现以下任一条件，建议用 `dict[identity_key, Session]` 或更高层 client pool 做隔离：

- 代码中存在不带 `auth=` 的调用，即依赖 `session.auth` 默认值。
- 多身份复用同一 Session，并且会在登录、切换租户、收到 401 或并发请求时修改 `session.auth`。
- 不同身份使用不同 token、catalog、project/scope、mTLS 证书、CA、代理或身份相关 cookie/header。
- 需要限制 invalidate、重认证、审计和故障爆炸半径。

推荐形状：

```text
identity A -> Session(auth=plugin_A, discovery_cache=shared_cache)
              └── Adapter(service_type=..., region_name=RegionOne, ...)

identity B -> Session(auth=plugin_B, discovery_cache=shared_cache)
              └── Adapter(service_type=..., region_name=RegionOne, ...)
```

不要在 A 的在途 401 回调里把 `session_A.auth` 改成 B。KSA 会就地重试，外层可能还没完成“是否允许换身份重试”的授权判断。需要换身份时，应让原操作按 A invalidate/retry 或失败，再由通用客户端显式选择 B 的 Session 发起新操作。

## 目录发现何时还能共享

实验中的 partitioned 用例把同一个字典传给两个 Session：

```python
shared_discovery_cache = {}
session_a = Session(auth=plugin_a, discovery_cache=shared_discovery_cache)
session_b = Session(auth=plugin_b, discovery_cache=shared_discovery_cache)
```

A 的第一次操作是 `miss` 并发起 discovery HTTP；A 的重试不重新发现；B 的第二个操作是 `hit`，没有第二次 discovery HTTP。transcript 中断言共享字典只有一个 cache key。

可验证的共享条件是：

1. `service_type`、`service_name`、`region_name`、`interface`、version/min/max、`allow` 和 version hack 条件给出相同选择。
2. 各身份 catalog 对该选择解析出相同的规范化 endpoint/discovery URL。
3. `discover.get_discovery()` 的 cache key 相同；这版 key 由 URL 和服务相关 version header 组成，不包含 token，见 `keystoneauth1/discover.py:1768`。
4. discovery 文档、微版本信息和 endpoint 可见性不随身份、项目或 token 变化。
5. 不同 Session 显式传入同一个 `discovery_cache`，或者本来就共用同一个 Session。

脚本的三个边界探针给出可复跑结果：

| 探针 | 第二次 discovery |
| --- | --- |
| 共享 cache + 相同 service/region/interface | `hit` |
| 各自私有 cache + 相同 service/region/interface | `miss` |
| 共享 cache + 不同 region | `miss` |

注意：相同 service 和 region 只是必要线索，不是充分条件。还要核对 interface、service name、版本约束、项目化 endpoint、策略过滤后的 catalog，以及 discovery 响应是否身份相关。若 discovery 文档可能按 token 变化，而缓存键没有身份维度，就不能共享该缓存；应使用每身份缓存，或在外层加入经过验证的身份/scope 缓存命名空间。

## 可机器验证的隔离判据

通用客户端可以把下面检查放进自己的集成测试：

- 对同一操作分别走 adapter、session default、request override 三条入口。
- 记录第一次请求、401 后重试和后续请求的 `X-Auth-Token` 占位符。
- 若测试在 401 后修改 `session.auth`，则：
  - adapter/override 用例必须保持原身份前缀；
  - session-default 用例在当前实现中会观察到新默认身份；
  - 如果新默认 plugin 没有缓存 `auth_ref`，必须观察到 invalidate 返回 `False` 且没有自动重试。
- 对相同服务/region 的第二个身份操作，断言 discovery HTTP 次数不增加且 transcript 为 `hit`。
- 对不同 region 或私有 cache，断言第二次为 `miss`。
- 任何真实日志或 transcript 只保存 `ph-token-*`、身份逻辑名、plugin 调用名和缓存结果，不保存原始 token、密码、应用凭据或完整认证响应。
