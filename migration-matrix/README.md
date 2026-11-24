# Elasticsearch 节点迁到私有域名：目标地址查证 + 本地可复跑矩阵

对象：本仓库的 `elastic-transport` Ruby 8.6.0（当前 checkout `3c61c95`）。
本目录用**替身（脚本化 Faraday 适配器，不起真实 ES、不绑端口）**验证“静态 hosts /
sniffer 发布地址 / 选择器 / 代理”最终如何决定真实连接，并给出安全迁移与准入拆除办法。

- 一键复跑：`bash migration-matrix/run.sh`
- 驱动记录（稳定文件名）：`migration-matrix/runs/latest.log`
- 同次机器可读台账：`migration-matrix/runs/latest.json`
- 带时间戳副本：`migration-matrix/runs/driver-record-*.log`、`matrix-*.json`

运行器优先使用仓库自带的离线 bundle `.feedback/bundle-env`（faraday 2.15.1 /
multi_json 1.21.2，已 vendored 在 `.feedback/vendor`），不需要联网装 gem。
矩阵共 18 个用例、数十条断言；任何一条与当前实现不符都会以非 0 退出。

---

## 1. 结论先行：一个请求到底连谁

真实目标由四层依次决定，必须分开看：

1. **配置地址（configured）**：`Client.new(hosts: ...)`。
   `Client#extract_hosts` / `parse_host` 把 String / 逗号串 / URI / Hash / `ENV['ELASTICSEARCH_URL']`
   归一化成 host 哈希（`lib/elastic/transport/client.rb:223`、`lib/elastic/transport/client.rb:247`、
   优先级见 `lib/elastic/transport/client.rb:238`）。默认 `localhost:9200`。
2. **发现候选（discovered）**：仅当显式调用 `reload_connections!`、开启周期
   `reload_connections`、或失败 `reload_on_failure` 时，`Sniffer#hosts` 才请求
   `GET _nodes/http`，读取每个节点的 `nodes.<id>.http.publish_address` 并解析出
   `host` / `port`（`lib/elastic/transport/transport/sniffer.rb:47`、`:53`、`:80`）。
   **默认 `reload_connections: false`（`lib/elastic/transport/client.rb:132`），所以默认根本不会嗅探。**
3. **连接池与实际选择（pool / selected）**：候选被构建成 `Connections::Connection`，
   由 `Connections::Collection#get_connection` + 选择器（默认 RoundRobin）挑一个
   （`lib/elastic/transport/transport/connections/collection.rb:85`、
   `lib/elastic/transport/transport/connections/selector.rb:75`）。请求 URL 在
   `Connection#full_url` 里用**被选中连接自己的 host 哈希**拼绝对地址
   （`lib/elastic/transport/transport/connections/connection.rb:56`），再交给
   `Faraday::Connection#run_request(method, absolute_url, ...)`
   （`lib/elastic/transport/transport/http/faraday.rb:42`、建连 `:66`）。
4. **代理（proxy）**：逻辑 authority 仍是第 3 步选中的 ES host；但真正的 TCP 对端可能是代理。
   显式 `transport_options: { proxy: ... }` 对每条 Faraday 连接生效（含嗅探重建出的连接）；
   未显式配置时 Faraday 2 按绝对 URL 从 `http_proxy/https_proxy/no_proxy` 环境变量解析。
   faraday-net_http 把代理 host/port 传给 `Net::HTTP`，目标主机仍是 `env.url.host`。

一句话：**配了什么 ≠ 发现了什么 ≠ 这一次选中了什么；而代理场景下“选中的 authority”
还 ≠ “TCP 对端”。** 矩阵把这四列分别打出来。

---

## 2. `publish_address` 多地址样式实测（用例 A-styles）

用真实 `Sniffer` 解析器对每种样式跑出来的当前行为：

| `publish_address` 样式 | 解析出的 host | port | 评价 |
| --- | --- | --- | --- |
| `10.0.0.11:9200` | `10.0.0.11` | `"9200"` | 可用 |
| `node-1.es.private:9200` | `node-1.es.private` | `"9200"` | **推荐**：裸私有 FQDN |
| `node-1.es.private/10.0.0.11:9200` | `node-1.es.private` | `"9200"` | **推荐**：取 `/` 左侧名字，DNS 决定 IP |
| `node-1.es.private/[2001:db8::11]:9200` | `node-1.es.private` | `"9200"` | 可用（用名字） |
| `[2001:db8::11]:9200` | `2001:db8::11` | `"9200"` | 解析正确，但**建连踩 IPv6 括号坑（A-ipv6-build）** |
| `inet[/10.0.0.11:9200]` | `10.0.0.11` | `"9200"` | 老式但可用 |
| `inet[node-1.es.private/10.0.0.11:9200]` | `ode-1.es.private/10.0.0.11` | `"9200"` | **解析缺陷陷阱** |
| `inet[node-1.es.private:9200]` | `ode-1.es.private` | `"9200"` | **解析缺陷陷阱** |

两个必须知道的当前实现细节（都在矩阵里固化为断言）：

- `inet[...]` 分支写死 `publish_address[6..-2]`（`sniffer.rb:82`），它假设前缀正好是
  `inet[/`（第 6 个字符才是 IP 首字符）。一旦方括号里是 `主机名/ip` 或 `主机名:port`，
  主机名首字符会被吃掉，且 `/ip` 不会被剥离，重建出 `ode-.../10.0.0.11` 这种非法 host
  （A-trap-reload：不报错，但目标是错的，更隐蔽）。
- 裸 IPv6 被解析成**不带方括号**的 `2001:db8::11`，而 `__full_url` / `Connection#full_url`
  直接字符串拼接、不会重新加括号（`base.rb:252`、`connection.rb:59`），于是 Faraday/URI 抛
  `URI::InvalidURIError: bad URI ... "http://2001:db8::11:9200"`。因为 `__connections_from_host`
  是一次 `map`，**一个坏候选会让整次 `reload_connections!` 抛错**（A-ipv6-build）。

迁移建议：让节点发布成裸 FQDN 或 `FQDN/ip:port`（现代 ES 默认就是这类），避免让客户端吃到
裸 IPv6 与带主机名的 `inet[name/...]` 形态。

---

## 3. 迁移时间线实测（用例 M1–M4、S1–S2、F1–F4、P1–P4）

`runs/latest.log` 有完整逐步输出，下面是结论索引。

- **M1 默认不嗅探**：配 `old-a.corp / old-b.corp`，连打 4 次，RoundRobin 顺序
  `old-a → old-b → old-a → old-b`，`_nodes/http` 调用数为 0。
  => 不改配置/不重启的常驻进程，**永远**打旧目标。
- **M2 嗅探切到新域名（理想态）**：旧地址仅作引导，`_nodes/http` 返回 3 个
  `*.es.private`，`reload_connections!` 后旧连接全部移除，一个完整选择周期全部打新域名。
  准入门 `ALLOWED`。
- **M3 混合批次**：发现 `new-1,new-2,old-c`。重建后池物理顺序是 `old-c,new-1,new-2`，
  一个周期实际选择 `new-1 → new-2 → old-c`（选择器游标在重建间持续，见下）。
  => 还有节点在发布旧地址时，**每个 RoundRobin 周期仍有 1/N 流量打旧目标**，准入门 `BLOCKED`。
- **M4 死连接/复活**：死连接在有活节点时被跳过；超过指数退避
  `60 * 2**(failures-1)`（`connection.rb:135`）后 `resurrect!` 会按**同一个旧 host key**
  重回轮询；全部死亡时 `Collection#get_connection` 用 `min_by(&:failures)`
  返回一个死连接兜底（`collection.rb:86`），仍尝试旧目标。
- **S1/S2 协议降级坑**：`publish_address` **不含 scheme**。即使静态引导是
  `https://bootstrap...`，嗅探重建时 `host[:scheme]` 为 nil，协议回退到
  `options[:scheme] || options[:http][:scheme] || 'http'`（`base.rb:165`）。
  不显式给 `scheme: 'https'`，嗅探节点会被建成 **`http://node-1.es.private:9200` 并真的按 http 发请求（S1）**；
  给了 `scheme: 'https'` 才是 https（S2）。用 `ca_fingerprint` 时，pin 之后若重建出 http 主机会在
  `base.rb:173` 直接报错（这是保护）；普通 PKI 模式没有这层硬保护，务必显式固定 https。

### 重建时“谁被保留”——为什么仅改 DNS 不一定搬走旧连接

`Connection#==` 只比较 `protocol / host / port.to_i / attributes`
（`connection.rb:143`）。`__rebuild_connections`（`base.rb:126`）的做法是：

- 新候选里与旧连接 `==` 的，**新对象被丢弃、旧物理连接对象被保留**（M3 中 `old-c` 的 `object_id` 不变）；
- 不相等的旧连接从池中移除，新 key 才 `add`；
- 而且它**不会**重建 `Connections::Collection`/选择器，只对同一个集合 `remove/add`
  （M3 断言集合 `object_id` 不变），所以 RoundRobin 游标也延续。

推论：

- 若只是把**旧名字**的 DNS 改指新 IP，host 字符串没变 => `==` 成立 => 旧 Faraday 对象及其
  keep-alive 长连接/选择器状态都可能延续，已建立的 TCP socket 不会因为 DNS 改变而迁移。
- **改用全新私有域名（新 host 字符串）时 key 必然不等，连接一定新建**，这是更干净的迁移方向。

### 发现不可用的两种失败模式（F1–F4）

- **F1 嗅探超时 = 被容忍**：`Sniffer` 用 `Timeout.timeout(sniffer_timeout=1, SnifferTimeoutError)`
  （`sniffer.rb:48`、`:35`）。超时被 `reload_connections!` 单独 `rescue SnifferTimeoutError`
  吞掉（`base.rb:105`），保留上一份池，后续请求仍由旧节点服务（实测 0.051s 中止）。
- **F2 硬错误（如连接被拒）直接调 `reload_connections!`**：不会被吞，抛
  `Elastic::Transport::Transport::Error`；池不变，但嗅探选中的那条连接会被 `dead!`，
  之后普通数据请求可由另一条旧节点成功服务。
- **F3 周期 reload 撞上硬错误会连累本次用户请求**：设 `reload_connections: 2`，
  第 2 次 `get_connection` 在 `base.rb:93` 触发 reload，嗅探硬错误（已在嗅探内部被包装成
  `Transport::Error`，不属于 `host_unreachable_exceptions` 里的 Faraday 异常）穿透
  `reload_connections!` 与外层 rescue，**用户的 `/ping` 根本没到达适配器**
  （台账只有 `data:/ping` 成功的第一次 + `discovery:/_nodes/http` 失败的第二次）。
  注意周期阈值：传整数 X 时 `reload_after = X`（`base.rb:76`），默认 `true` 时是 10000 次。
- **F4 `reload_on_failure` 自愈链**：旧 `old-a` 数据请求被拒 -> 标记死亡 ->
  `reload_connections!` 经**仍存活的 `old-b`** 请求 `_nodes/http` -> 得到新域名 ->
  `retry` 在新池上成功。实测链：
  `old-a.corp/ping -> old-b.corp/_nodes/http -> new-2.es.private/ping`。
  这给出安全迁移的关键姿态：**保留至少一个可达的旧引导节点来发布新拓扑。**

---

## 4. 代理场景（P1–P4）

- **P1 显式代理**：`transport_options: { proxy: 'http://proxy.corp:3128' }`。
  每条 Faraday 连接的 `proxy` 与每个请求的 `env.request.proxy` 都指向同一代理；
  RoundRobin 选中的 authority 分别是 `node-1`、`node-2`。对 http 目标，代理收到的是
  absolute-form：`GET http://node-1.es.private:9200/ping`。
- **P2 环境代理 + `no_proxy` 分流**：在 Ruby 4.0.7 / Faraday 2.15 实测，设
  `no_proxy=.es.private` 时，`node-1.es.private` 命中后缀匹配 => **DIRECT**，
  而 `old-a.corp` 不命中 => 走 `http://env-proxy.corp:8080`。
  迁移期若只把新域名加进 `NO_PROXY`，新旧流量会走不同路径，准入观测要同时覆盖两条路径。
  不需要环境代理时可设 `Faraday.ignore_env_proxy = true`。
- **P3 代理在嗅探重建后仍在**：新连接与被保留的 `old-c` 都带着同一个显式代理。
- **P4 https over proxy**：TCP 对端是 `proxy.corp:3128`，线路“替身”推导出
  `CONNECT node-1.es.private:9200`；CONNECT authority 即被选中的新域名，随后 TLS 端到端到该名字。
  常规 PKI 校验下，新域名必须在证书 SAN 且链/主机名校验通过。

> 沙箱说明：本环境禁止本地 `bind(2)`（矩阵启动时实测 `local_binding: unavailable (EPERM)`），
> 所以无法起真实 TCP 代理端口抓 CONNECT/absolute-form 报文。P1/P4 的 “wire” 行是根据
> Faraday 适配器 `env.url` 与 `env.request.proxy`（正是 faraday-net_http 建 `Net::HTTP`
> 代理对端和请求行的输入，见 vendored `faraday-net_http-3.5.0/.../net_http.rb:63`）推导的，
> 不是 socket 抓包。要做真实 socket 复核：在设置里允许
> `sandbox.network.allowLocalBinding: true`，或在普通机器上运行 `run.sh`，再挂一个记录型本地代理即可。
>
> 安全：矩阵会对代理 URL 的 userinfo 打码，且不记录 `*_PROXY_USERNAME/PASSWORD` 的值；
> 运行器启动时会先摘除当前 shell 的代理环境变量以保证用例密闭。

---

## 5. 迁移后“仍在使用旧目标”的连接清单

按可能性与矩阵用例对应：

1. **没重启、且没开嗅探的客户端进程（M1）**：池就是静态 hosts，全部旧目标，直到重新部署/重启。这是最大的一类。
2. **尚未改发布地址的节点（M3）**：只要集群还在 `publish_address` 发布旧 FQDN/旧 IP，嗅探就会把旧目标重新种回池中。
3. **`==` 命中而被保留的旧物理连接（M3）**：同 protocol/host/port/attributes 的旧 Faraday 对象与 keep-alive 会话不换；只改旧名 DNS 不重置既有 socket。
4. **死连接与兜底/复活（M4）**：旧 key 不变，退避后复活或“全死选最少失败”时仍会尝试旧地址。
5. **嗅探请求本身（F4 链）**：`_nodes/http` 也是经当前池选一条连接发出的；池搬到新域名之前，发现请求可能落在旧引导节点上。
6. **代理后的旧 authority（P1–P4）**：所有连接的 TCP 对端可能都是同一台代理（这不是“旧目标”），但只要选中的还是旧 host，代理就会按 absolute-URI / CONNECT 继续转发到旧目标；`NO_PROXY` 还可能让新旧路径不一致。**代理访问日志里的 upstream authority 是最权威的拆除依据。**
7. **协议/格式副作用**：未固定 `scheme: 'https'` 时嗅探后可能降级成 http（S1）；裸 IPv6 / 老式 `inet[name/..]` 候选可能让 reload 失败或得到错误 host（A 组），间接使池停留在旧集合。

---

## 6. 安全迁移办法（推荐顺序，兼容本实现的真实行为）

核心思想：**先让“新名字”在数据面与发布面都成立，用“新旧并存”桥接，靠观测准入，最后才拆旧。不要一次性把旧名字直接改指或删除。**

1. **预备新私有域名**
   - 内网 DNS / split-horizon 解析 `node-N.es.private` 到目标 IP；路由、安全组、`9200`/`9300`、代理与防火墙放行。
   - 证书 SAN 加入所有新 FQDN（必要时含通配名），客户端信任新链；若用 `ca_fingerprint`，确认与新证书链匹配并注意其主机名校验说明。
   - 明确代理策略：新域名是否走代理、是否加入 `no_proxy`，并同步到所有运行环境（P2 的分流要符合预期）。
2. **固定客户端协议/端口**
   - TLS 集群显式 `scheme: 'https'`（不要只在静态 URL 里写 https，嗅探候选不带 scheme，见 S1）。
   - 建议同时显式 `port`，避免缺省落到 `9200`/`80` 之类默认值。
3. **让 ES 发布新名字（让嗅探成为助力而不是意外）**
   - 用 `http.publish_host` / `network.publish_host`（必要时 `http.publish_port`）让节点在
     `_nodes/http` 发布私有 FQDN；优先产出 `fqdn:port` 或 `fqdn/ip:port`，避免裸 IPv6 与
     `inet[主机名/..]` 形态。
   - 滚动重启，逐节点 `curl -s .../_nodes/http?filter_path=nodes.*.http.publish_address` 核对。
4. **客户端“双写”配置并滚动发布**
   - 最稳的静态法：`hosts` 同时列出新域名与（少量）旧引导地址，或直接换成新域名但**保留至少一个旧引导**用于在过渡期响应 `_nodes/http`（F4）。
   - 开启嗅探可加速收敛：`reload_connections: true`（=10000 次）或合适的整数阈值、
     `reload_on_failure: true`；对可用性要求高的调用方评估 F3——周期 reload 遇到 `_nodes/http`
     **快速硬错误**会令触发请求失败（只有超时被吞），因此要保证 `_nodes/http` 高可用，或在客户端外层保留重试。
   - 由于默认不嗅探，**“重启/重新部署所有客户端工作负载”是唯一不依赖嗅探的收敛保证**（含 Deployment、CronJob、批处理、本地脚本、CI）。
5. **触发收敛并自检**
   - 重启或等待 reload；可用本矩阵同款探针/日志确认：configured 含新名、discovered 全是新名、
     完整 RoundRobin 周期 selected 全是新 authority、代理 `env.request.proxy`/CONNECT 符合设计。
6. **按准入拆旧（见第 7 节）**，顺序：先从客户端配置删除旧 hosts 并发布 -> 观测零旧流量 ->
   再删 `no_proxy`/旧 DNS 记录 -> 最后下线旧监听器/旧发布地址/防火墙。

---

## 7. 什么时候可以拆旧配置：准入标准

矩阵第 7 节把可自动化的三条闸门跑成了示例：`M2 ALLOWED`，`M1`/`M3 BLOCKED`。
可自动化的必要条件（对应 `evaluate_gate`）：

- `no_old_discovered`：最近一次 `_nodes/http` 候选无任何旧 FQDN/旧 IP/畸形旧样式；
- `no_old_in_pool`：连接池 `all`（含 dead）无旧 host key；
- `sel_all_new` + `cycle_covered`：连续至少一个完整选择器周期，实际请求 authority 全新。

但单进程闸门只是必要非充分。**集群级准入**还需满足：

- 所有客户端工作负载（全部副本/版本/定时任务/脚本）都已重启到新配置，或确认嗅探已收敛到全新池；
- 证书新 SAN/链、DNS、代理/`NO_PROXY` 策略全部生效；
- 在一个足够长的 **soak 窗口**内，ES 访问日志与**代理 upstream 日志**中旧 authority / 旧 IP 计数为 0。
  窗口要覆盖：发布滚动时长 + `reload_after` 周期 + keep-alive 空闲时长 +
  死亡复活退避（`60 * 2**(failures-1)`）+ DNS TTL，并留安全余量；
- `_nodes/http` 容量/可用性已确认，避免拆除旧引导后发现面单点。

满足后按第 6 节顺序拆除。任何一条不满足（尤其代理日志仍有旧 authority），旧配置/DNS/监听器都应保留。

---

## 8. 复跑与产物说明

```sh
bash migration-matrix/run.sh                 # 用 .feedback 离线 bundle 跑矩阵并写驱动记录
# 或手动：
sh .feedback/bundle-env exec ruby migration-matrix/run_matrix.rb
```

- 退出码 0：所有“当前实现应有的行为”断言成立（负向用例也是用断言锁定真实行为，不等于迁移可拆旧）。
- `runs/latest.log`：完整人类可读驱动记录；`runs/latest.json`：18 用例的结构化台账
  （configured / discovered / pool 快照含 `object_id`/dead、每次调用的 target/proxy/tcp_peer/wire、checks、gate）。
- 矩阵不访问网络、不连真实 ES；唯一的“外部”依赖是 vendored Faraday/multi_json。
