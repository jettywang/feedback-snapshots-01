# Net::FTP 迁移连接计划（全记录型替身）

复跑命令：

```sh
ruby audit/run.rb
```

本命令离线运行，不做 DNS、不发起真实连接、不绑定真实端口；`Socket.tcp`、`Addrinfo.tcp` 和 `SOCKSSocket.open` 均由记录型替身接管。原始事件见 `audit/out/records.json` 与 `audit/out/{connect,listen,accept,control_reply}.jsonl`。

## 代码调用依据

- 控制连接：`lib/net/ftp.rb:406` 调 `open_socket(host, port)`；分支在 `lib/net/ftp.rb:367`：有 `SOCKSSocket` 且 `SOCKS_SERVER` 非空时走 SOCKS，否则 `Socket.tcp`。
- 地址族和 PASV/EPSV 选择：`lib/net/ftp.rb:542` 与 `lib/net/ftp.rb:562` 都读取 `@bare_sock.remote_address`。
- 主动模式：`lib/net/ftp.rb:556` 用 `@bare_sock.local_address.ip_address` 和端口 `0` 监听；`lib/net/ftp.rb:598` 把该监听地址/端口写入 `PORT` 或 `EPRT`。
- 主动模式顺序：`lib/net/ftp.rb:595` 监听，`lib/net/ftp.rb:598` 发 PORT/EPRT，`lib/net/ftp.rb:605` 起等待 `1XX`，之后才在 `lib/net/ftp.rb:611` 调 `accept`。因此只有 `150/125` 不能证明数据连接建成。
- 被动模式：IPv4 控制对端发 `PASV` 并解析 227；IPv6 控制对端发 `EPSV` 并解析 229。默认 `use_pasv_ip: false` 时，227 里的主机地址被忽略，改用控制套接字的 `remote_address.ip_address`；229 本来只有端口，主机也永远取控制对端。
- 两级代理不是本版本 `Net::FTP` 的内建配置；它只识别一个旧式 `SOCKS_SERVER/SOCKSSocket` 钩子。两级链路必须由外部 SOCKS/CONNECT 链式服务、透明代理或定制套接字提供。

## 迁移前后离线对照

| 项目 | 迁移前 | 迁移后 | 影响 |
|---|---:|---:|---|
| `Net::FTP passive` | `false` | `true` | 迁移后使用出站 PASV/EPSV，避免在客户端开放主动回连监听。 |
| `use_pasv_ip` | `false` | `true` | true 时采用 227 明示主机；false 时用 @bare_sock.remote_address 推导。 |
| `SOCKS_SERVER` | `（未设置）` | `edge-proxy.audit.example:1080` | 这是本版 Net::FTP 唯一识别的代理钩子；两级链本身在代码之外。 |
| `proxy_chain_length` | `0` | `2` | Net::FTP 没有两级代理客户端配置项。 |
| `client_ingress_rules` | `2` | `0` | 改为被动后，客户端侧 FTP 回连入站规则降为 0。 |
| `client_egress_rules` | `client_ipv4 -> ftp_ipv4:21/tcp, client_ipv6 -> ftp_ipv6:21/tcp` | `client_ipv4 -> edge_proxy_ipv4:1080/tcp, client_ipv6 -> edge_proxy_ipv6:1080/tcp` | 分段后，客户端主机只需放行到第一级代理的出站。 |

同一客户端身份保持不变：`client_id=archive-agent-01`，`archive_job=nightly-bundle-to-object-store`，`ftp_host=ftp.archive.example`，`credentials_ref=vault://archive/ftp`。

## 场景核对

| 场景 | 模式/族 | 结论 | 必须开放的通路（记录中的具体元组） |
|---|---|---|---|
| `ipv4_active_complete` | active/ipv4 | **替身验证通过** (`verified_in_recording_double`) — 记录型替身中的连接、地址选择、命令/回复和数据套接字返回均一致；真实防火墙可达性仍需预发证据。 | `192.0.2.10 -> 198.51.100.20:21/tcp`（client-egress）<br>`198.51.100.20:20/tcp -> 192.0.2.10:50001/tcp`（client-ingress） |
| `ipv6_active_complete` | active/ipv6 | **替身验证通过** (`verified_in_recording_double`) — 记录型替身中的连接、地址选择、命令/回复和数据套接字返回均一致；真实防火墙可达性仍需预发证据。 | `2001:db8:10::10 -> 2001:db8:90::20:21/tcp`（client-egress）<br>`2001:db8:90::20:20/tcp -> 2001:db8:10::10:50001/tcp`（client-ingress） |
| `ipv4_passive_default_peer_complete` | passive/ipv4 | **替身验证通过** (`verified_in_recording_double`) — 记录型替身中的连接、地址选择、命令/回复和数据套接字返回均一致；真实防火墙可达性仍需预发证据。 | `192.0.2.10 -> 198.51.100.20:21/tcp`（client-egress）<br>`192.0.2.10 -> 198.51.100.20:50021/tcp`（client-egress） |
| `ipv4_passive_declared_complete` | passive/ipv4 | **替身验证通过** (`verified_in_recording_double`) — 记录型替身中的连接、地址选择、命令/回复和数据套接字返回均一致；真实防火墙可达性仍需预发证据。 | `192.0.2.10 -> 198.51.100.20:21/tcp`（client-egress）<br>`192.0.2.10 -> 198.51.100.22:50021/tcp`（client-egress） |
| `ipv6_passive_complete` | passive/ipv6 | **替身验证通过** (`verified_in_recording_double`) — 记录型替身中的连接、地址选择、命令/回复和数据套接字返回均一致；真实防火墙可达性仍需预发证据。 | `2001:db8:10::10 -> 2001:db8:90::20:21/tcp`（client-egress）<br>`2001:db8:10::10 -> 2001:db8:90::20:50021/tcp`（client-egress） |
| `active_ipv4_preliminary_only` | active/ipv4 | **证据不足** (`inconclusive`) — 已收到 1XX 预备控制回复，但没有 accept 返回或被动数据 connect 返回；不能判定数据连接建成。 | `192.0.2.10 -> 198.51.100.20:21/tcp`（client-egress）<br>`198.51.100.20:20/tcp -> 192.0.2.10:50001/tcp`（client-ingress） |
| `proxy2_v4_passive_declared_chain` | passive/ipv4 | **有条件可承诺** (`conditional`) — 记录型替身中的调用顺序和地址选择一致；生产仍取决于两级代理策略、代理协议和 remote_address 语义。 | `192.0.2.10 -> 192.0.2.100:1080/tcp`（client-egress）<br>`192.0.2.100:1080 -> 203.0.113.100:1080/tcp`（proxy-internal）<br>`inner-proxy -> 198.51.100.22:50021/tcp`（proxy-final-egress） |
| `proxy2_v6_passive_preserved_peer_chain` | passive/ipv6 | **有条件可承诺** (`conditional`) — 记录型替身中的调用顺序和地址选择一致；生产仍取决于两级代理策略、代理协议和 remote_address 语义。 | `2001:db8:10::10 -> 2001:db8:10::fe:1080/tcp`（client-egress）<br>`2001:db8:10::fe:1080 -> 2001:db8:99::fe:1080/tcp`（proxy-internal）<br>`inner-proxy -> 2001:db8:90::20:50021/tcp`（proxy-final-egress） |
| `proxy2_v6_passive_actual_peer_mismatch` | passive/ipv6 | **不能承诺** (`not_committable`) — TCPSocket 式 SOCKS 套接字的 remote_address 是第一级代理；EPSV 又不带主机，导致 Net::FTP 把数据目标选成代理地址而非 FTP 主机。 | `2001:db8:10::10 -> 2001:db8:10::fe:1080/tcp`（client-egress）<br>`2001:db8:10::fe:1080 -> 2001:db8:99::fe:1080/tcp`（proxy-internal）<br>`inner-proxy -> 2001:db8:10::fe:50021/tcp`（proxy-final-egress） |
| `proxy2_active_not_committable` | active/ipv4 | **不能承诺** (`not_committable`) — Net::FTP 仅完成本地 listen 与 PORT/EPRT，没有调用 SOCKS BIND 或任何反向代理接口；真实回连通路无法承诺。 | `192.0.2.10 -> 192.0.2.100:1080/tcp`（client-egress）<br>`192.0.2.100:1080 -> 203.0.113.100:1080/tcp`（proxy-internal）<br>`FTP data peer -> active listener -> client/proxy chain`（proxy-callback） |

## 地址逐项对账

| 场景 | 服务器明示 | 控制连接推导 | 主动通告 | 实际数据目标 | 对账 |
|---|---|---|---|---|---|
| `ipv4_active_complete` | — | `198.51.100.20:21` | `192.0.2.10:50001` | — | 全部对得上 |
| `ipv6_active_complete` | — | `2001:db8:90::20:21` | `2001:db8:10::10:50001` | — | 全部对得上 |
| `ipv4_passive_default_peer_complete` | `198.51.100.22:50021` | `198.51.100.20:21` | — | `198.51.100.20:50021` | 全部对得上 |
| `ipv4_passive_declared_complete` | `198.51.100.22:50021` | `198.51.100.20:21` | — | `198.51.100.22:50021` | 全部对得上 |
| `ipv6_passive_complete` | 仅端口 `50021`（EPSV） | `2001:db8:90::20:21` | — | `2001:db8:90::20:50021` | 全部对得上 |
| `active_ipv4_preliminary_only` | — | `198.51.100.20:21` | `192.0.2.10:50001` | — | 全部对得上 |
| `proxy2_v4_passive_declared_chain` | `198.51.100.22:50021` | `192.0.2.100:1080` | — | `198.51.100.22:50021` | 全部对得上 |
| `proxy2_v6_passive_preserved_peer_chain` | 仅端口 `50021`（EPSV） | `2001:db8:90::20:21` | — | `2001:db8:90::20:50021` | 全部对得上 |
| `proxy2_v6_passive_actual_peer_mismatch` | 仅端口 `50021`（EPSV） | `2001:db8:10::fe:1080` | — | `2001:db8:10::fe:50021` | 调用自洽；1 项通路不能承诺 |
| `proxy2_active_not_committable` | — | `192.0.2.100:1080` | `192.0.2.10:50001` | — | 调用自洽；1 项通路不能承诺 |

### `ipv4_active_complete`

- 控制连接本地地址：`192.0.2.10:51000`
- 实际控制对端/控制推导地址：`198.51.100.20:21`
- 服务器明示地址：`（无）`
- 主动通告地址：`192.0.2.10:50001`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=198.51.100.20
  - [x] `active_listen_recorded` — listen={"ip_address" => "192.0.2.10", "ip_port" => 50001, "note" => "recording-listener"}
  - [x] `active_advertised_command_recorded` — advertised={protocol: "PORT", eprt_family: nil, ip_address: "192.0.2.10", port: 50001}
  - [x] `advertised_address_matches_listener` — PORT/EPRT 192.0.2.10:50001 vs listen 192.0.2.10:50001
  - [x] `listener_uses_control_local_address_family` — Addrinfo.tcp(192.0.2.10,0) vs bare_sock.local_address=192.0.2.10
  - [x] `accept_recorded` — accept={"ip_address" => "198.51.100.20", "ip_port" => 20, "note" => "reference active source port"}
  - [x] `preliminary_reply_precedes_accept` — 1XX seq=14, accept seq=15

### `ipv6_active_complete`

- 控制连接本地地址：`2001:db8:10::10:51000`
- 实际控制对端/控制推导地址：`2001:db8:90::20:21`
- 服务器明示地址：`（无）`
- 主动通告地址：`2001:db8:10::10:50001`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=2001:db8:90::20
  - [x] `active_listen_recorded` — listen={"ip_address" => "2001:db8:10::10", "ip_port" => 50001, "note" => "recording-listener"}
  - [x] `active_advertised_command_recorded` — advertised={protocol: "EPRT", eprt_family: 2, ip_address: "2001:db8:10::10", port: 50001}
  - [x] `advertised_address_matches_listener` — PORT/EPRT 2001:db8:10::10:50001 vs listen 2001:db8:10::10:50001
  - [x] `listener_uses_control_local_address_family` — Addrinfo.tcp(2001:db8:10::10,0) vs bare_sock.local_address=2001:db8:10::10
  - [x] `accept_recorded` — accept={"ip_address" => "2001:db8:90::20", "ip_port" => 20, "note" => "reference active source port"}
  - [x] `preliminary_reply_precedes_accept` — 1XX seq=35, accept seq=36

### `ipv4_passive_default_peer_complete`

- 控制连接本地地址：`192.0.2.10:51000`
- 实际控制对端/控制推导地址：`198.51.100.20:21`
- 服务器明示地址：`198.51.100.22:50021`
- 主动通告地址：`（无）`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=198.51.100.20
  - [x] `server_declared_227/pasv_recorded` — declared={protocol: "PASV/227", host: "198.51.100.22", port: 50021, raw: "227 Entering Passive Mode (198,51,100,22,195,101)."}
  - [x] `passive_data_connect_recorded` — data connect={requested_host: "198.51.100.20", requested_port: 50021}
  - [x] `passive_port_matches_reply` — connect port 50021 vs reply port 50021
  - [x] `passive_host_matches_net_ftp_selection` — connect host 198.51.100.20 vs selected 198.51.100.20

### `ipv4_passive_declared_complete`

- 控制连接本地地址：`192.0.2.10:51000`
- 实际控制对端/控制推导地址：`198.51.100.20:21`
- 服务器明示地址：`198.51.100.22:50021`
- 主动通告地址：`（无）`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=198.51.100.20
  - [x] `server_declared_227/pasv_recorded` — declared={protocol: "PASV/227", host: "198.51.100.22", port: 50021, raw: "227 Entering Passive Mode (198,51,100,22,195,101)."}
  - [x] `passive_data_connect_recorded` — data connect={requested_host: "198.51.100.22", requested_port: 50021}
  - [x] `passive_port_matches_reply` — connect port 50021 vs reply port 50021
  - [x] `passive_host_matches_net_ftp_selection` — connect host 198.51.100.22 vs selected 198.51.100.22

### `ipv6_passive_complete`

- 控制连接本地地址：`2001:db8:10::10:51000`
- 实际控制对端/控制推导地址：`2001:db8:90::20:21`
- 服务器明示地址：`{protocol: "EPSV/229", host: nil, port: 50021, raw: "229 Entering Extended Passive Mode (|||50021|)."}`
- 主动通告地址：`（无）`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=2001:db8:90::20
  - [x] `server_declared_229/epsv_recorded` — declared={protocol: "EPSV/229", host: nil, port: 50021, raw: "229 Entering Extended Passive Mode (|||50021|)."}
  - [x] `passive_data_connect_recorded` — data connect={requested_host: "2001:db8:90::20", requested_port: 50021}
  - [x] `passive_port_matches_reply` — connect port 50021 vs reply port 50021
  - [x] `passive_host_matches_net_ftp_selection` — connect host 2001:db8:90::20 vs selected 2001:db8:90::20

### `active_ipv4_preliminary_only`

- 控制连接本地地址：`192.0.2.10:51000`
- 实际控制对端/控制推导地址：`198.51.100.20:21`
- 服务器明示地址：`（无）`
- 主动通告地址：`192.0.2.10:50001`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=198.51.100.20
  - [x] `active_listen_recorded` — listen={"ip_address" => "192.0.2.10", "ip_port" => 50001, "note" => "recording-listener"}
  - [x] `active_advertised_command_recorded` — advertised={protocol: "PORT", eprt_family: nil, ip_address: "192.0.2.10", port: 50001}
  - [x] `advertised_address_matches_listener` — PORT/EPRT 192.0.2.10:50001 vs listen 192.0.2.10:50001
  - [x] `listener_uses_control_local_address_family` — Addrinfo.tcp(192.0.2.10,0) vs bare_sock.local_address=192.0.2.10
  - [x] `preliminary_reply_recorded` — 150 File status okay; about to open data connection.
  - [x] `no_accept_for_preliminary_only_stop` — accept event count=0
  - [x] `data_establishment_not_proven` — 1XX alone is not evidence; no accept return or data connect return

### `proxy2_v4_passive_declared_chain`

- 控制连接本地地址：`192.0.2.10:51006`
- 实际控制对端/控制推导地址：`192.0.2.100:1080`
- 服务器明示地址：`198.51.100.22:50021`
- 主动通告地址：`（无）`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=192.0.2.100
  - [x] `server_declared_227/pasv_recorded` — declared={protocol: "PASV/227", host: "198.51.100.22", port: 50021, raw: "227 Entering Passive Mode (198,51,100,22,195,101)."}
  - [x] `passive_data_connect_recorded` — data connect={requested_host: "198.51.100.22", requested_port: 50021}
  - [x] `passive_port_matches_reply` — connect port 50021 vs reply port 50021
  - [x] `passive_host_matches_net_ftp_selection` — connect host 198.51.100.22 vs selected 198.51.100.22

### `proxy2_v6_passive_preserved_peer_chain`

- 控制连接本地地址：`2001:db8:10::10:51007`
- 实际控制对端/控制推导地址：`2001:db8:90::20:21`
- 服务器明示地址：`{protocol: "EPSV/229", host: nil, port: 50021, raw: "229 Entering Extended Passive Mode (|||50021|)."}`
- 主动通告地址：`（无）`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=2001:db8:90::20
  - [x] `server_declared_229/epsv_recorded` — declared={protocol: "EPSV/229", host: nil, port: 50021, raw: "229 Entering Extended Passive Mode (|||50021|)."}
  - [x] `passive_data_connect_recorded` — data connect={requested_host: "2001:db8:90::20", requested_port: 50021}
  - [x] `passive_port_matches_reply` — connect port 50021 vs reply port 50021
  - [x] `passive_host_matches_net_ftp_selection` — connect host 2001:db8:90::20 vs selected 2001:db8:90::20

### `proxy2_v6_passive_actual_peer_mismatch`

- 控制连接本地地址：`2001:db8:10::10:51008`
- 实际控制对端/控制推导地址：`2001:db8:10::fe:1080`
- 服务器明示地址：`{protocol: "EPSV/229", host: nil, port: 50021, raw: "229 Entering Extended Passive Mode (|||50021|)."}`
- 主动通告地址：`（无）`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=2001:db8:10::fe
  - [x] `server_declared_229/epsv_recorded` — declared={protocol: "EPSV/229", host: nil, port: 50021, raw: "229 Entering Extended Passive Mode (|||50021|)."}
  - [x] `passive_data_connect_recorded` — data connect={requested_host: "2001:db8:10::fe", requested_port: 50021}
  - [x] `passive_port_matches_reply` — connect port 50021 vs reply port 50021
  - [x] `passive_host_matches_net_ftp_selection` — connect host 2001:db8:10::fe vs selected 2001:db8:10::fe
  - [!] `derived_proxy_address_is_not_the_ftp_data_endpoint` — Net::FTP selected 2001:db8:10::fe; FTP-side endpoint is 2001:db8:90::20

### `proxy2_active_not_committable`

- 控制连接本地地址：`192.0.2.10:51009`
- 实际控制对端/控制推导地址：`192.0.2.100:1080`
- 服务器明示地址：`（无）`
- 主动通告地址：`192.0.2.10:50001`
- 检查项：
  - [x] `control_connect_recorded` — one connect event with role=control
  - [x] `control_peer_available_to_net_ftp` — @bare_sock.remote_address.ip_address=192.0.2.100
  - [x] `socks_hook_forces_passive_during_connect` — passive option=false, passive immediately after connect=true; audit then explicitly re-enables active for that scenario
  - [x] `active_listen_recorded` — listen={"ip_address" => "192.0.2.10", "ip_port" => 50001, "note" => "recording-listener"}
  - [x] `active_advertised_command_recorded` — advertised={protocol: "PORT", eprt_family: nil, ip_address: "192.0.2.10", port: 50001}
  - [x] `advertised_address_matches_listener` — PORT/EPRT 192.0.2.10:50001 vs listen 192.0.2.10:50001
  - [x] `listener_uses_control_local_address_family` — Addrinfo.tcp(192.0.2.10,0) vs bare_sock.local_address=192.0.2.10
  - [x] `accept_recorded` — accept={"ip_address" => "198.51.100.20", "ip_port" => 20}
  - [x] `preliminary_reply_precedes_accept` — 1XX seq=183, accept seq=184
  - [!] `reverse_proxy_bind_or_callback_operation_observed` — Net::FTP calls only local listen/PORT/EPRT; recording ledger has no proxy BIND API call


## 预备回复后停止的主动模式

`active_ipv4_preliminary_only` 场景真实调用了 `makeport`、`sendport` 和发送 `RETR` 的 `sendcmd`，在收到 `150` 后、调用 `listener.accept` 前停止。

- 有 `connect`、`listen`、PORT 命令、200 和 150 回复记录。
- `audit/out/accept.jsonl` 中没有该场景的 `accept` 记录。
- 判定只能是“预备回复已收到，数据连接未证明建成”；不能把 150 当作防火墙回连已通的证据。
- 完整主动场景必须额外出现 `accept` 返回和对端地址；被动场景必须额外出现数据 `connect` 成功返回，随后最好有一次 EOF/字节传输证据。
- 记录中的服务端源端口 `20` 只是传统 FTP-DATA 参考值；`Net::FTP` 不绑定或校验服务端源端口，真实规则应以 `accept` 对端记录和服务端部署为准。

## 仍不能承诺的通路

- 替身只证明 `Net::FTP` 的调用顺序和地址选择自洽，不证明真实防火墙、代理协商或路由可达。
- 主动模式真实代码绑定端口 `0`，生产端口是临时端口；报告中的 `50001` 只是确定性替身端口。没有固定端口范围、FTP ALG 或端口映射时，无法提前承诺单条入站规则。
- `Net::FTP` 总是把 `@bare_sock.local_address.ip_address` 写进 PORT/EPRT，没有“对外通告地址”选项。NAT/代理后的私网地址或代理内网地址不能靠客户端配置自动改成外部回连地址。
- 两级代理的 P1→P2、P2→FTP/数据端口两段不在 `Net::FTP` 记录内，必须由代理配置和代理侧防火墙负责。
- 普通正向 SOCKS/HTTP CONNECT 链不提供主动模式所需的反向 BIND/回连；`proxy2_active_not_committable` 中即使替身 `accept` 能返回，也不代表真实代理会把 FTP 服务端回连送达客户端监听器。
- 代理套接字的 `remote_address` 语义必须在预发用真实运行时核对：是第一级代理地址（TCPSocket 式实际对端），还是保留/转换后的 FTP 目标地址。两种替身分别给出了 `proxy2_v4_passive_declared_chain`、`proxy2_v6_passive_preserved_peer_chain` 与 `proxy2_v6_passive_actual_peer_mismatch` 的差异。
- FTPS 会保留同样的 TCP 源/目的端口需求，但加密控制连接使传统 FTP ALG 无法读取或改写 PASV/PORT；TLS 证书、主机名校验和 `PROT P` 需另行验证。
