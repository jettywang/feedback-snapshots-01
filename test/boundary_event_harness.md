# 边界事件验收：证据、结论与仪表缺口

`test/boundary_event_harness.rb` 为 WebMock 托管的 HTTP adapter 提供一套
离线验收办法。旧回归只能回答“客户端最后是否报错”；本线束把一次请求拆成
四个可分别断言的边界事件，供安全审核使用：

| 事件 | 含义 | 记录者 |
| --- | --- | --- |
| `connection_intent` | 客户端计划建连（尚未触碰 adapter） | 线束自身，单独事件种类 |
| `boundary_invocation` | 客户端实际调用了 adapter 守护的连接边界 | 仅测试替身（`BoundaryDouble`） |
| `adjudication` | WebMock 对请求做出裁决（allow/deny） | 公开配置观察点（见下） |
| `completion_callback` | `WebMock.after_request` 回调触发 | 公开配置观察点 |

## 现有 adapter 公开配置能取得的证据

以 Net::HTTP adapter 为例（其余 adapter 相同，因为证据点都在
adapter 中立的 WebMock 层）：

- `WebMock.after_request`（`CallbackRegistry`）：完成回调。回调触发是
  “裁决放行”的第一个公开信号，因此 `adjudication: allowed` 也在这里记录。
- `WebMock::NetConnectNotAllowedError`：裁决拒绝的公开信号（无匹配 stub
  且未放行真实连接）。
- `stub_request` / `WebMock.allow_net_connect!` / `disable_net_connect!`：
  裁决的策略输入，不是裁决记录。
- `WebMock::RequestRegistry`（`assert_requested` 的数据源）：net_http
  adapter 在裁决**之前**就计数，因此被拒请求也会被记为“已执行”
  （见 `test_request_registry_counts_denied_attempts...`）。它只能证明
  “到达过 adapter 边界”，不能当作完成证据。
- 连接边界本身（Net::HTTP 为 `Net::HTTP#request`）：WebMock 不提供钩子，
  只能由测试替身在实例上 prepend 记录；替身只观察、不改行为、不开 socket。

## 三个场景的记录形态

| 记录 | 事件序列 | 上层观察（`Outcome`） |
| --- | --- | --- |
| `allowed-stub` | intent → invocation → adjudication(allowed) → completion | `completed=true, "200"` |
| `client-cancel` | intent（仅此一条） | `completed=false, nil` |
| `rule-denied` | intent → invocation → adjudication(denied) | `completed=false, nil` |

`client-cancel` 与 `rule-denied` 的上层观察**完全相同**（旧回归无法区分），
只有边界事件能区分：取消场景没有 `boundary_invocation`，说明 WebMock 从未
被触及；拒绝场景有 `boundary_invocation` + `adjudication(denied)`。

记录为纯数据（`EventLog#to_json` / `.from_json`），可离线重放并重新推导
结论（`EventLog#verdicts`）。替身注册窗口之外（注册前/注销后、记录关闭后）
的调用一律进入 `quarantine`，不会混进任何请求记录。

## 能下的结论

- 客户端是否真正到达 adapter 边界（`boundary_invocation` 是否存在）。
- 裁决结果（allowed/denied）及其公开观察来源。
- 完成回调是否触发、回调携带的签名与状态。
- “客户端在构造前取消”与“被规则拒绝”可可靠区分。

## 需补仪表的结论（公开配置不够）

- 裁决的**精确发生时点**与内部顺序：`allowed` 是从回调反推的，adapter
  内部的决策点本身不可观测；升级实现应显式暴露决策钩子。
- 拒绝命中的是**哪条规则**（无 stub vs 禁真实连接）：目前只有异常消息
  字符串，无结构化原因。
- 放行真实连接时**是否会真的开 socket**：本验收全程离线，不覆盖该路径。
- 时延、重试、重定向等 adapter 内部子调用：公开回调不暴露。
- 客户端侧取消：WebMock 完全看不到，只能靠线束的 intent 日志；若取消
  发生在客户端内部更深处，需客户端自行埋点。

## 升级后的两种 adapter 如何复用

1. 为新实现写一个 probe，满足四个方法的契约（`boundary_label`、
   `build_connection`、`attach_double`、`perform`），参考 `NetHttpProbe`。
2. `BoundaryEventHarness.register_probe(:new_adapter, probe)`。
3. 用 `BoundaryEventHarness.run_suite(:new_adapter)` 跑同一套三场景，
   断言与 `minitest/boundary_events_test.rb` 完全相同的记录形态。

事件语义、`Outcome`、隔离（quarantine）与重放能力都与 adapter 无关，
因此新旧实现的验收结论可直接对比。
