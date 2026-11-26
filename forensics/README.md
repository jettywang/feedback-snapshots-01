# 跨服务 trace 传播取证（离线）

对象：OpenTelemetry Python 复合传播器 `CompositePropagator` 的真实 `extract` / `inject`。
场景：多段跨服务请求能按 trace ID 关联上，但采样来源与业务关联不一致。

## 一次性复跑

```sh
.venv/bin/python -m forensics.collect --out forensics/out
.venv/bin/python -m pytest -q -o addopts= forensics/tests/test_collect.py
forensics/reproduce.sh
```

- `forensics/out/evidence.json`：机器可读证据，sha256 可存档。
- `forensics/out/report.html`：自包含离线报告，无脚本、字体或网络资源。
- `forensics/reproduce.sh`：跑两次并逐字节比较。

## 实验设计

| Profile | 等价的 `OTEL_PROPAGATORS` | 阶段顺序 |
|---|---|---|
| A | `tracecontext,baggage,b3` | TraceContext → W3C Baggage → B3MultiFormat |
| B | `tracecontext,baggage,jaeger` | TraceContext → W3C Baggage → Jaeger |

两个 profile 共享前两阶段，第三阶段唯一不同。请求固定为端到端关联号
`e2e-jw175-0001` 的两个合成载体：

- `full`：`traceparent`、`tracestate`、`baggage`、`x-b3-*`、`uber-trace-id`、`uberctx-tenant` 全部存在。
- `partial`：保留 `traceparent` 与 `uber-trace-id`，删除 `tracestate`、`baggage`、`x-b3-sampled`、`uberctx-tenant`。

## 四类观察

每个 (profile, request, stage) 都落盘：

1. `inbound_carrier`：该阶段读取的 header。
2. `returned_context`：`span_id`、`is_remote`、`sampled`、`trace_flags`、`tracestate`、`baggage`。
3. `child_span`：用该上下文真实启动的 SDK `SERVER` span，含 `recording`、`exported`、`parent_span_id`。
4. `final_injected`：该 profile 从该上下文继续注入得到的全部 header。

另外记录 `context_diff`（相对上一阶段的变化）与 `comparisons[].stage_pairs`
（A/B 同阶段的差异），因此能分别区分 parent 改变、tracestate 不再适用、baggage 被改写、采样结论改变。

## 关键结论

- 首次差异固定在**阶段 3**：A 为 `B3MultiFormat`，B 为 `JaegerPropagator`。
  阶段 1/2 在两个 profile 中逐字段一致，分歧不可能来自入站 W3C 解析或 baggage 读取。
- `full`：trace ID 都是 `4bf92f3577b34da6a3ce929d0e0e4736`，但
  - parent A/B 分别为 `b3b3b3b3b3b3b3b3` / `0a0a0a0a0a0a0a0a`；
  - 阶段 2 的 `tracestate` 在阶段 3 被 B3/Jaeger 清空；
  - baggage 在 A 为 `tenant=blue`，在 B 被 `uberctx-tenant=green` 改写为 `tenant=green`。
- `partial`：trace ID 仍相同，但 A 因缺少 `x-b3-sampled` 把父上下文降为未采样，
  子 span `recording=false` 且不导出；B 的 `uber-trace-id` 带 `flags=1`，子 span 正常导出。
- 因此“trace ID 相同”仍可能需要两种排查结论：A 侧查 B3 采样字段缺失；
  B 侧查 Jaeger parent 与 `uberctx-*` 覆盖；两者不能共用“按 trace ID 已查全”的结论。

## 合成字段

trace ID `4bf92f3577b34da6a3ce929d0e0e4736`，入站 W3C span `00f067aa0ba902b7`，
B3 span `b3b3b3b3b3b3b3b3`，Jaeger span `0a0a0a0a0a0a0a0a`，
子 span `00c0ffee00c0ffee`，端到端关联号 `e2e-jw175-0001`。
所有值固定，无随机 ID、无时钟、无外部服务；两次运行 `evidence.json` 逐字节相同。
