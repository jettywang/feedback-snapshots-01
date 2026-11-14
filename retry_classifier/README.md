# GOAWAY 重试分类器原型

基于 h2 实际事件（而非超时猜测）决定连接断开后每个流的去向。
分类（协议能证明什么）与重试策略（应用给的幂等依据）严格分离。

## 运行

```bash
.venv/bin/python -m pytest retry_classifier/ -q   # 可重跑场景（含反例）
.venv/bin/python -m retry_classifier.demo          # 副作用 vs 分类对照表
```

## 分类（Category）——只表达协议事实

| 分类 | 判定依据（h2 事件） | 含义 |
|---|---|---|
| `COMPLETED` | `StreamEnded`（响应完整） | 已完成，交付应用 |
| `NOT_SENT` | 请求字节未刷到传输层连接即断 | 对端不可能见过 |
| `NOT_PROCESSED` | `stream_id > min(GOAWAY last_stream_id)` | RFC 7540 §6.8 保证未处理 |
| `REFUSED` | `StreamReset(error=REFUSED_STREAM)` | 对端显式声明未执行任何处理 |
| `MAYBE_PROCESSED` | `stream_id <= last_stream_id`，或无 GOAWAY 断连，或非 REFUSED 的 RST | 可能已执行，协议无法证明 |
| `PARTIAL_RESPONSE` | 收到响应头但无 `StreamEnded` | 已处理、结果未送达 |

关键规则：

- **多个 GOAWAY 取 `last_stream_id` 最小值**。RFC 允许对端追加 GOAWAY
  调低边界；即使对端违规调高，取最小也是最保守解释。
- **`REFUSED_STREAM` 与其它 RST 码严格区分**。`CANCEL`/`INTERNAL_ERROR`
  只表示流被中止，服务器可能已执行写操作，一律归入 `MAYBE_PROCESSED`。
- **"没收到响应"永远不等于"没处理"**。`MAYBE_PROCESSED` 是断连后的
  默认归属，不是可重放信号。

## 重试动作（Action）= 分类 + 应用幂等依据

幂等依据由应用显式声明（`IdempotencyHint`），不从"没响应"推断：

| 分类 | SAFE_METHOD（GET/PUT/DELETE…） | IDEMPOTENCY_KEY | NONE（裸 POST） |
|---|---|---|---|
| `COMPLETED` | 交付 | 交付 | 交付 |
| `NOT_SENT` / `NOT_PROCESSED` / `REFUSED` | 重放 | 重放 | 重放 |
| `MAYBE_PROCESSED` / `PARTIAL_RESPONSE` | 重放 | 重放（服务端按键去重） | **业务决策** |

## 调用建议

1. **不要把所有未完成流放回队列**。反例
   `test_counterexample_post_processed_then_goaway_no_response` 演示了
   朴素重放让同一笔写执行两次。只有 `NOT_SENT`/`NOT_PROCESSED`/`REFUSED`
   三类可无条件自动重放。
2. **裸 POST 进入 `ASK_APPLICATION` 后**，由业务选择：查后补（先 GET
   确认状态再决定）、人工处理、或放弃。传输层无权替业务做这个决定。
3. **写操作尽量带幂等键**（如 `Idempotency-Key` 头）。有了键，
   `MAYBE_PROCESSED` 即可自动重放，把"业务决策"前移为"服务端去重"。
4. **重放必须换新连接**（GOAWAY 后旧连接不可再开流），且使用原流
   的完整请求数据——分类器只给结论，不重造请求。
5. **收到 GOAWAY 不等于连接已死**：边界内的流仍可能正常完成，应继续
   等响应直到连接真正关闭，再对剩余流做分类。
6. `PARTIAL_RESPONSE` 即使对 GET 也建议重放而非截断交付：响应完整性
   无法验证。

## 原型边界

- 仿真用内存导线（`harness.py`），断连由 `Sim.cut()` 显式触发；
  接入真实事件循环时，把 `ClientEndpoint.receive` 里的事件转发逻辑
  搬到你的 I/O 回调即可，分类器本身与传输无关。
- 未覆盖：流控窗口中途耗尽、GOAWAY 的 debug_data、优先级信号；
  这些不改变分类语义。
