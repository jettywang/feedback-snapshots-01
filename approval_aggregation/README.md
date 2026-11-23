# 审批单汇总报告（approval aggregation）

发布系统把若干模板的权限评审结果拼成一个审批单。本目录提供：

- `aggregate.py` — 汇总器：把各资源的原始评审事件合并成一份审批单报告
- `monitor.py` — 监控视图：从报告中提取三类重点关注资源
- `samples/` — 本地样例（输入、报告、监控输出）
- `test_aggregation.py` — 行为测试

## 资源状态

每条资源在汇总层有且仅有一个状态：

| status | 含义 | 可交接 |
| --- | --- | --- |
| `checked` | 已查：分析完成并有定论（`finding` 为 `none` 或 `present`） | 是 |
| `pending` | 待核实：证据未到、只完成解析、或分析无定论 | 否 |
| `out_of_scope` | 不在授权范围：资源不在审批单 `scope` 内 | 是（无需处理） |
| `parse_failed` | 解析失败，未进入分析 | 否 |
| `analysis_failed` | 分析阶段失败 | 否 |

## 输入格式（raw results）

```json
{
  "ticket_id": "APPR-...",
  "generated_at": "可选，缺省取当前时间",
  "scope": ["resource-id", ...],
  "events": [
    {
      "resource_id": "...", "sequence": 2, "observed_at": "ISO-8601",
      "stage": "parse|analysis", "outcome": "completed|failed|inconclusive",
      "findings": [...], "error": {...}, "source": "..."
    }
  ]
}
```

`sequence` 是来源侧对同一资源单调递增的证据序号，重试必须携带更大的序号。

## 新鲜度规则（旧结果不得覆盖新证据）

同一资源的多条事件按 `(sequence, observed_at)` 排序，**最新者生效，与到达顺序无关**。
被取代的事件不丢弃，记入该资源的 `superseded` 供审计与监控：

- `stale` — 序号/时间更旧（如迟到的首次尝试结果）
- `duplicate` — 序号相同且内容摘要一致（重复投递）
- `conflict` — 序号相同但内容不一致（需人工介入）

## 故障隔离

缺字段的畸形事件（如解析器损坏时的输出）进入报告级 `quarantined_events`，
只影响对应资源，其余确定项目照常出现在 `handoff.ready` 中可交接。

## 报告格式

见 `samples/report.json`。要点：

- `summary` — 各状态计数
- `handoff.ready` / `handoff.blocked` — 可交接清单与被阻塞项（含原因状态）
- `resources[].evidence` — 当前生效证据（序号、时间、来源）
- `resources[].superseded` — 被取代证据及原因
- `resources[].error` — 失败详情（解析器、报错信息）

## 监控三类资源

```sh
python monitor.py samples/report.json
```

- `parse_not_analyzed` — 解析没到分析（`status == parse_failed`）
- `confirmed_clean` — 分析已确认无发现（`checked` 且 `finding == none`，自动排除范围外资源）
- `duplicate_results` — 收到重复结果（`superseded` 含 `reason == duplicate`）

## 本地样例

```sh
python aggregate.py samples/raw_results.json -o samples/report.json
python monitor.py samples/report.json -o samples/monitoring.json
python -m pytest -q -o addopts= test_aggregation.py
```

样例覆盖：`res-parse-fail`（解析没到分析，另有一条畸形重试被隔离）、
`res-clean`（分析确认无发现）、`res-dup`（重试新证据 + 迟到旧结果 + 重复投递）、
`res-pending`（分析无定论）、`res-no-evidence`（证据未到）、`res-extra`（不在授权范围）。
