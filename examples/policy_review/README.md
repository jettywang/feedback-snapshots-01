# 策略收敛复查（只读试删）

权限复查时，先用本工具对候选删除规则做**只读试删**，看清“删掉会影响谁”，再决定是否提交实际改动。
工具不会修改策略文件；策略原文与 SHA-256 会随报告输出，作为回滚证据。

## 输入

- `rbac_with_deny_domains_model.conf`：含 `allow/deny` 双效果、域角色继承（`g = _, _, _`）
  以及一个可选请求参数 `scope` 的模型。
- `rbac_with_deny_domains_policy.csv`：策略快照（回滚证据原文）。
- `archived_requests.json`：归档 API 请求（同时包含 allow 与 deny 记录）和两个以上候选规则。

归档请求字段说明：

```json
{
  "request_id": "REQ-005",
  "rvals": ["carol", "domain1", "reports", "read"],
  "expected": "allow"
}
```

`rvals` 长度允许短于模型请求字段：缺失的可选参数会被规范化为空字符串 `""`，
仍然进入 matcher 参与对照，而不是被静默丢弃。`expected` 接受 `allow/deny`、`true/false`、`0/1` 等写法。

## 运行

```sh
python -m casbin.policy_review.cli \
  --model examples/policy_review/rbac_with_deny_domains_model.conf \
  --policy examples/policy_review/rbac_with_deny_domains_policy.csv \
  --input examples/policy_review/archived_requests.json
```

加 `--format json` 输出机器可读报告；加 `--evidence-dir <目录>` 会把未改动的策略快照副本、
SHA-256 校验文件和报告写入该目录，方便归档与回滚。

## 三种结论（保守原则）

- `blocked`（禁止删除）：试删后至少一条归档请求的决策翻转。
  deny 规则被删时，原本被压制的 allow 会让请求从 deny 变 allow，禁令优先语义被破坏，一律阻断。
- `not_verifiable`（无法核实）：归档请求的决策虽然都不变，但规则的有效覆盖内存在归档没有
  对应请求的具体场景（含被 deny 遮蔽、无法直接观测的 allow 匹配）。无覆盖区域单独列出，
  保守起见不建议删除。
- `removable`（可核实可删）：所有归档决策保持不变，且规则没有超出归档证据的有效覆盖；
  若规则主体没有任何角色授予可达（死规则），会以“可核实死覆盖”形式给出证据。

报告同时列出每条候选规则的：

- 试删前后的逐条决策变化与解释规则（`enforce_ex` 的 explain）；
- 域继承下从真实主体到规则主体的完整角色链；
- 已知请求效果与无覆盖区域的明确区分；
- 基线快照与归档记录不一致的请求（此时任何删除结论都不予出具）。

## 库 API

```python
from casbin.policy_review import PolicySnapshot, ArchivedRequest, CandidateRule, review_candidate

snapshot = PolicySnapshot("model.conf", "policy.csv")
requests = [ArchivedRequest.from_dict(raw, snapshot.request_tokens) for raw in archived_raw]
review = review_candidate(snapshot, CandidateRule("C1", "p", ("auditor", "domain1", "data2", "read", "*", "allow")), requests)
print(review.verdict, review.decision_changes, review.unobserved_probes)
```
