# 审计读取策略跨分区条件不一致：离线排查包

背景：一份审计读取策略换到另一个分区后，审批工具显示部分语句的资源条件与旧环境不一致。
本目录用 Policy Sentry 真实的匹配与渲染入口做离线分层复现，把“资料缺失、资源匹配失败、
模板输入差异”三类原因区分开。所有资源值均为虚构项目 `fict-proj-audit`，全程不访问网络。

## 最小复跑（给运营）

```sh
# 在仓库根目录，一键重跑全部 5 个对照运行并重新生成报告
.venv/bin/python offline-triage/run_experiments.py
```

产物（全部在 `offline-triage/runs/`）：

- `report.md` — 运行矩阵、首处分歧层、关键判定、逐层 diff、定位建议
- `<运行名>.json` — 每次运行的分层原始记录（layer0–layer4）
- `home-*/.policy_sentry/iam-definition.json` — 各运行实际使用的目录快照
- `template-*.yml` — 由基准模板派生的单变量变体

单次手动复跑某一层级链路（换自己的模板或快照时）：

```sh
HOME=<含 .policy_sentry/iam-definition.json 的目录> \
    .venv/bin/python offline-triage/trace_run.py <模板.yml> <输出.json> <运行名>
```

注意：Policy Sentry 在**导入期**按 `$HOME/.policy_sentry/iam-definition.json` 是否存在来选择
目录快照（见 `policy_sentry/shared/constants.py` 的 `DATASTORE_FILE_PATH`），
所以换快照必须换 `HOME` 并另起进程，不能在同一进程内热替换。

## 分层约定与首处分歧

| 层 | 内容 | 使用的 Policy Sentry 入口 |
| --- | --- | --- |
| layer0 | 实际加载的快照路径与 sha256 | `shared/constants.py`、`shared/iam_data.py` |
| layer1 | 模板原文与 ARN 解析 | `util/arns.py: parse_arn` |
| layer2 | ARN → 候选资源类型 | `querying/arns.py: get_matching_raw_arns` |
| layer3 | 动作清单与条件键能力 | `querying/actions.py`、`querying/conditions.py` |
| layer4 | 最终渲染策略与内部 Sid | `writing/sid_group.py: SidGroup.process_template` |

定位决策表（与基准运行的**首处分歧层**对照）：

| 首处分歧 | 伴随现象 | 结论 | 补哪份资料复核 |
| --- | --- | --- | --- |
| layer1，layer2 候选非空、layer3 一致 | 渲染策略仅 Resource 字符串不同 | 模板输入差异（如只换分区；匹配器不比分区段） | 审批工具实际收到的模板原文、其自身分区处理逻辑 |
| layer1 或 layer2，且 layer2 候选为空 | 最终策略少一整条 Sid（ARN 被静默跳过） | 资源匹配失败 | ARN 资源段写法；写法无误则查快照是否含该服务/资源类型 |
| layer3，服务级 conditions 表仍有该键 | 动作与 Sid 不变，仅资源/动作级条件能力缩水 | 资料缺失（快照资源/动作表陈旧） | 该服务的资源/动作段数据（重新生成 iam-definition.json） |
| layer3，服务级 conditions 表也没有该键 | 同上，且 `get_condition_keys_for_service` 查不到 | 资料缺失（目录本身不含该条件） | 更新的整包 iam-definition.json |

关键事实：Policy Sentry 渲染出的策略**不含 Condition 块**（`sid_group.py` 中 conditions
恒为空列表，标有 TODO）。因此条件类分歧在最终文件层面不可见——若两个不同变动在审批工具的
最终文件里都表现为同一条件缺失，只能靠 layer3 的中间记录区分首处分歧。

## 本次实验结论（详见 runs/report.md）

- B（只换分区）：匹配与条件能力与基准逐项一致 → 分区变量被排除，分歧只能来自模板输入或审批工具侧。
- C（换目录快照，资源/动作条目缺 `kms:KeySpec`）与 D（对照目录，彻底不含该键）：
  两者渲染策略与基准逐字节一致（最终文件层面同一“条件缺失”），但 layer3 记录显示
  该键在服务级 conditions 表中一去一留 → 据此区分“补资源/动作段数据”还是“换整包快照”。
- E（模板资源段笔误）：layer2 候选为空，`KmsReadKey` Sid 整体消失 → 资源匹配失败的签名。
