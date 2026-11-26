# 离线 IAM 有效权限审计（Policy Sentry 支撑）

在**不调用 AWS** 的前提下，对一个虚构角色 `ci-artifact-deployer` 的
内联策略、附加托管策略和权限边界快照做合并分析，按
**动作 × 资源 × 条件组合**逐项给出可解释的结论，并区分「已确定」与「待补件」。

Policy Sentry 在本工具中只承担离线事实查询：动作是否存在、动作支持的资源
ARN 形态、条件键是否被该服务识别（数据源
`policy_sentry/shared/data/iam-definition.json`，452 个服务）。策略合并、
ARN/条件求值和有效权限判定由本目录的 `auditlab/engine.py` 实现。

## 判定语义

有效权限要求**身份侧（内联+附加）允许**与**权限边界允许**两边都有充分证据，
且涉及的每个条件都能离线评价。结论共五态：

| 结论 | 是否确定 | 含义 |
| --- | --- | --- |
| `DENY_EXPLICIT` | 确定 | 显式 Deny 命中（条件可评价且满足），优先级最高 |
| `ALLOW_EFFECTIVE` | 确定 | 身份侧与边界侧都结构性允许，且全部条件已评价通过 |
| `PENDING_CONDITION` | 待补件 | 结构匹配，但某条件缺请求/资源取值或无法离线评价 |
| `PENDING_MISSING_DATA` | 待补件 | 缺输入（如某附加策略未取回、无边界快照），无法证明允许 |
| `IMPLICIT_DENY` | 确定 | 现有快照内两侧均无允许（结论仅相对于当前快照） |

每个待确认项都标注：**哪一份输入**（策略/边界名）与**哪部分范围**
（动作 + 资源）受影响，以及原因。条件求值逐键记录
`operator / 期望值 / 实际值 / 来源语句 / 状态`。

## 目录

- `auditlab/engine.py`：加载快照、动作与 ARN 匹配、条件可评价性、五态判定。
- `auditlab/report.py`：逐项文本报告、汇总计数、缺件→补齐差异。
- `auditlab/policies/`：虚构角色的四份策略文档与两版清单。
  - `inline-policy.json`：内联（含一条显式 Deny、一条条件 Allow）。
  - `attached-1-artifacts-read.json`、`attached-2-logs-ssm.json`：两份有交叠的授权。
  - `permission-boundary.json`：条件边界（S3 带 `aws:ResourceTag/env` 条件）。
  - `missing-attached/manifest.json`：先省去附加策略 2 的不完整快照。
  - `complete/manifest.json`：补齐附加策略 2 的完整快照。
- `auditlab/targets.json`：待评估的动作/资源/上下文矩阵（T1–T8）。
- `tests/`：pytest 用例，锁定五态与「补齐只改相关结论」。
- `reports/`：两版文本/JSON 报告与差异文件。

## 运行

```bash
# 不完整快照（缺一份附加策略）
python run_audit.py auditlab/policies/missing-attached/manifest.json auditlab/targets.json

# 机器可读 JSON
python run_audit.py auditlab/policies/missing-attached/manifest.json auditlab/targets.json --json

# 一次对比缺件版与补齐版
python run_audit.py auditlab/policies/missing-attached/manifest.json auditlab/targets.json \
  --diff-with auditlab/policies/complete/manifest.json

# 测试
python -m pytest tests -q
```

## 逐项结论（缺件版）

| 目标 | 动作 / 资源要点 | 结论 | 依据 |
| --- | --- | --- | --- |
| T1 | `s3:PutObject` 到 `public/*` | 显式拒绝（确定） | 内联 `HardDenyPublicObjects` 无条件 Deny，压制边界允许 |
| T2 | `s3:GetObject`，标签 env=prod | 有效允许（确定） | 内联与附加 1 双重允许 + 边界条件可评价通过 |
| T3 | `logs:CreateLogStream` | 待确认-缺输入 | 边界已允许，但身份侧仅可能由缺失的附加 2 授予 |
| T4 | `ssm:GetParameter` | 待确认-缺输入 | 同上，缺 `LogsAndSsmPolicy` |
| T5 | `kms:Decrypt` | 有效允许（确定） | 附加 1 允许（CallerAccount 条件满足）+ 边界允许 |
| T6 | `s3:PutObject` 到 `uploads/*`，无资源标签事实 | 待确认-条件 | 内联允许，但边界 `aws:ResourceTag/env=prod` 无法评价 |
| T7 | `s3:GetObject`，无资源标签事实 | 待确认-条件 | 身份侧允许，边界条件缺取值 |
| T8 | `s3:DeleteObject` | 隐式拒绝（确定） | 两侧均无该动作允许 |

补齐附加策略 2 后，**仅 T3、T4** 从「待确认-缺输入」变为「有效允许」；
T1/T2/T5/T6/T7/T8 结论不变。内联、附加 1、边界各自仍可单独加载分析
（见 `test_individual_policies_remain_independently_loadable`）。

## 边界与限制

- 不做策略真实凭证调用；条件中的运行时值必须由 `targets.json` 的
  `request_context` / `resource_facts` 提供，缺失即判 `PENDING_CONDITION`。
- 未实现的条件运算符（如日期、IP、多值集合的部分算子）按不可评价处理，
  不会臆造允许结论。
- `IMPLICIT_DENY` 始终相对于当前快照；若快照本身缺件，相关目标会优先落入
  `PENDING_MISSING_DATA` 而不是误判为确定拒绝。
