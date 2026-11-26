# 离线 IAM 职责收敛计划（Policy Sentry）

目标：在**离线**条件下，用 Policy Sentry 自带的 IAM 数据库
（`policy_sentry/shared/data/iam-definition.json`，无任何网络调用）规划如何关闭
旧 IAM 职责 `LegacyOnCallDataAccess`，同时保证两个值班职责在迁移期不丢失必要读取，
过期授权只缩小、不放大，最终收敛到新批准范围 `NewApprovedOnCallTarget`。

## 输入产物（migration/policies/）

| 文件 | 角色 | 说明 |
| --- | --- | --- |
| `legacy-role.json` | 旧职责（待关闭） | 含值班仍依赖的读取，也含过宽/过期授权；全部为 Read/List 级 |
| `oncall-role-A.json` | 交叉批准值班职责 A | 审批单 APP-A：S3 证据桶 + DDB 工单表 + 共享 KMS 密钥读取 |
| `oncall-role-B.json` | 交叉批准值班职责 B | 审批单 APP-B：S3 前缀受限读取 + DDB 索引读取 + 同一 KMS 密钥读取 |
| `new-target-role.json` | 新批准目标范围 | 仅含 S3 与 DDB 读取，**未包含 KMS 密钥读取** |

所有动作、条件键、资源 ARN 均经离线库校验存在（见 `validate_artifacts.py`）。

## 方法：覆盖语义而非简单相等

把每条 Allow 声明展开为 `(动作, 资源, 条件指纹)` 权限元组（通配动作由
`policy_sentry.analysis.expand` 展开）。判定一项值班需求是否被某策略“覆盖”时使用
包含关系：

- 资源：授权资源范围包含需求资源（桶级授权覆盖前缀级授权，`*` 覆盖一切）；
- 条件：授权方条件是需求条件的**子集**（约束更少＝范围更宽）。

这样前缀受限的 `oncall-role-B`（`incidents/*` + `s3:prefix`）能被目标里更宽的桶级
S3 声明正确覆盖；而目标里完全不存在的 KMS 读取会被如实标记为缺失审批。

## 逐步最小生效权限（旧职责只缩小）

每一步给出旧职责上**仍须保留的最小权限**，对应可部署策略在 `migration/plan/`。
元组数量单调不增：**31 → 13 → 1**。

### S0 基线 — `plan/S0-baseline.json`（31 个权限元组）
旧职责完整挂载，值班 A/B 仍依赖它。包含 S3、DynamoDB、KMS 读取及两条
`Resource: "*"` 的过宽 List（`s3:ListAllMyBuckets`、`dynamodb:ListTables`）。

### S1 移除无值班依赖的过期授权 — `plan/S1-drop-dead-legacy.json`（13 个元组）
删除 18 个“无人再用”的旧授权（`legacy_dead_safe_to_drop`）：
- 过宽的 `s3:ListAllMyBuckets`、`dynamodb:ListTables`（`*` 资源）；
- `s3:GetBucketPolicy`、`dynamodb:Scan`；
- 对 `legacy-archive` 桶、`legacy-audit` 表的全部访问。

保留 13 个仍承载值班读取的元组（`legacy_load_bearing`）：S3 证据桶、DDB 工单表、
以及共享 KMS 密钥读取。此步不影响任何值班动作。

### S2 切换到新目标已批准范围 — `plan/S2-cutover-target-approved.json`（1 个元组）
把目标策略已覆盖的 16 个值班元组（S3 + DDB）从旧职责上切除，改由新目标承担。
旧职责上只剩唯一无法切换的元组：

```
kms:DescribeKey
  arn:aws:kms:us-east-1:111111111111:key/11111111-1111-1111-1111-111111111111
  Condition: StringEquals aws:ResourceTag/DataClass = internal
```

## 缺失审批（共享资源条件，无法安全过渡）

值班 A 的 `A3SharedKmsKeyRead` 与值班 B 的 `B3SharedKmsKeyRead` 是**两条共享同一
资源条件**的声明：同一 KMS 密钥 ARN + 同一 `aws:ResourceTag/DataClass=internal` 条件。
新目标策略中没有任何匹配该动作/资源/条件的 Allow，因此无法在不丢失读取的情况下过渡。

**缺哪个审批**：需要一份针对
`kms:DescribeKey` on `arn:aws:kms:...:key/1111...`（带 `aws:ResourceTag/DataClass=internal`）
的新批准，并加入 `new-target-role.json`。在该审批落地前，该权限必须继续留在旧职责上。

## 能否停止旧职责

**当前不能停止。** 阻断发生在 **S2**：S1 之后旧职责仍承载 KMS 读取，S2 切除目标已批准
项后仍残留 1 个元组（`can_retire_legacy_role=false`，`blocking_step=S2-...`）。
一旦上述 KMS 审批补入新目标，残留归零，即可在 S2 之后退役旧职责。

## 关于动作通符最小化

Policy Sentry 的 `minimize_statement_actions` 可把动作压缩成安全通符（如
`kms:DescribeKey` → `kms:desc*`）以缩短策略长度，但展开后会**额外包含同前缀动作**
（`kms:desc*` 还授予 `kms:DescribeCustomKeyStores`）。这属于范围放大，违背“过期授权
只能缩小”，因此 `migration/plan/` 中的部署产物一律使用**显式动作**；通符仅作为需要
压缩字符数时的参考，不用于本次收敛。

## 复现（离线）

```sh
.venv/bin/python migration/validate_artifacts.py     # 校验动作/条件/ARN，确认旧职责只读
.venv/bin/python migration/plan_offline.py           # 生成 plan/ 与 report/convergence-report.json
```
