# 条件落实证据

- 发布状态：`blocked_needs_evidence`（阻断：需审批人补证）
- 语句数：2
- 资源核对项：2
- 已覆盖：1
- 目录已知不支持：1
- 无法验证：0
- 待补证：1
- 条件：`StringEquals` `aws:ResourceTag/Project` = `proj-approved-204`

## 逐项对照

| 语句# | Sid | 动作 | 资源类型 / ARN | 目录结论 | 实际 Condition | 状态 |
|---:|---|---|---|---|---|---|
| 0 | `BedrockReadApplicationinferenceprofile` | `bedrock:GetInferenceProfile` | application-inference-profile<br>`arn:${Partition}:bedrock:${Region}:${Account}:application-inference-profile/${ResourceId}` | 支持<br>`condition_supported` | `{"StringEquals": {"aws:ResourceTag/Project": "proj-approved-204"}}` | 已受控 |
| 1 | `BedrockReadInferenceprofile` | `bedrock:GetInferenceProfile` | inference-profile<br>`arn:${Partition}:bedrock:${Region}:${Account}:inference-profile/${ResourceId}` | 已知不支持<br>`catalog_reports_unsupported` | 无 | 目录表明不支持 |

## 必须补证的资源

- 语句 #1 `BedrockReadInferenceprofile` / `inference-profile`：审批人必须为 bedrock:GetInferenceProfile 在资源 inference-profile 上的使用提供补偿控制证据或明确风险接受；目录已表明该资源不支持条件键 aws:ResourceTag/Project。

## 真实输出语句

### Statement 0: `BedrockReadApplicationinferenceprofile`

```json
{
  "Sid": "BedrockReadApplicationinferenceprofile",
  "Effect": "Allow",
  "Action": [
    "bedrock:GetInferenceProfile"
  ],
  "Resource": [
    "arn:${Partition}:bedrock:${Region}:${Account}:application-inference-profile/${ResourceId}"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Project": "proj-approved-204"
    }
  }
}
```

### Statement 1: `BedrockReadInferenceprofile`

```json
{
  "Sid": "BedrockReadInferenceprofile",
  "Effect": "Allow",
  "Action": [
    "bedrock:GetInferenceProfile"
  ],
  "Resource": [
    "arn:${Partition}:bedrock:${Region}:${Account}:inference-profile/${ResourceId}"
  ]
}
```
