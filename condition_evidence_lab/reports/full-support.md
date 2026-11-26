# 条件落实证据

- 发布状态：`publishable`（可发布）
- 语句数：2
- 资源核对项：2
- 已覆盖：2
- 目录已知不支持：0
- 无法验证：0
- 待补证：0
- 条件：`StringEquals` `aws:ResourceTag/Project` = `proj-approved-204`

## 逐项对照

| 语句# | Sid | 动作 | 资源类型 / ARN | 目录结论 | 实际 Condition | 状态 |
|---:|---|---|---|---|---|---|
| 0 | `BedrockReadApplicationinferenceprofile` | `bedrock:GetInferenceProfile` | application-inference-profile<br>`arn:${Partition}:bedrock:${Region}:${Account}:application-inference-profile/${ResourceId}` | 支持<br>`condition_supported` | `{"StringEquals": {"aws:ResourceTag/Project": "proj-approved-204"}}` | 已受控 |
| 1 | `BedrockReadInferenceprofile` | `bedrock:GetInferenceProfile` | inference-profile<br>`arn:${Partition}:bedrock:${Region}:${Account}:inference-profile/${ResourceId}` | 支持<br>`condition_supported` | `{"StringEquals": {"aws:ResourceTag/Project": "proj-approved-204"}}` | 已受控 |

## 必须补证的资源

无；所有实际输出语句均已落实请求条件，`publishable_policy` 可发布。

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
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Project": "proj-approved-204"
    }
  }
}
```
