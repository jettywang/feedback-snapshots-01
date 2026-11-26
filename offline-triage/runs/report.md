# 离线排查报告：审计读取策略跨分区条件不一致

所有资源值均为虚构项目 fict-proj-audit；全程离线，仅使用本仓库 Policy Sentry 的真实匹配与渲染入口。

## 运行矩阵与数据锚点

| 运行 | 变动 | datastore sha256 | 模板 sha256 |
| --- | --- | --- | --- |
| A-baseline | 无（基准） | `619e1a0bcf4991c2…` | `332325168d1c2283…` |
| B-partition-only | 仅分区 arn:aws:→arn:aws-cn: | `619e1a0bcf4991c2…` | `3215bbd39269eb9a…` |
| C-snapshot-only | 仅目录快照：资源/动作条目摘除 kms:KeySpec | `9a073b2494f01506…` | `332325168d1c2283…` |
| D-control-condition-absent | 仅目录快照：kms:KeySpec 彻底移除（对照） | `d8d054f7be4c47bc…` | `332325168d1c2283…` |
| E-template-resource-typo | 仅模板：KMS 资源段 key/→keystore/ | `619e1a0bcf4991c2…` | `fc21349cb6a4376e…` |

## 首处分歧层（各运行 vs A-baseline）

| 运行 | 首处分歧层 | 最终渲染策略是否与基准一致 | 说明 |
| --- | --- | --- | --- |
| B-partition-only | layer1_template_input | 否 | 分歧只来自模板输入本身；匹配与条件能力层完全一致 |
| C-snapshot-only | layer3_action_condition_capability | 是 | 条件能力在资源/动作条目层缺失，服务级 conditions 表仍有该键 |
| D-control-condition-absent | layer3_action_condition_capability | 是 | 条件键在目录中彻底不存在（对照） |
| E-template-resource-typo | layer1_template_input | 否 | 候选资源类型为空，KMS 的 Sid 整体消失 |

## 关键判定（剥离输入回显后的结构性比较）

| 运行 | 候选资源类型一致 | 动作+条件能力一致 | 渲染策略一致 | 渲染策略一致（归一化分区后） | 缺失的 Sid |
| --- | --- | --- | --- | --- | --- |
| B-partition-only | 是 | 是 | 否 | 是 | 无 |
| C-snapshot-only | 是 | 否 | 是 | 是 | 无 |
| D-control-condition-absent | 是 | 否 | 是 | 是 | 无 |
| E-template-resource-typo | 否 | 否 | 否 | 否 | KmsReadKey |

注：B 运行在 layer2/layer3 的 diff 明细里出现的差异，全部来自记录中回显的输入 ARN 字符串；上表剥离回显后可见匹配结果与条件能力逐项一致。C/D 的渲染策略与基准逐字节一致，说明条件缺失在 Policy Sentry 渲染层不可见，只能由 layer3 的能力记录暴露。

## 对照：kms:KeySpec 在两份问题快照中的落点

- C-snapshot-only：资源级条件键含 kms:KeySpec = False；服务级 conditions 表含 kms:KeySpec = True
- D-control-condition-absent：资源级条件键含 kms:KeySpec = False；服务级 conditions 表含 kms:KeySpec = False

## 逐层 diff 明细

### B-partition-only vs A-baseline

- `layer0_environment`：2 处差异
  - `$.template_path`
    - 基准: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/templates/au...
    - 变体: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/runs/templat...
  - `$.template_sha256`
    - 基准: "332325168d1c2283e066802bb73b095ffbb92552af035cdb92b880168a1d56b8"
    - 变体: "3215bbd39269eb9a53b590fb17beceb95f25dff92adbb6dbb66203ea00255806"
- `layer1_template_input`：3 处差异
  - `$.requested_arns`
    - 基准: [{"access_level": "Read", "arn": "arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "parsed": {"account": "111122223333", "a...
    - 变体: [{"access_level": "Read", "arn": "arn:aws-cn:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "parsed": {"account": "111122223333",...
  - `$.template.list`
    - 基准: ["arn:aws:s3:::fict-proj-audit-logs"]
    - 变体: ["arn:aws-cn:s3:::fict-proj-audit-logs"]
  - `$.template.read`
    - 基准: ["arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "arn:aws:s3:::fict-proj-audit-logs", "arn:aws:s3:::fict-proj-audit-logs/*"]
    - 变体: ["arn:aws-cn:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "arn:aws-cn:s3:::fict-proj-audit-logs", "arn:aws-cn:s3:::fict-proj-au...
- `layer2_resource_match`：1 处差异
  - `$`
    - 基准: [{"arn": "arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "candidates": [{"raw_arn": "arn:${Partition}:kms:${Region}:${Acc...
    - 变体: [{"arn": "arn:aws-cn:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "candidates": [{"raw_arn": "arn:${Partition}:kms:${Region}:${...
- `layer3_action_condition_capability`：1 处差异
  - `$`
    - 基准: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...
    - 变体: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...
- `layer4_final_sid`：5 处差异
  - `$.internal_sid_group.KmsReadKey.arn`
    - 基准: ["arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555"]
    - 变体: ["arn:aws-cn:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555"]
  - `$.internal_sid_group.S3ListBucket.arn`
    - 基准: ["arn:aws:s3:::fict-proj-audit-logs"]
    - 变体: ["arn:aws-cn:s3:::fict-proj-audit-logs"]
  - `$.internal_sid_group.S3ReadBucket.arn`
    - 基准: ["arn:aws:s3:::fict-proj-audit-logs"]
    - 变体: ["arn:aws-cn:s3:::fict-proj-audit-logs"]
  - `$.internal_sid_group.S3ReadObject.arn`
    - 基准: ["arn:aws:s3:::fict-proj-audit-logs/*"]
    - 变体: ["arn:aws-cn:s3:::fict-proj-audit-logs/*"]
  - `$.rendered_policy.Statement`
    - 基准: [{"Action": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport", "kms:GetPublicKey"], "Ef...
    - 变体: [{"Action": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport", "kms:GetPublicKey"], "Ef...

### C-snapshot-only vs A-baseline

- `layer0_environment`：2 处差异
  - `$.datastore_file_path`
    - 基准: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/runs/home-ba...
    - 变体: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/runs/home-sn...
  - `$.datastore_sha256`
    - 基准: "619e1a0bcf4991c241a94bab77f75ae151b668db0fe4431e9218fb6914a1e29b"
    - 变体: "9a073b2494f0150691488c31f4ddf6e0840698cfae40264a0df6313b80943fd9"
- `layer3_action_condition_capability`：1 处差异
  - `$`
    - 基准: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...
    - 变体: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...

### D-control-condition-absent vs A-baseline

- `layer0_environment`：2 处差异
  - `$.datastore_file_path`
    - 基准: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/runs/home-ba...
    - 变体: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/runs/home-sn...
  - `$.datastore_sha256`
    - 基准: "619e1a0bcf4991c241a94bab77f75ae151b668db0fe4431e9218fb6914a1e29b"
    - 变体: "d8d054f7be4c47bcc54dd3fcc081d612548614e543152d61f81372cbb4736d21"
- `layer3_action_condition_capability`：1 处差异
  - `$`
    - 基准: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...
    - 变体: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...

### E-template-resource-typo vs A-baseline

- `layer0_environment`：2 处差异
  - `$.template_path`
    - 基准: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/templates/au...
    - 变体: "/Users/apple/Documents/用户反馈项目/batches/feedback-20261120-backend-security-280-jettywang/prepared/FB-20261120-SEC-JW-191/workspace/offline-triage/runs/templat...
  - `$.template_sha256`
    - 基准: "332325168d1c2283e066802bb73b095ffbb92552af035cdb92b880168a1d56b8"
    - 变体: "fc21349cb6a4376e0cc02779fc7a8ff03919bbc4f0c7bef22e98ad2911c23e0a"
- `layer1_template_input`：2 处差异
  - `$.requested_arns`
    - 基准: [{"access_level": "Read", "arn": "arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "parsed": {"account": "111122223333", "a...
    - 变体: [{"access_level": "Read", "arn": "arn:aws:kms:ap-southeast-2:111122223333:keystore/11111111-2222-3333-4444-555555555555", "parsed": {"account": "111122223333...
  - `$.template.read`
    - 基准: ["arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "arn:aws:s3:::fict-proj-audit-logs", "arn:aws:s3:::fict-proj-audit-logs/*"]
    - 变体: ["arn:aws:kms:ap-southeast-2:111122223333:keystore/11111111-2222-3333-4444-555555555555", "arn:aws:s3:::fict-proj-audit-logs", "arn:aws:s3:::fict-proj-audit-...
- `layer2_resource_match`：1 处差异
  - `$`
    - 基准: [{"arn": "arn:aws:kms:ap-southeast-2:111122223333:key/11111111-2222-3333-4444-555555555555", "candidates": [{"raw_arn": "arn:${Partition}:kms:${Region}:${Acc...
    - 变体: [{"arn": "arn:aws:kms:ap-southeast-2:111122223333:keystore/11111111-2222-3333-4444-555555555555", "candidates": [], "match_ok": false, "service_prefix": "kms...
- `layer3_action_condition_capability`：1 处差异
  - `$`
    - 基准: [{"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport",...
    - 变体: [{"access_level": "Read", "actions": ["s3:AllowVendedLogDeliveryForResource", "s3:GetAccelerateConfiguration", "s3:GetAnalyticsConfiguration", "s3:GetBucketA...
- `layer4_final_sid`：2 处差异
  - `$.internal_sid_group.KmsReadKey`
    - 基准: {"access_level": "Read", "actions": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport", ...
    - 变体: "__MISSING__"
  - `$.rendered_policy.Statement`
    - 基准: [{"Action": ["kms:DescribeKey", "kms:GetKeyLastUsage", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetParametersForImport", "kms:GetPublicKey"], "Ef...
    - 变体: [{"Action": ["s3:AllowVendedLogDeliveryForResource", "s3:GetAccelerateConfiguration", "s3:GetAnalyticsConfiguration", "s3:GetBucketAbac", "s3:GetBucketAcl", ...

## 定位建议（给运营）

- 首处分歧在 `layer1_template_input` 且 layer2 候选非空、layer3 一致：模板输入差异。Policy Sentry 的匹配器不比较 ARN 分区段（`ARN.same_resource_type` 只比服务与资源段），单换分区不会改变匹配与条件能力；若审批工具此时已显示条件缺失，应复核其实际提交的模板与其自身的分区处理，补的资料是审批工具实际收到的模板原文。
- 首处分歧在 `layer1_template_input` 且 layer2 候选为空（或首处分歧直接在 layer2）：资源匹配失败。候选资源类型为空时该 ARN 会被静默跳过、最终策略少一整条 Sid。补齐方向：核对 ARN 资源段写法；若写法无误，则确认目录快照是否包含该服务/资源类型。
- 首处分歧在 `layer3_action_condition_capability`：资料缺失。动作与 Sid 不变、仅条件能力缩水；对照 `service_level_condition_keys` 可进一步区分——服务级仍有该键说明快照的资源/动作表陈旧（补该服务的资源/动作段数据），服务级也没有说明目录本身不含该条件（换更新的 iam-definition.json 整包复核）。
- 注意 `layer4_final_sid`：Policy Sentry 渲染的策略不含 Condition 块（内部 conditions 恒为空），所以条件类分歧在最终文件层面不可见，必须靠 layer3 的中间记录定位。
