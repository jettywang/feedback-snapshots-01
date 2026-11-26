# 项目标签只读申请：条件落实证据

这个本地实验用随库 `policy_sentry/shared/data/iam-definition.json` 中的真实 Bedrock 动作
`bedrock:GetInferenceProfile`。该动作在目录中匹配两类资源：

- `application-inference-profile`：目录列出 `aws:ResourceTag/${TagKey}`，可落实
  `aws:ResourceTag/Project = proj-approved-204`。
- `inference-profile`：用于模拟第二类资源在三种目录资料下的状态。

三份小覆盖资料位于 `test/files/condition_evidence/overlays/`：

- `full-support.json`：把第二类资源补成支持标签条件，预期 `publishable`。
- `primary-only.json`：第二类资源的 `condition_keys` 明确为空，属于“目录已表明不支持”。
- `old-missing.json`：从旧目录资料中删掉第二类资源的 `condition_keys` 字段，属于“目录缺项，无法验证”，不能误报成已知不支持。

## 生成报告

```sh
.venv/bin/python condition_evidence_lab/generate_reports.py
```

输出在 `condition_evidence_lab/reports/`：

- `<scenario>.json`：完整证据，含 `base_policy`、加条件后的 `rendered_policy`、逐项 `items`、`required_evidence` 和 `publishable_policy`。
- `<scenario>.md`：审批人可读的逐项对照表和真实语句 JSON。
- `<scenario>.base-policy.json`：Policy Sentry 原始渲染结果。
- `<scenario>.candidate-policy.json`：尽量补上条件后的诊断草稿；部分覆盖时含未约束语句，不能发布。
- `full-support.publishable-policy.json`：仅完整覆盖场景存在；两个部分覆盖场景不会写出可发布策略。
- `index.json`：三种场景的发布状态汇总。

门禁规则是：每个“实际输出语句 × 动作 × 匹配资源/原始 ARN”检查项都必须在真实语句中观察到请求的
`Condition`，且目录结论为 `supported`。任一项为 `known_unsupported`、`unverifiable` 或条件未落实，
总状态即为 `blocked_needs_evidence`，且 `publishable_policy` 为 `null`。第一类资源通过不会放行第二类
未约束语句。

## 命令行门禁

也可以直接调用子命令；完整覆盖时输出/写入可发布策略，部分覆盖时写出报告并以退出码 `2` 阻断：

```sh
.venv/bin/policy_sentry write-policy-evidence \
  --input-file test/files/condition_evidence/template.yml \
  --report "$TMPDIR/evidence.json" \
  --condition-key aws:ResourceTag/Project \
  --condition-value proj-approved-204 \
  --overlay test/files/condition_evidence/overlays/full-support.json
```

回归测试：

```sh
.venv/bin/python -m pytest -q -o addopts= test/writing/test_condition_evidence.py test/command/test_write_policy_evidence_click.py
```
