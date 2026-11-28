# PyPI 发布准入登记方案

本目录给出一套可维护的多构建系统发布者登记方案,用于审批"哪些 CI/CD 提供方、
哪些工作流边界允许向 PyPI 发布"。方案以本库(`pypi-attestations`)实际实现的
验签策略为准绳:登记字段能否参与准入,取决于 `_as_policy()` 是否真的校验它。

- `publishers.json`:登记表(示例含 4 家提供方、6 个条目)
- `check_registry.py`:登记校验 + 离线样本复核脚本

## 1. 现状核对:声明 vs 实际验签

库中 4 个发布者模型(`src/pypi_attestations/_impl.py:431` 起)的声明字段与
策略实际消费情况:

| 提供方 | 模型声明字段 | 策略实际校验(可参与准入) | 声明但未校验(只能辅助排查) |
| --- | --- | --- | --- |
| GitHub (`_impl.py:521`) | `repository`, `workflow`, `environment` | issuer 固定为 `token.actions.githubusercontent.com`;`repository` 经 Source Repository URI 校验;`workflow` 经 Build Config URI 与 Source Repository Digest/Ref 拼接比对(`_impl.py:441`) | `environment` — 模型收了但 `_as_policy()` 完全没用它 |
| GitLab (`_impl.py:613`) | `repository`, `workflow_filepath`, `environment` | issuer 固定为 `gitlab.com`;`repository` + `workflow_filepath` 经 Build Config URI 与 sha/ref 拼接比对(`_impl.py:548`) | `environment` — 同上,未参与验签 |
| Google (`_impl.py:640`) | `email` | `email` + issuer `accounts.google.com` 经 `policy.Identity` 校验 | — (边界仅到服务账号身份,无工作流级证明) |
| CircleCI (`_impl.py:712`) | `project_id`, `pipeline_definition_id`, `vcs_origin`, `vcs_ref` | issuer 固定为 `oidc.circleci.com`;`project_id` + `pipeline_definition_id` 经 Build Signer URI 精确比对(`_impl.py:655`);`vcs_origin`/`vcs_ref` 提供时校验 | `vcs_origin`/`vcs_ref` 缺省时静默跳过,边界退化为"同 pipeline 任意触发源" |

关键结论:

- **GitHub/GitLab 的 `environment` 是声明式字段,不是准入字段。** 登记时若把它
  当准入条件,等于没有审批。本方案将其列为待查原因 `unenforced-declared-field`。
- **Google 只能证明"哪个服务账号签的",证明不了"哪个工作流签的"。** 可准入,
  但审批人应知道边界强度是身份级。
- **CircleCI 的可选声明缺省时不报错**,登记层必须显式提示,否则审批人误以为
  触发源已固定。

## 2. 登记表 schema

每个条目区分三层,对应 `publishers.json` 的结构:

- `provider`(提供方):`kind` + `issuer`。`kind` 必须命中库已实现的 4 类之一,
  否则条目只能 `pending`(原因 `unsupported-provider`)。
- `workflow_boundary`(可证明的工作流边界):**只允许放该提供方准入字段集内的
  键**(见第 3 节)。这一层整体直接映射为库的 `Publisher` 模型并参与验签。
- `vendor_extensions`(供应商拓展字段):自由键值,放提供方特有、库未建模或
  未校验的信息(如 `runner_environment`)。**一律不得参与准入**,且不得与准入
  字段重名(防影子覆盖,违例报 `extension-shadows-admission`)。

状态机:

- `approved`:校验脚本推导不出任何阻断级发现,且附离线样本可复核通过。
- `pending`:必须在 `pending_reasons` 里逐条给出 `{code, field, detail}`,
  覆盖脚本推导出的全部阻断级发现;审批人按原因码逐项销项后才能转 `approved`。

## 3. 字段分类:准入 vs 辅助排查

参与准入(验签时强制比对,登记在 `workflow_boundary`):

| 提供方 | 准入字段 | 证书证据 |
| --- | --- | --- |
| GitHub | `repository`, `workflow` | Build Config URI + Source Repository Digest/Ref |
| GitLab | `repository`, `workflow_filepath` | Build Config URI + Source Repository Digest/Ref |
| Google | `email` | 证书 SAN 身份 + issuer |
| CircleCI | `project_id`, `pipeline_definition_id`(必选);`vcs_origin`, `vcs_ref`(可选但建议固定) | Build Signer URI;Source Repository URI/Ref |
| 通用 | `provider.kind`(决定 issuer 固定值) | IssuerV2 扩展 |

只能辅助排查(不进 `workflow_boundary`,可放 `vendor_extensions` 或审阅时参考):

- GitHub/GitLab 的 `environment`(库未校验)
- 证书中的 `runner_environment`、`source_repo_ref`、`source_repo_digest`、SAN、
  签名时间戳等——验签失败时定位用,不构成准入条件
- 任何 `vendor_extensions` 内容

## 4. 待查原因码

规则不完整时,条目保持 `pending` 并给出机器可筛的原因码:

| 原因码 | 级别 | 含义与销项方式 |
| --- | --- | --- |
| `unsupported-provider` | 阻断 | 库未实现该提供方策略;需先在上游实现 `_as_policy()` |
| `unenforced-declared-field` | 阻断 | 字段已声明但不参与验签(当前即 `environment`);从边界移除或等库支持 |
| `unknown-boundary-field` | 阻断 | 边界字段不在准入字段集内;移入 `vendor_extensions` 或删除 |
| `missing-required-field` | 阻断 | 缺必需准入字段;补齐 |
| `extension-shadows-admission` | 阻断 | 拓展字段与准入字段重名;改名 |
| `optional-claim-absent` | 提醒 | CircleCI 可选声明未固定;评估触发源风险后补登或接受 |
| `identity-only-boundary` | 提醒 | 边界仅身份级(Google);审批人知悉即可 |
| `missing-offline-sample` | 提醒 | approved 条目缺离线样本,无法复核 |

## 5. 维护流程

1. 新增/变更条目只改 `publishers.json`,跑
   `python publisher-registry/check_registry.py`(离线,无需网络;沙箱环境下
   若 TUF 缓存目录不可写,用 `HOME="$TMPDIR"` 运行)。
2. 脚本对每条目:结构校验 → 用库的 `Publisher` 模型重建边界 → 重放离线样本
   → 输出结果表;任一 approved 条目出现阻断级发现或样本复核失败即非零退出。
3. 库升级后(新增提供方、策略变化),更新脚本顶部的
   `ADMISSION_FIELDS` / `DECLARED_UNENFORCED` 常量并重跑,差异会自动变成
   待查原因而不是静默放行。

## 6. 离线正常样本与结果表

样本全部取自 `test/assets/`(GitHub: `pypi_attestation_models-0.0.4a2.tar.gz`
+ `.sigstore`;GitLab: `gitlab_oidc_project-0.0.3.tar.gz` + `.publish.attestation`;
另附 CircleCI 证书级与 Google provenance 级样本),`check_registry.py` 实测输出:

| 登记条目 | 提供方 | 状态 | 离线样本复核 | 检查发现 |
| --- | --- | --- | --- | --- |
| gh-trailofbits-pypi-attestation-models | GitHub | approved | PASS | — |
| gl-facutuesca-gitlab-oidc-project | GitLab | approved | PASS | — |
| cci-sign-and-publish-examples | CircleCI | pending | PASS | ⚠️ optional-claim-absent(vcs_origin, vcs_ref) |
| gcb-attestation-test | Google | approved | PASS | ⚠️ identity-only-boundary(email) |
| gh-environment-gated-release | GitHub | pending | PASS | ⛔ unenforced-declared-field(environment) |
| azure-devops-example | AzureDevOps | pending | - | ⛔ unsupported-provider(provider.kind) |

注意最后两行:GitHub environment 条目样本复核 PASS 但状态仍为 pending——
验签通过只证明 `repository`+`workflow` 匹配,`environment` 从未被检查,
这正是"声明字段 ≠ 准入字段"的实例。
