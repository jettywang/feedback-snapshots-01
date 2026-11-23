# Argon2 三工作者拆分：调用与数据权限矩阵

接口事实全部来自本仓库真实实现：`src/argon2/_password_hasher.py`、
`src/argon2/_utils.py`、`src/argon2/exceptions.py`、`src/argon2/profiles.py`。
演示代码：`worker_split/workers.py`、`worker_split/run_demo.py`；
运行产物：`worker_split/stage_records.jsonl`（三条阶段记录）、
`worker_split/call_log.jsonl`（本地替身观测日志）。

## 1. 接口能力分类（推导依据）

| 接口 | 实现位置 | 输入 | 是否接触原始秘密 | 依据 |
|---|---|---|---|---|
| `extract_parameters(hash)` | `_utils.py:111` | 仅摘要字符串 | 否 | 纯文本解析：split `$`、读 `v/m/t/p`、由 base64 段长度反推 salt/hash 长度；v1.2 历史格式（5 段）自动补 `v=18` |
| `PasswordHasher.check_needs_rehash(hash)` | `_password_hasher.py:262` | 仅摘要字符串 | 否 | 只做 `self._parameters != extract_parameters(hash)`，是与实例参数的**严格相等比较** |
| `PasswordHasher.verify(hash, password)` | `_password_hasher.py:215` | 摘要 + 明文 | **是** | 经 `verify_secret` 进 C 库重算并比对；只按头部 9 字节判类型，其余解析交给 C 库 |
| `PasswordHasher.hash(password)` | `_password_hasher.py:176` | 明文（+随机盐） | **是** | 发行新摘要，rehash 的唯一来源 |

结论：**参数判断（parse + check_needs_rehash）单靠摘要即可完成；核验（verify）与发行（hash/rehash）必须接触原始秘密。** 这就是三工作者权限边界的来源。

## 2. 调用与数据权限矩阵

| 工作者 | 允许调用 | 数据权限 | 禁止 | 异常面（真实接口） |
|---|---|---|---|---|
| 在线验证 worker | `verify` | 读摘要；明文仅登录瞬间**瞬时**持有，不落盘、不日志 | 不持久化明文；不发行新摘要 | `VerifyMismatchError`（秘密不匹配）、`VerificationError`（C 层失败，如 `Decoding failed`）、`InvalidHashError`（头部无法判型） |
| 离线审计 worker | `extract_parameters`、`check_needs_rehash` | 只读摘要库快照；**能力对象上根本没有 verify/hash 方法**（`DigestOnlyAuditGateway`，构造期移除而非约定） | 接触任何明文；写摘要库 | `InvalidHashError`（编码不可解析，含段数/键名/整型错误） |
| 升级作业 worker | 准入判断（摘要级）；`hash` 仅在登录事件带回明文时瞬时调用 | 读摘要 + 审计结论 + 在线验证结果；明文只在 rehash-on-login 触发点瞬时可用 | 批量任务中持有明文；绕过准入直接发行 | `HashingError`（发行失败）；`UnsupportedParametersError`（目标平台不支持目标 profile，如 WASM 上 parallelism≠1，`exceptions.py:49`） |

异常归口：`InvalidHashError` 属于**离线审计**（解析层）；`VerifyMismatchError`/`VerificationError`
属于**在线验证**（C 层核验）；`HashingError`/`UnsupportedParametersError` 属于**升级作业**（发行层）。
同一记录在不同阶段暴露不同异常，正是拆分后要分别观测的原因。

## 3. 两条历史记录的决定应形成于哪个阶段

- **R1「格式可读但在目标节点不能重新生成」**（`$argon2i$m=1024,...`，v1.2 历史编码，无 `v=` 段）：
  离线审计阶段 `extract_parameters` 照常读出参数（自动补 `v=18`），可分类、可判违规——
  但"能否重新生成"不取决于参数可读，而取决于**在线验证能否成功**。实测该记录在目标节点
  `verify` 抛出 `VerifyMismatchError`（即使明文正确），rehash-on-login 永远不会触发。
  因此它的去向（`manual-reset`，人工重置）只能在**升级准入阶段**、结合在线验证结果之后形成；
  审计阶段只能给出"违规"，给不出"不可自动升级"。
- **R2「参数不同但仍满足政策」**（PRE_21_2 profile：`m=102400,t=2,p=8,hash_len=16`）：
  与当前默认 profile 逐字段不等，但每一项都满足政策下限。该结论是纯摘要级的政策评估，
  应在**离线审计阶段**形成（`compliant`），升级准入据此拒绝入场（`no-op`）——
  不需要、也不应该等到在线或升级阶段再翻案。

## 4. 三条阶段记录（本地小样本实测）

样本与运行：`worker_split/run_demo.py`（明文 `"correct horse"` 仅用于演示）；
两个 worker 使用不同默认 profile：审计参考 profile = `PRE_21_2`，在线/升级发行 profile = 当前默认
`RFC_9106_LOW_MEMORY`（`profiles.py:49`）。完整记录见 `stage_records.jsonl`。

| 记录 | 在线验证 | 离线审计 | 升级准入 | 朴素 check_needs_rehash（审计 profile / 发行 profile） |
|---|---|---|---|---|
| R1 legacy v1.2 argon2i | error：`VerifyMismatchError` | violate（type/version/memory 三项违规） | **拒绝** → manual-reset | True / True |
| R2 PRE_21_2 profile | match | compliant（无违规） | **拒绝** → no-op | **False / True** |
| R3 低于政策（CHEAPEST） | match | violate（memory/time/hash_len 违规） | **准入** → rehash-on-login，已发行新摘要 | True / True |

三条记录、三种不同的阶段组合：在线结果、审计结论、升级准入两两都可以不一致。

## 5. 为什么 check_needs_rehash 不能直接当升级授权

1. **它是"与某一 profile 严格相等"，不是"满足政策下限"。** R2 满足全部政策，仅因字段与默认
   profile 不等，`check_needs_rehash=True`；照它授权会把合规记录送进升级作业，造成无意义
   churn（且 R2 在审计 profile 下为 False、在发行 profile 下为 True——**两个 worker 默认
   profile 不同，同一条记录给出相反布尔值**，说明它根本不是记录本身的属性，而是"记录 ×
   实例参数"的关系）。
2. **它看不见目标节点能否完成升级。** R1 在两个 profile 下都是 True，朴素授权会把它放进
   自动升级队列；但该记录在目标节点 `verify` 必抛 `VerifyMismatchError`，rehash-on-login
   永不触发，作业永远卡死。准入必须消费在线验证结果（本演示中准入逻辑读取 `online_verify`
   阶段产出），这是 check_needs_rehash 的摘要级视图给不出的。
3. **它的异常面与授权语义错位。** 对不可解析的摘要它抛 `InvalidHashError`（解析层信号），
   而授权需要区分"格式损坏→隔离"与"参数违规→可自动升级"；把异常一律当"需要升级"或一律
   当"跳过"都会误判。

正确归口：升级授权 = 离线审计的政策违规判定（摘要级）**且** 在线验证路径健康（需秘密的
核验结果），两者缺一不可；`check_needs_rehash` 至多是审计阶段的一个参考信号。

## 6. 业务复核：离线诊断不触及在线秘密

- **构造期能力移除**：离线 worker 只持有 `DigestOnlyAuditGateway`（`workers.py:106`），
  该对象没有 `verify`/`hash` 属性，秘密路径在类型层面不存在，而非靠自觉。
- **运行期可观测**：所有边界调用经本地替身 `InstrumentedHasher`/`CallLog` 记录
  （`touches_secret` 标记，秘密本身永不入日志）。本次运行 `call_log.jsonl` 中
  `offline-audit` 的 6 次调用全部 `touches_secret=false`，`verify`/`hash` 只出现在
  `online-verify` 与 `upgrade-job` 名下——业务可直接重放该日志复核。
- 复核命令：`.venv/bin/python worker_split/run_demo.py` 后检查末尾一行
  `offline-audit calls touching secrets: 0`。
