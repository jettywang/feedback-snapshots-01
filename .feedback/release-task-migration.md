# bundle-audit → Rake 发布准入迁移指南

面向“发布流水线从直接运行 `bundle-audit` 切换到 Rake”的逐步迁移。旧入口的退出码契约
保持不变；新入口在退出码之外，额外产出一份可对账的清单（manifest），把通告库修订、
锁文件身份、扫描发现和结果交付绑定到同一次扫描。

## 两个入口

### 旧入口（保留，契约不变）

```sh
# 直接命令
bundle-audit check --format json
# 或既有 Rake 封装（内部仍是 system('bundler-audit', ...)，原样透传退出码）
rake bundle:audit:check
```

退出契约（来自 `Bundler::Audit::Task` 与 `CLI#check`，本次未改动）：

| 情况 | 退出码 |
| --- | --- |
| 无发现 | 0 |
| 发现漏洞/不安全源 | 1 |
| 参数、锁文件、下载等命令级错误 | 1 |
| 命令无法执行（找不到可执行文件） | Rake 抛 `CommandNotFound` |

旧消费者继续只读退出码即可，无需任何改动。

### 新入口（新增，带对账证据）

```sh
rake bundle:audit:release \
  BUNDLER_AUDIT_DB=./.feedback/demo/advisory-dbs/db-with-advisory \
  BUNDLER_AUDIT_ROOT=./.feedback/demo/locks/vulnerable \
  BUNDLER_AUDIT_UPDATE=false \
  BUNDLER_AUDIT_FORMAT=json \
  BUNDLER_AUDIT_OUTPUT=./out/audit.json
# 清单默认写到 ./out/audit.json.manifest.json（可用 BUNDLER_AUDIT_MANIFEST 覆盖）
```

环境变量：`BUNDLER_AUDIT_DB`、`BUNDLER_AUDIT_ROOT`、`BUNDLER_AUDIT_GEMFILE_LOCK`、
`BUNDLER_AUDIT_UPDATE`（`true`/`false`，缺省 `:auto`）、`BUNDLER_AUDIT_IGNORE`（逗号分隔）、
`BUNDLER_AUDIT_FORMAT`（默认 `json`）、`BUNDLER_AUDIT_OUTPUT`、`BUNDLER_AUDIT_MANIFEST`。

退出契约（`Bundler::Audit::ReleaseTask`）：

| 退出码 | 常量 | 含义 |
| --- | --- | --- |
| 0 | — | 扫描完成且无发现 |
| 1 | `EXIT_VULNERABLE` | 扫描完成且有发现（与旧入口语义一致） |
| 3 | `EXIT_INCONCLUSIVE` | 输入/交付等基础设施问题，扫描结论不可采信 |

关键区别：**更新失败不等于没有发现，交付失败不等于扫描通过**。

## 新入口保证的四件事

1. 更新与扫描分离。更新前后各取一次通告库身份（git commit、更新时间、通告数），
   写进清单的 `advisory_database.before` / `.after`，并用 `identity_changed` 标明修订是否变化。
2. 更新失败不静默。`git pull` 失败时记录 `advisory_database.update.status = "update_failed"`
   与错误信息，扫描仍基于更新前那个**可信本地修订**继续；因此离线但本地库可信时仍能出报告，
   而干净扫描不会被误当成“更新成功且无漏洞”。
3. 原子交付。报告与清单都先写同目录临时文件、`fsync` 后 `rename`。新报告未完整落盘前，
   上一份报告一个字节都不会被改动；交付失败时清单记录 `delivery.report_delivered = false`。
4. 四类证据可对账。清单 `bundler-audit.release-manifest/v1` 同时包含：
   - 通告库修订：`advisory_database.before.commit` / `after.commit` / `identity_changed`
   - 锁文件身份：`lockfile.path` / `sha256` / `size` / `mtime_utc`
   - 扫描发现：`scan.vulnerable` / `result_count` / `advisory_ids`
   - 结果交付：`delivery.path` / `sha256` / `report_delivered` / `manifest_path`

   准入方核对：清单里 `delivery.sha256` 必须等于报告文件的实际 SHA-256，
   `lockfile.sha256` 必须等于本次被扫锁文件的实际 SHA-256，三者同属一个 `generated_at_utc`。

## 逐步切换路径

1. 阶段 0（现状）：流水线只调用旧入口 `bundle-audit check` / `rake bundle:audit:check`，
   消费者按 0/1 判断。
2. 阶段 1（影子运行）：保留旧入口作为准入结论；并行新增一步调用 `rake bundle:audit:release`，
   只收集清单与退出码，不阻断流水线。用历史构建比对两套退出码在“有/无发现”上是否一致（都为 1/0）。
3. 阶段 2（准入切换）：准入方改为读取新清单做对账（校验两个 SHA-256 与 `identity_changed`），
   退出码 3 视为基础设施失败而非通过；旧入口仍保留给只认退出码的消费者。
4. 阶段 3（收敛）：确认无消费者依赖旧入口后，再评估下线旧入口。本指南范围内旧入口始终保留。

## 四场景判断表（本地替身实测）

复现：`sh .feedback/demo/run_all.sh`（完全离线，使用 `.feedback/demo` 下的锁文件、
git 通告库和输出替身）。

| # | 场景 | 通告库更新 | 库身份变化 | 扫描发现 | 报告交付 | 新入口退出码 | 旧入口等价退出码 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 正常扫到通告 | skipped（不更新） | 否 | 1 条 CVE-2013-0276 | 成功 | 1 | 1 |
| 2 | 离线库可信、无发现 | update_failed（无 origin） | 否（沿用可信修订） | 0 条 | 成功 | 0 | 0 |
| 3 | 更新期间库标识变化 | updated（本地落后 origin 一个提交） | 是，commit 前进 | 2 条（含新增 CVE-2013-0277） | 成功 | 1 | 1 |
| 4 | 已有报告但新写出失败 | skipped | 否 | 1 条（仅入清单） | 失败，旧报告原样保留 | 3 | 1（命令级错误，不区分） |

## 两类消费者各自收到什么

- 旧消费者（只认退出码）：
  - 场景 1、3 收到 `1`（有发现），场景 2 收到 `0`（无发现），与切换前完全一致。
  - 场景 4 旧入口会给 `1`，无法区分“真有漏洞”还是“写报告失败”；这正是新入口用 `3` 解决的歧义。
- 新准入方（读清单 + 退出码）：
  - 场景 1：退出码 1 + 清单 `scan.vulnerable=true`、`advisory_ids` 非空、报告 SHA-256 可核验。
  - 场景 2：退出码 0，但清单显式标注 `update.status="update_failed"` 且 commit 前后相同，
    准入方知道“结论基于上一个可信修订”，而不是误以为联网更新成功。
  - 场景 3：清单 `identity_changed=true` 且记录前后两个 commit，准入方可确认报告针对的是更新后的修订。
  - 场景 4：退出码 3 + 清单 `delivery.report_delivered=false`、`intended_path` 与错误信息；
    旧报告 SHA-256 不变，准入方不得引用旧报告作为本次证据，应阻断或重试。

## 回退与证据保留

- 回退动作：把流水线调用从 `rake bundle:audit:release` 改回
  `bundle-audit check`（或 `rake bundle:audit:check`）。两者任务名独立，回退只改调用，不删代码。
- 回退后旧入口退出码契约不变，只认 0/1 的消费者无需改动。
- 保留一次正常扫描的证据：回退前最后一次成功运行（场景 1 形态）的
  报告 `*.json` 与 `*.json.manifest.json` 已落盘且含锁文件/通告库/报告三个 SHA-256 与 commit，
  归档该对文件即可长期对账；新报告写入失败（场景 4）永远不会覆盖它们。
