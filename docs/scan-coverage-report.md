# 扫描覆盖率报告：区分完整扫描与部分覆盖

> 状态：提案 + 参考实现（`scripts/scan_with_coverage.py`）
> 日期：2026-11-20

## 背景

安全扫描后台任务目前只上报发现数量（baseline 的 `results` 段只含"有发现"的
文件）。值班员看到 0 条发现时，无法区分以下三种情况，因而无法决定能否放行发布：

1. 真的扫完了所有文件且没有发现（完整扫描）；
2. 部分文件读不了（权限缺失等），被静默跳过（部分覆盖）；
3. 扫描宇宙本身就是空的（枚举失败），一个文件都没扫。

## 后台扫描入口梳理

| 入口 | 位置 | 静默吞掉证据的行为 |
| --- | --- | --- |
| 枚举：`get_files_to_scan` | `detect_secrets/core/scan.py:29` | 非 git 仓库且未加 `--all-files` 时 `valid_paths=False`，**一个文件都不产出**（`scan.py:81-83`），仅在 stderr 留一行 warning |
| 政策排除：`_is_filtered_out` | `detect_secrets/core/scan.py:149` | 命中 `--exclude-files`、`is_invalid_file`、`is_non_text_file` 等过滤器的文件直接 `return`，不留任何记录 |
| 读文件失败：`scan_file` | `detect_secrets/core/scan.py:164-166` | `except IOError` 只 `log.warning` 后 `return`，权限缺失文件与"扫完无发现"完全同形 |
| 汇总：`SecretsCollection.scan_files` | `detect_secrets/core/secrets_collection.py:52` | 只有产出 secret 的文件才进入 `data`；零发现文件不留痕迹 |
| 输出：`baseline.format_for_output` | `detect_secrets/core/baseline.py:67` | `results` 只含发现，没有覆盖率清单 |

结论：**"0 条发现"在现有输出里同时对应"全扫完没发现"、"部分文件没读成"、
"根本没扫到文件"三种语义**，必须引入覆盖率清单才能作为发布依据。

## 接口方案

### 每文件状态机

```
                ┌──────────────────────────────────────────┐
  get_files_to_scan 产出                                    │
                ▼                                          │
        命中政策过滤器？ ──是──► excluded_by_policy（确定性，重试无意义）
                │否
        open() 成功？ ────否──► unreadable（暂时性，值得重试）
                │是
        scan_file 完成 ──────► scanned（记录 findings 数，可为 0）
```

- `scanned`：文件被完整读取并处理，`findings` 为发现数（0 也是有效证据）。
- `unreadable`：OS 级读取失败（如 `PermissionError`），附 `error` 类型，
  `retryable: true`。
- `excluded_by_policy`：被已声明的政策过滤器排除（`--exclude-files`、
  `is_invalid_file`、`is_non_text_file` 等），`retryable: false`——
  这是确定性结果，重试 100 次也一样，要改的是政策而不是重跑。

### 报告 Schema（在 baseline 之外新增，或日后并入 `format_for_output`）

```json
{
  "scan_id": "…",
  "parent_scan_id": "…(仅重试时)",
  "generated_at": "…",
  "enumeration": { "mode": "all-files|git-tracked", "warning": null },
  "coverage": {
    "status": "COMPLETE | PARTIAL_BY_POLICY | PARTIAL_UNREADABLE | EMPTY_UNIVERSE",
    "release_gate": "GO | CONDITIONAL_GO | NO_GO",
    "counts": { "scanned": 0, "unreadable": 0, "excluded_by_policy": 0, "total": 0 }
  },
  "files": [ { "path": "…", "status": "…", "findings": 0, "retryable": false } ],
  "results": { "…": "与 baseline results 同构" }
}
```

汇总状态推导（优先级从高到低）：

| coverage.status | 条件 | release_gate | 进程退出码 |
| --- | --- | --- | --- |
| `EMPTY_UNIVERSE` | total == 0 | `NO_GO` | 1 |
| `PARTIAL_UNREADABLE` | unreadable > 0 | `NO_GO` | 1 |
| `PARTIAL_BY_POLICY` | 仅含政策排除 | `CONDITIONAL_GO` | 3 |
| `COMPLETE` | 全部 scanned | `GO` | 0 |

## 发布判据（值班员决策表）

1. **GO（放行）**：`coverage.status == COMPLETE`。此时 `results` 为空才允许
   解读为"仓库无泄露"。
2. **CONDITIONAL_GO（附条件放行）**：`status == PARTIAL_BY_POLICY`。值班员
   必须核对 `files` 中每条 `excluded_by_policy` 都有对应的政策条目
   （如 `--exclude-files 'vendor/.*'`），签字后可放行；排除清单随报告归档。
3. **NO_GO（阻断）**：`status == PARTIAL_UNREADABLE` 或 `EMPTY_UNIVERSE`。
   此时 `results` 里的 0 条发现**不具有任何证明力**，不得放行。
4. 任何情况下，"发现数量"只允许与 `coverage.counts` 一起解读；单独的上报
   数字不作为发布依据。

## 重试语义：哪些状态值得重试，且不得覆盖先前证据

| 状态 | 值得重试？ | 说明 |
| --- | --- | --- |
| `unreadable` | ✅ 是 | 权限/挂载/锁类故障多为暂时性；修复后重试可升级为 `scanned` |
| `EMPTY_UNIVERSE` | ✅ 是（先修配置） | 修正枚举方式（补 `--all-files` 或进入 git 检出目录）后整体重跑 |
| `excluded_by_policy` | ❌ 否 | 确定性结果；要变更的是政策，变更后属于新一次完整扫描而非重试 |
| `scanned` | ❌ 否 | 已有有效证据；文件内容变化应触发新 scan_id 的完整扫描，而非重试 |

合并规则（参考实现 `--retry-of` 已落实）：

1. 重试**只**重新尝试上一轮 `unreadable` 的文件，其余记录原样携带
   （`carried_over: true`），`results` 中的先前发现一并保留。
2. 重试成功则该文件升级为 `scanned` 并累计 `attempts`；重试失败保持
   `unreadable`，**不得**因此抹掉其他文件的既有证据。
3. 重试报告通过 `parent_scan_id` 串联，形成可审计链。
4. 重试永不把 `scanned` 降级——它与 `SecretsCollection.merge`
   （`detect_secrets/core/secrets_collection.py:92`）"新结果不覆盖已验证标记"
   的精神一致。

## 可复核的观测样例

固件（由 `scripts/coverage_demo.sh` 现场生成，权限位可见）：

```
app/clean.py          -rw-r--r--  无秘密            → scanned, findings=0
app/config.py         -rw-r--r--  含伪造 AWS key    → scanned, findings=1
app/locked.env        ----------  权限缺失          → unreadable (PermissionError)
vendor/bundle.min.js  -rw-r--r--  命中排除政策      → excluded_by_policy
```

复现命令：`./scripts/coverage_demo.sh`（固件与报告分别落在
`$TMPDIR/coverage-fixtures.*` 与 `$TMPDIR/coverage-reports.*`）。

### 样例 A：裸跑后台扫描（空宇宙陷阱）

`scan_with_coverage.py .`（非 git 目录、未加 `--all-files`）→ 退出码 1：

```json
{
  "enumeration": {
    "mode": "git-tracked",
    "warning": "not a git repository: directory scan yields ZERO files (get_files_to_scan silently returns nothing). Re-run with --all-files or inside a git checkout."
  },
  "coverage": {
    "status": "EMPTY_UNIVERSE",
    "release_gate": "NO_GO",
    "counts": { "scanned": 0, "unreadable": 0, "excluded_by_policy": 0, "total": 0 }
  }
}
```

对照：现有 `detect-secrets scan .` 在同一场景输出空 `results`、退出码 0——
正是值班员被"0 条发现"误导的来源。

### 样例 B：部分覆盖（权限缺失 + 政策排除）

`scan_with_coverage.py --all-files --exclude-files 'vendor/.*' .` → 退出码 1：

```json
{
  "coverage": {
    "status": "PARTIAL_UNREADABLE",
    "release_gate": "NO_GO",
    "counts": { "scanned": 2, "unreadable": 1, "excluded_by_policy": 1, "total": 4 }
  },
  "files": [
    { "path": "app/clean.py", "status": "scanned", "findings": 0, "retryable": false },
    { "path": "app/config.py", "status": "scanned", "findings": 1, "retryable": false },
    { "path": "app/locked.env", "status": "unreadable", "error": "PermissionError", "retryable": true },
    { "path": "vendor/bundle.min.js", "status": "excluded_by_policy", "retryable": false }
  ],
  "results": {
    "app/config.py": [
      { "type": "AWS Access Key", "line_number": 1,
        "hashed_secret": "25910f981e85ca04baf359199dd0bd4a3ae738b6",
        "is_verified": false }
    ]
  }
}
```

### 样例 C：修复权限后重试（证据不丢）

`chmod 600 app/locked.env` 后
`scan_with_coverage.py --all-files --exclude-files 'vendor/.*' --retry-of scenarioB.json .`
→ 退出码 3：

```json
{
  "parent_scan_id": "<样例B的scan_id>",
  "coverage": {
    "status": "PARTIAL_BY_POLICY",
    "release_gate": "CONDITIONAL_GO",
    "counts": { "scanned": 3, "unreadable": 0, "excluded_by_policy": 1, "total": 4 }
  },
  "files": [
    { "path": "app/clean.py", "status": "scanned", "findings": 0, "carried_over": true },
    { "path": "app/config.py", "status": "scanned", "findings": 1, "carried_over": true },
    { "path": "app/locked.env", "status": "scanned", "findings": 0, "attempts": 2 },
    { "path": "vendor/bundle.min.js", "status": "excluded_by_policy", "carried_over": true }
  ],
  "results": { "app/config.py": [ "…先前的 AWS Access Key 发现原样保留…" ] }
}
```

要点：`locked.env` 由 `unreadable` 升级为 `scanned`（`attempts: 2`）；
`config.py` 的发现未被重试覆盖；`bundle.min.js` 保持政策排除，值班员按
判据 2 签字即可放行。

### 样例 D：完整覆盖

`scan_with_coverage.py --all-files app/config.py app/clean.py` → 退出码 0：

```json
{
  "coverage": {
    "status": "COMPLETE",
    "release_gate": "GO",
    "counts": { "scanned": 2, "unreadable": 0, "excluded_by_policy": 0, "total": 2 }
  }
}
```

## 落地建议（后续 PR）

1. 把 `scan_file` 的 `except IOError`（`detect_secrets/core/scan.py:164`）
   改为向上抛出或返回状态对象，让 `SecretsCollection.scan_files` 能记录失败文件。
2. 在 `baseline.format_for_output`（`detect_secrets/core/baseline.py:67`）
   增加可选的 `coverage` 段（本报告的 `files` + `coverage`），保持对旧
   baseline 的向后兼容。
3. 将 `scan._is_filtered_out` 的文件级判定暴露为公开 API
   （如 `scan.is_file_excluded(filename)`），参考实现目前复用私有函数。
4. 多进程路径（`detect_secrets/core/secrets_collection.py:316` 的
   `_scan_file_and_serialize`）需改为返回 `(status, secrets)` 元组，
   否则并行扫描下状态仍会丢失。
