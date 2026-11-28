# 通告库可恢复的本地晋升（接收 → 核对 → 启用）

把审批后的通告库在**隔离构建机**上的接收、核对、启用做成**一次可恢复的本地操作**。
仅依赖 Python 3 标准库（`sqlite3`/`hashlib`/`json`/`os`），无需联网、无需第三方包。

## 两个本地目录

| 目录 | 角色 | 内容 |
| --- | --- | --- |
| `staging/` | 待启用副本（隔离区） | `pending-<id>/`（数据库 + manifest + 身份卡）、`pending` 符号链接 |
| `live/` | 正在使用的副本 | `current` 符号链接、不可变 `versions/<id>/`、`rollout-state.json`、`history/` |

- `staging/pending` 始终指向**当前在审**的那一份，值班人员看链接和 `status` 即知在审哪份。
- `live/current` 指向当前生效版本；只有最后一步会原子替换它。

## 交付包与待启用副本的独立身份 / 时效

每个交付包是一个目录，含：

- `notices.db`：SQLite 通告库（须含非空 `notices` 表）。
- `manifest.json`：独立身份 `id`、内容 `version`、数据库 `content_sha256`、
  时效窗口 `not_before` / `not_after`。

接收时在 `staging/pending-<id>/` 生成 `IDENTITY.txt` 身份卡，写明独立身份、
内容哈希、时效窗口与「等待批准」状态——待启用副本具备独立身份和时效说明。

## 可恢复状态机

状态持久化在 `live/rollout-state.json`（原子写），阶段流转：

```
RECEIVE -> VERIFY -> APPROVE -> PROMOTE -> ACTIVE
                    （核对失败 / 人工中止）-> REJECTED
```

- `run`：执行接收 + 核对，然后**停在批准闸门**，明确提示值班人员后续命令。
- `approve`：值班人员显式批准后进入 `PROMOTE`。
- `promote`：先物化不可变版本目录，再用「临时符号链接 + `os.replace`」**原子切换**
  `current`，最后落盘 `ACTIVE`。
- 每个阶段都幂等：中断后**重跑同一条命令**即从断点继续，已完成步骤显示 `idempotent`。
- `abort`：仅在未进入启用阶段（`PROMOTE` 之前）可中止，**绝不触碰 `current`**。

### 崩溃安全：任何一步中断都保留正在用的副本

`promote --crash-after` 用于确定性演练两个真实中断窗口：

- `materialize`：版本目录已物化、**切换前**崩溃 → `current` 不变，重跑完成切换。
- `swap`：`current` 已原子切换、**状态收尾前**崩溃（状态仍为 `PROMOTE`）→
  重跑时先**对账**：若 `current` 已指向目标且哈希正确，只补登记为 `ACTIVE`
  （返回 `reconciled`），不会二次切换或回退。

因为切换是单条原子 rename，系统在任意时刻读到的 `current` 要么是旧版本、要么是
新版本，不存在半成品；旧版本目录保留在 `live/versions/` 以便回退审计。

## 历史非 Git 目录：沿调用方指定的身份规则

`scan --identity-rule` 决定如何为目录推导身份：

- Git 目录（含 `.git`）：**优先**用 `git rev-parse --short HEAD`，标记 `git:<hash>`。
- 非 Git 历史目录：按调用方给的规则处理——
  - `hash`：对 `notices.db` 取 SHA-256（无 db 时退化为目录名哈希）。
  - `regex:PATTERN`：从目录名按正则提取身份（如 `regex:adv-([0-9]{4}-[0-9]{4})`）。

`scan --live-dir` 额外标注哪一份正被 `live/current` 使用（`在用 = YES`），
直接回答「现在扫描实际指定了哪一份数据库」。

## 固定时钟

所有命令接受全局 `--now <ISO-8601>`，用注入的确定性时间做时效判断与时间戳记录，
演示不依赖墙上时钟，可重复复现。

## 运行演示

```bash
cd notice_rollout
./demo.sh
```

演示覆盖：一次成功晋升；`materialize` 与 `swap` 两类中断及恢复；接收阶段中断的
幂等续跑与人工中止；过期副本被核对拒绝且在用副本不动；`hash`/`regex` 两种身份
规则下的扫描，以及 Git 目录优先用 HEAD、在用副本标 `YES`。

### 常用命令

```bash
# 构造交付包（演示用）
python3 notice_rollout.py --now 2026-11-29T08:00:00Z make-bundle \
  --out /tmp/bundle --id adv-1 --version 1 \
  --not-before 2026-11-29T00:00:00Z --not-after 2026-11-30T00:00:00Z \
  --notice "一条通告"

# 一次可恢复流程：接收+核对，停在批准闸门
python3 notice_rollout.py --now 2026-11-29T08:00:00Z run \
  --staging-dir ./staging --live-dir ./live --bundle-dir /tmp/bundle

# 值班人员看清在审哪份
python3 notice_rollout.py status --live-dir ./live

# 批准并原子启用
python3 notice_rollout.py --now 2026-11-29T09:00:00Z approve \
  --staging-dir ./staging --live-dir ./live
python3 notice_rollout.py --now 2026-11-29T09:00:00Z promote \
  --staging-dir ./staging --live-dir ./live

# 扫描：实际生效哪一份 + 历史目录身份
python3 notice_rollout.py scan --root ./some-history --live-dir ./live \
  --identity-rule 'regex:adv-([0-9]{4}-[0-9]{4})'
```

退出码：`0` 成功；`2` 业务错误（核对失败、阶段不符等）；`3` 模拟崩溃。
