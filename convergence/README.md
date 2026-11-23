# Casbin 服务账号访问面收敛（带前提校验的本地计划）

用 pycasbin 在 RBAC 模型上对几组服务账号做最小权限收敛。核心是把“目标状态”
编译成一份**可审计、带前提（precondition）的本地计划**：计划落盘前不修改任何策略，
应用前必须确认它依赖的其他策略没有变化；另一份审批若先落地、改变了判断依据，计划会
被拒绝并要求重新评估，而不是基于过期假设强行写入。

## 目录结构

- `model.conf` — 标准 RBAC 模型（`g(r.sub, p.sub)` + obj/act 精确匹配）。
- `state/policy.baseline.csv` — 基线策略，`p,` 为权限规则、`g,` 为角色边。
- `plans/plan_a.targets.json` / `plan_b.targets.json` — 两份**同时审核**的目标规格。
- `engine.py` — 策略解析、规范化指纹（sha256）、内存 enforcer、API 决策 diff。
- `planner.py` — 目标状态 → 计划（失效项 / 必留项 / 翻转决策 / 前提 / 作用域）。
- `applier.py` — 前提校验、范围冲突判定、rebase、受保护的落盘。
- `converge.py` — CLI：`plan` / `show` / `apply` / `verify` / `rebase`。
- `run_demo.sh` — 一键端到端演示；`test_convergence.py` — 行为测试。

## 计划如何表达“失效 / 必留”

- `losing_effect`：将失去作用的角色边（`g`）或权限规则（`p`），附原因。
- `must_retain`：目标状态下必须保留的边/规则，并标注保留原因。
- `ineffective_retained_permissions`：保留下来但已无任何入边可达的 `p` 规则
  （例如移除 svc_ops 后 `role_admin` 的规则变为不可达），提示后续可清理。
- `decision_changes`：用真实 pycasbin enforcer 计算的 API 决策翻转，格式
  `sub obj act BEFORE -> AFTER`（本场景均为 `ALLOW -> DENY` 的收敛）。

## 前提校验：依赖的其他策略是否变了

每份计划记录：

- `baseline_fingerprint`：基线全部 `p`/`g` 规则的规范化哈希；
- `premises.assume_unchanged`：计划判断所依赖、必须保持不变的规则；
- `premises.assume_removable`：计划预期仍存在、可被自己删除的规则；
- `scope`：按**账号/角色归属**界定的作用域（管理的 subjects、managed_roles、
  in_scope_rules）。

应用时 `applier.check_preconditions` 区分两类情况：

- **范围内阻断冲突**：本计划管理的依赖被另一份变更改动，或本计划要删的规则已被删除
  → 拒绝应用，`rebase` 也硬阻断，必须人工介入。
- **范围外前提漂移**：变动落在本计划作用域之外（典型：并行的另一份计划先落地）
  → 指纹不匹配且依赖前提失效，计划被标记 `needs_reevaluation`，退出码 2；
  确认自身规则未受影响后，可用 `rebase` 基于现状重新评估生成新基线再应用。

任何阻断情况下都不会写策略文件。

## 两份并行计划

- **Plan A（svc_ops 全面去权）**：删除 `svc_ops` 的 3 条角色边
  （role_admin / role_etl / role_billing），7 个 API 决策 `ALLOW -> DENY`。
- **Plan B（三个 worker 账号最小权限）**：删除 4 条 `p` 规则
  （reports.export、etl datasets.write/backup.read、billing invoices.read），
  4 个 API 决策 `ALLOW -> DENY`，保留各账号的角色边。

两者删除作用域互不相交，但 Plan B 把 `svc_ops` 的角色边当作“保留依赖”。先执行 A 后，
B 的该前提在范围外失效，因此 **B 必须重新评估**；rebase 到 A 之后的现状，B 自身的
4 条 `p` 规则仍在，重评后可安全应用，最终策略等于两个目标状态的并集。

## 用法

```sh
# 构建两份本地计划（同一基线、同时审核）
../.venv/bin/python converge.py plan plan_a --name "De-escalate svc_ops" --targets plans/plan_a.targets.json
../.venv/bin/python converge.py plan plan_b --name "Least-privilege workers" --targets plans/plan_b.targets.json

# 应用前确认依赖策略未变（--json 输出机读结果；退出码 2 = 需重新评估）
../.venv/bin/python converge.py verify plan_b --current state/policy.live.csv --json

# 受保护地应用（前提不满足则拒绝且不写文件）
../.venv/bin/python converge.py apply plan_a --current state/policy.baseline.csv --output state/policy.live.csv --json

# 范围外漂移后基于现状重新评估，再应用
../.venv/bin/python converge.py rebase plan_b --current state/policy.live.csv --targets plans/plan_b.targets.json

# 一键演示 / 测试
bash run_demo.sh
../.venv/bin/python -m pytest -q -o addopts= test_convergence.py
```
