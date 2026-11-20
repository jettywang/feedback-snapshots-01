# 通用授权表 → 直接外键表迁移方案评审

评审对象：django-guardian 当前代码（`guardian/`）与测试模型（`guardian/testapp/models.py`）。
配套可运行核对脚本：`migration_review/verify_switch.py`（`.venv/bin/python migration_review/verify_switch.py`）。

## 1. 读路径何时切到新表

Guardian 没有中央开关。每个模型的读路径在调用时由 `get_obj_perms_model`（guardian/utils.py:454）动态解析，**同时满足以下 5 个条件的那一刻起即开始读新表**：

1. 目标模型的反向关系中存在 `UserObjectPermissionBase` / `GroupObjectPermissionBase` 子类（即直连模型已注册、已建表）；
2. 该模型不是配置里的通用模型（`GUARDIAN_USER_OBJ_PERMS_MODEL` / `GUARDIAN_GROUP_OBJ_PERMS_MODEL`）；
3. `getattr(model, "enabled", True)` 为真 —— **这是内置的逐模型暂停杆**；
4. `model.objects.is_generic()` 为假；
5. `get_content_type(obj) == get_content_type(fk.remote_field.model)`（内容类型守卫，guardian/utils.py:472）。

任一不满足则静默回退通用表。因此"何时开始读新表"的答案是：**直连模型类上线且 `enabled` 为真、内容类型匹配时立即切换，逐模型生效，无灰度批次概念**。要控制时点，就把直连模型以 `enabled = False` 部署，回填核对通过后再翻为 `True`。

### 评审发现（读路径风险）

- **写路径同步切换**：`assign_perm` / `remove_perm`（guardian/shortcuts.py:172、guardian/shortcuts.py:240）用同一解析函数。启用直连后新授权只写新表，且 `remove_perm` 只删新表 —— 若通用表残留同义旧行未清理，将出现"删不掉的权限"。**回填完成与通用表旧行清理必须纳入同一切换窗口**。
- **AUTO_PREFETCH 与单点查询口径不一致**：`_prefetch_cache`（guardian/core.py:299）对通用表 + 所有 enabled 直连表取**并集**，而非预取路径只查**单表**。迁移窗口内两条路径可能对同一用户给出不同答案（预取路径掩盖丢失、或复活已删授权）。建议迁移窗口内关闭 `GUARDIAN_AUTO_PREFETCH`，或保证回填与清理在同一发布内原子完成。
- **内容类型守卫是静默回退**：若项目自定义 `GUARDIAN_GET_CONTENT_TYPE` 为代理感知（proxy-aware），条件 5 失配会静默读通用表，表现为"迁移后权限没丢但新表永远是空的"。预检必须显式覆盖，不能依赖运行时报错。

## 2. 权限差异报告的计算方式

定义有效权限集（与 `ObjectPermissionChecker.get_perms` 语义一致）：

```
E(subject, obj) = 用户直授(subject=User) ∪ 组授权展开(subject=User 时取其 groups 的组授权)
```

- **快照**：切换前、后分别对全部 (subject, obj) 计算 `E`。subject 覆盖每个用户与每个组；obj 覆盖每个目标模型的全部实例（核对脚本用 `ObjectPermissionChecker` 实算，等价于逐对象 `get_perms`）。
- **差异**：`REMOVED = E_before − E_after`（权限丢失，阻断上线）；`ADDED = E_after − E_before`（权限误增，安全敏感，同样阻断）。报告行为 `(状态, subject, obj, perm)`，空报告为通过条件。
- **归一化要点**（差异报告误报/漏报的三个来源）：
  - `object_pk` 是 `CharField(255)`（guardian/models/models.py:56），读路径用 `str(obj.pk)` 匹配。UUID 主键必须经 `pk_field.to_python(object_pk)` 归一成连字符形式再比对，否则十六进制无连字符的历史行会被漏判；
  - 代理模型按默认 `get_for_model`（for_concrete_model=True）归入具体模型的内容类型，核对时要用代理实例与具体实例各算一次；
  - 组授权必须展开到成员用户再比对，否则"组表漏迁"只在组维度可见、用户维度漏报。

## 3. 切换与回退顺序

### 切换（每模型一批，可并行但各自独立核对）

1. 部署含直连模型的代码，`enabled = False`（读、写仍走通用表）；
2. `migrate` 建新表；
3. **预检**（任一命中即暂停，见第 4 节）：缺失内容类型、object_pk 格式漂移、目标对象已不存在的孤儿行；
4. 数据修复后取**基线快照** `E_before`（修复后再取，基线即承诺保持的状态）；
5. 回填：通用表 → 直连表，主键经 `to_python` 归一，`get_or_create` 幂等；
6. `enabled = True` 发布，取 `E_after`，差异报告为空才放行；
7. 观察期后删除通用表中已迁移模型的旧行，并恢复 `GUARDIAN_AUTO_PREFETCH`。

### 回退

- **清理旧行之前**（步骤 6 之前/当天）：`enabled = False` 即完成回退，零数据移动 —— 通用表旧行原样保留，读路径立即恢复。核对脚本 phase A 演示了此场景：回填漏了 UUID 模型的组表 → 差异报告检出 `REMOVED user:alice / group:editors uuid:u1 view_uuidpkmodel` → 回退后差异归零 → 补回填 → 再切换通过。
- **清理旧行之后**：回退前需把直连表反向回填通用表（新表是切换后唯一写入点），再 `enabled = False`。
- 窗口内的新增授权只写新表，回退前必须同步，否则回退即丢权。

## 4. 缺失内容类型实例：怎样暂停切换

实例（核对脚本 preflight 1/2 实演）：通用表存在一行 `UserObjectPermission(pk=4, content_type=legacy.ghost, object_pk='1')` —— `legacy.ghost` 的模型类已删除，`ContentType.model_class()` 返回 `None`。该行无法映射到任何直连表。

暂停动作：

1. 预检逐行解析通用表两表的 `content_type`，`model_class() is None` 即命中；
2. **保持所有直连模型 `enabled = False`**（读路径不变，线上零影响），输出待处理清单 `(表, pk, app_label.model, 原因)`；
3. 处置（本例：确认模型已废弃，删除孤儿行；若模型将恢复，则等恢复后再迁）；
4. 重跑预检为空，才允许进入回填与 `enabled = True`。

同类暂停项还有 object_pk 格式漂移（preflight 2/2 实演）：`object_pk='46769ccb…4ef924'`（无连字符 UUID）在通用表语义下是**死行**（读路径查连字符形式，永不命中）；若回填时静默归一，切换后该权限会**凭空生效**（差异报告表现为 `ADDED`）。正确做法是暂停切换，把归一化作为独立的、经审批的数据修复在基线快照**之前**落到通用表，再继续流程。

## 5. 核对脚本覆盖矩阵

`migration_review/verify_switch.py` 在内存 SQLite 上实跑完整流程：

- UUID 主键（`UUIDPKModel` + 运行时直连模型，含无连字符历史行）；
- 代理模型（`ProjectProxy`，验证代理实例读到同一直连表）；
- 组授权（`editors` 组 → alice 的有效权限展开）；
- 缺失内容类型暂停（`legacy.ghost`）；
- 不完整回填的差异检出与 `enabled=False` 回退；
- 完整回填后切换，差异报告为空。
