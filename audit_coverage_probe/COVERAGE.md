# django-auditlog 全量注册 + 单模型规则：审计覆盖核对

环境：Django 5.2 / django-auditlog(本仓库源码，`auditlog/registry.py:352` 的 `register_from_settings`)。
探针应用：`audit_coverage_probe/`(`settings.py` 开 `AUDITLOG_INCLUDE_ALL_MODELS=True`，
排除 `probe.Excluded`，并对 `probe.Secret` 用 `AUDITLOG_INCLUDE_TRACKING_MODELS` 设 `exclude_fields=["password"]`)。

## 如何执行核对

```bash
cd audit_coverage_probe
../.venv/bin/python -m django makemigrations probe --settings=settings
../.venv/bin/python -m django migrate --settings=settings --run-syncdb
../.venv/bin/python run_probe.py     # A 注册表 / B 信号 / C 行为 / D 运行时 / E 汇总
```

三层可观察信号，逐层比对即完成一次覆盖评审：

1. **注册表层** `auditlog.get_models()` / `auditlog.contains(Model)` —— 声明的覆盖范围(脚本 A 段)。
2. **信号层** `post_save.receivers` 中 `lookup_key[1] == id(Model)` 的精确连接数 —— 实际接线(脚本 B 段)。
   注意不要用 `Signal._live_receivers(sender)`，它把 `sender=None` 的接收器也算进来，无法区分。
3. **行为层** 在事务里做 CUD / m2m 操作后查 `LogEntry` —— 真实产出(脚本 C 段)。

## 覆盖表(每格对应 run_probe.py 的可观察输出)

| 场景 | 注册表(A) | 信号连接(B) | 实际记录(C) | 证据 |
|---|---|---|---|---|
| 普通模型 create/update/delete | 在册 | 各 1 个 receiver | 各 1 条，action=create/update/delete | 条目 [1][2][3],ct=probe.item |
| `QuerySet.update()` / `bulk_create` / raw save | 在册 | 有连接 | **0 条**(不触发模型信号) | "Item queryset.update" → 0 条 |
| 代理模型经代理保存 | 在册(proxy=True) | 代理类各 1 个 receiver | 1 条，**ct 落到具体模型** probe.item，无双写 | 条目 [4][5] |
| MTI 子类 create/update | 父子均在册 | 各 1 个 receiver | 1 条 ct=probe.child,diff 含父表字段 | 条目 [6][7] 含 base_field |
| MTI 子类 delete | 父子均在册 | 各 1 个 receiver | **2 条**:ct=probe.child + ct=probe.base | 条目 [8][9] |
| m2m add/remove/clear | 父模型在册且 m2m_fields 自动推导 | m2m_changed 接在 through 上 | 父模型 1 条 action=update,changes 为 `{'tags': {'type':'m2m','operation':...}}` | 条目 [12][13] |
| 自动 through 模型直接 CUD | **在册**(include_auto_created=True) | 有连接 | **永远 0 条**:Django `save_base`/Collector 对 `auto_created` 模型不发信号 | `Through.objects.create` → 0 条(死注册) |
| 排除模型 CUD | 不在册 | 0 个 receiver | 0 条 | "Excluded ..." → 0 条 |
| 单模型规则(dict) | 在册，配置被 dict **整体替换** | 各 1 个 receiver | changes 不含 password | 条目 [14][15];A 段 exclude_fields=['password'] |
| 运行时新建模型(ready 之后) | **不在册** | 0 个 receiver | 0 条 | D 段注册前 contains=False |
| 运行时 `auditlog.register()` 后 | 在册 | 有连接 | 正常记录 | D 段条目 [17] |
| `auditlog.unregister()` 后 | 不在册 | 连接断开 | 0 条 | D 段最后一组 → 0 条 |

## 关键结论

- **注册顺序**:`INCLUDE_ALL` 循环先跑，`INCLUDE_TRACKING_MODELS` 后跑且先 `unregister` 再 `register`
  (`registry.py:262-278`)。所以同一模型同时出现在排除和包含里时，**包含赢**；dict 规则会**整体替换**
  全量注册的默认配置——全量注册自动推导的 `m2m_fields` 会丢失，需要手写。
- **代理模型**会被 `apps.get_models()` 枚举到并注册；经代理保存只记 1 条，ContentType 记具体模型。
  评审时按具体模型归集记录即可，不要指望 `ct=proxy`。
- **MTI**:create/update 只记子类一条(父表字段并入子类 diff);delete 记父子两条。统计"每个模型一条"
  的覆盖假设在删除路径上不成立。
- **through 死注册**:through 在注册表里但 Django 不给 `auto_created` 模型发信号，覆盖判断不能只看
  `contains()`。m2m 的真实覆盖来自父模型的 `m2m_fields` + `m2m_changed`。
- **默认排除**:`auditlog.LogEntry` 和 `admin.LogEntry` 始终排除(`registry.py:32`);`managed=False`
  模型被跳过(`registry.py:362`)。
- **噪音面**:`INCLUDE_ALL` 把 `contenttypes.ContentType`、`auth.Permission` 等也纳入。运行时新增模型
  会连带产生 contenttype 审计记录(D 段条目 [16])。上线前建议把 `contenttypes.ContentType`、
  `auth.Permission`、`sessions.Session` 加进 `AUDITLOG_EXCLUDE_TRACKING_MODELS`。

## 运行时注册的模型如何判断范围

`register_from_settings()` 只在 `AuditlogConfig.ready()` 跑一次(`apps.py:13`)。之后动态创建的模型
默认**不在**覆盖范围。评审/上线前核对按三步走：

1. **查注册表**:`auditlog.contains(Model)`。为 False 且模型是在 ready 之后出现的，即为漏网。
2. **验信号**:对 `post_save/pre_save/post_delete` 检查 `lookup_key[1] == id(Model)` 的 receiver 数；
   并检查 `Model._meta.auto_created`(through 死注册)与 `managed`(不迁移不注册)两个例外。
3. **行为抽检**:在测试事务里对该模型做一次 create+delete，按 ContentType 查 `LogEntry` 增量。

纳入方式二选一，均已验证有效：

- 显式 `auditlog.register(LateModel)`(可带 include/exclude/m2m_fields 等规则);
- 或再次调用 `auditlog.register_from_settings()`——它按调用时刻的 `apps.get_models()` 重新枚举，
  幂等(`dispatch_uid` 去重 + include 项先 unregister 再 register)，能把运行时模型补进全量注册。

撤销用 `auditlog.unregister(Model)`，会同步断开信号(D 段验证)。
