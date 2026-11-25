# Grape Entity：view 条件 → 角色声明 迁移判定方法

本目录是一套**不修改 gem 源码**的最小本地证据集，基于仓库自带 `lib/`（grape-entity 1.1.0）。
运行：

```sh
ruby role_migration/run.rb
# 生成 role_migration/evidence_report.md，并在 stdout 打印同样内容；末尾给出断言数
```

## 1. 先校准真实语义（判定的前提）

源码位置决定了迁移必须遵守的硬约束：

- 条件编译：`Exposure.compile_conditions` 把 `if_extras + if` 展平、`unless_extras + unless` 展平，`if` 全部排在 `unless` 前（`lib/grape_entity/exposure.rb:39`）。
- 短路求值：`Exposure::Base#conditions_met?` 用 `@conditions.all?`（`lib/grape_entity/exposure/base.rb:103`）。第一个为假的条件之后的条件**根本不会被调用**——这是"没有求值"，不是"求值为假"。
- 三类条件读取的都是**实体收到的 options**，与 object 无关，除 block 外：
  - Hash：`options[k.to_sym] == v`，`all?`（`if`）/`any? !=`（`unless`），见 `condition/hash_condition.rb`。
  - Symbol：`options[symbol]` 真值，见 `condition/symbol_condition.rb`。
  - Block：`entity.exec_with_object(options, &block)`，可读 object 和任意 option，见 `condition/block_condition.rb`。
- 继承：`Entity.inherited` 对 `root_exposure` 做 `dup`，子实体拿到整棵 exposure 树的拷贝（`lib/grape_entity/entity.rb:140`）。条件**不会跨字段流动**；子要"继承父门"只能 `override: true` 重声明同名字段，并把该门放进自己的条件链。
- 嵌套选项：`RepresentExposure#value` 与 `NestingExposure` 都走 `Options#for_nesting(key)`（`options.rb:61`）。它 `dup` 整个 options，仅剔除 `:collection`，并重置 `root/only/except/attr_path`。**`role`/`view` 等自定义键原样下传**，所以父子看到同一角色键。

## 2. 角色声明如何编译（不引入新引擎）

`role_migration/role_dsl.rb` 的角色 DSL 只产出 grape-entity 原生条件，因此可在条件级别论证等价：

| 角色声明 | 编译产物 | 对应旧形式 |
|---|---|---|
| `role_if(:admin)` | `{ role: :admin }` → HashCondition | `if: { view: :full }` |
| `role_if(:admin, :staff)` | OR BlockCondition | 旧的多值 view block |
| `role_unless(:guest)` | `{ role: :guest }` 走 `unless` | `unless: { view: :public }` |
| `role_capability(:x)` | 读 `options[:capabilities]` 的 block | `if: :x`（SymbolCondition） |
| `role_if { \|o,opts| ... }` | 任意 block | 旧 view block |

## 3. 迁移判定算法（逐 exposure）

对每个字段的编译后条件链，按顺序回答：

1. **键空间**：每个条件读取的 option 键是否都能由 `options[:role]`（或 role 派生的 capabilities）表达？
   - 出现 `:view / :version / :type / :channel / :region` 等非角色键 → 标记 blocked，除非先建立文档化的 role↔该键映射。
2. **条件类型**：
   - Hash 全是角色键 → 可直接换成 `role_if/role_unless`（同 HashCondition，等价最直接）。
   - Symbol 非角色键 → blocked，除非该标志可由角色推导，再用 `role_capability`。
   - Block → 静态检查其读取来源：只读 `options[:role]` 可迁；读 object 状态或混合键 → 拆分而非替换。
3. **顺序与短路**：迁移后条件链的**首个条件**必须与旧链首个条件对同一组角色/视图给出相同的真假，否则短路点移动，尾随条件的求值时机改变（见对照二）。
4. **继承**：凡是子字段依赖父/重声明门兜底的，迁移后必须在**叶子字段重复最窄显式门**，父门仅作纵深防御，不能是唯一守卫。
5. **嵌套**：确认 `for_nesting` 后子实体仍收到 `:role`（自定义键会下传）；父字段门失败时子实体不会被实例化（证据中 custodian 构造标记）。
6. **等价验收**：对每个角色×视图组合，断言新旧 `serializable_hash` 完全相等，并核对条件调用顺序与子实体 options。

判定器实现：`RoleMigration::MigrationClassifier.classify(exposure)`，输出 `:migratable/:blocked + reasons + rewrite`。

## 4. 三条件 × 父可见性 × 嵌套的共同生效

- 同一 exposure 上多条件是 **AND**（`all?`），顺序为 if 链（`if_extras` 先、`if` 后）再 unless 链。
- `with_options` 的 hash 门与字段级 hash 门经 `merge_options` 合并成一个 Hash；hash 与非 hash 混用时非 hash 进 `if_extras`（`entity.rb:653`）。迁移时要保留这一拼接结构。
- 嵌套 `using:` 字段：先过本字段条件，过了才 `represent` 子实体；子实体内部再用**下传的同一份 options** 独立判定。父门失败 = 子实体连实例化都不发生。
- 继承实体重声明字段：`override: true` 删除继承的同名 exposure 再插入新的，条件链以新声明为准，不会与父 exposure 的条件自动 AND。

## 5. 两个最小例子（证据见 evidence_report.md）

### 对照一：父子都显式角色 → 可直接迁（example_a_direct.rb）

`OldGadgetEntity/NewGadgetEntity` 与 Pro 子类，覆盖 hash/symbol/block、`unless`、`with_options` 合并、嵌套 `using`。
三种角色（admin/staff/guest）下新旧 `serializable_hash` 逐字段相等（6 条 PASS），并打印嵌套 `AuditTagEntity` 实际收到的 options（含 `for_nesting` 注入的 `root/only/except/attr_path`，且保留 `role`）。

### 对照二：子继承旧 view 门、父门提前终止 → 不能 naive 迁（example_b_shortcircuit.rb）

`OldMemoEntity#archive_code` 用数组 `if: [{view: :full}, block]` 让父 view 门居首。auditor（`view: :audit`）下：

- 旧规则：首条 HashCondition 失败 → 短路，block **未求值**，字段隐藏。
- naive 新规则：父门被换成 `role_if(:admin, :auditor)`，auditor 通过 → 顺序改变后尾随 block 被求值且通过，`archive_code` 与 `risk_score` **多露**。
- 修复版 `FixedMemoEntity`：叶子重复最窄 `role_if(:admin)`，三个角色下输出与旧规则完全一致（3 条 PASS）。
- 报告同时区分三类：**多露字段**（判定顺序改变）、**未求值字段**（被短路）、**无条件字段**（`doc_id/internal_note`，本就恒显，与门无关）。
- 父门失败时 custodian 嵌套实体 `constructed? = false`，admin 通过时打印其接到的 options。

## 6. 不能直接迁的声明位置与改写建议

完整机器判定见报告的分类表；源码位置在 `role_migration/blocked_catalog.rb`，人工建议如下：

| 位置 | 卡点 | 改写建议 |
|---|---|---|
| `EntityB1.release_notes` `if:{version:'v2'}` | 无角色轴 | 保留 version 条件，或先建 role↔version 矩阵再换 `role_if` |
| `EntityB1.compat_line` `if:{view:,channel:}` | 两个正交轴 | 拆成角色门 + 独立 channel 条件，用 hash 合并 AND，勿把 channel 塞进角色 |
| `EntityB2.draft_banner` `if: :show_draft` | Symbol 读非角色布尔 | 保留，除非 show_draft 可由角色推导，再用 `role_capability(:show_draft)` |
| `EntityB3.medical_flag` block 读 `object.sensitive?` | 依赖 object 状态 | 保留 block；可**追加**角色门，但不能用角色替换 |
| `EntityB4.combined_field` block 混 role+object | 混合谓词 | 拆为 `if: [role_if(:admin), object_block]`，两条件 AND |
| `EntityB5.internal_ticket` `unless:{channel:}` | unless 读非角色键 | 保留 channel unless，或建模为角色能力；单一角色无法表达 channel 范围 |
| `EntityB6.regional_data` 嵌套 `if:{region:}` | region 与角色正交 | 外层保留 `role_if(:staff)`，叶子保留 `if:{region::eu}` |

## 7. 文件清单

- `role_migration/tracer.rb`：无侵入探针（条件调用顺序、短路、子实体 options）。
- `role_migration/role_dsl.rb`：角色 DSL + `MigrationClassifier` 判定器。
- `role_migration/example_a_direct.rb`：可直接迁的父子/嵌套对照。
- `role_migration/example_b_shortcircuit.rb`：继承门 + 父门短路（naive 陷阱 + 修复）。
- `role_migration/blocked_catalog.rb`：不可迁声明目录与改写指引。
- `role_migration/run.rb`：运行器与 10 条等价性/陷阱断言。
- `role_migration/evidence_report.md`：生成的证据报告。
