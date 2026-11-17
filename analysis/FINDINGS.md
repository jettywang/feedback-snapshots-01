# `observed-data` 返回值语义核查：存在性 / witness / 完整枚举

所有结论均由 `analysis/` 下可运行脚本的真实输出支撑（`python -m analysis.expN_xxx`）。
库版本为本仓库 `stix2matcher/matcher.py`，STIX 2.0。

## 0. 先厘清库到底返回什么

匹配在库内部等价于求一组 **binding**：把模式里每个 observation expression
绑定到一个观测（observed-data SDO），使全部约束成立。关键点：

- 内部单元是 **binding 元组**，不是“命中的观测列表”。元组每个位置对应模式中的一个
  observation expression；该位置可能是观测下标，也可能是 `None`（该分支无需绑定）。
  见 `matcher.py:1197` `matched()`。
- 公开 API `match()` / `Pattern.match()` 只取**第一个 binding**，再解析成 SDO 列表：
  “returns the SDOs corresponding to only the first binding found”
  （`matcher.py:2473`、`matcher.py:2496`）。
- 因此业务把返回的 observed-data 当作“所有命中该指标的观测”，在一般情况下不成立。
  它最多是 **一个充分 witness**，不是完整命中集合。

业务的三种诉求必须分开：

| 诉求 | 问题 | 库能否回答 | 入口 |
|---|---|---|---|
| (E) 存在性判断 | 模式是否成立（布尔） | 能，且完备可靠 | `next(matched(), None) is not None` |
| (W) 一个充分 witness | 给一组能证明成立的 SDO | 能，但非唯一、非穷尽、顺序相关 | `match()` |
| (N) 完整命中枚举 | 给出每一个命中的观测 | **不能直接给**；只能给“已生成 binding 的并集”，覆盖受限 | 遍历 `matched()` 后自行并集去重 |

## 1. OR：单侧 binding 优化（这是“短路”的真实形态）

实现位于 `exitObservationExpressionOr`（`matcher.py:1392`）。OR 被实现成
**outer join，只产生单侧 binding**：LHS 命中时 RHS 填 `None`，反之亦然；
**永不产生两侧同时绑定的元组**。代码注释明确：

> Result bindings with values from both LHS and RHS are not included, to
> improve scalability (`matcher.py:1401`)
> I made the conscious decision to skip some bindings ... without affecting
> correctness (`matcher.py:1048`)

实测 `exp1_or.py`，模式 `[name='alice'] OR [age<20]`，alice 同时满足两支、bob 仅满足右支：

```
(0, None)      # alice 走左支
(None, 0)      # alice 走右支（同一 SDO，换了分支）
(None, 1)      # bob 走右支
two-sided bindings present: []   # exp5_full_enum.py，结构上不存在 (0,0)
```

这个优化在什么语义下成立：

- **对存在性 (E) 完备成立。** 只要存在任何满足赋值，就至少存在一个单侧赋值；
  双侧绑定对“OR 是否成立”没有额外贡献，所以不会产生 false negative。
- **对 witness (W) 成立。** 任一单侧元组本身就是合法证据。
- **对完整枚举 (N) 不成立。** 并集只能回答“哪些 SDO 至少满足一支”，
  **丢失了“某 SDO 满足了哪几支”**，且结构上拿不到双侧赋值。

### 关于“不要简单关闭短路就宣称全量正确”

`exp5_full_enum.py` 证明：关掉单侧优化不是“把已存在但被隐藏的元组露出来”，而是
**改变 binding 的基数**——需要新生成 `(0,0)` 这类双侧赋值，并连带改变 AND/FOLLOWEDBY
的 `_disjoint` 组合空间。即便如此，OR 的“完整命中”仍有歧义：是以 **分支赋值**
为粒度（alice 产生 left、right、both 三个命中）还是以 **SDO** 为粒度（alice 只算一个）。
库没有选择其中任何一种作为契约，因此调用方不能通过“关掉优化”获得一个有定义的全量结果。

## 2. 重复（REPEATS / number_observed）：实例粒度与去重粒度是两回事

### 2.1 实例展开

简单表达式先按 `number_observed` 展开成带实例号的复合 id
`(obs_idx, inst_idx)`，`inst_idx` 取 `0 .. number_observed-1`
（`matcher.py:1560-1561`，`create_instance_id`）。

### 2.2 顺序无关组合（不是排列）

REPEATS 用 `_filtered_combinations` 只求**互不相交的、顺序无关的组合**，
不求全排列（`Notes.md:29`；`matcher.py:810`）。组合之间通过 `_disjoint`
保证不重复消费同一实例。

### 2.3 `matched()` 的折叠会产生重复元组（关键契约点）

`matched()` 通过 `get_obs_index_filtered` 把 `inst_idx != 0` 的实例**折叠成 `None`**
（`matcher.py:1251-1263`，核心判断 `matcher.py:1263`）。实测
`exp2_repeat.py`，一个 `number_observed=3` 的 SDO + 三个单实例 SDO，
`REPEATS 3 TIMES`：

```
raw (obs,inst) bindings  : 20   # 全部唯一
collapsed tuples         : 20
unique collapsed tuples  : 14
duplicate tuples after collapse: 6
distinct sdo index union : [0,1,2,3]
```

即：底层 20 个互不相同的**实例级** binding，折叠到 **SDO 粒度**后只有 14 个不同元组，
**出现 6 个重复元组**。因此：

- 去重粒度的明确契约是 **observed-data SDO 下标**，不是实例，更不是 cyber-observable 内层对象。
- 同一 SDO 的 N 个实例在 `matched()` 输出里只计一次（其余变 `None`）；
  调用方若要“去重后的 SDO 集合”，**必须自己再做一次 `set()`**，不能假设元组唯一。
- 若业务需要实例级（multiset）计数，必须在折叠前读取内部栈的 `(obs_idx,inst_idx)`，
  公开 API 拿不到；这属于使用内部实现，升级不保证稳定。

## 3. 复合表达式 AND / FOLLOWEDBY：`_disjoint` 决定跨 SDO 约束

- AND（`matcher.py:1483`）与 FOLLOWEDBY（`matcher.py:1279`）都用 `_disjoint`
  （`matcher.py:585`）要求不同分支绑定到**不同观测**，`None` 忽略。
- 实测 `exp3_compound.py`：两个 SDO 各自同时含 network-traffic 和 email-addr 两类内层对象，
  模式 `[network-traffic...] AND [email-addr...]` 只产出 `(0,1)` 与 `(1,0)`，
  **不会**因为单个 SDO 内有两类对象就产出 `(0,0)`。内层“同一 SDO 内多对象”的命中
  由 comparison 层的 cyber-observable root 集合处理，observation 层仍强制跨 SDO 不相交。
- FOLLOWEDBY 在不相交之外再叠加时间序约束，实测只剩 `(0,1)`（Jan 先于 Feb）。
- 含义：复合表达式下，witness 的 SDO 列表是“满足整条联合约束的一组 SDO”，
  把它拆开当成“每个子指标各自的完整命中”是错误的。

## 4. 两个同为真的绑定，为何信息不同（实测对照）

### 4.1 witness 随输入顺序翻转（`exp4_witness.py`）

单比较 `[indicator:name='hit']`，两个 SDO（alpha confidence=10、gamma confidence=90）都命中：

```
input order [alpha, gamma] -> witness = alpha(10)
input order [gamma, alpha] -> witness = gamma(90)
```

模式与真值完全相同，仅输入顺序不同，公开 `match()` 报告的 SDO 就翻转。
说明返回值是“某一个充分 witness”，其身份受输入/分支顺序影响，**不是规范唯一答案**。

### 4.2 OR 下两个等真 binding 只暴露其一（`exp1` / `exp6`）

`[name='alice'] OR [name='carol']` 引擎生成 `(0,None)` 与 `(None,2)` 两个 binding，
`match()` 只返回 alice；carol 同为真却不出现在 witness 中。
遍历全部 binding 取并集才能同时看到 `{A, C}`（见 `exp6_api_demo.py` 的 N 列）。

## 5. 给调用方的接口建议与覆盖限制

参考实现：`analysis/contract_api.py`（三个显式命名的函数，不让类型假装全量）。

- `matches(pattern, obs) -> bool`：存在性。唯一在所有 OR/重复/复合结构下都可靠的语义；
  适合告警触发、规则命中与否的判定。
- `witness(pattern, obs) -> list[SDO]`：单个充分 witness（封装公开 `match()`）。
  契约写明：用于举证/下钻，**不得**把“不在列表里”解释为“未命中”；结果顺序相关、非穷尽。
- `matched_sdo_index_set(pattern, obs) -> set[int]`：遍历 `matched()` 后按 **SDO 下标**
  并集去重得到的覆盖集合。适合优先级排序、排查范围收敛，**不适合**要求完备性的合规/审计断言。

覆盖限制（须写进调用方契约）：

1. OR 仅单侧 binding：结果是“至少满足一支的 SDO 集合”，无 per-branch 命中映射，无双侧赋值。
2. 去重粒度恒为 observed-data SDO；`number_observed` 的多实例折叠为 1，
   且 `matched()` 可能产出重复元组，调用方需 `set()` 去重；实例级 multiset 公开 API 不提供。
3. 该集合是**部分 binding 空间**的并集，嵌套 OR/限界组合下不保证等于逻辑上的“全部满足观测”，
   禁止据此做“确认无遗漏”类结论。
4. AND/FOLLOWEDBY 的列表是联合约束下的一组 SDO（含不相交/时间序），不可按子指标拆分解读。
5. 若确需严格全量枚举，正确做法是在调用方明确**命中粒度契约**（分支赋值 vs SDO vs 实例），
   并改造引擎显式产出该粒度结果；仅关闭单侧短路不足以得到有定义的全量语义。

## 6. 复现实验清单

```
python -m analysis.exp1_or            # OR 单侧 binding、三支 OR
python -m analysis.exp2_repeat        # REPEATS 实例展开 / 组合 / 折叠重复
python -m analysis.exp3_compound      # AND / FOLLOWEDBY 的 _disjoint
python -m analysis.exp4_witness       # 两个等真绑定信息不同、顺序相关
python -m analysis.exp5_full_enum     # 关闭短路为何不等于全量
python -m analysis.exp6_api_demo      # 三语义适配接口的真实输出
```

## 7. 测试基线说明

`pytest stix2matcher/test/v20`：435 passed，18 failed。18 个失败全部位于
`test_temporal_qualifiers.py`，抛 ANTLR `InputMismatchException`，是锁定依赖
`stix2patterns` 语法版本与本仓库测试不匹配的**既有基线问题**；本次改动仅新增未跟踪的
`analysis/` 目录，未修改库代码，与该失败无关。OR/AND/repeat/complex 相关测试全部通过。
