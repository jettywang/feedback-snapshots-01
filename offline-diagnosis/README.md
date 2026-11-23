# 离线诊断与验收说明 — “无法确认”策略的两种根因

适用评审：同一 CloudFormation 模板中多条 IAM 策略显示“无法确认”。
结论先行：这些“无法确认”不是安全通过。校验器对两种状态都抛出 `ApplicationError`，
经 `main.py` 捕获后向 stderr 打印 `ERROR: ...` 并以 **退出码 1** 结束，
绝不会走到 `exit(0)` 的干净通过路径，也不会产出空 `BlockingFindings` 的通过报告。
已能独立解析出授权结果的资源不受影响，其策略 JSON 仍可作为证据保留。

本目录全部离线可复现，无需 AWS 凭证、网络或 IAM Access Analyzer 调用。

## 1. 交付物

- `diagnostic-template.yaml`：现场模板的最小复现，含 3 个角色，分别覆盖
  引用成环、资料不足、可独立解析（对照证据）三种情况。
- `diagnose.py`：驱动校验器**真实调用链**的离线诊断脚本，按角色输出确定结论。
- `output-no-params.json`：不传参数运行的结果（两个根因同时出现）。
- `output-with-param.json`：补齐参数后运行的结果（资料不足恢复，环仍在）。

运行方式（仓库根目录，使用随仓 `.venv`）：

```sh
AWS_EC2_METADATA_DISABLED=true \
  .venv/bin/python offline-diagnosis/diagnose.py \
  --template-path offline-diagnosis/diagnostic-template.yaml

# 补齐缺失参数，验证“资料不足”可恢复
AWS_EC2_METADATA_DISABLED=true \
  .venv/bin/python offline-diagnosis/diagnose.py \
  --template-path offline-diagnosis/diagnostic-template.yaml \
  --parameters BucketScope=audit-logs
```

脚本输出的 `safe_passes` 恒为 `0`，并把每个角色归入下列之一：
`CONFIRMED`（已解析、可作证据）、`UNCONFIRMED_CYCLE`（引用成环）、
`UNCONFIRMED_NO_DATA`（资料不足）、`UNCONFIRMED_OTHER`（其它硬错误，同样不算通过）。

## 2. 校验器实际调用链（判断依据）

模板加载与引用解析的真实路径：

1. `cfn_tools/cfn_loader.py:17` `load()` 构造 `NodeEvaluator` 并装配模板节点。
2. 角色解析时 `parsers/identity.py:161` `RoleParser.parse()` 调用
   `resource.eval(roles_schema)`，进入 `cfn_tools/cfn_object.py:39` `CfnObject.eval`。
3. `parsers/utils/node_evaluator.py:97` `NodeEvaluator.eval` 按首键分派到
   `Ref` / `Fn::GetAtt` / `Fn::Sub` 等求值器（分派点 `node_evaluator.py:124`）。
4. 资源先经 `parsers/utils/topological_sorter.py:23` `sort_resources()` 做依赖排序，
   但排序只决定处理顺序，**不消除属性内部的递归引用环**；环在求值阶段才被发现。
5. 求值器在“进入某资源的某个属性做递归求值”前调用
   `parsers/utils/cycle_detection.py:8` `validate_no_cycle()`，
   用 `(resource_name, property_name)` 组成的 `VisitedNode` 列表检测重入。

关键区别就在第 5 步之后走哪条分支：

- **重入了已访问节点** → `cycle_detection.py:16` 抛
  `Cycle detected for {resource} and {property}.`，这是**引用成环**。
- **节点不重入，但查找落空** → 求值器各自抛 `ApplicationError`，这是**资料不足**。

## 3. 根因一：引用成环（可复核的环路径）

### 3.1 判定特征

错误信息以 `Cycle detected for ` 开头，来源唯一：
`cycle_detection.py:16`。调用入口有三处，均在递归求值前做重入检查：

- `fn_get_att_evaluator.py:77`（显式名称属性上的 `Fn::GetAtt`）
- `fn_get_att_evaluator.py:117`（回退到同名属性的 `Fn::GetAtt`）
- `ref_evaluator.py:98`（名称提示属性上的 `Ref`）

### 3.2 现场模板中的环（可逐步复核）

`RoleRingA.RoleName = !Ref RoleRingB`，`RoleRingB.RoleName = !Ref RoleRingA`，
且 `RoleRingA` 的策略资源为 `!GetAtt RoleRingB.Arn`。求值 `RoleRingA` 时：

```
GetAtt RoleRingB.Arn
  -> 进入 RoleRingB.RoleName (Ref RoleRingA)
     -> 进入 RoleRingA.RoleName (Ref RoleRingB)
        -> 再次需要 RoleRingB.RoleName  <- 节点重入，validate_no_cycle 抛错
```

脚本通过包装 `validate_no_cycle` 记录重入瞬间的 `VisitedNode` 链，
在 `output-no-params.json` 中给出可复核的 `cycle_path`：

```
[["RoleRingB","RoleName"], ["RoleRingA","RoleName"], ["RoleRingB","RoleName"]]
```

首尾节点相同即闭合环；值班可按该序列在模板里逐跳核对。
两个角色分别报 `Cycle detected for RoleRingB and RoleName.`
与 `Cycle detected for RoleRingA and RoleName.`，均为 `UNCONFIRMED_CYCLE`。

### 3.3 处置

环是模板结构性缺陷，**补参数无法消除**（见 `output-with-param.json`，环依旧）。
需修改模板打断引用环（让至少一个名称/ARN 引用改为字面量或不回指），
重新解析通过前，这两个角色不得判为安全。

## 4. 根因二：资料不足（只点到缺失的那一步）

### 4.1 判定特征

节点没有重入，而是查找落空，由求值器直接抛出。可识别的信息签名：

- `No value passed for referenced parameter: X.`
  —— `ref_evaluator.py:107`，模板里有该参数但未传值。
- `Unable to find a referenced resource or parameter in template: X.`
  —— `ref_evaluator.py:112`，引用的逻辑名在 Resources/Parameters 中都不存在。
- `Unable to find referenced resource for GetAtt reference to X.Attr`
  —— `fn_get_att_evaluator.py:64`，`Fn::GetAtt` 指向不存在的资源。
- `Fn::FindInMap lookup failed...` —— 映射表缺键。

### 4.2 现场模板中的缺失点

`RoleNeedsParam` 的策略资源 `!Sub "arn:aws:s3:::${BucketScope}/*"` 引用参数
`BucketScope`，但运行时未提供值。调用链在 `RefEvaluator.evaluate`
（`ref_evaluator.py:38`）走到参数分支：参数对象存在，而
`parameter_values.get('BucketScope')` 为 `None`，于是在 `ref_evaluator.py:107`
抛 `No value passed for referenced parameter: BucketScope.`。

诊断**只点到这一步**：缺的是 `BucketScope` 的入参值，
不臆测其内容、不假设默认值、不据此放行。

### 4.3 处置与可恢复性

资料不足是**输入缺口而非结构缺陷**，补齐即可恢复：

```sh
--parameters BucketScope=audit-logs
```

`output-with-param.json` 显示 `RoleNeedsParam` 转为 `CONFIRMED`，
资源被解析为 `arn:aws:s3:::audit-logs/*`。恢复后仍须对解析出的实际策略再做
安全评审；在补齐并复核之前，该角色保持 `UNCONFIRMED_NO_DATA`，不得判为安全。

## 5. 受影响角色与可恢复证据

| 角色 | 状态 | 根因 / 缺失点 | 可恢复证据 |
| --- | --- | --- | --- |
| `RoleRingA` | `UNCONFIRMED_CYCLE` | 与 `RoleRingB` 经 `RoleName`/`Arn` 互相回指成环 | 无（结构未修复前不可解析） |
| `RoleRingB` | `UNCONFIRMED_CYCLE` | 同一环的对侧节点 | 无（结构未修复前不可解析） |
| `RoleNeedsParam` | `UNCONFIRMED_NO_DATA` | 缺参数 `BucketScope` 的值（`ref_evaluator.py:107`） | 补参后恢复，见 `output-with-param.json`，资源解析为 `arn:aws:s3:::audit-logs/*` |
| `RoleClean` | `CONFIRMED` | 无未决引用，独立解析 | 内联策略 `StaticRead`：`s3:ListBucket` on `arn:aws:s3:::static-evidence-bucket`，可直接作证据 |

说明：`RoleClean` 与环、缺参均无引用关系，其授权结果独立成立，
即使其它角色无法确认，该角色的策略 JSON 仍作为有效证据保留并参与后续评审。

## 6. 为什么两种状态都不是“安全通过”

- 二者都抛 `ApplicationError`，被 `main.py:279-281` 捕获，
  向 stderr 输出 `ERROR: ...` 并 `exit(1)`。
- 干净通过是 `exit(0)`（`main.py:46/58/71/83/96`），
  仅在成功解析且无阻断发现时到达；硬错误在解析阶段就中断，到不了该分支。
- 阻断发现（Access Analyzer 报错/告警）走的是 `exit(2)`，与 `exit(1)` 的
  解析期硬错误互斥但同样非通过。
- 因此值班判读规则：看到 `exit(1)` + `ERROR:` 即“无法确认”，
  按本说明区分环与缺料，一律不得登记为通过；只有 `exit(0)` 且报告无阻断发现
  才可记为通过，`exit(2)` 记为不通过。

## 7. 验收标准

1. 在无网络、无凭证环境运行 `diagnose.py`（设 `AWS_EC2_METADATA_DISABLED=true`），
   不发起任何 STS / Access Analyzer 调用即可得到结论。
2. 不传参数时：`roles_unconfirmed_cycle = [RoleRingA, RoleRingB]`、
   `roles_unconfirmed_no_data = [RoleNeedsParam]`、
   `roles_confirmed = [RoleClean]`、`safe_passes = 0`。
3. 环角色必须带有非空 `cycle_path`，且首尾 `(resource, property)` 相同，
   可在模板中逐跳复核。
4. 传入 `BucketScope=audit-logs` 后：`RoleNeedsParam` 进入 `roles_confirmed`，
   而两个环角色仍停留在 `roles_unconfirmed_cycle`，`safe_passes` 仍为 `0`。
5. 任何一次运行都不得把 `UNCONFIRMED_*` 角色计入通过；
   `CONFIRMED` 角色的策略 JSON 必须原样出现在 `evidence` 字段中。

## 8. 离线限制

本脚本只复刻解析/引用求值链路（`cfn_loader` + `NodeEvaluator`），
不调用 Access Analyzer，因此不产生 `INVALID_ACTION`、`SECURITY_WARNING` 等
Access Analyzer 发现。它回答的是“这条策略能否被解析确认”，
解析成功后的策略安全判定仍需在具备凭证与网络时由
`cfn-policy-validator validate` 等命令完成。
