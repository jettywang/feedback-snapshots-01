# ESSSecurityLabel 跨策略域接收检查（小型原型）

本目录是 `pyasn1-modules` 仓库内的可执行原型，直接复用
`pyasn1_modules.rfc2634` 的 ESS 标签结构：

```text
ESSSecurityLabel ::= SET {
    security-policy-identifier SecurityPolicyIdentifier,
    security-classification  SecurityClassification OPTIONAL,
    privacy-mark             ESSPrivacyMark OPTIONAL,
    security-categories      SecurityCategories OPTIONAL }
```

它只回答一个问题：**收件方网关收到一份带 ESS 标签的已签名邮件时，能否
依据本地显式配置，把原标签安全地换算到收件方策略，并证明收件人有权阅读？**

它不签名、不解密、不访问目录、不做证书路径校验，也不扩展成通用权限系统。

## 快速运行

```sh
python examples/ess_label_guard/demo.py
python -m unittest discover -s examples/ess_label_guard/tests
```

`demo.py` 依次打印：

1. 两套有限策略及其全部显式映射；
2. 一次合法的跨域投递（`ALLOW`）；
3. 一个数字比较导致越权的反例及其修正（`DENY`）；
4. 认证等价标签与本地映射冲突（`REVIEW`，即使冲突方声称更宽松）；
5. 未知类别、缺少必需类别、映射不完整（`REVIEW` / `DENY`）；
6. 从真实 `SignerInfo.signedAttrs` 提取标签属性。

## 设计要点

### 1. 分类数字只在策略 OID 下有意义

`SecurityClassification` 是 INTEGER，但 RFC 2634 §3.3.2 明确：整数含义和
层级由 `security-policy-identifier` 决定，且**不必按数值升序**，也**不必连续**。
本原型的 `Policy.levels` 是有序元组，序号才是等级；整数本身只是标签。

两套示例策略故意让同名/同数值产生不同含义：

| 策略 | 分类整数（按等级从低到高） |
|---|---|
| Agency-A `1.3.6.1.4.1.32473.100.1` | `0 unmarked` < `1 unclassified` < `11 SBU` < `2 restricted` < `4 secret` < `5 top-secret` |
| Agency-B `1.3.6.1.4.1.32473.200.1` | `0 public` < `2 internal` < `7 confidential` < `9 restricted` |

因此 `A/2` 是 restricted，而 `B/2` 是 internal；`A/11` 比 `A/2` 低，尽管
`11 > 2`。任何跨策略的直接数值比较都会放宽访问。

### 2. 安全类别必须连同策略 OID 解释

`SecurityCategory` 的 `type` 是 OID，`value` 是 `ANY`。**值的语法和含义都
由 `security-policy-identifier` 加本地策略表定义**，原型的
`CategorySpec.syntax`（`utf8` / `ia5` / `integer`）与 `values` 白名单就是
这层定义。A、B 对“部门/隔舱”使用不同 OID；同名概念也不共享 OID。

未知类别不会被“跳过”或按默认 UTF8 猜测：解析阶段保留原始 DER 字节，
判定阶段直接 `REVIEW`。未配置的值同样 `REVIEW`。

类别语法表不是硬编码常量：`check_access()` 默认从传入的策略表推导
`{category OID: syntax}`，也可用 `category_syntax=` 显式传入。因此新增
JSON 类别只改配置，不改代码（见
`JsonConfigurationTestCase.test_new_category_in_json_is_decoded_without_code_change`）。

### 3. 只认显式映射，且必须整条匹配

映射是 `(源策略, 源分类, 源类别全集) -> (目标策略, 目标分类, 目标类别全集)`
的完整条目。查找要求分类和**全部类别值**精确相等；没有“最接近”“下限”
或“取宽松者”的回退。没有匹配就是 `REVIEW`，不会给 `ALLOW`。

`mapping.validate_configuration()`（以及 JSON 加载器）在启动时拒绝：

- 未知策略 / 未知分类 / 未知类别；
- 目标标签缺少目标策略的必需类别；
- 同一源键对应多个目标（歧义映射）；
- 未列入本地 allowlist 的 assertor；
- 同一**方向**（源策略 → 目标策略）出现多个 assertor 角色，即“谁有权翻译”
  存在歧义；每个方向必须恰好由一个配置角色负责，即使多个角色都在全局
  allowlist 中；
- 同一类别 OID 在不同策略中定义不一致。

### 4. 三种证明彼此独立

| 需要证明的事实 | 由谁证明 | 原型中的表示 |
|---|---|---|
| 标签签名有效、绑定到内容 | 收件方 CMS 验证器：验证 `SignerInfo` 对 `signedAttrs` 的签名并校验签名者证书链 | `Attestations.label_signature` |
| 转换可信（谁有权把 A 标签解释成 B 标签） | 本地策略管理员配置的 assertor 角色，且**方向也必须授权**；CMS 验证器只确认 `EquivalentLabels` 属性的签名 | `Attestations.translator` + `TRANSLATIONS.assertor` |
| 收件人有资格 | 收件方的授权/资格机构（例如签署的 clearance 属性或目录记录） | `Attestations.clearance` |

发送者不证明收件人资格；网关也不授予资格。三者缺一，原型分别 `DENY` /
忽略该等价标签 / `DENY`，不会用另一项证明顶替。

### 5. `EquivalentLabels` 只收紧、不放宽

- 原标签策略在本地可理解时，按 RFC 2634 §3.4.2 **直接采用原标签**，等价标签
  只记录、不使用。这是唯一允许忽略等价标签内容的情形（规则由标准规定）；
  但若认证的等价标签重复了原策略 OID，仍按 RFC 2634 的唯一性要求
  `REVIEW`（`authenticated-labels-contradict`），不因“可忽略”而吞掉矛盾。
- 原标签策略不可本地理解时，判定只使用本地显式映射。等价标签只用于
  交叉核对：
  - 签名未验证或翻译方不受信任 → `ignored`；
  - 与本地映射一致 → `agrees`；
  - 与本地映射不一致 → `REVIEW`（`authenticated-labels-contradict`），
    即使它声称更宽松的等级；
  - 指向第三策略：若没有从源策略到该策略的授权方向，该翻译方无权作此声明，
    标为 `ignored`；若方向已授权但本地无法核对，标为
    `equivalent-labels-unverifiable` 并 `REVIEW`；
  - 同一策略 OID 重复 → `REVIEW`；
  - 多于一个 `EquivalentLabels` 属性 → `REVIEW`（不合并、不挑选）。
- 原策略可理解时，等价标签仍会被解析并标为 `ignored-policy-understood`，
  用于审计，但不参与判定；畸形内容只记录，不影响决定。
- 多个属性同时存在时，RFC 2634 允许实现选取第一个可验证的；本原型选择更
  保守的“交人工判断”，因为自动挑选会引入策略选择权。

### 6. 内层与外层标签分别检查，再取严格结果

RFC 2634 允许标签出现在内层签名（保护正文）、外层签名（保护加密体），或两者。
原型要求对**每个存在的层分别**调用 `check_access()`，然后用
`combine_layer_results()` 做逻辑与：

- 任一层 `DENY` → `DENY`
- 否则任一层 `REVIEW` → `REVIEW`
- 全部 `ALLOW` → `ALLOW`

这样较宽的外层标签不能放宽较严的内层标签，也不会把两个不同层的分类/类别
合并成一个“新标签”。

### 7. 多签名者与多属性

RFC 2634 §3.4.1 要求：只要任一 `signerInfo` 带 ESS 标签，所有 `signerInfo`
都必须带且**完全相同**。`label.collect_signed_labels()` 在 CMS 层强制执行：

- 任一签名者缺失标签 → 异常；
- 标签不一致 → 异常（不会挑选其中一个）；
- 同一 ESS 属性出现多个 `AttributeValue` → 异常（§3.1 只允许一个）；
- 同一 `signerInfo` 重复出现同一属性 → 异常。

`EquivalentLabels` 从所有签名者收集；判定器见到多于一个属性时直接 `REVIEW`。

### 8. `privacy-mark` 仅供展示

`privacy-mark` 不参与访问控制（RFC 2634 §3.3.3）。原型会在结果中显示它并
标注 `display only`，避免运维把可打印标记误当密级。

## 两套有限策略的映射示例

完整表见 `mapping.py` 与 `policies.example.json`。摘录：

**A → B**

| 源标签（策略 A） | 目标标签（策略 B） | 说明 |
|---|---|---|
| `1 + compartment=ALPHA` | `0 + department=FIN` | 低等级也需改写类别 |
| `11 + compartment=ALPHA` | `2 + department=FIN` | 11 是 SBU，等级低于 2 |
| `2 + compartment=ALPHA` | `7 + department=FIN` | restricted → confidential |
| `4 + compartment=BRAVO` | `9 + department=ENG` | 类别值同时变化 |
| `5 + compartment=ALPHA` | `9 + department=FIN + handling=NEED-TO-KNOW` | 目标多出一个必需类别 |

**B → A**

| 源标签（策略 B） | 目标标签（策略 A） | 说明 |
|---|---|---|
| `0 + department=FIN` | `1 + compartment=ALPHA` | 反向映射独立配置 |
| `2 + department=FIN` | `11 + compartment=ALPHA` | internal → SBU |
| `7 + department=ENG` | `2 + compartment=BRAVO` | confidential → restricted |
| `9 + department=FIN` | `4 + compartment=ALPHA` | restricted → secret |

反向表不是正向表的自动反转；两侧由各自的 assertor 角色声明，避免把单向
协议误当成双向授权。

## 越权反例与修正

反例（`demo.py` 第 3 节，测试
`EscalationTestCase.test_numeric_comparison_would_grant_access_but_guard_denies`）：

```text
原标签: A/2 + compartment=ALPHA        (restricted)
收件人 clearance: B/2 + department=FIN (internal)
朴素比较: 2 <= 2 -> ALLOW              ← 越权
```

数值相等纯属巧合；`A/2` 与 `B/2` 不是同一密级。修正路径：

1. 用策略 OID 分别解释两侧，得到 `A/2 = restricted`、`B/2 = internal`；
2. 查显式映射：`A/2 + ALPHA -> B/7 + FIN`（confidential）；
3. 在 B 的有序等级上比较：`B/7` 高于 `B/2`；
4. 结果 `DENY (clearance-below-label)`。

同一策略内也有类似陷阱：`A/2` 高于 `A/11`，但 `2 <= 11` 的数值比较会
错误放行（
`test_numeric_order_inside_same_policy_would_grant_access`）。

类别维度同样不能放宽：`A/5 + ALPHA` 映射到 `B/9 + FIN + NEED-TO-KNOW`，
只有 `B/9 + FIN` 的收件人等级足够但类别不全，结果为
`DENY (clearance-missing-category)`。

## 目录结构

| 文件 | 作用 |
|---|---|
| `label.py` | 用 `rfc2634` 解析/构造标签，保留未知类别的原始 DER；跨 signerInfo 一致性检查 |
| `mapping.py` | 两套有限策略、显式映射、启动校验、`Clearance` |
| `checker.py` | `check_access()` 决策、三种证明的类型、内层/外层结果合成 |
| `config.py` | 从本地 JSON 加载同一套有限配置 |
| `policies.example.json` | 可部署的显式策略文档（与 `mapping.py` 一致） |
| `demo.py` | 可执行演示 |
| `tests/test_guard.py` | 49 个自测（含 DER 往返、跨签名者一致性与反例） |

## 已知边界

- 不实现 CMS 签名/解密/证书路径校验；这些结果必须由调用方以
  `Attestations` 传入，且原型不会自行推断为 `True`。
- 不实现残余密级、多级安全、动态授权或通用 PDP/PEP。
- 不把 `EquivalentLabels` 当授权来源；它只能确认或触发人工复核。
- 不在本地策略表之外做任何 OID、语法或等级推断。
