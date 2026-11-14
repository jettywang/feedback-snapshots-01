# RFC 3820 代理链准入方案

面向只实现普通 CA 链验证的后端服务。后端已有能力：用既有 CA 锚点校验证书
签名与有效期；本方案负责在“普通证书链 → 代理链”的衔接处做准入判定，并把
代理权限收窄为可审计的显式集合。

实现：`pyasn1_modules/proxychain.py`
离线演示：`tools/proxychain-admission.py`
测试：`tests/test_proxychain.py`
PEM 夹具：`docs/fixtures/`（由 `--emit` 生成，测试会重新解析后判定）

## 1. 分层模型

```
外部已验签的链
  CA ... -> EEC -> PC1 -> PC2 (leaf)
                 |      |
                 |      +-- ProxyCertInfo(critical), policyLanguage, pCPathLenConstraint
                 +--------- ProxyCertInfo(critical), ...
```

输入约定：`check_chain(eec, [pc1, pc2, ...])`。EEC 及其到信任锚的普通
RFC 5280 校验由调用方完成；代理证书签名可用可选的
`verify_signatures(cert, issuer)` 回调绑定，回调抛异常即拒绝。原型本身不
内置密码学实现，避免在 `pyasn1-modules` 中引入加密依赖。

判定分两层：

| 层 | 内容 | 谁来判定 |
| --- | --- | --- |
| 结构准入 | ProxyCertInfo 存在且 critical、主体派生、issuer 衔接、BasicConstraints、SAN/IAN 禁用、KeyUsage、pCPathLenConstraint、重复/未知 critical 扩展、有效期 | 引擎自动判定 |
| 授权语义 | `id-ppl-inheritAll`、`id-ppl-independent`、自定义 policyLanguage | 内置规则 + 应用注册的 `PolicyInterpreter` |

## 2. 衔接与主体派生

- EEC 不得带 ProxyCertInfo；EEC subject 不得为空；EEC 若带 KeyUsage，
  必须包含 `digitalSignature`（RFC 3820 §3.1/§3.6）。
- 签发下游代理的证书若带 KeyUsage，必须含 `digitalSignature`（§3.1、
  §4.1.4(f)）；KeyUsage 缺席表示无此约束，不属于违规。
- 代理证书必须是 v3，且 ProxyCertInfo **必须 critical**（§3.8）。
- 代理 subject 必须严格等于签发者 subject 再追加**恰好一个** CN RDN
  （§3.4）。追加 O/OU/第二个 CN、替换 EEC 名称前缀都拒绝。
- 代理 issuer 必须与上一层 subject 相同。
- 代理不得带 `subjectAltName`、`issuerAltName`（§3.2/§3.5）。
- 代理 BasicConstraints 的 `cA` 不得为 TRUE（§3.7）。

名称比较使用 DER 规范化后逐 RDN 比较，RDN 内多值属性顺序无关。这避免了
“同一名称不同字符串编码”被误判为不同主体。

## 3. 路径长度

`pCPathLenConstraint` 表示**该证书之后**还能有多少张代理证书（§3.8.1）：

- 字段缺失：不限；
- `0`：不得再签发代理；
- 值 `k`：其后最多 `k` 张代理。

引擎对每张证书检查 `k >= len(proxies) - index`。因此同一条链上任何一层
的较小约束都会生效，后续代理不能放宽它。

### 关于 `max_path_length` 的递减

RFC 3820 §4.1.2(e) 另有一个 `max_path_length`，初始化为链长度 `n`，并在
§4.1.4(a) 每处理一层减一。两种表述等价：

- 对证书 x（1-based），其后代理数 = `n - x`；
- 引擎直接检查“该证书的 `pCPathLenConstraint` ≥ 其后代理数”。

因此不需要额外维护递减计数器，也不会漏掉中间层较小的约束。`pCPathLen`
缺失时视为不限；`0` 表示不得再签发。

## 4. 策略语言与权限代数

三个 RFC 3820 内置值的行为固定：

- `id-ppl-inheritAll`：继承签发者全部权限；`policy` 字段**必须缺席**。
- `id-ppl-independent`：不继承任何权限；`policy` 字段必须缺席；返回显式
  空集合，而不是“无限制”。
- `id-ppl-anyLanguage`：只是路径验证的输入哨兵，**不得**作为证书内策略
  出现；出现即拒绝。

自定义语言必须由应用显式注册 `PolicyInterpreter`。解释器接收
`(policy_octets, delegated_rights)` 并返回 `Rights`：

- 返回值必须是**有限集合**；只有 `inheritAll` 可以表示“无限制”。
- 返回值必须是 `delegated_rights` 的子集；越权返回直接拒绝
  （`policy_interpreter_not_monotone`），不会悄悄做交集掩盖解释器缺陷。
- 解释器无法判定时必须抛 `PolicyError`；未注册语言返回
  `INDETERMINATE`，绝不当作继承全部权限。

`check_chain` 返回的 `rights` 是逐层交集。`independent` 把继承集合置空，
其后的 `inheritAll` 仍然继承这个空集合，不能复活 EEC 权限。KeyUsage 与
EKU 的有效集合同样按 §4.2 计算：普通代理与签发者求交，`independent`
重置为自身值；EKU 的 `anyExtendedKeyUsage` 视为不额外收窄。

## 5. 合法两级链

```
EEC  CN=Alice                        KeyUsage=digitalSignature
 |
 |  issuer=EEC.subject
 v
PC1  CN=alice-proxy-1                ProxyCertInfo{critical, pCPathLen=1,
 |                                    policyLanguage=id-ppl-inheritAll}
 |  issuer=PC1.subject
 v
PC2  CN=alice-proxy-2                ProxyCertInfo{critical, pCPathLen=0,
                                      policyLanguage=id-ppl-inheritAll}
```

判定：`ACCEPT`，`rights=unrestricted`。PC1 之后有 1 张代理，`1 >= 1`；
PC2 之后为 0，`0 >= 0`。

## 6. 失败对照

| 变体 | 结果 | 原因码 |
| --- | --- | --- |
| PC1 `pCPathLen=0` 却签发 PC2 | REJECT | `path_length_exceeded` |
| 代理 subject 追加 O 而非 CN | REJECT | `subject_not_derived_from_issuer` |
| 代理 subject 追加两个 CN | REJECT | `subject_not_derived_from_issuer` |
| `ProxyCertInfo` 非 critical | REJECT | `proxy_cert_info_not_critical` |
| `inheritAll` 带 `policy` 字段 | REJECT | `policy_forbidden_field` |
| 自定义语言、无解释器 | INDETERMINATE | `policy_unknown_language` |
| 解释器返回超出委托集合 | REJECT | `policy_interpreter_not_monotone` |
| 自定义解释器返回无限制集合 | REJECT | `policy_interpreter_unrestricted` |
| `independent` 后再 `inheritAll` | ACCEPT，`rights=[]` | 语义为空集合 |
| `anyLanguage` 出现在证书内 | REJECT | `policy_any_language_in_certificate` |
| 应用不接受该语言 | REJECT | `policy_unsupported_by_application` |
| 未知 critical 扩展 | REJECT | `unknown_critical_extension` |
| 未知非 critical 扩展 | ACCEPT + warning | 按 RFC 5280 忽略 |

## 7. 自动决定 vs 应用解释器

**可以自动决定（引擎直接给出 ACCEPT/REJECT）**

- 上述所有结构检查、路径长度、有效期、criticality、KeyUsage/EKU 有效集；
- `inheritAll` / `independent` 的固定语义及字段禁用；
- 解释器返回值与上一层权限的单调性。

**必须由应用决定**

- 非内置 policyLanguage 的具体语义：策略表达式是否能解析、请求的操作/资源
  是否落在策略内、EEC 本身在本地授权库中是否拥有该权限；
- `acceptable_policy_languages` 白名单：应用应只登记自己真正理解的
  (language, semantics) 对，而不是只登记 OID。

**必须失败关闭**

- 未知语言、解释器异常、解释器返回越权或“无限制”；
- 无法解码的 ProxyCertInfo、未知 critical 扩展；
- 任何“看不懂但看起来像继承”的情况。`INDETERMINATE` 的调用方必须拒绝
  授权，不能降级为 `ACCEPT`。

`INDETERMINATE` 仅用于“本服务暂时无法解释”的两种情况：语言未注册、或
解释器报错。语言被应用白名单显式排除属于**已决定的拒绝**，返回 `REJECT`。
同时，`id-ppl-anyLanguage` 只是 RFC 3820 的路径验证输入哨兵；将它放进
白名单表示“先不检查具体语言”，但未知语言仍必须由解释器处理，绝不会因为
白名单含 `anyLanguage` 就自动继承权限。

## 8. 后端接入建议

1. 用既有 CA 链验证 EEC，得到受信任的 EEC 及其 subject/public key。
2. 按 TLS/签名协议收集代理链，按 root-most → leaf 排序，逐张用
   `verify_signatures` 校验（或在上游已经验签后传入已验证标记）。
3. 调用 `check_chain`，并注册本服务真正支持的策略解释器与语言白名单。
4. 仅当 `result.accepted` 为真时，才把 leaf 的 subject 视为 EEC 的短期
   代表；`rights` 用于后续授权交集，`key_usage`/`extended_key_usage`
   用于功能门控。
5. 将 `INDETERMINATE` 与 `REJECT` 都映射为拒绝，并记录原因码；不要向
   客户端暴露“差一点成功”的语义。
6. `result.key_usage` / `result.extended_key_usage` 可能为 `None`（表示
   该链上没有任何一层约束该扩展）。`None` 不等于“无权限”，也不等于
   “所有权限”；是否允许某项功能仍由应用按本地策略决定。
