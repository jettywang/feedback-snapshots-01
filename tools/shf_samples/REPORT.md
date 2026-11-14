# SecureHeaderFields 取证核对报告（RFC 7508）

归档后端已完成 S/MIME 签名验证。本报告回答调查员的下一个问题：**界面上
显示的哪些邮件头确实被该签名保护**。方法是从已验证的 signedAttrs 中取出
`id-aa-secureHeaderFieldsIdentifier`（OID 1.2.840.113549.1.9.16.2.55）属性，
按属性声明的规范化算法与归档邮件的原始头逐条比对。

- 工具：`tools/secure_header_verify.py`（只读，不改写归档邮件）
- 样本：`tools/shf_samples/NN-*.eml` + `NN-*.shf.b64`（DER 编码的
  SecureHeaderFields，由 `tools/make_shf_samples.py` 确定性生成）
- 复现：`.venv/bin/python tools/secure_header_verify.py <eml> --attribute <shf.b64>`

## 比对语义

- 规范化：`simple` 原样比较（不允许任何改动）；`relaxed` 按 RFC 6376
  §3.4.2 展开折叠行、压缩连续空白、去除首尾空白后再比较。
- 重复头按出现顺序一一对应（签名方按 RFC 7508 §4.5.1 必须包含全部实例），
  绝不退化成"最终字典值"比较；数量不一致时用保序的值对齐，对齐不唯一即
  判 **unconfirmed**，不猜。
- `field-Status` 语义：`duplicated`（默认，传输中不应改变）、`deleted`
  （DCA 保密删除，归档中缺失属预期）、`modified`（DCA 合法替换过值，与
  签名值不同属预期差异，不等于被篡改）。
- 未知 `canonAlgorithm` 或未知 `field-Status`：一律 **unconfirmed**。

结论等级：`valid` → `valid-with-documented-differences` → `unconfirmed` →
`invalid-headers`。

## 样本 01-duplicate-from：两个 From —— valid

两个 `From` 实例在属性中按序各有一条记录，与收到的两个实例按序对应，
全部 `confirmed`。若中转把两个 From 调换了顺序，逐条对应会报告两个
`changed`（单测 `test_swapped_duplicates_fail_per_entry_not_by_dict`），
而不是被"最后值覆盖"的字典比较漏掉。

## 样本 02-folded-subject：折叠 Subject —— valid

归档件中 Subject 被重新折叠且空白被改动：

```
secured : 'Quarterly results and roadmap discussion'
received: ' Quarterly\r\n\tresults  and   roadmap\r\n discussion'
```

属性声明 `relaxed`，折叠与空白差异被规范化吸收，`confirmed`。
若签名方使用 `simple`，同样的重新折叠会被判 `changed` —— 这正是
RFC 7508 §4.3 建议用 relaxed 的原因。

## 样本 03-relay-modified：合法中转修改 —— valid-with-documented-differences

中转/DCA 对邮件做了四类改动，均**不构成签名失效**：

- 新增 `Received`、`X-Spam-Score`：不在 SecureHeaderFields 列表内。
  RFC 7508 §4.5.2 第 6 步只针对"与已保护头同名的新增头"，普通中继
  追踪头不影响结论。
- Subject 被重新折叠：relaxed 规范化吸收（同样本 02）。
- `X-Confidential-Note`（status `modified`）：DCA 按 §4.6 用
  `*** replaced by DCA ***` 替换了原值。属性中留有原始值
  `Project NIGHTINGALE budget`，记为 `expected-difference` —— 差异
  被签名本身声明过，是合法保密替换而非篡改。
- `X-Internal-Tag`（status `deleted`）：DCA 删除，归档中缺失记为
  `absent-as-expected`。

依据：§4.5.2 的失效判定针对"已保护头失配/缺失/同名新增"，而上述差异
要么在保护集之外，要么被 status 显式声明。结论
`valid-with-documented-differences` 保留了全部差异证据供调查员核对。

## 样本 04-attacker-inserted：攻击者插入头 —— invalid-headers

```
[!!] extra header with secured name: From: "CEO" <ceo@example.com>
[??] displayed but NOT secured: reply-to
verdict: invalid-headers
```

- 攻击者在真实 `From: alice@example.com` 之前插入
  `From: "CEO" <ceo@example.com>`。同名头数量与属性不一致，保序对齐
  唯一地把真实 From 对应到签名值（`confirmed`），多出的伪造 From 被
  单独列为 **extra header**（§4.5.2 第 6 步）。
- `Reply-To: attacker@evil.example` 不在 SecureHeaderFields 中，属于
  "界面显示了未认证的身份"：邮件客户端通常直接展示 From/Reply-To，
  用户看到的身份没有任何签名背书。

**风险结论：该邮件在界面上呈现的身份（CEO 发件人、攻击者 Reply-To）
未经认证；签名只担保 `alice@example.com` 等已列出的头。** 调查界面应
以属性中的值为准展示身份，并对 extra/unsecured 头给出显著告警。

## 无法确认的情形（设计为不猜测）

- `canonAlgorithm` 不是 simple/relaxed：全部条目 `unconfirmed`，结论
  `unconfirmed`（退出码 2）。
- 同名头数量不一致且值对齐不唯一（如属性 1 条、收到 2 条且值都不
  匹配）：对应关系歧义，相关条目 `unconfirmed`，不臆断哪条是原始头。
- 未知 `field-Status` 值：该条目 `unconfirmed`。

## 证据完整性

工具对归档邮件只读：解析原始字节做比对，不写回、不重格式化、不规范化
存档副本。所有"合法修改"的判断均基于签名属性内声明的 status 与值，
原始证据（`.eml` 与 `.shf.b64`）保持字节级原样。
