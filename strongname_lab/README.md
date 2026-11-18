# 强名称核查实验（pefile, 离线）

目标：把 PE/.NET 里常见但容易被误用的几类"签名证据"拆开——**CLI 标志、
Assembly 公钥/token、强名称签名槽、Authenticode PKCS#7**——分别说明它们能
证明什么、不能证明什么，并用独立实现交叉核对。

本目录里所有样本都是**合成的最小托管 PE**，只用文件字节做解析和密码学验证；
没有任何一步加载或执行被分析程序集。

## 快速运行

```sh
.venv/bin/python -m strongname_lab --out strongname_lab/out
.venv/bin/python -m pytest tests/strongname_lab_test.py -q
```

产物：

- `fixtures/generated/` — 16 个样本 + `manifest.json`（SHA-256、说明）
- `out/report.json` — 每个样本的完整结构化结论
- `out/summary.txt` — CLI 打印的对照表

样本密钥由固定种子派生，重建后 SHA-256 不变（已实测两次构建逐字节一致）。

## 三个容易混淆的字段

| 位置 | 字段 | 实际含义 |
| --- | --- | --- |
| CLI header +0x10 | `COMIMAGE_FLAGS_STRONGNAMESIGNED (0x8)` | 编译/签名工具留下的**声明位**，校验器不应据此判定签名有效 |
| CLI header +0x20 | `StrongNameSignature` RVA/Size | 签名槽的位置和长度；延迟签名会保留槽位但填 0 |
| Assembly 表 | `PublicKey` blob、`Flags.PublicKey(0x1)` | 完整的 CAPI `PUBLICKEYBLOB`；token 只是它的 SHA-1 末 8 字节反转 |

`PublicKeyToken` 的计算（ECMA-335）：

```text
token = reverse( SHA1(public_key_blob)[-8:] )
```

token 是**公钥 blob 的摘要**，不是签名的摘要，也不含任何信任判断。它短（64 位）、
可碰撞，且在 `AssemblyRef` 里既可以放完整公钥也可以只放 token（由 `Flags` 区分）。

## 强名称摘要覆盖范围

强名称签名的哈希输入是：**PE 头（到 `SizeOfHeaders`）+ 所有节的
`SizeOfRawData` 原始字节，按文件偏移顺序**，并且：

- 跳过 `OptionalHeader.CheckSum` 4 字节；
- 跳过证书表目录项 8 字节（`IMAGE_DIRECTORY_ENTRY_SECURITY` 的 RVA/Size）；
- 跳过 `StrongNameSignature` 槽本身（长度按 CLI 头声明）。

与本实验的 `sn_full` 实测一致（文件 2560 B，覆盖 2292 B）：

| 范围 | 长度 |
| --- | --- |
| `0x000–0x0D8` 校验和前 | 216 |
| `0x0DC–0x118` 校验和与证书目录项之间 | 60 |
| `0x120–0x200` 证书目录项之后到 `SizeOfHeaders` | 224 |
| `0x200–0x804` `.text` 签名槽之前 | 1540 |
| `0x904–0xA00` `.text` 签名槽之后 | 252 |

## Authenticode 摘要覆盖范围（对照）

按 PE 规范与 `ImageGetDigestStream` 的语义，Authenticode 覆盖：**头（同样跳过
校验和与证书目录项）+ 每个节的原始数据 + 节末尾到证书表之间的附加数据**；
**不覆盖证书表本身**，也**不覆盖证书表之后追加的字节**。

`auth_full`（4944 B）覆盖 2548 B：头 500 B + `.text` 2048 B，证书表
（2384 B）整段不在摘要内。注意 `auth_*` 样本是在 `sn_full` 之上追加证书表，
因此 `.text` 长度不变，强名称摘要也与 `sn_full` 完全相同（2292 B）。

这带来一个必须写进报告的事实：**追加在证书表之后的字节，两种方案都不会发现**。
`dual_trailing` 就是这种样本：Authenticode 仍"密码学有效"，但报告会给出
`unauthenticated_trailing_bytes=32`。这是覆盖边界，不是安全性。

反过来，节末尾到证书表之间的数据在 Authenticode 覆盖内、但不在强名称覆盖内；
`dual_overlay` 改动这段数据后强名称仍有效、Authenticode 失效。两个样本一起说明：
比较两种签名时必须比较**各自的覆盖范围**，不能只比较"有没有签名/验签是否通过"。

## 强名称 vs Authenticode

| | 强名称 | Authenticode |
| --- | --- | --- |
| 对象 | .NET 程序集的**身份 + 程序集内容完整性** | PE 文件**整体**（除上述排除区） |
| 密钥/凭据 | 程序集自带的公钥；私钥由发布者自持 | X.509 叶证书 + 链 |
| 信任来源 | **没有**公共信任根；是否信任由调用方策略决定 | 操作系统/浏览器/应用自带的根存储 + 证书策略（EKU、有效期、吊销、时间戳） |
| 典型作用 | 程序集绑定、版本共存、防篡改 | 发布者身份声明、SmartScreen/驱动加载等策略输入 |
| 不覆盖 | Authenticode 签名、证书表、节外附加数据 | 证书表自身、证书表之后的追加数据 |
| 常见误判 | "token 相同就是同一发布者"、"flag 置位就可信" | "数学验签通过 = 发布者可信" |

两者**互不替代**：强名称不能证明发布者身份（任何人都能生成一对密钥并自签），
Authenticode 也不能替代程序集身份绑定（它不校验 AssemblyRef 的 token/version）。

## 样本矩阵与实测结论

`strongname_lab/out/report.json` 是权威结果；下表是 CLI 摘要。

| 样本 | 构造 | 强名称 | Authenticode |
| --- | --- | --- | --- |
| `sn_full` | 正常 SHA-1 强名称签名 | **有效** | 无签名 |
| `sn_sha256` | `HashAlgId=SHA-256` | **有效** | 无签名 |
| `sn_delay` | 有槽位、有公钥、槽位全 0，flag 未置位 | 无效（槽位为零） | 无签名 |
| `sn_flag_only` | 只置 `STRONGNAMESIGNED`，无槽位 | 无效（无材料） | 无签名 |
| `sn_no_material` | 无槽位、无 flag | 无效 | 无签名 |
| `sn_flag_without_public_key_flag` | 签名有效但 `AssemblyFlags.PublicKey` 未置位 | 有效，但标志不一致 | 无签名 |
| `sn_other_key_valid` | 同名同版本，**另一密钥**完整签名 | 有效，token 不同 | 无签名 |
| `sn_body_tampered` | 签名后改方法体 1 字节 | **无效** | 无签名 |
| `sn_token_forgery` | 用另一私钥签名后把原公钥写回 | **无效，token 与 `sn_full` 相同** | 无签名 |
| `auth_full` | 强名称 + Authenticode，链锚定到随附根 | 有效 | 有效 + 受信 |
| `auth_untrusted_root` | 同上，但根不在随附信任锚 | 有效 | **密码学有效，但不受信** |
| `auth_wrong_digest` | PKCS#7 内封装的 PE 摘要被改坏 | 有效 | 签名有效但摘要不匹配 → 无效 |
| `auth_body_tampered` | Authenticode 签名后改方法体 | 无效 | 无效 |
| `dual_overlay` | 改"节末尾到证书表之间"的附加数据 | **仍有效** | **无效** |
| `dual_trailing` | 证书表之后追加 32 B | 仍有效 | 仍有效，但 32 B 未认证 |
| `dual_checksum_edit` | 改 `CheckSum` 字段 | 仍有效 | 仍有效 |

关键反例（`sn_token_forgery`）：`sn_full` 与 `sn_token_forgery` 的
`PublicKeyToken` 都是 `e20f9bf307719724`，`PublicKey` blob 逐字节相同，CLI flag 都置位，槽位都非零；
但其中一份的 RSA 签名是用**另一把私钥**做的，验证失败。这直接说明：
**token、公钥、标志位都只能说明"声称的身份"，只有对覆盖范围做密码学验证才能
说明"内容与私钥持有者的绑定"。**

## 独立验证

`strongname_lab/external.py` 用 OpenSSL 复核，避免"自己签、自己验"的循环：

- 用 `openssl dgst -sha1/-sha256 -verify` 对**相同覆盖字节**验 RSA 签名；
- 用 `openssl verify -CAfile` 独立验证 X.509 链；
- 用 `openssl dgst` 重算覆盖范围摘要，与本实现比对。

`report.json` 中每个 case 的 `strong_name.external` / `authenticode.external`
记录这些交叉结果；OpenSSL 不可用时字段为 `available: false`，不会伪装成通过。

## 结论边界（必须保留在展示层）

1. "RSA/PKCS#1 验证通过"只表示：**签名由该公钥对应的私钥产生，且被覆盖的字节
   未被改动**。它不表示发布者可信、不表示代码安全、不表示未被吊销。
2. 强名称**没有信任根**。默认 .NET Framework 的强名称验证也只保证"绑定一致"，
   是否信任 token/公钥必须由应用自己的允许列表决定。
3. Authenticode 的"受信"依赖**外部根存储**。本实验的根是随附的离线根，仅用于
   演示；`auth_untrusted_root` 展示了"数学有效 + 链不受信"的组合。
4. 两种方案都有覆盖盲区：强名称不覆盖节外数据；Authenticode 不覆盖证书表和其
   之后的字节。报告中必须分别给出覆盖字节数和未认证尾部字节数。
5. `COMIMAGE_FLAGS_STRONGNAMESIGNED` 是声明位，**永远不能单独作为证据**。

## 后端展示建议

建议把结论拆成**四个互不折叠的维度**，每维带证据和覆盖范围：

```json
{
  "identity":  {"name": "...", "version": "...", "token": "...", "public_key_sha256": "..."},
  "strong_name": {
    "state": "valid | invalid | delay_signed | absent",
    "hash_algorithm": "sha1",
    "covered_bytes": 2292,
    "uncovered": ["certificate_table", "bytes_after_sections"],
    "flag_only": false
  },
  "authenticode": {
    "state": "valid | invalid | absent",
    "chain_trusted": true,
    "timestamp_present": false,
    "unauthenticated_trailing_bytes": 0,
    "certificate_subject": "..."
  },
  "publisher_trust": {
    "value": "unknown | allowlisted | trusted_by_os_store",
    "source": "policy:..."
  }
}
```

展示规则：

- **不要**把 token 当作发布者主键。`sn_other_key_valid` 与 `sn_full` 同名同
  版本，但 token 不同（分别是 `dee015d295aa2852` 和 `e20f9bf307719724`），
  说明名称/版本相同并不等于同一密钥；而 `sn_token_forgery` 证明反过来也不行：
  同一 token/blob 可以配上另一私钥的无效签名。应展示 `public_key_sha256` 作为
  更强、但不等于信任的身份指纹，并把"签名验证"单独列出。
- **不要**用单一 `signed: true` 布尔值。至少区分 `signature_valid`（数学）、
  `content_covered`（摘要覆盖）、`identity_bound`（名称/token/公钥一致）、
  `publisher_trusted`（外部策略）。
- 当 `strong_name.state=valid` 而 `authenticode.state=absent` 时，UI 应显示
  "程序集完整性可验证，但发布者身份未验证"。
- 当 `authenticode.chain_trusted=false` 时，即使 `signature_valid=true`，也只能
  显示"签名有效，证书链不受信"。
- 对 `unauthenticated_trailing_bytes > 0` 单独告警：签名之后追加的数据不在任何
  摘要内。
- 所有"已验证"结论都应附 `covered_bytes` 和算法，便于审计复算。

## 复现

```sh
.venv/bin/python -m strongname_lab --out strongname_lab/out
.venv/bin/python -m pytest tests/strongname_lab_test.py -q   # 18 passed
```

本机无 Windows/.NET 工具链，因此样本是合成 PE 而非 `csc`/`sn` 产物；验证逻辑
按 ECMA-335 与 PE 规范实现，并用 OpenSSL 复核密码学部分。这足以说明字段语义和
覆盖差异，但**不能**替代在真实 Windows 上对 `sn -vf` / `signtool verify /pa`
的行为比对。合成样本只包含 `mscoree.dll!_CorDllMain` 导入桩、一个 IL 方法体和
元数据，不构成可运行程序；实验全程只读文件字节。
