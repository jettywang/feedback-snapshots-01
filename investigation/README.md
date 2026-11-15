# 双签布局离线调查（signify 0.9.3）

合作方的"双人签署"程序被 signify 拒绝。"双签"在 Authenticode 里有三种可能的
布局，本调查对每种布局生成最小样本，用库的公开接口逐一验证，定位拒绝原因。

## 复跑方法

```sh
cd investigation
../.venv/bin/python generate_samples.py   # 生成证书(openssl CLI) + 6 个样本
../.venv/bin/python run_investigation.py  # 跑公开 API，输出见 results.txt
```

依赖：仓库自带 `.venv`（signify 0.9.3 / asn1crypto 1.5.1）与 openssl CLI
（仅用于签发 CA/两张代码签名证书和 RSA 签名）。全部离线。

样本（`samples/`，均为最小 PE32 + Authenticode 签名，authentihash 用 signify
自身的 fingerprinter 计算，messageDigest 口径经 4 个真实签名文件核对）：

| 样本 | 布局 |
|---|---|
| `A-multi-cert-entry.exe` | PE 证书表两个 WIN_CERTIFICATE 条目（条目1: SHA-1/leaf1，条目2: SHA-256/leaf2） |
| `A-tampered.exe` | A 的阴性对照：`.text` 翻转 1 字节 |
| `B-nested-signature.exe` | 一个 SignedData（SHA-1/leaf1），其 unauthenticated attribute `microsoft_nested_signature`（1.3.6.1.4.1.311.2.4.1）内嵌第二个 SignedData（SHA-256/leaf2） |
| `C1-multi-signerinfo-same-digest.exe` | 一个 SignedData 含两个 SignerInfo（均 SHA-256，leaf1+leaf2） |
| `C2-multi-signerinfo-two-digests.exe` | 一个 SignedData 含两个 SignerInfo（SHA-1 + SHA-256） |
| `D-poisoned-first-entry.exe` | 证书表 = [C1 信封, 合法 SHA-256 信封]，检验失败是否传染 |

## 实际调用结果（完整输出见 results.txt）

### A. 多个 PE 证书条目 —— 支持，全部通过

- `iter_embedded_signatures` 产出 2 个 `AuthenticodeSignature`（每个证书条目一个，
  `signed_file/pe.py:328`）。
- 签署者选择由 `verify(multi_verify_mode=...)` 控制（`signed_file/base.py:247`）：
  `any`/`first` 按文件顺序取条目1（SHA-1/leaf1）；`all` 两条链都验；`best`
  自动选 SHA-256 条目。`explain_verify -> OK`。
- 每个签名单独做三方 digest 一致性检查（SignedData ↔ IndirectData ↔ SignerInfo）
  和文件摘要检查（authentihash ↔ IndirectData.digest）。
- 阴性对照 `A-tampered.exe`：所有模式抛 `AuthenticodeInvalidDigestError`
  （"The expected hash does not match the digest in the indirect data."），
  `explain_verify -> INVALID_DIGEST`。文件摘要检查对每个签名独立生效。

### B. 嵌套签名 —— 支持，全部通过

- 外层签名的 unauthenticated attribute 解析出嵌套 SignedData
  （`authenticode/signer_info.py:102`），`iter_recursive_nested`
  （`authenticode/signed_data.py:102`）把外层+嵌套一并产出，共 2 个签名。
- verify 各模式行为与 A 完全一致（`best` 选嵌套的 SHA-256），`explain_verify -> OK`。
- 这正是 `signtool sign /as`（追加签名）在 Windows 上产生的布局。

### C. 一个 SignedData 多个 SignerInfo —— 不支持，解析期拒绝

- C1（两个 SignerInfo 同算法）：`AuthenticodeParseError:
  "SignedData.signerInfos must contain exactly 1 signer, not 2"`，抛自
  `authenticode/signed_data.py:82` 的 `_validate_asn1`。
- C2（两个 SignerInfo 不同算法）：更早一层就失败，`ParseError:
  "SignedData.digestAlgorithms must contain exactly 1 algorithm, not 2"`，抛自
  `pkcs7/signed_data.py:89`（RFC 5652 允许 digestAlgorithms 收集所有签署者算法，
  这里按 Authenticode 单签署者假设收紧为 1）。
- 所有 `multi_verify_mode` 下结果相同；`explain_verify -> PARSE_ERROR`。
- 即使绕过解析，验证路径也建立在不变量"恰好 1 个 SignerInfo"上：
  `pkcs7/signed_data.py:159` 的 `signer_info` 属性在非 1 时抛 `AttributeError`，
  `_verify_message_digest`（`:185`）与 `SignedData.verify`（`:254`）都只取
  单数 signer。因此不能靠"取第一个 SignerInfo"让样本通过——那只会静默漏验
  第二个签署者，且 `AttributeError` 不在公开异常体系（`SignifyError`）内。

### D. 失败传染性 —— 一个多 SignerInfo 条目会拖垮整个文件

证书表条目1 为 C1 信封、条目2 完全合法时，`iter_embedded_signatures` 在条目1
就抛出 `AuthenticodeParseError`，条目2 永远不会被产出。原因是
`pe.py:354` 的 `ignore_parse_errors=True` 只吞 `SignedPEParseError`，
不吞 `AuthenticodeParseError`。fail-closed 方向没错，但意味着证书表里任何一个
多 SignerInfo 条目都会让整份文件判死，即使其余条目合法。

## 结论：布局限制 vs 数据无效

- **协议布局限制**：只有 C（单 SignedData 多 SignerInfo）。Microsoft
  Authenticode 规范本身按单 SignerInfo 描述，Windows 官方双签做法就是嵌套签名
  （布局 B）。signify 在解析期硬拒绝，属设计使然而非缺陷。
- **A、B 均为已支持布局**：若合作方程序实际是这两种却被拒，拒绝原因在数据
  （摘要不匹配 → `INVALID_DIGEST`；链/EKU/有效期 → `CERTIFICATE_ERROR` 等），
  用 `explain_verify` 的枚举 + 异常即可定位，不应放宽解析。
- **数据无效**：`A-tampered` 演示了文件摘要检查正常工作；任何"为让样本通过"
  而取第一个 SignerInfo 或放松 `_validate_asn1` 的做法都会同时削弱 A/B 的
  完整性保证，不可取。

## 公开错误是否足以定位原因

足够。C1/C2 的异常类型（`AuthenticodeParseError`/`ParseError`）和消息
（明确写出 "must contain exactly 1 signer, not 2" / "exactly 1 algorithm"）
直接指向不支持的布局与字段；`explain_verify` 映射为 `PARSE_ERROR` 与数据类
失败（`INVALID_DIGEST`/`CERTIFICATE_ERROR`）区分清楚。两个小瑕疵：
(1) D 场景下错误被提前抛出，调用方无法知道证书表后续条目是否合法；
(2) 通用 pkcs7 层若绕过 Authenticode 子类，多 SignerInfo 会在 `verify` 时以
`AttributeError` 泄漏，不在 `SignifyError` 体系内（映射为 `UNKNOWN_ERROR`）。

## 处理建议

1. 先让合作方确认"双签"布局：用 `iter_embedded_signatures` 数签名个数、看
   `signer_infos` 长度即可分辨（本调查脚本前半部分即诊断工具）。
2. 若是 C 布局：请对方改用嵌套签名（`signtool /as`）或多个证书条目重签；
   这不需改动 signify。
3. 若是 A/B 布局仍被拒：按 `explain_verify` 的具体异常排查数据问题
   （摘要、证书链、EKU），与布局无关。
4. 若确需 signify 支持单 SignedData 多 SignerInfo，以下条件必须**共同**成立，
   且不得影响 A/B 现有语义：
   - 签署者选择：引入显式多 SignerInfo 策略（默认全部验证，或复用
     `multi_verify_mode` 语义），禁止静默取 `signer_infos[0]`；
   - digestAlgorithms：允许集合含多个算法，但每个 SignerInfo.digestAlgorithm
     必须出现在集合中，且与 IndirectData.digestAlgorithm 三方一致（按签署者
     逐一核对）；0 个算法仍须拒绝；
   - 认证属性：每个 SignerInfo 独立满足 content_type/message_digest 必备与
     唯一性检查，messageDigest 用各自算法对同一 eContent 内容
     （SEQUENCE contents，RFC 2315 §9.3 口径）核验——`get_content_digest`
     需按算法参数化；
   - 文件摘要：eContent 只有一份，authentihash 检查一次，但其算法须与每个
     签署者一致（同上三方一致）；
   - 链验证：每个 SignerInfo 的 sid（issuer+serial）独立建链到信任锚，
     EKU code_signing、签名值、计数签名逐一验证；
   - 解析容错：决定 `AuthenticodeParseError` 是否应被 `ignore_parse_errors`
     吞掉（D 场景），否则一个坏条目仍拖垮整份文件。
