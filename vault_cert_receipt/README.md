# Vault 内部短期服务证书领用回执（本地可核对演示）

运维通过 `hvac` 向 Vault PKI 申领内部短期服务证书。本目录提供一套**本地可复现**的
领用—核对—回执—流转核验流程，用于确认“实际收到的证书”与“审批单”一致，并产出
可随工单流转、防篡改、且**不含任何私钥材料**的领用回执。

## 设计要点

- **审批驱动**：审批单 `approvals/*.json` 指定 Vault 签发方（钉扎中间 CA 的
  SHA-256 指纹）、允许的 CN/SAN、可用期限上限（TTL）与信任根。
- **接口对齐 hvac**：`mock_hvac.MockPki.generate_certificate` 的方法签名与真实
  `hvac.api.secrets_engines.pki.Pki.generate_certificate` 完全一致
  （`name, common_name, extra_params, mount_point, wrap_ttl`），响应结构对齐
  Vault `/pki/issue/:role`（含 `certificate / issuing_ca / ca_chain /
  private_key / serial_number`）。生产环境把 `issue_cert.build_client` 换成
  `hvac.Client(url, token)` 即可，其余流程不变。
- **五类可区分结论（机读 verdict）**，按固定优先级判定：
  - `PASS`：证据齐全、链可信、身份一致、期限合规。
  - `REJECT_INCOMPLETE_EVIDENCE`：证据缺失（无证书/签发链/CA），无法复核。
  - `REJECT_UNTRUSTED_CHAIN`：`openssl verify` 链校验失败，或签发方指纹与审批钉扎不符。
  - `REJECT_IDENTITY_MISMATCH`：CN 不相等，或实际 SAN 超出审批范围。
  - `REJECT_TTL_VIOLATION`：实际有效期超过审批 TTL 上限，或起期早于审批时间。
- **回执可流转、防篡改**：回执用 ECDSA-P256-SHA256 签名（规范化 JSON），第三方可用
  `keys/receipt-signing.pub.pem` 验签并独立复算结论；任何篡改都会使验签失败或复算漂移。
- **只留识别信息**：回执仅含序列号、证书/公钥 SHA-256 指纹、DN、SAN、起止时间、
  有效期秒数与签发方指纹；**不含 PEM 证书、不含私钥**。私钥字段在证据落盘前即被
  `redact_sensitive` 剥离，并有 `assert_no_private_material` 阻断断言。

## 目录

- `pki_crypto.py`：OpenSSL CLI 封装（密钥/CA/叶子签发、解析、链校验、签名验签）。
- `mock_hvac.py`：本地模拟 hvac PKI 客户端（含 TTL 解析、Vault 响应结构）。
- `receipt.py`：审批核对、五类结论、回执组装与签名信封。
- `setup_lab.py`：构建根 CA + 中间 CA（模拟 Vault 签发方）+ 回执签名密钥 + 审批单。
- `issue_cert.py`：领用入口，产出 `evidence/` 证据与 `receipts/` 回执。
- `verify_receipt.py`：独立核验器（验签 + 复算 + 私钥泄漏检查）。
- `run_demo.py`：一键端到端演示。

## 运行

```bash
# 在仓库根目录，使用自带 .venv
.venv/bin/python -m vault_cert_receipt.run_demo

# 单独领用 / 核验
.venv/bin/python -m vault_cert_receipt.issue_cert case-a-valid
.venv/bin/python -m vault_cert_receipt.verify_receipt \
    vault_cert_receipt/receipts/case-a-valid.receipt.json
```

## 三个内置用例

| 用例 | 模拟情形 | 预期结论 |
| --- | --- | --- |
| `case-a-valid` | 审批范围内正常签发 | `PASS` |
| `case-b-wrong-identity` | 申请的 CN/SAN 与审批不符（身份越权） | `REJECT_IDENTITY_MISMATCH` |
| `case-c-incomplete` | 发行结果缺签发链与 ca_chain（证据不全） | `REJECT_INCOMPLETE_EVIDENCE` |

另有边界验证覆盖 `REJECT_UNTRUSTED_CHAIN`（独立 Rogue CA 签发）、
`REJECT_TTL_VIOLATION`（10 天证书超出 72h 上限）、回执篡改验签失败、证据调包复算漂移。

## 私钥边界

- 所有 `*.key` 权限 `600`，集中在 `ca/private/` 与 `keys/`，被 `.gitignore` 忽略。
- `receipts/`、`evidence/`、`approvals/` 中可出现的 PEM 仅为**公开证书**（叶子/CA/根），
  全量扫描 `PRIVATE KEY` 命中数为 0。
