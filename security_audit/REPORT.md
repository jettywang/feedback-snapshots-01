# uefi_firmware “签名验证通过”结论核查报告

日期：2026-11-18 ｜ 对象：uefi-firmware-parser @ 4942c48 ｜ 实验脚本：`security_audit/audit_signed_status.py` ｜ 原始输出：`security_audit/audit_results.json`

## 结论摘要

安全报告中“固件签名验证通过”的两处来源都**不是**密码学验证：

1. **GUID-defined section 的 `AUTH_VALID`** —— 来自 section 头里 2 字节 `attrs` 状态位（`ATTR_AUTH_STATUS_VALID = 0x02`）的回显，见 `uefi_firmware/uefi.py:884-900`（`showinfo`/`to_dict`）。该位是**镜像制作者写入的自我声明**（PI 规范中由构建/更新流程在验证后置位），解析器只做 `attrs == 0x02` 判断，全库没有任何签名/证书/哈希校验代码。
2. **“signed capsule”** —— 来自胶囊头 16 字节 GUID 的**名称匹配**（`APTIO_SIGNED_CAPSULE_GUID`），见 `uefi_firmware/misc/checker.py:61-64`（`AptioSignedCapsuleTester.match` 仅比较前缀）与 `uefi_firmware/uefi.py:2049-2063`（signed 与 unsigned Aptio 胶囊走**完全相同**的解析路径，AMI 签名块从未被定位、解析或验证）。

## 实验 A：AUTH_VALID 是状态位回显

构造可解析的 GUID-defined section（未知 GUID + 自定义 payload），对照篡改：

| 输入 | attrs 字段 | payload SHA-256 前 8 | 解析器报告 |
|---|---|---|---|
| 置位 + 原始 payload | 0x02 | 05835dad | `AUTH_VALID` |
| 置位 + **篡改** payload | 0x02 | a1122008 | `AUTH_VALID` |
| 清位 + 原始 payload | 0x00 | 05835dad | `ATTR_UNKNOWN` |

篡改内容后显示不变；清空状态位后同内容立刻变成 `ATTR_UNKNOWN`。证明显示只跟状态位走，与内容无关。

## 实验 B：signed capsule 是 GUID 名称匹配

同一 ROM 分别套 signed/unsigned Aptio GUID，再对 signed 版篡改 ROM 体 1 字节：

| 输入 | 解析类型 | process() | 报签名错误 |
|---|---|---|---|
| signed GUID + 完整 ROM | FirmwareCapsule | True | 否 |
| unsigned GUID + 同一 ROM | FirmwareCapsule | True | 否 |
| signed GUID + **篡改** ROM | FirmwareCapsule | True | 否 |

另：`AptioSignedCapsuleTester().match(GUID + 64 字节垃圾)` 返回 `True` —— 检测器只认 16 字节前缀。

## 实验 C：独立密码学校验（openssl，真实调用）

对实验 B 的胶囊体（`capsule[0x40:0x1240]`，RomImageOffset 到末尾，共 4608 字节）做 RSA-2048/SHA-256 分离签名：

- 签名覆盖字节：**显式选取的胶囊体区间**；真实 AMI/UEFI 封装各有自己的签名块与覆盖范围，必须先真实解析才能确定。
- 可信材料来源：**调用方提供的证书**（实验中临时自签，即无真实信任锚）。uefi_firmware 不内置任何厂商密钥，也没有接收信任根的 API。

真实 openssl 调用结果：

```
sign_body_sha256   rc=0
verify_intact      rc=0  "Verified OK"
verify_tampered    rc=1  "Verification failure ... rsa routines: bad signature"
```

同一签名、篡改 1 字节即验签失败 —— 这才是“数学验证成立/不成立”的判定方式，解析器目前不具备。

## 厂商封装边界（明确不支持）

- **AMI Aptio signed capsule**：AMI 私有签名块格式，解析器不定位、不解析、不验证；“signed” 仅是 GUID 名字。
- **UEFI / FMP capsule**（GUID [2]/[3]）：`uefi_firmware/uefi.py:2065-2074` 只读 `size/flags/image_size`，`CAPSULE_FLAGS` 与 FMP 认证头（`EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER` / 证书块）均未解析。
- 对上述格式，任何“已验证/未验证”的结论都超出当前解析器能力，只能报“未知”。

## 给后端的状态建议

不要用单一布尔或“验证通过/失败”二值。建议三轴 + 解析状态：

```json
"signature": {
  "material_present": "true|false|unknown",
  "math_valid":       "true|false|unknown",
  "trust_anchored":   "true|false|unknown",
  "parse_status":     "ok|parse_error|unsupported_format",
  "declared":         {"capsule_guid": "...", "auth_status_bit": "valid|unknown"}
}
```

映射规则：

- `material_present`：签名/证书块被**真实解析定位**才为 true；GUID 名称匹配只能填进 `declared`，不得置 true。
- `math_valid`：只有跑过密码学验签才填 true/false（如实验 C）；未执行一律 `unknown`。
- `trust_anchored`：数学验证通过 **且** 证书链到调用方信任根才为 true；自签/无链为 false。
- **解析失败 ≠ 签名无效**：`parse_status=parse_error` 时三个轴全部为 `unknown`，文案用“无法判定”，禁止写“签名无效”。
- `AUTH_VALID` 位只映射为 `declared.auth_status_bit="valid"`（镜像自我声明），展示文案应为“镜像声明已验证”，而非“签名验证通过”。

当前代码下，后端能拿到的上限是：`declared` 两个字段 + `parse_status`；三个验证轴恒为 `unknown`。
