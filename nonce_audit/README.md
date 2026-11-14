# ECDSA nonce 重用离线审计工具

面向自有测试签名日志的**离线**分析工具：给定曲线、公钥、签名 (r, s) 与
实际摘要，判断是否存在 ECDSA nonce 重用。工具不联网、不读取样本之外的任何
材料，只处理调用方显式提供的合成或授权样本。

## 判定原则

相同 `r` 只是**线索**，不能直接下结论。工具对每个同 `r` 分组执行：

1. **标准 ECDSA 验证**：每条签名必须与其声明公钥、摘要相互印证；
2. **low-S 规范化**：枚举两条 `s` 的 4 种方向组合（原值 / 取反），
   兼容日志混用 high-S 与 low-S 的情况；
3. **差分推导**：对不同消息配对计算候选私钥
   `d = (s2·z1 − s1·z2) / (r·(s1 − s2)) (mod n)`，
   并恢复 `k = (z1 + d·r) / s1 (mod n)`；
4. **三重确认**，全部满足才报告 `confirmed_nonce_reuse`：
   - 候选 `d·G` 等于记录声明的公钥；
   - 组内全部有效签名都能被该 `d` 解释；
   - 所有不同消息配对收敛到同一个 `d`。

无法确认时保留为线索并给出原因码：

| 原因码 | 含义 |
| --- | --- |
| `duplicate_record` | 同摘要且 low-S 规范化后 `s` 相同的重复日志，无新增信息 |
| `same_message_repeat` | 同一消息重复签名，差分消不掉 `z`，数学上不可推导 |
| `denominator_noninvertible` | 差分分母不可逆（如 `s1 ≡ s2 (mod n)`） |
| `no_candidate_matches_pubkey` | 候选 `d` 均无法重现公钥，线索不成立 |
| `cross_key_r_collision` | 相同 `r` 来自不同公钥，属碰撞，禁止跨钥匙合并推导 |
| `invalid_signature_in_group` | 组内含验证失败的签名，证据链不完整 |
| `single_record` | 同 `r` 只有一条记录，没有可配对的第二条签名 |

恢复出的私钥 `d` 与 nonce `k` **默认不输出**；仅在显式传入
`--reveal-secrets` 时写入报告，JSON 中以 `secrets.redacted=false` 标注。

## 输入格式

JSON 文件（`-` 表示标准输入），`schema` 固定为 `ecdsa-nonce-audit/v1`：

```json
{
  "schema": "ecdsa-nonce-audit/v1",
  "records": [
    {
      "id": "sig-0001",
      "curve": "NIST256p",
      "public_key": {"x": 123, "y": 456},
      "digest": "十六进制摘要",
      "r": 111,
      "s": 222
    }
  ]
}
```

- 支持曲线：`NIST192p`、`NIST224p`、`NIST256p`、`NIST384p`、
  `NIST521p`、`SECP256k1`（以及 `P-256`、`secp256r1` 等别名）。
- 公钥支持 `{"x", "y"}` 整数/十六进制、`{"sec1": hex}`（含压缩格式）、
  `{"pem": "..."}` 三种形式。
- `digest` 是实际摘要的十六进制；工具按 FIPS 186-4 取最左
  `order.bit_length()` 位得到 `z`。
- `r` / `s` 接受整数或十六进制字符串，越界直接拒绝整个样本。

## 用法

```bash
# 生成覆盖全部判定分支的合成故障样本（私钥默认不落盘）
python -m nonce_audit generate-demo sample.json
python -m nonce_audit generate-demo sample.json --emit-private  # 本地交叉验证

# 文本报告（默认隐藏私钥）
python -m nonce_audit analyze sample.json

# 机器可读 JSON
python -m nonce_audit analyze sample.json --format json

# CI 场景：确认重用时退出码为 2
python -m nonce_audit analyze sample.json --fail-on-confirmed
```

## 演示样本覆盖的对照情形

`generate-demo` 用种子化 RNG 生成固定样本，包含：

- 固定 `k` 签三条不同消息（含一条 high-S 翻转）→ 应确认重用；
- 其中一条的完全重复日志 → 重复记录线索；
- RFC 6979 健康签名器，`r` 两两不同 → 无告警；
- 独立钥匙用 `n−k` 构造相同 `r` → 跨钥匙碰撞，不可确认；
- 摘要被篡改的记录 → 验证失败，不阻断同桶有效证据；
- 同 `k` 同消息的 `s` 翻转记录 → 重复 + 分母不可逆；
- 随机 `s` 的伪造外观记录 → 候选 `d` 不匹配公钥。

## 测试

```bash
python -m pytest tests/ -q
```
