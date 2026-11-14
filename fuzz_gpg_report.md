# securesystemslib 内置 OpenPGP 解析器结构化模糊测试报告

- 日期： 2026-11-15；基准 rev: `64b0728`
- 工具： `tests/fuzz_gpg_parser.py`（确定性，`--seed 1400`，纯 Python，不启动外部 gpg）
- 复现： `python3 tests/fuzz_gpg_parser.py --report <out.md>`
- 种子： 10 个签名包 + 6 个公钥 payload + 2 个完整 key bundle，全部取自仓库静态样本
  （`tests/gpg_keyrings/rsa/*.raw`、`tests/gpg_keyrings/eddsa/short.sig`；
  `tests/gpg_keyrings/eddsa/pubring.gpg` 是 0 字节空文件，故 Ed25519 公钥种子按解析器
  自身期望结构合成）。变异算子：包长度字段（失步/重同步两种模式）、子包计数与长度、
  MPI 位长（0/1/7/8/9/±1/+8/0x7FFF/0xFFFF）、边界定点截断 + 每包 120 个随机截断点。

## 判据与各自依据

| 判据 | 依据（独立来源） |
|---|---|
| C1 尾随包隔离 | `parse_signature_packet` 按 `data[header_len:packet_len]` 切片（common.py:698）；尾随的另一包字节不得进入当前签名材料 |
| C2 异常分类 | 各函数 docstring 承诺的公开可捕获异常：`PacketParsingError`/`ValueError`/`IndexError`（`parse_pubkey_bundle` 仅承诺 `PacketParsingError`） |
| C3 截断完整性 | RFC4880 §3.2/§5.2.3.1：MPI 与子包均为长度前缀；截断输入必须报解析错误，不得静默产出不同材料 |
| C4 未知子包容忍（合法对照） | RFC4880 §5.2.3.1：未知子包类型必须可忽略；长度字段含类型字节故最小为 1 |
| C5 bundle 遍历记账 | RFC4880 §12.1 包序列结构；长度字段失步必须被拒绝，不得重叠/错位消费 |

## 解析消费段记录（种子包）

```
rsa-sig        packet_len=315 header=[0,3)  hashed=[9,43)  unhashed=[45,55)  left16=[55,57) mpi=[57,315)
rsa-sig        packet_len=290 header=[0,3)  hashed=[9,18)  unhashed=[20,30)  left16=[30,32) mpi=[32,290)
rsa-expired    packet_len=324 header=[0,3)  hashed=[9,52)  unhashed=[54,64)  left16=[64,66) mpi=[66,324)
rsa-expired    packet_len=577 header=[0,3)  hashed=[9,18)  unhashed=[20,317) left16=[317,319) mpi=[319,577)
eddsa-short    packet_len=118 header=[0,2)  hashed=[8,37)  unhashed=[39,49)  left16=[49,51) mpi=[51,118)
```

C1 对照（25 组：签名包 + 另一真实包/`\x00` 填充）全部通过：解析材料与消费长度均不受尾随字节影响，
尾随包未被吞入当前签名材料。

## 真实发现（可复现反例）

### F-1 `struct.error` 逃出公开异常分类（C2）

- 根因： 多处 `struct.unpack` 直接作用于可能不足的切片——`util.py:61`（`get_mpi_length`）、
  `util.py:264`（0xFF 形式子包头）、`common.py:751/764`（hashed/unhashed 计数）、
  `common.py:827`（创建时间子包）。`struct.error` 不是 `ValueError`/`IndexError`，
  也不在 `_gpg.exceptions` 内；`parse_pubkey_bundle` 只捕获
  `(PacketParsingError, IndexError)`（common.py:296），故同样逃逸。
- 逃逸路径： (a) 签名包体截断在计数字段前；(b) 创建时间子包长度置 0/过短；
  (c) bundle 主钥包体 ≤6 字节 → `parse_pubkey_payload` → `get_mpi_length(b"")`。
- 最小样本（自动缩减）：
  - 26B（计数字段截断）：`8900380400010200029200000208020000000000000000000000`
  - 43B（创建时间子包长度 0）：`89003804000102002200000000000000000000000000000000000000000000000000000000000000006200`
  - 37B（EdDSA 子包计数失步）：`887404001608001d0000000000000000000000000000000000000000000000000000001000`
- 影响： 直接调用 `parse_signature_packet` 的下游（如 in-toto）按文档捕获
  `ValueError`/`IndexError` 时会漏捕；bundle 导入主路径因 `_assign_certified_key_info`
  的宽 `except Exception` 而部分被掩盖，但主钥包本身触发时无保护。

### F-2 EdDSA 签名截断被静默接受（C3）

- 根因： `eddsa.get_signature_params`（eddsa.py:134-150）无任何长度校验，
  短读由 `rjust` 补零——该补零本意是兼容 in-toto#171 的"短签名"，实际接受任意截断。
- 最小样本： 58B `887404001608001d16210000000000000000000000000000000000000000000502000000a700090000000000002d000000000000000000000000`
  （包头声明包体 116B，实际 56B，解析成功且材料不同于原签名）。
- 对照： RSA/DSA 同类截断会抛 `PacketParsingError`（见"仅覆盖到的风险"），行为不一致。
- 影响： 低——后续验签会失败；但解析边界未执行，属于重构适配层时必须显式处理的差异。

### F-3 Ed25519 公钥 payload 截断静默缩短（C3）

- 根因： `eddsa.get_pubkey_params`（eddsa.py:104）`public_key = data[ptr:ptr+32]`
  未校验实得长度。
- 最小样本： 19B `040000000016092b06010401da470f01010740` → 解析成功，`q` 为空串。
- 影响： 低——`create_pubkey` 阶段才会失败；与 RSA 的显式截断检查不一致。

### F-4 零长度子包被静默错位解析（C4）

- 根因： `parse_subpacket_header`（util.py:254-256）对长度 0 返回
  `subpacket_len=1`，类型字节取自**下一个字节**；位于子包区中部时不抛
  `IndexError`（代码注释声称调用方会收到 IndexError，仅当零长度子包在末尾时成立），
  而是静默产生一个幻影子包并把后续字节错位解析。
- 最小样本： 70B `c2c000040001020023000502000000ed00000000000000070000000000000000000400000000001e00000000000a091000000000000000000000000000000000000000000000`
  → 解析成功，`info["subpackets"]` 多出幻影类型 5（unhashed 区情形多出类型 9）。
- 影响： 轻微——只污染 advisory 的 info 字典；但属静默边界违反，且与代码注释的承诺相反。

### F-5 公钥包体尾部垃圾被静默忽略（C5）

- 根因： `parse_pubkey_payload`/RSA handler 不校验包体是否被恰好消费完
  （common.py:142、rsa.py:86-97）；而 keyid 是对**整个包体**计算的（util.py:240）。
- 最小样本： 270B `c6c04e040000000001080000…`（合法 RSA 主钥 + 3 字节尾部垃圾，
  另含一个位长为 0 的 MPI）→ 解析成功，keyid 与规范形式不同。
- 影响： 轻微——非规范包被接受；keyid 变化本身符合 RFC（指纹覆盖传输字节），
  但适配层重构时若要做规范化需注意此处无校验。

### F-6 包长度字段失步被接受，遍历"再同步"（C5，最值得注意）

- 根因： `parse_pubkey_bundle` 无条件信任包头长度（common.py:203-205），
  不校验包体解析是否恰好消费 `body_len`。
- 反例（未缩减，6792B）： 将 rsa bundle 主钥包长度字段 +1（流字节不变）→
  **解析成功**，主钥 keyid 由 `f557d0ff451def45…` 静默变为 `68782a02e006fd12…`，
  User ID 包由 1 个变为 0 个（被错位的 0x00 长度字节吸收成一个被忽略的 0 型幻影包，
  遍历在其后重新同步）。
- 影响： 中低——下游 `get_pubkey_bundle` 按 keyid 查找会失败（`KeyNotFoundError`），
  不会静默用错钥；但解析层本身对结构性失步完全沉默，是适配层重构的主要风险点。

## 仅覆盖到的风险（处理正确，非发现）

- RSA/DSA 截断 MPI 检查（rsa.py:89-90、96-97、130-131；dsa.py 对应四处）：
  标记 `# pragma: no cover` 但实际可达且行为正确——模糊器 1129 次截断变异均落入
  可允许异常（`PacketParsingError("This signature was truncated!")` 等）。
- `common.py:756` hashed 计数一致性检查同样标了 `pragma: no cover` 但可达且生效
  （见 W1）。两处 coverage 标注本身值得修正。
- 部分体长（新格式 224-254）与不定长（旧格式类型 3）包头 → 正确抛 `PacketParsingError`。
- 未知子包合法对照 18/18 通过：类型 100 子包插入 hashed/unhashed 区均被忽略，
  keyid/签名材料不变。
- bundle 在包边界 ±1 截断 → 均抛带位置信息的 `PacketParsingError`。
- `get_mpi_length(0)` 返回 1（RFC4880 §3.2 规定 0 位 MPI 占 0 字节）：轻微规格偏差，
  不致崩溃，仅记录。
- `parse_pubkey_bundle(bytearray(...))` → `TypeError: unhashable type`：
  输入类型契约（bytes）之外的行为，仅记录。

## 弱化实验（变异测试，验证模糊器敏感度）

| 实验 | 弱化点 | 完整代码行为 | 弱化后行为 | 模糊器反例 |
|---|---|---|---|---|
| W1（包长度判断） | 删除 common.py:756-759 hashed 计数一致性检查 | `ValueError("unexpected amount of hashed octets")` | `struct.error: unpack requires a buffer of 2 bytes` | C2 EXC-TAXONOMY：rsa-sig 种子 hashed-count=0xFFFF |
| W2（MPI 边界判断） | 删除 rsa.py:130-131 签名 MPI 截断检查 | `PacketParsingError("This signature was truncated!")` | 静默解析成功，签名仅 8 字节（应为 256） | C3 SILENT-TRUNC：rsa-sig 种子 truncate@62 |

两处弱化均已回退（`git diff` 对 `securesystemslib/` 为空）。注意 W1 的自动缩减产物
（7B `89003804000102`）塌缩到了基线也可达的 F-1 路径——缩减谓词只匹配异常类型，
因此 W1 的精确见证是**未缩减**的种子级反例；这是最小化器的已知局限。

## 结论

重构 GPG 适配层前需要显式决策的边界：(1) 统一把 `struct.error` 包装进公开解析异常；
(2) EdDSA 与 RSA/DSA 的截断语义对齐；(3) 子包长度 0 的拒绝策略；(4) 包体消费完整性
（F-5/F-6）是否在校验层补充断言。C1（尾随包隔离）与 C4 合法对照当前行为正确，可作为
重构的回归基线。
