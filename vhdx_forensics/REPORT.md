# VHDX 非空日志与“崩溃前最后状态”承诺核查报告

范围：仅核查当前加载流程（`dissect.hypervisor.disk.vhdx.VHDX`）对 VHDX 变更日志
（change log / 重放日志）的处理，并给出只读的状态对照与接收建议。原始证据
（`tests/_data/disk/vhdx/*.gz`）全程未被修改；所有可执行演示均基于在
`vhdx_forensics/synthetic/` 下新生成的合成盘，或在临时目录解压的副本。

---

## 1. 结论摘要

调查服务把读取器对磁盘的**直接读取结果**称为“崩溃前最后状态”，这一承诺在
日志非空时**不成立**。当前读取器完全不解析、不校验、不重放变更日志，它返回的
始终是 BAT/元数据所指向的**已落盘提交状态**。该状态只有在“无待重放事务”时才
等于崩溃前一致状态；一旦存在有效但尚未应用的日志，直接读取得到的是**更新前的
旧镜像**，而不是最后状态。

关键事实（在仓库自带 `fixed.vhdx.gz`、`dynamic.vhdx.gz` 上实测）：

- 两个文件的活动 header `log_guid` 均为全零（表示“无活动日志 / 已干净关闭”）。
- 但其 1 MB 日志窗口内**确实存在 CRC-32C 校验正确的 `loge` 条目**（fixed 2 条、
  dynamic 2 条），条目携带的 `log_guid` 是非零 GUID，与 header 的零 GUID **不匹配**。
- 这是典型的**陈旧/孤立日志（orphan/stale log）**：能被扫描出来，但按 MS-VHDX 规则
  绝不允许重放。读取器恰好因为“忽略整个日志”而返回了正确的已提交视图——这是
  巧合性正确，而非它实现了崩溃一致性。

---

## 2. 当前读取器到底做了什么（沿加载流程逐点核对）

源码：`dissect/hypervisor/disk/vhdx.py`、`dissect/hypervisor/disk/c_vhdx.py`。

1. **双 header（`vhdx.py:64-73`）**
   - 读取 offset 64 KiB、128 KiB 两个 header，直接比较 `sequence_number`，取序号大者。
   - **不校验 header 的 CRC-32C 校验和**；`c_vhdx.header` 虽解析了 `checksum` 字段，
     但代码从不使用它。
   - 解析了 `log_guid / log_offset / log_length / log_version`，但**之后从不引用**。

2. **双 region table（`vhdx.py:75-82`）**
   - 只使用 `region_table1`（3 MiB），`region_table2` 被构造但未参与任何决策。
   - **不校验 region table 校验和**；不比较两份表是否一致。

3. **元数据与 BAT（`vhdx.py:84-102`）**
   - 从 region table 取 metadata、BAT 偏移，解析虚拟磁盘大小、块大小、扇区大小等。
   - BAT 条目在 `read_sectors` 中按 `state` 决定读零、读父盘或读物理偏移。
   - 元数据表无校验和字段，读取器也不做额外完整性检查。

4. **变更日志：完全缺位**
   - 全文件没有任何 `loge` / 日志描述符（`dddd`/`zero`/`desc`）结构定义；
     `c_vhdx.py` 中没有日志条目结构体，也没有 LOG region GUID 常量。
   - 没有“header `log_guid` 是否非零”“条目 GUID 是否与 header 链接”
     “条目 CRC-32C”“序列号连续性”的任何判断。
   - 因此读取器**无法区分**：干净关闭、有效待重放、孤立日志、损坏日志。

5. **读取语义（`vhdx.py:106-178`）**
   - `read_sectors` 只依据当前 BAT 的 `file_offset_mb` 到物理文件取字节。
   - 当日志里挂着对同一数据区或对 BAT 本身的待应用更新时，这些更新对读取器不可见，
     输出保持为日志写入**之前**的内容。

> 读取器给出的准确定义是：**“当前 header/BAT 所引用的、磁盘上已提交字节的视图”**。
> 它不是、也未自称具备日志重放能力；把它标注为“崩溃前最后状态”是调查流程外加的、
> 缺乏依据的承诺。

---

## 3. MS-VHDX 决定可重放性的四个链接条件

一份日志即使能被扫描、签名是 `loge`、校验和正确，也只有同时满足下列条件才构成
可安全重放的事务（参见 MS-VHDX 日志重放规则）：

1. **header 声明活动日志**：活动 header 的 `log_guid` 非零，且 `log_offset/log_length`
   窗口覆盖这些条目。
2. **GUID 链接**：每条 `loge` 的 `log_guid` 必须与活动 header 的 `log_guid` **逐字节相等**。
   header 为零 GUID 而条目非零（本仓库样本即如此）→ 孤立日志，禁止重放。
3. **校验和**：header、region table、每个 `loge` 的 CRC-32C（Castagnoli，非普通 CRC-32）
   全部正确。任一错误 → 事务完整性无法证明。
4. **序列连续性**：`loge` 的 `sequence_number` 严格递增（本工具要求相邻差 1），
   且 tail 指针形成完整链；出现断链/回绕异常 → 不可重放。

“能扫描出日志条目”只证明该磁盘区域留有日志形态的数据，**不授予重放许可**。

---

## 4. 三分类（接收口径）

| 类别 | 结构判据 | 直接读取是否可信 | 处置 |
|---|---|---|---|
| **已应用状态 APPLIED / clean** | 无待重放条目（header `log_guid=0` 且无有效载荷条目） | 是，直接读取=最后提交状态 | 可直接接收 |
| **可确认但未应用 CONFIRMED-BUT-NOT-APPLIED** | header 非零 GUID、GUID 链接成立、全部 CRC 正确、序列连续 | 否，直接读取是更新前旧镜像 | 先在受控副本上重放，再读取重放视图 |
| **材料不足 INSUFFICIENT-MATERIAL** | 有日志条目但 GUID 不匹配/校验和错/序列断裂/header 未声明活动日志 | 仅可作为“已提交字节”证据，不可称崩溃前最后状态 | 禁止重放；标注局限，补充来源证据 |

---

## 5. 可运行的状态对照（短合成例子）

同一逻辑磁盘、同一份已提交数据区，仅改变日志状态，生成 5 个变体
（`make_synthetic.py`，输出于 `vhdx_forensics/synthetic/`）：

- `clean.vhdx`：header 零 GUID，无待重放日志。
- `active.vhdx`：有效活动日志，含一条 `dddd` 数据描述符，把同一负载扇区
  从 `COMMITTED...` 更新为 `PENDING...`，但尚未落盘。
- `orphan.vhdx`：与 active **完全相同的日志字节**，仅 header `log_guid` 置零（孤立日志）。
- `bat_pending.vhdx`：有效活动日志，含一条 `desc` 描述符，把负载块 BAT 重映射到
  第二个已存在数据区（演示 BAT/元数据类更新）。
- `corrupt.vhdx`：GUID 链接成立但翻转一个负载字节且不更新 CRC，制造校验和失败。

运行：

```sh
.venv/bin/python vhdx_forensics/run_comparison.py
```

实测输出（同一数据区，直接读取恒定为已提交字节，但完整性承诺不同）：

| 文件 | 读取器直接读取 | 完整性分类 | 安全恢复视图 |
|---|---|---|---|
| clean.vhdx | `COMMITTED-BYTE...` | APPLIED / clean | 无需重放（拒绝重放是正确行为） |
| active.vhdx | `COMMITTED-BYTE...`（旧） | CONFIRMED-BUT-NOT-APPLIED | `PENDING-LOG-UPDATE...`（内存重放） |
| orphan.vhdx | `COMMITTED-BYTE...` | INSUFFICIENT-MATERIAL | 拒绝重放 |
| bat_pending.vhdx | `COMMITTED-BYTE...`（旧映射） | CONFIRMED-BUT-NOT-APPLIED | `REMAP-TARGET...`（内存重放 BAT） |
| corrupt.vhdx | `COMMITTED-BYTE...` | INSUFFICIENT-MATERIAL | 拒绝重放（CRC 失败） |

要点：`active` 与 `orphan` 的**日志字节逐字节相同、数据区也相同**，读取器对两者
返回完全一致的直接读取结果；但前者可恢复到更新后状态，后者绝不能重放。这正说明
**同样的直接字节在不同有效日志状态下不能给出同一完整性承诺**。

只读保证：`build_recovered_view` 只在内存 `bytearray` 上重放，证据文件以 `rb` 打开；
`test_evidence_file_is_never_modified` 用 SHA-256 前后比对证明文件未被改动。

---

## 6. 安全恢复视图尚缺的条件（相对当前读取器）

当前读取器要诚实地提供“崩溃前最后状态”，至少还需补齐：

1. 校验并比较**双 header / 双 region table** 的 CRC-32C 与一致性，而非只取序号大的
   header、只用 region table 1。
2. 解析日志窗口：识别 `loge` 条目、tail 链、`sequence_number`、条目 `log_guid`、
   数据/零/BAT（`dddd`/`zero`/`desc`）描述符及其 4 KiB 对齐负载。
3. 实现第 3 节的**四项可重放性闸门**；任一不满足即拒绝重放并降级为“仅已提交视图”。
4. 在**可写副本而非原始证据**上按序列号顺序重放：先应用数据/零描述符到负载区，
   再应用 `desc` 到 BAT/元数据，重算受影响结构校验和。
5. 在输出中**显式标注**数据来源等级（已提交 / 已重放 / 材料不足），而不是统一冠以
   “崩溃前最后状态”。

在这些能力补齐前，安全做法是维持只读、不重放，并按下节口径接收。

---

## 7. 接收建议（triage）

- **默认按“已提交字节视图”接收**，报告措辞改为“磁盘当前已提交内容（未应用日志）”，
  不要使用“崩溃前最后状态”。
- 对 header `log_guid != 0` 的盘：运行本工具审计；仅当判定为
  CONFIRMED-BUT-NOT-APPLIED 时，在**取证副本**上重放后再分析，并同时保留原始直读结果。
- 对孤立/损坏日志（本仓库两个样本即属此类）：**禁止重放**；其直读结果可作为已提交
  状态证据，但需注明“存在不可链接/不可校验的残留日志，崩溃瞬间的未落盘更新无法还原”。
- 保留 hash、header/region/日志校验结果与分类结论，形成可复核的证据链。

---

## 8. 工具与复现

- `vhdx_forensics/vhdx_audit.py`：只读审计器（双 header/region/BAT/日志、CRC-32C、
  GUID 链接、序列号、三分类）。
- `vhdx_forensics/crc32c.py`：纯 Python CRC-32C（Castagnoli）。
- `vhdx_forensics/safe_replay.py`：仅内存重放，含可重放性闸门，拒绝不安全重放。
- `vhdx_forensics/make_synthetic.py`：生成 5 个合成变体（不触碰原证据）。
- `vhdx_forensics/run_comparison.py`：直接读取 / 审计分类 / 恢复视图三向对照。
- `vhdx_forensics/audit_cli.py`：对任意 VHDX 输出完整审计文本。
- `vhdx_forensics/test_forensics.py`：6 项自测，全部通过；仓库原基线
  `pytest tests/disk/test_vhdx.py tests/disk/test_qcow2.py` 仍为 20 passed。

```sh
.venv/bin/python vhdx_forensics/make_synthetic.py vhdx_forensics/synthetic
.venv/bin/python vhdx_forensics/run_comparison.py
.venv/bin/python vhdx_forensics/audit_cli.py vhdx_forensics/synthetic/active.vhdx
.venv/bin/python -m pytest -q vhdx_forensics/test_forensics.py
```
