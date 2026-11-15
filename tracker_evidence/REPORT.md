# LNK TrackerDataBlock 关联调查报告

日期：2026-11-15
工具链：`lnk_tracker_view.py`（证据视图，基于 dissect.shellitem 解析并交叉校验）→
`make_samples.py`（合成样本）→ `correlate.py`（批量关联）。
分析对象：`samples/` 下 7 份合成 LNK。

## 1. 证据视图方法

`lnk_tracker_view.py` 按 MS-SHLLINK 结构顺序走查文件
（SHELL_LINK_HEADER → LINKTARGET_IDLIST → LINKINFO → STRING_DATA → EXTRA_DATA），
定位 TRACKER_PROPS 块（签名 `0xA0000003`），逐字段记录**绝对文件偏移 + 原始字节 + 解码值**，
并用 dissect.shellitem 的 `Lnk` 解析结果交叉校验。TrackerDataBlock 字段偏移（相对块起始）：

| 字段 | 块内偏移 | 大小 | 样本文件内绝对偏移 |
|---|---|---|---|
| block_size / signature | 0x00 / 0x04 | 4+4 | 0x4c / 0x50 |
| length (=0x58) | 0x08 | 4 | 0x54 |
| version (=0) | 0x0c | 4 | 0x58 |
| machine_id | 0x10 | 16 | 0x5c |
| volume_droid（当前卷） | 0x20 | 16 | 0x6c |
| file_droid（当前文件） | 0x30 | 16 | 0x7c |
| volume_droid_birth | 0x40 | 16 | 0x8c |
| file_droid_birth | 0x50 | 16 | 0x9c |

（本批样本 link_flags=0，EXTRA_DATA 紧跟 0x4c 字节头部；工具对含 IDList/LinkInfo/StringData
的样本同样按结构走查计算偏移。）

## 2. GUID 混合端序：由原始字节复算

Droid 字段按 GUID packet representation（MS-DTYP 2.3.4.2）存储：前三个字段小端，后 8 字节原样。
以 `gamma_same_machine_name.lnk` 的 volume_droid（偏移 0x6c）为例：

```
原始字节: 67 45 23 01 ab 89 ef cd 01 23 45 67 89 ab cd ef
Data1 = LE u32(67 45 23 01) = 01234567
Data2 = LE u16(ab 89)       = 89ab
Data3 = LE u16(ef cd)       = cdef
Data4 = 原样(01 23 45 67 89 ab cd ef) = 0123-456789abcdef
GUID  = 01234567-89ab-cdef-0123-456789abcdef   ✓ 与 UUID(bytes_le=raw) 一致
```

证据视图中每个 droid 字段都带 `recompute` 值，可独立复算，不依赖解析器结论。

## 3. 样本与证据要点

| 样本 | machine_id | 当前对 (vol,file) | birth 对 (vol,file) | 备注 |
|---|---|---|---|---|
| alpha_created.lnk | DESKTOP-ALPHA01 | VB1, FB1 | VB1, FB1 | 新建，当前=birth |
| alpha_duplicate.lnk | DESKTOP-ALPHA01 | VB1, FB1 | VB1, FB1 | 同一快捷方式副本 |
| beta_moved.lnk | DESKTOP-ALPHA01 | VC2, FC2 | VB1, FB1 | birth 同 alpha，当前对已变 |
| gamma_same_machine_name.lnk | DESKTOP-ALPHA01 | VG1, FG1 | VG1, FG1 | 仅机器名相同 |
| delta_shared_volume.lnk | DESKTOP-BETA02 | VB1, FD1 | VB_D, FB_D | 仅共享 alpha 的当前卷 GUID |
| epsilon_zeroed.lnk | DESKTOP-GAMMA03 | 全零 | 全零 | 无可用身份 |
| zeta_truncated.lnk | DESKTOP-DELTA04 | VB1, FB1 | **缺失** | 块声明 0x60 字节，实际仅 0x40 |

异常记录（证据视图 `anomalies`）：
- `epsilon_zeroed.lnk`：四个 droid 字段 `all_zero=true`，不作为身份参与匹配。
- `zeta_truncated.lnk`：`truncated: declared 0x60 bytes, only 0x40 available`；
  `volume_droid_birth`/`file_droid_birth` 标记 `missing`，保留已存字段原值；
  dissect.shellitem 对该块拒绝解析（`tracker_props_parsed=false`），两口径一致记录差异。

## 4. 关联结果（correlation.json）

关联策略显式声明所用身份对：**当前对** = (volume_droid, file_droid)，
**birth 对** = (volume_droid_birth, file_droid_birth)。

### 可支持的关联

- **R1 同一对象**（当前对 + birth 对均相同且非零）：
  `alpha_created.lnk` + `alpha_duplicate.lnk` —— 同一被跟踪对象的相同快照/副本。
- **R2 迁移候选**（birth 对相同、当前对分歧）：
  `alpha_created.lnk` / `alpha_duplicate.lnk` ↔ `beta_moved.lnk`，
  关联依据 = birth 对 `(11111111-…-555555555555, aaaaaaaa-…-eeeeeeeeeeee)`。
  三者 birth 相同说明同源；`beta_moved.lnk` 当前对变为
  `(66666666-…, ffff0000-…)` 提示对象在其后被移动。**记录保持分立，不合并**：
  同 birth 身份但当前身份不同，正是迁移链的证据价值所在。

### 不足以关联的反例（R3）

- `gamma_same_machine_name.lnk` 与 alpha/beta：**仅 machine_id 相同**
  （`DESKTOP-ALPHA01`），四个 droid 全不同 → 不足以关联。机器名可重用、可伪造。
- `delta_shared_volume.lnk` 与 alpha：**仅当前卷 GUID 相同**（VB1），
  文件 droid 与 birth 对均不同 → 不足以关联。同卷上可以有任意多文件。
- `delta_shared_volume.lnk` 与 `zeta_truncated.lnk`：同样仅单个卷 GUID 重合 → 不足以关联。

### 部分匹配（R5，报告但不确认）

- `zeta_truncated.lnk` 与 `alpha_created.lnk`/`alpha_duplicate.lnk`：
  当前对完整一致，但 zeta 的 birth 对因截断缺失，无法确认同一对象 —— 列为候选线索，
  需其他证据（如 LinkInfo、IDList、时间戳）补强。

### 无法关联

- `epsilon_zeroed.lnk`：全部 droid 字段为零，零值不构成身份，不参与任何匹配
  （包括与其他全零字段互配）。

## 5. 限制与声明

- TrackerDataBlock 是自报告元数据：字段相同**不证明目标文件当前存在**，
  也**不证明 machine_id 对应真实主机**（可重名、可伪造、可来自镜像/副本）。
- 全零字段、局部损坏（截断/尺寸不符）按原样保留并标注，不做猜测性补全。
- 任何合并结论都必须声明所用身份对（当前对 / birth 对）；单 GUID 或单机器名重合
  一律不构成合并依据。
