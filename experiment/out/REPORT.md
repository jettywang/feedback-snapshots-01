# EWF → ASDF 取证可证明性实验

生成时间：`2026-11-15T07:37:38.094307+00:00`  
转换器：`experiment/forensic_conversion.py`  
转换器 SHA256：`819bd0ccd5eb307df976e53ff7581a9beeb243598633a20c6e384501421f15e1`  
接口：`dissect.evidence.ewf.EWF`（源）与 `dissect.evidence.asdf.AsdfWriter/AsdfSnapshot`（派生）

## 结论先行

ASDF 能证明的是：**本次转换程序从 EWF 读出的逻辑字节，被完整、可校验地写入了 ASDF**。它不能证明：原 EWF 段文件仍是采集时的那些字节、EWF 容器级校验当时通过、采集错误范围内的占位字节是原始介质内容、或段集合在采集时完整。ASDF 的 SHA256 只是 ASDF 文件自身的哈希，不是原始 EWF 文件哈希；EWF 的存储 MD5 也只是采集工具对逻辑流的声明，不是介质原件哈希。

## 实验对象

| 案例 | 源 | 段数 | 声明错误 | 用途 |
|---|---|---|---|---|
| A 正常 | `tests/_data/ewf/segmented/image.E01..E05` | 5 | 无 | 建立基线：容器校验、逻辑内容、元数据齐全 |
| B 变体 | 由 A 复制并合成修改 | 5 | 8 个扇区（4 KiB） | 展示坏扇区占位、错误声明与 ASDF 语义丢失 |
| C 不完整 | A 去掉 E05 | 4/5 | — | 展示来源不完整时必须保留不完整标记 |

> 案例 B 是**合成变体**，不是真实采集。它的 `error2` 段是实验定义的编码；本仓库的 EWF 读取器不解析 `error2`，只把它作为未知 Section 暴露原始字节。这个事实本身是结论的一部分：现有接口不提供采集错误范围的一等语义。

## 逐项追踪

### 1. 原段身份

| # | 段 | 字节 | 段文件 SHA256 | 段号 | set_identifier |
|---|---|---|---|---|---|
| 0 | `image.E01` | 1,018,464 | `dff882f955c5cccb79690e9f5be42125c8b5875052f1d3d1dda1d7de597fb6c8` | 1 | 9a132fa3912542deaf9fc28e8a763365 |
| 1 | `image.E02` | 1,017,681 | `9bd439cdbb5158c1bbc4c12ccac98dc874655573977214763895eb043004f32e` | 2 | 9a132fa3912542deaf9fc28e8a763365 |
| 2 | `image.E03` | 1,017,681 | `35bc51ba09665794b3852cfe57b9415c7aca901185e64abcd22e90c8b6ebb361` | 3 | 9a132fa3912542deaf9fc28e8a763365 |
| 3 | `image.E04` | 1,017,681 | `b4823add0c226c42255be4c2cc09ee80cce4f03f107c8c2c7b84e48a46449fce` | 4 | 9a132fa3912542deaf9fc28e8a763365 |
| 4 | `image.E05` | 132,761 | `78844b5d5b80695ba6d8c0901c28820389ebd6bacb0330a934ca01ec06bcd8d1` | 5 | 9a132fa3912542deaf9fc28e8a763365 |

正常镜像的段集合指纹：`5354e4a84ca27949245e764eba7688a745a3caedf4a196e452290dcd622f40ea`。该指纹只覆盖转换时读取到的段文件字节；要证明它是采集时的段集合，必须与原始交接记录中的段哈希逐一比对。

### 2. 采集错误范围

| 字段 | 值 | 取证含义 |
|---|---|---|
| first_sector | 1,984 | 声明的首个坏扇区（LBA） |
| number_of_sectors | 8 | 声明范围长度 |
| byte_start / byte_end | `0xf8000` – `0xf9000` | 逻辑流中的字节区间 |
| placeholder | `0x00` | 变体中实际写入的占位模式 |
| error_granularity | 64 | EWF 卷声明的错误粒度（扇区） |
| content_status | unverified_placeholder | **未验证占位，不得当作已确认内容** |

变体构造：复制正常 5 段后，在 `image.E02` 的 chunk 31（文件偏移 `0x4c1`） 将 4,096 字节置零，重算该未压缩块的尾部 adler32，再在 E05 的 `hash` 段前插入 100 字节 `error2` 段，并重算 hash 段的 MD5 与 adler32。因此变体是**自洽但合成**的容器：它演示“声明 + 占位”如何进入证据链，不证明任何真实介质状态。

正常镜像没有 `error2` 声明。注意：正常镜像里也存在全零块（例如 chunk 0），**零字节本身不等于坏扇区**；只有采集声明、错误日志或工具元数据才能把某个范围标为错误。把“看起来是零”当成“坏扇区”或反过来把“声明为坏扇区”当成“内容已确认”都是不成立的。

### 3. 容器级校验

| 段 | Section | 偏移 | raw size | descriptor adler32 | body 校验 | body OK |
|---|---|---|---|---|---|---|
| 1 | header2 | `0xd` | 296 | yes | adler32(decompressed, big-endian) | yes |
| 1 | header2 | `0x135` | 296 | yes | adler32(decompressed, big-endian) | yes |
| 1 | header | `0x25d` | 191 | yes | adler32(decompressed, big-endian) | yes |
| 1 | volume | `0x31c` | 1,128 | yes | adler32 | yes |
| 1 | sectors | `0x784` | 1,016,008 | yes | deferred_to_last_chunk_check | — |
| 1 | table | `0xf884c` | 228 | yes | adler32(entries) | yes |
| 1 | table2 | `0xf8930` | 228 | yes | adler32(entries) | yes |
| 1 | next | `0xf8a14` | 0 | yes | unknown_section_no_public_checksum_rule | — |
| 2 | data | `0xd` | 1,128 | yes | adler32 | yes |
| 2 | sectors | `0x475` | 1,016,008 | yes | deferred_to_last_chunk_check | — |
| 2 | table | `0xf853d` | 228 | yes | adler32(entries) | yes |
| 2 | table2 | `0xf8621` | 228 | yes | adler32(entries) | yes |
| 2 | next | `0xf8705` | 0 | yes | unknown_section_no_public_checksum_rule | — |
| 3 | data | `0xd` | 1,128 | yes | adler32 | yes |
| 3 | sectors | `0x475` | 1,016,008 | yes | deferred_to_last_chunk_check | — |
| 3 | table | `0xf853d` | 228 | yes | adler32(entries) | yes |
| 3 | table2 | `0xf8621` | 228 | yes | adler32(entries) | yes |
| 3 | next | `0xf8705` | 0 | yes | unknown_section_no_public_checksum_rule | — |
| 4 | data | `0xd` | 1,128 | yes | adler32 | yes |
| 4 | sectors | `0x475` | 1,016,008 | yes | deferred_to_last_chunk_check | — |
| 4 | table | `0xf853d` | 228 | yes | adler32(entries) | yes |
| 4 | table2 | `0xf8621` | 228 | yes | adler32(entries) | yes |
| 4 | next | `0xf8705` | 0 | yes | unknown_section_no_public_checksum_rule | — |
| 5 | data | `0xd` | 1,128 | yes | adler32 | yes |
| 5 | sectors | `0x475` | 131,184 | yes | deferred_to_last_chunk_check | — |
| 5 | table | `0x204e5` | 124 | yes | adler32(entries) | yes |
| 5 | table2 | `0x20561` | 124 | yes | adler32(entries) | yes |
| 5 | hash | `0x205dd` | 112 | yes | adler32 | yes |
| 5 | done | `0x2064d` | 0 | yes | empty | — |

EWF 存储 MD5：`9683f7575933eac7390416991cfc5b84`；本次从逻辑流重算 MD5：`9683f7575933eac7390416991cfc5b84`；一致：yes。

最后一个未压缩块的尾部 adler32：`adler32`（stored=`0x33b20583`, calculated=`0x33b20583`, ok=yes）。压缩块只有 zlib 自带校验，EWF 不再额外存 adler32。

**重要限定（变体构造）**：案例 B 的存储 MD5 是本实验在写入零占位后**重新计算并写回**的，因此“存储 MD5 与重算一致”只说明变体容器被构造成自洽，不能说明采集时内容真实。真实采集工具在遇到坏扇区时如何处理摘要，必须查工具版本与采集日志；这也是“容器自洽 ≠ 介质真实”的直接示例。

`header`/`header2` 的尾部校验是**解压后正文的 adler32，按大端存放**（上表 body OK 已按此复核）。本实验不把“能解压”当成“校验通过”：只有实际比对存储值与计算值才记为 yes。

### 4. 逻辑内容

| 量 | 正常镜像 | 错误变体 | 说明 |
|---|---|---|---|
| 逻辑流大小 | 4,194,320 | 4,194,320 | EWF 读取器给出的可读字节数 |
| 卷声明扇区字节 | 4,194,304 | 4,194,304 | number_of_sectors × bytes_per_sector |
| 声明扇区之外的尾部 | 16 | 16 | 本样本有 16 字节非扇区对齐尾部 |
| 逻辑流 SHA256 | `8241e6f7d36d541c8de78dce98a41df4cff14cf45b80bb3d334fffed7e8001e3` | `c572901549246daace51a0b8b1ce59afc6184bf6d420e988ff132d710dfbf6f9` | 转换时从 EWF 读出的字节 |
| EWF 存储 MD5 | `9683f7575933eac7390416991cfc5b84` | `45420cfda3e251d4d1dd959cc4e4967f` | 容器内的采集摘要声明 |
| 存储 MD5 与重算一致 | yes | yes | 只证明容器内部自洽，不证明介质 |

本样本的逻辑流比卷声明的扇区范围多 16 字节（`kusjes van SRT<3`）。ASDF 会原样保留这 16 字节，但 ASDF 不记录“为什么有这段尾部”。要解释它，必须回到 EWF 容器查看 `volume.data.number_of_sectors`、分块表和采集工具行为。

`逻辑流 SHA256` 是转换时读到的哈希；`independent_reread_sha256` 是转换结束后再次用 EWF 读取的哈希。两者一致才说明“派生流 = 当前源流”，而不是只与转换器自己的记录一致。

### 5. 采集元数据

`header2` 原始文本（行保留原样，避免把长名行误读成值行）：

```
3
main
a	c	n	e	t	md	sn	av	ov	m	u	p	dc
description	case_number	evidence_number	examiner_name	notes			20140608	Linux	1766585902	1766585902	0	

srce
0	1
p	n	id	ev	tb	lo	po	ah	gu	aq
0	0
					-1	-1			

sub
0	1
p	n	id	nu	co	gu
0	0
				1
```

`main` 的短键含义可参考 `HEADER_LONG_NAMES`，但**本实验不把第二行当作已确认的值行**：该样本中第二行既有字段长名又有 `av/ov/m/u` 等值，行语义取决于采集工具版本。因此报告只展示原始行，元数据字段的权威解释必须回到原件与工具文档。

这些字段只是 EWF header/header2 中的文本。ASDF 把它们复制进 `provenance/manifest.json`，但 ASDF 没有原生采集元数据 schema，也不对这份 JSON 做密码学绑定；修改 JSON 并重算 ASDF footer 即可得到另一份“自洽”的 ASDF。因此元数据必须与原件、交接记录和外部锚定的 manifest 哈希一起复核。

## 可证明性分级

| 事实 | 仅凭 ASDF 可证明？ | 还需要什么 |
|---|---|---|
| ASDF 文件未被意外损坏 | 是（footer SHA256 + 块 CRC32） | 外部锚定的 ASDF 哈希，防故意重写 |
| ASDF 逻辑流等于转换时 EWF 读出流 | 有条件：ASDF 只证明内部一致；本实验靠转换后独立重读 EWF 并比对 SHA256 才成立 | 可信的转换程序哈希、独立重读记录 |
| EWF 段文件就是采集时的文件 | 否 | 段文件 SHA256 与交接记录 |
| EWF section/table/volume 校验当时通过 | 否 | 原容器上的 EWF 校验复算 |
| EWF 存储 MD5 代表介质内容 | 否 | 采集工具报告、原始介质或独立验证 |
| 声明错误范围是真实坏扇区 | 否 | 采集日志、设备错误记录、工具元数据 |
| 错误范围内的零是原始介质内容 | **否，且应标为未验证占位** | 不可能仅靠 ASDF；需原始介质或采集证据 |
| 段集合在采集时完整 | 否 | E01..E0n 连续性、段号、set_identifier、交接记录 |
| 采集元数据字段真实 | 否 | header/header2 原文与案件记录，最好有签名/时间戳 |

## 派生证据清单

| 案例 | ASDF | 整文件 SHA256 | footer SHA256 | footer OK | 全部 block CRC OK | 表项 | 派生流 SHA256 | 与独立重读源流一致 |
|---|---|---|---|---|---|---|---|---|
| A 正常 | `normal.asdf` | `7c03ac7821eb1eddf54c1d8a93fe4d21b3c48fbd38677a5a04dccc1eb342ea81` | `53bc4cbe90a9d2239c7a2eee99696e2070cca788ca29fbd3ebd3aab8b28cf113` | yes | yes | 130 | `8241e6f7d36d541c8de78dce98a41df4cff14cf45b80bb3d334fffed7e8001e3` | yes |
| B 变体 | `variant.asdf` | `185c548d216e1b7a5d6cef90693716d79993e3a479c27e347ed67f3580bdaf55` | `cfe5e99d50926c628ef0d1d6625e8f651fd3f6c897443be1273f36d01978186a` | yes | yes | 130 | `c572901549246daace51a0b8b1ce59afc6184bf6d420e988ff132d710dfbf6f9` | yes |

逐块映射（仅 idx=0 的磁盘流块）：

| 案例 | 块 # | 逻辑偏移 | 大小 | CRC32 | 命中错误范围 | 派生状态 |
|---|---|---|---|---|---|---|
| A 正常 | 0 | `0x0` | 32,768 | yes | — | 按读取字节保留 |
| A 正常 | 1 | `0x8000` | 32,768 | yes | — | 按读取字节保留 |
| A 正常 | 2 | `0x10000` | 32,768 | yes | — | 按读取字节保留 |
| B 变体 | 30 | `0xf0000` | 32,768 | yes | — | 按读取字节保留 |
| B 变体 | 31 | `0xf8000` | 32,768 | yes | err-0 | 占位字节，内容未验证 |
| B 变体 | 32 | `0x100000` | 32,768 | yes | — | 按读取字节保留 |

完整映射见两份外部 manifest 的 `chunks` 字段。

## 随库工具交叉复核

| 案例 | asdf-verify 返回码 | asdf-dd 返回码 | dd 导出 SHA256 | 与独立重读源流一致 |
|---|---|---|---|---|
| A 正常 | 0 | 0 | `8241e6f7d36d541c8de78dce98a41df4cff14cf45b80bb3d334fffed7e8001e3` | yes |
| B 变体 | 0 | 0 | `c572901549246daace51a0b8b1ce59afc6184bf6d420e988ff132d710dfbf6f9` | yes |

`asdf-verify` 验证的是 ASDF 自身 footer SHA256 和块 CRC32；`asdf-dd` 只按块表导出，不验证也不解释源 EWF。两者通过只能说明派生文件自洽且可复现，不能替代第 1–3 步对原件的复核。

## 丢失信息（明确清单）

| 丢失项 | 为什么 ASDF 不能证明 | 必须回到哪里 |
|---|---|---|
| 原段文件字节与段哈希 | ASDF 只保存逻辑流，不保存 E01..E0n 的容器字节。段文件 SHA256、段边界、段号、压缩方式、容器内偏移全部不进入 ASDF 的证明链。 | 必须回到原段文件重算 SHA256 并与交接记录比对。 |
| EWF 容器级校验 | section descriptor adler32、table entries adler32、volume/data/hash body adler32、存储 MD5 都是 EWF 容器事实；ASDF footer/block CRC 是另一套事实，不能互相替代。 | 用 EWF 读取器/独立工具复核 section 与 MD5。 |
| 采集错误范围与占位策略 | ASDF 没有坏扇区/错误范围语义。变体中的 `error2` 只在实验 manifest 里被复制；ASDF 块不知道哪些字节是占位，也不记录工具重试、错误粒度、占位模式来源。 | 回到 EWF 的 `error2`、采集日志和工具配置；逐范围比对。 |
| 逐字节来源置信度 | ASDF 块证明“转换器读到了这些字节”，不证明“这些字节来自介质”还是“工具写入的零/图案”。 | 需要采集工具的坏扇区报告、设备日志和原始 EWF 对照。 |
| 采集元数据语义 | header/header2 的字段被复制成 JSON，但 ASDF 不解释、不签名、不校验；字段缺失或伪造无法由 ASDF 发现。 | 回到 header/header2 原始文本和案件交接记录。 |
| 段集合完整性 | ASDF 没有段概念，也没有“应有 E05”的独立证据。缺段只能在转换时由 EWF 读取器/文件名序列发现。 | 检查 E01..E0n 是否连续、段号是否连续、set_identifier 是否一致；必要时重新采集。 |
| ADCRYPT 加密状态与密钥路径 | 转换必须先解锁 EWF；派生 ASDF 是明文。加密状态、密钥、解锁时间和访问记录不进入 ASDF。 | 回到原容器和密钥管理记录。 |
| 非扇区对齐尾部 | 本样本逻辑流比卷声明多 16 字节。ASDF 保留字节，但不保留“为什么多出来”的容器解释。 | 回到 volume 几何、table 和采集工具行为。 |
| 转换程序自身错误 | 若转换中某块读取失败，ASDF 的稀疏填充是格式产物（0xa5df），不是源数据，也不是零。必须保留 incomplete 标记。 | 查看转换日志、manifest 的 `completeness`，以及 `*.INCOMPLETE.json` 侧车文件。 |
| 原始 EWF 文件哈希 | ASDF 整文件 SHA256 是派生文件哈希；EWF 存储 MD5 是逻辑流声明哈希；两者都不是“原始 EWF 文件哈希”。 | 对每个 E01..E0n 单独计算 SHA256，并与采集时记录比对。 |

## 不完整来源的守卫

| 项目 | 结果 |
|---|---|
| 输入 | `image.E01..E04`（缺 E05） |
| 预检结果 | `EWF reader refused: IndexError: Chunk 128 out of range; volume declares 129 chunks but tables only cover 124 (missing segment files)` |
| 卷声明块数 / 表现有段覆盖块数 | 129 / 124 |
| 转换器行为 | 拒绝转换；不产出可被称为完整镜像的 ASDF |
| 派生输出 | 无 |
| 保留的标记 | `/Users/apple/Documents/用户反馈项目/run-control/first-five/jobs/FB-20261115-SEC15-056/workspace/experiment/out/incomplete-source.json` |

守卫逻辑是“**缺段就不产出可被称为完整镜像的 ASDF**”，并写出 `INCOMPLETE_SOURCE` 标记；而不是把缺失块静默补零。即使将来允许产出带缺口的 ASDF，缺口也必须是显式 sparse/未知，不能变成已确认内容。

## 如何复核原件、转换程序与派生输出

1. **先固定原件**：对每个 `image.E0n` 计算 SHA256，与采集交接记录比对；不要用 ASDF 的哈希代替。
2. **再验 EWF 容器**：用 `EWF` 打开全部段，检查段号连续、`set_identifier` 一致、section descriptor/body 校验、存储 MD5 与逻辑流 MD5 是否一致。
3. **验转换程序**：核对 `provenance/manifest.json` 中 `converter.script_sha256` 与实际脚本；用同一脚本重跑，比较源段哈希、逻辑流 SHA256、块映射和 ASDF GUID。
4. **验派生 ASDF 自洽性**：`python -m dissect.evidence.tools.asdf.verify <asdf>` 检查 footer SHA256 与每块 CRC32。
5. **验派生内容等价性**：`asdf-dd -w <输出文件> <asdf>` 导出流，重新用 `EWF.open()` 读取源流，逐字节比较；本实验的 `与独立重读源流一致` 列即该检查。
6. **验错误范围**：回到 EWF `error2`，逐范围读取并标记 `unverified_placeholder`；不要因为 ASDF 里也是零就升级为“已确认内容”。
7. **锚定 manifest**：把 `SHA256SUMS.json`（以及其中的外部 manifest 哈希）记入案件记录/时间戳服务；ASDF 内嵌 manifest 与同目录的哈希清单都不是自证，必须与外部锚点比对。
8. **验来源完整性**：检查 `completeness.status`；若为 `incomplete`，不得把派生输出当作完整镜像。

## 仍必须回到原容器检查的事实

- E01..E0n 是否齐全、段号是否连续、`set_identifier` 是否一致。
- 每个段文件的 SHA256 是否等于采集时记录；ASDF 哈希不能替代。
- EWF section descriptor/table/volume/hash 的校验是否通过；存储 MD5 是否等于逻辑流 MD5。
- `error2` 声明的坏扇区范围、错误粒度、占位模式，以及这些范围是否真的对应占位字节。
- header/header2 中的案件号、证据号、采集人、备注、采集时间、工具版本。
- 卷几何与被采集介质的对应关系，包括本样本 16 字节非扇区对齐尾部。
- ADCRYPT 是否加密、密钥/证书来源、解锁与访问记录。

## 复现

```bash
python experiment/forensic_conversion.py run
python experiment/forensic_conversion.py run --out /path/to/output   # 隔离输出目录
python -m dissect.evidence.tools.asdf.verify experiment/out/normal.asdf
python -m dissect.evidence.tools.asdf.verify experiment/out/variant.asdf
python -m pytest tests/test_forensic_conversion.py
```

产物：`normal.asdf`、`variant.asdf`、各自的外部 manifest、`incomplete-source.json`、`SHA256SUMS.json`（锚点文件），以及本报告（均位于 `--out` 指定的目录，默认 `experiment/out`）。

`SHA256SUMS.json` 记录本次运行结束时各产物的 SHA256；它本身也应被外部记录（案件日志、时间戳服务），否则只是同一目录内的自指清单。
