# 格式猜测单选路由审查报告

审查对象：接收端以 oletools 的格式猜测（`oletools/ftguess.py`）决定后续分析器，
并把第一个成功的识别结果当作唯一真实格式。结论基于对 6 个冲突样本的
实际识别与解析输出，全程只解析、不执行文档内容。

## 1. 被审查的机制（代码事实）

- `ftguess.py:825`：容器识别按固定顺序 `RTF → OLE → ZIP → OneNote → PNG`，
  **首个 `recognize()` 成功即 `break`**，其余候选不再检查。
- `ftguess.py` 全程**不读取文件扩展名**；OLE 细分只靠根存储 CLSID
  （`ftguess.py:839` 查 `clsid_ftypes` 表）；OpenXML 细分只靠
  `[Content_Types].xml` 里主部件的**声明** content-type（`ftguess.py:478`）。
- `olevba.py:2767-2774`：`VBA_Parser` 同样单选——`isOleFile` 命中即走 OLE
  分支，只有 `self.type is None` 时才尝试 ZIP。OLE 命中后 ZIP 分支被短路。
- 因此"第一个成功 = 唯一真实格式"在两层都成立：路由器（ftguess）和分析器
  （VBA_Parser）各自丢弃其余候选。

## 2. 四层证据的可信度分级

| 证据层 | 性质 | 能证明什么 |
|---|---|---|
| 扩展名 | 纯提示，ftguess 完全不采纳 | 只能作候选，不能作任何证明 |
| OLE 根 CLSID | 文件内**自报**的元数据，攻击者可改（见 S6） | 候选细分类型；需流目录交叉验证 |
| ZIP 部件声明（[Content_Types].xml） | 文件内**自报**的声明（见 S3） | 候选能力；需与实际部件列表对照 |
| 实际可解析结构 | 解析器真实走通 CFB 目录 / ZIP 中央目录 | 唯一可称为"已验证"的层 |

任何一个标志字段（CLSID、content-type、扩展名）都不是完整证明。

## 3. 冲突样本与路由对照（实际输出）

样本由 `make_samples.py` 生成，VBA 载荷来自 oletools 自带测试文件，内容惰性。
完整输出见 `results/ftguess_routing.txt`、`results/olevba_single_path.txt`、
`results/probe_all_output.txt`。

| 样本 | 四层证据 | ftguess 单选 | 单选路径漏查 |
|---|---|---|---|
| S1 `S1_ole_renamed.docx` | 扩展名 docx；OLE magic；CLSID=PowerPoint；**还内嵌一个 4 部件 ZIP** | Powerpoint97 (OLE) | 扩展名冲突被静默忽略；内嵌 ZIP 半区不可见 |
| S2 `S2_ole_zip_polyglot.doc` | OLE magic 在 0 偏移 + 尾部完整 DOCM 包（含 vbaProject.bin） | Powerpoint97 (OLE) | **整个 OOXML 半区及其 vbaProject.bin**；olevba 只报 `OLE stream: 'VBA/Module1'` |
| S3 `S3_docm_declared_as_docx.docx` | 声明主部件=DOCX（无宏），实际存在 word/vbaProject.bin | Word2007_DOCX | 若路由按"DOCX 无宏"跳过宏扫描，**真实 VBA 漏查**（olevba 按部件名扫描能找到，但路由器已决定不调用） |
| S4 `S4_ole_magic_only.doc` | 仅 8 字节 OLE magic，无 FAT/目录 | Unknown | ftguess 报 Unknown；olevba 抛未处理 `AttributeError`。结构**无法验证**，不等于"损坏" |
| S5 `S5_xlsx_with_ole_embed.xlsx` | 声明 XLSX；`xl/embeddings/oleObject1.bin` 是带 VBA 的完整 CFB | Excel2007_XLSX | 路由层看不到嵌入 OLE；`Excel2007_XLSX.may_contain_vba=False` 会误导"安全"判定 |
| S6 `S6_clsid_spoofed.doc` | 根 CLSID 被改为 Word97，流目录仍是 `PowerPoint Document` | Word97 (OLE) | 被路由到 Word 分析器；CLSID 与流目录矛盾未被标记 |

附带发现：oletools 自带的良性测试文件 `tests/test-data/olevba/sample_with_vba.ppt`
**天然就是 OLE+ZIP 双容器**（尾部带 drs/ 恢复数据 ZIP，4 个部件）。多容器不是
 exotic 攻击样本，正常 Office 文件即如此。

## 4. 单选路径能保证什么、不能保证什么

能保证：
- 对单一容器、自报元数据与结构一致的文件，路由结果正确（S1 的 OLE 判定）。
- 判定是确定性的（固定顺序），可复现。

不能保证：
- **完备性**：OLE magic 在 0 偏移时，同文件内任何 ZIP/OOXML 结构被永久丢弃
  （S2）；反之 ZIP 优先时 OLE 同理。第一个成功与其余候选互斥是设计使然。
- **真实性**：CLSID（S6）与 content-type 声明（S3）都是可伪造的自报字段，
  单选路径把它们当终点而非候选。
- **可归因的失败**：S4 既不是"已验证的 OLE"也不是"已证明的损坏"，olevba 还
  抛未处理异常；接收端若把这类输入统称"损坏"，是在用方便替代结论。

## 5. 有边界的接入方案（`probe_all.py` 为参考实现）

原则：探测彼此独立、全部跑完；只有解析走通才算"已验证"；声明与结构并列展示；
无法排除的内容单列，不并入"损坏"。

1. **独立探测层**：扩展名（仅提示）、RTF magic、OLE magic+CFB 解析、
   ZIP EOCD+中央目录解析，全部执行，不短路。输出候选列表。
2. **按已验证视图扇出**：每个解析成功的容器视图各自进入对应分析器
   （OLE 视图 → olevba/oleid；ZIP 视图 → OOXML 检查），结果取并集，
   按视图归因（如 `ZIP-view!xl/embeddings/oleObject1.bin`）。
3. **声明-结构对照**：`[Content_Types].xml` 声明的主部件类型 vs 实际部件
   （vbaProject.bin 是否存在）、根 CLSID vs 流目录，矛盾记入 conflicts。
4. **有界递归**：嵌入 OLE 部件递归解析，`MAX_DEPTH=2`、`MAX_PARTS=512`、
   `MAX_PART_BYTES=64MB`，超限记入 unverifiable 而非静默丢弃。
5. **只解析不执行**：全程仅 olefile/zipfile/olevba 静态解析；样本中 VBA
   载荷为惰性测试代码，未被运行。

`probe_all.py` 对 6 个样本的输出（`results/probe_all_output.txt`）显示：
S2 两个半区的 VBA 均被检出并分别归因；S3 的"声明 DOCX 但存在
vbaProject.bin"被列为 conflict；S4 被列为 unverifiable（"magic 声称 OLE、
结构未验证"），未被归为损坏；S5 的嵌入 OLE 被递归解析并检出 VBA。

## 6. 复现

```
.venv/bin/python conflict_lab/make_samples.py          # 生成 6 个样本
.venv/bin/python oletools/ftguess.py conflict_lab/samples/*   # 当前单选路由
.venv/bin/olevba conflict_lab/samples/*                       # 当前单选分析
.venv/bin/python conflict_lab/probe_all.py conflict_lab/samples/*  # 多探针方案
```
