# VBK `verify=True` 覆盖清单

结论先行：`verify=True` **不是**全文件认证。它只在打开时对每个已填充的快照槽做一次
CRC（`SnapshotSlot.verify()`），用于**槽选择**；目录元数据、FIB、存储块、摘要字段在
打开、列目录、读取的任何阶段都**不做完整性校验**。本文件所有结论均可复现：

```
.venv/bin/python tests/vbk/verify_coverage.py
```

## 代码路径审计（dissect/archive/vbk/vbk.py）

| 范围 | 结构 | 代码位置 | verify=True 时的实际行为 |
|---|---|---|---|
| 存储头 | `StorageHeader` | `VBK.__init__` (vbk.py:49) | 无任何校验（该结构本无校验字段） |
| 槽 | `SnapshotSlotHeader`+`SnapshotDescriptor`+`BanksGrain`+`BankDescriptor[]` | `SnapshotSlot.verify()` (vbk.py:186) | **CRC32C**（`SnapshotSlotFormat>5`）或 CRC32，覆盖槽头后 4 字节起的内容；失败则**静默跳过该槽**（vbk.py:61-65），两槽都失败才抛 `VBKError` |
| Bank | `BankHeader`、bank 数据页 | `Bank.verify()` (vbk.py:246) | 方法存在但**从未被调用** |
| 目录元数据 | `MetaBlob` 页、`DirItemRecord` | `MetaVector`/`MetaBlob` (vbk.py:772,812) | 无任何校验 |
| FIB | `FibBlockDescriptor(V7).Digest` | `FibStream._read` (vbk.py:1030) | 摘要被解析但**从不比对** |
| 存储块 | `StgBlockDescriptor(V7).Digest`、`Lz4BlockHeader.CRC` | `FibStream._read` (vbk.py:1046-1054) | 摘要与 LZ4 块头 CRC 都**从不检查**；只有 LZ4 解码器自身的格式错误 |

## 检查类型区分

- **CRC（检错码）**：仅槽元数据一处。CRC32/CRC32C 任何人可重算，**不能证明来源真实性**（见 V6）。
- **内容摘要**：`StorageHeader.DigestType="md5"`，块摘要确实存在于 `StgBlockDescriptor`/`FibBlockDescriptor`
  且与数据一致（脚本末尾手动验证 md5 匹配），但后端**从不读取比对**。
- **格式边界**：UTF-8 解码、LZ4 解码、MetaVector 索引越界等异常只是解析器撞墙，不是完整性检查，
  且与 `verify` 参数无关（verify=False 表现相同）。
- **来源真实性**：无签名、无 MAC、无密钥参与。**未证明**。

## 篡改变体与真实输出（test9.vbk，format 9，双槽均填充）

| 变体 | 篡改点 | verify=True 结果 | 说明 |
|---|---|---|---|
| V0 | 无 | open/list/read 全部 ok | 基线 |
| V1 | `StorageHeader.DigestType` | 全部 ok | 存储头无校验 |
| V2a | 活动槽 `DirectoryRoot.Count`（CRC 失效） | open ok，**静默回退到 slot2**（@0xd000），list/read ok | 槽 CRC 唯一作用：槽选择；回退无任何告警 |
| V2b | 两个槽描述符都篡改 | open **FAIL** `VBKError: No active VBK metadata slot found` | verify=True 唯一能产生的完整性错误 |
| V3a | 目录页文件名→非法 UTF-8 | open ok，list FAIL `UnicodeDecodeError` | 格式边界错误，非完整性检查 |
| V3b | 文件名 `D`→`X`（合法 UTF-8） | open/list ok（显示错误名 `XEV__...`），按原名读取 FAIL `FileNotFoundError` | 目录元数据被静默接受 |
| V4a | 存储块 LZ4 负载 1 字节 | open/list ok，read FAIL `ValueError`（LZ4 解码器） | 编解码器边界，非摘要比对；部分损坏可能静默产出错误数据 |
| V4b | `Lz4BlockHeader.CRC` 字段 | 全部 ok | 该字段从未被读取 |
| V4c | `StgBlockDescriptor.Digest` 1 字节 | 全部 ok，读取内容不变 | 块摘要从未被比对 |
| V5a | 非活动槽 slot2 的 bank 数据页 | 全部 ok | 未引用区域无任何检查 |
| V5b | 活动槽中无引用的 bank 页 | 全部 ok | 同上 |
| V5c | 非活动槽描述符（CRC 失效） | 全部 ok | 槽被静默弃用，无信号 |
| V6 | 活动槽描述符篡改 **+ 重算 CRC** | open ok（槽被接受为"已验证"），list 在格式边界 FAIL `IndexError` | **CRC 可重算 → 不是来源认证** |

V2a 真实输出摘录：

```
V2a active slot1 DirectoryRoot.Count flipped (slot CRC now bad)
  verify=True  open   : ok (active slot @ 0xd000)      <- 静默换槽，无告警
  verify=True  read   : ok sha256=337350cac29d2ed3... (matches baseline)
  verify=False open   : ok (active slot @ 0x1000)
  verify=False listdir: FAIL IndexError: list index out of range
```

摘要存在但未用（脚本末尾手动验证）：

```
  manual md5 of decompressed block : 826dc6afc780f6cb441d1ad406f695e6
  StgBlockDescriptor.Digest        : 826dc6afc780f6cb441d1ad406f695e6   <- 一致，但后端从不检查
  FibBlockDescriptor.Digest        : 826dc6afc780f6cb441d1ad406f695e6   <- 一致，但后端从不检查
  StorageHeader.DigestType         : md5
```

## 明确未检查的部分（不得声称已验证）

- 目录元数据（`DirItemRecord`、MetaBlob 页、属性字典）：可任意篡改，仅可能触发格式错误。
- FIB 块描述符表及其 `Digest` 字段。
- 存储块内容及其 `Digest`、`Lz4BlockHeader.CRC`。
- Bank 头与 bank 数据页（`Bank.verify()` 死代码）。
- 非活动槽的全部数据区、活动槽中未被引用的页、文件空隙。
- 备份整体完整性、加密/签名、来源真实性：**未证明**。

## 后端状态建议

不要用布尔 `verified: true` 配绿色标记。改为按范围记录检查结果，服务据此输出
"哪些范围通过哪项检查"：

```json
{
  "scopes": [
    {"scope": "slot[active].metadata", "check": "crc32c", "status": "passed",
     "detail": "slot @0x1000, version 7"},
    {"scope": "slot[standby].metadata", "check": "crc32c", "status": "passed"},
    {"scope": "storage.header", "check": "none", "status": "not-checked"},
    {"scope": "directory.metadata", "check": "none", "status": "not-checked"},
    {"scope": "fib.descriptors.digest", "check": "md5", "status": "not-checked"},
    {"scope": "storage.blocks.digest", "check": "md5", "status": "not-checked"},
    {"scope": "storage.blocks.lz4_header_crc", "check": "crc32c", "status": "not-checked"},
    {"scope": "banks", "check": "crc32", "status": "not-checked"},
    {"scope": "unreferenced.regions", "check": "none", "status": "not-checked"},
    {"scope": "provenance", "check": "none", "status": "not-checked",
     "detail": "no signature/MAC; CRC is recomputable"}
  ]
}
```

规则建议：

- `status` 只允许 `passed` / `failed` / `not-checked`；没有 `verified` 这种无范围的总括态。
- 槽 CRC 失败当前是**静默换槽**（vbk.py:61-65），应把"槽被弃用"作为事件上报，
  否则 V2a 类篡改在双槽文件上完全不可见。
- 若要真正覆盖数据面，读取路径需比对 `StgBlockDescriptor.Digest`（md5 已布好），
  并在打开时调用现有的 `Bank.verify()`；在此之前，任何 UI 都不得对数据块范围显示"已验证"。
