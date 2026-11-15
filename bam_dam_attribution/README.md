# BAM/DAM 归属调查（基于 dissect.regf）

把 BAM（Background Activity Moderator）/ DAM（Desktop Activity Moderator）记录按
**用户 SID** 归属，输出从 hive 键路径一直到二进制 FILETIME 字段的完整证据链。
目标是解决“同一条程序路径被合并到错误用户”的问题：归属永远以
`控制集 + 服务(bam/dam) + SID + 程序路径` 四元组为单位，不做跨用户合并。

## 最小输入

只需要一个文件，无其它依赖参数：

- `SYSTEM` 注册表 hive（原始 hive，不是 `.LOG`/事务日志）。

可选参数都有默认值，正常调查无需提供：

| 参数 | 默认 | 含义 |
| --- | --- | --- |
| `-o/--output` | 打印到 stdout | 结构化 JSON 报告写入路径 |
| `--min-year` | `1970` | 可信 FILETIME 年份下界（含） |
| `--max-year` | `2100` | 可信 FILETIME 年份上界（含） |

## 运行

```bash
# 用仓库自带的合成夹具生成报告
python bam_dam_attribution/bam_dam_investigate.py \
    bam_dam_attribution/fixtures/SYSTEM_fixture -o report.json

# 对真实 SYSTEM hive
python bam_dam_attribution/bam_dam_investigate.py /path/to/SYSTEM
```

重建合成夹具（确定性输出，字节稳定）：

```bash
python bam_dam_attribution/fixtures/build_fixture_hive.py \
    bam_dam_attribution/fixtures/SYSTEM_fixture
```

测试：

```bash
python -m pytest bam_dam_attribution/tests -q
```

## 遍历的 hive 布局

```
<root>
└── ControlSetNNN
    └── Services
        ├── bam
        │   └── UserSettings
        │       └── <SID>            # 每个 SID 一个键
        │           └── <value>      # 名称=程序路径，数据=REG_BINARY
        └── dam
            └── UserSettings
                └── <SID>
                    └── <value>
```

- `Select\\Current`（DWORD）决定当前控制集；报告对每条记录标注
  `control_set_is_current`，但**非当前控制集的记录同样保留**，用于历史对照。
- 同一 hive 内可存在多个 `ControlSetNNN`，布局差异通过逐个控制集枚举体现，
  不假设只有一个。

## BAM/DAM 二进制结构

每个程序值是 `REG_BINARY`，标准头部 16 字节：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 8 | head QWORD（版本/序号，按原值保留，不解释语义） |
| 8 | 8 | FILETIME（Windows 100ns 计数，UTC 起点 1601-01-01） |
| 16 | 变长 | 未知尾部数据（如有，原样保留为 hex） |

## 结构化归属规则

1. **四元组身份**：每条证据的唯一身份是
   `(control_set, service, sid_key, program_path)`。两个用户拥有同一程序路径时，
   产生两条独立证据，报告的 `shared_program_path_groups` 仅做并列提示，绝不合并。
2. **SID 归属**：程序值归属到其所在 `UserSettings` 子键的键名 SID。SID 不符合
   Windows SID 文法时，记录保留但标记 `sid_malformed`，不猜测用户名、不跨键迁移。
3. **FILETIME 仅来自二进制偏移 8 的 QWORD**。键的最后写入时间
   （`key_last_write_time_utc`）作为独立字段记录，**严禁**用它补出缺失的程序时间。
4. **无效 FILETIME 不渲染为时间**，原样保留 `filetime_raw_qword` 并给出原因码；
   `filetime_utc` 置 `null`。
5. **未知尾部数据不解释**：超过 16 字节头部的部分按 hex 留存并标记
   `unknown_trailing_data`，不假设其结构或含义。
6. **过短二进制**：不足 16 字节时无法读取 FILETIME，标记
   `binary_too_short_for_filetime`，能读多少 head 就读多少。
7. **证据链完整可复核**：每条记录都给出
   `hive -> key -> value name -> raw binary -> FILETIME QWORD -> UTC -> 键写入时间`。
8. **语义中立**：BAM/DAM 是系统活动记账。时间只表示“该服务在该 SID 下记录此程序
   路径的时刻”，**不表述为成功登录，也不表述为（恶意）执行**。
9. **缺失即显式不确定**：缺 SID、缺时间、坏时间都必须带具体原因码，不静默丢弃。

## 不确定原因码

| 原因码 | 触发条件 |
| --- | --- |
| `sid_malformed` | SID 键名不匹配 Windows SID 文法 |
| `invalid_filetime_zero` | FILETIME QWORD 为 0，不表示任何时刻 |
| `invalid_filetime_unrepresentable` | QWORD 无法转换为 datetime（溢出等） |
| `filetime_outside_expected_window` | 转换出的年份超出 `min-year..max-year` |
| `binary_too_short_for_filetime` | 二进制不足 16 字节，读不到 FILETIME |
| `unknown_trailing_data` | 16 字节头部之外存在未解释的尾部字节 |

## 报告结构（摘要）

```json
{
  "input": { "select": {"Current": 1}, "current_control_set": "ControlSet001" },
  "counts": { "evidence_records": 9, "records_with_uncertainty": 6 },
  "shared_program_path_groups": [ /* 同路径不同 SID 的并列证据 */ ],
  "evidence": [
    {
      "identity": { "control_set": "...", "service": "bam",
                    "sid_key": "S-1-5-...", "program_path": "..." },
      "hive_key_path": "ControlSet001\\Services\\bam\\UserSettings\\S-1-5-...",
      "value": { "binary_hex": "...", "filetime_raw_qword": 0,
                 "filetime_utc": null, "unknown_trailing_hex": null },
      "key_last_write_time_utc": "...",
      "uncertainty_reasons": ["..."],
      "evidence_chain": ["hive:...", "key:...", "raw_binary(hex):...", "..."]
    }
  ]
}
```

## 合成夹具覆盖的情形

`fixtures/SYSTEM_fixture` 是用 REGF 磁盘格式手工构造的测试数据（非真实机器镜像），
刻意包含：

- 两个 SID 在同一控制集、同一服务下拥有**相同程序路径**（必须保持两条证据）；
- 同一 SID 的记录同时出现在 `ControlSet001` 与 `ControlSet002`；
- BAM 与 DAM 两个服务；
- 含未知尾部字节的 20/18 字节二进制；
- FILETIME 为 0、超出可信窗口、以及仅 4 字节的过短二进制；
- 一个不符合 SID 文法的 SID 键。
